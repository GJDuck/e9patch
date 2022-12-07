/*
 * e9trampoline.cpp
 * Copyright (C) 2021 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cassert>
#include <cstdint>
#include <cstring>

#include <map>

#include <sys/mman.h>

#include "e9alloc.h"
#include "e9optimize.h"
#include "e9patch.h"
#include "e9trampoline.h"
#include "e9x86_64.h"

#define MACRO_DEPTH_MAX             128

/*
 * The general structure of a trampoline is as follows:
 *
 *      +--------------+--------------+--------------+
 *      |              |              |              |
 *      |   PROLOGUE   |  TRAMPOLINE  |   EPILOGUE   |
 *      |              |              |              |
 *      +--------------+--------------+--------------+
 *
 * Where:
 *      - PROLOGUE: are relocated instructions from *before* the patched
 *        instruction.  The prologue essentially serves as a "landing pad" for
 *        the -Opeephole optimization.
 *      - TRAMPOLINE: this is the original "user" trampoline.
 *      - EPILOGUE: are relocated instructions from *after* the patched
 *        instruction.  The epilogue attempts to avoid jumping back to the
 *        main program immediately, and instead waits for some other
 *        control-flow-transfer to do it for "free".  The epilogue is built as
 *        part of the builtin "$break" macro.
 *
 * Ultimately, the prologue/epilogue aim reduce the number of jumps the
 * patched binary uses, which can translated into a significant performance
 * gain.
 */

/*
 * Evictee trampoline template.
 */
const Trampoline *evicteeTrampoline = nullptr;

/*
 * Initialize the evictee trampoline.
 */
void __attribute__((__constructor__(8000))) evicteeTrampolineInit(void)
{
    size_t num_entries = 2;
    uint8_t *ptr =
        new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
    Trampoline *T          = (Trampoline *)ptr;
    T->prot                = PROT_READ | PROT_EXEC;
    T->num_entries         = num_entries;
    T->preload             = false;
    T->entries[0].kind     = ENTRY_INSTR;
    T->entries[0].length   = 0;
    T->entries[0].bytes    = nullptr;
    T->entries[1].kind     = ENTRY_BREAK;
    T->entries[1].optimize = true;
    T->entries[1].bytes    = nullptr;

    evicteeTrampoline = T;
}

/*
 * Label set.
 */
struct Label
{
    const intptr_t addr;
    const char * const name;

    Label(const Instr *I, const char *name): addr(I->addr), name(name)
    {
        ;
    }

    bool operator<(const Label &l) const
    {
        if (addr != l.addr)
            return (addr < l.addr);
        return (strcmp(name, l.name) < 0);
    }
};
typedef std::map<Label, intptr_t> LabelSet;

/*
 * Break location information.
 */
typedef std::map<intptr_t, intptr_t> BreakInfo;

/*
 * Lookup a macro value.
 */
static const Trampoline *expandMacro(const Binary *B,
    const Metadata *meta, const char *name)
{
    if (meta != nullptr)
    {
        ssize_t lo = 0, hi = (ssize_t)meta->num_entries-1;
        while (lo <= hi)
        {
            ssize_t mid = (lo + hi) / 2;
            int cmp = strcmp(name, meta->entries[mid].name);
            if (cmp == 0)
                return meta->entries[mid].T;
            else if (cmp < 0)
                hi = mid - 1;
            else
                lo = mid + 1;
        }
    }
    auto i = B->Ts.find(name);
    if (i != B->Ts.end())
        return i->second;
    return nullptr;
}

/*
 * Save a jump instruction for future optimization.
 */
static void saveJump(const Binary *B, intptr_t addr, uint8_t *bytes,
    size_t size)
{
    if (!option_Opeephole || bytes == nullptr || !isCFT(bytes, size, CFT_JMP))
        return;
    B->Js.push_back({addr, bytes, size});
}

/*
 * Relocate an instruction to the given address.
 */
static int relocateInstr(const Instr *I, intptr_t addr, Buffer *buf = nullptr)
{
    bool relax   = (addr == INTPTR_MIN);
    off_t offset = (relax? 0: addr - I->addr);
    return relocateInstr(I->addr, offset, I->ORIG, I->size, I->pic, buf,
        relax);
}

/*
 * Build a jump instruction that implements an unoptimized $break.
 */
enum BuildMode
{
    BUILD_SIZE,     // Build size and offsets (buf == nullptr)
    BUILD_BYTES,    // Build bytes (buf != nullptr)
};
static int buildBreak(const Binary *B, const Instr *I, intptr_t addr,
    BuildMode mode = BUILD_SIZE, const BreakInfo *breaks = nullptr,
    Buffer *buf = nullptr)
{
    if (mode == BUILD_SIZE)
        return /*sizeof(jmpq)=*/5;

    intptr_t target = I->addr + I->size;
    if (breaks != nullptr)
    {
        auto i = breaks->find(I->addr);
        if (i != breaks->end())
            target = i->second;
    }
    off_t rel = target - (addr + /*sizeof(jmpq)=*/5);
    assert(rel >= INT32_MIN && rel <= INT32_MAX);
    int32_t rel32 = (int32_t)rel;
    uint8_t *bytes = buf->bytes();
    buf->push(/*jmpq opcode=*/0xE9);
    buf->push((const uint8_t *)&rel32, sizeof(rel32));

    const Instr *J = I->succ();
    if (option_Opeephole && J != nullptr && buf->bytes() != nullptr)
        saveJump(B, addr, bytes, /*sizeof(jmpq)=*/5);
 
    return /*sizeof(jmpq)=*/5;
}

/*
 * Build a $break/$BREAK operation from a trampoline back to the main code.
 *
 * Note this is heavily optimized.  The Naive way would be to simply use a
 * single jmpq to the next instruction (as per the paper).  However, a far
 * better approach is to clone an "epilogue" containing the succeeding
 * instruction sequence up to and including the next control-flow-transfer
 * (CFT) instruction (including other jumps to unrelated trampolines).  This
 * saves a jump and a lot of overhead (since CPUs like locality).
 *
 * This function has two modes: building the size or building the bytes.
 * The first mode is for information gathering (e.g., determining the size of
 * the trampoline), while the latter actually builds the trampoline bytes.
 * The two modes use the same code to avoid a double maintenance problem.
 */
static int buildBreak(const Binary *B, const Instr *I, intptr_t addr,
    bool fallthrough, bool optimize, BuildMode mode = BUILD_SIZE,
    BreakInfo *breaks = nullptr, Buffer *buf = nullptr)
{
    intptr_t addr_0 = addr;
    if (fallthrough)
        return 0;       // Fallthrough
    if (!optimize || I->no_optimize)
        return buildBreak(B, I, addr, mode, breaks, buf);

    // Determine the epilogue by finding the next unconditional CFT.
    const Instr *J = I;
    unsigned i = 0;
    bool cft = false;
    unsigned size = 0;
    while (!cft && i < option_Oepilogue && size < option_Oepilogue_size)
    {
        const Instr *K = J->succ();
        if (K == nullptr)
            break;
        J = K;
        i++;
        cft = (J->is_patched && !J->is_evicted);
        cft = cft || isCFT(J->ORIG, J->size, CFT_CALL | CFT_RET | CFT_JMP);
        size += J->size;
    }

    if (!cft)
    {
        // Optimization cannot be applied --> jump to next instruction.
        return buildBreak(B, I, addr, mode, breaks, buf);
    }

    // Build the epilogue:
    J = I->next();
    unsigned start = (mode == BUILD_BYTES? buf->size(): 0);
    bool ok = true;
    for (unsigned j = 0; ok && j < i; j++, J = J->next())
    {
        if (J->is_patched && !J->is_evicted)
        {
            assert(j == i-1);
            addr += buildBreak(B, J->prev(), addr, mode, breaks, buf);
            break;
        }

        int len = 0;
        uint8_t *bytes;
        switch (mode)
        {
            case BUILD_SIZE:
                len = relocateInstr(J, INTPTR_MIN);
                break;
            case BUILD_BYTES:
                bytes = buf->bytes();
                len = relocateInstr(J, addr, buf);
                ok = (len >= 0);
                if (ok)
                    saveJump(B, addr, bytes, len);
                break;
        }
        addr += (unsigned)len;
    }

    if (!ok)
    {
        // Failed to apply optimization --> jump to next instruction.
        if (buf != nullptr)
            buf->reset(start);
        return buildBreak(B, I, addr_0, mode, breaks, buf);
    }

    return addr - addr_0;
}

/*
 * Build a trampoline prologue, which may include instructions before the
 * patched instruction.  The trampoline prologue allows other instructions
 * to jump to the trampoline "early", without having to go back to the main
 * program.  The code is similar to buildBreak().
 */
static int buildPrologue(const Binary *B, const Instr *I,
    intptr_t addr, BuildMode mode = BUILD_SIZE, Buffer *buf = nullptr)
{
    if (!option_Opeephole)
        return 0;
    const Instr *J = getTrampolinePrologueStart(B->Es, I);
    if (J == nullptr || J == I)
        return 0;

    int r = 0;
    unsigned start = (mode == BUILD_BYTES? buf->size(): 0);
    std::vector<std::pair<const Instr *, intptr_t>> entries;
    for (; J != I; J = J->next())
    {
        int len = 0;
        switch (mode)
        {
            case BUILD_SIZE:
                len = relocateInstr(J, INTPTR_MIN);
                break;
            case BUILD_BYTES:
            {
                uint8_t *bytes = buf->bytes();
                intptr_t entry = addr;
                len = relocateInstr(J, addr, buf);
                if (len < 0)
                {
                    buf->reset(start);
                    break;
                }
                saveJump(B, entry, bytes, len);
                entries.push_back({J, entry});
            }
        }
        if (len < 0)
            return 0;
        addr += len;
        r += len;
    }

    for (const auto &entry: entries)
        setTrampolineEntry(B->Es, entry.first, entry.second);

    return r;
}

/*
 * Calculate trampoline size.
 * Returns (-1) if the trampoline cannot be constructed.
 */
static int getTrampolineSize(const Binary *B, const Trampoline *T,
    const Instr *I, bool last, unsigned depth)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline size; maximum macro expansion depth "
            "(%u) exceeded", MACRO_DEPTH_MAX);
    unsigned size = 0;
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                size += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
                continue;
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                size += entry.length;
                continue;
            case ENTRY_INT8:
                size += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                size += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                size += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                size += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
                continue;
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline size; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                int r = getTrampolineSize(B, U, I, last, depth+1);
                if (size < 0)
                    return -1;
                size += r;
                continue;
            }
            case ENTRY_REL8:
                size += sizeof(int8_t);
                continue;
            case ENTRY_REL32:
                size += sizeof(int32_t);
                continue;
            case ENTRY_INSTR:
            {
                int r = relocateInstr(I, INTPTR_MIN);
                if (r < 0)
                    return -1;
                size += r;
                continue;
            }
            case ENTRY_INSTR_BYTES:
                size += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                size += buildBreak(B, I, /*addr=*/0, fallthrough, optimize,
                    BUILD_SIZE);
                continue;
            }
            case ENTRY_TAKE:
                size += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    int r = (I->T != nullptr?
                        getTrampolineSize(B, I->T, I, last, depth+1):
                        relocateInstr(I, INTPTR_MIN));
                    if (r < 0)
                        return -1;
                    size += r;
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    size += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE);
                continue;
            }
        }
    }
    return size;
}

/*
 * Calculate trampoline size.
 */
int getTrampolineSize(const Binary *B, const Trampoline *T,
    const Instr *I)
{
    return getTrampolineSize(B, T, I, /*last=*/true, /*depth=*/0);
}

/*
 * Calculate trampoline prologue size.
 */
int getTrampolinePrologueSize(const Binary *B, const Instr *I)
{
    if (I == nullptr)
        return 0;
    return buildPrologue(B, I, /*addr=*/0, BUILD_SIZE);
}

/*
 * Get the address of a "builtin" label, or INTPTR_MIN.
 */
static intptr_t getBuiltinLabelAddress(const Binary *B, const Instr *I,
    const char *label)
{
    if (label[0] != '.' && label[1] != 'L')
        return INTPTR_MIN;

    // Check for "builtin" labels:
    switch (label[2])
    {
        case 'b':
            if (strcmp(label, ".Lbreak") == 0)
                return (intptr_t)I->addr + (intptr_t)I->size;
            break;
        case 'c':
            if (strcmp(label, ".Lconfig") == 0)
                return B->config;
            break;
        case 'i':
            if (strcmp(label, ".Linstr") == 0)
                return (intptr_t)I->addr;
            break;
        case 't':
            if (strcmp(label, ".Ltake") == 0)
            {
                intptr_t target = getCFTTarget(I->addr, I->ORIG, I->size,
                    CFT_JCC);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\".Ltake\")", I->addr);
                return target;
            }
            break;
    }
    return INTPTR_MIN;
}

/*
 * Calculate trampoline bounds.
 */
static size_t getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I, unsigned depth, size_t size, bool last, Bounds &b)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline bounds; maximum macro expansion "
            "depth (%u) exceeded", MACRO_DEPTH_MAX);
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                size += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
                continue;
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                size += entry.length;
                continue;
            case ENTRY_INT8:
                size += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                size += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                size += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                size += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
                continue;
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline bounds; metadata for "
                        "macro \"%s\" is missing", entry.macro);
                size = getTrampolineBounds(B, U, I, depth+1, size, last, b);
                continue;
            }
            case ENTRY_REL8: case ENTRY_REL32:
            {
                size += (entry.kind == ENTRY_REL8?
                    sizeof(int8_t): sizeof(int32_t));
                intptr_t addr = INTPTR_MIN;
                if (entry.use)
                    addr = getBuiltinLabelAddress(B, I, entry.label);
                else
                    addr = (intptr_t)entry.uint64;
                if (addr != INTPTR_MIN)
                {
                    intptr_t lb = addr - size + 1 +
                        (entry.kind == ENTRY_REL8? INT8_MIN: INT32_MIN);
                    intptr_t ub = addr - size - 1 +
                        (entry.kind == ENTRY_REL8? INT8_MAX: INT32_MAX);
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                continue;
            }
            case ENTRY_INSTR:
            {
                int r = relocateInstr(I, INTPTR_MIN);
                size += (r < 0? 0: r);
                continue;
            }
            case ENTRY_INSTR_BYTES:
                size += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                size += buildBreak(B, I, /*addr=*/0, fallthrough, optimize,
                    BUILD_SIZE);
                continue;
            }
            case ENTRY_TAKE:
                size += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    size += (I->T != nullptr?
                        getTrampolineBounds(B, I->T, I, depth+1, size, last, b):
                        (size_t)relocateInstr(I, INTPTR_MIN));
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    size += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE);
                continue;
            }
        }
    }
    return size;
}

/*
 * Calculate trampoline bounds.
 */
Bounds getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I)
{
    Bounds b = {INTPTR_MIN, INTPTR_MAX};
    if (T == evicteeTrampoline)
        return b;
    getTrampolineBounds(B, T, I, /*depth=*/0, /*size=*/0, /*last=*/true, b);
    return b;
}

/*
 * Build the set of labels.
 */
static intptr_t buildLabelSet(const Binary *B, const Trampoline *T,
    const Instr *I, intptr_t addr, bool last, BreakInfo &breaks,
    LabelSet &labels)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                addr += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                addr += entry.length;
                continue;
            case ENTRY_INT8:
                addr += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                addr += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                addr += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                addr += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
            {
                Label L(I, entry.label);
                auto i = labels.insert(std::make_pair(L, addr));
                if (!i.second)
                    error("failed to build trampoline; duplicate label "
                        "\"%s\"", entry.label);
                continue;
            }
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata, entry.macro);
                if (U == nullptr)
                    error("failed to build trampoline; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                addr = buildLabelSet(B, U, I, addr, last, breaks, labels);
                continue;
            }
            case ENTRY_REL8:
                addr += sizeof(int8_t);
                continue;
            case ENTRY_REL32:
                addr += sizeof(int32_t);
                continue;
            case ENTRY_INSTR:
                addr += relocateInstr(I, addr);
                continue;
            case ENTRY_INSTR_BYTES:
                addr += I->size;
                continue;
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                addr += buildBreak(B, I, addr, fallthrough, optimize,
                    BUILD_SIZE, &breaks, nullptr);
                continue;
            }
            case ENTRY_TAKE:
                addr += /*sizeof(jmpq)=*/5;
                continue;
            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    if (I->T != nullptr)
                        addr = buildLabelSet(B, I->T, I, addr, last, breaks,
                            labels);
                    else
                        addr += relocateInstr(I, addr);
                    if (!last)
                        breaks.insert({I->addr, addr});
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                    addr += buildBreak(B, J, /*addr=*/0, false, true,
                        BUILD_SIZE, &breaks, nullptr);
                continue;
            }
        }
    }
    return addr;
}

/*
 * Lookup a label value.
 */
static off_t lookupLabel(const Binary *B, const char *label,
    const Instr *I, intptr_t addr, const LabelSet &labels)
{
    if (label[0] != '.' && label[1] != 'L')
        error("failed to build trampoline; unknown prefix for \"%s\" label",
            label);

    intptr_t target = getBuiltinLabelAddress(B, I, label);
    if (target != INTPTR_MIN)
        return target - addr;

    // Check for user labels:
    Label L(I, label);
    auto i = labels.find(L);
    if (i == labels.end())
        error("failed to build trampoline; unknown label \"%s\"", label); 
    return i->second - addr;
}

/*
 * Build the trampoline bytes.
 */
static void buildBytes(const Binary *B, const Trampoline *T, const Instr *I,
    intptr_t addr, bool last, const BreakInfo &breaks, const LabelSet &labels,
    Buffer &buf)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                if (I != nullptr && I->debug)
                    buf.push(/*int3=*/0xcc);
                continue;
            case ENTRY_BYTES:
                buf.push(entry.bytes, entry.length);
                continue;
            case ENTRY_ZEROES:
                for (unsigned i = 0; i < entry.length; i++)
                    buf.push(0x0);
                continue;  
            case ENTRY_INT8: case ENTRY_INT16: case ENTRY_INT32:
            case ENTRY_INT64:
            {
                int64_t val = 0;
                if (entry.use)
                {
                    val = lookupLabel(B, entry.label, I, addr + buf.size(),
                        labels);
                    val += (addr + buf.size());
                }
                else
                    val = (int64_t)entry.uint64;
                switch (entry.kind)
                {
                    case ENTRY_INT8:
                        buf.push((uint8_t)val);
                        break;
                    case ENTRY_INT16:
                        buf.push((uint8_t *)&val, sizeof(uint16_t));
                        break;
                    case ENTRY_INT32:
                        buf.push((uint8_t *)&val, sizeof(uint32_t));
                        break;
                    case ENTRY_INT64:
                        buf.push((uint8_t *)&val, sizeof(uint64_t));
                        break;
                    default:
                        break;
                }
                continue;
            }
 
            case ENTRY_LABEL:
                continue;

            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                assert(U != nullptr);
                buildBytes(B, U, I, addr, last, breaks, labels, buf);
                continue;
            }

            case ENTRY_REL8:
            case ENTRY_REL32:
            {
                off_t rel = 0;
                if (entry.use)
                    rel = lookupLabel(B, entry.label, I, addr + buf.size(),
                        labels);
                else
                    rel = (intptr_t)entry.uint64 - (addr + buf.size());
                rel -= (entry.kind == ENTRY_REL8? sizeof(int8_t):
                                                  sizeof(int32_t));
                if (entry.kind == ENTRY_REL8)
                {
                    if (rel < INT8_MIN || rel > INT8_MAX)
                        error("failed to build trampoline; rel8 value (%zd) "
                            "is out-of-range (%d..%d)", rel, (int)INT8_MIN,
                            INT8_MAX);
                    int8_t rel8 = (int8_t)rel;
                    buf.push((uint8_t)rel8);
                }
                else
                {
                    if (rel < INT32_MIN || rel > INT32_MAX)
                        error("failed to build trampoline; rel32 value (%zd) "
                            "is out-of-range (%zd..%zd)", rel,
                            (ssize_t)INT32_MIN, INT32_MAX);
                    int32_t rel32 = (int32_t)rel;
                    buf.push((const uint8_t *)&rel32, sizeof(rel32));
                    break;
                }
                continue;
            }

            case ENTRY_INSTR:
                relocateInstr(I, addr + buf.size(), &buf);
                continue;

            case ENTRY_INSTR_BYTES:
                buf.push(I->ORIG, I->size);
                break;
        
            case ENTRY_BREAK:
            {
                bool fallthrough = !last && (i+1 >= T->num_entries);
                bool optimize    = last && entry.optimize;
                (void)buildBreak(B, I, addr + buf.size(), fallthrough,
                    optimize, BUILD_BYTES, (BreakInfo *)&breaks, &buf);
                break;
            }

            case ENTRY_TAKE:
            {
                intptr_t target = getCFTTarget(I->addr, I->ORIG, I->size,
                    CFT_JCC);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\"$taken\")", I->addr);
                off_t rel = target - (addr + buf.size() + /*sizeof(jmpq)=*/5);

                buf.push(/*jmpq opcode=*/0xE9);
                assert(rel >= INT32_MIN);
                assert(rel <= INT32_MAX);
                int32_t rel32 = (int32_t)rel;
                buf.push((const uint8_t *)&rel32, sizeof(rel32));
                break;
            }

            case ENTRY_BATCH:
            {
                const Instr *J = nullptr;
                while (I != nullptr && I->addr <= (intptr_t)entry.uint64)
                {
                    bool last = (I->addr == (intptr_t)entry.uint64);
                    if (I->T != nullptr)
                        buildBytes(B, I->T, I, addr, last, breaks, labels,
                            buf);
                    else
                    {
                        int r = relocateInstr(I, addr + buf.size(), &buf);
                        if (r < 0)
                            error("failed to relocate instruction at "
                                "address 0x%lx", I->addr);
                    }
                    J = I;
                    I = I->next();
                }
                if (J->T == nullptr)
                {
                    (void)buildBreak(B, J, addr + buf.size(), false, true,
                        BUILD_BYTES, (BreakInfo *)&breaks, &buf);
                }
                I = nullptr;
                continue;
            }
        }
    }
}

/*
 * Flatten a trampoline into a memory buffer.
 */
static void flattenTrampoline(const Binary *B, uint8_t *bytes, size_t size,
    uint8_t fill, intptr_t addr, int32_t offset32, int32_t entry32,
    const Trampoline *T, const Instr *I)
{
    // Note: it is possible for actual size to be smaller than the `size'.
    //       This occurs when the trampoline size was calculated under the
    //       assumption that instructions can be relocated, however the
    //       assumption fails when real offsets are used (after the trampoline
    //       has been placed).  This wastes a few bytes but is otherwise
    //       harmless.

    LabelSet labels;
    BreakInfo breaks;
    intptr_t end = buildLabelSet(B, T, I, addr, true, breaks, labels);
    size_t offset = (size_t)(end - addr);
    
    if (offset > size)
        error("failed to flatten trampoline for instruction at address 0x%lx; "
            "buffer size (%zu) exceeds the trampoline size (%zu)",
            I->addr, offset, size);

    int presize = entry32 - offset32;
    if (presize > 0)
    {
        Buffer buf(bytes, presize);
        (void)buildPrologue(B, I, addr - presize, BUILD_BYTES, &buf);
        assert(buf.size() == (size_t)presize || buf.size() == 0);
        if (buf.size() == 0)
            buf.push(fill, presize);
    }

    bytes += presize;
    size  -= presize;
    {
        Buffer buf(bytes, size);
        buildBytes(B, T, I, addr, true, breaks, labels, buf);
        assert(buf.i <= size);
        buf.push(fill, size - buf.i);
    }
}

/*
 * Flatten all trampolines.
 */
void flattenAllTrampolines(Binary *B)
{
    for (auto *A: B->allocator)
    {
        if (A->T == nullptr)
        {
            A->bytes = nullptr;
            continue;
        }
        size_t size = A->ub - A->lb;
        uint8_t *bytes = new uint8_t[size];

        const Instr *I = A->I;
        int32_t offset32 = (int32_t)(I == nullptr? 0: A->lb - I->addr);
        int32_t entry32  = offset32 + A->entry;
        intptr_t addr    = (I == nullptr? A->lb: I->addr + entry32);
        flattenTrampoline(B, bytes, size, /*fill=int3=*/0xcc, addr, offset32,
            entry32, A->T, I);
        A->bytes = bytes;
    }
}

/*
 * Trampoline comparison.
 */
bool TrampolineCmp::operator()(const Trampoline *a, const Trampoline *b) const
{
    if (a->num_entries != b->num_entries)
        return (a->num_entries < b->num_entries);
    for (unsigned i = 0; i < a->num_entries; i++)
    {
        const Entry *entry_a = a->entries + i;
        const Entry *entry_b = b->entries + i;
        if (entry_a->kind != entry_b->kind)
            return (entry_a->kind < entry_b->kind);
        int cmp = 0;
        switch (entry_a->kind)
        {
            case ENTRY_BYTES:
                if (entry_a->length != entry_b->length)
                    return (entry_a->length < entry_b->length);
                cmp = memcmp(entry_a->bytes, entry_b->bytes, entry_a->length);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_ZEROES:
                if (entry_a->length != entry_b->length)
                    return (entry_a->length < entry_b->length);
                break;
            case ENTRY_LABEL:
                cmp = strcmp(entry_a->label, entry_b->label);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_MACRO:
                cmp = strcmp(entry_a->macro, entry_b->macro);
                if (cmp != 0)
                    return (cmp < 0);
                break;
            case ENTRY_REL8: case ENTRY_REL32:
            case ENTRY_INT8: case ENTRY_INT16: case ENTRY_INT32:
            case ENTRY_INT64:
                if (entry_a->use != entry_b->use)
                    return (entry_a->use < entry_b->use);
                if (entry_a->use)
                {
                    cmp = strcmp(entry_a->label, entry_b->label);
                    if (cmp != 0)
                        return (cmp < 0);
                }
                else
                {
                    if (entry_a->uint64 != entry_b->uint64)
                        return (entry_a->uint64 < entry_b->uint64);
                }
                break;
            case ENTRY_DEBUG: case ENTRY_INSTR:
            case ENTRY_INSTR_BYTES: case ENTRY_BREAK:
            case ENTRY_TAKE:
                break;
            case ENTRY_BATCH:
                if (entry_a->uint64 != entry_b->uint64)
                    return (entry_a->uint64 < entry_b->uint64);
                break;
        }
    }
    return false;
}

