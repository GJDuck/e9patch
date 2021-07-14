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
#include "e9patch.h"
#include "e9trampoline.h"
#include "e9x86_64.h"

#define MACRO_DEPTH_MAX             128

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
    Trampoline *T        = (Trampoline *)ptr;
    T->prot              = PROT_READ | PROT_EXEC;
    T->num_entries       = num_entries;
    T->preload           = false;
    T->entries[0].kind   = ENTRY_INSTRUCTION;
    T->entries[0].length = 0;
    T->entries[0].bytes  = nullptr;
    T->entries[1].kind   = ENTRY_CONTINUE;
    T->entries[1].length = 0;
    T->entries[1].bytes  = nullptr;

    evicteeTrampoline = T;
}

/*
 * Label set.
 */
typedef std::map<const char *, off_t, CStrCmp> LabelSet;

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
 * Build a jump instruction from a trampoline back to the main code.
 */
static int buildJump(off_t offset, const Instr *J, Buffer *buf)
{
    if (buf != nullptr)
    {
        offset = -(offset + /*sizeof(jmpq)=*/5);

        // If the target (J) is itself a jump, we can skip the target and
        // jump directly to the target's target...
        if (option_Ojump_peephole && J != nullptr)
        {
            intptr_t target = J->trampoline;
            target = (target != INTPTR_MIN? target:
                getJumpTarget(J->addr, J->patched.bytes, J->size));
            if (target != INTPTR_MIN)
            {
                off_t offset_target = offset + (target - J->addr);
                if (offset_target >= INT32_MIN && offset_target <= INT32_MAX)
                    offset = offset_target;
            }
        }

        int32_t rel32 = (int32_t)offset;
        if (option_Ojump_peephole && rel32 == 0)
        {
            // If we do not jump anywhere then just use a NOP:
            // nopl 0x0(%rax,%rax,1)
            buf->push(0x0F); buf->push(0x1F); buf->push(0x44);
            buf->push(0x00); buf->push(0x00);
        }
        else
        {
            buf->push(/*jmpq opcode=*/0xE9);
            buf->push((const uint8_t *)&rel32, sizeof(rel32));
        }
    }
    return /*sizeof(jmpq)=*/5;
}

/*
 * Build a $continue operation from a trampoline back to the main code.
 *
 * Note this is heavily optimized.  The Naive way would be to simply use a
 * single jmpq to the next instruction (as per the paper).  However, a far
 * better approach is to clone the succeeding instruction sequence up to and
 * including the next control-flow-transfer (CFT) instruction (including
 * other jumps to unrelated trampolines).  This saves a jump and a lot of
 * overhead (since CPUs like locality).
 */
static int buildContinue(const Binary *B, const Instr *I, int32_t offset32,
    Buffer *buf)
{
    // Lookahead to find the next unconditional CFT instruction.
    const Instr *J = I;
    unsigned i = 0;
    bool cft = false;
    unsigned size = 0;
    while (!cft && !I->no_optimize && i < option_Ojump_elim &&
        size < option_Ojump_elim_size)
    {
        const Instr *K = J->next;
        if (K == nullptr || J->addr + J->size != K->addr)
            break;
        J = K;
        i++;
        cft = (J->trampoline != INTPTR_MIN && !J->evicted);
        cft = cft ||
            isUnconditionalControlFlowTransfer(J->original.bytes, J->size);
        size += J->size;
    }

    const Instr *K = I->next;
    K = (K != nullptr && I->addr + I->size != K->addr? nullptr: K);
    if (!cft)
    {
        // Optimization cannot be applied --> jump to next instruction.
        return buildJump(offset32 - (off_t)I->size, K, buf);
    }

    // Relocate all instructions up-to-and-including the CFT
    J = I->next;
    int s = I->size, r = 0;
    unsigned save = (buf == nullptr? 0: buf->i);
    bool ok = true;
    for (unsigned j = 0; j < i; j++, J = J->next)
    {
        if (J->trampoline != INTPTR_MIN && !J->evicted)
        {
            assert(j == i-1);
            r += buildJump((off_t)offset32 + (off_t)(r - s), J, buf);
            break;
        }

        int len = 0;
        if (buf != nullptr)
            len = relocateInstr(J->addr, offset32 + (r - s),
                J->original.bytes, J->size, J->pic, buf->bytes + buf->i);
        else
            len = relocateInstr(J->addr, /*offset=*/0, J->original.bytes,
                J->size, J->pic, nullptr, /*relax=*/true);
        if (len < 0)
        {
            ok = false;
            break;
        }
        if (buf != nullptr)
        {
            if (option_Ojump_peephole && len == /*sizeof(jcc rel32)=*/6)
            {
                // As per above, if conditional jump target is itself a jump,
                // then jump directly to the target's target.
                intptr_t addr = J->addr + offset32 + (r - s);
                intptr_t target = getJccTarget(addr, buf->bytes + buf->i, len);
                Instr *K = findInstr(B, target);
                if (K != nullptr)
                {
                    target = K->trampoline;
                    target = (target != INTPTR_MIN? target:
                        getJumpTarget(K->addr, K->patched.bytes, K->size));
                    if (target != INTPTR_MIN)
                    {
                        off_t offset = (off_t)target - (off_t)(addr + len);
                        if (offset >= INT32_MIN && offset <= INT32_MAX)
                        {
                            int32_t rel32 = (int32_t)offset;
                            memcpy(buf->bytes + buf->i + len - sizeof(rel32),
                                &rel32, sizeof(rel32));
                        }
                    }
                }
            }
            buf->i += (unsigned)len;
        }
        s += J->size;
        r += (unsigned)len;
    }

    if (!ok)
    {
        // Failed to apply optimization --> jump to next instruction.
        if (buf != nullptr)
            buf->i = save;
        return buildJump(offset32 - (off_t)I->size, K, buf);
    }

    return r;
}

/*
 * Calculate trampoline size.
 * Returns (-1) if the trampoline cannot be constructed.
 */
static int getTrampolineSize(const Binary *B, const Trampoline *T,
    const Instr *I, unsigned depth)
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
                int r = getTrampolineSize(B, U, I, depth+1);
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
            case ENTRY_INSTRUCTION:
            {
                int r = relocateInstr(I->addr, /*offset=*/0, I->original.bytes,
                    I->size, I->pic, nullptr);
                if (r < 0)
                    return -1;
                size += r;
                continue;
            }
            case ENTRY_INSTRUCTION_BYTES:
                size += I->size;
                continue;
            case ENTRY_CONTINUE:
                size += buildContinue(B, I, /*offset=*/0, nullptr);
                continue;
            case ENTRY_TAKEN:
                size += /*sizeof(jmpq)=*/5;
                continue;
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
    return getTrampolineSize(B, T, I, /*depth=*/0);
}

/*
 * Calculate trampoline bounds.
 */
static size_t getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I, unsigned depth, size_t size, Bounds &b)
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
                size = getTrampolineBounds(B, U, I, depth+1, size, b);
                continue;
            }
            case ENTRY_REL8:
            {
                size += sizeof(int8_t);
                if (!entry.use_label)
                {
                    intptr_t lb = (intptr_t)entry.uint64 + (INT8_MIN + 1);
                    intptr_t ub = (intptr_t)entry.uint64 + (INT8_MAX - 1);
                    lb -= size;
                    ub -= size;
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                continue;
            }
            case ENTRY_REL32:
            {
                size += sizeof(int32_t);
                if (!entry.use_label)
                {
                    intptr_t lb = (intptr_t)entry.uint64 + (INT32_MIN + 1);
                    intptr_t ub = (intptr_t)entry.uint64 + (INT32_MAX - 1);
                    lb -= size;
                    ub -= size;
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                continue;
            }
            case ENTRY_INSTRUCTION:
            {
                int r = relocateInstr(I->addr, /*offset=*/0, I->original.bytes,
                    I->size, I->pic, nullptr);
                size += (r < 0? 0: r);
                continue;
            }
            case ENTRY_INSTRUCTION_BYTES:
                size += I->size;
                continue;
            case ENTRY_CONTINUE:
                size += buildContinue(B, I, /*offset=*/0, nullptr);
                continue;
            case ENTRY_TAKEN:
                size += /*sizeof(jmpq)=*/5;
                continue;
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
    getTrampolineBounds(B, T, I, /*depth=*/0, /*size=*/0, b);
    return b;
}

/*
 * Build the set of labels.
 */
static off_t buildLabelSet(const Binary *B, const Trampoline *T,
    const Instr *I, off_t offset, LabelSet &labels)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_DEBUG:
                offset += (I != nullptr && I->debug? /*sizeof(int3)=*/1: 0);
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                offset += entry.length;
                continue;
            case ENTRY_INT8:
                offset += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                offset += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                offset += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                offset += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
            {
                auto i = labels.find(entry.label);
                if (i != labels.end())
                    error("failed to build trampoline; duplicate label "
                        "\"%s\"", entry.label);
                labels.insert(std::make_pair(entry.label, offset));
                continue;
            }
            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                if (U == nullptr)
                    error("failed to build trampoline; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                offset = buildLabelSet(B, U, I, offset, labels);
                continue;
            }
            case ENTRY_REL8:
                offset += sizeof(int8_t);
                continue;
            case ENTRY_REL32:
                offset += sizeof(int32_t);
                continue;
            case ENTRY_INSTRUCTION:
                offset += relocateInstr(I->addr, /*offset=*/0,
                    I->original.bytes, I->size, I->pic, nullptr);
                continue;
            case ENTRY_INSTRUCTION_BYTES:
                offset += I->size;
                continue;
            case ENTRY_CONTINUE:
                offset += buildContinue(B, I, /*offset=*/0, nullptr);
                continue;
            case ENTRY_TAKEN:
                offset += /*sizeof(jmpq)=*/5;
                continue;
        }
    }
    return offset;
}

/*
 * Lookup a label value.
 */
static off_t lookupLabel(const char *label, const Instr *I, int32_t offset32,
    const LabelSet &labels)
{
    if (label[0] != '.' && label[1] != 'L')
        error("failed to build trampoline; unknown prefix for \"%s\" label",
            label);

    // Check for "builtin" labels:
    switch (label[2])
    {
        case 'c':
            if (strcmp(label, ".Lcontinue") == 0)
                return (I == nullptr? 0: (off_t)I->size - (off_t)offset32);
            break;
        case 'i':
            if (strcmp(label, ".Linstruction") == 0)
                return -(off_t)offset32;
            break;
        case 't':
            if (strcmp(label, ".Ltaken") == 0)
            {
                if (I == nullptr)
                    return 0;
                intptr_t target = getJccTarget(I->addr, I->original.bytes,
                    I->size);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\".Ltaken\")", I->addr);
                off_t offset = (off_t)offset32 + (I->addr - target);
                return offset;
            }
            break;
    }

    // Check for user labels:
    auto i = labels.find(label);
    if (i == labels.end())
        error("failed to build trampoline; unknown label \"%s\"", label); 
    return i->second;
}

/*
 * Build the trampoline bytes.
 */
static void buildBytes(const Binary *B, const Trampoline *T,
    const Instr *I, int32_t offset32, const LabelSet &labels, Buffer &buf)
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
            case ENTRY_INT8:
                buf.push(entry.uint8);
                break;
            case ENTRY_INT16:
                buf.push((uint8_t *)&entry.uint16, sizeof(entry.uint16));
                break;
            case ENTRY_INT32:
                buf.push((uint8_t *)&entry.uint32, sizeof(entry.uint32));
                break;
            case ENTRY_INT64:
                buf.push((uint8_t *)&entry.uint64, sizeof(entry.uint64));
                break;
 
            case ENTRY_LABEL:
                continue;

            case ENTRY_MACRO:
            {
                const Trampoline *U = expandMacro(B, I->metadata,
                    entry.macro);
                assert(U != nullptr);
                buildBytes(B, U, I, offset32, labels, buf);
                continue;
            }

            case ENTRY_REL8:
            case ENTRY_REL32:
            {
                off_t rel = 0;
                if (entry.use_label)
                {
                    rel = lookupLabel(entry.label, I, offset32, labels);
                    rel = rel - (buf.size() +
                        (entry.kind == ENTRY_REL8? sizeof(int8_t):
                                                   sizeof(int32_t)));
                }
                else
                {
                    intptr_t addr = I->addr + (intptr_t)offset32 +
                        buf.size() +
                        (entry.kind == ENTRY_REL8? sizeof(int8_t):
                                                   sizeof(int32_t));
                    rel = (intptr_t)entry.uint64 - addr;
                }
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

            case ENTRY_INSTRUCTION:
            {
                buf.i += relocateInstr(I->addr, offset32 + buf.size(),
                    I->original.bytes, I->size, I->pic, buf.bytes + buf.i);
                continue;
            }

            case ENTRY_INSTRUCTION_BYTES:
                buf.push(I->original.bytes, I->size);
                break;
        
            case ENTRY_CONTINUE:
                (void)buildContinue(B, I, offset32 + buf.size(), &buf);
                break;

            case ENTRY_TAKEN:
            {
                intptr_t target = getJccTarget(I->addr, I->original.bytes,
                    I->size);
                if (target == INTPTR_MIN)
                    error("failed to build trampoline; instruction at address "
                        "0x%lx is not a conditional branch (as required by "
                        "\"$taken\")", I->addr);
                off_t rel = (off_t)offset32 + buf.size() + /*sizeof(jmpq)=*/5;
                rel = -rel + (target - I->addr);

                buf.push(/*jmpq opcode=*/0xE9);
                assert(rel >= INT32_MIN);
                assert(rel <= INT32_MAX);
                int32_t rel32 = (int32_t)rel;
                buf.push((const uint8_t *)&rel32, sizeof(rel32));
                break;
            }
        }
    }
}

/*
 * Flatten a trampoline into a memory buffer.
 */
void flattenTrampoline(const Binary *B, uint8_t *bytes, size_t size,
    int32_t offset32, const Trampoline *T, const Instr *I)
{
    LabelSet labels;
    off_t offset = buildLabelSet(B, T, I, /*offset=*/0, labels);
    if ((size_t)offset > size)
        error("failed to flatten trampoline for instruction at address 0x%lx; "
            "buffer size (%zu) exceeds the trampoline size (%zu)",
            I->addr, (size_t)offset, size);

    // Note: it is possible for the offset to be smaller than the size.
    //       This occurs when the trampoline size was calculated under the
    //       assumption that instructions can be relocated for -Ojump-delay,
    //       however the assumption fails when real offsets are used
    //       (after the trampoline is placed).  This wastes a few bytes but
    //       is otherwise harmless.

    Buffer buf(bytes, offset);
    buildBytes(B, T, I, offset32, labels, buf);
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
                if (entry_a->use_label != entry_b->use_label)
                    return (entry_a->use_label < entry_b->use_label);
                if (entry_a->use_label)
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
            case ENTRY_INT8:
                if (entry_a->uint8 != entry_b->uint8)
                    return (entry_a->uint8 < entry_b->uint8);
                break;
            case ENTRY_INT16:
                if (entry_a->uint16 != entry_b->uint16)
                    return (entry_a->uint16 < entry_b->uint16);
                break;
            case ENTRY_INT32:
                if (entry_a->uint32 != entry_b->uint32)
                    return (entry_a->uint32 < entry_b->uint32);
                break;
            case ENTRY_INT64:
                if (entry_a->uint64 != entry_b->uint64)
                    return (entry_a->uint64 < entry_b->uint64);
                break;
            case ENTRY_DEBUG: case ENTRY_INSTRUCTION:
            case ENTRY_INSTRUCTION_BYTES: case ENTRY_CONTINUE:
            case ENTRY_TAKEN:
                break;
        }
    }
    return false;
}

