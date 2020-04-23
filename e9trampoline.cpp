/*
 * e9trampoline.cpp
 * Copyright (C) 2020 National University of Singapore
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
 * Bounds information.
 */
struct BoundsInfo
{
    size_t size;
    intptr_t lb;
    intptr_t ub;
};

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
static Trampoline *expandMacro(const Metadata *meta, const char *name)
{
    if (meta == nullptr)
        return nullptr;
    ssize_t lo = 0, hi = (ssize_t)meta->num_entries-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        int cmp = strcmp(name, meta->entries[mid]->name);
        if (cmp == 0)
            return meta->entries[mid];
        else if (cmp < 0)
            hi = mid - 1;
        else
            lo = mid + 1;
    }
    return nullptr;
}

/*
 * Calculate trampoline size.
 * Returns (-1) if the trampoline cannot be constructed.
 */
static int getTrampolineSize(const Trampoline *T, const Instr *I,
    unsigned depth)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline size ; maximum macro expansion depth "
            "(%u) exceeded", MACRO_DEPTH_MAX);
    unsigned size = 0;
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
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
                Trampoline *U = expandMacro(I->metadata, entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline size; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                size += getTrampolineSize(U, I, depth+1);
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
int getTrampolineSize(const Trampoline *T, const Instr *I)
{
    return getTrampolineSize(T, I, /*depth=*/0);
}

/*
 * Calculate trampoline bounds.
 */
static BoundsInfo getTrampolineBounds(const Trampoline *T, const Instr *I,
    unsigned depth)
{
    if (depth > MACRO_DEPTH_MAX)
        error("failed to get trampoline bounds ; maximum macro expansion "
            "depth (%u) exceeded", MACRO_DEPTH_MAX);
    BoundsInfo b =
    {
        .size = 0,
        .lb   = INTPTR_MIN,
        .ub   = INTPTR_MAX
    };
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
            case ENTRY_BYTES:
            case ENTRY_ZEROES:
                b.size += entry.length;
                continue;
            case ENTRY_INT8:
                b.size += sizeof(uint8_t);
                continue;
            case ENTRY_INT16:
                b.size += sizeof(uint16_t);
                continue;
            case ENTRY_INT32:
                b.size += sizeof(uint32_t);
                continue;
            case ENTRY_INT64:
                b.size += sizeof(uint64_t);
                continue;
            case ENTRY_LABEL:
                continue;
            case ENTRY_MACRO:
            {
                Trampoline *U = expandMacro(I->metadata, entry.macro);
                if (U == nullptr)
                    error("failed to get trampoline bounds; metadata for "
                        "macro \"%s\" is missing", entry.macro);
                BoundsInfo c = getTrampolineBounds(U, I, depth+1);
                b.size += c.size;
                b.lb    = std::max(b.lb, c.lb);
                b.ub    = std::min(b.ub, c.ub);
                continue;
            }
            case ENTRY_REL8:
            {
                if (!entry.use_label)
                {
                    intptr_t lb = (intptr_t)entry.uint64 + (INT8_MIN + 1);
                    intptr_t ub = (intptr_t)entry.uint64 + (INT8_MAX - 1);
                    lb -= b.size + sizeof(int8_t);
                    ub -= b.size + sizeof(int8_t);
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                b.size += sizeof(int8_t);
                continue;
            }
            case ENTRY_REL32:
            {
                if (!entry.use_label)
                {
                    intptr_t lb = (intptr_t)entry.uint64 + (INT32_MIN + 1);
                    intptr_t ub = (intptr_t)entry.uint64 + (INT32_MAX - 1);
                    lb -= b.size + sizeof(int32_t);
                    ub -= b.size + sizeof(int32_t);
                    b.lb = std::max(b.lb, lb);
                    b.ub = std::min(b.ub, ub);
                }
                b.size += sizeof(int32_t);
                continue;
            }
            case ENTRY_INSTRUCTION:
            {
                int r = relocateInstr(I->addr, /*offset=*/0, I->original.bytes,
                    I->size, I->pic, nullptr);
                b.size += (r < 0? 0: r);
                continue;
            }
            case ENTRY_INSTRUCTION_BYTES:
                b.size += I->size;
                continue;
            case ENTRY_CONTINUE:
            case ENTRY_TAKEN:
                b.size += /*sizeof(jmpq)=*/5;
                continue;
        }
    }
    return b;
}

/*
 * Calculate trampoline bounds.
 */
Bounds getTrampolineBounds(const Trampoline *T, const Instr *I)
{
    if (T == evicteeTrampoline)
        return {INTPTR_MIN, INTPTR_MAX};
    BoundsInfo b = getTrampolineBounds(T, I, /*depth=*/0);
    return {b.lb, b.ub};
}

/*
 * Build the set of labels.
 */
static off_t buildLabelSet(const Trampoline *T, const Instr *I, off_t offset,
    LabelSet &labels)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
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
                Trampoline *U = expandMacro(I->metadata, entry.macro);
                if (U == nullptr)
                    error("failed to build trampoline; metadata for macro "
                        "\"%s\" is missing", entry.macro);
                offset = buildLabelSet(U, I, offset, labels);
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
static void buildBytes(const Trampoline *T, const Instr *I,
    int32_t offset32, const LabelSet &labels, Buffer &buf)
{
    for (unsigned i = 0; i < T->num_entries; i++)
    {
        const Entry &entry = T->entries[i];
        switch (entry.kind)
        {
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
                Trampoline *U = expandMacro(I->metadata, entry.macro);
                assert(U != nullptr);
                buildBytes(U, I, offset32, labels, buf);
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
                            "is out-of-range (%d..%d)", rel, INT8_MIN,
                            INT8_MAX);
                    int8_t rel8 = (int8_t)rel;
                    buf.push((uint8_t)rel8);
                }
                else
                {
                    if (rel < INT32_MIN || rel > INT32_MAX)
                        error("failed to build trampoline; rel32 value (%zd) "
                            "is out-of-range (%zd..%zd)", rel, INT32_MIN,
                            INT32_MAX);
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
            {
                off_t rel = (off_t)offset32 + buf.size() + /*sizeof(jmpq)=*/5;
                rel = -rel + (off_t)I->size;
 
                // Skip unconditional jump instructions if possible.
                const Instr *J = I->next;
                if (J != nullptr && I->addr + I->size == J->addr)
                {
                    intptr_t target = J->trampoline;
                    target = (target != INTPTR_MIN? target:
                        getJumpTarget(J->addr, J->patched.bytes, J->size));
                    if (target != INTPTR_MIN)
                    {
                        // Next instruction is an unconditional jump, so we
                        // can instead jump directly to the target.
                        off_t rel_target = rel + (target - J->addr);
                        if (rel_target >= INT32_MIN && rel_target <= INT32_MAX)
                        {
                            debug("bypass 0x%lx and jump directly to "
                                ADDRESS_FORMAT, J->addr, ADDRESS(target));
                            rel = rel_target;
                        }
                    }
                }

                buf.push(/*jmpq opcode=*/0xE9);
                assert(rel >= INT32_MIN);
                assert(rel <= INT32_MAX);
                int32_t rel32 = (int32_t)rel;
                buf.push((const uint8_t *)&rel32, sizeof(rel32));
                break;
            }

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
void flattenTrampoline(uint8_t *bytes, size_t size, int32_t offset32,
    const Trampoline *T, const Instr *I)
{
    LabelSet labels;
    off_t offset = buildLabelSet(T, I, /*offset=*/0, labels);
    if ((size_t)offset != size)
    error("failed to flatten trampoline; buffer size (%zu) does not "
        "trampoline size (%zu)", (size_t)offset, size);

    Buffer buf(bytes, size);
    buildBytes(T, I, offset32, labels, buf);
}

