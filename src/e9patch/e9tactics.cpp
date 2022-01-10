/*
 * e9tactics.cpp
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
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include "e9alloc.h"
#include "e9optimize.h"
#include "e9patch.h"
#include "e9tactics.h"
#include "e9trampoline.h"

#define JMP_REL32_SIZE      sizeof(int32_t)
#define JMP_SIZE            (/*jmpq opcode=*/1 + JMP_REL32_SIZE)
#define PREFIX_MAX          (JMP_SIZE - 1)
#define PATCH_MAX           32

#define SHORT_JMP_MAX       INT8_MAX
#define SHORT_JMP_MIN       INT8_MIN

/*
 * This code uses short variable names.  See here for the key:
 *
 * A     = a virtual address space allocation (Alloc)
 * B     = the input binary to be rewritten (Binary)
 * I,J,K = instructions (Instr)
 * P,Q   = patches (Patch)
 * T,U   = trampoline (Trampoline)
 */

enum Tactic
{
    TACTIC_B1,                          // Jump.
    TACTIC_B2,                          // Punned jump.
    TACTIC_T1,                          // Prefixed punned jump.
    TACTIC_T2,                          // Successor eviction.
    TACTIC_T3                           // Neighbour eviction.
};

/*
 * Representation of a patch.
 */
struct Patch
{
    const Alloc *A;                     // Virtual address space allocation.
    Instr * const I;                    // Instruction.
    Tactic tactic;                      // Tactic used.
    const struct Original
    {
        bool is_patched;                // Original is_patched?
        uint8_t state[PATCH_MAX];       // Original state bytes.
        uint8_t bytes[PATCH_MAX];       // Original data bytes.

        Original(const Instr *I) : is_patched(I->is_patched)
        {
            memcpy(state, I->patched.state, PATCH_MAX);
            memcpy(bytes, I->patched.bytes, PATCH_MAX);
        }
    } original;
    Patch *next = nullptr;              // Next dependent patch.

    Patch(Instr *I, Tactic t, const Alloc *A = nullptr) :
        A(A), I(I), tactic(t), original(I)
    {
        // TODO: fix stateful update in constructor
        I->is_patched = true;
        if (A != nullptr && A->T == evicteeTrampoline)
            I->is_evicted = true;
    }
};

/*
 * Convert a tactic to a string.
 */
static const char *getTacticName(Tactic tactic)
{
    switch (tactic)
    {
        case TACTIC_B1:
            return "B1";
        case TACTIC_B2:
            return "B2";
        case TACTIC_T1:
            return "T1";
        case TACTIC_T2:
            return "T2";
        case TACTIC_T3:
            return "T3";
        default:
            return "???";
    }
}

/*
 * Find successor instruction.
 */
static Instr *successor(const Instr *I)
{
    Instr *J = I->next;
    if (J == nullptr)
        return nullptr;
    return (I->addr + I->size == J->addr? J: nullptr);
}

/*
 * Commit a patch.
 */
static void commit(Binary &B, Patch *P)
{
    switch (P->tactic)
    {
        case TACTIC_B1:
            stat_num_B1++;
            break;
        case TACTIC_B2:
            stat_num_B2++;
            break;
        case TACTIC_T1:
            stat_num_T1++;
            break;
        case TACTIC_T2:
            stat_num_T2++;
            break;
        case TACTIC_T3:
            stat_num_T3++;
            break;
    }

    while (P != nullptr)
    {
        if (P->A != nullptr)
            setTrampolineEntry(B.Es, P->I, P->A->lb + P->A->entry);

        // Delete the P (we do not need it anymore)
        Patch *Q = P;
        P = P->next;
        delete Q;
    }
}

/*
 * Undo the application of a patch.
 */
static void undo(Binary &B, Patch *P)
{
    while (P != nullptr)
    {
        P->I->is_patched = P->original.is_patched;
        P->I->is_evicted = false;
        for (unsigned i = 0; i < PATCH_MAX; i++)
        {
            P->I->patched.state[i] = P->original.state[i];
            P->I->patched.bytes[i] = P->original.bytes[i];
        }
        deallocate(&B, P->A);
        Patch *Q = P;
        P = P->next;
        delete Q;
    }
}

/*
 * Calculate trampoline bounds.
 */
static Bounds makeBounds(Binary &B, const Trampoline *T, const Instr *I,
    const Instr *J, unsigned prefix)
{
    // Step (1): Calculate the mask to protect overlapping instructions:
    assert(prefix < I->size);
    size_t size = prefix + 1;
    for (; size < I->size &&
            (I->patched.state[size] == STATE_INSTRUCTION ||
             I->patched.state[size] == STATE_FREE); size++)
        ;
    assert(prefix < size);
    size_t diff = size - prefix - /*sizeof(jmpq opcode)=*/1;

    // Step (2): Calculate the minimum and maximum jmpq rel32 values:
    int32_t rel32_lo, rel32_hi;
    if (diff >= sizeof(int32_t))
    {
        rel32_lo = INT32_MIN;
        rel32_hi = INT32_MAX;
    }
    else
    {
        uint32_t mask = 0xFFFFFFFFu << (8 * diff);
        uint32_t urel32 =
          *(uint32_t *)(I->patched.bytes + prefix + /*sizeof(jmpq opcode)=*/1);
        uint32_t urel32_lo = urel32 & mask;
        uint32_t urel32_hi = urel32_lo | (0xFFFFFFFFu & ~mask);
        rel32_lo = (int32_t)urel32_lo;
        rel32_hi = (int32_t)urel32_hi;
    }

    // Step (3): Calculate the minimum/maximum jump target address:
    intptr_t jmp_from = I->addr + prefix + JMP_SIZE;
    intptr_t jmp_lo = jmp_from + rel32_lo;
    intptr_t jmp_hi = jmp_from + rel32_hi;
    if (jmp_lo > jmp_hi)
    {
        intptr_t tmp = jmp_lo;
        jmp_lo = jmp_hi;
        jmp_hi = tmp;
    }
    intptr_t lo = jmp_lo;
    intptr_t hi = jmp_hi;

    // Step (4): Trampoline must be within a 32bit offset of a return address.
    intptr_t addr_lo = jmp_from - (intptr_t)INT32_MAX;
    intptr_t addr_hi = jmp_from - (intptr_t)INT32_MIN;
    addr_hi -= TRAMPOLINE_MAX;
    lo = std::max(lo, addr_lo);
    hi = std::min(hi, addr_hi);

    // Step (5): The trampoline itself may have bounds.
    Bounds b = getTrampolineBounds(&B, T, J);
    lo = std::max(lo, b.lb);
    hi = std::min(hi, b.ub);

    // Step (6): If the instruction is position-dependent, the trampoline
    // must be withing a 32bit offset of the target address.
    if (I->pcrel32_idx != 0 || I->pcrel8_idx != 0)
    {
        intptr_t pcrel;
        if (I->pcrel32_idx != 0)
            pcrel = *(const int32_t *)(I->original.bytes + I->pcrel32_idx);
        else
            pcrel = (int8_t)I->original.bytes[I->pcrel32_idx];
        intptr_t target = I->addr + I->size + pcrel;
        intptr_t target_lo = target - (intptr_t)INT32_MAX;
        intptr_t target_hi = target - (intptr_t)INT32_MIN;
        target_hi -= TRAMPOLINE_MAX;
        lo = std::max(lo, target_lo);
        hi = std::min(hi, target_hi);
    }

    // Step (7): Apply the user-specified bounds (if any).
    lo = std::max(lo, option_mem_lb);
    hi = std::min(hi, option_mem_ub);
    switch (B.mode)
    {
        case MODE_ELF_EXE: case MODE_ELF_DSO:
            hi = std::min(hi, option_loader_base);
        default:
            break;
    }
 
    return {lo, hi};
}

/*
 * Allocate virtual address space for a punned jump.
 */
static const Alloc *allocatePunnedJump(Binary &B, const Instr *I,
    unsigned prefix, const Instr *J, const Trampoline *T)
{
    for (unsigned i = 0; i <= /*sizeof(jmpq)=*/5; i++)
        if (I->patched.state[prefix + i] == STATE_QUEUED)
            return nullptr;
    auto b = makeBounds(B, T, I, J, prefix);
    return allocate(&B, b.lb, b.ub, T, J, !option_mem_multi_page);
}

/*
 * Allocate virtual address space for a non-punned jump.
 */
static const Alloc *allocateJump(Binary &B, const Instr *I,
    const Trampoline *T)
{
    return allocatePunnedJump(B, I, /*prefix=*/0, I, T);
}

/*
 * Patch in a (redundant) jmp instruction prefix.
 */
static void patchJumpPrefix(Patch *P, unsigned prefix)
{
    // TODO: support other prefixes/encodings/NOPs
    const uint8_t prefixes[] = {0x48, 0x26, 0x36, 0x3E};
    assert(prefix < P->I->size && prefix <= sizeof(prefixes));

    uint8_t *bytes = P->I->patched.bytes, *state = P->I->patched.state;
    for (unsigned i = 0; i < prefix; i++)
    {
        assert(state[i] == STATE_INSTRUCTION);
        bytes[i] = prefixes[i];
        state[i] = STATE_PATCHED;
    }
}

/*
 * Patch in a jmpq instruction.
 */
static void patchJump(Patch *P, unsigned offset)
{
    assert(offset <= PATCH_MAX - JMP_SIZE);
    assert(offset < P->I->size);
    assert(P->A != nullptr);
     
    intptr_t diff = (P->A->lb + P->A->entry) -
        (P->I->addr + offset + JMP_SIZE);
    assert(diff >= INT32_MIN && diff <= INT32_MAX);
    int32_t rel32 = (int32_t)diff;
    
    uint8_t *bytes = P->I->patched.bytes + offset,
            *state = P->I->patched.state + offset;
    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = /*jmpq opcode=*/0xE9;
    *state++ = STATE_PATCHED;
    offset++;

    const uint8_t *rel32p8 = (uint8_t *)&rel32;
    unsigned i = 0;
    for (; i < sizeof(rel32) && offset + i < P->I->size; i++)
    {
        assert(state[i] == STATE_INSTRUCTION || state[i] == STATE_FREE ||
            (state[i] == STATE_PATCHED && bytes[i] == rel32p8[i]));
        bytes[i] = rel32p8[i];
        state[i] = STATE_PATCHED;
    }
    for (; i < sizeof(rel32); i++)
    {
        assert(state[i] != STATE_QUEUED);
        assert(rel32p8[i] == bytes[i]);
        state[i] |= STATE_LOCKED;
    }
}

/*
 * Patch in a short jmp instruction.
 */
static void patchShortJump(Patch *P, intptr_t addr)
{
    intptr_t diff = addr - (P->I->addr + /*sizeof(short jmp)=*/2);
    assert(diff >= INT8_MIN && diff <= INT8_MAX);
    int8_t rel8 = (int8_t)diff;

    uint8_t *bytes = P->I->patched.bytes,
            *state = P->I->patched.state;

    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = /*short jmp opcode=*/0xEB;
    *state++ = STATE_PATCHED;

    assert(*state == STATE_INSTRUCTION || *state == STATE_FREE);
    *bytes++ = (uint8_t)rel8;
    *state++ = STATE_PATCHED;
}

/*
 * Patch in unused memory.
 */
static void patchUnused(Patch *P, unsigned offset)
{
    assert(offset <= P->I->size);
    for (unsigned i = offset; i < P->I->size; i++)
    {
        if (P->I->patched.state[i] == STATE_INSTRUCTION)
        {
            P->I->patched.bytes[i] = /*int3=*/0xcc;
            P->I->patched.state[i] = STATE_FREE;
        }
    }
}

/*
 * Return true if the given instruction can be instrumented.
 */
static bool canInstrument(const Instr *I)
{
    return (I->patched.state[0] == STATE_INSTRUCTION);
}

/*
 * Tactic B1: replace the instruction with a jump.
 */
static Patch *tactic_B1(Binary &B, Instr *I, const Trampoline *T,
    Tactic tactic = TACTIC_B1)
{
    if (I->size < JMP_SIZE || !option_tactic_B1 || !canInstrument(I))
        return nullptr;
    const Alloc *A = allocateJump(B, I, T);
    if (A == nullptr)
        return nullptr;
    Patch *P = new Patch(I, tactic, A);
    patchJump(P, /*offset=*/0);
    patchUnused(P, /*offset=sizeof(jmpq)=*/5);
    return P;
}

/*
 * Tactic B2: replace the instruction with a punned jump.
 */
static Patch *tactic_B2(Binary &B, Instr *I, const Trampoline *T,
    Tactic tactic = TACTIC_B2)
{
    if (I->size >= JMP_SIZE || !option_tactic_B2 || !canInstrument(I))
        return nullptr;
    const Alloc *A = allocatePunnedJump(B, I, /*offset=*/0, I, T);
    if (A == nullptr)
        return nullptr;
    Patch *P = new Patch(I, tactic, A);
    patchJump(P, /*offset=*/0);
    return P;
}

/*
 * Tactic T1: replace the instruction with a prefixed punned jump.
 */
static Patch *tactic_T1(Binary &B, Instr *I, const Trampoline *T,
    Tactic tactic = TACTIC_T1)
{
    if (I->size >= JMP_SIZE || !option_tactic_T1 || !canInstrument(I))
        return nullptr;
    for (unsigned prefix = 1;
            prefix < I->size && prefix < JMP_REL32_SIZE && 
                (I->patched.state[prefix] == STATE_INSTRUCTION ||
                 I->patched.state[prefix] == STATE_FREE);
            prefix++)
    {
        const Alloc *A = allocatePunnedJump(B, I, prefix, I, T);
        if (A != nullptr)
        {
            Patch *P = new Patch(I, tactic, A);
            patchJumpPrefix(P, prefix);
            patchJump(P, prefix);
            return P;
        }
    }
    return nullptr;
}

/*
 * Tactic T2: evict the successor instruction.
 */
static Patch *tactic_T2(Binary &B, Instr *I, const Trampoline *T)
{
    if (I->size >= JMP_SIZE || !option_tactic_T2 || !canInstrument(I))
        return nullptr;

    // Step (1): Evict the successor instruction:
    Instr *J = successor(I);
    if (J == nullptr || !canInstrument(J))
        return nullptr;
    const Trampoline *U = evicteeTrampoline;
    Patch *Q = nullptr;
    Q = (Q == nullptr? tactic_B2(B, J, U, TACTIC_T2): Q);
    Q = (Q == nullptr? tactic_T1(B, J, U, TACTIC_T2): Q);
    if (Q == nullptr)
        return nullptr;

    // Step (2): Patch the instruction:
    Patch *P = nullptr;
    P = (P == nullptr? tactic_B2(B, I, T, TACTIC_T2): P);
    P = (P == nullptr? tactic_T1(B, I, T, TACTIC_T2): P);

    if (P == nullptr)
    {
        undo(B, Q);
        return nullptr;
    }
    P->tactic = TACTIC_T2;
    P->next   = Q;

    return P;
}

/*
 * Tactic T3 (single-byte instruction): evict a neighbour instruction.
 */
static Patch *tactic_T3b(Binary &B, Instr *I, const Trampoline *T)
{
    // We can still use T3 on single-byte instructions, only if the next
    // byte interpreted as a short jmp rel8 happens to land in a suitable
    // location.

    if (I->size != 1 || !option_tactic_T3 || !canInstrument(I))
        return nullptr;
    Instr *J = I->next;
    if (J == nullptr || I->addr + I->size != J->addr)
        return nullptr;
    switch (J->patched.state[0])
    {
        case STATE_INSTRUCTION:
            break;
        default:
            return nullptr;
    }
    int8_t rel8 = (int8_t)J->patched.bytes[0];
    if (!option_tactic_backward_T3 && rel8 < 1)
        return nullptr;
    intptr_t target = I->addr + /*sizeof(short jmp)=*/2 + (intptr_t)rel8;
    if (target >= I->addr)
    {
        for (; J != nullptr && J->addr + J->size <= target; J = J->next)
            ;
    }
    else
    {
        for (J = I->prev; J != nullptr && J->addr > target; J = J->prev)
            ;
    }
    if (J == nullptr || target <= J->addr ||
            (J->addr < I->addr && J->addr + J->size > I->addr))
        return nullptr;
    unsigned i = target - J->addr;
    uint8_t state = J->patched.state[i];
    Patch *P = nullptr;
    const Alloc *A = nullptr;
    switch (state)
    {
        case STATE_INSTRUCTION:
        case STATE_FREE:
        {
            bool save = (bool)J->no_optimize;
            if (target < I->addr)
                J->no_optimize = true;
            A = allocatePunnedJump(B, J, i, I, T);
            if (A == nullptr)
            {
                J->no_optimize = save;
                return nullptr;
            }
            P = new Patch(J, TACTIC_T3, A);
            patchJump(P, i);
            if (state == STATE_FREE)
            {
                // J is already patched. so we are done.
                P->A = nullptr;
                break;
            }
            
            // Step (2b): Attempt to evict J
            const Trampoline *U = evicteeTrampoline;
            Patch *Q = nullptr;
            Q = (Q == nullptr? tactic_B1(B, J, U, TACTIC_T3): Q);
            Q = (Q == nullptr? tactic_B2(B, J, U, TACTIC_T3): Q);
            Q = (Q == nullptr? tactic_T1(B, J, U, TACTIC_T3): Q);
            if (Q == nullptr)
            {
                // Eviction failed...
                J->no_optimize = save;
                undo(B, P);
                return nullptr;
            }
            Q->next = P;
            P->A = nullptr;
            P = Q;
            break;
        }
        default:
            return nullptr;
    }

    assert(A != nullptr);
    Patch *Q = new Patch(I, TACTIC_T3, A);
    assert(I->patched.state[0] == STATE_INSTRUCTION);
    I->patched.state[0] = STATE_PATCHED;
    I->patched.bytes[0] = /*short jmp opcode=*/0xEB;
    I->next->patched.state[0] |= STATE_LOCKED;
    Q->next = P;
    return Q;
}

/*
 * Tactic T3: evict a neighbour instruction.
 */
static Patch *tactic_T3(Binary &B, Instr *I, const Trampoline *T)
{
    if (I->size == 1)
        return tactic_T3b(B, I, T);
    if (I->size >= JMP_SIZE || !option_tactic_T3 || !canInstrument(I))
        return nullptr;

    // Step (1): find nearest instruction at +SHORT_JMP_MAX (or
    // -SHORT_JMP_MIN) bytes ahead.
    Instr *J = I;
    while (true)
    {
        Instr *K = J->next;
        if (K == nullptr)
            break;
        if (K->addr - (I->addr + /*sizeof(short jmp)=*/2) > SHORT_JMP_MAX)
            break;
        J = K;
    }

    // Step (2): Iterate through all neighbour instructions:
    Patch *P = nullptr;
    const Alloc *A = nullptr;
    intptr_t addr = 0;
    for (; P == nullptr; J = J->prev)
    {
        if (J == I)
            continue;
        if (J == nullptr)
            break;
        if (!option_tactic_backward_T3 && J->addr < I->addr)
            break;
        if ((I->addr + /*sizeof(short jmp)=*/2) - (J->addr + J->size -1) >
                -SHORT_JMP_MIN)
        {
            // Out-of-range, so give up... :(
            break;
        }

        switch (J->patched.state[0])
        {
            case STATE_INSTRUCTION:
                break;
            case STATE_PATCHED:
            case STATE_PATCHED | STATE_LOCKED:
            {
                if (J->patched.state[J->size-1] == STATE_FREE)
                    break;
                continue;
            }
            default:
                continue;
        }

        for (int i = (int)J->size - 1; i >= 1 && P == nullptr; i--)
        {
            if (J->addr > I->addr &&
                (J->addr + i) - (I->addr + /*sizeof(short jmp)=*/2) >
                    SHORT_JMP_MAX)
            {
                // Out-of-range
                continue;
            }
            if (J->addr < I->addr &&
                (I->addr + /*sizeof(short jmp)=*/2) - (J->addr + i) >
                    -SHORT_JMP_MIN)
            {
                // Out-of-range
                break;
            }
            if (J->addr < I->addr &&
                    I->addr - (J->addr + i) < /*sizeof(jmpq)=*/5)
            {
                // Cannot overlap with short jump.
                continue;
            }

            uint8_t state = J->patched.state[i];
            switch (state)
            {
                case STATE_FREE:
                case STATE_INSTRUCTION:
                {
                    // Step (2a): Attempt to insert a jump here:
                    bool save = J->no_optimize;
                    if (J->addr < I->addr)
                        J->no_optimize = true;
                    A = allocatePunnedJump(B, J, i, I, T);
                    if (A == nullptr)
                    {
                        J->no_optimize = save;
                        continue;
                    }
                    addr = J->addr + i;
                    P = new Patch(J, TACTIC_T3, A);
                    patchJump(P, i);
                    if (state == STATE_FREE)
                    {
                        // J is already patched. so we are done.
                        P->A = nullptr;
                        continue;
                    }
                    
                    // Step (2b): Attempt to evict J
                    const Trampoline *U = evicteeTrampoline;
                    Patch *Q = nullptr;
                    Q = (Q == nullptr? tactic_B1(B, J, U, TACTIC_T3): Q);
                    Q = (Q == nullptr? tactic_B2(B, J, U, TACTIC_T3): Q);
                    Q = (Q == nullptr? tactic_T1(B, J, U, TACTIC_T3): Q);
                    if (Q == nullptr)
                    {
                        // Eviction failed...
                        J->no_optimize = save;
                        undo(B, P);
                        P = nullptr;
                        continue;
                    }
                    Q->next = P;
                    P->A = nullptr;
                    P = Q;
                    continue;
                }
                default:
                    continue;
            }
        }
    }
    if (P == nullptr)
        return nullptr;             // T3 failed

    // Step (3): Insert a short jump to the trampoline jump:
    assert(A != nullptr);
    Patch *Q = new Patch(I, TACTIC_T3, A);
    patchShortJump(Q, addr);
    patchUnused(Q, /*sizeof(short jmp)=*/2);
    Q->next = P;
    return Q;
}

/*
 * Patch the instruction at the given offset.
 */
bool patch(Binary &B, Instr *I, const Trampoline *T)
{
    switch (I->patched.state[0])
    {
        case STATE_INSTRUCTION:
            break;
        default:
            error("failed to patch instruction 0x%lx (%zu) with invalid "
                "state (0x%.2X) (maybe \"patch\" messages are not sent "
                "in reverse order?)", I->addr, I->size,
                I->patched.state[0]);
    }

    // Try all patching tactics in order B1/B2/T1/T2/T3:
    Patch *P = nullptr;
    if (P == nullptr)
        P = tactic_B1(B, I, T);
    if (P == nullptr)
        P = tactic_B2(B, I, T);
    if (P == nullptr)
        P = tactic_T1(B, I, T);
    if (P == nullptr)
        P = tactic_T2(B, I, T);
    if (P == nullptr)
        P = tactic_T3(B, I, T);

    if (P == nullptr)
    {
        debug("failed to patch instruction at address 0x%lx (%zu)", I->addr,
            I->size);
        log(COLOR_RED, 'X');
        return false;       // Failed :(
    }

    commit(B, P);
    if (option_debug)
    {
        intptr_t entry = getTrampolineEntry(B.Es, I);
        intptr_t lb    = entry - getTrampolinePrologueSize(&B, I);
        intptr_t ub    = entry + getTrampolineSize(&B, T, I);
        debug("patched instruction 0x%lx [size=%zu, tactic=%s, "
            "entry=" ADDRESS_FORMAT ", "
            "trampoline=" ADDRESS_FORMAT ".." ADDRESS_FORMAT ", "
            "offset=%zd]",
            I->addr, I->size, getTacticName(P->tactic), 
            ADDRESS(entry), ADDRESS(lb), ADDRESS(ub),
            (ssize_t)(entry - lb));
    }
    log(COLOR_GREEN, '.');
    return true;            // Success!
}

