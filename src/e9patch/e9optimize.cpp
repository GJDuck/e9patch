/*
 * e9optimize.cpp
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

#include "e9patch.h"
#include "e9x86_64.h"

/*
 * Build the initial trampoline entry set.
 */
void buildEntrySet(Binary *B)
{
    // The entry points are only needed when trampoline prologues are enabled.
    if (!option_batch || !option_Opeephole ||
            option_Oprologue == 0 || option_Oprologue_size == 0)
        return;

    auto i = B->Is.rbegin();
    if (i == B->Is.rend())
        return;
    const Instr *I = i->second, *J = nullptr;
    unsigned num = 0, size = 0;
    while (I != nullptr)
    {
        if (I->patch)
        {
            J = I;
            num = size = 0;
        }
        else if (isCFT(I->original.bytes, I->size,
                CFT_CALL | CFT_RET | CFT_JMP))
            J = nullptr;
        if (J != nullptr && num <= option_Oprologue &&
                size <= option_Oprologue_size)
        {
            EntryPoint E = {J, INTPTR_MIN, false, false};
            B->Es.insert({I->addr, E});
        }
        num  += 1;
        size += I->size;
        I = I->prev;
        if (I == nullptr || I->addr + I->size != I->next->addr)
            J = nullptr;
    }

    for (const auto &entry: B->Is)
    {
        const Instr *I = entry.second;
        if (I->patch)
            continue;
        bool is_rel8 = false;
  		switch (I->original.bytes[0])
        {
            case 0xEB: case 0xE3:
            case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
            case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
            case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
            case 0x7F:
				if (I->size != /*sizeof(jmp/jcc rel8)*/2)
                    continue;
                is_rel8 = true;
                break;
            case 0x66:
                if (I->size != /*sizeof(jecxz rel8)*/3 ||
                        I->original.bytes[1] != 0xE3)
                    continue;
                is_rel8 = true;
                break;
            case 0xE8: case 0xE9:
                if (I->size != /*sizeof(jmpq/call rel32)=*/5)
                    continue;
                break;
            case 0x0F:
                if (I->size != /*sizeof(jcc rel32)=*/6)
                    continue;
                switch (I->original.bytes[1])
                {
                    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                    case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                    case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                    case 0x8F:
                        break;
                    default:
                        continue;
                }
                break;
            default:
                continue;
        }
        off_t rel = 0;
        if (is_rel8)
        {
            int8_t rel8 = (int8_t)*(int8_t *)
                (I->original.bytes + I->size - sizeof(int8_t));
            rel = (off_t)rel8;
            if (rel >= 0)
            {
                // -Opeephole can only be applied to *relocated* 8bit relative
                // jumps.  As a simple heuristic, assume that only backjumps
                // will be relocated.  TODO: make this more sophisticated.
                continue;
            }
        }
        else
        {
            int32_t rel32 = (int32_t)*(int32_t *)
                (I->original.bytes + I->size - sizeof(int32_t));
            rel = (off_t)rel32;
        }
        intptr_t target = (intptr_t)I->addr + (intptr_t)I->size + rel;
        auto i = B->Es.find(target);
        if (i == B->Es.end())
            continue;
        EntryPoint &E = i->second;
        if (is_rel8)
            E.target8 = true;
        else
            E.target32 = true;
 	}
}

/*
 * Calculate the start of the trampoline prologue.
 */
const Instr *getTrampolinePrologueStart(const EntrySet &Es, const Instr *I)
{
    if (!option_Opeephole)
        return nullptr;
    auto i = Es.find(I->addr);
    if (i == Es.end())
        return nullptr;
    const EntryPoint &E = i->second;
    if (E.I != I)
        return nullptr;

    auto j = Es.begin();
    const Instr *J = I, *K = nullptr;
    while (i != j)
    {
        J = J->prev;
        i--;
        const EntryPoint &F = i->second;
        if (F.I != E.I)
            break;
        if (F.target32 || F.target8)
            K = J;
    }
    return K;
}

/*
 * Get the corresponding trampoline entry if it exists, else INTPTR_MIN.
 */
intptr_t getTrampolineEntry(const EntrySet &Es, const Instr *I)
{
    auto i = Es.find(I->addr);
    if (i == Es.end())
        return INTPTR_MIN;
    return i->second.entry;
}

/*
 * Set the corresponding trampoline entry.
 */
void setTrampolineEntry(EntrySet &Es, const Instr *I, intptr_t entry)
{
    auto i = Es.find(I->addr);
    if (i == Es.end())
    {
        if (entry != INTPTR_MIN)
        {
            EntryPoint E = {I, entry, false, false};
            Es.insert({I->addr, E});
        }
        return;
    }
    EntryPoint &E = i->second;
    E.entry       = entry;
}

/*
 * Find the instruction at the given address.
 */
Instr *findInstr(const Binary *B, intptr_t addr)
{
    if (addr <= 0)
        return nullptr;
    off_t offset = addr - B->diff;
    auto i = B->Is.find(offset);
    if (i == B->Is.end())
        return nullptr;
    Instr *I = i->second;
    if (I->addr != addr)
        return nullptr;
    return I;
}

/*
 * Optimize a jump (or call) instruction.
 */
static void optimizeJump(const Binary *B, intptr_t addr, uint8_t *bytes,
    size_t size)
{
    if (!option_Opeephole || size == 0)
        return;

    bool jcc = false, jmp = false;
    switch (bytes[0])
    {
        case 0xE9:
            jmp = true;
            // Fallthrough:
        case 0xE8:
            if (size != /*sizeof(jmpq/call rel32)=*/5)
                return;
            break;
        case 0x0F:
            if (size != /*sizeof(jcc rel32)=*/6)
                return;
            jcc = true;
            switch (bytes[1])
            {
                case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                case 0x8F:
                    break;
                default:
                    return;
            }
            break;
        default:
            return;
    }

	int32_t rel32 = *(int32_t *)(bytes + (jcc? 2: 1));
    intptr_t target = addr + (intptr_t)size + (intptr_t)rel32;
    const Instr *J = findInstr(B, target);
    if (J == nullptr)
        return;
    target = getTrampolineEntry(B->Es, J);
    if (target == INTPTR_MIN)
        target = getCFTTarget(J->addr, J->patched.bytes, J->size, CFT_JMP);
    if (target == INTPTR_MIN)
        return;

    intptr_t diff = target - (addr + (intptr_t)size);
    if (jmp && diff == 0)
    {
        // As a special case, we can replace this JMP with a 5-byte NOP.
        bytes[0] = 0x0F; bytes[1] = 0x1F; bytes[2] = 0x44;
        bytes[3] = 0x00; bytes[4] = 0x00;
        return;
    }
    if (diff < INT32_MIN || diff > INT32_MAX)
        return;
    *(int32_t *)(bytes + (jcc? 2: 1)) = (int32_t)diff;
}

/*
 * Optimize all jumps in the binary.
 */
void optimizeAllJumps(Binary *B)
{
    if (!option_Opeephole)
        return;

    for (const auto &J: B->Js)
        optimizeJump(B, J.addr, J.bytes, J.size);
    B->Js.clear();

    for (const auto &entry: B->Is)
    {
        Instr *I = entry.second;
        if (I->is_patched)
            continue;
        bool ok = true;
        for (size_t i = 0; ok && i < I->size; i++)
            ok = (I->patched.state[i] == STATE_INSTRUCTION);
        if (!ok)
            continue;

        optimizeJump(B, I->addr, I->patched.bytes, I->size);
    }
}

