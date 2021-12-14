/*
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

/*
 * VERY SIMPLE CONTROL-FLOW-RECOVERY ANALYSIS.
 *
 * This is a very simple control-flow (jump target) recovery analysis.
 *
 * NOTES:
 * - The analysis is not intended to be accurate, and is allowed to
 *   overapproximate the set of basic-blocks.  It is intended for applications
 *   where such overapproximations can be tolerated.
 * - The implementation assumes well-behaved compiler idioms, i.e., jump
 *   tables of a specific form.
 * - The current implementation is somewhat basic and could be improved.
 */

#include <cstdint>

#include <set>

#include "e9elf.h"
#include "e9tool.h"

using namespace e9tool;

extern bool option_debug;
#define DEBUG(targets, target, msg, ...)                                \
    do                                                                  \
    {                                                                   \
        if (option_debug && (targets).find(target) == (targets).end())  \
            debug("CFG: " msg, ##__VA_ARGS__);                          \
    }                                                                   \
    while (false)

typedef std::set<intptr_t> RelaInfo;

/*
 * Insert target information.
 */
static void addTarget(intptr_t target, TargetKind kind, Targets &targets)
{
    auto r = targets.insert({target, kind});
    if (!r.second)
    {
        // Existing entry found:
        r.first->second |= kind;
    }  
}

/*
 * Get the bounds of a buffer assuming T-aligment.
 */
template <typename T>
static std::pair<const T *, const T *> getBounds(const uint8_t *lb0,
    const uint8_t *ub0)
{
    uintptr_t lb = (uintptr_t)lb0, ub = (uintptr_t)ub0;
    if (lb % sizeof(T) != 0)
    {
        lb += sizeof(T);
        lb -= lb % sizeof(T);
    }
    if (ub % sizeof(T) != 0)
        ub -= ub % sizeof(T);
    return {(const T *)lb, (const T *)ub}; 
}

/*
 * Find the instruction corresponding to the address.  Returns a negative index
 * corresponding instruction is not found.
 */
ssize_t e9tool::findInstr(const Instr *Is, size_t size, intptr_t address)
{
    ssize_t lo = 0, hi = (ssize_t)size-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        if ((intptr_t)Is[mid].address < address)
            lo = mid+1;
        else if ((intptr_t)Is[mid].address > address)
            hi = mid-1;
        else
            return mid;
    }
    return -1;
}

/*
 * Code analysis pass: find all probable code targets.
 */
static void CFGCodeAnalysis(const ELF *elf, bool pic, const Instr *Is,
    size_t size, std::set<intptr_t> &tables, Targets &targets)
{
    // STEP (1): Calculate a rough-cut of the targets:
    intptr_t next = INTPTR_MIN;
    for (size_t i = 0; i < size; i++)
    {
        InstrInfo I0, *I = &I0;
        getInstrInfo(elf, Is + i, I);
        if (next != I->address)
        {
            // [HEURISTIC] This is the first instruction after a "gap" in the
            // executable code.  Thus, something probably jumps here, so is
            // considered a jump target.
            DEBUG(targets, I->address, "Entry : %p", (void *)I->address);
            addTarget(I->address, TARGET_ENTRY, targets);
        }
        next = I->address + I->size;

        intptr_t target = INTPTR_MIN;
        bool call = false;
        switch (I->mnemonic)
        {
            case MNEMONIC_MOV:
                if (pic || I->op[0].type != OPTYPE_IMM)
                    continue;

                // [HEURISTIC] This instruction may be moving a jump target
                // into another location for later use.  Thus, we consider the
                // immediate value to be a target if it happens to point to a
                // valid instruction.
                //
                // [HEURISTIC] The target is assumed to be a function.
                target = (intptr_t)I->op[0].imm;
                if (findInstr(Is, size, target) >= 0)
                {
                    DEBUG(targets, target, "Load  : %p", (void *)target);
                    addTarget(target, TARGET_INDIRECT | TARGET_FUNCTION,
                        targets);
                }
                continue;

            case MNEMONIC_LEA:
                if (I->op[0].type != OPTYPE_MEM ||
                        I->op[0].mem.base != REGISTER_RIP)
                    continue;

                // [HEURISTIC] Similar to the "mov" case but for PIC.
                target = (intptr_t)I->address + (intptr_t)I->size +
                    (intptr_t)I->op[0].mem.disp;
                if (findInstr(Is, size, target) >= 0)
                {
                    DEBUG(targets, target, "Load  : %p", (void *)target);
                    addTarget(target, TARGET_INDIRECT | TARGET_FUNCTION,
                        targets);
                }
                else if (pic)
                {
                    // This does not point to an instruction, but may be
                    // pointing to the base of a PIC-style jump-table.  We
                    // save the address for later analysis.
                    tables.insert(target);
                }
                continue;

            case MNEMONIC_RET:
                DEBUG(targets, next, "Next  : %p", (void *)next);
                addTarget(next, TARGET_ENTRY, targets);
                continue;
            case MNEMONIC_JMP:
                if (!pic &&
                        I->op[0].type == OPTYPE_MEM &&
                        I->op[0].mem.base == REGISTER_NONE &&
                        I->op[0].mem.index != REGISTER_NONE &&
                        I->op[0].mem.scale == sizeof(void *))
                {
                    target = (intptr_t)I->op[0].mem.disp;
                    tables.insert(target);
                }
                DEBUG(targets, next, "Next  : %p", (void *)next);
                addTarget(next, TARGET_ENTRY, targets);
                break;
            case MNEMONIC_CALL:
                call = true;
                break;
            case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
            case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
            case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
            case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
            case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
            case MNEMONIC_JG: case MNEMONIC_JRCXZ: case MNEMONIC_JECXZ:
                // The branch-not-taken is considered a jump target:
                DEBUG(targets, next, "NotTkn: %p", (void *)next);
                addTarget(next, TARGET_DIRECT, targets);
                break;
            default:
                continue;
        }

        // If we reach here then the instruction is a jump or call.
        if (I->op[0].type != OPTYPE_IMM)
        {
            // For indirect jumps/call, we do not directly know the target.
            continue;
        }
        target = (intptr_t)I->address + (intptr_t)I->size +
            (intptr_t)I->op[0].imm;
        DEBUG(targets, target, "Target: %p%s", (void *)target,
            (call? " (F)": ""));
        addTarget(target, TARGET_DIRECT | (call? TARGET_FUNCTION: 0), targets);
    }

    // Symbols are assumed to be functions:
    for (unsigned i = 0; i < 2; i++)
    {
        const SymbolInfo &syms = (i == 0? getELFDynSymInfo(elf):
                                          getELFSymInfo(elf));
        for (auto &entry: syms)
        {
            const Elf64_Sym *sym = entry.second;
            if (sym->st_shndx == SHN_UNDEF ||
                    ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                continue;
            intptr_t target = sym->st_value;
            DEBUG(targets, target, "Symbol: %p (F)", (void *)target);
            addTarget(target, TARGET_INDIRECT | TARGET_FUNCTION, targets);
        }
    }
}

/*
 * Section analysis pass: find potential code pointers in data.
 */
static void CFGSectionAnalysis(const ELF *elf, bool pic, const char *name,
    const Elf64_Shdr *shdr, const Instr *Is, size_t size, const RelaInfo relas,
    const std::set<intptr_t> &tables, Targets &targets)
{
    if ((shdr->sh_flags & SHF_EXECINSTR) != 0 || shdr->sh_addr == 0x0)
        return;
    
    const uint8_t *sh_data = getELFData(elf) + shdr->sh_offset;
    size_t sh_size = shdr->sh_size;
    
    if (!pic)
    {
        if (shdr->sh_type != SHT_PROGBITS)
            return;

        // Scan the data for absolute addresses.
        auto bounds = getBounds<intptr_t>(sh_data, sh_data + sh_size);
        bool call = true;
        for (const intptr_t *p = bounds.first; p < bounds.second; p++)
        {
            intptr_t table = (intptr_t)shdr->sh_addr +
                ((intptr_t)p - (intptr_t)sh_data);
            if (tables.find(table) != tables.end())
                call = false;
            intptr_t target = *p;
            if (target != 0 && findInstr(Is, size, target) >= 0)
            {
                // "Probably" a jump target.
                DEBUG(targets, target, "%s: %p%s", (call? "Data  ": "JmpTbl"),
                    (void *)target, (call? " (F)": ""));
                addTarget(target,
                    TARGET_INDIRECT | (call? TARGET_FUNCTION: 0), targets);
            }
            else
                call = true;
        }
        return;
    }
    else if (pic)
    {
        if (shdr->sh_type == SHT_PROGBITS && (shdr->sh_flags & SHF_WRITE) == 0)
        {
            // Scan the data for PIC-style jump tables.
            auto bounds = getBounds<int32_t>(sh_data, sh_data + sh_size);
            for (const int32_t *p = bounds.first; p < bounds.second; )
            {
                intptr_t table = (intptr_t)shdr->sh_addr +
                    ((intptr_t)p - (intptr_t)sh_data);
                auto i = tables.find(table);
                if (i == tables.end())
                {
                    p++;
                    continue;
                }

                // This is "probably" a PIC-style jump table.
                for (const int32_t *q = p++; q < bounds.second; q++, p = q)
                {
                    intptr_t offset = (intptr_t)*q;
                    intptr_t target = table + offset;
                    if (findInstr(Is, size, target) < 0)
                        break;
                    DEBUG(targets, target, "JmpTbl: %p%+zd = %p",
                        (void *)table, offset, (void *)target);
                    // Jump tables are treated as direct:
                    addTarget(target, TARGET_DIRECT, targets);
                }
            }
        }

        if (shdr->sh_type == SHT_PROGBITS)
        {
            // Scan for code pointers using relocation information.
            auto bounds = getBounds<int64_t>(sh_data, sh_data + sh_size);
            for (const int64_t *p = bounds.first; p < bounds.second; p++)
            {
                intptr_t offset = (intptr_t)shdr->sh_addr +
                    ((intptr_t)p - (intptr_t)sh_data);
                auto i = relas.find(offset);
                if (i == relas.end())
                    continue;
                
                intptr_t target = *p;
                if (findInstr(Is, size, target) < 0)
                    continue;
                DEBUG(targets, target, "Reloc : %p (F)", (void *)target);
                addTarget(target, TARGET_INDIRECT | TARGET_FUNCTION, targets);
            }
        }
    }
}

/*
 * Data analysis pass: find potential code pointers in data.
 */
static void CFGDataAnalysis(const ELF *elf, bool pic, const Instr *Is,
    size_t size, const std::set<intptr_t> &tables, Targets &targets)
{
    // Gather relocation information:
    const SectionInfo &sections = getELFSectionInfo(elf);
    RelaInfo relas;
    for (const auto &entry: sections)
    {
        const Elf64_Shdr *shdr = entry.second;
        if (shdr->sh_type != SHT_RELA)
            continue;
        const uint8_t *sh_data = getELFData(elf) + shdr->sh_offset;
        size_t sh_size = shdr->sh_size;
        const Elf64_Rela *rela = (const Elf64_Rela *)sh_data;
        const Elf64_Rela *rela_end = rela + sh_size / sizeof(Elf64_Rela);
        for (; rela < rela_end; rela++)
        {
            if (ELF64_R_TYPE(rela->r_info) == R_X86_64_RELATIVE &&
                    rela->r_addend == 0)
                relas.insert(rela->r_offset);
        }
    }

    // Analyze each data section:
    for (const auto &entry: sections)
        CFGSectionAnalysis(elf, pic, entry.first, entry.second, Is, size,
            relas, tables, targets);
}

/*
 * Build the set of potential jump targets.
 */
void e9tool::buildTargets(const ELF *elf, const Instr *Is, size_t size,
    Targets &targets)
{
    bool pic = false;
    switch (getELFType(elf))
    {
        case BINARY_TYPE_ELF_DSO: case BINARY_TYPE_ELF_PIE:
            pic = true;
            break;
        default:
            break;
    }

    // Pass #1: Find all code targets. 
    std::set<intptr_t> tables;
    CFGCodeAnalysis(elf, pic, Is, size, tables, targets);
    
    // Pass #2: Find all data targets.
    CFGDataAnalysis(elf, pic, Is, size, tables, targets);

    // Pass #3: "Clean up" the targets.
    Targets new_targets;
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first;
        TargetKind kind = entry.second;

        // Find the corresponding instruction:
        ssize_t i = findInstr(Is, size, target);
        if (i < 0)
            continue;

        // Skip any NOPs
        InstrInfo I0, *I = &I0;
        for (; i < (ssize_t)size; i++)
        {
            getInstrInfo(elf, Is + i, I);
            bool stop = false;
            switch (I->mnemonic)
            {
                case MNEMONIC_NOP:
                    break;
                default:
                    stop = true;
                    break;
            }
            if (stop)
                break;
            if (i+1 < (ssize_t)size &&
                    (intptr_t)Is[i+1].address != I->address + I->size)
                i = SIZE_MAX;
        }
        if (i >= (ssize_t)size)
            continue;   // No target found.
        
        // Add target:
        addTarget((intptr_t)Is[i].address, kind, new_targets);
    }
    targets.swap(new_targets);
}

/*
 * Build the set of basic blocks.
 */
void e9tool::buildBBs(const ELF *elf, const Instr *Is, size_t size,
    const Targets &targets, BBs &bbs)
{
    std::map<uint32_t, BB> tmp;
    for (const auto &entry: targets)
    {
        intptr_t target = entry.first;
        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;
        uint32_t lb = i, ub = i, best = i;
        const Instr *I = Is + i;

        for (++i; i < size; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool cft = false;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                case MNEMONIC_JMP:
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG: 
                    cft = true;
                    break;
                case MNEMONIC_INT: case MNEMONIC_INT1: case MNEMONIC_INT3:
                case MNEMONIC_INTO:
                case MNEMONIC_UD0: case MNEMONIC_UD1: case MNEMONIC_UD2:
                case MNEMONIC_HLT:
                    cft = true;     // Treat as end-of-BB
                    break;
                default:
                    break;
            }
            if (cft)
                break;
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            if (targets.find(J->address) != targets.end())
                break;
            ub++;
            if (Is[best].size < /*sizeof(jmpq)=*/5 &&
                    Is[ub].size > Is[best].size)
                best = ub;
            I = J;
        }
        debug("basic block 0x%lx..0x%lx [%zui,%zuB]", Is[lb].address,
            Is[ub].address, ub - lb + 1, 
            Is[ub].address - Is[lb].address + Is[ub].size);
        BB bb(lb, ub, best);
        tmp.insert({lb, bb});
    }

    bbs.reserve(tmp.size());
    for (const auto &entry: tmp)
        bbs.push_back(entry.second);
}

/*
 * Find a basic block based on an instruction index.
 */
const BB *e9tool::findBB(const BBs &bbs, size_t idx)
{
    ssize_t lo = 0, hi = (ssize_t)bbs.size()-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        if (bbs[mid].ub < idx)
            lo = mid+1;
        else if (bbs[mid].lb > idx)
            hi = mid-1;
        else
            return &bbs[mid];
    }
    return nullptr;
}

/*
 * Build the set of functions.
 */
void e9tool::buildFs(const ELF *elf, const Instr *Is, size_t size,
    const Targets &targets, Fs &fs)
{
    std::map<intptr_t, const char *> names;
    for (unsigned i = 0; i < 2; i++)
    {
        const SymbolInfo &syms = (i == 0? getELFDynSymInfo(elf):
                                          getELFSymInfo(elf));
        for (auto &entry: syms)
        {
            const Elf64_Sym *sym = entry.second;
            if (sym->st_shndx == SHN_UNDEF ||
                    ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                continue;
            intptr_t target = sym->st_value;
            const char *name = entry.first;
            names.insert({target, name});
        }
    }
    std::map<uint32_t, F> tmp;
    for (const auto &entry: targets)
    {
        if ((entry.second & TARGET_FUNCTION) == 0)
            continue;
        intptr_t target = entry.first;
        size_t i = findInstr(Is, size, target);
        if (i >= size)
            continue;
        uint32_t lb = i, ub = i, best = i;
        bool found = false;
        const Instr *I = Is + i;

        for (++i; i < size; i++)
        {
            InstrInfo info0, *info = &info0;
            getInstrInfo(elf, I, info);
            bool cft = false;
            switch (info->mnemonic)
            {
                case MNEMONIC_RET:
                case MNEMONIC_JMP:
                case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB:
                case MNEMONIC_JAE: case MNEMONIC_JE: case MNEMONIC_JNE:
                case MNEMONIC_JBE: case MNEMONIC_JA: case MNEMONIC_JS:
                case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
                case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE:
                case MNEMONIC_JG: 
                    cft = true;
                    break;
                case MNEMONIC_INT: case MNEMONIC_INT1: case MNEMONIC_INT3:
                case MNEMONIC_INTO:
                case MNEMONIC_UD0: case MNEMONIC_UD1: case MNEMONIC_UD2:
                case MNEMONIC_HLT:
                    cft = true;     // Treat as end-of-BB
                    break;
                default:
                    break;
            }
            if (cft)
                found = true;
            const Instr *J = I+1;
            if (I->address + I->size != J->address)
                break;
            auto j = targets.find(J->address);
            if (j != targets.end() && (j->second & TARGET_FUNCTION) != 0)
                break;
            ub++;
            if (!found && Is[best].size < /*sizeof(jmpq)=*/5 &&
                    Is[ub].size > Is[best].size)
                best = ub;
            I = J;
        }
        auto j = names.find(Is[lb].address);
        const char *name = (j == names.end()? nullptr: j->second);
        debug("function 0x%lx..0x%lx [%zui,%zuB%s%s]", Is[lb].address,
            Is[ub].address, ub - lb + 1, 
            Is[ub].address - Is[lb].address + Is[ub].size,
            (name == nullptr? "": ",name="), (name == nullptr? "": name));
        F f(name, lb, ub, best);
        tmp.insert({lb, f});
    }

    fs.reserve(tmp.size());
    for (const auto &entry: tmp)
        fs.push_back(entry.second);
}

/*
 * Find a function based on an instruction index.
 */
const F *e9tool::findF(const Fs &fs, size_t idx)
{
    ssize_t lo = 0, hi = (ssize_t)fs.size()-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        if (fs[mid].ub < idx)
            lo = mid+1;
        else if (fs[mid].lb > idx)
            hi = mid-1;
        else
            return &fs[mid];
    }
    return nullptr;
}

