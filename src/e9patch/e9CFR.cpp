/*
 * e9CFR.cpp
 * Copyright (C) 2022 National University of Singapore
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

#include <sys/mman.h>

#include "e9CFR.h"
#include "e9elf.h"
#include "e9x86_64.h"

/*
 * Setter/getter.
 */
static bool setTarget(uint8_t *targets, size_t size, intptr_t offset)
{
    if (offset < (intptr_t)sizeof(Elf64_Ehdr) || (size_t)offset >= size)
        return false;
    size_t i = (size_t)offset / 8;
    size_t j = (size_t)offset % 8;
    targets[i] |= (1 << j);
    return true;
}
static bool isTarget(const uint8_t *targets, size_t size, intptr_t offset)
{
    if (offset < (intptr_t)sizeof(Elf64_Ehdr) || (size_t)offset >= size)
        return false;
    size_t i = (size_t)offset / 8;
    size_t j = (size_t)offset % 8;
    return ((targets[i] & (1 << j)) != 0);
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
 * Get the offset for an address.
 */
static intptr_t addrToOffset(const Elf64_Phdr *phdrs, size_t phnum,
    intptr_t addr, bool x = true)
{
    if (addr == 0x0)
        return INTPTR_MIN;
    for (unsigned i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        switch (phdr->p_type)
        {
            case PT_LOAD: case PT_GNU_RELRO:
                break;
            default:
                continue;
        }
        if (x && (phdr->p_flags & PF_X) == 0)
            continue;
        intptr_t base = (intptr_t)phdr->p_vaddr;
        size_t size   = (size_t)phdr->p_filesz;
        off_t offset  = (off_t)phdr->p_offset;
        if (addr >= base && addr < base + (ssize_t)size)
            return offset + (addr - base);
    }
    return INTPTR_MIN;
}

/*
 * Target analysis.  Find instructions that can be reached by a
 * control-flow-transfer, including returns.  This can be a "safe"
 * overapproximation, even if the general case is undecidable.
 */
void targetAnalysis(Binary *B)
{
    // Step (1): Basic checks
    if (B->targets != nullptr || !option_OCFR)
        return;
    switch (B->mode)
    {
        case MODE_ELF_EXE: case MODE_ELF_DSO:
            break;
        default:
            warning("target analysis for Windows PE binaries is "
                "not-yet-implemented; `-OCFR' will be ignored");
            option_OCFR = false;
            return;         // Windows PE is NYI
    }
    bool cet = false;
    if (B->elf.features == nullptr ||
            (*B->elf.features & GNU_PROPERTY_X86_FEATURE_1_IBT) == 0 ||
            (*B->elf.features & GNU_PROPERTY_X86_FEATURE_1_SHSTK) == 0)
        cet = true;
    bool pic = B->pic;
    const uint8_t *data = B->original.bytes;
    const Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + B->elf.ehdr->e_phoff);
    size_t phnum = B->elf.ehdr->e_phnum;
    const Elf64_Phdr *phdr_dynamic = nullptr;
    for (unsigned i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        if (phdr->p_type == PT_DYNAMIC)
            phdr_dynamic = phdr;
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_X) == 0)
            continue;
        if ((phdr->p_flags & PF_W) != 0)
        {
            warning("target analysis does not support writable code segments");
            return;         // Not read-only
        }
    }

    // Step (2): Create the target map:
    void *ptr = mmap(nullptr, (B->size + PAGE_SIZE) / 8,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
        -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to allocate target map: %s", strerror(errno));
    uint8_t *targets = (uint8_t *)ptr;
    B->targets = targets;

    // Step (3): Find all direct jump targets.
    //
    // Note: This is a basic overapproximation that assumes *all* executable
    //       byte patterns resembling direct calls/jumps *are* direct
    //       calls/jumps.  This analysis does not assume the binary can be
    //       disassembled, and safely handles data-in-code, etc.
    //
    std::set<intptr_t> tables;
    for (unsigned i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_X) == 0)
            continue;
        off_t offset  = (off_t)phdr->p_offset;
        intptr_t addr = (intptr_t)phdr->p_vaddr;
        size_t size   = (size_t)phdr->p_memsz;
        off_t end     = (offset + size > B->size? B->size: offset + size);
        for (off_t j = offset; j < end; j++)
        {
            int8_t rel8;
            int32_t rel32;
            intptr_t target = INTPTR_MIN, next = INTPTR_MIN;
            switch (data[j])
            {
                case 0x0F:                  // jcc rel32
                    if (j+1 >= end)
                        continue;
                    switch (data[j+1])
                    {
                        case 0x80: case 0x81: case 0x82: case 0x83:
                        case 0x84: case 0x85: case 0x86: case 0x87:
                        case 0x88: case 0x89: case 0x8A: case 0x8B:
                        case 0x8C: case 0x8D: case 0x8E: case 0x8F:
                            j++;
                            next = j + 5;
                            break;
                        default:
                            continue;
                    }
                    // Fallthrough:
                case 0xE8: case 0xE9:       // callq/jumpq rel32
                    if (j + /*sizeof(callq/jmpq)=*/5 > end)
                        continue;
                    memcpy(&rel32, data + j + 1, sizeof(rel32));
                    target = j + 5 + (intptr_t)rel32;
                    if (data[j] == 0xE8)
                        next = j + 5;       // return target
                    break;
                case 0xE3:                  // jrcxz rel8
                case 0xEB:                  // jmp rel8
                case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
                case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
                case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
                case 0x7F:                  // jcc rel8
                    if (j + /*sizeof(jmp rel8)=*/2 > end)
                        continue;
                    rel8 = data[j + 1];
                    target = j + 2 + (intptr_t)rel8;
                    next = j + 2;
                    break;
                case 0xFF:                  // call *mem64
                {
                    if (j+2 > end)
                        continue;
                    ssize_t sz = getModRMSize(data+j+1, end-(j+1));
                    if (sz < 0)
                        continue;
                    next = j + 1 + sz;
                    break;
                }
                case 0xB8: case 0xB9: case 0xBA: case 0xBB:
                case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                case 0x68:                  // mov $ptr,%reg; push $ptr
                    if (pic || j+5 > end)
                        continue;
                    target = addrToOffset(phdrs, phnum,
                        *(int32_t *)(data + j + 1));
                    break;
                case 0xC7:                  // mov $ptr,mem64
                {
                    if (pic || j+2 > end)
                        continue;
                    ssize_t sz = getModRMSize(data+j+1, end-(j+1));
                    if (sz < 0 || j+1+sz+(ssize_t)sizeof(int32_t) > end)
                        continue;
                    int32_t imm32 = *(int32_t *)(data + j + 1 + sz);
                    target = addrToOffset(phdrs, phnum, imm32);
                    break;
                }
                case 0x48: case 0x4C:       // lea ptr(%rip),%reg
                {
                    if (j+7 > end)
                        continue;
                    if (data[j+1] != 0x8d)
                        continue;
                    uint8_t modRM = data[j+2];
                    uint8_t mod = (modRM & 0xc0) >> 6;
                    uint8_t rm  = modRM & 0x7;
                    if (mod != 0x00 && rm != 0x05)
                        continue;
                    target = j + 7 + *(int32_t *)(data + j + 3);
                    if (target >= 0 && target % sizeof(int32_t) == 0)
                    {
                        intptr_t table = addr + (target - offset);
                        tables.insert(table);
                    }
                    break;
                }
                case 0xF3:                  // endbr64
                    if (j+4 > end || !cet)
                        continue;
                    if (data[j+1] != 0x0F || data[j+2] != 0x1E ||
                            data[j+3] != 0xFA)
                        continue;
                    target = j;     // endbr64
                    break;
                default:
                    continue;
            }
            setTarget(targets, B->size, target);
            setTarget(targets, B->size, next);
        }
    }

    // Step (4): Find other indirect jump targets.
    {
        // Entry point
        intptr_t target = addrToOffset(phdrs, phnum, B->elf.ehdr->e_entry);
        setTarget(targets, B->size, target);
    }
    struct hshtab_s
    {
        uint32_t nbuckets;
        uint32_t symoffset;
        uint32_t bloomsz;
        uint32_t bloomshft;
        uint8_t data[];
    };
    if (phdr_dynamic != nullptr)
    {
        // Dynamic section:
        const Elf64_Dyn *dynamic =
            (const Elf64_Dyn *)(data + phdr_dynamic->p_offset);
        const intptr_t *init_array = nullptr, *fini_array = nullptr;
        size_t init_size = 0, fini_size = 0;
        const Elf64_Rela *rela = nullptr;
        size_t rela_size = 0;
        const struct hshtab_s *hshtab = nullptr;
        const Elf64_Sym *symtab = nullptr;
        for (size_t i = 0; dynamic[i].d_tag != DT_NULL; i++)
        {
            switch (dynamic[i].d_tag)
            {
                case DT_INIT: case DT_FINI:
                {
                    intptr_t target = addrToOffset(phdrs, phnum,
                        dynamic[i].d_un.d_ptr);
                    setTarget(targets, B->size, target);
                    break;
                }
                case DT_INIT_ARRAY: case DT_FINI_ARRAY:
                {
                    intptr_t offset = addrToOffset(phdrs, phnum,
                        dynamic[i].d_un.d_ptr, /*x=*/false);
                    if (offset < 0)
                        break;
                    const intptr_t *array = (const intptr_t *)(data + offset);
                    init_array = (dynamic[i].d_tag == DT_INIT_ARRAY? array:
                        init_array);
                    fini_array = (dynamic[i].d_tag == DT_FINI_ARRAY? array:
                        fini_array);
                    break;
                }
                case DT_INIT_ARRAYSZ:
                    init_size = dynamic[i].d_un.d_val / sizeof(void *);
                    break;
                case DT_FINI_ARRAYSZ:
                    fini_size = dynamic[i].d_un.d_val / sizeof(void *);
                    break;
                case DT_RELA:
                {
                    intptr_t offset = addrToOffset(phdrs, phnum,
                        dynamic[i].d_un.d_ptr, /*x=*/false);
                    if (offset < 0)
                        break;
                    rela = (const Elf64_Rela *)(data + offset);
                    break;
                }
                case DT_RELASZ:
                    rela_size = dynamic[i].d_un.d_val / sizeof(Elf64_Rela);
                    break;
                case DT_SYMTAB:
                {
                    intptr_t offset = addrToOffset(phdrs, phnum,
                        dynamic[i].d_un.d_ptr, /*x=*/false);
                    if (offset < 0)
                        break;
                    symtab = (const Elf64_Sym *)(data + offset);
                    break;
                }
                case DT_GNU_HASH:
                {
                    intptr_t offset = addrToOffset(phdrs, phnum,
                        dynamic[i].d_un.d_ptr, /*x=*/false);
                    if (offset < 0)
                        break;
                    hshtab = (const struct hshtab_s *)(data + offset);
                    break;
                }
                default:
                    break;
            }
        }
        for (size_t i = 0; init_array != nullptr && i < init_size; i++)
        {
            // Init array
            intptr_t target = addrToOffset(phdrs, phnum, init_array[i]);
            setTarget(targets, B->size, target);
        }
        for (size_t i = 0; fini_array != nullptr && i < fini_size; i++)
        {
            // Fini array
            intptr_t target = addrToOffset(phdrs, phnum, fini_array[i]);
            setTarget(targets, B->size, target);
        }
        for (size_t i = 0; pic && rela != nullptr && i < rela_size; i++)
        {
            // Rela section
            if (ELF64_R_TYPE(rela[i].r_info) != R_X86_64_RELATIVE)
                continue;
            intptr_t addr = rela[i].r_offset;
            intptr_t offset = addrToOffset(phdrs, phnum, addr, /*x=*/false);
            if (offset < 0)
                continue;
            addr = rela[i].r_addend;
            intptr_t target = addrToOffset(phdrs, phnum, addr);
            setTarget(targets, B->size, target);
        }
        if (hshtab != nullptr && symtab != nullptr)
        {
            // Symbols
            const uint32_t *buckets =
                (const uint32_t *)(hshtab->data +
                    hshtab->bloomsz * sizeof(uint64_t));
            const uint32_t *chain = buckets + hshtab->nbuckets;
            uint32_t nsyms = 0;
            for (uint32_t i = 0; i < hshtab->nbuckets; i++)
                nsyms = std::max(nsyms, buckets[i]);
            for (; (chain[nsyms - hshtab->symoffset] & 0x1) == 0; nsyms++)
                ;
            for (uint32_t i = 0; i < nsyms; i++)
            {
                if (symtab[i].st_shndx == SHN_UNDEF ||
                        ELF64_ST_TYPE(symtab[i].st_info) != STT_FUNC)
                    continue;
                intptr_t addr = symtab[i].st_value;
                intptr_t target = addrToOffset(phdrs, phnum, addr);
                setTarget(targets, B->size, target);
            }
        }
    }
    if (!pic || option_OCFR_hacks)
    {
        // Non-PIC code pointers & jump tables
        for (unsigned i = 0; i < phnum; i++)
        {
            const Elf64_Phdr *phdr = phdrs + i;
            if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_R) == 0)
                continue;
            off_t offset = (off_t)phdr->p_offset;
            size_t size  = (size_t)phdr->p_memsz;
            off_t end    = (offset + size > B->size? B->size: offset + size);
            auto bounds = getBounds<intptr_t>(data + offset, data + end);
            for (const intptr_t *p = bounds.first; p < bounds.second; p++)
            {
                intptr_t target = addrToOffset(phdrs, phnum, *p);
                setTarget(targets, B->size, target);
            }
        }
    }

    // PIC-style jump tables
    // Note: We do this analysis even for non-PIC binaries.  This is because
    //       it is possible that a non-PIC binary was compiled with -fPIC.
    for (unsigned i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_R) == 0)
            continue;
        off_t offset  = (off_t)phdr->p_offset;
        intptr_t addr = (intptr_t)phdr->p_vaddr;
        size_t size   = (size_t)phdr->p_memsz;
        off_t end     = (offset + size > B->size? B->size: offset + size);
        const uint8_t *base = data + offset;
        auto bounds = getBounds<int32_t>(base, data + end);
        for (const int32_t *p = bounds.first; p < bounds.second; p++)
        {
            intptr_t table = addr + ((intptr_t)p - (intptr_t)base);
            auto i = tables.find(table);
            if (i == tables.end())
                continue;
            
            for (const int32_t *q = p; q < bounds.second; q++)
            {
                intptr_t offset = (intptr_t)*q;
                intptr_t label = table + offset;
                intptr_t target = addrToOffset(phdrs, phnum, label);
                if (!setTarget(targets, B->size, target))
                    break;
            }
        }
    }
}

/*
 * Check if the given offset is "possibly" a jump target.
 */
bool isTarget(const Binary *B, off_t offset)
{
    if (B->targets == nullptr)
        return true;
    return isTarget(B->targets, B->size, offset);
}

