/*
 * e9elf.cpp
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
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utility>

#include "e9alloc.h"
#include "e9elf.h"
#include "e9loader.h"
#include "e9mapping.h"
#include "e9patch.h"

static const
#include "e9loader.c"

/*
 * Patch refactoring for the dynamic loader.
 */
struct Refactor
{
    intptr_t addr;                      // Mapping address
    size_t size;                        // Mapping size
    struct
    {
        off_t offset;                   // Original offset
    } original;
    struct
    {
        off_t offset;                   // Patched offset
    } patched;

    Refactor(intptr_t addr, off_t offset, size_t size) :
        addr(addr), size(size)
    {
        original.offset = offset;
        patched.offset  = 0;
    }
};
typedef std::vector<Refactor> RefactorSet;

/*
 * Parse the ELF file & reserve any occupied address space.
 */
void parseElf(Allocator &allocator, const char *filename, uint8_t *data,
    size_t size, Mode mode, ElfInfo &info)
{
    if (size < sizeof(Elf64_Ehdr))
        error("failed to parse ELF EHDR from file \"%s\"; file is too small",
            filename);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
            ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
            ehdr->e_ident[EI_MAG3] != ELFMAG3)
        error("failed to parse ELF file \"%s\"; invalid magic number",
            filename);
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        error("failed to parse ELF file \"%s\"; file is not 64bit",
            filename);
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        error("failed to parse ELF file \"%s\"; file is not little endian",
            filename);
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
        error("failed to parse ELF file \"%s\"; invalid version",
            filename);
    if (ehdr->e_machine != EM_X86_64)
        error("failed to parse ELF file \"%s\"; file is not x86_64",
            filename);
    if (ehdr->e_phoff < sizeof(Elf64_Ehdr) || ehdr->e_phoff >= size)
        error("failed to parse ELF file \"%s\"; invalid program header "
            "offset", filename);
    if (ehdr->e_phnum > PN_XNUM)
        error("failed to parse ELF file \"%s\"; too many program headers",
            filename);
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size)
        error("failed to parse ELF file \"%s\"; invalid program headers",
            filename);

    bool pic = false, pie = false;
    switch (ehdr->e_type)
    {
        case ET_EXEC:
        {
            if (mode == MODE_SHARED_OBJECT)
                error("failed to parse ELF file \"%s\": file is an "
                    "executable and not a shared object", filename);
            if (!reserve(allocator, 0x0, 0x10000))
                error("failed to reserve low-address range");
            break;
        }
        case ET_DYN:
            pic = true;
            pie = (mode == MODE_EXECUTABLE);
            break;
        default:
            error("failed to parse ELF file \"%s\"; file is not executable",
                filename);
    }
    if (!pie)
    {
        // Only PIEs can use the negative address range.  Other PIC such
        // as shared objects cannot use this range since the dynamic
        // linker tends to use it for other libraries.
        if (!reserve(allocator, RELATIVE_ADDRESS_MIN, 0x0))
            error("failed to reserve negative-address range");
    }

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + ehdr->e_phoff);
    Elf64_Phdr *phdr_note = nullptr, *phdr_dynamic = nullptr;
    for (unsigned i = 0; i < ehdr->e_phnum; i++)
    {
        Elf64_Phdr *phdr = phdrs + i;
        switch (phdr->p_type)
        {
            case PT_LOAD:
            {
                intptr_t vstart = (intptr_t)phdr->p_vaddr;
                intptr_t vend   = vstart + phdr->p_memsz;
                if (!reserve(allocator, vstart, vend))
                    error("failed to reserve address space range %p..%p",
                        vstart, vend);
                break;
            }
            case PT_DYNAMIC:
                phdr_dynamic = phdr;
                break;
            case PT_NOTE:
                phdr_note = phdr;
                break;
        }
    }
    if (phdr_note == nullptr)
        error("failed to parse ELF file \"%s\"; missing PT_NOTE segment",
            filename);
    if (phdr_dynamic != nullptr &&
            phdr_dynamic->p_offset + phdr_dynamic->p_memsz > size)
        error("failed to parse ELF file \"%s\": invalid dynamic section",
            filename);
    info.ehdr         = ehdr;
    info.phdr_note    = phdr_note;
    info.phdr_dynamic = phdr_dynamic;
    info.pic          = pic;
}

/*
 * Refactor out the patched pages & restore the original pages.
 * For some programs/libraries, it is difficult to ensure the loader is
 * run before the code segment is executed.  This is especially difficult
 * with some advanced uses of the dynamic linker.  This refactoring provides
 * a simple solution: have the loader also patch the code.
 */
static size_t emitRefactoredPatch(const uint8_t *original, uint8_t *data,
    size_t size, size_t mapping_size, const InstrSet &Is,
    RefactorSet &refactors)
{
    if (option_static_loader)
        return 0;

    assert(size % PAGE_SIZE == 0);

    // Step #1: Find refactorings:
    intptr_t curr_addr   = INTPTR_MIN;
    off_t    curr_offset = -1;
    size_t   curr_size   = 0;
    for (off_t offset = 0; offset < (off_t)size; offset += PAGE_SIZE)
    {
        if (memcmp(original + offset, data + offset, PAGE_SIZE) == 0)
            continue;
        auto i = Is.lower_bound(offset);
        assert(i != Is.end());
        const Instr *I = i->second;
        intptr_t page_addr   = I->addr - (I->addr % PAGE_SIZE);
        off_t    page_offset = I->offset - (I->offset % PAGE_SIZE);
        assert(page_offset == offset);
 
        if (curr_addr < 0 || page_addr < curr_addr ||
                (intptr_t)(curr_addr + curr_size + mapping_size) < page_addr)
        {
            if (curr_addr >= 0)
            {
                Refactor r(curr_addr, curr_offset, curr_size);
                refactors.push_back(r);
            }
            curr_addr   = page_addr;
            curr_offset = page_offset;
            curr_size   = PAGE_SIZE;
        }
        else
            curr_size += (page_addr + PAGE_SIZE) - (curr_addr + curr_size);
    }
    if (curr_addr >= 0)
    {
        Refactor r(curr_addr, curr_offset, curr_size);
        refactors.push_back(r);
    }

    // Step #2: Write out a copy of the patched pages & restore original pages:
    size_t size_0 = size;
    for (auto &r: refactors)
    {
        r.patched.offset = (off_t)size;
        memcpy(data + size, data + r.original.offset, r.size);
        memcpy(data + r.original.offset, original + r.original.offset, r.size);
        size += r.size;
    }

    return size - size_0;
}

/*
 * Emit a mmap() system call.
 */
static size_t emitLoaderMmap(uint8_t *data, bool pic, intptr_t addr,
    size_t len, size_t prev_len, int prot, int prev_prot, off_t offset,
    off_t prev_offset, bool user_mmap = false)
{
    // The e9loader is assumed to have:
    // (1) placed the fd into %r8
    // (2) placed (PROT_EXEC | PROT_READ) into %rdx
    // (3) placed (MAP_PRIVATE | MAP_FIXED) into %r10
    // (4) for PIC, placed the base address into %r12
    size_t size = 0;

    // Step (1): Load the address into %rdi
    bool absolute = IS_ABSOLUTE(addr);
    addr = BASE_ADDRESS(addr);
    if (addr >= 0 && addr <= INT32_MAX)
    {
        // mov $addr32,%edi
        int32_t addr32 = (int32_t)addr;
        data[size++] = 0xbf;
        memcpy(data + size, &addr32, sizeof(addr32));
        size += sizeof(addr32);
    }
    else
    {
        // movabs $addr,%rdi
        data[size++] = 0x48; data[size++] = 0xbf;
        memcpy(data + size, &addr, sizeof(addr));
        size += sizeof(addr);
    }
    if (pic && !absolute)
    {
        // addq %r12,%rdi
        data[size++] = 0x4c; data[size++] = 0x01; data[size++] = 0xe7;
    }
    
    // Step (2): Load the length into %rsi
    assert(len <= INT32_MAX);
    if (len != prev_len)
    {
        // mov $len32,%esi
        int32_t len32 = (int32_t)len;
        data[size++] = 0xbe;
        memcpy(data + size, &len32, sizeof(len32));
        size += sizeof(len32);
    }

    // Step (3): Load the protections into %rdx
    if (prot != prev_prot)
    {
        // mov $prot,%edx
        int32_t prot32 = (int32_t)prot;
        data[size++] = 0xba;
        memcpy(data + size, &prot32, sizeof(prot32));
        size += sizeof(prot32);
    }
 
    // Step (4): Load the offset into %r9
    if (offset != prev_offset)
    {
        if (offset <= INT32_MAX)
        {
            // mov $offset32,%r9d
            int32_t offset32 = (int32_t)offset;
            data[size++] = 0x41; data[size++] = 0xb9;
            memcpy(data + size, &offset32, sizeof(offset32));
            size += sizeof(offset32);
        }
        else
        {
            // movabs $offset,%r9
            data[size++] = 0x49; data[size++] = 0xb9;
            memcpy(data + size, &offset, sizeof(offset));
            size += sizeof(offset);
        }
    }

    // Step (5): Execute the system call (or user mmap call).
    if (!user_mmap)
    {
        // mov %r13d,%eax  # mov SYS_MMAP into %rax
        data[size++] = 0x44; data[size++] = 0x89; data[size++] = 0xe8;

        // syscall
        data[size++] = 0x0f; data[size++] = 0x05; 
    }
    else
    {
        // call *%r15
        data[size++] = 0x41; data[size++] = 0xff; data[size++] = 0xd7;
    }

    // Step (6): Check for error.
    {
        // cmp %rdi,%rax
        data[size++] = 0x48; data[size++] = 0x39; data[size++] = 0xf8;

        // je .Lskip
        data[size++] = 0x74; data[size++] = 0x03;

        // jmpq *%r14
        data[size++] = 0x41; data[size++] = 0xff; data[size++] = 0xe6;

        // .Lskip:
    }

    const size_t MIN_SIZE = (pic? 21: 18);
    if (size <= MIN_SIZE)
        fputs("\33[36m0\33[0m", stdout);
    else
        putchar((size - MIN_SIZE < 10?
                '0' + (size - MIN_SIZE):
                'A' + (size - MIN_SIZE)));

    return size;
}

/*
 * Loads a function pointer into %rax.
 */
static size_t emitLoadFuncPtrIntoRAX(uint8_t *data, bool pic, intptr_t fptr)
{
    size_t size = 0;
    bool absolute = IS_ABSOLUTE(fptr);
    fptr = BASE_ADDRESS(fptr);
    if (fptr <= INT32_MAX)
    {
        // mov $fptr32,%eax
        int32_t fptr32 = (int32_t)fptr;
        data[size++] = 0xb8;
        memcpy(data + size, &fptr32, sizeof(fptr32));
        size += sizeof(fptr32);
    }
    else
    {
        // movabs $fptr,%rax
        data[size++] = 0x48; data[size++] = 0xb8;
        memcpy(data + size, &fptr, sizeof(fptr));
        size += sizeof(fptr);
    }
    if (pic && !absolute)
    {
        // addq %r12,%rax
        data[size++] = 0x4c; data[size++] = 0x01; data[size++] = 0xe0;
    }
    return size;
}

/*
 * Emit the loader.
 */
static size_t emitLoader(const RefactorSet &refactors,
    const MappingSet &mappings, uint8_t *data, intptr_t entry, bool pic,
    const InitSet &inits, intptr_t mmap, Mode mode)
{
    /*
     * Stage #1
     */

    // Step (1): Emit the loader entry:
    memcpy(data, e9loader_bin, e9loader_bin_len);
    size_t size = e9loader_bin_len;

    /*
     * Stage #2
     */

    // Step (1): Setup mmap() prot/flags parameters.
    int32_t prot = PROT_READ | PROT_EXEC, flags = MAP_PRIVATE | MAP_FIXED;

    // mov $prot,%edx
    data[size++] = 0xba;
    memcpy(data + size, &prot, sizeof(prot));
    size += sizeof(prot);

    // mov $flags,%r10d
    data[size++] = 0x41; data[size++] = 0xba;
    memcpy(data + size, &flags, sizeof(flags));
    size += sizeof(flags);

    size_t mmap_idx = 0;
    if (mmap != INTPTR_MIN)
    {
        // lea mmap(%rip),%r15
        data[size++] = 0x4c; data[size++] = 0x8d; data[size++] = 0x3d;
        data[size++] = 0x00; data[size++] = 0x00; data[size++] = 0x00;
        data[size++] = 0x00;
        mmap_idx = size;
    }

    // Step (2): Emit calls to mmap() that load trampoline pages:
    off_t prev_offset = -1;
    size_t prev_len   = SIZE_MAX;
    int prev_prot     = prot;
    std::vector<Bounds> bounds;
    for (int preload = 1; preload >= false; preload--)
    {
        for (auto mapping: mappings)
        {
            if (preload == false)
                stat_num_physical_bytes += mapping->size;
            off_t offset_0  = mapping->offset;
            for (; mapping != nullptr; mapping = mapping->merged)
            {
                if (mapping->preload != (bool)preload)
                    continue;
                bounds.clear();
                getVirtualBounds(mapping, bounds);
                for (const auto b: bounds)
                {
                    intptr_t base = mapping->base + b.lb;
                    size_t len    = b.ub - b.lb;
                    off_t offset  = offset_0 + b.lb;
                    int prot      = mapping->prot;
                    debug("load trampoline: mmap(" ADDRESS_FORMAT ", %zu, "
                        "%s%s%s0, MAP_FIXED | MAP_PRIVATE, fd, +%zd)",
                        ADDRESS(base), len,
                        (prot & PROT_READ? "PROT_READ | ": ""),
                        (prot & PROT_WRITE? "PROT_WRITE | ": ""),
                        (prot & PROT_EXEC? "PROT_EXEC | ": ""), offset);
                    stat_num_virtual_bytes += len;
                    size += emitLoaderMmap(data + size, pic, base, len,
                        prev_len, prot, prev_prot, offset, prev_offset,
                        (!preload && mmap != INTPTR_MIN));
                    prev_len    = len;
                    prev_offset = offset;
                    prev_prot   = prot;
                }
            }
        }
    }
    for (const auto &refactor: refactors)
    {
        intptr_t base = refactor.addr;
        size_t len    = refactor.size;
        off_t offset  = refactor.patched.offset;
        int prot      = PROT_READ | PROT_EXEC;
        debug("load refactoring: mmap(" ADDRESS_FORMAT ", %zu, %s%s%s0, "
            "MAP_FIXED | MAP_PRIVATE, fd, +%zd)",
            ADDRESS(base), len,
            (prot & PROT_READ? "PROT_READ | ": ""),
            (prot & PROT_WRITE? "PROT_WRITE | ": ""),
            (prot & PROT_EXEC? "PROT_EXEC | ": ""), offset);
        size += emitLoaderMmap(data + size, pic, base, len, prev_len, prot,
            prev_prot, offset, prev_offset);
        prev_len    = len;
        prev_offset = offset;
        prev_prot   = prot;
    }

    // Step (3): Close the fd:
    const uint8_t close_fd[] =
    {
        0x4c, 0x89, 0xc7,               // movq %r8,%rdi
        0xb8,                           // mov $SYS_CLOSE,%eax
            0x03, 0x00, 0x00, 0x00,
        0x0f, 0x05,                     // syscall (close)
    };
    memcpy(data + size, close_fd, sizeof(close_fd));
    size += sizeof(close_fd);

    // Step (4): Call the initialization routines (if any):
    for (auto init: inits)
    {
        size += emitLoadFuncPtrIntoRAX(data + size, pic, init);

        switch (mode)
        {
            case MODE_EXECUTABLE:
            {
                // Load argc, argv, and envp into %rdi, %rsi, and %rdx
                const uint8_t restore_args[] =
                {
                    0x48, 0x8b, 0x7c, 0x24, 0x60,   // mov 0x60(%rsp),%rdi
                    0x48, 0x8d, 0x74, 0x24, 0x68,   // lea 0x68(%rsp),%rsi
                    0x48, 0x8d, 0x54, 0xfe, 0x08,   // lea 0x8(%rsi,%rdi,8),%rdx
                };
                memcpy(data + size, restore_args, sizeof(restore_args));
                size += sizeof(restore_args);
                break;
            }
            case MODE_SHARED_OBJECT:
            {
                const uint8_t zero_args[] =
                {
                    0x31, 0xff,                     // xor %edi,%edi
                    0x31, 0xf6,                     // xor %esi,%esi
                    0x31, 0xd2,                     // xor %edx,%edx
                };
                memcpy(data + size, zero_args, sizeof(zero_args));
                size += sizeof(zero_args);
                break;
            }
        }
 
        // callq *%rax
        data[size++] = 0xff; data[size++] = 0xd0;
    }

    // Step (5): Setup jump to the real program/library entry address.
    size += emitLoadFuncPtrIntoRAX(data + size, pic, entry);

    // Step (6): Restore the register state (saved by loader entry):
    const uint8_t restore_state[] =
    {
        0x5f,                           // popq %rdi
        0x5e,                           // popq %rsi
        0x5a,                           // popq %rdx
        0x59,                           // popq %rcx
        0x41, 0x58,                     // popq %r8
        0x41, 0x59,                     // popq %r9
        0x41, 0x5a,                     // popq %r10
        0x41, 0x5b,                     // popq %r11
        0x41, 0x5c,                     // popq %r12
        0x41, 0x5d,                     // popq %r13
        0x41, 0x5e,                     // popq %r14
        0x41, 0x5f,                     // popq %r15
    };
    memcpy(data + size, restore_state, sizeof(restore_state));
    size += sizeof(restore_state);

    // Step (7): Jump to real entry address:
    // jmpq *rax
    data[size++] = 0xff; data[size++] = 0xe0;

    /*
     * Stage #3 (mmap wrapper)
     */

    // Emit the user-mmap wrapper (if necessary).
    if (mmap != INTPTR_MIN)
    {
        int32_t diff32 = size - mmap_idx;
        memcpy(data + mmap_idx - sizeof(int32_t), &diff32, sizeof(diff32));

        // This wrapper function translates from the syscall ABI into the
        // SYSV ABI, and preserves the necessary registers.

        // mov %r10, %rcx
        data[size++] = 0x4c; data[size++] = 0x89; data[size++] = 0xd1;

        // push scratch registers that we care about
        data[size++] = 0x57;                        // pushq %rdi
        data[size++] = 0x56;                        // pushq %rsi
        data[size++] = 0x52;                        // pushq %rdx
        data[size++] = 0x41; data[size++] = 0x50;   // pushq %r8
        data[size++] = 0x41; data[size++] = 0x51;   // pushq %r9
        data[size++] = 0x41; data[size++] = 0x52;   // pushq %r10

        if (mmap >= 0 && mmap <= INT32_MAX)
        {
            // mov $mmap32,%eax
            int32_t mmap32 = (int32_t)mmap;
            data[size++] = 0xb8;
            memcpy(data + size, &mmap32, sizeof(mmap32));
            size += sizeof(mmap32);
        }
        else
        {
            // movabs $mmap,%rax
            data[size++] = 0x48; data[size++] = 0xb8;
            memcpy(data + size, &mmap, sizeof(mmap));
            size += sizeof(mmap);
        }
        if (pic && !IS_ABSOLUTE(mmap))
        {
            // addq %r12,%rax
            data[size++] = 0x4c; data[size++] = 0x01; data[size++] = 0xe0;
        }

        // call *%rax
        data[size++] = 0xff; data[size++] = 0xd0;

        // pop scratch registers
        data[size++] = 0x41; data[size++] = 0x5a;      // popq %r10
        data[size++] = 0x41; data[size++] = 0x59;      // popq %r9
        data[size++] = 0x41; data[size++] = 0x58;      // popq %r8
        data[size++] = 0x5a;                           // popq %rdx
        data[size++] = 0x5e;                           // popq %rsi
        data[size++] = 0x5f;                           // popq %rdi

        // retq
        data[size++] = 0xc3;
    }

    return size;
}

/*
 * Emit the (modified) ELF binary.
 */
size_t emitElf(const Binary *B, const MappingSet &mappings,
    size_t mapping_size)
{
    uint8_t *data = B->patched.bytes;
    size_t size = B->patched.size;

    // Step (1): Round-up to nearest page boundary (zero-fill)
    stat_input_file_size = size;
    size = (size % PAGE_SIZE == 0?
        size: size + PAGE_SIZE - (size % PAGE_SIZE));

    // Step (2): Refactor the patching (if necessary):
    RefactorSet refactors;
    size += emitRefactoredPatch(B->original.bytes, data, size, mapping_size,
        B->Is, refactors);
    
    // Step (3): Emit all mappings:
    for (auto mapping: mappings)
    {
        uint8_t *base = data + size;
        mapping->offset = (off_t)size;
        printf("[\33[33m%.16lX\33[0m]", mapping->key);
        flattenMapping(base, mapping, /*int3=*/0xcc);
        size += mapping->size;
    }
    putchar('\n');

    // Step (4): Modify the entry address.
    intptr_t old_entry = 0;
    switch (B->mode)
    {
        case MODE_EXECUTABLE:
        {
            Elf64_Ehdr *ehdr = B->elf.ehdr;
            old_entry     = (intptr_t)B->elf.ehdr->e_entry;
            ehdr->e_entry = (Elf64_Addr)LOADER_ADDRESS;
            break;
        }
        case MODE_SHARED_OBJECT:
        {
            Elf64_Phdr *phdr = B->elf.phdr_dynamic;
            if (phdr == nullptr)
                error("failed to replace DT_INIT entry; missing PT_DYNAMIC "
                    "program header");
            Elf64_Dyn *dynamic = (Elf64_Dyn *)(data + phdr->p_offset);
            size_t num_dynamic = phdr->p_memsz / sizeof(Elf64_Dyn);
            bool found = false;
            for (size_t i = 0; !found && i < num_dynamic; i++)
            {
                if (dynamic[i].d_tag == DT_NULL)
                    break;
                if (dynamic[i].d_tag == DT_INIT)
                {
                    found = true;
                    old_entry = (intptr_t)dynamic[i].d_un.d_ptr;
                    dynamic[i].d_un.d_ptr = (Elf64_Addr)LOADER_ADDRESS;
                }
            }
            if (!found)
                error("failed to replace DT_INIT entry; entry was not found");
            break;
        }
    }

    // Step (5): Emit the loader:
    off_t loader_offset = (off_t)size;
    size_t loader_size  = emitLoader(refactors, mappings, data + size,
        old_entry, B->elf.pic, B->inits, B->mmap, B->mode);
    size += loader_size;

    // Step (6): Modify the PHDR to load the loader.
    // NOTE: Currently we use the well-known and easy-to-implement PT_NOTE
    //       injection method to load the loader.  Some alternative methods
    //       may also work, but are not yet implemented.
    Elf64_Phdr *phdr = B->elf.phdr_note;
    phdr->p_type   = PT_LOAD;
    phdr->p_flags  = PF_X | PF_R;
    phdr->p_offset = loader_offset;
    phdr->p_vaddr  = (Elf64_Addr)LOADER_ADDRESS;
    phdr->p_paddr  = (Elf64_Addr)nullptr;
    phdr->p_filesz = loader_size;
    phdr->p_memsz  = loader_size;
    phdr->p_align  = PAGE_SIZE;

    stat_output_file_size = size;
    return size;
}

