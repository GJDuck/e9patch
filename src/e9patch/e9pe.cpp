/*
 * e9pe.cpp
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

#include "e9loader_pe.c"

struct _IMAGE_FILE_HEADER
{
      uint16_t Machine;
      uint16_t NumberOfSections;
      uint32_t TimeDateStamp;
      uint32_t PointerToSymbolTable;
      uint32_t NumberOfSymbols;
      uint16_t SizeOfOptionalHeader;
      uint16_t Characteristics;
};

#define IMAGE_FILE_MACHINE_AMD64 0x8664

typedef struct _IMAGE_DATA_DIRECTORY
{
      uint32_t VirtualAddress;
      uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct _IMAGE_OPTIONAL_HEADER64
{
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[];
};

struct _IMAGE_SECTION_HEADER
{
    char Name[8];
    union
    {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    };
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_SHARED    0x10000000

#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001

#define ALIGN(x, y)             \
    ((x) % (y) == 0? (x): (x) + (y) - ((x) % (y)))

/*
 * Parse a Windows PE executable.
 */
void parsePE(Binary *B)
{
    const char *filename = B->filename;
    uint8_t *data = B->patched.bytes;
    size_t size = B->size;
    PEInfo &info = B->pe;

    if (size < 0x3c + sizeof(uint32_t))
        error("failed to parse PE file \"%s\"; file size (%zu) is too small "
            "for MS-DOS header", filename, size);
    if (data[0] != 'M' || data[1] != 'Z')
        error("failed to parse PE file \"%s\"; invalid MS-DOS stub header "
            "magic number, expected \"MZ\"", filename);
    uint32_t pe_offset = *(const uint32_t *)(data + 0x3c);
    const size_t pe_hdr_size = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) +
        sizeof(IMAGE_OPTIONAL_HEADER64);
    if (pe_offset < 0x3c + sizeof(uint32_t) || pe_offset + pe_hdr_size > size)
        error("failed to parse PE file \"%s\"; file size (%zu) is too small"
            "for PE header(s)", filename, size);
    if (data[pe_offset] != 'P' ||
            data[pe_offset+1] != 'E' ||
            data[pe_offset+2] != 0x0 ||
            data[pe_offset+3] != 0x0)
        error("failed to parse PE file \"%s\"; invalid PE signature, "
            "expected \"PE\\0\\0\"", filename);
    PIMAGE_FILE_HEADER file_hdr =
        (PIMAGE_FILE_HEADER)(data + pe_offset + sizeof(uint32_t));
    if (file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64)
        error("failed to parse PE file \"%s\"; invalid machine (0x%x), "
            "expected x86_64 (0x%x)", filename, file_hdr->Machine,
            IMAGE_FILE_MACHINE_AMD64);
    if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
        error("failed to parse PE file \"%s\"; invalid optional header "
            "size (%zu), expected (>=%zu)", filename,
            file_hdr->SizeOfOptionalHeader,
            sizeof(IMAGE_OPTIONAL_HEADER64));
    PIMAGE_OPTIONAL_HEADER64 opt_hdr =
        (PIMAGE_OPTIONAL_HEADER64)(file_hdr + 1);
    static const uint16_t PE64_MAGIC = 0x020b;
    if (opt_hdr->Magic != PE64_MAGIC)
        error("failed to parse PE file \"%s\"; invalid magic number (0x%x), "
            "expected PE64 (0x%x)", opt_hdr->Magic, PE64_MAGIC);
    uint32_t file_align = opt_hdr->FileAlignment;
    if (file_align < 512)
        error("failed to parse PE file \"%s\"; invalid file alignment (%u), "
            "expected (>=512)", file_align, filename);
    PIMAGE_SECTION_HEADER shdr =
        (PIMAGE_SECTION_HEADER)&opt_hdr->DataDirectory[
            opt_hdr->NumberOfRvaAndSizes];
    PIMAGE_SECTION_HEADER shdr_end = shdr + file_hdr->NumberOfSections;
    uint8_t *shdr_end8 = (uint8_t *)shdr_end;
    size_t shdr_size   = shdr_end8 - data;
    size_t shdr_size_1 = (shdr_size + file_align) - (shdr_size % file_align);
    if (shdr_size_1 > size)
        error("failed to parse PE file \"%s\"; invalid section header size "
            "(%zu), expected (<=%zu)", filename, shdr_size_1, size);
    if (shdr_size_1 - shdr_size < 2 * sizeof(IMAGE_SECTION_HEADER))
        error("failed to parse PE file \"%s\"; no free space in section "
            "header (NYI)");

    intptr_t lb = (intptr_t)opt_hdr->ImageBase;
    intptr_t ub = lb + (intptr_t)opt_hdr->SizeOfImage;
    lb -= lb % WINDOWS_VIRTUAL_ALLOC_SIZE;
    ub  = ALIGN(ub, WINDOWS_VIRTUAL_ALLOC_SIZE);
    if (!reserve(B, lb, ub))
        error("failed to reserve image range [0x%lx..0x%lx]", lb, ub);

    info.file_hdr  = file_hdr;
    info.opt_hdr   = opt_hdr;
    info.free_shdr = shdr + file_hdr->NumberOfSections;
}

/*
 * Emit the (modified) PE executable.
 */
size_t emitPE(const Binary *B, const MappingSet &mappings, size_t mapping_size)
{
    uint8_t *data = B->patched.bytes;
    size_t size = B->patched.size;
    uint32_t mapping_align = (uint32_t)WINDOWS_VIRTUAL_ALLOC_SIZE;
    stat_input_file_size = size;
    size = ALIGN(size, mapping_align);
     
    // Emit all mappings:
    for (auto mapping: mappings)
    {
        uint8_t *base = data + size;
        mapping->offset = (off_t)size;
        flattenMapping(B, base, mapping, /*int3=*/0xcc);
        size += mapping->size;
    }

    // Emit the loader:
    PIMAGE_OPTIONAL_HEADER64 opt_hdr = B->pe.opt_hdr;
    uint32_t size_of_image = opt_hdr->SizeOfImage;

    uint32_t section_align = opt_hdr->SectionAlignment;
    uint32_t file_align = B->pe.opt_hdr->FileAlignment;
    size = ALIGN(size, file_align);
    off_t loader_offset = (off_t)size;
    struct e9_config_s *config = (struct e9_config_s *)(data + size);
    size_t config_offset = size;
    size += sizeof(struct e9_config_s);
    const char magic[]   = "E9PATCH";
    memcpy(config->magic, magic, sizeof(magic));
    config->base  = (intptr_t)size_of_image;
    config->entry = (intptr_t)opt_hdr->AddressOfEntryPoint;

    std::vector<Bounds> bounds;
    config->maps[1] = (uint32_t)(size - config_offset);
    for (auto mapping: mappings)
    {
        // XXX: TODO: refactor!
        stat_num_physical_bytes += mapping->size;
        off_t offset_0 = mapping->offset;
        for (; mapping != nullptr; mapping = mapping->merged)
        {
            bounds.clear();
            getVirtualBounds(mapping, WINDOWS_VIRTUAL_ALLOC_SIZE, bounds);
            bool r = ((mapping->prot & PROT_READ) != 0);
            bool w = ((mapping->prot & PROT_WRITE) != 0);
            bool x = ((mapping->prot & PROT_EXEC) != 0);
            for (const auto b: bounds)
            {
                intptr_t base = mapping->base + b.lb;
                size_t len    = b.ub - b.lb;
                off_t offset  = offset_0 + b.lb;

                debug("load trampoline: mmap(" ADDRESS_FORMAT ", %zu, "
                    "%s%s%s0, MAP_FIXED | MAP_PRIVATE, fd, +%zd)",
                    ADDRESS(base), len,
                    (r? "PROT_READ | ": ""),
                    (w? "PROT_WRITE | ": ""),
                    (x? "PROT_EXEC | ": ""), offset_0);
                stat_num_virtual_bytes += len;

                size += emitLoaderMap(data + size, base, len, offset,
                    r, w, x, nullptr);
                config->num_maps[1]++;
            }
        }
    }

    uint32_t addr_of_entry = size_of_image + (uint32_t)(size - config_offset);
    opt_hdr->AddressOfEntryPoint = addr_of_entry;

    if (option_trap_entry)
        data[size++] = /*int3=*/0xCC;
    // lea config(%rip), %rdx
    data[size++] = 0x48; data[size++] = 0x8D; data[size++] = 0x15;
    int32_t config_rel32 =
        -(int32_t)((size + sizeof(int32_t)) - config_offset);
    memcpy(data + size, &config_rel32, sizeof(config_rel32));
    size += sizeof(config_rel32);
    memcpy(data + size, e9loader_pe_bin, sizeof(e9loader_pe_bin));
    size += sizeof(e9loader_pe_bin);

    uint32_t loader_virtual_size = (uint32_t)(size - config_offset);
    size = ALIGN(size, file_align);
    uint32_t loader_disk_size = (uint32_t)(size - config_offset);
    size_t config_size = (size_t)loader_disk_size;
    config->size = (uint32_t)ALIGN(config_size, PAGE_SIZE);

    // Step (6): Update the PE headers:
    PIMAGE_SECTION_HEADER shdr = B->pe.free_shdr;
    memset(shdr, 0x0, sizeof(IMAGE_SECTION_HEADER));
    const char section_name[] = ".e9load";
    memcpy(shdr->Name, section_name, sizeof(section_name));
    if (loader_offset > UINT32_MAX)
        error("failed to set the loader offset to %+ld; maximum allowable "
            "value (%+lu) exceeded", loader_offset, UINT32_MAX);

    shdr->VirtualAddress   = size_of_image;
    shdr->VirtualSize      = loader_virtual_size;
    shdr->SizeOfRawData    = loader_disk_size;
    shdr->PointerToRawData = (uint32_t)loader_offset;
    shdr->Characteristics  = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_SHARED;

    uint32_t virtual_size = ALIGN(loader_virtual_size, section_align);
    size_of_image += virtual_size;
    opt_hdr->SizeOfImage = size_of_image;
    opt_hdr->CheckSum    = 0;

    PIMAGE_FILE_HEADER file_hdr = B->pe.file_hdr;
    file_hdr->NumberOfSections++;

    /*
     * Disable ASLR.
     *
     * Windows ASLR depends on text relocations, which is not compatible with
     * static binary rewriting.  Thus, it must be disabled...
     */
    opt_hdr->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
    opt_hdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
    file_hdr->Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    stat_output_file_size = size;
    return size;
}

