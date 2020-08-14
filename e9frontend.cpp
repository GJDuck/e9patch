/*
 *        ___  _              _ 
 *   ___ / _ \| |_ ___   ___ | |
 *  / _ \ (_) | __/ _ \ / _ \| |
 * |  __/\__, | || (_) | (_) | |
 *  \___|  /_/ \__\___/ \___/|_|
 *  
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

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <regex>
#include <string>

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <elf.h>

#include "e9frontend.h"

/*
 * ELF file.
 */
namespace e9frontend
{
    struct ELF
    {
        const char *filename;           // Filename.
        const uint8_t *data;            // File data.
        size_t size;                    // File size.
        intptr_t base;                  // Base address.
        const Elf64_Phdr *phdrs;        // Elf PHDRs.
        size_t phnum;                   // Number of PHDRs.
        off_t    text_offset;           // (.text) section offset.
        intptr_t text_addr;             // (.text) section address.
        size_t   text_size;             // (.text) section size.
        const char *dynamic_strtab;     // Dynamic string table.
        size_t dynamic_strsz;           // Dynamic string table size.
        const Elf64_Sym *dynamic_symtab;// Dynamic symbol table.
        size_t dynamic_symsz;           // Dynamic symbol table size.
        intptr_t free_addr;             // First unused address.
        bool pie;                       // PIE?
        bool dso;                       // Shared object?
        bool reloc;                     // Needs relocation?
    };
};

using namespace e9frontend;

/*
 * Options.
 */
static bool option_is_tty = false;

/*
 * Backend info.
 */
struct Backend
{
    FILE *out;                      // JSON RPC output.
    pid_t pid;                      // Backend process ID.
};

/*
 * Report an error and exit.
 */
void NO_RETURN e9frontend::error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s: ",
        (option_is_tty? "\33[31m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);

    putc('\n', stderr);

    _Exit(EXIT_FAILURE);
}

/*
 * Print a warning message.
 */
void e9frontend::warning(const char *msg, ...)
{
    fprintf(stderr, "%swarning%s: ",
        (option_is_tty? "\33[33m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);

    putc('\n', stderr);
}

/*
 * Duplicate a string.
 */
static char *strDup(const char *old_str, size_t n = SIZE_MAX)
{
    char *new_str = strndup(old_str, n);
    if (new_str == nullptr)
        error("failed to duplicate string \"%s\": %s", old_str,
            strerror(ENOMEM));
    return new_str;
}

/*
 * Send message header.
 */
void e9frontend::sendMessageHeader(FILE *out, const char *method)
{
    fprintf(out, "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{",
        method);
}

/*
 * Send message footer.
 */
unsigned e9frontend::sendMessageFooter(FILE *out, bool sync)
{
    static unsigned next_id = 0;
    unsigned id = next_id;
    next_id++;
    fprintf(out, "},\"id\":%u}\n", id);
    if (sync)
        fflush(out);
    return id;
}

/*
 * Send parameter header.
 */
void e9frontend::sendParamHeader(FILE *out, const char *name)
{
    fprintf(out, "\"%s\":", name);
}

/*
 * Send parameter separator.
 */
void e9frontend::sendSeparator(FILE *out, bool last)
{
    fprintf(out, "%s", (last? "": ","));
}

/*
 * Send metadata header.
 */
void e9frontend::sendMetadataHeader(FILE *out)
{
    putc('{', out);
}


/*
 * Send metadata footer.
 */
void e9frontend::sendMetadataFooter(FILE *out)
{
    putc('}', out);
}

/*
 * Send definition header.
 */
void e9frontend::sendDefinitionHeader(FILE *out, const char *name)
{
    fprintf(out, "\"%s\":", name);
}

/*
 * Send an integer parameter.
 */
void e9frontend::sendInteger(FILE *out, intptr_t i)
{
    if (i >= INT32_MIN && i <= INT32_MAX)
        fprintf(out, "%ld", i);
    else
    {
        bool neg = (i < 0);
        uint64_t x = (uint64_t)(neg? -i: i);
        fprintf(out, "\"%s0x%lx\"", (neg? "-": ""), x);
    }
}

/*
 * Send a string parameter.
 */
void e9frontend::sendString(FILE *out, const char *s)
{
    putc('\"', out);
    for (unsigned i = 0; s[i] != '\0'; i++)
    {
        char c = s[i];
        switch (c)
        {
            case '\\':
                fputs("\\\\", out);
                break;
            case '\"':
                fputs("\\\"", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\b':
                fputs("\\b", out);
                break;
            case '\f':
                fputs("\\f", out);
                break;
            default:
                putc(c, out);
                break;
        }
    }
    putc('\"', out);
}

/*
 * Send a "binary" message.
 */
static unsigned sendBinaryMessage(FILE *out, const char *mode,
    const char *filename)
{
    sendMessageHeader(out, "binary");
    sendParamHeader(out, "filename");
    sendString(out, filename);
    sendSeparator(out);
    sendParamHeader(out, "mode");
    sendString(out, mode);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send an "instruction" message.
 */
static unsigned sendInstructionMessage(FILE *out, intptr_t addr,
    size_t size, off_t offset)
{
    sendMessageHeader(out, "instruction");
    sendParamHeader(out, "address");
    sendInteger(out, addr);
    sendSeparator(out);
    sendParamHeader(out, "length");
    sendInteger(out, (intptr_t)size);
    sendSeparator(out);
    sendParamHeader(out, "offset");
    sendInteger(out, (intptr_t)offset);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out);
}

/*
 * Send a "patch" message.
 */
unsigned e9frontend::sendPatchMessage(FILE *out, const char *trampoline,
    off_t offset, const Metadata *metadata)
{
    sendMessageHeader(out, "patch");
    sendParamHeader(out, "trampoline");
    sendString(out, trampoline);
    sendSeparator(out);
    if (metadata != nullptr)
    {
        sendParamHeader(out, "metadata");
        sendMetadataHeader(out);
        for (unsigned i = 0; metadata[i].name != nullptr; i++)
        {
            sendDefinitionHeader(out, metadata[i].name);
            fputs(metadata[i].data, out);
            sendSeparator(out, (metadata[i+1].name == nullptr));
        }
        sendMetadataFooter(out);
        sendSeparator(out);
    }
    sendParamHeader(out, "offset");
    sendInteger(out, (intptr_t)offset);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send an "emit" message.
 */
static unsigned sendEmitMessage(FILE *out, const char *filename,
    const char *format, size_t mapping_size)
{
    sendMessageHeader(out, "emit");
    sendParamHeader(out, "filename");
    sendString(out, filename);
    sendSeparator(out);
    sendParamHeader(out, "format");
    sendString(out, format);
    sendSeparator(out);
    sendParamHeader(out, "mapping_size");
    sendInteger(out, mapping_size);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "reserve" message.
 */
unsigned e9frontend::sendReserveMessage(FILE *out, intptr_t addr, size_t len,
    bool absolute)
{
    sendMessageHeader(out, "reserve");
    sendParamHeader(out, "address");
    sendInteger(out, addr);
    sendSeparator(out);
    if (absolute)
    {
        sendParamHeader(out, "absolute");
        fprintf(out, "true");
        sendSeparator(out);
    }
    sendParamHeader(out, "length");
    sendInteger(out, (intptr_t)len);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out);
}

/*
 * Send a "reserve" message.
 */
unsigned e9frontend::sendReserveMessage(FILE *out, intptr_t addr,
    const uint8_t *data, size_t len, int prot, intptr_t init, intptr_t mmap,
    bool absolute)
{
    sendMessageHeader(out, "reserve");
    sendParamHeader(out, "address");
    sendInteger(out, addr);
    sendSeparator(out);
    sendParamHeader(out, "protection");
    fprintf(out, "\"%c%c%c\"",
        (prot & PROT_READ?  'r': '-'),
        (prot & PROT_WRITE? 'w': '-'),
        (prot & PROT_EXEC?  'x': '-'));
    sendSeparator(out);
    if (init != 0x0)
    {
        sendParamHeader(out, "init");
        sendInteger(out, init);
        sendSeparator(out);
    }
    if (mmap != 0x0)
    {
        sendParamHeader(out, "mmap");
        sendInteger(out, mmap);
        sendSeparator(out);
    }
    if (absolute)
    {
        sendParamHeader(out, "absolute");
        fprintf(out, "true");
        sendSeparator(out);
    }
    sendParamHeader(out, "bytes");
    fputc('[', out);
    for (size_t i = 0; i+1 < len; i++)
        fprintf(out, "%u,", data[i]);
    if (len != 0)
        fprintf(out, "%u", data[len-1]);
    fputc(']', out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "passthru" "trampoline" message.
 */
unsigned e9frontend::sendPassthruTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "passthru");
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);
    fprintf(out, "\"$instruction\",\"$continue\"]");
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "print" "trampoline" message.
 */
unsigned e9frontend::sendPrintTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "print");
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);

    /*
     * Print instrumentation works by setting up a SYS_write system call that
     * prints a string representation of the instruction to stderr.  The
     * string representation is past via macros defined by the "patch"
     * message.
     */

    // Save registers we intend to use:
    fprintf(out, "%u,%u,%u,%u,%u,%u,%u,%u,",        // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x00, 0xc0, 0xff, 0xff);
    fprintf(out, "%u,", 0x57);                      // push %rdi
    fprintf(out, "%u,", 0x56);                      // push %rsi
    fprintf(out, "%u,", 0x50);                      // push %rax
    fprintf(out, "%u,", 0x51);                      // push %rcx
    fprintf(out, "%u,", 0x52);                      // push %rdx
    fprintf(out, "%u,%u,", 0x41, 0x53);             // push %r11

    // Set-up the arguments to the SYS_write system call:
    fprintf(out, "%u,%u,%u,", 0x48, 0x8d, 0x35);    // leaq .Lstring(%rip), %rsi
    fprintf(out, "{\"rel32\":\".Lstring\"},");
    fprintf(out, "%u,", 0xba);                      // mov $strlen,%edx
    fprintf(out, "\"$asmStrLen\",");
    fprintf(out, "%u,%u,%u,%u,%u,",                 // mov $0x2,%edi
        0xbf, 0x02, 0x00, 0x00, 0x00);
    fprintf(out, "%u,%u,%u,%u,%u,",                 // mov $0x1,%eax
        0xb8, 0x01, 0x00, 0x00, 0x00);

    // Execute the system call:
    fprintf(out, "%u,%u", 0x0f, 0x05);              // syscall 

    // Restore the saved registers:
    fprintf(out, ",%u,%u", 0x41, 0x5b);             // pop %r11
    fprintf(out, ",%u", 0x5a);                      // pop %rdx
    fprintf(out, ",%u", 0x59);                      // pop %rcx
    fprintf(out, ",%u", 0x58);                      // pop %rax
    fprintf(out, ",%u", 0x5e);                      // pop %rsi
    fprintf(out, ",%u", 0x5f);                      // pop %rdi
    fprintf(out, ",%u,%u,%u,%u,%u,%u,%u,%u",        // lea 0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x00, 0x40, 0x00, 0x00);
    
    // Execute the displaced instruction, and return from the trampoline:
    fprintf(out, ",\"$instruction\",\"$continue\"");
    
    // Place the string representation of the instruction here:
    fprintf(out, ",\".Lstring\",\"$asmStr\"]");

    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "trap" "trampoline" message.
 */
unsigned e9frontend::sendTrapTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "trap");
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);
    fprintf(out, "%u]", 0xcc);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Attempt to guess if the filename is a library or not.
 */
static bool isLibraryFilename(const char *filename)
{
    const char *str;
    while ((str = strchr(filename, '/')) != nullptr)
        filename = str+1;
    str = strstr(filename, "lib");
    if (str == nullptr)
        return false;
    str = strstr(str, ".so");
    if (str == nullptr)
        return false;
    str += 3;
    while (*str != '\0')
    {
        if (*str != '.')
            return false;
        str++;
        if (!isdigit(*str++))
            return false;
        while (isdigit(*str))
            str++;
    }
    return true;
}

/*
 * Parse an ELF file.
 */
void e9frontend::parseELF(const char *filename, intptr_t base, ELF &elf)
{
    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", filename,
            strerror(errno));

    struct stat stat;
    if (fstat(fd, &stat) != 0)
        error("failed to get statistics for file \"%s\": %s", filename,
            strerror(errno));

    size_t size = (size_t)stat.st_size;
    void *ptr = mmap(NULL, size, MAP_SHARED, PROT_READ, fd, 0);
    if (ptr == MAP_FAILED)
        error("failed to map file \"%s\" into memory: %s", filename,
            strerror(errno));
    close(fd);
    const uint8_t *data = (const uint8_t *)ptr;

    /*
     * Basic ELF file parsing.
     */
    if (size < sizeof(Elf64_Ehdr))
        error("failed to parse ELF EHDR from file \"%s\"; file is too small",
            filename);
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
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
    if (ehdr->e_phoff < sizeof(Elf64_Ehdr) ||
        ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr) > size)
        error("failed to parse ELF file \"%s\"; invalid program headers",
            filename);
    if (ehdr->e_shnum > SHN_LORESERVE)
        error("failed to parse ELF file \"%s\"; too many section headers",
            filename);
    if (ehdr->e_shoff < sizeof(Elf64_Ehdr) ||
        ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > size)
        error("failed to parse ELF file \"%s\"; invalid section headers",
            filename);

    bool pic = false;
    bool exe = false;
    switch (ehdr->e_type)
    {
        case ET_DYN:
            pic = true;
            break;
        case ET_EXEC:
            exe = true;
            break;
        default:
            error("failed to parse ELF file \"%s\"; file is not executable",
                filename);
    }

    /*
     * Find the (.strtab) section.
     */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(data + ehdr->e_shoff);
    if (ehdr->e_shstrndx >= ehdr->e_shnum ||
        shdrs[ehdr->e_shstrndx].sh_offset + shdrs[ehdr->e_shstrndx].sh_size
            > size)
    {
        error("failed to parse ELF file \"%s\"; invalid \".strtab\" section",
            filename);
    }
    size_t strtab_size = shdrs[ehdr->e_shstrndx].sh_size;
    const char *strtab =
        (const char *)(data + shdrs[ehdr->e_shstrndx].sh_offset);

    /*
     * Find the (.text) and (.dynamic) sections.
     */
    size_t shnum = (size_t)ehdr->e_shnum;
    const Elf64_Shdr *shdr_text = nullptr, *shdr_dynsym = nullptr,
        *shdr_dynstr = nullptr;
    bool reloc = false;
    for (size_t i = 0; i < shnum; i++)
    {
        const Elf64_Shdr *shdr = shdrs + i;
        if (shdr->sh_name >= strtab_size)
            continue;
        switch (shdr->sh_type)
        {
            case SHT_PROGBITS:
                if (strcmp(strtab + shdr->sh_name, ".text") == 0)
                    shdr_text = shdr;
                break;
            case SHT_DYNSYM:
                if (strcmp(strtab + shdr->sh_name, ".dynsym") == 0)
                    shdr_dynsym = shdr;
                break;
            case SHT_STRTAB:
                if (strcmp(strtab + shdr->sh_name, ".dynstr") == 0)
                    shdr_dynstr = shdr;
                break;
            case SHT_REL:
            case SHT_RELA:
                reloc = true;
                break;
            default:
                break;
        }
    }
    if (shdr_text == nullptr)
        error("failed to parse ELF file \"%s\"; missing \".text\" section",
            filename);
    intptr_t text_addr = (intptr_t)shdr_text->sh_addr;
    size_t   text_size = (size_t)shdr_text->sh_size;

    /*
     * Find the (.text) offset.
     */
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    size_t phnum = (size_t)ehdr->e_phnum;
    off_t text_offset = -1;
    intptr_t free_addr = INTPTR_MIN;
    for (size_t i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        intptr_t phdr_base = (intptr_t)phdr->p_vaddr;
        intptr_t phdr_end  = phdr_base + phdr->p_memsz;
        free_addr = std::max(free_addr, phdr_end);
        switch (phdr->p_type)
        {
            case PT_LOAD:
            {
                if (text_addr >= phdr_base &&
                        text_addr + (ssize_t)text_size <= phdr_end)
                {
                    off_t segment_offset =
                        (off_t)text_addr - (off_t)phdr->p_vaddr;
                    text_offset = (off_t)phdr->p_offset + segment_offset;
                }
                break;
            }
            case PT_INTERP:
                if (!exe && !isLibraryFilename(filename))
                    exe = true;
                break;
            default:
                break;
        }
    }
    if (text_offset < 0)
        error("failed to parse ELF file \"%s\"; missing segment for "
            "\".text\" section", filename);

    /*
     * Parse the dynamic section.
     */
    const char *dynamic_strtab = nullptr;
    const Elf64_Sym *dynamic_symtab = nullptr;
    size_t dynamic_strsz = 0, dynamic_symsz = 0;
    if (shdr_dynstr != nullptr && shdr_dynsym != nullptr)
    {
        // TODO Check offsets within file bounds...
        dynamic_strtab = (const char *)(data + shdr_dynstr->sh_offset);
        dynamic_strsz  = shdr_dynstr->sh_size;
        dynamic_symtab = (const Elf64_Sym *)(data + shdr_dynsym->sh_offset);
        dynamic_symsz  = shdr_dynsym->sh_size;
    }

    elf.filename       = strDup(filename);
    elf.data           = data;
    elf.size           = size;
    elf.base           = base;
    elf.phdrs          = phdrs;
    elf.phnum          = phnum;
    elf.text_offset    = text_offset;
    elf.text_addr      = text_addr;
    elf.text_size      = text_size;
    elf.dynamic_strtab = dynamic_strtab;
    elf.dynamic_strsz  = dynamic_strsz;
    elf.dynamic_symtab = dynamic_symtab;
    elf.dynamic_symsz  = dynamic_symsz;
    elf.free_addr      = free_addr;
    elf.pie            = (pic && exe);
    elf.dso            = (pic && !exe);
    elf.reloc          = reloc;
}

/*
 * Lookup the address of a symbol, or INTPTR_MIN if not found.
 */
intptr_t e9frontend::lookupSymbol(const ELF &elf, const char *symbol)
{
    if (elf.dynamic_symtab == nullptr || elf.dynamic_symsz == 0 ||
            elf.dynamic_strtab == nullptr || elf.dynamic_strsz == 0)
        return INTPTR_MIN;

    size_t num_dyms = elf.dynamic_symsz / sizeof(Elf64_Sym);
    for (size_t i = 0; i < num_dyms; i++)
    {
        const Elf64_Sym *sym = elf.dynamic_symtab + i;
        if (sym->st_name >= elf.dynamic_strsz)
            continue;
        if (strcmp(elf.dynamic_strtab + sym->st_name, symbol) == 0)
        {
            intptr_t addr = elf.base + (intptr_t)sym->st_value;
            return addr;
        }
    }
    return INTPTR_MIN;
}

/*
 * Embed an ELF file.
 */
void e9frontend::sendELFFileMessage(FILE *out, const ELF &elf, bool absolute)
{
    /*
     * Sanity checks.
     */
    if (!elf.pie)
        error("failed to embed ELF file \"%s\"; file is not a dynamic "
            "executable", elf.filename);
    if (elf.reloc)
        error("failed to embed ELF file \"%s\"; file uses relocations",
            elf.filename);

    /*
     * Check for special routines.
     */
    intptr_t init = lookupSymbol(elf, "init");
    intptr_t mmap = lookupSymbol(elf, "mmap");

    /*
     * Send segments.
     */
    const Elf64_Phdr *phdrs = elf.phdrs;
    for (size_t i = 0; i < elf.phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        if (phdr->p_type != PT_LOAD)
            continue;
        intptr_t phdr_base  = (intptr_t)phdr->p_vaddr + elf.base;
        intptr_t phdr_end   = phdr_base + phdr->p_memsz;
        char prot[4] = "---";
        prot[0] = ((phdr->p_flags & PF_R) != 0? 'r': '-');
        prot[1] = ((phdr->p_flags & PF_W) != 0? 'w': '-');
        prot[2] = ((phdr->p_flags & PF_X) != 0? 'x': '-');

        sendMessageHeader(out, "reserve");
        sendParamHeader(out, "address");
        sendInteger(out, phdr_base);
        sendSeparator(out);
        if (absolute)
        {
            sendParamHeader(out, "absolute");
            fprintf(out, "true");
            sendSeparator(out);
        }
        if ((phdr->p_flags & PF_X) != 0 && init >= phdr_base &&
                init <= phdr_end)
        {
            sendParamHeader(out, "init");
            sendInteger(out, init);
            sendSeparator(out);
        }
        if ((phdr->p_flags & PF_X) != 0 && mmap >= phdr_base &&
                mmap <= phdr_end)
        {
            sendParamHeader(out, "mmap");
            sendInteger(out, mmap);
            sendSeparator(out);
        }
        sendParamHeader(out, "protection");
        sendString(out, prot);
        sendSeparator(out);
        sendParamHeader(out, "bytes");
        fputc('[', out);
        size_t j;
        for (j = 0; j < phdr->p_filesz; j++)
            fprintf(out, "%u%s", elf.data[phdr->p_offset + j],
                (j + 1 < phdr->p_memsz? ",": ""));
        for (; j < phdr->p_memsz; j++)
            fprintf(out, "0%s", (j + 1 < phdr->p_memsz? ",": ""));
        fputc(']', out);
        sendSeparator(out, /*last=*/true);
        sendMessageFooter(out, /*sync=*/true);
    }
}

/*
 * Send a `mov %r64,%r64' instruction.
 */
static void sendMovR64R64(FILE *out, ArgumentKind arg, unsigned argno)
{
    switch (arg)
    {
        case ARGUMENT_RAX:
        case ARGUMENT_RBX:
        case ARGUMENT_RCX:
        case ARGUMENT_RDX:
        case ARGUMENT_RDI:
        case ARGUMENT_RSI:
        case ARGUMENT_RBP:
            fprintf(out, "%u,", (argno < 4? 0x48: 0x49));
            break;
        case ARGUMENT_R8:
        case ARGUMENT_R9:
        case ARGUMENT_R10:
        case ARGUMENT_R11:
        case ARGUMENT_R12:
        case ARGUMENT_R13:
        case ARGUMENT_R14:
        case ARGUMENT_R15:
            fprintf(out, "%u,", (argno < 4? 0x4c: 0x4d));
            break;
        default:
            return;
    }
    fprintf(out, "%u,", 0x89);
    uint8_t mod = 0x3;
    const uint8_t rm[] = {0x7, 0x6, 0x2, 0x1, 0x0, 0x1};
    uint8_t reg = 0;
    switch (arg)
    {
        case ARGUMENT_RAX: case ARGUMENT_R8:
            reg = 0x0; break;
        case ARGUMENT_RCX: case ARGUMENT_R9:
            reg = 0x1; break;
        case ARGUMENT_RDX: case ARGUMENT_R10:
            reg = 0x2; break;
        case ARGUMENT_RBX: case ARGUMENT_R11:
            reg = 0x3; break;
        case ARGUMENT_R12:
            reg = 0x4; break;
        case ARGUMENT_RBP: case ARGUMENT_R13:
            reg = 0x5; break;
        case ARGUMENT_RSI: case ARGUMENT_R14:
            reg = 0x6; break;
        case ARGUMENT_RDI: case ARGUMENT_R15:
            reg = 0x7; break;
        default:
            break;
    };
    uint8_t modRM = (mod << 6) | (reg << 3) | rm[argno];
    fprintf(out, "%u,", modRM);
}

/*
 * Send a `mov off8(%rsp),%r64' instruction.
 */
static void sendMovRSPR64(FILE *out, int8_t offset8, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8b, 0x7c);                  // mov off8(%rsp),%rdi
            break;
        case 1:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8b, 0x74);                  // mov off8(%rsp),%rsi
            break;
        case 2:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8b, 0x54);                  // mov off8(%rsp),%rdx
            break;
        case 3:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8b, 0x4c);                  // mov off8(%rsp),%rcx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8b, 0x44);                  // mov off8(%rsp),%r8
            break;
        case 5:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8b, 0x4c);                  // mov off8(%rsp),%r9
            break;
    }
    fprintf(out, "%u,%u,", 0x24, (uint8_t)offset8);
}

/*
 * Send a `movzwl off8(%rsp),%r32' instruction.
 */
static void sendMovZWLRSPR32(FILE *out, int8_t offset8, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,%u,",
                0x0f, 0xb7, 0x7c);                  // movzwl off8(%rsp),%edi
            break;
        case 1:
            fprintf(out, "%u,%u,%u,",
                0x0f, 0xb7, 0x74);                  // movzwl off8(%rsp),%esi
            break;
        case 2:
            fprintf(out, "%u,%u,%u,",
                0x0f, 0xb7, 0x54);                  // movzwl off8(%rsp),%edx
            break;
        case 3:
            fprintf(out, "%u,%u,%u,",
                0x0f, 0xb7, 0x4c);                  // movzwl off8(%rsp),%ecx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,%u,",
                0x44, 0x0f, 0xb7, 0x44);            // movzwl off8(%rsp),%r8d
            break;
        case 5:
            fprintf(out, "%u,%u,%u,%u,",
                0x44, 0x0f, 0xb7, 0x4c);            // movzwl off8(%rsp),%r9d
            break;
    }
    fprintf(out, "%u,%u,", 0x24, (uint8_t)offset8);
}

/*
 * Send a `mov $i32,%r32' instruction opcode.
 */
static void sendMovI32R32(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,", 0xbf);              // mov ...,%edi
            break;
        case 1:
            fprintf(out, "%u,", 0xbe);              // mov ...,%esi
            break;
        case 2:
            fprintf(out, "%u,", 0xba);              // mov ...,%edx
            break;
        case 3:
            fprintf(out, "%u,", 0xb9);              // mov ...,%ecx
            break;
        case 4:
            fprintf(out, "%u,%u,", 0x41, 0xb8);     // mov ...,%r8d
            break;
        case 5:
            fprintf(out, "%u,%u,", 0x41, 0xb9);     // mov ...,%r9d
            break;
    }
}

/*
 * Send a `xor %r32,%r32` instruction.
 */
static void sendZeroR32(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,", 0x31, 0xff);     // xor %edi,%edi
            break;
        case 1:
            fprintf(out, "%u,%u,", 0x31, 0xf6);     // xor %esi,%esi
            break;
        case 2:
            fprintf(out, "%u,%u,", 0x31, 0xd2);     // xor %edx,%edx
            break;
        case 3:
            fprintf(out, "%u,%u,", 0x31, 0xc9);     // xor %ecx,%ecx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,",
                0x45, 0x31, 0xc0);                  // xor %r8d,%r8d
            break;
        case 5:
            fprintf(out, "%u,%u,%u,",
                0x45, 0x31, 0xc9);                  // xor %r9d,%r9d
            break;
    }
}

/*
 * Send a `mov $i32,%r64' instruction opcode.
 */
static void sendMovI32R64(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,%u,",
                0x48, 0xc7, 0xc7);                  // mov ...,%rdi
            break;
        case 1:
            fprintf(out, "%u,%u,%u,",
                0x48, 0xc7, 0xc6);                  // mov ...,%rsi
            break;
        case 2:
            fprintf(out, "%u,%u,%u,",
                0x48, 0xc7, 0xc2);                  // mov ...,%rdx
            break;
        case 3:
            fprintf(out, "%u,%u,%u,",
                0x48, 0xc7, 0xc1);                  // mov ...,%rcx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,",
                0x49, 0xc7, 0xc0);                  // mov ...,%r8
            break;
        case 5:
            fprintf(out, "%u,%u,%u,",
                0x49, 0xc7, 0xc1);                  // mov ...,%r9
            break;
    }
}

/*
 * Send a `movabs $i64,%r64' instruction opcode.
 */
static void sendMovI64R64(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,", 0x48, 0xbf);     // movabs ...,%rdi
            break;
        case 1:
            fprintf(out, "%u,%u,", 0x48, 0xbe);     // movabs ...,%rsi
            break;
        case 2:
            fprintf(out, "%u,%u,", 0x48, 0xba);     // movabs ...,%rdx
            break;
        case 3:
            fprintf(out, "%u,%u,", 0x48, 0xb9);     // movabs ...,%rcx
            break;
        case 4:
            fprintf(out, "%u,%u,", 0x49, 0xb8);     // movabs ...,%r8
            break;
        case 5:
            fprintf(out, "%u,%u,", 0x49, 0xb9);     // movabs ...,%r9
            break;
    }
}

/*
 * Send a `lea ...(%rip),%r64' instruction opcode.
 */
static void sendLeaRIPR64(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x3d);                  // lea ...(%rip),%rdi
            break;
        case 1:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x35);                  // lea ...(%rip),%rsi
            break;
        case 2:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x15);                  // lea ...(%rip),%rdx
            break;
        case 3:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x0d);                  // lea ...(%rip),%rcx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8d, 0x05);                  // lea ...(%rip),%r8
            break;
        case 5:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8d, 0x0d);                  // lea ...(%rip),%r9
            break;
    }
}

/*
 * Send a `lea ...(%rsp),%r64' instruction opcode.
 */
static void sendLeaRSPR64(FILE *out, unsigned argno)
{
    switch (argno)
    {
        case 0:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0xbc);                  // lea ...(%rsp),%rdi
            break;
        case 1:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0xb4);                  // lea ...(%rsp),%rsi
            break;
        case 2:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x94);                  // lea ...(%rsp),%rdx
            break;
        case 3:
            fprintf(out, "%u,%u,%u,",
                0x48, 0x8d, 0x8c);                  // lea ...(%rsp),%rcx
            break;
        case 4:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8d, 0x84);                  // lea ...(%rsp),%r8
            break;
        case 5:
            fprintf(out, "%u,%u,%u,",
                0x4c, 0x8d, 0x8c);                  // lea ...(%rsp),%r9
            break;
    }
    fprintf(out, "%u,", 0x24);
}

/*
 * Get load target name.
 */
static const char *getLoadTargetName(int argno)
{
    switch (argno)
    {
        case 0:
            return "$loadTargetRDI";
        case 1:
            return "$loadTargetRSI";
        case 2:
            return "$loadTargetRDX";
        case 3:
            return "$loadTargetRCX";
        case 4:
            return "$loadTargetR8";
        case 5:
            return "$loadTargetR9";
        default:
            return nullptr;
    }
}

/*
 * Send an argument.
 */
static void sendArgument(FILE *out, ArgumentKind arg, intptr_t value,
    unsigned argno, int8_t rdi_offset8, int32_t rsp_offset32, bool before,
    bool flags)
{
    if (argno > MAX_ARGNO)
        error("failed to send argument; maximum number of function call "
            "arguments (%u) exceeded", MAX_ARGNO);

    switch (arg)
    {
        case ARGUMENT_INTEGER:
            if (value == 0 && !flags)
            {
                sendZeroR32(out, argno);
                break;
            }
            else if (value >= INT32_MIN && value < 0)
            {
                sendMovI32R64(out, argno);
                fprintf(out, "{\"int32\":");
            }
            else if (value >= 0 && value <= INT32_MAX)
            {
                sendMovI32R32(out, argno);
                fprintf(out, "{\"int32\":");
            }
            else
            {
                sendMovI64R64(out, argno);
                fprintf(out, "{\"int64\":");
            }
            sendInteger(out, value);
            fprintf(out, "},");
            break;
        case ARGUMENT_ADDR:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".Linstruction\"},");
            break;
        case ARGUMENT_NEXT:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".Lcontinue\"},");
            break;
        case ARGUMENT_ASM_STR:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".LasmStr\"},");
            break;
        case ARGUMENT_ASM_STR_LEN:
            sendMovI32R32(out, argno);
            fprintf(out, "\"$asmStrLen\",");
            break;
        case ARGUMENT_BYTES:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".Lbytes\"},");
            break;
        case ARGUMENT_BYTES_LEN:
            sendMovI32R32(out, argno);
            fprintf(out, "\"$bytesLen\",");
            break;
        case ARGUMENT_TARGET:
            fprintf(out, "\"%s\",", getLoadTargetName(argno));
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".Ltrampoline\"},");
            break;
        case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
        case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RDI:
        case ARGUMENT_RSI: case ARGUMENT_R8: case ARGUMENT_R9:
        case ARGUMENT_R10: case ARGUMENT_R11: case ARGUMENT_R12:
        case ARGUMENT_R13: case ARGUMENT_R14: case ARGUMENT_R15:
        {
            switch (arg)
            {
                case ARGUMENT_RDI:
                    if (argno != 0)
                        sendMovRSPR64(out, rdi_offset8, argno);
                    return;
                case ARGUMENT_RSI:
                    if (argno == 1)
                        return;
                    if (argno > 1)
                    {
                        sendMovRSPR64(out, rdi_offset8 + 8, argno);
                        return;
                    }
                    break;
                case ARGUMENT_RDX:
                    if (argno == 2)
                        return;
                    if (argno > 2)
                    {
                        sendMovRSPR64(out, rdi_offset8 + 16, argno);
                        return;
                    }
                    break;
                case ARGUMENT_RCX:
                    if (argno == 3)
                        return;
                    if (argno > 3)
                    {
                        sendMovRSPR64(out, rdi_offset8 + 24, argno);
                        return;
                    }
                    break;
                case ARGUMENT_R8:
                    if (argno == 4)
                        return;
                    if (argno > 4)
                    {
                        sendMovRSPR64(out, rdi_offset8 + 32, argno);
                        return;
                    }
                    break;
                case ARGUMENT_R9:
                    if (argno == 5)
                        return;
                    break;
                case ARGUMENT_RAX:
                    if (rdi_offset8 != 0)
                    {
                        sendMovRSPR64(out, rdi_offset8 + 48, argno);
                        return;
                    }
                    break;
                default:
                    break;
            }
            sendMovR64R64(out, arg, argno);
            break;
        }
        case ARGUMENT_RIP:
            sendLeaRIPR64(out, argno);
            fprintf(out, "{\"rel32\":\".L%s\"},",
                (before? "instruction": "continue"));
            break;
        case ARGUMENT_RSP:
            sendLeaRSPR64(out, argno);
            fprintf(out, "{\"int32\":");
            sendInteger(out, (intptr_t)rsp_offset32);
            fprintf(out, "},");
            break;
        case ARGUMENT_RFLAGS:
            if (rdi_offset8 == 0)
                error("failed to emit \"rflags\" argument; the \"rflags\" "
                    "argument is not supported for \"naked\" calls");
            sendMovZWLRSPR32(out, rdi_offset8 - 8, argno);
            break;
        default:
            break;
    }
}

/*
 * Send argument data.
 */
static void sendArgumentData(FILE *out, ArgumentKind arg, unsigned argno)
{
    switch (arg)
    {
        case ARGUMENT_ASM_STR:
            fprintf(out, ",\".LasmStr\",\"$asmStr\"");
            break;
        case ARGUMENT_BYTES:
            fprintf(out, ",\".Lbytes\",\"$bytes\"");
            break;
        default:
            break;
    }
}

/*
 * Send an ELF trampoline.
 */
unsigned e9frontend::sendCallTrampolineMessage(FILE *out, const ELF &elf,
    const char *filename, const char *symbol, const char *name,
    const std::vector<Argument> args, bool clean, bool before, bool replace)
{
    intptr_t addr = lookupSymbol(elf, symbol);
    if (addr < 0)
        error("failed to find dynamic symbol \"%s\" in ELF file \"%s\"",
            symbol, filename);

    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, name);
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);
    if (!replace && !before)
        fprintf(out, "\"$instruction\",");

    for (const auto &arg: args)
    {
        if (arg.kind == ARGUMENT_TRAMPOLINE)
        {
            fputs("\".Ltrampoline\",", out);
            break;
        }
    }

    int32_t rsp_offset32 = 0;
    fprintf(out, "%u,%u,%u,%u,%u,%u,%u,%u,",        // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x00, 0xc0, 0xff, 0xff);
    rsp_offset32 += 0x4000;
    
    int8_t rdi_offset8;
    bool flags = false;
    if (clean)
    {
        // Save the state:
        fprintf(out, "%u,%u,", 0x41, 0x53);         // push   %r11
        fprintf(out, "%u,%u,", 0x41, 0x52);         // push   %r10
        fprintf(out, "%u,", 0x50);                  // push   %rax
        fprintf(out, "%u,%u,", 0x41, 0x51);         // push   %r9
        fprintf(out, "%u,%u,", 0x41, 0x50);         // push   %r8
        fprintf(out, "%u,", 0x51);                  // push   %rcx
        fprintf(out, "%u,", 0x52);                  // push   %rdx
        fprintf(out, "%u,", 0x56);                  // push   %rsi
        fprintf(out, "%u,", 0x57);                  // push   %rdi
        fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto   %al
        fprintf(out, "%u,", 0x9f);                  // lahf
        fprintf(out, "%u,", 0x50);                  // push   %rax
        rdi_offset8 = 8;
        rsp_offset32 += 80;
    }
    else
    {
        switch (args.size())
        {
            case 6:
                fprintf(out, "%u,%u,", 0x41, 0x51); // push   %r9
                rsp_offset32 += 8;
            case 5:
                fprintf(out, "%u,%u,", 0x41, 0x50); // push   %r8
                rsp_offset32 += 8;
            case 4:
                fprintf(out, "%u,", 0x51);          // push   %rcx
                rsp_offset32 += 8;
            case 3:
                fprintf(out, "%u,", 0x52);          // push   %rdx
                rsp_offset32 += 8;
            case 2:
                fprintf(out, "%u,", 0x56);          // push   %rsi
                rsp_offset32 += 8;
            case 1:
                fprintf(out, "%u,", 0x57);          // push   %rdi
                rsp_offset32 += 8;
            default:
                break;
        }
        rdi_offset8 = 0;
        flags = true;
    }
    unsigned argno = 0;
    for (auto arg: args)
        sendArgument(out, arg.kind, arg.value, argno++, rdi_offset8,
            rsp_offset32, replace || before, flags);
    fprintf(out, "%u", 0xe8);                       // callq ...
    fprintf(out, ",{\"rel32\":");
    sendInteger(out, addr);
    fputc('}', out);
    if (clean)
    {
        // Restore the state:
        fprintf(out, ",%u", 0x58);                  // pop    %rax
        fprintf(out, ",%u,%u", 0x04, 0x7f);         // add    $0x7f,%al
        fprintf(out, ",%u", 0x9e);                  // sahf   
        fprintf(out, ",%u", 0x5f);                  // pop    %rdi
        fprintf(out, ",%u", 0x5e);                  // pop    %rsi
        fprintf(out, ",%u", 0x5a);                  // pop    %rdx
        fprintf(out, ",%u", 0x59);                  // pop    %rcx
        fprintf(out, ",%u,%u", 0x41, 0x58);         // pop    %r8
        fprintf(out, ",%u,%u", 0x41, 0x59);         // pop    %r9
        fprintf(out, ",%u", 0x58);                  // pop    %rax
        fprintf(out, ",%u,%u", 0x41, 0x5a);         // pop    %r10
        fprintf(out, ",%u,%u", 0x41, 0x5b);         // pop    %r11
    }
    else
    {
        for (size_t i = 1; i <= args.size(); i++)
        {
            switch (i)
            {
                case 6:
                    fprintf(out, ",%u,%u", 0x41, 0x59); // pop    %r9
                    break;
                case 5:
                    fprintf(out, ",%u,%u", 0x41, 0x58); // pop    %r8
                    break;
                case 4:
                    fprintf(out, ",%u", 0x59);          // pop    %rcx
                    break;
                case 3:
                    fprintf(out, ",%u", 0x5a);          // pop    %rdx
                    break;
                case 2:
                    fprintf(out, ",%u", 0x5e);          // pop    %rsi
                    break;
                case 1:
                    fprintf(out, ",%u", 0x5f);          // pop    %rdi
                    break;

            }
        }
    }
    fprintf(out, ",%u,%u,%u,%u,%u,%u,%u,%u",        // lea 0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x00, 0x40, 0x00, 0x00);
    if (!replace && before)
        fprintf(out, ",\"$instruction\"");
    fprintf(out, ",\"$continue\"");
    argno = 0;
    bool seen[ARGUMENT_MAX] = {false};
    for (auto arg: args)
    {
        if (!seen[arg.kind])
        {
            sendArgumentData(out, arg.kind, argno);
            seen[arg.kind] = true;
        }
        argno++;
    }
    fputc(']', out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Get argument name.
 */
static const char *getArgumentName(ArgumentKind arg)
{
    switch (arg)
    {
        case ARGUMENT_ASM_STR:
            return "$asmStr";
        case ARGUMENT_ASM_STR_LEN:
            return "$asmStrLen";
        case ARGUMENT_BYTES:
            return "$bytes";
        case ARGUMENT_BYTES_LEN:
            return "$bytesLen";
        default:
            return "???";
    }
}

/*
 * Check for suffix.
 */
static bool hasSuffix(const std::string &str, const char *suffix)
{
    size_t len = strlen(suffix);
    return (str.size() < len? false: str.compare(str.size()-len,
        len, suffix, len) == 0);
}

/*
 * Spawn e9patch backend instance.
 */
static void spawnBackend(const char *prog, const std::vector<char *> &options,
    Backend &backend)
{
    int fds[2];
    if (pipe(fds) != 0)
        error("failed to open pipe to backend process: %s",
            strerror(errno));
    pid_t pid = fork();
    if (pid == 0)
    {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0)
            error("failed to dup backend process pipe file descriptor "
                "(%d): %s", fds[0], strerror(errno));
        close(fds[0]);
        char *argv[options.size() + 2];
        argv[0] = strDup("e9patch");
        unsigned i = 1;
        for (auto option: options)
            argv[i++] = option;
        argv[i] = nullptr;
        execvp(prog, argv);
        error("failed to execute backend process \"%s\": %s", argv[0],
            strerror(errno));
    }
    else if (pid < 0)
        error("failed to fork backend process: %s", strerror(errno));
    
    close(fds[0]);
    FILE *out = fdopen(fds[1], "w");
    if (out == nullptr)
        error("failed to open backend process stream: %s",
            strerror(errno));

    backend.out = out;
    backend.pid = pid;
}

/*
 * Wait for e9patch instance to terminate.
 */
static void waitBackend(const Backend &backend)
{
    fclose(backend.out);
    
    if (backend.out == 0)
        return;
    int status;
    do
    {
        if (waitpid(backend.pid, &status, WUNTRACED | WCONTINUED) < 0)
            error("failed to wait for backend process (%d): %s",
                backend.pid, strerror(errno));
    }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        error("backend process (%d) exitted with a non-zero status (%d)",
            backend.pid, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        error("backend process (%d) killed by signal (%s)", backend.pid,
            strsignal(WTERMSIG(status)));
}

