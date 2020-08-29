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

using namespace e9frontend;

/*
 * Registers.
 */
#define RDI             0
#define RSI             1
#define RDX             2
#define RCX             3
#define R8              4
#define R9              5
#define RFLAGS          6
#define RAX             7
#define R10             8
#define R11             9
#define RBX             10
#define RBP             11
#define R12             12
#define R13             13
#define R14             14
#define R15             15
#define RSP             16
#define RMAX            RSP

/*
 * Convert an argument into a regno.
 */
static unsigned getRegNo(ArgumentKind arg)
{
    switch (arg)
    {
        case ARGUMENT_RAX: case ARGUMENT_RAX_PTR:
            return RAX;
        case ARGUMENT_RBX: case ARGUMENT_RBX_PTR:
            return RBX;
        case ARGUMENT_RCX: case ARGUMENT_RCX_PTR:
            return RCX;
        case ARGUMENT_RDX: case ARGUMENT_RDX_PTR:
            return RDX;
        case ARGUMENT_RSP: case ARGUMENT_RSP_PTR:
            return RSP;
        case ARGUMENT_RBP: case ARGUMENT_RBP_PTR:
            return RBP;
        case ARGUMENT_RDI: case ARGUMENT_RDI_PTR:
            return RDI;
        case ARGUMENT_RSI: case ARGUMENT_RSI_PTR:
            return RSI;
        case ARGUMENT_R8: case ARGUMENT_R8_PTR:
            return R8;
        case ARGUMENT_R9: case ARGUMENT_R9_PTR:
            return R9;
        case ARGUMENT_R10: case ARGUMENT_R10_PTR:
            return R10;
        case ARGUMENT_R11: case ARGUMENT_R11_PTR:
            return R11;
        case ARGUMENT_R12: case ARGUMENT_R12_PTR:
            return R12;
        case ARGUMENT_R13: case ARGUMENT_R13_PTR:
            return R13;
        case ARGUMENT_R14: case ARGUMENT_R14_PTR:
            return R14;
        case ARGUMENT_R15: case ARGUMENT_R15_PTR:
            return R15;
        case ARGUMENT_RFLAGS:
            return RFLAGS;
        default:
            return UINT32_MAX;
    }
}

/*
 * Call state helper class.
 */
struct CallInfo
{
    int32_t rsp_offset;     // Stack offset
    uint32_t saved;         // Saved registers
    uint32_t clobbered;     // Clobbered registers

    void save(unsigned reg)
    {
        saved |= (0x1 << reg);
    }

    bool isSaved(unsigned reg) const
    {
        return ((saved & (0x1 << reg)) != 0);
    }

    void clobber(unsigned reg)
    {
        clobbered |= (0x1 << reg);
    }

    bool isClobbered(unsigned reg) const
    {
        return ((clobbered & (0x1 << reg)) != 0);
    }

    void restore(unsigned reg)
    {
        clobbered &= ~(0x1 << reg);
    }

    static int32_t offset(unsigned reg)
    {
        return sizeof(uint64_t) * reg;
    }

    void push(unsigned reg)
    {
        rsp_offset += 8;
        save(reg);
        if (reg == RFLAGS)
        {
            assert(isSaved(RAX));
            clobber(RAX);
        }
    }

    void loadArg(ArgumentKind arg, unsigned argno)
    {
        switch (arg)
        {
            case ARGUMENT_RFLAGS:
                if (!isSaved(RFLAGS))
                {
                    save(RAX);
                    clobber(RAX);
                    save(RFLAGS);
                }
            case ARGUMENT_RAX_PTR: case ARGUMENT_RBX_PTR:
            case ARGUMENT_RCX_PTR: case ARGUMENT_RDX_PTR:
            case ARGUMENT_RBP_PTR: case ARGUMENT_RSP_PTR:
            case ARGUMENT_RDI_PTR: case ARGUMENT_RSI_PTR:
            case ARGUMENT_R8_PTR:  case ARGUMENT_R9_PTR:
            case ARGUMENT_R10_PTR: case ARGUMENT_R11_PTR:
            case ARGUMENT_R12_PTR: case ARGUMENT_R13_PTR:
            case ARGUMENT_R14_PTR: case ARGUMENT_R15_PTR:
                save(getRegNo(arg));
                break;
            default:
                break;
        }
        clobber(argno);
    }

    CallInfo(bool clean, size_t num_args) :
        rsp_offset(0x4000), saved(0x0), clobbered(0x0)
    {
        if (clean)
        {
            push(R11);
            push(R10);
            push(RAX);
            push(RFLAGS);
            push(R9);
            push(R8);
            push(RCX);
            push(RDX);
            push(RSI);
            push(RDI);
        }
        else
        {
            for (unsigned reg = 0; reg < num_args; reg++)
                push(reg);
        }
    }
};

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
    fprintf(out, "\"$%s\":", name);
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
 * Send code/data.
 */
void e9frontend::sendCode(FILE *out, const char *code)
{
     fputc('[', out);
     size_t len = strlen(code);
     while (len > 0 && isspace(code[len-1]))
         len--;
     if (len > 0 && code[len-1] == ',')
         len--;
     fwrite(code, sizeof(char), len, out);
     fputc(']', out);
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
            sendCode(out, metadata[i].data);
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
static bool sendMovFromR64ToR64(FILE *out, unsigned regno_src,
    unsigned regno_dst)
{
    if (regno_src == regno_dst)
        return false;
    const uint8_t REX_MASK[] =
		{0, 0, 0, 0, 1, 1, 0,
		 0, 1, 1, 0, 0, 1, 1, 1, 1, 0};
    const uint8_t REX[] = {0x48, 0x4c, 0x49, 0x4d};
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
    
    uint8_t rex = REX[(REX_MASK[regno_dst] << 1) | REX_MASK[regno_src]];
    uint8_t modrm = (0x03 << 6) | (REG[regno_src] << 3) | REG[regno_dst];
    fprintf(out, "%u,%u,%u,", rex, 0x89, modrm);
    return true;
}

/*
 * Send a `mov offset(%rsp),%r64' instruction.
 */
static void sendMovFromStackToR64(FILE *out, int32_t offset, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
	const uint8_t MODRM_8[] =
		{0x7c, 0x74, 0x54, 0x4c, 0x44, 0x4c, 0x00, 
		 0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
	const uint8_t MODRM_32[] =
		{0xbc, 0xb4, 0x94, 0x8c, 0x84, 0x8c, 0x00,
		 0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x8b, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x8b, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `mov %r64,offset(%rsp)' instruction.
 */
static void sendMovFromR64ToStack(FILE *out, unsigned regno, int32_t offset)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
	const uint8_t MODRM_8[] =
		{0x7c, 0x74,  0x54, 0x4c, 0x44, 0x4c, 0x00, 
		 0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
	const uint8_t MODRM_32[] =
		{0xbc, 0xb4,  0x94, 0x8c, 0x84, 0x8c, 0x00,
		 0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x89, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x89, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `movzwl offset(%rsp),%r32' instruction.
 */
static void sendMovFromStack16ToR64(FILE *out, int32_t offset, unsigned regno)
{
    const uint8_t REX[] =
		{0x00, 0x00, 0x00, 0x00, 0x44, 0x44, 0x00,
         0x00, 0x44, 0x44, 0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x00};
	const uint8_t MODRM_8[] =
		{0x7c, 0x74,  0x54, 0x4c, 0x44, 0x4c, 0x00, 
		 0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
	const uint8_t MODRM_32[] =
		{0xbc, 0xb4,  0x94, 0x8c, 0x84, 0x8c, 0x00,
		 0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (REX[regno] != 0x00)
        fprintf(out, "%u,", REX[regno]);
    if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x0f, 0xb7, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            0x0f, 0xb7, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `mov $value,%r32' instruction.
 */
static void sendSExtFromI32ToR64(FILE *out, const char *value, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x00,
		 0x48, 0x49, 0x49, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x48};
	const uint8_t MODRM[] =
		{0xc7, 0xc6, 0xc2, 0xc1, 0xc0, 0xc1, 0x00,  
		 0xc0, 0xc2, 0xc3, 0xc3, 0xc5, 0xc4, 0xc5, 0xc6, 0xc7, 0xc4};
	fprintf(out, "%u,%u,%u,%s,",
        REX[regno], 0xc7, MODRM[regno], value);
}

/*
 * Send a `mov $value,%r32' instruction.
 */
static void sendSExtFromI32ToR64(FILE *out, int32_t value, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x00,
		 0x48, 0x49, 0x49, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x48};
	const uint8_t MODRM[] =
		{0xc7, 0xc6, 0xc2, 0xc1, 0xc0, 0xc1, 0x00,  
		 0xc0, 0xc2, 0xc3, 0xc3, 0xc5, 0xc4, 0xc5, 0xc6, 0xc7, 0xc4};
	fprintf(out, "%u,%u,%u,{\"int32\":%d},",
        REX[regno], 0xc7, MODRM[regno], value);
}

/*
 * Send a `mov $value,%r64' instruction.
 */
static void sendZExtFromI32ToR64(FILE *out, const char *value, unsigned regno)
{
    const uint8_t REX[] =
		{0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x00,
         0x00, 0x41, 0x41, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41, 0x00};
    const uint8_t OPCODE[] =
		{0xbf, 0xbe, 0xba, 0xb9, 0xb8, 0xb9, 0x00,
		 0xb8, 0xba, 0xbb, 0xbb, 0xbd, 0xbc, 0xbd, 0xbe, 0xbf, 0xbc};
    if (REX[regno] != 0x00)
        fprintf(out, "%u,", REX[regno]);
	fprintf(out, "%u,%s,", OPCODE[regno], value);
}

/*
 * Send a `mov $value,%r64' instruction.
 */
static void sendZExtFromI32ToR64(FILE *out, int32_t value, unsigned regno)
{
    const uint8_t REX[] =
		{0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x00,
         0x00, 0x41, 0x41, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41, 0x00};
    const uint8_t OPCODE[] =
		{0xbf, 0xbe, 0xba, 0xb9, 0xb8, 0xb9, 0x00,
		 0xb8, 0xba, 0xbb, 0xbb, 0xbd, 0xbc, 0xbd, 0xbe, 0xbf, 0xbc};
    if (REX[regno] != 0x00)
        fprintf(out, "%u,", REX[regno]);
	fprintf(out, "%u,{\"int32\":%d},", OPCODE[regno], value);
}

/*
 * Send a `movabs $i64,%r64' instruction.
 */
static void sendMovFromI64ToR64(FILE *out, intptr_t value, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x00,
         0x48, 0x49, 0x49, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x48};
    const uint8_t OPCODE[] =
		{0xbf, 0xbe, 0xba, 0xb9, 0xb8, 0xb9, 0x00,
		 0xb8, 0xba, 0xbb, 0xbb, 0xbd, 0xbc, 0xbd, 0xbe, 0xbf, 0xbc};
	fprintf(out, "%u,%u,{\"int64\":", REX[regno], OPCODE[regno]);
	sendInteger(out, value);
    fputs("},", out);
}

/*
 * Send a `lea offset(%rip),%r64' instruction opcode.
 */
static void sendLeaFromPCRelToR64(FILE *out, const char *offset,
    unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
	const uint8_t MODRM[] =
		{0x3d, 0x35, 0x15, 0x0d, 0x05, 0x0d, 0x00, 
         0x05, 0x15, 0x1d, 0x1d, 0x2d, 0x25, 0x2d, 0x35, 0x3d, 0x25};
    fprintf(out, "%u,%u,%u,%s,",
        REX[regno], 0x8d, MODRM[regno], offset);
}

/*
 * Send a `lea offset(%rip),%r64' instruction opcode.
 */
static void sendLeaFromPCRelToR64(FILE *out, int32_t offset, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
	const uint8_t MODRM[] =
		{0x3d, 0x35, 0x15, 0x0d, 0x05, 0x0d, 0x00, 
         0x05, 0x15, 0x1d, 0x1d, 0x2d, 0x25, 0x2d, 0x35, 0x3d, 0x25};
    fprintf(out, "%u,%u,%u,{\"rel32\":%d},",
        REX[regno], 0x8d, MODRM[regno], offset);
}

/*
 * Send a `lea ...(%rsp),%r64' instruction opcode.
 */
static void sendLeaFromStackToR64(FILE *out, int32_t offset, unsigned regno)
{
    const uint8_t REX[] =
		{0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
	const uint8_t MODRM_8[] =
		{0x7c, 0x74, 0x54, 0x4c, 0x44, 0x4c, 0x00, 
		 0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
	const uint8_t MODRM_32[] =
		{0xbc, 0xb4, 0x94, 0x8c, 0x84, 0x8c, 0x00,
		 0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x8d, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x8d, MODRM_32[regno], 0x24, offset);
}

/*
 * Get load target name.
 */
static const char *getLoadTargetName(int argno)
{
    switch (argno)
    {
        case 0:
            return "loadTargetRDI";
        case 1:
            return "loadTargetRSI";
        case 2:
            return "loadTargetRDX";
        case 3:
            return "loadTargetRCX";
        case 4:
            return "loadTargetR8";
        case 5:
            return "loadTargetR9";
        default:
            return nullptr;
    }
}

/*
 * Get load target name.
 */
static const char *getLoadNextName(int argno)
{
    switch (argno)
    {
        case 0:
            return "loadNextRDI";
        case 1:
            return "loadNextRSI";
        case 2:
            return "loadNextRDX";
        case 3:
            return "loadNextRCX";
        case 4:
            return "loadNextR8";
        case 5:
            return "loadNextR9";
        default:
            return nullptr;
    }
}

/*
 * Send an argument.
 */
static void sendArgument(FILE *out, ArgumentKind arg, intptr_t value,
    const char *name, unsigned argno, const CallInfo &info, bool before)
{
    if (argno > MAX_ARGNO)
        error("failed to send argument; maximum number of function call "
            "arguments (%u) exceeded", MAX_ARGNO);

    switch (arg)
    {
        case ARGUMENT_USER:
            fprintf(out, "\"$%s\",", name);
            break;
        case ARGUMENT_INTEGER:
            if (value >= INT32_MIN && value <= INT32_MAX)
                sendSExtFromI32ToR64(out, value, argno);
            else if (value >= 0 && value <= UINT32_MAX)
                sendZExtFromI32ToR64(out, value, argno);
            else
                sendMovFromI64ToR64(out, value, argno);
            break;
        case ARGUMENT_OFFSET:
            sendZExtFromI32ToR64(out, "\"$offset\"", argno);
            break;
        case ARGUMENT_ADDR:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}", argno);
            break;
        case ARGUMENT_NEXT:
            if (before)
                fprintf(out, "\"$%s\",", getLoadNextName(argno));
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    argno);
            break;
        case ARGUMENT_BASE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":0}", argno);
            break;
        case ARGUMENT_STATIC_ADDR:
            sendZExtFromI32ToR64(out, "\"$staticAddr\"",argno);
            break;
        case ARGUMENT_ASM_STR:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".LasmStr\"}", argno);
            break;
        case ARGUMENT_ASM_STR_LEN:
            sendZExtFromI32ToR64(out, "\"$asmStrLen\"", argno);
            break;
        case ARGUMENT_BYTES:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lbytes\"}", argno);
            break;
        case ARGUMENT_BYTES_LEN:
            sendZExtFromI32ToR64(out, "\"$bytesLen\"", argno);
            break;
        case ARGUMENT_TARGET:
            fprintf(out, "\"$%s\",", getLoadTargetName(argno));
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Ltrampoline\"}", argno);
            break;
        case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
        case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RDI:
        case ARGUMENT_RSI: case ARGUMENT_R8: case ARGUMENT_R9:
        case ARGUMENT_R10: case ARGUMENT_R11: case ARGUMENT_R12:
        case ARGUMENT_R13: case ARGUMENT_R14: case ARGUMENT_R15:
        {
            unsigned regno = getRegNo(arg);
            if (info.isClobbered(regno))
                sendMovFromStackToR64(out, info.offset(regno), argno);
            else 
                sendMovFromR64ToR64(out, regno, argno);
            break;
        }
        case ARGUMENT_RAX_PTR: case ARGUMENT_RBX_PTR: case ARGUMENT_RCX_PTR:
        case ARGUMENT_RDX_PTR: case ARGUMENT_RBP_PTR: case ARGUMENT_RDI_PTR:
        case ARGUMENT_RSI_PTR: case ARGUMENT_R8_PTR:  case ARGUMENT_R9_PTR:
        case ARGUMENT_R10_PTR: case ARGUMENT_R11_PTR: case ARGUMENT_R12_PTR:
        case ARGUMENT_R13_PTR: case ARGUMENT_R14_PTR: case ARGUMENT_R15_PTR:
        {
            unsigned regno = getRegNo(arg);
            if (!info.isSaved(regno))
                sendMovFromR64ToStack(out, regno, info.offset(regno));
            sendLeaFromStackToR64(out, info.offset(regno), argno);
            break;
        }
        case ARGUMENT_RSP_PTR:
            if (!info.isSaved(RSP))
            {
                // Use argno as scratch...
                sendLeaFromStackToR64(out, info.rsp_offset, argno);
                sendMovFromR64ToStack(out, argno, info.offset(RSP));
            }
            sendLeaFromStackToR64(out, info.offset(RSP), argno);
            break;
        case ARGUMENT_RIP:
            if (before)
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}",
                    argno);
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    argno);
            break;
        case ARGUMENT_RSP:
            sendLeaFromStackToR64(out, info.rsp_offset, argno);
            break;
        case ARGUMENT_RFLAGS:
            if (!info.isSaved(RFLAGS))
            {
                // %rflags (& %rax) was not saved, so read directly:
                if (!info.isSaved(RAX))
                    sendMovFromR64ToStack(out, RAX, info.offset(RAX));
                fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto %al
                fprintf(out, "%u,", 0x9f);                  // lahf
                sendMovFromR64ToStack(out, RAX, info.offset(RFLAGS));
            }
            sendMovFromStack16ToR64(out, info.offset(RFLAGS), argno);
            break;
        default:
            break;
    }
}

/*
 * Restore an argument (if necessary).
 */
static void sendArgumentRestore(FILE *out, ArgumentKind arg, unsigned rmin)
{
    switch (arg)
    {
        case ARGUMENT_RAX_PTR: case ARGUMENT_RBX_PTR: case ARGUMENT_RCX_PTR:
        case ARGUMENT_RDX_PTR: case ARGUMENT_RBP_PTR: case ARGUMENT_RDI_PTR:
        case ARGUMENT_RSI_PTR: case ARGUMENT_R8_PTR:  case ARGUMENT_R9_PTR:
        case ARGUMENT_R10_PTR: case ARGUMENT_R11_PTR: case ARGUMENT_R12_PTR:
        case ARGUMENT_R13_PTR: case ARGUMENT_R14_PTR: case ARGUMENT_R15_PTR:
        {
            unsigned regno = getRegNo(arg);
            if (regno < rmin)
                return;         // Will be restored by default anyway...
            sendMovFromStackToR64(out, CallInfo::offset(regno), regno);
            break;
        }
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
            fprintf(out, "\".LasmStr\",\"$asmStr\",");
            break;
        case ARGUMENT_BYTES:
            fprintf(out, "\".Lbytes\",\"$bytes\",");
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
    const std::vector<Argument> &args, bool clean, bool before, bool replace)
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

    fprintf(out, "%u,%u,%u,%u,%u,%u,%u,%u,",        // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x00, 0xc0, 0xff, 0xff);
    if (clean)
    {
        // Save the state:
        fprintf(out, "%u,%u,", 0x41, 0x53);         // push   %r11
        fprintf(out, "%u,%u,", 0x41, 0x52);         // push   %r10
        fprintf(out, "%u,", 0x50);                  // push   %rax
        fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto   %al
        fprintf(out, "%u,", 0x9f);                  // lahf
        fprintf(out, "%u,", 0x50);                  // push   %rax
        fprintf(out, "%u,%u,", 0x41, 0x51);         // push   %r9
        fprintf(out, "%u,%u,", 0x41, 0x50);         // push   %r8
        fprintf(out, "%u,", 0x51);                  // push   %rcx
        fprintf(out, "%u,", 0x52);                  // push   %rdx
        fprintf(out, "%u,", 0x56);                  // push   %rsi
        fprintf(out, "%u,", 0x57);                  // push   %rdi
    }
    else
    {
        switch (args.size())
        {
            case 6:
                fprintf(out, "%u,%u,", 0x41, 0x51); // push   %r9
            case 5:
                fprintf(out, "%u,%u,", 0x41, 0x50); // push   %r8
            case 4:
                fprintf(out, "%u,", 0x51);          // push   %rcx
            case 3:
                fprintf(out, "%u,", 0x52);          // push   %rdx
            case 2:
                fprintf(out, "%u,", 0x56);          // push   %rsi
            case 1:
                fprintf(out, "%u,", 0x57);          // push   %rdi
            default:
                break;
        }
    }

    CallInfo info(clean, args.size());
    unsigned argno = 0;
    for (const auto &arg: args)
    {
        sendArgument(out, arg.kind, arg.value, arg.name, argno, info,
            replace || before);
        info.loadArg(arg.kind, argno);
        argno++;
    }

    unsigned rmin = (clean? RBX: (unsigned)args.size()+1);
    for (unsigned regno = rmin; regno <= RMAX; regno++)
    {
        if (info.isClobbered(regno))
            sendMovFromStackToR64(out, info.offset(regno), regno);
    }

    fprintf(out, "%u,", 0xe8);                      // callq ...
    fputs("{\"rel32\":", out);
    sendInteger(out, addr);
    fputs("},", out);

    bool rsp_restore = false;
    for (const auto &arg: args)
    {
        if (arg.duplicate)
            continue;
        if (arg.kind == ARGUMENT_RSP_PTR)
        {
            rsp_restore = true;
            continue;       // Handle later
        }
        sendArgumentRestore(out, arg.kind, rmin);
    }

    int32_t rsp_adjust = 0;
    if (clean)
    {
        // Restore the state:
        fprintf(out, "%u,", 0x5f);                  // pop    %rdi
        fprintf(out, "%u,", 0x5e);                  // pop    %rsi
        fprintf(out, "%u,", 0x5a);                  // pop    %rdx
        fprintf(out, "%u,", 0x59);                  // pop    %rcx
        fprintf(out, "%u,%u,", 0x41, 0x58);         // pop    %r8
        fprintf(out, "%u,%u,", 0x41, 0x59);         // pop    %r9
        fprintf(out, "%u,", 0x58);                  // pop    %rax
        fprintf(out, "%u,%u,", 0x04, 0x7f);         // add    $0x7f,%al
        fprintf(out, "%u,", 0x9e);                  // sahf   
        fprintf(out, "%u,", 0x58);                  // pop    %rax
        fprintf(out, "%u,%u,", 0x41, 0x5a);         // pop    %r10
        fprintf(out, "%u,%u,", 0x41, 0x5b);         // pop    %r11
        rsp_adjust -= 80;
    }
    else
    {
        for (size_t i = 1; i <= args.size(); i++)
        {
            switch (i)
            {
                case 6:
                    fprintf(out, "%u,%u,", 0x41, 0x59); // pop    %r9
                    break;
                case 5:
                    fprintf(out, "%u,%u,", 0x41, 0x58); // pop    %r8
                    break;
                case 4:
                    fprintf(out, "%u,", 0x59);          // pop    %rcx
                    break;
                case 3:
                    fprintf(out, "%u,", 0x5a);          // pop    %rdx
                    break;
                case 2:
                    fprintf(out, "%u,", 0x5e);          // pop    %rsi
                    break;
                case 1:
                    fprintf(out, "%u,", 0x5f);          // pop    %rdi
                    break;
            }
            rsp_adjust -= 8;
        }
    }

    if (rsp_restore)
        sendMovFromStackToR64(out, info.offset(RSP) + rsp_adjust, RSP);
    else
        fprintf(out, "%u,%u,%u,%u,%u,%u,%u,%u,",    // lea 0x4000(%rsp),%rsp
            0x48, 0x8d, 0xa4, 0x24, 0x00, 0x40, 0x00, 0x00);

    if (!replace && before)
        fputs("\"$instruction\",", out);
    fputs("\"$continue\",", out);
    argno = 0;
    for (const auto &arg: args)
    {
        if (!arg.duplicate)
            sendArgumentData(out, arg.kind, argno);
        argno++;
    }
    fputs("null]", out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a generic trampoline.
 */
unsigned e9frontend::sendTrampolineMessage(FILE *out,
    const char *name, const char *template_)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, name);
    sendSeparator(out);
    sendParamHeader(out, "template");
    sendCode(out, template_);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
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
    
    if (backend.pid == 0)
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

