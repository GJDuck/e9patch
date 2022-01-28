/*
 *        ___  _              _ 
 *   ___ / _ \| |_ ___   ___ | |
 *  / _ \ (_) | __/ _ \ / _ \| |
 * |  __/\__, | || (_) | (_) | |
 *  \___|  /_/ \__\___/ \___/|_|
 *  
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

#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <list>
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

#include "e9codegen.h"
#include "e9elf.h"
#include "e9tool.h"
#include "e9misc.h"
#include "e9types.h"
#include "../e9patch/e9loader.h"

using namespace e9tool;

/*
 * Report an error and exit.
 */
void NO_RETURN e9tool::error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s  : ",
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
void e9tool::warning(const char *msg, ...)
{
    if (option_no_warnings)
        return;

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
 * Print a debug message.
 */
void e9tool::debug(const char *msg, ...)
{
    if (!option_debug)
        return;

    fprintf(stderr, "%sdebug%s: ",
        (option_is_tty? "\33[35m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);

    putc('\n', stderr);
}

/*
 * Send message header.
 */
void e9tool::sendMessageHeader(FILE *out, const char *method)
{
    fprintf(out, "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":{",
        method);
}

/*
 * Send message footer.
 */
unsigned e9tool::sendMessageFooter(FILE *out, bool sync)
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
void e9tool::sendParamHeader(FILE *out, const char *name)
{
    fprintf(out, "\"%s\":", name);
}

/*
 * Send parameter separator.
 */
void e9tool::sendSeparator(FILE *out, bool last)
{
    fprintf(out, "%s", (last? "": ","));
}

/*
 * Send metadata header.
 */
void e9tool::sendMetadataHeader(FILE *out)
{
    putc('{', out);
}


/*
 * Send metadata footer.
 */
void e9tool::sendMetadataFooter(FILE *out)
{
    putc('}', out);
}

/*
 * Send definition header.
 */
void e9tool::sendDefinitionHeader(FILE *out, const char *patch,
    const char *name)
{
    fprintf(out, "\"$%s@%s\":[", name, patch);
}

/*
 * Send definition footer.
 */
void e9tool::sendDefinitionFooter(FILE *out, bool last)
{
    putc(']', out);
    sendSeparator(out, last);
}

/*
 * Send an integer parameter.
 */
void e9tool::sendInteger(FILE *out, intptr_t i)
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
void e9tool::sendString(FILE *out, const char *s)
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
void e9tool::sendCode(FILE *out, const char *code)
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
unsigned e9tool::sendBinaryMessage(FILE *out, const char *mode,
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
 * Send a "options" message.
 */
unsigned e9tool::sendOptionsMessage(FILE *out, std::vector<const char *> &argv)
{
    sendMessageHeader(out, "options");
    sendParamHeader(out, "argv");
    fputc('[', out);
    bool prev = false;
    for (const char *arg: argv)
    {
        if (prev)
            fputc(',', out);
        prev = true;
        sendString(out, arg);
    }
    fputc(']', out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send an "instruction" message.
 */
unsigned e9tool::sendInstructionMessage(FILE *out, intptr_t addr, size_t size,
    off_t offset)
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
 * Send an "emit" message.
 */
unsigned e9tool::sendEmitMessage(FILE *out, const char *filename,
    const char *format)
{
    sendMessageHeader(out, "emit");
    sendParamHeader(out, "filename");
    sendString(out, filename);
    sendSeparator(out);
    sendParamHeader(out, "format");
    sendString(out, format);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "reserve" message.
 */
unsigned e9tool::sendReserveMessage(FILE *out, intptr_t addr, size_t len,
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
unsigned e9tool::sendReserveMessage(FILE *out, intptr_t addr,
    const uint8_t *data, size_t len, int prot, intptr_t init, intptr_t fini,
    intptr_t mmap, bool absolute)
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
    if (fini != 0x0)
    {
        sendParamHeader(out, "fini");
        sendInteger(out, fini);
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
 * Send an "empty" "trampoline" message.
 */
unsigned e9tool::sendEmptyTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "$empty");
    sendSeparator(out);
    sendParamHeader(out, "template");
    fputs("[]", out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "trap" "trampoline" message.
 */
unsigned e9tool::sendTrapTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "$trap");
    sendSeparator(out);
    sendParamHeader(out, "template");
    fprintf(out, "[%u]", /*int3=*/0xcc);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a "print" "trampoline" message.
 */
unsigned e9tool::sendPrintTrampolineMessage(FILE *out, e9tool::BinaryType type)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "$print");
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);

    /*
     * Print instrumentation works by setting up a "write" system call that
     * prints a string representation of the instruction to stderr.  The
     * string representation is past via macros defined by the "patch"
     * message.
     */
    switch (type)
    {
        case BINARY_TYPE_ELF_DSO: case BINARY_TYPE_ELF_EXE:
        case BINARY_TYPE_ELF_PIE:
            // lea -0x4000(%rsp),%rsp
            // push %rdi
            // push %rsi
            // push %rax
            // push %rcx
            // push %rdx
            // push %r11
            fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                0x48, 0x8d, 0xa4, 0x24, -0x4000);
            fprintf(out, "%u,", 0x57);
            fprintf(out, "%u,", 0x56);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,", 0x51);
            fprintf(out, "%u,", 0x52);
            fprintf(out, "%u,%u,", 0x41, 0x53);

            // leaq .Lasm(%rip), %rsi
            // mov $strlen,%edx
            // mov $0x2,%edi        # stderr
            // mov $0x1,%eax        # SYS_write
            fprintf(out, "%u,%u,%u,{\"rel32\":\".Lasm@print\"},",
                0x48, 0x8d, 0x35);
            fprintf(out, "%u,\"$ASM_LEN@print\",", 0xba);
            fprintf(out, "%u,{\"int32\":%d},",
                0xbf, 0x02);
            fprintf(out, "%u,{\"int32\":%d},",
                0xb8, 0x01);

            // syscall
            fprintf(out, "%u,%u", 0x0f, 0x05);

            // pop %r11
            // pop %rdx
            // pop %rcx
            // pop %rax
            // pop %rsi
            // pop %rdi
            // lea 0x4000(%rsp),%rsp
            fprintf(out, ",%u,%u", 0x41, 0x5b);
            fprintf(out, ",%u", 0x5a);
            fprintf(out, ",%u", 0x59);
            fprintf(out, ",%u", 0x58);
            fprintf(out, ",%u", 0x5e);
            fprintf(out, ",%u", 0x5f);
            fprintf(out, ",%u,%u,%u,%u,{\"int32\":%d}",
                0x48, 0x8d, 0xa4, 0x24, 0x4000);

            break;

        case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:

            // lea -0x1000(%rsp),%rsp
            // push %rax
            // seto %al
            // lahf
            // push %rax
            // push %rcx
            // push %rdx
            // push %r8
            // push %r9
            // push %r10
            // push %r11
            fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                0x48, 0x8d, 0xa4, 0x24, -0x1000);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
            fprintf(out, "%u,", 0x9f);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,", 0x51);
            fprintf(out, "%u,", 0x52);
            fprintf(out, "%u,%u,", 0x41, 0x50);
            fprintf(out, "%u,%u,", 0x41, 0x51);
            fprintf(out, "%u,%u,", 0x41, 0x52);
            fprintf(out, "%u,%u,", 0x41, 0x53);

            // mov $0x0,%edx            # Event = NULL
            // mov %edx,%r8d            # ApcRoutine = NULL
            // mov %edx,%r9d            # ApcContext = NULL
            // push %rdx                # Key = NULL
            // push %rdx                # ByteOffset = NULL
            // mov $strlen,%eax
            // push %rax                # Length=ASM_LEN
            // leaq .Lasm(%rip),%rax
            // push %rax                # Buffer=ASM
            // lea 0x78(%rsp),%rax
            // push %rax                # IoStatusBlock=...
            // lea -0x20(%rsp),%rsp
            // leaq .Lconfig(%rip),%rax # E9Patch "config" struct
            //                          # (see e9loader.h)
            // mov ...(%rax),%rcx       # FileHandle=config->stderr
            // callq *...(%rax)         # call config->NtWriteFile()
            size_t stderr_offset = sizeof(struct e9_config_s) +
                offsetof(struct e9_config_pe_s, stderr_handle);
            size_t nt_write_file_offset = sizeof(struct e9_config_s) +
                offsetof(struct e9_config_pe_s, nt_write_file);
            assert(stderr_offset <= UINT8_MAX &&
                nt_write_file_offset <= UINT8_MAX);

            fprintf(out, "%u,\{\"int32\":%d},",
                0xba, 0x0);
            fprintf(out, "%u,%u,%u,",
                0x41, 0x89, 0xd0);
            fprintf(out, "%u,%u,%u,",
                0x41, 0x89, 0xd1);
            fprintf(out, "%u,", 0x52);
            fprintf(out, "%u,", 0x52);
            fprintf(out, "%u,\"$ASM_LEN@print\",",
                0xb8);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,%u,%u,{\"rel32\":\".Lasm@print\"},",
                0x48, 0x8d, 0x05);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
                0x48, 0x8d, 0x44, 0x24, 0x78);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
                0x48, 0x8d, 0x64, 0x24, -0x20);
            fprintf(out, "%u,%u,%u,{\"rel32\":\".Lconfig\"},",
                0x48, 0x8d, 0x05);
            fprintf(out, "%u,%u,%u,{\"int8\":%d},",
                0x48, 0x8b, 0x48, (int)stderr_offset);
            fprintf(out, "%u,%u,{\"int8\":%d}",
                0xff, 0x50, (int)nt_write_file_offset);

            // lea 0x48(%rsp),%rsp
            // pop %r11
            // pop %r10
            // pop %r9
            // pop %r8
            // pop %rdx
            // pop %rcx
            // pop %rax
            // add $0x7f,%al
            // sahf
            // pop %rax
            // lea 0x1000(%rsp),%rsp
            fprintf(out, ",%u,%u,%u,%u,{\"int8\":%d}",
                0x48, 0x8d, 0x64, 0x24, 0x48);
            fprintf(out, ",%u,%u", 0x41, 0x5b);
            fprintf(out, ",%u,%u", 0x41, 0x5a);
            fprintf(out, ",%u,%u", 0x41, 0x59);
            fprintf(out, ",%u,%u", 0x41, 0x58);
            fprintf(out, ",%u", 0x5a);
            fprintf(out, ",%u", 0x59);
            fprintf(out, ",%u", 0x58);
            fprintf(out, ",%u,%u", 0x04, 0x7f);
            fprintf(out, ",%u", 0x9e);
            fprintf(out, ",%u", 0x58);
            fprintf(out, ",%u,%u,%u,%u,{\"int32\":%d}",
                0x48, 0x8d, 0xa4, 0x24, 0x1000);

            break;
    }

    fputc(']', out);
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send an "exit" "trampoline" message.
 */
unsigned e9tool::sendExitTrampolineMessage(FILE *out, BinaryType type,
    int status)
{
    switch (type)
    {
        case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
            error("exit trampolines are not-yet-implemented for "
                "Windows PE binaries");
        default:
            break;
    }
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    fprintf(out, "\"$exit_%d\"", status);
    sendSeparator(out);
    sendParamHeader(out, "template");
    
    putc('[', out);
    fprintf(out, "%u,{\"int32\":%d},",              // mov $status, %edi
        0xbf, status);
    fprintf(out, "%u,{\"int32\":%d},",              // mov $SYS_EXIT, %eax
        0xb8, 60);
    fprintf(out, "%u,%u", 0x0f, 0x05);              // syscall
    putc(']', out);

    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Parse the Global Offset Table (GOT).
 */
static void parseGOT(const uint8_t *data, const Elf64_Shdr *shdr_got,
    const Elf64_Shdr *shdr_rela_got, const Elf64_Sym *dynsym_tab,
    size_t dynsym_num, const char *dynstr_tab, GOTInfo &got)
{
    const Elf64_Rela *rela_tab =
        (const Elf64_Rela *)(data + shdr_rela_got->sh_offset);
    size_t rela_num = shdr_rela_got->sh_size / sizeof(Elf64_Rela);
    for (size_t i = 0; i < rela_num; i++)
    {
        const Elf64_Rela *rela = rela_tab + i;
        if (rela->r_offset < shdr_got->sh_addr ||
                rela->r_offset >= shdr_got->sh_addr + shdr_got->sh_size)
            continue;
        size_t idx = (size_t)ELF64_R_SYM(rela->r_info);
        if (idx >= dynsym_num)
            continue;
        const Elf64_Sym *sym = dynsym_tab + idx;
        const char *name = dynstr_tab + sym->st_name;
        if (name[0] == '\0')
            continue;
        if (sym->st_shndx != SHN_UNDEF)
            continue;
        got.insert({name, rela->r_offset});
    }
}

/*
 * Parse the Procedure Linkage Table (PLT).
 */
static void parsePLT(const uint8_t *data, const Elf64_Shdr *shdr_plt,
    const Elf64_Shdr *shdr_rela_plt, const Elf64_Sym *dynsym_tab,
    size_t dynsym_num, const char *dynstr_tab, size_t plt_entry_sz,
    PLTInfo &plt)
{
    intptr_t plt_addr = (intptr_t)shdr_plt->sh_addr;
    size_t   plt_size = (size_t)shdr_plt->sh_size;
    const uint8_t *plt_data = data + shdr_plt->sh_offset;
    plt_size -= plt_size % plt_entry_sz;
    std::map<intptr_t, intptr_t> entries;
    for (size_t i = 0; i < plt_size; i += plt_entry_sz)
    {
        const uint8_t *plt_entry = plt_data + i;
        if (plt_entry[0] != 0xFF || plt_entry[1] != 0x25)   // jmpq *
            continue;
        intptr_t offset = *(const uint32_t *)(plt_entry + 2);
        intptr_t addr   = plt_addr + i + /*sizeof(jmpq)=*/6 + offset;
        entries.insert({addr, plt_addr + i});
    }
    
    const Elf64_Rela *rela_tab =
        (const Elf64_Rela *)(data + shdr_rela_plt->sh_offset);
    size_t rela_num = shdr_rela_plt->sh_size / sizeof(Elf64_Rela);
    for (size_t i = 0; i < rela_num; i++)
    {
        const Elf64_Rela *rela = rela_tab + i;
        auto k = entries.find(rela->r_offset);
        if (k == entries.end())
            continue;
        size_t idx = (size_t)ELF64_R_SYM(rela->r_info);
        if (idx >= dynsym_num)
            continue;
        const Elf64_Sym *sym = dynsym_tab + idx;
        const char *name = dynstr_tab + sym->st_name;
        if (name[0] == '\0')
            continue;
        if (sym->st_shndx != SHN_UNDEF ||
                ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;
        plt.insert({name, k->second});
    }
}

/*
 * Parse a symbol table.
 */
static void parseSymbols(const uint8_t *data, const Elf64_Shdr *shdr_syms,
    const Elf64_Shdr *shdr_strs, SymbolInfo &syms)
{
    const Elf64_Sym *sym_tab =
        (const Elf64_Sym *)(data + shdr_syms->sh_offset);
    const char *str_tab = (const char *)(data + shdr_strs->sh_offset);
    size_t sym_num = shdr_syms->sh_size / sizeof(Elf64_Sym);
    size_t str_len = shdr_strs->sh_size;
    for (size_t i = 0; i < sym_num; i++)
    {
        const Elf64_Sym *sym = sym_tab + i;
        if (sym->st_name >= str_len)
            continue;
        const char *name = str_tab + sym->st_name;
        if (name[0] == '\0')
            continue;
        syms.insert({name, sym});
    }
}

/*
 * Parse an ELF file.
 */
ELF *e9tool::parseELF(const char *filename, intptr_t base)
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
     * Find all sections.
     */
    size_t shnum = (size_t)ehdr->e_shnum;
    bool reloc = false;
    SectionInfo sections;
    std::map<off_t, const Elf64_Shdr *> exes;
    for (size_t i = 0; i < shnum; i++)
    {
        const Elf64_Shdr *shdr = shdrs + i;
        if (shdr->sh_name >= strtab_size)
            continue;
        if (shdr->sh_offset + shdr->sh_size > size)
            continue;
        if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA)
            reloc = true;
        const char *name = strtab + shdr->sh_name;
        if (name[0] == '\0')
            continue;
        sections.insert({name, shdr});
        if (shdr->sh_size > 0 &&
                shdr->sh_type == SHT_PROGBITS &&
                (shdr->sh_flags & SHF_WRITE) == 0 &&
                (shdr->sh_flags & SHF_ALLOC) != 0 &&
                (shdr->sh_flags & SHF_EXECINSTR) != 0)
        {
            // Executable section for disassembly:
            exes.insert({(off_t)shdr->sh_offset, shdr});
        }
    }

    /*
     * Find all program headers.
     */
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    size_t phnum = (size_t)ehdr->e_phnum;
    intptr_t end = INTPTR_MIN;
    bool dynlink = false;
    for (size_t i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        intptr_t phdr_base = (intptr_t)phdr->p_vaddr;
        intptr_t phdr_end  = phdr_base + phdr->p_memsz;
        end = std::max(end, phdr_end);
        if (!exe && phdr->p_type == PT_INTERP && !isLibraryFilename(filename))
            exe = true;
        if (phdr->p_type == PT_INTERP)
            dynlink = true;
    }
    end += base;

    /*
     * Find all symbols.
     */
    SymbolInfo dynsyms;
    auto i = sections.find(".dynsym");
    auto j = sections.find(".dynstr");
    const Elf64_Sym *dynsym_tab = nullptr;
    const char *dynstr_tab = nullptr;
    size_t dynsym_num = 0;
    if (i != sections.end() && j != sections.end() &&
            i->second->sh_type == SHT_DYNSYM &&
            j->second->sh_type == SHT_STRTAB)
    {
        const Elf64_Shdr *shdr_dynsym = i->second;
        const Elf64_Shdr *shdr_dynstr = j->second;
        dynsym_tab = (const Elf64_Sym *)(data + shdr_dynsym->sh_offset);
        dynstr_tab = (const char *)(data + shdr_dynstr->sh_offset);
        dynsym_num = shdr_dynsym->sh_size / sizeof(Elf64_Sym);
        parseSymbols(data, shdr_dynsym, shdr_dynstr, dynsyms);
    }
    SymbolInfo syms;
    i = sections.find(".symtab");
    j = sections.find(".strtab");
    if (i != sections.end() && j != sections.end() &&
            i->second->sh_type == SHT_SYMTAB &&
            j->second->sh_type == SHT_STRTAB)
    {
        // Binary is not stripped, so may as well parse the symtab.
        const Elf64_Shdr *shdr_syms = i->second;
        const Elf64_Shdr *shdr_strs = j->second;
        parseSymbols(data, shdr_syms, shdr_strs, syms);
    }

    /*
     * Find all GOT entries.
     */
    GOTInfo got;
    i = sections.find(".got");
    j = sections.find(".rela.dyn");
    if (dynsym_tab != nullptr && dynstr_tab != nullptr &&
        i != sections.end() && j != sections.end() &&
        i->second->sh_type == SHT_PROGBITS &&
        j->second->sh_type == SHT_RELA)
    {
        const Elf64_Shdr *shdr_got      = i->second;
        const Elf64_Shdr *shdr_rela_got = j->second;
        parseGOT(data, shdr_got, shdr_rela_got, dynsym_tab, dynsym_num,
            dynstr_tab, got);
    }

    /*
     * Find all PLT entries.
     */
    PLTInfo plt;
    i = sections.find(".plt");
    j = sections.find(".rela.plt");
    if (dynsym_tab != nullptr && dynstr_tab != nullptr &&
        i != sections.end() && j != sections.end() &&
        i->second->sh_type == SHT_PROGBITS &&
        j->second->sh_type == SHT_RELA)
    {
        const Elf64_Shdr *shdr_plt      = i->second;
        const Elf64_Shdr *shdr_rela_plt = j->second;
        parsePLT(data, shdr_plt, shdr_rela_plt, dynsym_tab, dynsym_num,
            dynstr_tab, /*entry_size=*/16, plt);
    }
    i = sections.find(".plt.got");
    j = sections.find(".rela.dyn");
    if (dynsym_tab != nullptr && dynstr_tab != nullptr &&
        i != sections.end() && j != sections.end() &&
        i->second->sh_type == SHT_PROGBITS &&
        j->second->sh_type == SHT_RELA)
    {
        const Elf64_Shdr *shdr_plt      = i->second;
        const Elf64_Shdr *shdr_rela_plt = j->second;
        parsePLT(data, shdr_plt, shdr_rela_plt, dynsym_tab, dynsym_num,
            dynstr_tab, /*entry_size=*/8, plt);
    }

    BinaryType type = BINARY_TYPE_ELF_EXE;
    type = (pic && exe?  BINARY_TYPE_ELF_PIE: type);
    type = (pic && !exe? BINARY_TYPE_ELF_DSO: type);
    dynlink = (dynlink || (type != BINARY_TYPE_ELF_EXE));

    ELF *elf = new ELF;
    elf->filename       = strDup(filename);
    elf->data           = data;
    elf->size           = size;
    elf->base           = base;
    elf->end            = end;
    elf->strs           = strtab;
    elf->phdrs          = phdrs;
    elf->phnum          = phnum;
    elf->type           = type;
    elf->reloc          = reloc;
    elf->dynlink        = dynlink;
    elf->sections.swap(sections);
    elf->dynsyms.swap(dynsyms);
    elf->syms.swap(syms);
    elf->got.swap(got);
    elf->plt.swap(plt);
    elf->exes.reserve(exes.size());
    for (const auto &entry: exes)
        elf->exes.push_back(entry.second);
    return elf;
}

/*
 * Parse a PE file into an ELF structure.
 */
typedef struct _IMAGE_FILE_HEADER
{
      uint16_t Machine;
      uint16_t NumberOfSections;
      uint32_t TimeDateStamp;
      uint32_t PointerToSymbolTable;
      uint32_t NumberOfSymbols;
      uint16_t SizeOfOptionalHeader;
      uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
#define IMAGE_FILE_MACHINE_AMD64 0x8664
typedef struct _IMAGE_DATA_DIRECTORY
{
      uint32_t VirtualAddress;
      uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
typedef struct _IMAGE_OPTIONAL_HEADER64
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
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
typedef struct _IMAGE_SECTION_HEADER
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
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000
#define IMAGE_SCN_MEM_SHARED    0x10000000
#define IMAGE_SCN_CNT_CODE      0x00000020
#define IMAGE_FILE_DLL          0x2000
ELF *e9tool::parsePE(const char *filename)
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
    const IMAGE_FILE_HEADER *file_hdr =
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
    const IMAGE_OPTIONAL_HEADER64 *opt_hdr =
        (PIMAGE_OPTIONAL_HEADER64)(file_hdr + 1);
    static const uint16_t PE64_MAGIC = 0x020b;
    if (opt_hdr->Magic != PE64_MAGIC)
        error("failed to parse PE file \"%s\"; invalid magic number (0x%x), "
            "expected PE64 (0x%x)", filename, opt_hdr->Magic, PE64_MAGIC);
    BinaryType type = BINARY_TYPE_PE_EXE;
    if ((file_hdr->Characteristics & IMAGE_FILE_DLL) != 0)
        type = BINARY_TYPE_PE_DLL;
    const IMAGE_SECTION_HEADER *shdrs =
        (PIMAGE_SECTION_HEADER)&opt_hdr->DataDirectory[
            opt_hdr->NumberOfRvaAndSizes];

    /*
     * Find all sections.
     */
    SectionInfo sections;
    std::map<off_t, const Elf64_Shdr *> exes;
    std::string strs;
    std::list<Elf64_Shdr> secs;
    for (uint16_t i = 0; i < file_hdr->NumberOfSections; i++)
    {
        const IMAGE_SECTION_HEADER *shdr = shdrs + i;
        off_t offset  = (off_t)shdr->PointerToRawData;
        intptr_t addr = (intptr_t)shdr->VirtualAddress;
        size_t size   = (size_t)shdr->VirtualSize;
        Elf64_Shdr elf_shdr;

        uint64_t flags = 0;
        if (offset != 0)
            flags |= SHF_ALLOC;
        if ((shdr->Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
            flags |= SHF_WRITE;
        if ((shdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            flags |= SHF_EXECINSTR;
        elf_shdr.sh_name      = strs.size();
        elf_shdr.sh_type      = SHT_PROGBITS;
        elf_shdr.sh_flags     = flags;
        elf_shdr.sh_addr      = addr;
        elf_shdr.sh_offset    = offset;
        elf_shdr.sh_size      = size;
        elf_shdr.sh_link      = 0;
        elf_shdr.sh_info      = 0;
        elf_shdr.sh_addralign = PAGE_SIZE;
        elf_shdr.sh_entsize   = 0;

        const char *name = shdr->Name;
        strs += shdr->Name;
        strs += '\0';

        secs.push_back(elf_shdr);
        const Elf64_Shdr *elf_shdr_ptr = &secs.back();
        sections.insert({name, elf_shdr_ptr});
        if ((shdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                (shdr->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
            exes.insert({offset, elf_shdr_ptr});
    }

    ELF *elf = new ELF;
    elf->filename       = strDup(filename);
    elf->data           = data;
    elf->size           = size;
    elf->base           = (intptr_t)opt_hdr->ImageBase;
    elf->end            = elf->base + (intptr_t)opt_hdr->SizeOfImage;;
    elf->strs           = strs.data();
    elf->phdrs          = nullptr;
    elf->phnum          = 0;
    elf->type           = type;
    elf->reloc          = false;
    elf->dynlink        = false;
    elf->sections.swap(sections);
    elf->exes.reserve(exes.size());
    for (const auto &entry: exes)
        elf->exes.push_back(entry.second);
    elf->sec_cache.swap(secs);
    elf->str_cache.swap(strs);

    return elf;
}

/*
 * Parse a binary.
 */
ELF *e9tool::parseBinary(const char *filename, intptr_t base)
{
    int fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", filename,
            strerror(errno));
    char c;
    if (read(fd, &c, sizeof(char)) != 1)
        error("failed to read file \"%s\": %s", filename, strerror(errno));
    close(fd);
 
    switch (c)
    {
        case 'E':
        default:
            return parseELF(filename, base);
        case 'M':
            return parsePE(filename);
    }
}

/*
 * Free an ELF file object.
 */
void freeELF(ELF *elf)
{
    free((void *)elf->filename);
    munmap((void *)elf->data, elf->size);
    delete elf;
}

/*
 * ELF getters.
 */
e9tool::BinaryType e9tool::getELFType(const ELF *elf)
{
    return elf->type;
}
const char *e9tool::getELFFilename(const ELF *elf)
{
    return elf->filename;
}
const uint8_t *e9tool::getELFData(const ELF *elf)
{
    return elf->data;
}
size_t e9tool::getELFDataSize(const ELF *elf)
{
    return elf->size;
}
intptr_t e9tool::getELFBaseAddr(const ELF *elf)
{
    return elf->base;
}
intptr_t e9tool::getELFEndAddr(const ELF *elf)
{
    return elf->end;
}
const Elf64_Shdr *e9tool::getELFSection(const ELF *elf, const char *name)
{
    auto i = elf->sections.find(name);
    if (i == elf->sections.end())
        return nullptr;
    return i->second;
}
const Elf64_Sym *e9tool::getELFDynSym(const ELF *elf, const char *name)
{
    auto i = elf->dynsyms.find(name);
    if (i == elf->dynsyms.end())
        return nullptr;
    return i->second;
}
const Elf64_Sym *e9tool::getELFSym(const ELF *elf, const char *name)
{
    auto i = elf->syms.find(name);
    if (i == elf->syms.end())
        return nullptr;
    return i->second;
}
intptr_t e9tool::getELFPLTEntry(const ELF *elf, const char *name)
{
    auto i = elf->plt.find(name);
    if (i == elf->plt.end())
        return INTPTR_MIN;
    return i->second;
}
intptr_t e9tool::getELFGOTEntry(const ELF *elf, const char *name)
{
    auto i = elf->got.find(name);
    if (i == elf->got.end())
        return INTPTR_MIN;
    return i->second;
}
const char *e9tool::getELFStrTab(const ELF *elf)
{
    return elf->strs;
}
extern const SectionInfo &e9tool::getELFSectionInfo(const ELF *elf)
{
    return elf->sections;
}
extern const SymbolInfo &e9tool::getELFDynSymInfo(const ELF *elf)
{
    return elf->dynsyms;
}
extern const SymbolInfo &e9tool::getELFSymInfo(const ELF *elf)
{
    return elf->syms;
}
extern const GOTInfo &e9tool::getELFGOTInfo(const ELF *elf)
{
    return elf->got;
}
extern const PLTInfo &e9tool::getELFPLTInfo(const ELF *elf)
{
    return elf->plt;
}

/*
 * Find the address associated with the given name.
 */
intptr_t e9tool::getELFObject(const ELF *elf, const char *name)
{
    // CASE #1: section
    const Elf64_Shdr *shdr = getELFSection(elf, name);
    if (shdr != nullptr)
        return elf->base + (intptr_t)shdr->sh_addr;

    // CASE #2: symbol
    const Elf64_Sym *sym = getELFDynSym(elf, name);
    if (sym == nullptr)
        sym = getELFSym(elf, name);
    if (sym != nullptr && sym->st_shndx != SHN_UNDEF)
        return elf->base + (intptr_t)sym->st_value;

    // CASE #3: PLT entry
    intptr_t val = getELFPLTEntry(elf, name);
    if (val != INTPTR_MIN)
        return elf->base + val;

    // CASE #4: undefined symbol
    if (sym != nullptr)
        return -1;

    return INTPTR_MIN;
}

/*
 * Lookup the address of a symbol, or INTPTR_MIN if not found.
 */
intptr_t e9tool::getSymbol(const ELF *elf, const char *symbol)
{
    return ::lookupSymbol(elf, symbol, TYPESIG_UNTYPED);
}

/*
 * Embed an ELF file.
 */
void e9tool::sendELFFileMessage(FILE *out, const ELF *ptr, bool absolute)
{
    const ELF &elf = *ptr;

    /*
     * Sanity checks.
     */
    if (elf.type != BINARY_TYPE_ELF_PIE)
        error("failed to embed ELF file \"%s\"; file is not a dynamic "
            "executable", elf.filename);
    if (elf.reloc)
        error("failed to embed ELF file \"%s\"; file uses relocations",
            elf.filename);

    /*
     * Check for special routines.
     */
    TypeSig sig = getInitSig(/*envp=*/true);
    intptr_t init = ::lookupSymbol(&elf, "init", sig);
    if (init == INTPTR_MIN)
    {
        sig = getInitSig(/*envp=*/false);
        init = ::lookupSymbol(&elf, "init", sig);
    }
    if (init == INTPTR_MIN)
    {
        sig = TYPESIG_EMPTY;
        init = ::lookupSymbol(&elf, "init", sig);
    }
    sig = TYPESIG_EMPTY;
    intptr_t fini = ::lookupSymbol(&elf, "fini", sig);
    sig = getMMapSig();
    intptr_t mmap = ::lookupSymbol(&elf, "mmap", sig);
    if (mmap == INTPTR_MIN)
    {
        // Alternative name to avoid conflict with stdlib mmap()
        mmap = ::lookupSymbol(&elf, "_mmap", sig);
    }

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
        if ((phdr->p_flags & PF_X) != 0 && fini >= phdr_base &&
                fini <= phdr_end)
        {
            sendParamHeader(out, "fini");
            sendInteger(out, fini);
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
 * Send a call ELF trampoline.
 */
unsigned e9tool::sendCallTrampolineMessage(FILE *out, const char *name,
    const std::vector<Argument> &args, BinaryType type, CallABI abi,
    CallJump jmp, PatchPos pos)
{
    bool state = false;
    for (const auto &arg: args)
    {
        if (arg.kind == ARGUMENT_STATE)
        {
            state = true;
            break;
        }
    }
    bool sysv = true;
    switch (type)
    {
        case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
            sysv = false;
            break;
        default:
            break;
    }

    const char *patch = name+1;
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, name);
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);

    // Adjust the stack:
    fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",     // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, -0x4000);

    // Push all caller-save registers:
    bool conditional = (jmp != JUMP_NONE);
    bool clean = (abi == ABI_CLEAN);
    const int *rsave = getCallerSaveRegs(sysv, clean, state, conditional,
        args.size());
    int num_rsave = 0;
    Register rscratch = (clean || state? REGISTER_RAX: REGISTER_INVALID);
    int32_t offset = 0x4000;
    for (int i = 0; rsave[i] >= 0; i++, num_rsave++)
    {
        sendPush(out, offset, (pos != POS_AFTER), getReg(rsave[i]), rscratch);
        if (rsave[i] != RSP_IDX && rsave[i] != RIP_IDX)
            offset += sizeof(int64_t);
    }

    // Load the arguments:
    fprintf(out, "\"$ARGS@%s\",", patch);
    if (!sysv)
    {
        // lea -0x20(%rsp),%rsp         # MS ABI red-zone
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, -0x20);
    }

    // Call the function:
    fprintf(out, "%u,\"$FUNC@%s\",", 0xe8, patch);      // callq function

    // Restore the state:
    if (!sysv)
    {
        // lea 0x20(%rsp),%rsp          # MS ABI red-zone
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, 0x20);
    }
    fprintf(out, "\"$RSTOR@%s\",", patch);
    
    // If clean & conditional & !state, store result in %rcx, else in %rax
    bool preserve_rax = (conditional || !clean);
    bool result_rax   = true;
    if (conditional && clean && !state)
    {
        // mov %rax,%rcx
        fprintf(out, "%u,%u,%u,", 0x48, 0x89, 0xc1);
        preserve_rax = false;
        result_rax   = false;
    }

    // Pop all callee-save registers:
    int rmin = (conditional? 1: 0);
    for (int i = num_rsave-1; i >= rmin; i--)
    {
        if (rsave[i] == RSP_IDX || rsave[i] == RIP_IDX)
            continue;
        sendPop(out, preserve_rax, getReg(rsave[i]));
    }

    // If conditional, jump to $instruction if %rax is zero:
    if (conditional)
    {
        if (result_rax)
        {
            // xchg %rax,%rcx
            // jrcxz .Lskip
            // xchg %rax,%rcx
            //
            fprintf(out, "%u,%u,", 0x48, 0x91);
            fprintf(out, "%u,{\"rel8\":\".Lskip@%s\"},", 0xe3, patch);
            fprintf(out, "%u,%u,", 0x48, 0x91);
        }
        else
        {
            // jrcxz .Lskip
            fprintf(out, "%u,{\"rel8\":\".Lskip@%s\"},", 0xe3, patch);
        }

        // The result is non-zero
        if (jmp == JUMP_GOTO)
        {
            // The register state, including %rsp, must be fully restored
            // before implementing the jump.  This means (1) the jump target
            // must be stored in memory, and (2) must be thread-local.  We
            // therefore use thread-local address %fs:0x40 (same as stdlib.c
            // errno).  However, this assumes the binary has set %fs to be the
            // TLS base address (any binary using glibc should do this).

            // mov %rax/rcx, %fs:0x40
            // pop %rax/rcx
            //
            int tls_offset = 0x40; 
            fprintf(out, "%u,%u,%u,%u,%u,{\"int32\":%d},",
                0x64, 0x48, 0x89, (result_rax? 0x04: 0x0c), 0x25, tls_offset);
            fprintf(out, "%u,", (result_rax? 0x58: 0x59));
            fprintf(out, "\"$RSTOR_RSP@%s\",", patch);

            // jmpq *%fs:0x40
            fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                0x64, 0xff, 0x24, 0x25, tls_offset);
        }
        else
        {
            fprintf(out, "%u,", (result_rax? 0x58: 0x59));
            fprintf(out, "\"$RSTOR_RSP@%s\",", patch);
            fputs("\"$break\",", out);
        }
 
        // The result is zero...
        fprintf(out, "\".Lskip@%s\",", patch);
        if (result_rax)
        {
            // xchg %rax,%rcx
            fprintf(out, "%u,%u,", 0x48, 0x91);
        }
        fprintf(out, "%u,", (result_rax? 0x58: 0x59));
    }

    // Restore the stack pointer.
    fprintf(out, "\"$RSTOR_RSP@%s\"]", patch);
    
    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send a generic trampoline.
 */
unsigned e9tool::sendTrampolineMessage(FILE *out, const char *name,
    const char *template_)
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

