/*
 * e9frontend.h
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

#ifndef __E9FRONTEND_H
#define __E9FRONTEND_H

#include <vector>

#include <cstdint>
#include <cstdio>

#include <elf.h>

#define NO_RETURN       __attribute__((__noreturn__))

#define MAX_ARGNO       6

namespace e9frontend
{

/*
 * ELF file.
 */
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
    bool     pie;                   // PIE?   
    bool     dso;                   // Shared object?
};

/*
 * Metadata.
 */
struct Metadata
{
    const char *name;               // Metadata name.
    const char *data;               // Metadata data.
};

/*
 * Arguments.
 */
enum ArgumentKind
{
    ARGUMENT_INVALID,               // Invalid argument
    ARGUMENT_INTEGER,               // Constant integer argument
    ARGUMENT_ADDR,                  // Instruction address
    ARGUMENT_NEXT,                  // Next instruction address
    ARGUMENT_ASM_STR,               // Assembly string
    ARGUMENT_ASM_STR_LEN,           // Assembly string length
    ARGUMENT_BYTES,                 // Instruction bytes
    ARGUMENT_BYTES_LEN,             // Instruction bytes length
    ARGUMENT_TARGET,                // Call/jump target
    ARGUMENT_TRAMPOLINE,            // Trampoline
    ARGUMENT_RAX,                   // %rax register
    ARGUMENT_RBX,                   // %rbx register
    ARGUMENT_RCX,                   // %rcx register
    ARGUMENT_RDX,                   // %rdx register
    ARGUMENT_RBP,                   // %rbp register
    ARGUMENT_RDI,                   // %rdi register
    ARGUMENT_RSI,                   // %rsi register
    ARGUMENT_R8,                    // %r8 register
    ARGUMENT_R9,                    // %r9 register
    ARGUMENT_R10,                   // %r10 register
    ARGUMENT_R11,                   // %r11 register
    ARGUMENT_R12,                   // %r12 register
    ARGUMENT_R13,                   // %r13 register
    ARGUMENT_R14,                   // %r14 register
    ARGUMENT_R15,                   // %r15 register
    ARGUMENT_RFLAGS,                // %rflags register
    ARGUMENT_RIP,                   // %rip register
    ARGUMENT_RSP,                   // %rsp register

    ARGUMENT_MAX                    // Maximum argument value
};

struct Argument
{
    ArgumentKind kind;              // Argument kind.
    intptr_t value;                 // Argument value.
};

/*
 * Low-level functions that send fragments of JSONRPC messages:
 */
extern void sendMessageHeader(FILE *out, const char *method);
extern unsigned sendMessageFooter(FILE *out, bool sync = false);
extern void sendParamHeader(FILE *out, const char *name);
extern void sendSeparator(FILE *out, bool last = false);
extern void sendMetadataHeader(FILE *out);
extern void sendMetadataFooter(FILE *out);
extern void sendDefinitionHeader(FILE *out, const char *name);
extern void sendInteger(FILE *out, intptr_t i);
extern void sendString(FILE *out, const char *s);

/*
 * High-level functions that send complete E9PATCH JSONRPC messages:
 */
extern unsigned sendPatchMessage(FILE *out, const char *trampoline,
    off_t offset, const Metadata *metadata = nullptr);
extern unsigned sendReserveMessage(FILE *out, intptr_t addr, size_t len,
    bool absolute = false);
extern unsigned sendReserveMessage(FILE *out, intptr_t addr,
    const uint8_t *data, size_t len, int prot, intptr_t init = 0x0,
    intptr_t mmap = 0x0, bool absolute = false);
extern void sendELFFileMessage(FILE *out, const ELF &elf,
    bool absolute = false);
extern unsigned sendPassthruTrampolineMessage(FILE *out);
extern unsigned sendPrintTrampolineMessage(FILE *out);
extern unsigned sendTrapTrampolineMessage(FILE *out);
extern unsigned sendCallTrampolineMessage(FILE *out, const ELF &elf,
    const char *filename, const char *symbol, const char *name,
    const std::vector<Argument> args,
    bool clean = true, bool before = true, bool replace = false);

/*
 * Misc. functions:
 */
extern void parseELF(const char *filename, intptr_t base, ELF &elf);
extern intptr_t lookupSymbol(const ELF &elf, const char *symbol);
extern void NO_RETURN error(const char *msg, ...);
extern void warning(const char *msg, ...);

}   // namespace e9frontend

#endif
