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

#define MAX_ARGNO       8

namespace e9frontend
{

/*
 * ELF file.
 */
struct ELF;

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
    ARGUMENT_USER,                  // User-defined argument
    ARGUMENT_INTEGER,               // Constant integer argument
    ARGUMENT_OFFSET,                // Instruction file offset
    ARGUMENT_ADDR,                  // Instruction address
    ARGUMENT_NEXT,                  // Next instruction address
    ARGUMENT_BASE,                  // Base address of ELF binary in memory
    ARGUMENT_STATIC_ADDR,           // (Static) instruction address
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
    
    ARGUMENT_RAX_PTR,               // %rax register pointer
    ARGUMENT_RBX_PTR,               // %rbx register pointer
    ARGUMENT_RCX_PTR,               // %rcx register pointer
    ARGUMENT_RDX_PTR,               // %rdx register pointer
    ARGUMENT_RBP_PTR,               // %rbp register pointer
    ARGUMENT_RDI_PTR,               // %rdi register pointer
    ARGUMENT_RSI_PTR,               // %rsi register pointer
    ARGUMENT_R8_PTR,                // %r8 register pointer
    ARGUMENT_R9_PTR,                // %r9 register pointer
    ARGUMENT_R10_PTR,               // %r10 register pointer
    ARGUMENT_R11_PTR,               // %r11 register pointer
    ARGUMENT_R12_PTR,               // %r12 register pointer
    ARGUMENT_R13_PTR,               // %r13 register pointer
    ARGUMENT_R14_PTR,               // %r14 register pointer
    ARGUMENT_R15_PTR,               // %r15 register pointer
    ARGUMENT_RFLAGS_PTR,            // %rflags register pointer
    ARGUMENT_RIP_PTR,               // %rip register pointer
    ARGUMENT_RSP_PTR,               // %rsp register pointer

    ARGUMENT_OPERAND_0,             // Operand[0]
    ARGUMENT_OPERAND_1,             // Operand[1]
    ARGUMENT_OPERAND_2,             // Operand[2]
    ARGUMENT_OPERAND_3,             // Operand[3]
    ARGUMENT_OPERAND_4,             // Operand[4]
    ARGUMENT_OPERAND_5,             // Operand[5]
    ARGUMENT_OPERAND_6,             // Operand[6]
    ARGUMENT_OPERAND_7,             // Operand[7]

    ARGUMENT_SRC_0,                 // Source operand[0]
    ARGUMENT_SRC_1,                 // Source operand[1]
    ARGUMENT_SRC_2,                 // Source operand[2]
    ARGUMENT_SRC_3,                 // Source operand[3]
    ARGUMENT_SRC_4,                 // Source operand[4]
    ARGUMENT_SRC_5,                 // Source operand[5]
    ARGUMENT_SRC_6,                 // Source operand[6]
    ARGUMENT_SRC_7,                 // Source operand[7]

    ARGUMENT_DST_0,                 // Dest operand[0]
    ARGUMENT_DST_1,                 // Dest operand[1]
    ARGUMENT_DST_2,                 // Dest operand[2]
    ARGUMENT_DST_3,                 // Dest operand[3]
    ARGUMENT_DST_4,                 // Dest operand[4]
    ARGUMENT_DST_5,                 // Dest operand[5]
    ARGUMENT_DST_6,                 // Dest operand[6]
    ARGUMENT_DST_7,                 // Dest operand[7]

    ARGUMENT_MAX                    // Maximum argument value
};

struct Argument
{
    ArgumentKind kind;              // Argument kind.
    bool duplicate;                 // Argument is a duplicate?
    intptr_t value;                 // Argument value (ARGUMENT_INTEGER/USER).
    const char *name;               // Argument name  (ARGUMENT_USER).
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
extern void sendCode(FILE *out, const char *code);

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
    const std::vector<Argument> &args, bool clean = true, bool before = true,
    bool replace = false);
extern unsigned sendTrampolineMessage(FILE *out, const char *name,
    const char *template_);

/*
 * Misc. functions:
 */
extern void parseELF(const char *filename, intptr_t base, ELF &elf);
extern intptr_t lookupSymbol(const ELF &elf, const char *symbol);
extern void NO_RETURN error(const char *msg, ...);
extern void warning(const char *msg, ...);

}   // namespace e9frontend

#endif
