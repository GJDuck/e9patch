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
 * Call kind
 */
enum CallKind
{
    CALL_BEFORE,
    CALL_AFTER,
    CALL_REPLACE,
    CALL_CONDITIONAL
};

/*
 * Argument fields.
 */
enum FieldKind
{
    FIELD_NONE,                     // No field.
    FIELD_DISPL,                    // Displacement.
    FIELD_BASE,                     // Base register.
    FIELD_INDEX,                    // Index register.
    FIELD_SCALE,                    // Scale.
    FIELD_SIZE,                     // Operand size.
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
    ARGUMENT_ASM,                   // Assembly string
    ARGUMENT_ASM_SIZE,              // Assembly string size
    ARGUMENT_ASM_LEN,               // Assembly string length
    ARGUMENT_BYTES,                 // Instruction bytes
    ARGUMENT_BYTES_SIZE,            // Instruction bytes size
    ARGUMENT_TARGET,                // Call/jump target
    ARGUMENT_TRAMPOLINE,            // Trampoline
    ARGUMENT_RANDOM,                // Random number
    
    ARGUMENT_AL,                    // %al register
    ARGUMENT_AH,                    // %ah register
    ARGUMENT_BL,                    // %bl register
    ARGUMENT_BH,                    // %bh register
    ARGUMENT_CL,                    // %cl register
    ARGUMENT_CH,                    // %ch register
    ARGUMENT_DL,                    // %dl register
    ARGUMENT_DH,                    // %dh register
    ARGUMENT_BPL,                   // %bpl register
    ARGUMENT_DIL,                   // %dil register
    ARGUMENT_SIL,                   // %sil register
    ARGUMENT_R8B,                   // %r8b register
    ARGUMENT_R9B,                   // %r9b register
    ARGUMENT_R10B,                  // %r10b register
    ARGUMENT_R11B,                  // %r11b register
    ARGUMENT_R12B,                  // %r12b register
    ARGUMENT_R13B,                  // %r13b register
    ARGUMENT_R14B,                  // %r14b register
    ARGUMENT_R15B,                  // %r15b register
    ARGUMENT_SPL,                   // %spl register
    
    ARGUMENT_AX,                    // %ax register
    ARGUMENT_BX,                    // %bx register
    ARGUMENT_CX,                    // %cx register
    ARGUMENT_DX,                    // %dx register
    ARGUMENT_BP,                    // %bp register
    ARGUMENT_DI,                    // %di register
    ARGUMENT_SI,                    // %si register
    ARGUMENT_R8W,                   // %r8w register
    ARGUMENT_R9W,                   // %r9w register
    ARGUMENT_R10W,                  // %r10w register
    ARGUMENT_R11W,                  // %r11w register
    ARGUMENT_R12W,                  // %r12w register
    ARGUMENT_R13W,                  // %r13w register
    ARGUMENT_R14W,                  // %r14w register
    ARGUMENT_R15W,                  // %r15w register
    ARGUMENT_SP,                    // %sp register

    ARGUMENT_EAX,                   // %eax register
    ARGUMENT_EBX,                   // %ebx register
    ARGUMENT_ECX,                   // %ecx register
    ARGUMENT_EDX,                   // %edx register
    ARGUMENT_EBP,                   // %ebp register
    ARGUMENT_EDI,                   // %edi register
    ARGUMENT_ESI,                   // %esi register
    ARGUMENT_R8D,                   // %r8d register
    ARGUMENT_R9D,                   // %r9d register
    ARGUMENT_R10D,                  // %r10d register
    ARGUMENT_R11D,                  // %r11d register
    ARGUMENT_R12D,                  // %r12d register
    ARGUMENT_R13D,                  // %r13d register
    ARGUMENT_R14D,                  // %r14d register
    ARGUMENT_R15D,                  // %r15d register
    ARGUMENT_ESP,                   // %esp register

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
 
    ARGUMENT_OP,                    // Operand[i]
    ARGUMENT_SRC,                   // Source operand[i]
    ARGUMENT_DST,                   // Dest operand[i]
    ARGUMENT_IMM,                   // Immediate operand[i]
    ARGUMENT_REG,                   // Register operand[i]
    ARGUMENT_MEM,                   // Memory operand[i]

    ARGUMENT_MAX                    // Maximum argument value
};

struct Argument
{
    ArgumentKind kind;              // Argument kind.
    FieldKind field;                // Argument field.
    bool ptr;                       // Argument is passed by pointer?
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
extern void sendELFFileMessage(FILE *out, const ELF *elf,
    bool absolute = false);
extern unsigned sendPassthruTrampolineMessage(FILE *out);
extern unsigned sendPrintTrampolineMessage(FILE *out);
extern unsigned sendTrapTrampolineMessage(FILE *out);
extern unsigned sendExitTrampolineMessage(FILE *out, int status);
extern unsigned sendCallTrampolineMessage(FILE *out, const char *name,
    const std::vector<Argument> &args, bool clean = true, 
    CallKind call = CALL_BEFORE);
extern unsigned sendTrampolineMessage(FILE *out, const char *name,
    const char *template_);

/*
 * Misc. functions:
 */
extern ELF *parseELF(const char *filename, intptr_t base);
extern void freeELF(ELF *elf);
extern const uint8_t *getELFData(const ELF *elf);
extern size_t getELFDataSize(const ELF *elf);
extern intptr_t getSymbol(const ELF *elf, const char *symbol);
extern intptr_t getTextAddr(const ELF *elf);
extern off_t getTextOffset(const ELF *elf);
extern size_t getTextSize(const ELF *elf);
extern void NO_RETURN error(const char *msg, ...);
extern void warning(const char *msg, ...);

}   // namespace e9frontend

#endif
