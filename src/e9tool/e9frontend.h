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
 * Registers.
 */
enum Register
{
    REGISTER_NONE,

    REGISTER_AH,
    REGISTER_CH,
    REGISTER_DH,
    REGISTER_BH,
    
    REGISTER_AL,
    REGISTER_CL,
    REGISTER_DL,
    REGISTER_BL,
    REGISTER_SPL,
    REGISTER_BPL,
    REGISTER_SIL,
    REGISTER_DIL,
    REGISTER_R8B,
    REGISTER_R9B,
    REGISTER_R10B,
    REGISTER_R11B,
    REGISTER_R12B,
    REGISTER_R13B,
    REGISTER_R14B,
    REGISTER_R15B,
    
    REGISTER_AX,
    REGISTER_CX,
    REGISTER_DX,
    REGISTER_BX,
    REGISTER_SP,
    REGISTER_BP,
    REGISTER_SI,
    REGISTER_DI,
    REGISTER_R8W,
    REGISTER_R9W,
    REGISTER_R10W,
    REGISTER_R11W,
    REGISTER_R12W,
    REGISTER_R13W,
    REGISTER_R14W,
    REGISTER_R15W,
    
    REGISTER_EFLAGS,
    REGISTER_IP,
    
    REGISTER_EAX,
    REGISTER_ECX,
    REGISTER_EDX,
    REGISTER_EBX,
    REGISTER_ESP,
    REGISTER_EBP,
    REGISTER_ESI,
    REGISTER_EDI,
    REGISTER_R8D,
    REGISTER_R9D,
    REGISTER_R10D,
    REGISTER_R11D,
    REGISTER_R12D,
    REGISTER_R13D,
    REGISTER_R14D,
    REGISTER_R15D,
    
    REGISTER_EIP,
    
    REGISTER_RAX,
    REGISTER_RCX,
    REGISTER_RDX,
    REGISTER_RBX,
    REGISTER_RSP,
    REGISTER_RBP,
    REGISTER_RSI,
    REGISTER_RDI,
    REGISTER_R8,
    REGISTER_R9,
    REGISTER_R10,
    REGISTER_R11,
    REGISTER_R12,
    REGISTER_R13,
    REGISTER_R14,
    REGISTER_R15,
    
    REGISTER_RIP,
    
    REGISTER_XMM0,
    REGISTER_XMM1,
    REGISTER_XMM2,
    REGISTER_XMM3,
    REGISTER_XMM4,
    REGISTER_XMM5,
    REGISTER_XMM6,
    REGISTER_XMM7,
    REGISTER_XMM8,
    REGISTER_XMM9,
    REGISTER_XMM10,
    REGISTER_XMM11,
    REGISTER_XMM12,
    REGISTER_XMM13,
    REGISTER_XMM14,
    REGISTER_XMM15,
    REGISTER_XMM16,
    REGISTER_XMM17,
    REGISTER_XMM18,
    REGISTER_XMM19,
    REGISTER_XMM20,
    REGISTER_XMM21,
    REGISTER_XMM22,
    REGISTER_XMM23,
    REGISTER_XMM24,
    REGISTER_XMM25,
    REGISTER_XMM26,
    REGISTER_XMM27,
    REGISTER_XMM28,
    REGISTER_XMM29,
    REGISTER_XMM30,
    REGISTER_XMM31,
    
    REGISTER_YMM0,
    REGISTER_YMM1,
    REGISTER_YMM2,
    REGISTER_YMM3,
    REGISTER_YMM4,
    REGISTER_YMM5,
    REGISTER_YMM6,
    REGISTER_YMM7,
    REGISTER_YMM8,
    REGISTER_YMM9,
    REGISTER_YMM10,
    REGISTER_YMM11,
    REGISTER_YMM12,
    REGISTER_YMM13,
    REGISTER_YMM14,
    REGISTER_YMM15,
    REGISTER_YMM16,
    REGISTER_YMM17,
    REGISTER_YMM18,
    REGISTER_YMM19,
    REGISTER_YMM20,
    REGISTER_YMM21,
    REGISTER_YMM22,
    REGISTER_YMM23,
    REGISTER_YMM24,
    REGISTER_YMM25,
    REGISTER_YMM26,
    REGISTER_YMM27,
    REGISTER_YMM28,
    REGISTER_YMM29,
    REGISTER_YMM30,
    REGISTER_YMM31,
    
    REGISTER_ZMM0,
    REGISTER_ZMM1,
    REGISTER_ZMM2,
    REGISTER_ZMM3,
    REGISTER_ZMM4,
    REGISTER_ZMM5,
    REGISTER_ZMM6,
    REGISTER_ZMM7,
    REGISTER_ZMM8,
    REGISTER_ZMM9,
    REGISTER_ZMM10,
    REGISTER_ZMM11,
    REGISTER_ZMM12,
    REGISTER_ZMM13,
    REGISTER_ZMM14,
    REGISTER_ZMM15,
    REGISTER_ZMM16,
    REGISTER_ZMM17,
    REGISTER_ZMM18,
    REGISTER_ZMM19,
    REGISTER_ZMM20,
    REGISTER_ZMM21,
    REGISTER_ZMM22,
    REGISTER_ZMM23,
    REGISTER_ZMM24,
    REGISTER_ZMM25,
    REGISTER_ZMM26,
    REGISTER_ZMM27,
    REGISTER_ZMM28,
    REGISTER_ZMM29,
    REGISTER_ZMM30,
    REGISTER_ZMM31,
    
    REGISTER_ES,
    REGISTER_CS,
    REGISTER_SS,
    REGISTER_DS,
    REGISTER_FS,
    REGISTER_GS,
    
    REGISTER_CR0,
    REGISTER_CR1,
    REGISTER_CR2,
    REGISTER_CR3,
    REGISTER_CR4,
    REGISTER_CR5,
    REGISTER_CR6,
    REGISTER_CR7,
    REGISTER_CR8,
    REGISTER_CR9,
    REGISTER_CR10,
    REGISTER_CR11,
    REGISTER_CR12,
    REGISTER_CR13,
    REGISTER_CR14,
    REGISTER_CR15,
    
    REGISTER_DR0,
    REGISTER_DR1,
    REGISTER_DR2,
    REGISTER_DR3,
    REGISTER_DR4,
    REGISTER_DR5,
    REGISTER_DR6,
    REGISTER_DR7,
    REGISTER_DR8,
    REGISTER_DR9,
    REGISTER_DR10,
    REGISTER_DR11,
    REGISTER_DR12,
    REGISTER_DR13,
    REGISTER_DR14,
    REGISTER_DR15,
    
    REGISTER_FP0,
    REGISTER_FP1,
    REGISTER_FP2,
    REGISTER_FP3,
    REGISTER_FP4,
    REGISTER_FP5,
    REGISTER_FP6,
    REGISTER_FP7,
    
    REGISTER_K0,
    REGISTER_K1,
    REGISTER_K2,
    REGISTER_K3,
    REGISTER_K4,
    REGISTER_K5,
    REGISTER_K6,
    REGISTER_K7,
    
    REGISTER_MM0,
    REGISTER_MM1,
    REGISTER_MM2,
    REGISTER_MM3,
    REGISTER_MM4,
    REGISTER_MM5,
    REGISTER_MM6,
    REGISTER_MM7,
    
    REGISTER_ST0,
    REGISTER_ST1,
    REGISTER_ST2,
    REGISTER_ST3,
    REGISTER_ST4,
    REGISTER_ST5,
    REGISTER_ST6,
    REGISTER_ST7,
    
    REGISTER_FPSW,
    
    REGISTER_UNKNOWN,
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
 * Memory operand seg:disp(base,index,scale)
 */
struct MemOp
{
    Register seg;
    int32_t disp;
    Register base;
    Register index;
    int8_t scale;
    int8_t size;
};

/*
 * Argument kinds.
 */
enum ArgumentKind
{
    ARGUMENT_INVALID,               // Invalid argument
    ARGUMENT_USER,                  // User-defined argument
    ARGUMENT_INTEGER,               // Constant integer argument
    ARGUMENT_ID,                    // Patch ID
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
    ARGUMENT_REGISTER,              // Register
    ARGUMENT_MEMOP,                 // Memory operand

    ARGUMENT_OP,                    // Operand[i]
    ARGUMENT_SRC,                   // Source operand[i]
    ARGUMENT_DST,                   // Dest operand[i]
    ARGUMENT_IMM,                   // Immediate operand[i]
    ARGUMENT_REG,                   // Register operand[i]
    ARGUMENT_MEM,                   // Memory operand[i]

    ARGUMENT_MAX                    // Maximum argument value
};

/*
 * Argument.
 */
struct Argument
{
    ArgumentKind kind;              // Argument kind.
    FieldKind field;                // Argument field.
    bool ptr;                       // Argument is passed by pointer?
    bool duplicate;                 // Argument is a duplicate?
    intptr_t value;                 // Argument value.
    MemOp memop;                    // Argument memop value.
    const char *name;               // Argument name (ARGUMENT_USER).
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
