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
 * GPR register indexes.
 */
#define RDI_IDX         0
#define RSI_IDX         1
#define RDX_IDX         2
#define RCX_IDX         3
#define R8_IDX          4
#define R9_IDX          5
#define RFLAGS_IDX      6
#define RAX_IDX         7
#define R10_IDX         8
#define R11_IDX         9
#define RBX_IDX         10
#define RBP_IDX         11
#define R12_IDX         12
#define R13_IDX         13
#define R14_IDX         14
#define R15_IDX         15
#define RSP_IDX         16
#define RMAX_IDX        17

/*
 * Prototypes.
 */
static char *strDup(const char *old_str, size_t n = SIZE_MAX);
static std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
    x86_reg reg, x86_reg rscratch = X86_REG_INVALID);
static bool sendPop(FILE *out, bool conditional, x86_reg reg,
    x86_reg rscratch = X86_REG_INVALID);
static bool sendMovFromR64ToR64(FILE *out, int srcno, int dstno);
static void sendMovFromR32ToR64(FILE *out, int srcno, int dstno);
static void sendMovFromR16ToR64(FILE *out, int srcno, int dstno);
static void sendMovFromR8ToR64(FILE *out, int srcno, bool srchi, int dstno);
static void sendMovFromStackToR64(FILE *out, int32_t offset, int regno);
static void sendMovFromStack32ToR64(FILE *out, int32_t offset, int regno);
static void sendMovFromStack16ToR64(FILE *out, int32_t offset, int regno);
static void sendMovFromStack8ToR64(FILE *out, int32_t offset, int regno);
static void sendMovFromR64ToStack(FILE *out, int regno, int32_t offset);
static void sendMovFromRAX16ToR64(FILE *out, int regno);
static void sendSExtFromI32ToR64(FILE *out, const char *value, int regno);
static void sendSExtFromI32ToR64(FILE *out, int32_t value, int regno);
static void sendZExtFromI32ToR64(FILE *out, const char *value, int regno);
static void sendZExtFromI32ToR64(FILE *out, int32_t value, int regno);
static void sendMovFromI64ToR64(FILE *out, intptr_t value, int regno);
static void sendLeaFromPCRelToR64(FILE *out, const char *offset, int regno);
static void sendLeaFromPCRelToR64(FILE *out, int32_t offset, int regno);
static void sendLeaFromStackToR64(FILE *out, int32_t offset, int regno);

/*
 * Symbols.
 */
typedef uint8_t Type;

#define TYPE_NONE                   0x00
#define TYPE_CHAR                   0x01
#define TYPE_INT8                   0x02
#define TYPE_INT16                  0x03
#define TYPE_INT32                  0x04
#define TYPE_INT64                  0x05
#define TYPE_VOID                   0x06
#define TYPE_NULL_PTR               0x07
#define TYPE_PTR                    0x10
#define TYPE_PTR_PTR                0x20
#define TYPE_CONST                  0x40

#define TYPE_VOID_PTR               (TYPE_VOID | TYPE_PTR)
#define TYPE_CONST_VOID_PTR         (TYPE_CONST | TYPE_VOID | TYPE_PTR)
#define TYPE_CONST_CHAR_PTR         (TYPE_CONST | TYPE_CHAR | TYPE_PTR)
#define TYPE_CONST_INT8_PTR         (TYPE_CONST | TYPE_INT8 | TYPE_PTR)

typedef uint64_t TypeSig;

#define TYPESIG_MIN     0
#define TYPESIG_MAX     UINT64_MAX

#define TYPESIG_EMPTY   0
#define TYPESIG_UNTYPED (UINT64_MAX-1)

struct Symbol
{
    const char * const name;            // Symbol name
    const TypeSig      sig;             // Symbol typesig.

    bool operator<(const Symbol &sym) const
    {
        int cmp = strcmp(name, sym.name);
        if (cmp != 0)
            return (cmp < 0);
        return (sig < sym.sig);
    }

    Symbol(const char *name, TypeSig sig) : name(name), sig(sig)
    {
        ;
    }
};

/*
 * Symbol cache.  INTPTR_MIN=missing, (>0)=original, (<0)=derived.
 */
typedef std::map<Symbol, intptr_t> Symbols;

/*
 * Get argument register index.
 */
static int getArgRegIdx(int argno)
{
    if (argno <= R9_IDX)
        return argno;
    if (argno == RFLAGS_IDX)
        return R10_IDX;
    if (argno == RAX_IDX)
        return R11_IDX;
    return -1;
}

/*
 * Convert an argument into a register.
 */
static x86_reg getReg(ArgumentKind arg)
{
    switch (arg)
    {
        case ARGUMENT_RAX:
            return X86_REG_RAX;
        case ARGUMENT_RBX:
            return X86_REG_RBX;
        case ARGUMENT_RCX:
            return X86_REG_RCX;
        case ARGUMENT_RDX:
            return X86_REG_RDX;
        case ARGUMENT_RSP:
            return X86_REG_RSP;
        case ARGUMENT_RBP:
            return X86_REG_RBP;
        case ARGUMENT_RDI:
            return X86_REG_RDI;
        case ARGUMENT_RSI:
            return X86_REG_RSI;
        case ARGUMENT_R8:
            return X86_REG_R8;
        case ARGUMENT_R9:
            return X86_REG_R9;
        case ARGUMENT_R10:
            return X86_REG_R10;
        case ARGUMENT_R11:
            return X86_REG_R11;
        case ARGUMENT_R12:
            return X86_REG_R12;
        case ARGUMENT_R13:
            return X86_REG_R13;
        case ARGUMENT_R14:
            return X86_REG_R14;
        case ARGUMENT_R15:
            return X86_REG_R15;

        case ARGUMENT_EAX:
            return X86_REG_EAX;
        case ARGUMENT_EBX:
            return X86_REG_EBX;
        case ARGUMENT_ECX:
            return X86_REG_ECX;
        case ARGUMENT_EDX:
            return X86_REG_EDX;
        case ARGUMENT_ESP:
            return X86_REG_ESP;
        case ARGUMENT_EBP:
            return X86_REG_EBP;
        case ARGUMENT_EDI:
            return X86_REG_EDI;
        case ARGUMENT_ESI:
            return X86_REG_ESI;
        case ARGUMENT_R8D:
            return X86_REG_R8D;
        case ARGUMENT_R9D:
            return X86_REG_R9D;
        case ARGUMENT_R10D:
            return X86_REG_R10D;
        case ARGUMENT_R11D:
            return X86_REG_R11D;
        case ARGUMENT_R12D:
            return X86_REG_R12D;
        case ARGUMENT_R13D:
            return X86_REG_R13D;
        case ARGUMENT_R14D:
            return X86_REG_R14D;
        case ARGUMENT_R15D:
            return X86_REG_R15D;

        case ARGUMENT_AX:
            return X86_REG_AX;
        case ARGUMENT_BX:
            return X86_REG_BX;
        case ARGUMENT_CX:
            return X86_REG_CX;
        case ARGUMENT_DX:
            return X86_REG_DX;
        case ARGUMENT_SP:
            return X86_REG_SP;
        case ARGUMENT_BP:
            return X86_REG_BP;
        case ARGUMENT_DI:
            return X86_REG_DI;
        case ARGUMENT_SI:
            return X86_REG_SI;
        case ARGUMENT_R8W:
            return X86_REG_R8W;
        case ARGUMENT_R9W:
            return X86_REG_R9W;
        case ARGUMENT_R10W:
            return X86_REG_R10W;
        case ARGUMENT_R11W:
            return X86_REG_R11W;
        case ARGUMENT_R12W:
            return X86_REG_R12W;
        case ARGUMENT_R13W:
            return X86_REG_R13W;
        case ARGUMENT_R14W:
            return X86_REG_R14W;
        case ARGUMENT_R15W:
            return X86_REG_R15W;
 
        case ARGUMENT_AL:
            return X86_REG_AL;
        case ARGUMENT_AH:
            return X86_REG_AH;
        case ARGUMENT_BL:
            return X86_REG_BL;
        case ARGUMENT_BH:
            return X86_REG_BH;
        case ARGUMENT_CL:
            return X86_REG_CL;
        case ARGUMENT_CH:
            return X86_REG_CH;
        case ARGUMENT_DL:
            return X86_REG_DL;
        case ARGUMENT_DH:
            return X86_REG_DH;
        case ARGUMENT_SPL:
            return X86_REG_SPL;
        case ARGUMENT_BPL:
            return X86_REG_BPL;
        case ARGUMENT_DIL:
            return X86_REG_DIL;
        case ARGUMENT_SIL:
            return X86_REG_SIL;
        case ARGUMENT_R8B:
            return X86_REG_R8B;
        case ARGUMENT_R9B:
            return X86_REG_R9B;
        case ARGUMENT_R10B:
            return X86_REG_R10B;
        case ARGUMENT_R11B:
            return X86_REG_R11B;
        case ARGUMENT_R12B:
            return X86_REG_R12B;
        case ARGUMENT_R13B:
            return X86_REG_R13B;
        case ARGUMENT_R14B:
            return X86_REG_R14B;
        case ARGUMENT_R15B:
            return X86_REG_R15B;

        case ARGUMENT_RFLAGS:
            return X86_REG_EFLAGS;
        default:
            return X86_REG_INVALID;
    }
}

/*
 * Convert a register number into a register.
 */
static x86_reg getReg(int regno)
{
    switch (regno)
    {
        case RDI_IDX:
            return X86_REG_RDI;
        case RSI_IDX:
            return X86_REG_RSI;
        case RDX_IDX:
            return X86_REG_RDX;
        case RCX_IDX:
            return X86_REG_RCX;
        case R8_IDX:
            return X86_REG_R8;
        case R9_IDX:
            return X86_REG_R9;
        case RFLAGS_IDX:
            return X86_REG_EFLAGS;
        case RAX_IDX:
            return X86_REG_RAX;
        case R10_IDX:
            return X86_REG_R10;
        case R11_IDX:
            return X86_REG_R11;
        case RBX_IDX: 
            return X86_REG_RBX;
        case RBP_IDX:
            return X86_REG_RBP;
        case R12_IDX:
            return X86_REG_R12;
        case R13_IDX:
            return X86_REG_R13;
        case R14_IDX:
            return X86_REG_R14;
        case R15_IDX:
            return X86_REG_R15;
        case RSP_IDX:
            return X86_REG_RSP;
        default:
            return X86_REG_INVALID;
    }
}

/*
 * Convert a register into a register index.
 */
static int getRegIdx(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_DI: case X86_REG_DIL: case X86_REG_EDI: case X86_REG_RDI:
            return RDI_IDX;
        case X86_REG_SI: case X86_REG_SIL: case X86_REG_ESI: case X86_REG_RSI:
            return RSI_IDX;
        case X86_REG_DH: case X86_REG_DL:
        case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX:
            return RDX_IDX;
        case X86_REG_CH: case X86_REG_CL:
        case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX:
            return RCX_IDX;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8:
            return R8_IDX;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9:
            return R9_IDX;
        case X86_REG_AH: case X86_REG_AL:
        case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX:
            return RAX_IDX;
        case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
        case X86_REG_R10:
            return R10_IDX;
        case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
        case X86_REG_R11:
            return R11_IDX;
        case X86_REG_BH: case X86_REG_BL:
        case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX:
            return RBX_IDX;
        case X86_REG_BP: case X86_REG_BPL: case X86_REG_EBP: case X86_REG_RBP:
            return RBP_IDX;
        case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
        case X86_REG_R12:
            return R12_IDX;
        case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
        case X86_REG_R13:
            return R13_IDX;
        case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
        case X86_REG_R14:
            return R14_IDX;
        case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
        case X86_REG_R15:
            return R15_IDX;
        case X86_REG_SP: case X86_REG_SPL: case X86_REG_ESP: case X86_REG_RSP:
            return RSP_IDX;
        default:
            return -1;
    }
}

/*
 * Convert a register into a canonical register.
 */
static x86_reg getCanonicalReg(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_DI: case X86_REG_DIL: case X86_REG_EDI: case X86_REG_RDI:
            return X86_REG_RDI;
        case X86_REG_SI: case X86_REG_SIL: case X86_REG_ESI: case X86_REG_RSI:
            return X86_REG_RSI;
        case X86_REG_DH: case X86_REG_DL:
        case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX:
            return X86_REG_RDX;
        case X86_REG_CH: case X86_REG_CL:
        case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX:
            return X86_REG_RCX;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8:
            return X86_REG_R8;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9:
            return X86_REG_R9;
        case X86_REG_AH: case X86_REG_AL:
        case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX:
            return X86_REG_RAX;
        case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
        case X86_REG_R10:
            return X86_REG_R10;
        case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
        case X86_REG_R11:
            return X86_REG_R11;
        case X86_REG_BH: case X86_REG_BL:
        case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX:
            return X86_REG_RBX;
        case X86_REG_BP: case X86_REG_BPL: case X86_REG_EBP: case X86_REG_RBP:
            return X86_REG_RBP;
        case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
        case X86_REG_R12:
            return X86_REG_R12;
        case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
        case X86_REG_R13:
            return X86_REG_R13;
        case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
        case X86_REG_R14:
            return X86_REG_R14;
        case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
        case X86_REG_R15:
            return X86_REG_R15;
        case X86_REG_SP: case X86_REG_SPL: case X86_REG_ESP: case X86_REG_RSP:
            return X86_REG_RSP;
        case X86_REG_IP: case X86_REG_EIP: case X86_REG_RIP:
            return X86_REG_RIP;
        default:
            return reg;
    }
}

/*
 * Get the storage size of a register.
 */
static int32_t getRegSize(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH: case X86_REG_AL: case X86_REG_BH:
        case X86_REG_BL: case X86_REG_CH: case X86_REG_CL:
        case X86_REG_BPL: case X86_REG_DIL: case X86_REG_DL:
        case X86_REG_DH: case X86_REG_SIL: case X86_REG_SPL:
        case X86_REG_R8B: case X86_REG_R9B: case X86_REG_R10B:
        case X86_REG_R11B: case X86_REG_R12B: case X86_REG_R13B:
        case X86_REG_R14B: case X86_REG_R15B:
            return sizeof(int8_t);
        
        case X86_REG_EFLAGS: case X86_REG_AX: case X86_REG_BP:
        case X86_REG_BX: case X86_REG_CX: case X86_REG_DX:
        case X86_REG_DI: case X86_REG_IP: case X86_REG_SI:
        case X86_REG_SP: case X86_REG_R8W: case X86_REG_R9W:
        case X86_REG_R10W: case X86_REG_R11W: case X86_REG_R12W:
        case X86_REG_R13W: case X86_REG_R14W: case X86_REG_R15W:
            return sizeof(int16_t);
        
        case X86_REG_EAX: case X86_REG_EBP: case X86_REG_EBX:
        case X86_REG_ECX: case X86_REG_EDI: case X86_REG_EDX:
        case X86_REG_EIP: case X86_REG_EIZ: case X86_REG_ESI:
        case X86_REG_ESP: case X86_REG_R8D: case X86_REG_R9D:
        case X86_REG_R10D: case X86_REG_R11D: case X86_REG_R12D:
        case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
            return sizeof(int32_t);
 
        case X86_REG_RAX: case X86_REG_RBP: case X86_REG_RBX:
        case X86_REG_RCX: case X86_REG_RDI: case X86_REG_RDX:
        case X86_REG_RIP: case X86_REG_RIZ: case X86_REG_RSI:
        case X86_REG_RSP: case X86_REG_R8: case X86_REG_R9:
        case X86_REG_R10: case X86_REG_R11: case X86_REG_R12:
        case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
            return sizeof(int64_t);
        
        case X86_REG_XMM0: case X86_REG_XMM1: case X86_REG_XMM2:
        case X86_REG_XMM3: case X86_REG_XMM4: case X86_REG_XMM5:
        case X86_REG_XMM6: case X86_REG_XMM7: case X86_REG_XMM8:
        case X86_REG_XMM9: case X86_REG_XMM10: case X86_REG_XMM11:
        case X86_REG_XMM12: case X86_REG_XMM13: case X86_REG_XMM14:
        case X86_REG_XMM15: case X86_REG_XMM16: case X86_REG_XMM17:
        case X86_REG_XMM18: case X86_REG_XMM19: case X86_REG_XMM20:
        case X86_REG_XMM21: case X86_REG_XMM22: case X86_REG_XMM23:
        case X86_REG_XMM24: case X86_REG_XMM25: case X86_REG_XMM26:
        case X86_REG_XMM27: case X86_REG_XMM28: case X86_REG_XMM29:
        case X86_REG_XMM30: case X86_REG_XMM31:
            return 2 * sizeof(int64_t);
        
        case X86_REG_YMM0: case X86_REG_YMM1: case X86_REG_YMM2:
        case X86_REG_YMM3: case X86_REG_YMM4: case X86_REG_YMM5:
        case X86_REG_YMM6: case X86_REG_YMM7: case X86_REG_YMM8:
        case X86_REG_YMM9: case X86_REG_YMM10: case X86_REG_YMM11:
        case X86_REG_YMM12: case X86_REG_YMM13: case X86_REG_YMM14:
        case X86_REG_YMM15: case X86_REG_YMM16: case X86_REG_YMM17:
        case X86_REG_YMM18: case X86_REG_YMM19: case X86_REG_YMM20:
        case X86_REG_YMM21: case X86_REG_YMM22: case X86_REG_YMM23:
        case X86_REG_YMM24: case X86_REG_YMM25: case X86_REG_YMM26:
        case X86_REG_YMM27: case X86_REG_YMM28: case X86_REG_YMM29:
        case X86_REG_YMM30: case X86_REG_YMM31:
            // return 4 * sizeof(int64_t);
            return 0;
        
        case X86_REG_ZMM0: case X86_REG_ZMM1: case X86_REG_ZMM2:
        case X86_REG_ZMM3: case X86_REG_ZMM4: case X86_REG_ZMM5:
        case X86_REG_ZMM6: case X86_REG_ZMM7: case X86_REG_ZMM8:
        case X86_REG_ZMM9: case X86_REG_ZMM10: case X86_REG_ZMM11:
        case X86_REG_ZMM12: case X86_REG_ZMM13: case X86_REG_ZMM14:
        case X86_REG_ZMM15: case X86_REG_ZMM16: case X86_REG_ZMM17:
        case X86_REG_ZMM18: case X86_REG_ZMM19: case X86_REG_ZMM20:
        case X86_REG_ZMM21: case X86_REG_ZMM22: case X86_REG_ZMM23:
        case X86_REG_ZMM24: case X86_REG_ZMM25: case X86_REG_ZMM26:
        case X86_REG_ZMM27: case X86_REG_ZMM28: case X86_REG_ZMM29:
        case X86_REG_ZMM30: case X86_REG_ZMM31:
            // return 8 * sizeof(int64_t);
            return 0;
        
        case X86_REG_ES: case X86_REG_CS: case X86_REG_DS:
        case X86_REG_FPSW: case X86_REG_FS: case X86_REG_GS:
        case X86_REG_SS: case X86_REG_CR0: case X86_REG_CR1:
        case X86_REG_CR2: case X86_REG_CR3: case X86_REG_CR4:
        case X86_REG_CR5: case X86_REG_CR6: case X86_REG_CR7:
        case X86_REG_CR8: case X86_REG_CR9: case X86_REG_CR10:
        case X86_REG_CR11: case X86_REG_CR12: case X86_REG_CR13:
        case X86_REG_CR14: case X86_REG_CR15: case X86_REG_DR0:
        case X86_REG_DR1: case X86_REG_DR2: case X86_REG_DR3:
        case X86_REG_DR4: case X86_REG_DR5: case X86_REG_DR6:
        case X86_REG_DR7: case X86_REG_DR8: case X86_REG_DR9:
        case X86_REG_DR10: case X86_REG_DR11: case X86_REG_DR12:
        case X86_REG_DR13: case X86_REG_DR14: case X86_REG_DR15:
        case X86_REG_FP0: case X86_REG_FP1: case X86_REG_FP2:
        case X86_REG_FP3: case X86_REG_FP4: case X86_REG_FP5:
        case X86_REG_FP6: case X86_REG_FP7: case X86_REG_K0:
        case X86_REG_K1: case X86_REG_K2: case X86_REG_K3:
        case X86_REG_K4: case X86_REG_K5: case X86_REG_K6:
        case X86_REG_K7: case X86_REG_MM0: case X86_REG_MM1:
        case X86_REG_MM2: case X86_REG_MM3: case X86_REG_MM4:
        case X86_REG_MM5: case X86_REG_MM6: case X86_REG_MM7:
        case X86_REG_ST0: case X86_REG_ST1: case X86_REG_ST2:
        case X86_REG_ST3: case X86_REG_ST4: case X86_REG_ST5:
        case X86_REG_ST6: case X86_REG_ST7:
            return 0;

        case X86_REG_INVALID: case X86_REG_ENDING:
        default:
            return 0;
    }
}

/*
 * Get the type of a register.
 */
static Type getRegType(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH: case X86_REG_AL: case X86_REG_BH:
        case X86_REG_BL: case X86_REG_CH: case X86_REG_CL:
        case X86_REG_BPL: case X86_REG_DIL: case X86_REG_DL:
        case X86_REG_DH: case X86_REG_SIL: case X86_REG_SPL:
        case X86_REG_R8B: case X86_REG_R9B: case X86_REG_R10B:
        case X86_REG_R11B: case X86_REG_R12B: case X86_REG_R13B:
        case X86_REG_R14B: case X86_REG_R15B:
            return TYPE_INT8;
 
        case X86_REG_EFLAGS: case X86_REG_AX: case X86_REG_BP:
        case X86_REG_BX: case X86_REG_CX: case X86_REG_DX:
        case X86_REG_DI: case X86_REG_IP: case X86_REG_SI:
        case X86_REG_SP: case X86_REG_R8W: case X86_REG_R9W:
        case X86_REG_R10W: case X86_REG_R11W: case X86_REG_R12W:
        case X86_REG_R13W: case X86_REG_R14W: case X86_REG_R15W:
            return TYPE_INT16;
 
        case X86_REG_EAX: case X86_REG_EBP: case X86_REG_EBX:
        case X86_REG_ECX: case X86_REG_EDI: case X86_REG_EDX:
        case X86_REG_EIP: case X86_REG_EIZ: case X86_REG_ESI:
        case X86_REG_ESP: case X86_REG_R8D: case X86_REG_R9D:
        case X86_REG_R10D: case X86_REG_R11D: case X86_REG_R12D:
        case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
            return TYPE_INT32;
 
        case X86_REG_RAX: case X86_REG_RBP: case X86_REG_RBX:
        case X86_REG_RCX: case X86_REG_RDI: case X86_REG_RDX:
        case X86_REG_RIP: case X86_REG_RIZ: case X86_REG_RSI:
        case X86_REG_RSP: case X86_REG_R8: case X86_REG_R9:
        case X86_REG_R10: case X86_REG_R11: case X86_REG_R12:
        case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
            return TYPE_INT64;
 
        case X86_REG_XMM0: case X86_REG_XMM1: case X86_REG_XMM2:
        case X86_REG_XMM3: case X86_REG_XMM4: case X86_REG_XMM5:
        case X86_REG_XMM6: case X86_REG_XMM7: case X86_REG_XMM8:
        case X86_REG_XMM9: case X86_REG_XMM10: case X86_REG_XMM11:
        case X86_REG_XMM12: case X86_REG_XMM13: case X86_REG_XMM14:
        case X86_REG_XMM15: case X86_REG_XMM16: case X86_REG_XMM17:
        case X86_REG_XMM18: case X86_REG_XMM19: case X86_REG_XMM20:
        case X86_REG_XMM21: case X86_REG_XMM22: case X86_REG_XMM23:
        case X86_REG_XMM24: case X86_REG_XMM25: case X86_REG_XMM26:
        case X86_REG_XMM27: case X86_REG_XMM28: case X86_REG_XMM29:
        case X86_REG_XMM30: case X86_REG_XMM31:
            return TYPE_NULL_PTR;
 
        case X86_REG_YMM0: case X86_REG_YMM1: case X86_REG_YMM2:
        case X86_REG_YMM3: case X86_REG_YMM4: case X86_REG_YMM5:
        case X86_REG_YMM6: case X86_REG_YMM7: case X86_REG_YMM8:
        case X86_REG_YMM9: case X86_REG_YMM10: case X86_REG_YMM11:
        case X86_REG_YMM12: case X86_REG_YMM13: case X86_REG_YMM14:
        case X86_REG_YMM15: case X86_REG_YMM16: case X86_REG_YMM17:
        case X86_REG_YMM18: case X86_REG_YMM19: case X86_REG_YMM20:
        case X86_REG_YMM21: case X86_REG_YMM22: case X86_REG_YMM23:
        case X86_REG_YMM24: case X86_REG_YMM25: case X86_REG_YMM26:
        case X86_REG_YMM27: case X86_REG_YMM28: case X86_REG_YMM29:
        case X86_REG_YMM30: case X86_REG_YMM31:
            return TYPE_NULL_PTR;
 
        case X86_REG_ZMM0: case X86_REG_ZMM1: case X86_REG_ZMM2:
        case X86_REG_ZMM3: case X86_REG_ZMM4: case X86_REG_ZMM5:
        case X86_REG_ZMM6: case X86_REG_ZMM7: case X86_REG_ZMM8:
        case X86_REG_ZMM9: case X86_REG_ZMM10: case X86_REG_ZMM11:
        case X86_REG_ZMM12: case X86_REG_ZMM13: case X86_REG_ZMM14:
        case X86_REG_ZMM15: case X86_REG_ZMM16: case X86_REG_ZMM17:
        case X86_REG_ZMM18: case X86_REG_ZMM19: case X86_REG_ZMM20:
        case X86_REG_ZMM21: case X86_REG_ZMM22: case X86_REG_ZMM23:
        case X86_REG_ZMM24: case X86_REG_ZMM25: case X86_REG_ZMM26:
        case X86_REG_ZMM27: case X86_REG_ZMM28: case X86_REG_ZMM29:
        case X86_REG_ZMM30: case X86_REG_ZMM31:
            return TYPE_NULL_PTR;
 
        case X86_REG_ES: case X86_REG_CS: case X86_REG_DS:
        case X86_REG_FPSW: case X86_REG_FS: case X86_REG_GS:
        case X86_REG_SS: case X86_REG_CR0: case X86_REG_CR1:
        case X86_REG_CR2: case X86_REG_CR3: case X86_REG_CR4:
        case X86_REG_CR5: case X86_REG_CR6: case X86_REG_CR7:
        case X86_REG_CR8: case X86_REG_CR9: case X86_REG_CR10:
        case X86_REG_CR11: case X86_REG_CR12: case X86_REG_CR13:
        case X86_REG_CR14: case X86_REG_CR15: case X86_REG_DR0:
        case X86_REG_DR1: case X86_REG_DR2: case X86_REG_DR3:
        case X86_REG_DR4: case X86_REG_DR5: case X86_REG_DR6:
        case X86_REG_DR7: case X86_REG_DR8: case X86_REG_DR9:
        case X86_REG_DR10: case X86_REG_DR11: case X86_REG_DR12:
        case X86_REG_DR13: case X86_REG_DR14: case X86_REG_DR15:
        case X86_REG_FP0: case X86_REG_FP1: case X86_REG_FP2:
        case X86_REG_FP3: case X86_REG_FP4: case X86_REG_FP5:
        case X86_REG_FP6: case X86_REG_FP7: case X86_REG_K0:
        case X86_REG_K1: case X86_REG_K2: case X86_REG_K3:
        case X86_REG_K4: case X86_REG_K5: case X86_REG_K6:
        case X86_REG_K7: case X86_REG_MM0: case X86_REG_MM1:
        case X86_REG_MM2: case X86_REG_MM3: case X86_REG_MM4:
        case X86_REG_MM5: case X86_REG_MM6: case X86_REG_MM7:
        case X86_REG_ST0: case X86_REG_ST1: case X86_REG_ST2:
        case X86_REG_ST3: case X86_REG_ST4: case X86_REG_ST5:
        case X86_REG_ST6: case X86_REG_ST7:
            return TYPE_NULL_PTR;

        case X86_REG_INVALID: case X86_REG_ENDING:
        default:
            return TYPE_NULL_PTR;
    }
}

/*
 * Return `true' for high-byte registers.
 */
static bool getRegHigh(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH: case X86_REG_BH: case X86_REG_CH: case X86_REG_DH:
            return true;
        default:
            return false;
    }
}

/*
 * Get a register name.
 */
static const char *getRegName(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH:      return "%ah";
        case X86_REG_AL:      return "%al";
        case X86_REG_BH:      return "%bh";
        case X86_REG_BL:      return "%bl";
        case X86_REG_CH:      return "%ch";
        case X86_REG_CL:      return "%cl";
        case X86_REG_BPL:     return "%bpl";
        case X86_REG_DIL:     return "%dil";
        case X86_REG_DL:      return "%dl";
        case X86_REG_DH:      return "%dh";
        case X86_REG_SIL:     return "%sil";
        case X86_REG_SPL:     return "%spl";
        case X86_REG_R8B:     return "%r8b";
        case X86_REG_R9B:     return "%r9b";
        case X86_REG_R10B:    return "%r10b";
        case X86_REG_R11B:    return "%r11b";
        case X86_REG_R12B:    return "%r12b";
        case X86_REG_R13B:    return "%r13b";
        case X86_REG_R14B:    return "%r14b";
        case X86_REG_R15B:    return "%r15b";
        case X86_REG_EFLAGS:  return "%rflags";
        case X86_REG_AX:      return "%ax";
        case X86_REG_BP:      return "%bp";
        case X86_REG_BX:      return "%bx";
        case X86_REG_CX:      return "%cx";
        case X86_REG_DX:      return "%dx";
        case X86_REG_DI:      return "%di";
        case X86_REG_IP:      return "%ip";
        case X86_REG_SI:      return "%si";
        case X86_REG_SP:      return "%sp";
        case X86_REG_R8W:     return "%r8w";
        case X86_REG_R9W:     return "%r9w";
        case X86_REG_R10W:    return "%r10w";
        case X86_REG_R11W:    return "%r11w";
        case X86_REG_R12W:    return "%r12w";
        case X86_REG_R13W:    return "%r13w";
        case X86_REG_R14W:    return "%r14w";
        case X86_REG_R15W:    return "%r15w";
        case X86_REG_EAX:     return "%eax";
        case X86_REG_EBP:     return "%ebp";
        case X86_REG_EBX:     return "%ebx";
        case X86_REG_ECX:     return "%ecx";
        case X86_REG_EDI:     return "%edi";
        case X86_REG_EDX:     return "%edx";
        case X86_REG_EIP:     return "%eip";
        case X86_REG_EIZ:     return "%eiz";
        case X86_REG_ESI:     return "%esi";
        case X86_REG_ESP:     return "%esp";
        case X86_REG_R8D:     return "%r8d";
        case X86_REG_R9D:     return "%r9d";
        case X86_REG_R10D:    return "%r10d";
        case X86_REG_R11D:    return "%r11d";
        case X86_REG_R12D:    return "%r12d";
        case X86_REG_R13D:    return "%r13d";
        case X86_REG_R14D:    return "%r14d";
        case X86_REG_R15D:    return "%r15d";
        case X86_REG_RAX:     return "%rax";
        case X86_REG_RBP:     return "%rbp";
        case X86_REG_RBX:     return "%rbx";
        case X86_REG_RCX:     return "%rcx";
        case X86_REG_RDI:     return "%rdi";
        case X86_REG_RDX:     return "%rdx";
        case X86_REG_RIP:     return "%rip";
        case X86_REG_RIZ:     return "%riz";
        case X86_REG_RSI:     return "%rsi";
        case X86_REG_RSP:     return "%rsp";
        case X86_REG_R8:      return "%r8";
        case X86_REG_R9:      return "%r9";
        case X86_REG_R10:     return "%r10";
        case X86_REG_R11:     return "%r11";
        case X86_REG_R12:     return "%r12";
        case X86_REG_R13:     return "%r13";
        case X86_REG_R14:     return "%r14";
        case X86_REG_R15:     return "%r15";
        case X86_REG_XMM0:    return "%xmm0";
        case X86_REG_XMM1:    return "%xmm1";
        case X86_REG_XMM2:    return "%xmm2";
        case X86_REG_XMM3:    return "%xmm3";
        case X86_REG_XMM4:    return "%xmm4";
        case X86_REG_XMM5:    return "%xmm5";
        case X86_REG_XMM6:    return "%xmm6";
        case X86_REG_XMM7:    return "%xmm7";
        case X86_REG_XMM8:    return "%xmm8";
        case X86_REG_XMM9:    return "%xmm9";
        case X86_REG_XMM10:   return "%xmm10";
        case X86_REG_XMM11:   return "%xmm11";
        case X86_REG_XMM12:   return "%xmm12";
        case X86_REG_XMM13:   return "%xmm13";
        case X86_REG_XMM14:   return "%xmm14";
        case X86_REG_XMM15:   return "%xmm15";
        case X86_REG_XMM16:   return "%xmm16";
        case X86_REG_XMM17:   return "%xmm17";
        case X86_REG_XMM18:   return "%xmm18";
        case X86_REG_XMM19:   return "%xmm19";
        case X86_REG_XMM20:   return "%xmm20";
        case X86_REG_XMM21:   return "%xmm21";
        case X86_REG_XMM22:   return "%xmm22";
        case X86_REG_XMM23:   return "%xmm23";
        case X86_REG_XMM24:   return "%xmm24";
        case X86_REG_XMM25:   return "%xmm25";
        case X86_REG_XMM26:   return "%xmm26";
        case X86_REG_XMM27:   return "%xmm27";
        case X86_REG_XMM28:   return "%xmm28";
        case X86_REG_XMM29:   return "%xmm29";
        case X86_REG_XMM30:   return "%xmm30";
        case X86_REG_XMM31:   return "%xmm31";
        case X86_REG_YMM0:    return "%ymm0";
        case X86_REG_YMM1:    return "%ymm1";
        case X86_REG_YMM2:    return "%ymm2";
        case X86_REG_YMM3:    return "%ymm3";
        case X86_REG_YMM4:    return "%ymm4";
        case X86_REG_YMM5:    return "%ymm5";
        case X86_REG_YMM6:    return "%ymm6";
        case X86_REG_YMM7:    return "%ymm7";
        case X86_REG_YMM8:    return "%ymm8";
        case X86_REG_YMM9:    return "%ymm9";
        case X86_REG_YMM10:   return "%ymm10";
        case X86_REG_YMM11:   return "%ymm11";
        case X86_REG_YMM12:   return "%ymm12";
        case X86_REG_YMM13:   return "%ymm13";
        case X86_REG_YMM14:   return "%ymm14";
        case X86_REG_YMM15:   return "%ymm15";
        case X86_REG_YMM16:   return "%ymm16";
        case X86_REG_YMM17:   return "%ymm17";
        case X86_REG_YMM18:   return "%ymm18";
        case X86_REG_YMM19:   return "%ymm19";
        case X86_REG_YMM20:   return "%ymm20";
        case X86_REG_YMM21:   return "%ymm21";
        case X86_REG_YMM22:   return "%ymm22";
        case X86_REG_YMM23:   return "%ymm23";
        case X86_REG_YMM24:   return "%ymm24";
        case X86_REG_YMM25:   return "%ymm25";
        case X86_REG_YMM26:   return "%ymm26";
        case X86_REG_YMM27:   return "%ymm27";
        case X86_REG_YMM28:   return "%ymm28";
        case X86_REG_YMM29:   return "%ymm29";
        case X86_REG_YMM30:   return "%ymm30";
        case X86_REG_YMM31:   return "%ymm31";
        case X86_REG_ZMM0:    return "%zmm0";
        case X86_REG_ZMM1:    return "%zmm1";
        case X86_REG_ZMM2:    return "%zmm2";
        case X86_REG_ZMM3:    return "%zmm3";
        case X86_REG_ZMM4:    return "%zmm4";
        case X86_REG_ZMM5:    return "%zmm5";
        case X86_REG_ZMM6:    return "%zmm6";
        case X86_REG_ZMM7:    return "%zmm7";
        case X86_REG_ZMM8:    return "%zmm8";
        case X86_REG_ZMM9:    return "%zmm9";
        case X86_REG_ZMM10:   return "%zmm10";
        case X86_REG_ZMM11:   return "%zmm11";
        case X86_REG_ZMM12:   return "%zmm12";
        case X86_REG_ZMM13:   return "%zmm13";
        case X86_REG_ZMM14:   return "%zmm14";
        case X86_REG_ZMM15:   return "%zmm15";
        case X86_REG_ZMM16:   return "%zmm16";
        case X86_REG_ZMM17:   return "%zmm17";
        case X86_REG_ZMM18:   return "%zmm18";
        case X86_REG_ZMM19:   return "%zmm19";
        case X86_REG_ZMM20:   return "%zmm20";
        case X86_REG_ZMM21:   return "%zmm21";
        case X86_REG_ZMM22:   return "%zmm22";
        case X86_REG_ZMM23:   return "%zmm23";
        case X86_REG_ZMM24:   return "%zmm24";
        case X86_REG_ZMM25:   return "%zmm25";
        case X86_REG_ZMM26:   return "%zmm26";
        case X86_REG_ZMM27:   return "%zmm27";
        case X86_REG_ZMM28:   return "%zmm28";
        case X86_REG_ZMM29:   return "%zmm29";
        case X86_REG_ZMM30:   return "%zmm30";
        case X86_REG_ZMM31:   return "%zmm31";
        case X86_REG_ES:      return "%es";
        case X86_REG_CS:      return "%cs";
        case X86_REG_DS:      return "%ds";
        case X86_REG_FPSW:    return "%fpsw";
        case X86_REG_FS:      return "%fs";
        case X86_REG_GS:      return "%gs";
        case X86_REG_SS:      return "%ss";
        case X86_REG_CR0:     return "%cr0";
        case X86_REG_CR1:     return "%cr1";
        case X86_REG_CR2:     return "%cr2";
        case X86_REG_CR3:     return "%cr3";
        case X86_REG_CR4:     return "%cr4";
        case X86_REG_CR5:     return "%cr5";
        case X86_REG_CR6:     return "%cr6";
        case X86_REG_CR7:     return "%cr7";
        case X86_REG_CR8:     return "%cr8";
        case X86_REG_CR9:     return "%cr9";
        case X86_REG_CR10:    return "%cr10";
        case X86_REG_CR11:    return "%cr11";
        case X86_REG_CR12:    return "%cr12";
        case X86_REG_CR13:    return "%cr13";
        case X86_REG_CR14:    return "%cr14";
        case X86_REG_CR15:    return "%cr15";
        case X86_REG_DR0:     return "%dr0";
        case X86_REG_DR1:     return "%dr1";
        case X86_REG_DR2:     return "%dr2";
        case X86_REG_DR3:     return "%dr3";
        case X86_REG_DR4:     return "%dr4";
        case X86_REG_DR5:     return "%dr5";
        case X86_REG_DR6:     return "%dr6";
        case X86_REG_DR7:     return "%dr7";
        case X86_REG_DR8:     return "%dr8";
        case X86_REG_DR9:     return "%dr9";
        case X86_REG_DR10:    return "%dr10";
        case X86_REG_DR11:    return "%dr11";
        case X86_REG_DR12:    return "%dr12";
        case X86_REG_DR13:    return "%dr13";
        case X86_REG_DR14:    return "%dr14";
        case X86_REG_DR15:    return "%dr15";
        case X86_REG_FP0:     return "%fp0";
        case X86_REG_FP1:     return "%fp1";
        case X86_REG_FP2:     return "%fp2";
        case X86_REG_FP3:     return "%fp3";
        case X86_REG_FP4:     return "%fp4";
        case X86_REG_FP5:     return "%fp5";
        case X86_REG_FP6:     return "%fp6";
        case X86_REG_FP7:     return "%fp7";
        case X86_REG_K0:      return "%k0";
        case X86_REG_K1:      return "%k1";
        case X86_REG_K2:      return "%k2";
        case X86_REG_K3:      return "%k3";
        case X86_REG_K4:      return "%k4";
        case X86_REG_K5:      return "%k5";
        case X86_REG_K6:      return "%k6";
        case X86_REG_K7:      return "%k7";
        case X86_REG_MM0:     return "%mm0";
        case X86_REG_MM1:     return "%mm1";
        case X86_REG_MM2:     return "%mm2";
        case X86_REG_MM3:     return "%mm3";
        case X86_REG_MM4:     return "%mm4";
        case X86_REG_MM5:     return "%mm5";
        case X86_REG_MM6:     return "%mm6";
        case X86_REG_MM7:     return "%mm7";
        case X86_REG_ST0:     return "%st0";
        case X86_REG_ST1:     return "%st1";
        case X86_REG_ST2:     return "%st2";
        case X86_REG_ST3:     return "%st3";
        case X86_REG_ST4:     return "%st4";
        case X86_REG_ST5:     return "%st5";
        case X86_REG_ST6:     return "%st6";
        case X86_REG_ST7:     return "%st7";
        case X86_REG_INVALID: return "???";
        case X86_REG_ENDING:  return "???";
        default:              return "???";
    }
}

/*
 * Special stack slots.
 */
#define RSP_SLOT    0x4000
#define RIP_SLOT    (0x4000 - sizeof(int64_t))

/*
 * Get all callee-save registers.
 */
static const int *getCallerSaveRegs(bool clean, bool conditional,
    size_t num_args)
{
    static const int clean_save[] =
    {
        RCX_IDX, RAX_IDX, RFLAGS_IDX, R11_IDX, R10_IDX, R9_IDX, R8_IDX,
        RDX_IDX, RSI_IDX, RDI_IDX, -1
    };
    static const int naked_save[] =
    {
        R11_IDX, R10_IDX, R9_IDX, R8_IDX, RCX_IDX, RDX_IDX, RSI_IDX, RDI_IDX,
        -1
    };
    if (clean)
        return clean_save;
    else if (!conditional)
        return naked_save + (8 - num_args);
    else
    {
        // If conditional, %rax must be the first register:
        static const int conditional_save[][10] =
        {
            {RAX_IDX, -1},
            {RAX_IDX, RDI_IDX, -1},
            {RAX_IDX, RSI_IDX, RDI_IDX, -1},
            {RAX_IDX, RDX_IDX, RSI_IDX, RDI_IDX, -1},
            {RAX_IDX, RCX_IDX, RDX_IDX, RSI_IDX, RDI_IDX, -1},
            {RAX_IDX, R8_IDX, RCX_IDX, RDX_IDX, RSI_IDX, RDI_IDX, -1},
            {RAX_IDX, R9_IDX, R8_IDX, RCX_IDX, RDX_IDX, RSI_IDX, RDI_IDX, -1},
            {RAX_IDX, R10_IDX, R9_IDX, R8_IDX, RCX_IDX, RDX_IDX, RSI_IDX,
                RDI_IDX, -1},
            {RAX_IDX, R11_IDX, R10_IDX, R9_IDX, R8_IDX, RCX_IDX, RDX_IDX,
                RSI_IDX, RDI_IDX, -1},
        };
        return conditional_save[num_args];
    }
}

/*
 * Call state helper class.
 */
struct CallInfo
{
    /*
     * Stored register information.
     */
    struct RegInfo
    {
        const int32_t offset;                   // Register stack offset.
        const int32_t size;                     // Register storage size.
        const int push;                         // Push index.
        uint32_t saved:1;                       // Register saved?
        uint32_t clobbered:1;                   // Register clobbered?
        uint32_t used:1;                        // Register in use?
        uint32_t caller_save:1;                 // Register caller save?

        RegInfo(int32_t offset, int32_t size, int push) :
            offset(offset), size(size), push(push), saved(0), clobbered(0),
                used(0), caller_save(0)
        {
            ;
        }
    };

    const int * const rsave;                    // Caller save regsters.
    const bool before;                          // Before or after inst.
    int32_t rsp_offset = 0x4000;                // Stack offset
    std::map<x86_reg, RegInfo> info;            // Register info
    std::vector<x86_reg> pushed;                // Pushed registers

    /*
     * Get register info.
     */
    RegInfo *getInfo(x86_reg reg)
    {
        auto i = info.find(getCanonicalReg(reg));
        if (i == info.end())
            return nullptr;
        return &i->second;
    }

    /*
     * Get register info.
     */
    const RegInfo *getInfo(x86_reg reg) const
    {
        auto i = info.find(getCanonicalReg(reg));
        if (i == info.end())
            return nullptr;
        return &i->second;
    }

    /*
     * Get register offset relative to the current %rsp value.
     */
    int32_t getOffset(x86_reg reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        return rsp_offset - rinfo->offset;
    }

    /*
     * Get register saved.
     */
    bool getSaved(x86_reg reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->saved != 0);
    }

    /*
     * Get register clobbered.
     */
    bool getClobbered(x86_reg reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->clobbered != 0);
    }

    /*
     * Get register used.
     */
    bool getUsed(x86_reg reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? true: rinfo->used != 0);
    }

    /*
     * Set register saved.
     */
    void setSaved(x86_reg reg, bool saved)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->saved = saved;
    }

    /*
     * Set register clobbered.
     */
    void setClobbered(x86_reg reg, bool clobbered)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->clobbered = clobbered;
    }

    /*
     * Set register used.
     */
    void setUsed(x86_reg reg, bool used)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->used = used;
    }

    /*
     * Save a register.
     */
    void save(x86_reg reg)
    {
        setSaved(reg, true);
    }

    /*
     * Check if a register is saved.
     */
    bool isSaved(x86_reg reg) const
    {
        return getSaved(reg);
    }

    /*
     * Clobber a register.
     */
    void clobber(x86_reg reg)
    {
        setClobbered(reg, true);
    }

    /*
     * Undo a register clobber.
     */
    void restore(x86_reg reg)
    {
        setClobbered(reg, false);
    }

    /*
     * Check if a register is clobbered.
     */
    bool isClobbered(x86_reg reg) const
    {
        return getClobbered(reg);
    }

    /*
     * Restore a register.
     */
    void use(x86_reg reg)
    {
        assert(reg != X86_REG_RAX && reg != X86_REG_EFLAGS);
        setUsed(reg, true);
    }

    /*
     * Check if a register is used.
     */
    bool isUsed(x86_reg reg) const
    {
        return getUsed(reg);
    }

    /*
     * Get a suitable scratch register.
     */
    x86_reg getScratch(const x86_reg *exclude = nullptr)
    {
        x86_reg reg = X86_REG_INVALID;
        for (const auto &entry: info)
        {
            int regno = getRegIdx(entry.first);
            if (regno < 0 || regno == RFLAGS_IDX || regno == RSP_IDX)
                continue;
            bool found = false;
            for (unsigned i = 0; !found && exclude != nullptr &&
                    exclude[i] != X86_REG_INVALID; i++)
                found = (entry.first == exclude[i]);
            if (found)
                continue;
            const RegInfo &rinfo = entry.second;
            if (rinfo.used)
                continue;
            if (rinfo.clobbered)
                return entry.first;
            if (rinfo.saved)
                reg = entry.first;
        }
        return reg;
    }

    /*
     * Emulate a register push.
     */
    void push(x86_reg reg, bool caller_save = false)
    {
        reg = getCanonicalReg(reg);
        assert(getInfo(reg) == nullptr);

        intptr_t reg_offset = 0;
        switch (reg)
        {
            case X86_REG_EFLAGS:
                rsp_offset += sizeof(int64_t);
                reg_offset = rsp_offset;
                break;
            case X86_REG_RSP:
                reg_offset = RSP_SLOT;
                break;
            case X86_REG_RIP:
                reg_offset = RIP_SLOT;
                break;
            default:
                rsp_offset += getRegSize(reg);
                reg_offset = rsp_offset;
        }
        RegInfo rinfo(reg_offset, getRegSize(reg), (int)pushed.size());
        rinfo.saved = true;
        rinfo.caller_save = caller_save;
        info.insert({reg, rinfo});
        pushed.push_back(reg);
    }

    /*
     * Emulate the call.
     */
    void call(bool conditional)
    {
        for (auto &entry: info)
        {
            RegInfo &rinfo = entry.second;
            if (conditional && entry.first == X86_REG_RAX)
            {
                // %rax holds the return value:
                assert(rinfo.saved);
                rinfo.clobbered = true;
                rinfo.used      = true;
                continue;
            }
            if (rinfo.caller_save)
            {
                // Caller saved registers are clobbered and unused.
                rinfo.clobbered = true;
                rinfo.used      = false;
            }
            else if (!rinfo.clobbered)
                rinfo.used = !rinfo.clobbered;
        }
    }

    /*
     * Emulate a register pop.
     */
    x86_reg pop()
    {
        if (pushed.size() == 0)
            return X86_REG_INVALID;
        x86_reg reg = pushed.back();
        auto i = info.find(reg);
        assert(i != info.end());
        RegInfo &rinfo = i->second;
        if (rinfo.caller_save)
        {
            // Stop at first caller-save.  These are handled by the
            // trampoline template rather than the metadata.
            return X86_REG_INVALID;
        }
        rinfo.used      = true;
        rinfo.saved     = false;
        rinfo.clobbered = false;
        pushed.pop_back();
        return reg;
    }

    /*
     * Check if regsiter is caller-saved.
     */
    bool isCallerSave(x86_reg reg)
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->caller_save != 0);
    }

    /*
     * Constructor.
     */
    CallInfo(bool clean, bool conditional, size_t num_args, bool before) :
        rsave(getCallerSaveRegs(clean, conditional, num_args)), before(before)
    {
        for (unsigned i = 0; rsave[i] >= 0; i++)
            push(getReg(rsave[i]), /*caller_save=*/true);
        if (clean)
        {
            // For clean calls, %rax will be clobbered when %rflags in pushed.
            clobber(X86_REG_RAX);
        }
    }

    CallInfo() = delete;
    CallInfo(const CallInfo &) = delete;
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
        mutable bool symbols_inited;    // Symbol cached inited?
        mutable Symbols symbols;        // Symbol cache.
    };
};

/*
 * Options.
 */
static bool option_is_tty      = false;
static bool option_no_warnings = false;

/*
 * Backend info.
 */
struct Backend
{
    FILE *out;                      // JSON RPC output.
    pid_t pid;                      // Backend process ID.
};

#define CONTEXT_FORMAT      "%lx: %s%s%s%s%s: "
#define CONTEXT(I)          (I)->address,                           \
                            (option_is_tty? "\33[32m": ""),         \
                            (I)->mnemonic,                          \
                            ((I)->op_str[0] == '\0'? "": " "),      \
                            (I)->op_str,                            \
                            (option_is_tty? "\33[0m": "")

/*
 * Report an error and exit.
 */
void NO_RETURN e9frontend::error(const char *msg, ...)
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
void e9frontend::warning(const char *msg, ...)
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
 * Duplicate a string.
 */
static char *strDup(const char *old_str, size_t n)
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
    fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",     // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, -0x4000);
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
    fprintf(out, ",%u,%u,%u,%u,{\"int32\":%d}",     // lea 0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, 0x4000);
    
    // Execute the displaced instruction, and return from the trampoline:
    fprintf(out, ",\"$instruction\",\"$continue\"");
    
    // Place the string representation of the instruction here:
    fprintf(out, ",\".Lstring\",\"$asmStr\"]");

    sendSeparator(out, /*last=*/true);
    return sendMessageFooter(out, /*sync=*/true);
}

/*
 * Send an "exit" "trampoline" message.
 */
unsigned e9frontend::sendExitTrampolineMessage(FILE *out, int status)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    fprintf(out, "\"exit_%d\"", status);
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
 * Get path information.
 */
static void getPath(bool exe, std::vector<std::string> &paths)
{
    if (exe)
    {
        char *path = getenv("PATH"), *save, *dir;
        if (path == nullptr)
            return;
        path = strDup(path);
        strtok_r(path, ":", &save);
        while ((dir = strtok_r(nullptr, ":", &save)) != nullptr)
            paths.push_back(dir);
        free(path);
    }
    else
    {
        void *handle = dlopen(nullptr, RTLD_LAZY);
        if (handle == nullptr)
            return;
        Dl_serinfo serinfo_0, *serinfo = nullptr;
        if (dlinfo(handle, RTLD_DI_SERINFOSIZE, &serinfo_0) != 0)
        {
            dlinfo_error:
            free(serinfo);
            dlclose(handle);
            return;
        }
        serinfo = (Dl_serinfo *)malloc(serinfo_0.dls_size);
        if (serinfo == nullptr)
            goto dlinfo_error;
        if (dlinfo(handle, RTLD_DI_SERINFOSIZE, serinfo) != 0)
            goto dlinfo_error;
        if (dlinfo(handle, RTLD_DI_SERINFO, serinfo) != 0)
            goto dlinfo_error;
        for (unsigned i = 0; i < serinfo->dls_cnt; i++)
            paths.push_back(serinfo->dls_serpath[i].dls_name);
        free(serinfo);
        dlclose(handle);
        return;
    }
}

/*
 * Parse an ELF file.
 */
ELF *e9frontend::parseELF(const char *filename, intptr_t base)
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

    ELF *elf = new ELF;
    elf->filename       = strDup(filename);
    elf->data           = data;
    elf->size           = size;
    elf->base           = base;
    elf->phdrs          = phdrs;
    elf->phnum          = phnum;
    elf->text_offset    = text_offset;
    elf->text_addr      = text_addr;
    elf->text_size      = text_size;
    elf->dynamic_strtab = dynamic_strtab;
    elf->dynamic_strsz  = dynamic_strsz;
    elf->dynamic_symtab = dynamic_symtab;
    elf->dynamic_symsz  = dynamic_symsz;
    elf->free_addr      = free_addr;
    elf->pie            = (pic && exe);
    elf->dso            = (pic && !exe);
    elf->reloc          = reloc;
    elf->symbols_inited = false;
    return elf;
}

/*
 * Free an ELF file object.
 */
void freeELF(ELF *elf)
{
    munmap((void *)elf->data, elf->size);
    delete elf;
}

/*
 * ELF getters.
 */
const uint8_t *getELFData(const ELF *elf)
{
    return elf->data;
}
const size_t getELFDataSize(const ELF *elf)
{
    return elf->size;
}
const intptr_t getTextAddr(const ELF *elf)
{
    return elf->text_addr;
}
const off_t getTextOffset(const ELF *elf)
{
    return elf->text_offset;
}
const off_t getTextSize(const ELF *elf)
{
    return elf->text_offset;
}

/*
 * Symbol handling implementations.
 */
#include "e9types.cpp"

/*
 * Lookup the address of a symbol, or INTPTR_MIN if not found.
 */
intptr_t e9frontend::getSymbol(const ELF *elf, const char *symbol)
{
    return ::lookupSymbol(elf, symbol, TYPESIG_UNTYPED);
}

/*
 * Embed an ELF file.
 */
void e9frontend::sendELFFileMessage(FILE *out, const ELF *ptr, bool absolute)
{
    const ELF &elf = *ptr;

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
    sig = getMMapSig();
    intptr_t mmap = ::lookupSymbol(&elf, "mmap", sig);

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
 * Move a register to stack.
 */
static bool sendMovBetweenRegAndStack(FILE *out, x86_reg reg, bool to_stack)
{
    uint8_t opcode = (to_stack? 0x7f: 0x6f);
    uint8_t modrm = 0;
    switch (reg)
    {
        case X86_REG_XMM0: case X86_REG_XMM8:
        case X86_REG_XMM16: case X86_REG_XMM24:
            modrm = 0x04; break;
        case X86_REG_XMM1: case X86_REG_XMM9:
        case X86_REG_XMM17: case X86_REG_XMM25:
            modrm = 0x0c; break;
        case X86_REG_XMM2: case X86_REG_XMM10:
        case X86_REG_XMM18: case X86_REG_XMM26:
            modrm = 0x14; break;
        case X86_REG_XMM3: case X86_REG_XMM11:
        case X86_REG_XMM19: case X86_REG_XMM27:
            modrm = 0x1c; break;
        case X86_REG_XMM4: case X86_REG_XMM12:
        case X86_REG_XMM20: case X86_REG_XMM28:
            modrm = 0x24; break;
        case X86_REG_XMM5: case X86_REG_XMM13:
        case X86_REG_XMM21: case X86_REG_XMM29:
            modrm = 0x2c; break;
        case X86_REG_XMM6: case X86_REG_XMM14:
        case X86_REG_XMM22: case X86_REG_XMM30:
            modrm = 0x34; break;
        case X86_REG_XMM7: case X86_REG_XMM15:
        case X86_REG_XMM23: case X86_REG_XMM31:
            modrm = 0x3c; break;
        default:
            return false;
    }

    switch (reg)
    {
        case X86_REG_XMM0: case X86_REG_XMM1: case X86_REG_XMM2:
        case X86_REG_XMM3: case X86_REG_XMM4: case X86_REG_XMM5:
        case X86_REG_XMM6: case X86_REG_XMM7:
            // movdqu %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,", 0xf3, 0x0f, opcode, modrm, 0x24);
            return true;

        case X86_REG_XMM8: case X86_REG_XMM9: case X86_REG_XMM10:
        case X86_REG_XMM11: case X86_REG_XMM12: case X86_REG_XMM13:
        case X86_REG_XMM14: case X86_REG_XMM15:
            // movdqu %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,",
                0xf3, 0x44, 0x0f, opcode, modrm, 0x24);
            return true;

        case X86_REG_XMM16: case X86_REG_XMM17: case X86_REG_XMM18:
        case X86_REG_XMM19: case X86_REG_XMM20: case X86_REG_XMM21:
        case X86_REG_XMM22: case X86_REG_XMM23:
            // vmovdqu64 %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0xe1, 0xfe, 0x08, opcode, modrm, 0x24);
            return true;

        case X86_REG_XMM24: case X86_REG_XMM25: case X86_REG_XMM26:
        case X86_REG_XMM27: case X86_REG_XMM28: case X86_REG_XMM29:
        case X86_REG_XMM30: case X86_REG_XMM31:
            // vmovdqu64 %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0x61, 0xfe, 0x08, opcode, modrm, 0x24);
            return true;

        default:
            return false;
    }
}

/*
 * Send (or emulate) a push instruction.
 */
static std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
    x86_reg reg, x86_reg rscratch)
{
    // Special cases:
    int scratch = -1, old_scratch = -1;
    bool rax_stack = false;
    switch (reg)
    {
        case X86_REG_RIP:
        case X86_REG_RSP:
        case X86_REG_EFLAGS:
            scratch = getRegIdx(rscratch);
            assert(scratch != RSP_IDX && scratch != RFLAGS_IDX);
            if (scratch < 0)
            {
                // No available scratch register.  Evict %rax to into stack
                // redzone at offset -16:
                sendMovFromR64ToStack(out, RAX_IDX, -16);
                scratch = RAX_IDX;
                rax_stack = true;
            }
            if (reg == X86_REG_EFLAGS && scratch != RAX_IDX)
            {
                // %rflags requires %rax as the scratch register:
                sendMovFromR64ToR64(out, RAX_IDX, scratch);
                old_scratch = scratch;
                scratch = RAX_IDX;
            }
            break;
        default:
            break;
    }
    switch (reg)
    {
        case X86_REG_RIP:
            if (before)
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}",
                    scratch);
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    scratch);
            sendMovFromR64ToStack(out, scratch, offset - RIP_SLOT);
            break;

        case X86_REG_RSP:
            // lea offset(%rsp),%rax
            // mov %rax,0x4000-8(%rax)
            sendLeaFromStackToR64(out, offset, scratch);
            sendMovFromR64ToStack(out, scratch, offset - RSP_SLOT);
            break;

       case X86_REG_EFLAGS:
            // seto %al
            // lahf
            assert(scratch == RAX_IDX);
            fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
            fprintf(out, "%u,", 0x9f);
            sendPush(out, offset + sizeof(int64_t), before, X86_REG_RAX);
            break;

        default:
            break;
    }
    switch (reg)
    {
        case X86_REG_RIP:
        case X86_REG_RSP:
        case X86_REG_EFLAGS:
            if (old_scratch >= 0)
                sendMovFromR64ToR64(out, old_scratch, scratch);
            else if (rax_stack)
                sendMovFromStackToR64(out, -16+8, RAX_IDX);
            return {true, !rax_stack};
        default:
            break;
    }

    // Normal cases:
    int regno = getRegIdx(reg);
    int32_t size = getRegSize(reg);
    if (regno >= 0)
    {
        // push %reg
        const uint8_t REX[] =
            {0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x00,
             0x00, 0x41, 0x41, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41, 0x00};
        const uint8_t OPCODE[] =
            {0x57, 0x56, 0x52, 0x51, 0x50, 0x51, 0x00,
             0x50, 0x52, 0x53, 0x53, 0x55, 0x54, 0x55, 0x56, 0x57, 0x54};
        
        if (REX[regno] != 0x00)
            fprintf(out, "%u,", REX[regno]);
        fprintf(out, "%u,", OPCODE[regno]);
        return {true, false};
    }
    else if (size > 0)
    {
        // lea -size(%rsp),%rsp
        // mov %reg,(%rsp)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, -size);
        sendMovBetweenRegAndStack(out, reg, /*to_stack=*/true);
        return {true, false};
    }
    else
        return {false, false};
}

/*
 * Send (or emulate) a pop instruction.
 */
static bool sendPop(FILE *out, bool preserve_rax, x86_reg reg,
    x86_reg rscratch)
{
    // Special cases:
    switch (reg)
    {
        case X86_REG_EFLAGS:
        {
            int scratch = -1;
            if (preserve_rax)
            {
                scratch = getRegIdx(rscratch);
                if (scratch < 0)
                    sendMovFromR64ToStack(out, RAX_IDX,
                        -(int32_t)sizeof(uint64_t));
                else
                    sendMovFromR64ToR64(out, RAX_IDX, scratch);
            }

            sendPop(out, false, X86_REG_RAX);
            // add $0x7f,%al
            // sahf
            fprintf(out, "%u,%u,", 0x04, 0x7f);
            fprintf(out, "%u,", 0x9e);

            if (preserve_rax)
            {
                if (scratch < 0)
                    sendMovFromStackToR64(out, -2*(int32_t)sizeof(uint64_t),
                        RAX_IDX);
                else
                {
                    sendMovFromR64ToR64(out, scratch, RAX_IDX);
                    return true;
                }
            }
            return false;
        }

        case X86_REG_RIP:
            // %rip is treated as read-only & stored in a special slot.
            // So the pop operation is treated as a NOP.
            return false;

        default:
            break;
    }

    int regno = getRegIdx(reg);
    int32_t size = getRegSize(reg);
    if (regno >= 0)
    {
        // pop %reg
        const uint8_t REX[] =
            {0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x00,
             0x00, 0x41, 0x41, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41, 0x00};
        const uint8_t OPCODE[] =
            {0x5f, 0x5e, 0x5a, 0x59, 0x58, 0x59, 0x00,
             0x58, 0x5a, 0x5b, 0x5b, 0x5d, 0x5c, 0x5d, 0x5e, 0x5f, 0x5c};
        
        if (REX[regno] != 0x00)
            fprintf(out, "%u,", REX[regno]);
        fprintf(out, "%u,", OPCODE[regno]);
    }
    else if (size > 0)
    {
        // mov (%rsp),%reg
        // lea size(%rsp),%rsp
        sendMovBetweenRegAndStack(out, reg, /*to_stack=*/false);
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, size);
    }
    else
        ;   // NOP

    return false;
}

/*
 * Send a `mov %r64,%r64' instruction.
 */
static bool sendMovFromR64ToR64(FILE *out, int srcno, int dstno)
{
    if (srcno == dstno)
        return false;
    const uint8_t REX_MASK[] =
        {0, 0, 0, 0, 1, 1, 0,
         0, 1, 1, 0, 0, 1, 1, 1, 1, 0};
    const uint8_t REX[] = {0x48, 0x4c, 0x49, 0x4d};
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
    
    uint8_t rex = REX[(REX_MASK[dstno] << 1) | REX_MASK[srcno]];
    uint8_t modrm = (0x03 << 6) | (REG[srcno] << 3) | REG[dstno];
    fprintf(out, "%u,%u,%u,", rex, 0x89, modrm);
    return true;
}

/*
 * Send a `movslq %r32,%r64' instruction.
 */
static void sendMovFromR32ToR64(FILE *out, int srcno, int dstno)
{
    const uint8_t REX_MASK[] =
        {0, 0, 0, 0, 1, 1, 0,
         0, 1, 1, 0, 0, 1, 1, 1, 1, 0};
    const uint8_t REX[] = {0x48, 0x4c, 0x49, 0x4d};
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
    
    uint8_t rex = REX[(REX_MASK[srcno] << 1) | REX_MASK[dstno]];
    uint8_t modrm = (0x03 << 6) | (REG[dstno] << 3) | REG[srcno];
    fprintf(out, "%u,%u,%u,", rex, 0x63, modrm);
}

/*
 * Send a `movswl %r16,%r64' instruction.
 */
static void sendMovFromR16ToR64(FILE *out, int srcno, int dstno)
{
    const uint8_t REX_MASK[] =
        {0, 0, 0, 0, 1, 1, 0,
         0, 1, 1, 0, 0, 1, 1, 1, 1, 0};
    const uint8_t REX[] = {0x48, 0x4c, 0x49, 0x4d};
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
 
    uint8_t rex = REX[(REX_MASK[srcno] << 1) | REX_MASK[dstno]];
    uint8_t modrm = (0x03 << 6) | (REG[dstno] << 3) | REG[srcno];
    fprintf(out, "%u,%u,%u,%u,", rex, 0x0f, 0xbf, modrm);
}

/*
 * Send a `movsbl %r8,%r32' instruction.
 */
static void sendMovFromR8ToR64(FILE *out, int srcno, bool srchi, int dstno)
{
    const uint8_t REX_MASK[] =
        {0, 0, 0, 0, 1, 1, 0,
         0, 1, 1, 0, 0, 1, 1, 1, 1, 0};
    const uint8_t REX[] = {0x48, 0x4c, 0x49, 0x4d};
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
    
    uint8_t rex = REX[(REX_MASK[srcno] << 1) | REX_MASK[dstno]];
    bool xchg = false;
    uint8_t srcreg = REG[srcno];
    if (rex == 0x00)
    {
        switch (srcno)
        {
            case RAX_IDX: case RBX_IDX: case RCX_IDX: case RDX_IDX:
                if (srchi)
                    srcreg += 4;     // Convert to %rh encoding
                break;
            case RDI_IDX: case RSI_IDX: case RSP_IDX: case RBP_IDX:
                rex = 0x40; break;
            default:
                break;
        }
    }
    else if (srchi)
    {
        // xchgb %rh,%rl
        xchg = true;
        switch (srcno)
        {
            case RAX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xe0); break;
            case RBX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xfb); break;
            case RCX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xe9); break;
            case RDX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xf2); break;
        }
    }
    uint8_t modrm = (0x03 << 6) | (REG[dstno] << 3) | srcreg;
    fprintf(out, "%u,%u,%u,%u,", rex, 0x0f, 0xbe, modrm);
    if (xchg)
    {
        // xchgb %rh,%rl
        switch (srcno)
        {
            case RAX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xe0); break;
            case RBX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xfb); break;
            case RCX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xe9); break;
            case RDX_IDX:
                fprintf(out, "%u,%u,", 0x86, 0xf2); break;
        }
    }
}

/*
 * Send a `mov offset(%rsp),%r64' instruction.
 */
static void sendMovFromStackToR64(FILE *out, int32_t offset, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM_0[] =
        {0x3c, 0x34, 0x14, 0x0c, 0x04, 0x0c, 0x00,  
         0x04, 0x14, 0x1c, 0x1c, 0x2c, 0x24, 0x2c, 0x34, 0x3c, 0x24};
    const uint8_t MODRM_8[] =
        {0x7c, 0x74, 0x54, 0x4c, 0x44, 0x4c, 0x00, 
         0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
    const uint8_t MODRM_32[] =
        {0xbc, 0xb4, 0x94, 0x8c, 0x84, 0x8c, 0x00,
         0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset == 0)
        fprintf(out, "%u,%u,%u,%u,",
            REX[regno], 0x8b, MODRM_0[regno], 0x24);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x8b, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x8b, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `movslq offset(%rsp),%r64' instruction.
 */
static void sendMovFromStack32ToR64(FILE *out, int32_t offset, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM_0[] =
        {0x3c, 0x34, 0x14, 0x0c, 0x04, 0x0c, 0x00,  
         0x04, 0x14, 0x1c, 0x1c, 0x2c, 0x24, 0x2c, 0x34, 0x3c, 0x24};
    const uint8_t MODRM_8[] =
        {0x7c, 0x74, 0x54, 0x4c, 0x44, 0x4c, 0x00, 
         0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
    const uint8_t MODRM_32[] =
        {0xbc, 0xb4, 0x94, 0x8c, 0x84, 0x8c, 0x00,
         0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset == 0)
        fprintf(out, "%u,%u,%u,%u,",
            REX[regno], 0x63, MODRM_0[regno], 0x24);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x63, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x63, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `movswl offset(%rsp),%r64' instruction.
 */
static void sendMovFromStack16ToR64(FILE *out, int32_t offset, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM_0[] =
        {0x3c, 0x34, 0x14, 0x0c, 0x04, 0x0c, 0x00,  
         0x04, 0x14, 0x1c, 0x1c, 0x2c, 0x24, 0x2c, 0x34, 0x3c, 0x24};
    const uint8_t MODRM_8[] =
        {0x7c, 0x74,  0x54, 0x4c, 0x44, 0x4c, 0x00, 
         0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
    const uint8_t MODRM_32[] =
        {0xbc, 0xb4,  0x94, 0x8c, 0x84, 0x8c, 0x00,
         0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset == 0)
        fprintf(out, "%u,%u,%u,%u,%u,",
            REX[regno], 0x0f, 0xbf, MODRM_0[regno], 0x24);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x0f, 0xbf, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x0f, 0xbf, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `movzbl offset(%rsp),%r64' instruction.
 */
static void sendMovFromStack8ToR64(FILE *out, int32_t offset, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM_0[] =
        {0x3c, 0x34, 0x14, 0x0c, 0x04, 0x0c, 0x00,  
         0x04, 0x14, 0x1c, 0x1c, 0x2c, 0x24, 0x2c, 0x34, 0x3c, 0x24};
    const uint8_t MODRM_8[] =
        {0x7c, 0x74,  0x54, 0x4c, 0x44, 0x4c, 0x00, 
         0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
    const uint8_t MODRM_32[] =
        {0xbc, 0xb4,  0x94, 0x8c, 0x84, 0x8c, 0x00,
         0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset == 0)
        fprintf(out, "%u,%u,%u,%u,%u,",
            REX[regno], 0x0f, 0xbe, MODRM_0[regno], 0x24);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x0f, 0xbe, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x0f, 0xbe, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `mov %r64,offset(%rsp)' instruction.
 */
static void sendMovFromR64ToStack(FILE *out, int regno, int32_t offset)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM_0[] =
        {0x3c, 0x34, 0x14, 0x0c, 0x04, 0x0c, 0x00,  
         0x04, 0x14, 0x1c, 0x1c, 0x2c, 0x24, 0x2c, 0x34, 0x3c, 0x24};
    const uint8_t MODRM_8[] =
        {0x7c, 0x74,  0x54, 0x4c, 0x44, 0x4c, 0x00, 
         0x44, 0x54, 0x5c, 0x5c, 0x6c, 0x64, 0x6c, 0x74, 0x7c, 0x64};
    const uint8_t MODRM_32[] =
        {0xbc, 0xb4,  0x94, 0x8c, 0x84, 0x8c, 0x00,
         0x84, 0x94, 0x9c, 0x9c, 0xac, 0xa4, 0xac, 0xb4, 0xbc, 0xa4};

    if (offset == 0)
        fprintf(out, "%u,%u,%u,%u,",
            REX[regno], 0x89, MODRM_0[regno], 0x24);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x89, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x89, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a `movzwl %ax,%r32' instruction.
 */
static void sendMovFromRAX16ToR64(FILE *out, int regno)
{
    const uint8_t REX[] =
        {0x00, 0x00, 0x00, 0x00, 0x44, 0x44, 0x00,
         0x00, 0x44, 0x44, 0x00, 0x00, 0x44, 0x44, 0x44, 0x44, 0x00};
    const uint8_t MODRM[] =
        {0xf8, 0xf0, 0xd0, 0xc8, 0xc0, 0xc8, 0x00,
         0xc0, 0xd0, 0xd8, 0xd8, 0xe8, 0xe0, 0xe8, 0xf0, 0xf8, 0xe0};
    if (REX[regno] != 0x00)
        fprintf(out, "%u,", REX[regno]);
    fprintf(out, "%u,%u,%u,", 0x0f, 0xb7, MODRM[regno]);
}

/*
 * Send a `mov $value,%r32' instruction.
 */
static void sendSExtFromI32ToR64(FILE *out, const char *value, int regno)
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
static void sendSExtFromI32ToR64(FILE *out, int32_t value, int regno)
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
static void sendZExtFromI32ToR64(FILE *out, const char *value, int regno)
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
static void sendZExtFromI32ToR64(FILE *out, int32_t value, int regno)
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
static void sendMovFromI64ToR64(FILE *out, intptr_t value, int regno)
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
 * Send a `lea offset(%rip),%r64' instruction.
 */
static void sendLeaFromPCRelToR64(FILE *out, const char *offset, int regno)
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
 * Send a `lea offset(%rip),%r64' instruction.
 */
static void sendLeaFromPCRelToR64(FILE *out, int32_t offset, int regno)
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
 * Send a `lea offset(%rsp),%r64' instruction.
 */
static void sendLeaFromStackToR64(FILE *out, int32_t offset, int regno)
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

    if (offset == 0)
        sendMovFromR64ToR64(out, RSP_IDX, regno);
    else if (offset >= INT8_MIN && offset <= INT8_MAX)
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            REX[regno], 0x8d, MODRM_8[regno], 0x24, offset);
    else
        fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
            REX[regno], 0x8d, MODRM_32[regno], 0x24, offset);
}

/*
 * Send a call ELF trampoline.
 */
unsigned e9frontend::sendCallTrampolineMessage(FILE *out, const char *name,
    const std::vector<Argument> &args, bool clean, CallKind call)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, name);
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);
    
    // Put a label at the start of the trampoline:
    fputs("\".Ltrampoline\",", out);

    // Put instruction here for "after" instrumentation.
    if (call == CALL_AFTER)
        fprintf(out, "\"$instruction\",");

    // Adjust the stack:
    fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",     // lea -0x4000(%rsp),%rsp
        0x48, 0x8d, 0xa4, 0x24, -0x4000);

    // Push all caller-save registers:
    bool conditional = (call == CALL_CONDITIONAL);
    const int *rsave = getCallerSaveRegs(clean, conditional, args.size());
    int num_rsave = 0;
    x86_reg rscratch = (clean? X86_REG_RAX: X86_REG_INVALID);
    for (int i = 0; rsave[i] >= 0; i++, num_rsave++)
        sendPush(out, 0, (call != CALL_AFTER), getReg(rsave[i]), rscratch);

    // Load the arguments:
    fputs("\"$loadArgs\",", out);

    // Call the function:
    fprintf(out, "%u,\"$function\",", 0xe8);        // callq function

    // Restore the state:
    fputs("\"$restoreState\",", out);
    
    // If clean & conditional, store result in %rcx, else it stays in %rax
    bool preserve_rax = (conditional || !clean);
    bool result_rax   = true;
    if (conditional && clean)
    {
        // mov %rax,%rcx
        fprintf(out, "%u,%u,%u,", 0x48, 0x89, 0xc1);
        preserve_rax = false;
        result_rax   = false;
    }

    // Pop all callee-save registers:
    int rmin = (conditional? 1: 0);
    for (int i = num_rsave-1; i >= rmin; i--)
        sendPop(out, preserve_rax, getReg(rsave[i]));

    // If conditional, jump away from $instruction if %rax is zero:
    if (conditional)
    {
        // xchg %rax,%rcx
        // jrcxz .Lskip
        // xchg %rax,%rcx
        // pop %rax
        //
        if (result_rax)
            fprintf(out, "%u,%u,", 0x48, 0x91);
        fprintf(out, "%u,{\"rel8\":\".Lskip\"},", 0xe3);
        if (result_rax)
        {
            fprintf(out, "%u,%u,", 0x48, 0x91);
            fprintf(out, "%u,", 0x58);
        }
        else
            fprintf(out, "%u,", 0x59);
    }

    // Restore the stack pointer.
    fputs("\"$restoreRSP\",",out);
    
    // Put instruction here for "before" instrumentation:
    if (call == CALL_BEFORE || call == CALL_CONDITIONAL)
        fputs("\"$instruction\",", out);

    // Return from trampoline:
    fputs("\"$continue\"", out);

    // If conditional, but the .Lskip block here:
    if (conditional)
    {
        // .Lskip:
        // xchg %rax,%rcx
        // pop %rax
        //
        fputs(",\".Lskip\",", out);
        if (result_rax)
        {
            fprintf(out, "%u,%u,", 0x48, 0x91);
            fprintf(out, "%u,", 0x58);
        }
        else
            fprintf(out, "%u,", 0x59);

        fputs("\"$restoreRSP\",",out);
        fputs("\"$continue\"", out);
    }
    
    // Any additional data:
    if (args.size() > 0)
        fputs(",\"$data\"]", out);
    else
        fputc(']', out);
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
 * Find an exe file in PATH.
 */
static const char *findBinary(const char *filename, bool exe = true,
    bool dot = false)
{
    if (filename[0] == '/')
        return filename;
    std::vector<std::string> path;
    getPath(exe, path);
    if (dot)
        path.push_back(".");
    for (const auto &dirname: path)
    {
        std::string pathname_0(dirname);
        pathname_0 += '/';
        pathname_0 += filename;

        char *pathname = realpath(pathname_0.c_str(), nullptr);
        if (pathname == nullptr)
            continue;
        struct stat buf;
        if (stat(pathname, &buf) == 0 && (buf.st_mode & S_IXOTH) != 0)
            return pathname;
        free(pathname);
    }

    error("failed to find %s file \"%s\" in %s",
        (exe? "executable": "library"), filename, (exe? "PATH": "RPATH"));
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
        prog = findBinary(prog, /*exe=*/true, /*dot=*/true);
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

