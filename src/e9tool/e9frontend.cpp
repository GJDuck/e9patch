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
#include "../e9patch/e9loader.h"

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
#define RIP_IDX         17
#define RMAX_IDX        RIP_IDX

/*
 * Prototypes.
 */
static char *strDup(const char *old_str, size_t n = SIZE_MAX);
static std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
    Register reg, Register rscratch = REGISTER_INVALID);
static bool sendPop(FILE *out, bool conditional, Register reg,
    Register rscratch = REGISTER_INVALID);
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
static int getArgRegIdx(bool sysv, int argno)
{
    switch (argno)
    {
        case 0:
            return (sysv? RDI_IDX: RCX_IDX);
        case 1:
            return (sysv? RSI_IDX: RDX_IDX);
        case 2:
            return (sysv? RDX_IDX: R8_IDX);
        case 3:
            return (sysv? RCX_IDX: R9_IDX);
        case 4:
            return (sysv? R8_IDX: R10_IDX);
        case 5:
            return (sysv? R9_IDX: R11_IDX);
        case 6:
            return (sysv? R10_IDX: -1);
        case 7:
            return (sysv? R11_IDX: -1);
        default:
            return -1;
    }
}

/*
 * Convert a register number into a register.
 */
static Register getReg(int regno)
{
    switch (regno)
    {
        case RDI_IDX:
            return REGISTER_RDI;
        case RSI_IDX:
            return REGISTER_RSI;
        case RDX_IDX:
            return REGISTER_RDX;
        case RCX_IDX:
            return REGISTER_RCX;
        case R8_IDX:
            return REGISTER_R8;
        case R9_IDX:
            return REGISTER_R9;
        case RFLAGS_IDX:
            return REGISTER_EFLAGS;
        case RAX_IDX:
            return REGISTER_RAX;
        case R10_IDX:
            return REGISTER_R10;
        case R11_IDX:
            return REGISTER_R11;
        case RBX_IDX: 
            return REGISTER_RBX;
        case RBP_IDX:
            return REGISTER_RBP;
        case R12_IDX:
            return REGISTER_R12;
        case R13_IDX:
            return REGISTER_R13;
        case R14_IDX:
            return REGISTER_R14;
        case R15_IDX:
            return REGISTER_R15;
        case RSP_IDX:
            return REGISTER_RSP;
        case RIP_IDX:
            return REGISTER_RIP;
        default:
            return REGISTER_INVALID;
    }
}

/*
 * Convert a register into a register index.
 */
static int getRegIdx(Register reg)
{
    switch (reg)
    {
        case REGISTER_DI: case REGISTER_DIL: case REGISTER_EDI: case REGISTER_RDI:
            return RDI_IDX;
        case REGISTER_SI: case REGISTER_SIL: case REGISTER_ESI: case REGISTER_RSI:
            return RSI_IDX;
        case REGISTER_DH: case REGISTER_DL:
        case REGISTER_DX: case REGISTER_EDX: case REGISTER_RDX:
            return RDX_IDX;
        case REGISTER_CH: case REGISTER_CL:
        case REGISTER_CX: case REGISTER_ECX: case REGISTER_RCX:
            return RCX_IDX;
        case REGISTER_R8B: case REGISTER_R8W: case REGISTER_R8D: case REGISTER_R8:
            return R8_IDX;
        case REGISTER_R9B: case REGISTER_R9W: case REGISTER_R9D: case REGISTER_R9:
            return R9_IDX;
        case REGISTER_AH: case REGISTER_AL:
        case REGISTER_AX: case REGISTER_EAX: case REGISTER_RAX:
            return RAX_IDX;
        case REGISTER_R10B: case REGISTER_R10W: case REGISTER_R10D:
        case REGISTER_R10:
            return R10_IDX;
        case REGISTER_R11B: case REGISTER_R11W: case REGISTER_R11D:
        case REGISTER_R11:
            return R11_IDX;
        case REGISTER_BH: case REGISTER_BL:
        case REGISTER_BX: case REGISTER_EBX: case REGISTER_RBX:
            return RBX_IDX;
        case REGISTER_BP: case REGISTER_BPL: case REGISTER_EBP: case REGISTER_RBP:
            return RBP_IDX;
        case REGISTER_R12B: case REGISTER_R12W: case REGISTER_R12D:
        case REGISTER_R12:
            return R12_IDX;
        case REGISTER_R13B: case REGISTER_R13W: case REGISTER_R13D:
        case REGISTER_R13:
            return R13_IDX;
        case REGISTER_R14B: case REGISTER_R14W: case REGISTER_R14D:
        case REGISTER_R14:
            return R14_IDX;
        case REGISTER_R15B: case REGISTER_R15W: case REGISTER_R15D:
        case REGISTER_R15:
            return R15_IDX;
        case REGISTER_SP: case REGISTER_SPL: case REGISTER_ESP: case REGISTER_RSP:
            return RSP_IDX;
        default:
            return -1;
    }
}

/*
 * Convert a register into a canonical register.
 */
static Register getCanonicalReg(Register reg)
{
    switch (reg)
    {
        case REGISTER_DI: case REGISTER_DIL: case REGISTER_EDI: case REGISTER_RDI:
            return REGISTER_RDI;
        case REGISTER_SI: case REGISTER_SIL: case REGISTER_ESI: case REGISTER_RSI:
            return REGISTER_RSI;
        case REGISTER_DH: case REGISTER_DL:
        case REGISTER_DX: case REGISTER_EDX: case REGISTER_RDX:
            return REGISTER_RDX;
        case REGISTER_CH: case REGISTER_CL:
        case REGISTER_CX: case REGISTER_ECX: case REGISTER_RCX:
            return REGISTER_RCX;
        case REGISTER_R8B: case REGISTER_R8W: case REGISTER_R8D: case REGISTER_R8:
            return REGISTER_R8;
        case REGISTER_R9B: case REGISTER_R9W: case REGISTER_R9D: case REGISTER_R9:
            return REGISTER_R9;
        case REGISTER_AH: case REGISTER_AL:
        case REGISTER_AX: case REGISTER_EAX: case REGISTER_RAX:
            return REGISTER_RAX;
        case REGISTER_R10B: case REGISTER_R10W: case REGISTER_R10D:
        case REGISTER_R10:
            return REGISTER_R10;
        case REGISTER_R11B: case REGISTER_R11W: case REGISTER_R11D:
        case REGISTER_R11:
            return REGISTER_R11;
        case REGISTER_BH: case REGISTER_BL:
        case REGISTER_BX: case REGISTER_EBX: case REGISTER_RBX:
            return REGISTER_RBX;
        case REGISTER_BP: case REGISTER_BPL: case REGISTER_EBP: case REGISTER_RBP:
            return REGISTER_RBP;
        case REGISTER_R12B: case REGISTER_R12W: case REGISTER_R12D:
        case REGISTER_R12:
            return REGISTER_R12;
        case REGISTER_R13B: case REGISTER_R13W: case REGISTER_R13D:
        case REGISTER_R13:
            return REGISTER_R13;
        case REGISTER_R14B: case REGISTER_R14W: case REGISTER_R14D:
        case REGISTER_R14:
            return REGISTER_R14;
        case REGISTER_R15B: case REGISTER_R15W: case REGISTER_R15D:
        case REGISTER_R15:
            return REGISTER_R15;
        case REGISTER_SP: case REGISTER_SPL: case REGISTER_ESP: case REGISTER_RSP:
            return REGISTER_RSP;
        case REGISTER_IP: case REGISTER_EIP: case REGISTER_RIP:
            return REGISTER_RIP;
        default:
            return reg;
    }
}

/*
 * Get the storage size of a register.
 */
static int32_t getRegSize(Register reg)
{
    switch (reg)
    {
        case REGISTER_AH: case REGISTER_AL: case REGISTER_BH:
        case REGISTER_BL: case REGISTER_CH: case REGISTER_CL:
        case REGISTER_BPL: case REGISTER_DIL: case REGISTER_DL:
        case REGISTER_DH: case REGISTER_SIL: case REGISTER_SPL:
        case REGISTER_R8B: case REGISTER_R9B: case REGISTER_R10B:
        case REGISTER_R11B: case REGISTER_R12B: case REGISTER_R13B:
        case REGISTER_R14B: case REGISTER_R15B:
            return sizeof(int8_t);
        
        case REGISTER_EFLAGS: case REGISTER_AX: case REGISTER_BP:
        case REGISTER_BX: case REGISTER_CX: case REGISTER_DX:
        case REGISTER_DI: case REGISTER_IP: case REGISTER_SI:
        case REGISTER_SP: case REGISTER_R8W: case REGISTER_R9W:
        case REGISTER_R10W: case REGISTER_R11W: case REGISTER_R12W:
        case REGISTER_R13W: case REGISTER_R14W: case REGISTER_R15W:
            return sizeof(int16_t);
        
        case REGISTER_EAX: case REGISTER_EBP: case REGISTER_EBX:
        case REGISTER_ECX: case REGISTER_EDI: case REGISTER_EDX:
        case REGISTER_EIP: case REGISTER_ESI: case REGISTER_ESP:
        case REGISTER_R8D: case REGISTER_R9D: case REGISTER_R10D:
        case REGISTER_R11D: case REGISTER_R12D: case REGISTER_R13D:
        case REGISTER_R14D: case REGISTER_R15D:
            return sizeof(int32_t);

        case REGISTER_RAX: case REGISTER_RBP: case REGISTER_RBX:
        case REGISTER_RCX: case REGISTER_RDI: case REGISTER_RDX:
        case REGISTER_RIP: case REGISTER_RSI: case REGISTER_RSP:
        case REGISTER_R8: case REGISTER_R9: case REGISTER_R10:
        case REGISTER_R11: case REGISTER_R12: case REGISTER_R13:
        case REGISTER_R14: case REGISTER_R15:
            return sizeof(int64_t);

        case REGISTER_XMM0: case REGISTER_XMM1: case REGISTER_XMM2:
        case REGISTER_XMM3: case REGISTER_XMM4: case REGISTER_XMM5:
        case REGISTER_XMM6: case REGISTER_XMM7: case REGISTER_XMM8:
        case REGISTER_XMM9: case REGISTER_XMM10: case REGISTER_XMM11:
        case REGISTER_XMM12: case REGISTER_XMM13: case REGISTER_XMM14:
        case REGISTER_XMM15: case REGISTER_XMM16: case REGISTER_XMM17:
        case REGISTER_XMM18: case REGISTER_XMM19: case REGISTER_XMM20:
        case REGISTER_XMM21: case REGISTER_XMM22: case REGISTER_XMM23:
        case REGISTER_XMM24: case REGISTER_XMM25: case REGISTER_XMM26:
        case REGISTER_XMM27: case REGISTER_XMM28: case REGISTER_XMM29:
        case REGISTER_XMM30: case REGISTER_XMM31:
            return 2 * sizeof(int64_t);

        case REGISTER_YMM0: case REGISTER_YMM1: case REGISTER_YMM2:
        case REGISTER_YMM3: case REGISTER_YMM4: case REGISTER_YMM5:
        case REGISTER_YMM6: case REGISTER_YMM7: case REGISTER_YMM8:
        case REGISTER_YMM9: case REGISTER_YMM10: case REGISTER_YMM11:
        case REGISTER_YMM12: case REGISTER_YMM13: case REGISTER_YMM14:
        case REGISTER_YMM15: case REGISTER_YMM16: case REGISTER_YMM17:
        case REGISTER_YMM18: case REGISTER_YMM19: case REGISTER_YMM20:
        case REGISTER_YMM21: case REGISTER_YMM22: case REGISTER_YMM23:
        case REGISTER_YMM24: case REGISTER_YMM25: case REGISTER_YMM26:
        case REGISTER_YMM27: case REGISTER_YMM28: case REGISTER_YMM29:
        case REGISTER_YMM30: case REGISTER_YMM31:
            return 4 * sizeof(int64_t);

        case REGISTER_ZMM0: case REGISTER_ZMM1: case REGISTER_ZMM2:
        case REGISTER_ZMM3: case REGISTER_ZMM4: case REGISTER_ZMM5:
        case REGISTER_ZMM6: case REGISTER_ZMM7: case REGISTER_ZMM8:
        case REGISTER_ZMM9: case REGISTER_ZMM10: case REGISTER_ZMM11:
        case REGISTER_ZMM12: case REGISTER_ZMM13: case REGISTER_ZMM14:
        case REGISTER_ZMM15: case REGISTER_ZMM16: case REGISTER_ZMM17:
        case REGISTER_ZMM18: case REGISTER_ZMM19: case REGISTER_ZMM20:
        case REGISTER_ZMM21: case REGISTER_ZMM22: case REGISTER_ZMM23:
        case REGISTER_ZMM24: case REGISTER_ZMM25: case REGISTER_ZMM26:
        case REGISTER_ZMM27: case REGISTER_ZMM28: case REGISTER_ZMM29:
        case REGISTER_ZMM30: case REGISTER_ZMM31:
            return 8 * sizeof(int64_t);

        case REGISTER_ES: case REGISTER_CS: case REGISTER_DS:
        case REGISTER_FS: case REGISTER_GS: case REGISTER_SS:
        case REGISTER_CR0: case REGISTER_CR1: case REGISTER_CR2:
        case REGISTER_CR3: case REGISTER_CR4: case REGISTER_CR5:
        case REGISTER_CR6: case REGISTER_CR7: case REGISTER_CR8:
        case REGISTER_CR9: case REGISTER_CR10: case REGISTER_CR11:
        case REGISTER_CR12: case REGISTER_CR13: case REGISTER_CR14:
        case REGISTER_CR15: case REGISTER_DR0: case REGISTER_DR1:
        case REGISTER_DR2: case REGISTER_DR3: case REGISTER_DR4:
        case REGISTER_DR5: case REGISTER_DR6: case REGISTER_DR7:
        case REGISTER_DR8: case REGISTER_DR9: case REGISTER_DR10:
        case REGISTER_DR11: case REGISTER_DR12: case REGISTER_DR13:
        case REGISTER_DR14: case REGISTER_DR15: case REGISTER_K0:
        case REGISTER_K1: case REGISTER_K2: case REGISTER_K3:
        case REGISTER_K4: case REGISTER_K5: case REGISTER_K6:
        case REGISTER_K7: case REGISTER_MM0: case REGISTER_MM1:
        case REGISTER_MM2: case REGISTER_MM3: case REGISTER_MM4:
        case REGISTER_MM5: case REGISTER_MM6: case REGISTER_MM7:
        case REGISTER_ST0: case REGISTER_ST1: case REGISTER_ST2:
        case REGISTER_ST3: case REGISTER_ST4: case REGISTER_ST5:
        case REGISTER_ST6: case REGISTER_ST7:
            return 0;

        case REGISTER_INVALID:
        default:
            return 0;
    }
}

/*
 * Get the type of a register.
 */
static Type getRegType(Register reg)
{
    switch (reg)
    {
        case REGISTER_AH: case REGISTER_AL: case REGISTER_BH:
        case REGISTER_BL: case REGISTER_CH: case REGISTER_CL:
        case REGISTER_BPL: case REGISTER_DIL: case REGISTER_DL:
        case REGISTER_DH: case REGISTER_SIL: case REGISTER_SPL:
        case REGISTER_R8B: case REGISTER_R9B: case REGISTER_R10B:
        case REGISTER_R11B: case REGISTER_R12B: case REGISTER_R13B:
        case REGISTER_R14B: case REGISTER_R15B:
            return TYPE_INT8;
 
        case REGISTER_EFLAGS: case REGISTER_AX: case REGISTER_BP:
        case REGISTER_BX: case REGISTER_CX: case REGISTER_DX:
        case REGISTER_DI: case REGISTER_IP: case REGISTER_SI:
        case REGISTER_SP: case REGISTER_R8W: case REGISTER_R9W:
        case REGISTER_R10W: case REGISTER_R11W: case REGISTER_R12W:
        case REGISTER_R13W: case REGISTER_R14W: case REGISTER_R15W:
            return TYPE_INT16;
 
        case REGISTER_EAX: case REGISTER_EBP: case REGISTER_EBX:
        case REGISTER_ECX: case REGISTER_EDI: case REGISTER_EDX:
        case REGISTER_EIP: case REGISTER_ESI:
        case REGISTER_ESP: case REGISTER_R8D: case REGISTER_R9D:
        case REGISTER_R10D: case REGISTER_R11D: case REGISTER_R12D:
        case REGISTER_R13D: case REGISTER_R14D: case REGISTER_R15D:
            return TYPE_INT32;
 
        case REGISTER_RAX: case REGISTER_RBP: case REGISTER_RBX:
        case REGISTER_RCX: case REGISTER_RDI: case REGISTER_RDX:
        case REGISTER_RIP: case REGISTER_RSI:
        case REGISTER_RSP: case REGISTER_R8: case REGISTER_R9:
        case REGISTER_R10: case REGISTER_R11: case REGISTER_R12:
        case REGISTER_R13: case REGISTER_R14: case REGISTER_R15:
            return TYPE_INT64;
 
        case REGISTER_XMM0: case REGISTER_XMM1: case REGISTER_XMM2:
        case REGISTER_XMM3: case REGISTER_XMM4: case REGISTER_XMM5:
        case REGISTER_XMM6: case REGISTER_XMM7: case REGISTER_XMM8:
        case REGISTER_XMM9: case REGISTER_XMM10: case REGISTER_XMM11:
        case REGISTER_XMM12: case REGISTER_XMM13: case REGISTER_XMM14:
        case REGISTER_XMM15: case REGISTER_XMM16: case REGISTER_XMM17:
        case REGISTER_XMM18: case REGISTER_XMM19: case REGISTER_XMM20:
        case REGISTER_XMM21: case REGISTER_XMM22: case REGISTER_XMM23:
        case REGISTER_XMM24: case REGISTER_XMM25: case REGISTER_XMM26:
        case REGISTER_XMM27: case REGISTER_XMM28: case REGISTER_XMM29:
        case REGISTER_XMM30: case REGISTER_XMM31:
            return TYPE_NULL_PTR;
 
        case REGISTER_YMM0: case REGISTER_YMM1: case REGISTER_YMM2:
        case REGISTER_YMM3: case REGISTER_YMM4: case REGISTER_YMM5:
        case REGISTER_YMM6: case REGISTER_YMM7: case REGISTER_YMM8:
        case REGISTER_YMM9: case REGISTER_YMM10: case REGISTER_YMM11:
        case REGISTER_YMM12: case REGISTER_YMM13: case REGISTER_YMM14:
        case REGISTER_YMM15: case REGISTER_YMM16: case REGISTER_YMM17:
        case REGISTER_YMM18: case REGISTER_YMM19: case REGISTER_YMM20:
        case REGISTER_YMM21: case REGISTER_YMM22: case REGISTER_YMM23:
        case REGISTER_YMM24: case REGISTER_YMM25: case REGISTER_YMM26:
        case REGISTER_YMM27: case REGISTER_YMM28: case REGISTER_YMM29:
        case REGISTER_YMM30: case REGISTER_YMM31:
            return TYPE_NULL_PTR;
 
        case REGISTER_ZMM0: case REGISTER_ZMM1: case REGISTER_ZMM2:
        case REGISTER_ZMM3: case REGISTER_ZMM4: case REGISTER_ZMM5:
        case REGISTER_ZMM6: case REGISTER_ZMM7: case REGISTER_ZMM8:
        case REGISTER_ZMM9: case REGISTER_ZMM10: case REGISTER_ZMM11:
        case REGISTER_ZMM12: case REGISTER_ZMM13: case REGISTER_ZMM14:
        case REGISTER_ZMM15: case REGISTER_ZMM16: case REGISTER_ZMM17:
        case REGISTER_ZMM18: case REGISTER_ZMM19: case REGISTER_ZMM20:
        case REGISTER_ZMM21: case REGISTER_ZMM22: case REGISTER_ZMM23:
        case REGISTER_ZMM24: case REGISTER_ZMM25: case REGISTER_ZMM26:
        case REGISTER_ZMM27: case REGISTER_ZMM28: case REGISTER_ZMM29:
        case REGISTER_ZMM30: case REGISTER_ZMM31:
            return TYPE_NULL_PTR;
 
        case REGISTER_ES: case REGISTER_CS: case REGISTER_DS:
        case REGISTER_FS: case REGISTER_GS: case REGISTER_SS:
        case REGISTER_CR0: case REGISTER_CR1: case REGISTER_CR2:
        case REGISTER_CR3: case REGISTER_CR4: case REGISTER_CR5:
        case REGISTER_CR6: case REGISTER_CR7: case REGISTER_CR8:
        case REGISTER_CR9: case REGISTER_CR10: case REGISTER_CR11:
        case REGISTER_CR12: case REGISTER_CR13: case REGISTER_CR14:
        case REGISTER_CR15: case REGISTER_DR0: case REGISTER_DR1:
        case REGISTER_DR2: case REGISTER_DR3: case REGISTER_DR4:
        case REGISTER_DR5: case REGISTER_DR6: case REGISTER_DR7:
        case REGISTER_DR8: case REGISTER_DR9: case REGISTER_DR10:
        case REGISTER_DR11: case REGISTER_DR12: case REGISTER_DR13:
        case REGISTER_DR14: case REGISTER_DR15: case REGISTER_K0:
        case REGISTER_K1: case REGISTER_K2: case REGISTER_K3:
        case REGISTER_K4: case REGISTER_K5: case REGISTER_K6:
        case REGISTER_K7: case REGISTER_MM0: case REGISTER_MM1:
        case REGISTER_MM2: case REGISTER_MM3: case REGISTER_MM4:
        case REGISTER_MM5: case REGISTER_MM6: case REGISTER_MM7:
        case REGISTER_ST0: case REGISTER_ST1: case REGISTER_ST2:
        case REGISTER_ST3: case REGISTER_ST4: case REGISTER_ST5:
        case REGISTER_ST6: case REGISTER_ST7:
            return TYPE_NULL_PTR;

        case REGISTER_INVALID:
        default:
            return TYPE_NULL_PTR;
    }
}

/*
 * Return `true' for high-byte registers.
 */
static bool getRegHigh(Register reg)
{
    switch (reg)
    {
        case REGISTER_AH: case REGISTER_BH: case REGISTER_CH: case REGISTER_DH:
            return true;
        default:
            return false;
    }
}

/*
 * Get a register name.
 */
static const char *getRegName(Register reg)
{
    switch (reg)
    {
        case REGISTER_AH:      return "%ah";
        case REGISTER_AL:      return "%al";
        case REGISTER_BH:      return "%bh";
        case REGISTER_BL:      return "%bl";
        case REGISTER_CH:      return "%ch";
        case REGISTER_CL:      return "%cl";
        case REGISTER_BPL:     return "%bpl";
        case REGISTER_DIL:     return "%dil";
        case REGISTER_DL:      return "%dl";
        case REGISTER_DH:      return "%dh";
        case REGISTER_SIL:     return "%sil";
        case REGISTER_SPL:     return "%spl";
        case REGISTER_R8B:     return "%r8b";
        case REGISTER_R9B:     return "%r9b";
        case REGISTER_R10B:    return "%r10b";
        case REGISTER_R11B:    return "%r11b";
        case REGISTER_R12B:    return "%r12b";
        case REGISTER_R13B:    return "%r13b";
        case REGISTER_R14B:    return "%r14b";
        case REGISTER_R15B:    return "%r15b";
        case REGISTER_EFLAGS:  return "%rflags";
        case REGISTER_AX:      return "%ax";
        case REGISTER_BP:      return "%bp";
        case REGISTER_BX:      return "%bx";
        case REGISTER_CX:      return "%cx";
        case REGISTER_DX:      return "%dx";
        case REGISTER_DI:      return "%di";
        case REGISTER_IP:      return "%ip";
        case REGISTER_SI:      return "%si";
        case REGISTER_SP:      return "%sp";
        case REGISTER_R8W:     return "%r8w";
        case REGISTER_R9W:     return "%r9w";
        case REGISTER_R10W:    return "%r10w";
        case REGISTER_R11W:    return "%r11w";
        case REGISTER_R12W:    return "%r12w";
        case REGISTER_R13W:    return "%r13w";
        case REGISTER_R14W:    return "%r14w";
        case REGISTER_R15W:    return "%r15w";
        case REGISTER_EAX:     return "%eax";
        case REGISTER_EBP:     return "%ebp";
        case REGISTER_EBX:     return "%ebx";
        case REGISTER_ECX:     return "%ecx";
        case REGISTER_EDI:     return "%edi";
        case REGISTER_EDX:     return "%edx";
        case REGISTER_EIP:     return "%eip";
        case REGISTER_ESI:     return "%esi";
        case REGISTER_ESP:     return "%esp";
        case REGISTER_R8D:     return "%r8d";
        case REGISTER_R9D:     return "%r9d";
        case REGISTER_R10D:    return "%r10d";
        case REGISTER_R11D:    return "%r11d";
        case REGISTER_R12D:    return "%r12d";
        case REGISTER_R13D:    return "%r13d";
        case REGISTER_R14D:    return "%r14d";
        case REGISTER_R15D:    return "%r15d";
        case REGISTER_RAX:     return "%rax";
        case REGISTER_RBP:     return "%rbp";
        case REGISTER_RBX:     return "%rbx";
        case REGISTER_RCX:     return "%rcx";
        case REGISTER_RDI:     return "%rdi";
        case REGISTER_RDX:     return "%rdx";
        case REGISTER_RIP:     return "%rip";
        case REGISTER_RSI:     return "%rsi";
        case REGISTER_RSP:     return "%rsp";
        case REGISTER_R8:      return "%r8";
        case REGISTER_R9:      return "%r9";
        case REGISTER_R10:     return "%r10";
        case REGISTER_R11:     return "%r11";
        case REGISTER_R12:     return "%r12";
        case REGISTER_R13:     return "%r13";
        case REGISTER_R14:     return "%r14";
        case REGISTER_R15:     return "%r15";
        case REGISTER_XMM0:    return "%xmm0";
        case REGISTER_XMM1:    return "%xmm1";
        case REGISTER_XMM2:    return "%xmm2";
        case REGISTER_XMM3:    return "%xmm3";
        case REGISTER_XMM4:    return "%xmm4";
        case REGISTER_XMM5:    return "%xmm5";
        case REGISTER_XMM6:    return "%xmm6";
        case REGISTER_XMM7:    return "%xmm7";
        case REGISTER_XMM8:    return "%xmm8";
        case REGISTER_XMM9:    return "%xmm9";
        case REGISTER_XMM10:   return "%xmm10";
        case REGISTER_XMM11:   return "%xmm11";
        case REGISTER_XMM12:   return "%xmm12";
        case REGISTER_XMM13:   return "%xmm13";
        case REGISTER_XMM14:   return "%xmm14";
        case REGISTER_XMM15:   return "%xmm15";
        case REGISTER_XMM16:   return "%xmm16";
        case REGISTER_XMM17:   return "%xmm17";
        case REGISTER_XMM18:   return "%xmm18";
        case REGISTER_XMM19:   return "%xmm19";
        case REGISTER_XMM20:   return "%xmm20";
        case REGISTER_XMM21:   return "%xmm21";
        case REGISTER_XMM22:   return "%xmm22";
        case REGISTER_XMM23:   return "%xmm23";
        case REGISTER_XMM24:   return "%xmm24";
        case REGISTER_XMM25:   return "%xmm25";
        case REGISTER_XMM26:   return "%xmm26";
        case REGISTER_XMM27:   return "%xmm27";
        case REGISTER_XMM28:   return "%xmm28";
        case REGISTER_XMM29:   return "%xmm29";
        case REGISTER_XMM30:   return "%xmm30";
        case REGISTER_XMM31:   return "%xmm31";
        case REGISTER_YMM0:    return "%ymm0";
        case REGISTER_YMM1:    return "%ymm1";
        case REGISTER_YMM2:    return "%ymm2";
        case REGISTER_YMM3:    return "%ymm3";
        case REGISTER_YMM4:    return "%ymm4";
        case REGISTER_YMM5:    return "%ymm5";
        case REGISTER_YMM6:    return "%ymm6";
        case REGISTER_YMM7:    return "%ymm7";
        case REGISTER_YMM8:    return "%ymm8";
        case REGISTER_YMM9:    return "%ymm9";
        case REGISTER_YMM10:   return "%ymm10";
        case REGISTER_YMM11:   return "%ymm11";
        case REGISTER_YMM12:   return "%ymm12";
        case REGISTER_YMM13:   return "%ymm13";
        case REGISTER_YMM14:   return "%ymm14";
        case REGISTER_YMM15:   return "%ymm15";
        case REGISTER_YMM16:   return "%ymm16";
        case REGISTER_YMM17:   return "%ymm17";
        case REGISTER_YMM18:   return "%ymm18";
        case REGISTER_YMM19:   return "%ymm19";
        case REGISTER_YMM20:   return "%ymm20";
        case REGISTER_YMM21:   return "%ymm21";
        case REGISTER_YMM22:   return "%ymm22";
        case REGISTER_YMM23:   return "%ymm23";
        case REGISTER_YMM24:   return "%ymm24";
        case REGISTER_YMM25:   return "%ymm25";
        case REGISTER_YMM26:   return "%ymm26";
        case REGISTER_YMM27:   return "%ymm27";
        case REGISTER_YMM28:   return "%ymm28";
        case REGISTER_YMM29:   return "%ymm29";
        case REGISTER_YMM30:   return "%ymm30";
        case REGISTER_YMM31:   return "%ymm31";
        case REGISTER_ZMM0:    return "%zmm0";
        case REGISTER_ZMM1:    return "%zmm1";
        case REGISTER_ZMM2:    return "%zmm2";
        case REGISTER_ZMM3:    return "%zmm3";
        case REGISTER_ZMM4:    return "%zmm4";
        case REGISTER_ZMM5:    return "%zmm5";
        case REGISTER_ZMM6:    return "%zmm6";
        case REGISTER_ZMM7:    return "%zmm7";
        case REGISTER_ZMM8:    return "%zmm8";
        case REGISTER_ZMM9:    return "%zmm9";
        case REGISTER_ZMM10:   return "%zmm10";
        case REGISTER_ZMM11:   return "%zmm11";
        case REGISTER_ZMM12:   return "%zmm12";
        case REGISTER_ZMM13:   return "%zmm13";
        case REGISTER_ZMM14:   return "%zmm14";
        case REGISTER_ZMM15:   return "%zmm15";
        case REGISTER_ZMM16:   return "%zmm16";
        case REGISTER_ZMM17:   return "%zmm17";
        case REGISTER_ZMM18:   return "%zmm18";
        case REGISTER_ZMM19:   return "%zmm19";
        case REGISTER_ZMM20:   return "%zmm20";
        case REGISTER_ZMM21:   return "%zmm21";
        case REGISTER_ZMM22:   return "%zmm22";
        case REGISTER_ZMM23:   return "%zmm23";
        case REGISTER_ZMM24:   return "%zmm24";
        case REGISTER_ZMM25:   return "%zmm25";
        case REGISTER_ZMM26:   return "%zmm26";
        case REGISTER_ZMM27:   return "%zmm27";
        case REGISTER_ZMM28:   return "%zmm28";
        case REGISTER_ZMM29:   return "%zmm29";
        case REGISTER_ZMM30:   return "%zmm30";
        case REGISTER_ZMM31:   return "%zmm31";
        case REGISTER_ES:      return "%es";
        case REGISTER_CS:      return "%cs";
        case REGISTER_DS:      return "%ds";
        case REGISTER_FS:      return "%fs";
        case REGISTER_GS:      return "%gs";
        case REGISTER_SS:      return "%ss";
        case REGISTER_CR0:     return "%cr0";
        case REGISTER_CR1:     return "%cr1";
        case REGISTER_CR2:     return "%cr2";
        case REGISTER_CR3:     return "%cr3";
        case REGISTER_CR4:     return "%cr4";
        case REGISTER_CR5:     return "%cr5";
        case REGISTER_CR6:     return "%cr6";
        case REGISTER_CR7:     return "%cr7";
        case REGISTER_CR8:     return "%cr8";
        case REGISTER_CR9:     return "%cr9";
        case REGISTER_CR10:    return "%cr10";
        case REGISTER_CR11:    return "%cr11";
        case REGISTER_CR12:    return "%cr12";
        case REGISTER_CR13:    return "%cr13";
        case REGISTER_CR14:    return "%cr14";
        case REGISTER_CR15:    return "%cr15";
        case REGISTER_DR0:     return "%dr0";
        case REGISTER_DR1:     return "%dr1";
        case REGISTER_DR2:     return "%dr2";
        case REGISTER_DR3:     return "%dr3";
        case REGISTER_DR4:     return "%dr4";
        case REGISTER_DR5:     return "%dr5";
        case REGISTER_DR6:     return "%dr6";
        case REGISTER_DR7:     return "%dr7";
        case REGISTER_DR8:     return "%dr8";
        case REGISTER_DR9:     return "%dr9";
        case REGISTER_DR10:    return "%dr10";
        case REGISTER_DR11:    return "%dr11";
        case REGISTER_DR12:    return "%dr12";
        case REGISTER_DR13:    return "%dr13";
        case REGISTER_DR14:    return "%dr14";
        case REGISTER_DR15:    return "%dr15";
        case REGISTER_K0:      return "%k0";
        case REGISTER_K1:      return "%k1";
        case REGISTER_K2:      return "%k2";
        case REGISTER_K3:      return "%k3";
        case REGISTER_K4:      return "%k4";
        case REGISTER_K5:      return "%k5";
        case REGISTER_K6:      return "%k6";
        case REGISTER_K7:      return "%k7";
        case REGISTER_MM0:     return "%mm0";
        case REGISTER_MM1:     return "%mm1";
        case REGISTER_MM2:     return "%mm2";
        case REGISTER_MM3:     return "%mm3";
        case REGISTER_MM4:     return "%mm4";
        case REGISTER_MM5:     return "%mm5";
        case REGISTER_MM6:     return "%mm6";
        case REGISTER_MM7:     return "%mm7";
        case REGISTER_ST0:     return "%st0";
        case REGISTER_ST1:     return "%st1";
        case REGISTER_ST2:     return "%st2";
        case REGISTER_ST3:     return "%st3";
        case REGISTER_ST4:     return "%st4";
        case REGISTER_ST5:     return "%st5";
        case REGISTER_ST6:     return "%st6";
        case REGISTER_ST7:     return "%st7";
        case REGISTER_INVALID: return "???";
        default:               return "???";
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
static const int *getCallerSaveRegs(bool sysv, bool clean, bool state,
    bool conditional, size_t num_args)
{
    // If "state", then we must save the entire register state:
    static const int state_save[] =
    {
        RAX_IDX, RCX_IDX, RDX_IDX, RBX_IDX, RBP_IDX, RSI_IDX, RDI_IDX, R8_IDX,
        R9_IDX, R10_IDX, R11_IDX, R12_IDX, R13_IDX, R14_IDX, R15_IDX,
        RFLAGS_IDX, RSP_IDX, RIP_IDX, -1
    };
    if (state)
        return state_save;
 
    // For clean calls, we must save all caller save registers according
    // to the corresponding ABI.  Notes:
    // - To support `conditional', %rcx must be saved first.
    // - %rax must be saved before %rflags.
    static const int clean_sysv_save[] =
    {
        RCX_IDX, RAX_IDX, RFLAGS_IDX, R11_IDX, R10_IDX, R9_IDX, R8_IDX,
        RDX_IDX, RSI_IDX, RDI_IDX, -1
    };
    static const int clean_win64_save[] =
    {
        RCX_IDX, RAX_IDX, RFLAGS_IDX, R11_IDX, R10_IDX, R9_IDX, R8_IDX,
        RDX_IDX, -1
    };
    const int *clean_save = (sysv? clean_sysv_save: clean_win64_save);
    if (clean)
        return clean_save;

    // For `naked' calls, we only save the number of registers actually used
    // by args.
    static const int naked_sysv_save[] =
    {
        R11_IDX, R10_IDX, R9_IDX, R8_IDX, RCX_IDX, RDX_IDX, RSI_IDX, RDI_IDX,
        -1
    };
    static const int naked_win64_save[] =
    {
        R11_IDX, R10_IDX, R9_IDX, R8_IDX, RDX_IDX, RCX_IDX, -1
    };
    const int *naked_save = (sysv? naked_sysv_save: naked_win64_save);
    unsigned naked_len    = (sysv? 8: 6);
    if (!conditional)
        return naked_save + (naked_len - num_args);

    // For `conditional+naked' calls. %rax must be saved first:
    if (sysv)
    {
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
    else
    {
        static const int conditional_save[][10] =
        {
            {RAX_IDX, -1},
            {RAX_IDX, RCX_IDX, -1},
            {RAX_IDX, RDX_IDX, RCX_IDX, -1},
            {RAX_IDX, R8_IDX, RDX_IDX, RCX_IDX, -1},
            {RAX_IDX, R9_IDX, R8_IDX, RDX_IDX, RCX_IDX, -1},
            {RAX_IDX, R10_IDX, R9_IDX, R8_IDX, RDX_IDX, RCX_IDX, -1},
            {RAX_IDX, R11_IDX, R10_IDX, R9_IDX, R8_IDX, RDX_IDX, RCX_IDX, -1},
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
    const bool pic;                             // PIC?
    int32_t rsp_offset = 0x4000;                // Stack offset
    std::map<Register, RegInfo> info;           // Register info
    std::vector<Register> pushed;               // Pushed registers

    /*
     * Get register info.
     */
    RegInfo *getInfo(Register reg)
    {
        auto i = info.find(getCanonicalReg(reg));
        if (i == info.end())
            return nullptr;
        return &i->second;
    }

    /*
     * Get register info.
     */
    const RegInfo *getInfo(Register reg) const
    {
        auto i = info.find(getCanonicalReg(reg));
        if (i == info.end())
            return nullptr;
        return &i->second;
    }

    /*
     * Get register offset relative to the current %rsp value.
     */
    int32_t getOffset(Register reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        return rsp_offset - rinfo->offset;
    }

    /*
     * Get register saved.
     */
    bool getSaved(Register reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->saved != 0);
    }

    /*
     * Get register clobbered.
     */
    bool getClobbered(Register reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->clobbered != 0);
    }

    /*
     * Get register used.
     */
    bool getUsed(Register reg) const
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? true: rinfo->used != 0);
    }

    /*
     * Set register saved.
     */
    void setSaved(Register reg, bool saved)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->saved = saved;
    }

    /*
     * Set register clobbered.
     */
    void setClobbered(Register reg, bool clobbered)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->clobbered = clobbered;
    }

    /*
     * Set register used.
     */
    void setUsed(Register reg, bool used)
    {
        RegInfo *rinfo = getInfo(reg);
        assert(rinfo != nullptr);
        rinfo->used = used;
    }

    /*
     * Save a register.
     */
    void save(Register reg)
    {
        setSaved(reg, true);
    }

    /*
     * Check if a register is saved.
     */
    bool isSaved(Register reg) const
    {
        return getSaved(reg);
    }

    /*
     * Clobber a register.
     */
    void clobber(Register reg)
    {
        setClobbered(reg, true);
    }

    /*
     * Undo a register clobber.
     */
    void restore(Register reg)
    {
        setClobbered(reg, false);
    }

    /*
     * Check if a register is clobbered.
     */
    bool isClobbered(Register reg) const
    {
        return getClobbered(reg);
    }

    /*
     * Restore a register.
     */
    void use(Register reg)
    {
        assert(reg != REGISTER_RAX && reg != REGISTER_EFLAGS);
        setUsed(reg, true);
    }

    /*
     * Check if a register is used.
     */
    bool isUsed(Register reg) const
    {
        return getUsed(reg);
    }

    /*
     * Get a suitable scratch register.
     */
    Register getScratch(const Register *exclude = nullptr)
    {
        Register reg = REGISTER_INVALID;
        for (const auto &entry: info)
        {
            int regno = getRegIdx(entry.first);
            if (regno < 0 || regno == RFLAGS_IDX || regno == RSP_IDX ||
                    regno == RIP_IDX)
                continue;
            bool found = false;
            for (unsigned i = 0; !found && exclude != nullptr &&
                    exclude[i] != REGISTER_INVALID; i++)
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
    void push(Register reg, bool caller_save = false)
    {
        reg = getCanonicalReg(reg);
        assert(getInfo(reg) == nullptr);

        intptr_t reg_offset = 0;
        switch (reg)
        {
            case REGISTER_EFLAGS:
                rsp_offset += sizeof(int64_t);
                reg_offset = rsp_offset;
                break;
            case REGISTER_RSP:
                reg_offset = RSP_SLOT;
                break;
            case REGISTER_RIP:
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
            if (conditional && entry.first == REGISTER_RAX)
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
    Register pop()
    {
        if (pushed.size() == 0)
            return REGISTER_INVALID;
        Register reg = pushed.back();
        auto i = info.find(reg);
        assert(i != info.end());
        RegInfo &rinfo = i->second;
        if (rinfo.caller_save)
        {
            // Stop at first caller-save.  These are handled by the
            // trampoline template rather than the metadata.
            return REGISTER_INVALID;
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
    bool isCallerSave(Register reg)
    {
        const RegInfo *rinfo = getInfo(reg);
        return (rinfo == nullptr? false: rinfo->caller_save != 0);
    }

    /*
     * Constructor.
     */
    CallInfo(bool sysv, bool clean, bool state,  bool conditional,
            size_t num_args, bool before, bool pic) :
        rsave(getCallerSaveRegs(sysv, clean, state, conditional, num_args)),
        before(before), pic(pic)
    {
        for (unsigned i = 0; rsave[i] >= 0; i++)
            push(getReg(rsave[i]), /*caller_save=*/true);
        if (clean || state)
        {
            // For clean/state calls, %rax will be clobbered when %rflags
            // is pushed.
            clobber(REGISTER_RAX);
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
        // Data
        const char *filename;           // Filename.
        const uint8_t *data;            // File data.
        size_t size;                    // File size.
        intptr_t base;                  // Base address.
        intptr_t end;                   // End address.

        // Strtab
        const char *strs;

        // Program headers
        const Elf64_Phdr *phdrs;        // Elf PHDRs.
        size_t phnum;                   // Number of PHDRs.

        // Sections
        SectionInfo sections;

        // Executable sections (sorted by offset)
        std::vector<const Elf64_Shdr *> exes;

        // Symbols
        SymbolInfo dynsyms;
        SymbolInfo syms;                // Only if not stripped

        // GOT
        GOTInfo got;

        // PLT
        PLTInfo plt;

        BinaryType type;                // Binary type.
        bool reloc;                     // Needs relocation?
 
        Targets targets;                // Jump/Call targets [optional]

        mutable Symbols symbols;        // Symbol cache.
    };
};

/*
 * Options.
 */
static bool option_is_tty      = false;
static bool option_no_warnings = false;
static bool option_debug       = false;

/*
 * Backend info.
 */
struct Backend
{
    FILE *out;                      // JSON RPC output.
    pid_t pid;                      // Backend process ID.
};

#define CONTEXT_FORMAT      "%lx: %s%s%s: "
#define CONTEXT(I)          (I)->address,                           \
                            (option_is_tty? "\33[32m": ""),         \
                            (I)->string.instr,                      \
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
 * Print a debug message.
 */
void e9frontend::debug(const char *msg, ...)
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
 * Send a "options" message.
 */
unsigned e9frontend::sendOptionsMessage(FILE *out,
    std::vector<const char *> &argv)
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
    sendString(out, "$passthru");
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
unsigned e9frontend::sendPrintTrampolineMessage(FILE *out,
    e9frontend::BinaryType type)
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

            // leaq .Lstring(%rip), %rsi
            // mov $strlen,%edx
            // mov $0x2,%edi        # stderr
            // mov $0x1,%eax        # SYS_write
            fprintf(out, "%u,%u,%u,{\"rel32\":\".Lstring\"},",
                0x48, 0x8d, 0x35);
            fprintf(out, "%u,\"$asmStrLen\",", 0xba);
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
            // push %rax                # Length=asmStrLen
            // leaq .Lstring(%rip),%rax
            // push %rax                # Buffer=asmStr
            // lea 0x78(%rsp),%rax
            // push %rax                # IoStatusBlock=...
            // lea -0x20(%rsp),%rsp
            // leaq .Lconfig(%rip),%rax # E9Patch "config" struct
            //                          # (see e9loader.h)
            // mov ...(%rax),%rcx       # FileHandle=config->stderr
            // callq *...(%rax)         # call config->NtWriteFile()
            size_t stderr_offset = sizeof(struct e9_config_s) +
                offsetof(struct e9_config_pe_s, stderr);
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
            fprintf(out, "%u,\"$asmStrLen\",",
                0xb8);
            fprintf(out, "%u,", 0x50);
            fprintf(out, "%u,%u,%u,{\"rel32\":\".Lstring\"},",
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
unsigned e9frontend::sendExitTrampolineMessage(FILE *out, BinaryType type,
    int status)
{
    switch (type)
    {
        case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
            error("exit actions for Windows PE binaries are "
                "not-yet-implemented");
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
 * Send a "trap" "trampoline" message.
 */
unsigned e9frontend::sendTrapTrampolineMessage(FILE *out)
{
    sendMessageHeader(out, "trampoline");
    sendParamHeader(out, "name");
    sendString(out, "$trap");
    sendSeparator(out);
    sendParamHeader(out, "template");
    putc('[', out);
    fprintf(out, "%u,\"$instruction\",\"$continue\"", 0xcc);
    putc(']', out);
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
 * Parse the Global Offset Table (GOT).
 */
static void parseGOT(const uint8_t *data, const Elf64_Shdr *shdr_got,
    const Elf64_Shdr *shdr_rela_got, const Elf64_Sym *dynsym_tab,
    size_t dynsym_num, const char *dynstr_tab, GOTInfo &got)
{
    const Elf64_Rela *rela_tab =
        (const Elf64_Rela *)(data + shdr_rela_got->sh_offset);
    size_t rela_num = shdr_rela_got->sh_size / sizeof(Elf64_Rela);
    for (size_t i = 1; i < rela_num; i++)
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
    for (size_t i = 1; i < rela_num; i++)
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
    for (size_t i = 0; i < phnum; i++)
    {
        const Elf64_Phdr *phdr = phdrs + i;
        intptr_t phdr_base = (intptr_t)phdr->p_vaddr;
        intptr_t phdr_end  = phdr_base + phdr->p_memsz;
        end = std::max(end, phdr_end);
        if (!exe && phdr->p_type == PT_INTERP && !isLibraryFilename(filename))
            exe = true;
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
ELF *e9frontend::parsePE(const char *filename)
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
    const IMAGE_SECTION_HEADER *shdrs =
        (PIMAGE_SECTION_HEADER)&opt_hdr->DataDirectory[
            opt_hdr->NumberOfRvaAndSizes];

    /*
     * Find all sections.
     */
    SectionInfo sections;
    std::map<off_t, const Elf64_Shdr *> exes;
    std::string strtab;
    for (uint16_t i = 0; i < file_hdr->NumberOfSections; i++)
    {
        const IMAGE_SECTION_HEADER *shdr = shdrs + i;
        off_t offset  = (off_t)shdr->PointerToRawData;
        intptr_t addr = (intptr_t)shdr->VirtualAddress;
        size_t size   = (size_t)shdr->VirtualSize;
        Elf64_Shdr *elf_shdr = new Elf64_Shdr;

        uint64_t flags = 0;
        if (offset != 0)
            flags |= SHF_ALLOC;
        if ((shdr->Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
            flags |= SHF_WRITE;
        if ((shdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
            flags |= SHF_EXECINSTR;
        elf_shdr->sh_name      = strtab.size();
        elf_shdr->sh_type      = SHT_PROGBITS;
        elf_shdr->sh_flags     = flags;
        elf_shdr->sh_addr      = addr;
        elf_shdr->sh_offset    = offset;
        elf_shdr->sh_size      = size;
        elf_shdr->sh_link      = 0;
        elf_shdr->sh_info      = 0;
        elf_shdr->sh_addralign = PAGE_SIZE;
        elf_shdr->sh_entsize   = 0;

        const char *name = shdr->Name;
        strtab += shdr->Name;
        strtab += '\0';

        sections.insert({name, elf_shdr});
        if ((shdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                (shdr->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
            exes.insert({offset, elf_shdr});
    }

    ELF *elf = new ELF;
    elf->filename       = strDup(filename);
    elf->data           = data;
    elf->size           = size;
    elf->base           = (intptr_t)opt_hdr->ImageBase;
    elf->end            = elf->base + (intptr_t)opt_hdr->SizeOfImage;;
    elf->strs           = new char[strtab.size()];
    elf->phdrs          = nullptr;
    elf->phnum          = 0;
    elf->type           = BINARY_TYPE_PE_EXE;
    elf->reloc          = false;
    elf->sections.swap(sections);
    elf->exes.reserve(exes.size());
    for (const auto &entry: exes)
        elf->exes.push_back(entry.second);
    memcpy((void *)elf->strs, strtab.c_str(), strtab.size());

    return elf;
}

/*
 * Parse a binary.
 */
ELF *e9frontend::parseBinary(const char *filename, intptr_t base)
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
    switch (elf->type)
    {
        case BINARY_TYPE_PE_DLL: case BINARY_TYPE_PE_EXE:
            // For Windows PE, the ELF objects are allocated by `new':
            for (auto &entry: elf->sections)
                delete entry.second;
            delete elf->strs;
            break;
        default:
            break;
    }
    free((void *)elf->filename);
    munmap((void *)elf->data, elf->size);
    delete elf;
}

/*
 * ELF getters.
 */
e9frontend::BinaryType e9frontend::getELFType(const ELF *elf)
{
    return elf->type;
}
const char *e9frontend::getELFFilename(const ELF *elf)
{
    return elf->filename;
}
const uint8_t *e9frontend::getELFData(const ELF *elf)
{
    return elf->data;
}
size_t e9frontend::getELFDataSize(const ELF *elf)
{
    return elf->size;
}
intptr_t e9frontend::getELFBaseAddr(const ELF *elf)
{
    return elf->base;
}
intptr_t e9frontend::getELFEndAddr(const ELF *elf)
{
    return elf->end;
}
const Elf64_Shdr *e9frontend::getELFSection(const ELF *elf, const char *name)
{
    auto i = elf->sections.find(name);
    if (i == elf->sections.end())
        return nullptr;
    return i->second;
}
const Elf64_Sym *e9frontend::getELFDynSym(const ELF *elf, const char *name)
{
    auto i = elf->dynsyms.find(name);
    if (i == elf->dynsyms.end())
        return nullptr;
    return i->second;
}
const Elf64_Sym *e9frontend::getELFSym(const ELF *elf, const char *name)
{
    auto i = elf->syms.find(name);
    if (i == elf->syms.end())
        return nullptr;
    return i->second;
}
intptr_t e9frontend::getELFPLTEntry(const ELF *elf, const char *name)
{
    auto i = elf->plt.find(name);
    if (i == elf->plt.end())
        return INTPTR_MIN;
    return i->second;
}
intptr_t e9frontend::getELFGOTEntry(const ELF *elf, const char *name)
{
    auto i = elf->got.find(name);
    if (i == elf->got.end())
        return INTPTR_MIN;
    return i->second;
}
const char *e9frontend::getELFStrTab(const ELF *elf)
{
    return elf->strs;
}
extern const SectionInfo &e9frontend::getELFSectionInfo(const ELF *elf)
{
    return elf->sections;
}
extern const SymbolInfo &e9frontend::getELFDynSymInfo(const ELF *elf)
{
    return elf->dynsyms;
}
extern const SymbolInfo &e9frontend::getELFSymInfo(const ELF *elf)
{
    return elf->syms;
}
extern const GOTInfo &e9frontend::getELFGOTInfo(const ELF *elf)
{
    return elf->got;
}
extern const PLTInfo &e9frontend::getELFPLTInfo(const ELF *elf)
{
    return elf->plt;
}

/*
 * Find the address associated with the given name.
 */
static intptr_t getELFObject(const ELF *elf, const char *name)
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
static bool sendMovBetweenRegAndStack(FILE *out, Register reg, bool to_stack)
{
    uint8_t opcode = (to_stack? 0x7f: 0x6f);
    uint8_t modrm = 0;
    switch (reg)
    {
        case REGISTER_XMM0: case REGISTER_XMM8:
        case REGISTER_XMM16: case REGISTER_XMM24:
        case REGISTER_YMM0: case REGISTER_YMM8:
        case REGISTER_YMM16: case REGISTER_YMM24:
        case REGISTER_ZMM0: case REGISTER_ZMM8:
        case REGISTER_ZMM16: case REGISTER_ZMM24:
            modrm = 0x04; break;
        case REGISTER_XMM1: case REGISTER_XMM9:
        case REGISTER_XMM17: case REGISTER_XMM25:
        case REGISTER_YMM1: case REGISTER_YMM9:
        case REGISTER_YMM17: case REGISTER_YMM25:
        case REGISTER_ZMM1: case REGISTER_ZMM9:
        case REGISTER_ZMM17: case REGISTER_ZMM25:
            modrm = 0x0c; break;
        case REGISTER_XMM2: case REGISTER_XMM10:
        case REGISTER_XMM18: case REGISTER_XMM26:
        case REGISTER_YMM2: case REGISTER_YMM10:
        case REGISTER_YMM18: case REGISTER_YMM26:
        case REGISTER_ZMM2: case REGISTER_ZMM10:
        case REGISTER_ZMM18: case REGISTER_ZMM26:
            modrm = 0x14; break;
        case REGISTER_XMM3: case REGISTER_XMM11:
        case REGISTER_XMM19: case REGISTER_XMM27:
        case REGISTER_YMM3: case REGISTER_YMM11:
        case REGISTER_YMM19: case REGISTER_YMM27:
        case REGISTER_ZMM3: case REGISTER_ZMM11:
        case REGISTER_ZMM19: case REGISTER_ZMM27:
            modrm = 0x1c; break;
        case REGISTER_XMM4: case REGISTER_XMM12:
        case REGISTER_XMM20: case REGISTER_XMM28:
        case REGISTER_YMM4: case REGISTER_YMM12:
        case REGISTER_YMM20: case REGISTER_YMM28:
        case REGISTER_ZMM4: case REGISTER_ZMM12:
        case REGISTER_ZMM20: case REGISTER_ZMM28:
            modrm = 0x24; break;
        case REGISTER_XMM5: case REGISTER_XMM13:
        case REGISTER_XMM21: case REGISTER_XMM29:
        case REGISTER_YMM5: case REGISTER_YMM13:
        case REGISTER_YMM21: case REGISTER_YMM29:
        case REGISTER_ZMM5: case REGISTER_ZMM13:
        case REGISTER_ZMM21: case REGISTER_ZMM29:
            modrm = 0x2c; break;
        case REGISTER_XMM6: case REGISTER_XMM14:
        case REGISTER_XMM22: case REGISTER_XMM30:
        case REGISTER_YMM6: case REGISTER_YMM14:
        case REGISTER_YMM22: case REGISTER_YMM30:
        case REGISTER_ZMM6: case REGISTER_ZMM14:
        case REGISTER_ZMM22: case REGISTER_ZMM30:
            modrm = 0x34; break;
        case REGISTER_XMM7: case REGISTER_XMM15:
        case REGISTER_XMM23: case REGISTER_XMM31:
        case REGISTER_YMM7: case REGISTER_YMM15:
        case REGISTER_YMM23: case REGISTER_YMM31:
        case REGISTER_ZMM7: case REGISTER_ZMM15:
        case REGISTER_ZMM23: case REGISTER_ZMM31:
            modrm = 0x3c; break;
        default:
            return false;
    }

    switch (reg)
    {
        case REGISTER_XMM0: case REGISTER_XMM1: case REGISTER_XMM2:
        case REGISTER_XMM3: case REGISTER_XMM4: case REGISTER_XMM5:
        case REGISTER_XMM6: case REGISTER_XMM7:
            // movdqu %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,", 0xf3, 0x0f, opcode, modrm, 0x24);
            return true;

        case REGISTER_YMM0: case REGISTER_YMM1: case REGISTER_YMM2:
        case REGISTER_YMM3: case REGISTER_YMM4: case REGISTER_YMM5:
        case REGISTER_YMM6: case REGISTER_YMM7:
            // vmovdqu %ymm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,", 0xc5, 0xfe, opcode, modrm, 0x24);
            return true;

        case REGISTER_ZMM0: case REGISTER_ZMM1: case REGISTER_ZMM2:
        case REGISTER_ZMM3: case REGISTER_ZMM4: case REGISTER_ZMM5:
        case REGISTER_ZMM6: case REGISTER_ZMM7:
            // vmovdqu64 %zmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,", 0x62, 0xf1, 0xfe, 0x48,
                opcode, modrm, 0x24);
            return true;

        case REGISTER_XMM8: case REGISTER_XMM9: case REGISTER_XMM10:
        case REGISTER_XMM11: case REGISTER_XMM12: case REGISTER_XMM13:
        case REGISTER_XMM14: case REGISTER_XMM15:
            // movdqu %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,",
                0xf3, 0x44, 0x0f, opcode, modrm, 0x24);
            return true;

        case REGISTER_YMM8: case REGISTER_YMM9: case REGISTER_YMM10:
        case REGISTER_YMM11: case REGISTER_YMM12: case REGISTER_YMM13:
        case REGISTER_YMM14: case REGISTER_YMM15:
            // vmovdqu %ymm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,",
                0xc5, 0x7e, opcode, modrm, 0x24);
            return true;

        case REGISTER_ZMM8: case REGISTER_ZMM9: case REGISTER_ZMM10:
        case REGISTER_ZMM11: case REGISTER_ZMM12: case REGISTER_ZMM13:
        case REGISTER_ZMM14: case REGISTER_ZMM15:
            // vmovdqu64 %zmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,", 0x62, 0x71, 0xfe, 0x48,
                opcode, modrm, 0x24);
            return true;

        case REGISTER_XMM16: case REGISTER_XMM17: case REGISTER_XMM18:
        case REGISTER_XMM19: case REGISTER_XMM20: case REGISTER_XMM21:
        case REGISTER_XMM22: case REGISTER_XMM23:
            // vmovdqu64 %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0xe1, 0xfe, 0x08, opcode, modrm, 0x24);
            return true;

        case REGISTER_YMM16: case REGISTER_YMM17: case REGISTER_YMM18:
        case REGISTER_YMM19: case REGISTER_YMM20: case REGISTER_YMM21:
        case REGISTER_YMM22: case REGISTER_YMM23:
            // vmovdqu64 %ymm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0xe1, 0xfe, 0x28, opcode, modrm, 0x24);
            return true;

        case REGISTER_ZMM16: case REGISTER_ZMM17: case REGISTER_ZMM18:
        case REGISTER_ZMM19: case REGISTER_ZMM20: case REGISTER_ZMM21:
        case REGISTER_ZMM22: case REGISTER_ZMM23:
            // vmovdqu64 %zmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,", 0x62, 0xe1, 0xfe, 0x48,
                opcode, modrm, 0x24);
            return true;

        case REGISTER_XMM24: case REGISTER_XMM25: case REGISTER_XMM26:
        case REGISTER_XMM27: case REGISTER_XMM28: case REGISTER_XMM29:
        case REGISTER_XMM30: case REGISTER_XMM31:
            // vmovdqu64 %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0x61, 0xfe, 0x08, opcode, modrm, 0x24);
            return true;

        case REGISTER_YMM24: case REGISTER_YMM25: case REGISTER_YMM26:
        case REGISTER_YMM27: case REGISTER_YMM28: case REGISTER_YMM29:
        case REGISTER_YMM30: case REGISTER_YMM31:
            // vmovdqu64 %xmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,",
                0x62, 0x61, 0xfe, 0x28, opcode, modrm, 0x24);
            return true;

        case REGISTER_ZMM24: case REGISTER_ZMM25: case REGISTER_ZMM26:
        case REGISTER_ZMM27: case REGISTER_ZMM28: case REGISTER_ZMM29:
        case REGISTER_ZMM30: case REGISTER_ZMM31:
            // vmovdqu64 %zmm,(%rsp)
            fprintf(out, "%u,%u,%u,%u,%u,%u,%u,", 0x62, 0x61, 0xfe, 0x48,
                opcode, modrm, 0x24);
            return true;

        default:
            return false;
    }
}

/*
 * Send (or emulate) a push instruction.
 */
static std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
    Register reg, Register rscratch)
{
    // Special cases:
    int scratch = -1, old_scratch = -1;
    bool rax_stack = false;
    switch (reg)
    {
        case REGISTER_RIP:
        case REGISTER_RSP:
        case REGISTER_EFLAGS:
            scratch = getRegIdx(rscratch);
            assert(scratch != RSP_IDX && scratch != RFLAGS_IDX &&
                scratch != RIP_IDX);
            if (scratch < 0)
            {
                // No available scratch register.  Evict %rax to into stack
                // redzone at offset -16:
                sendMovFromR64ToStack(out, RAX_IDX, -16);
                scratch = RAX_IDX;
                rax_stack = true;
            }
            if (reg == REGISTER_EFLAGS && scratch != RAX_IDX)
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
        case REGISTER_RIP:
            if (before)
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}",
                    scratch);
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    scratch);
            sendMovFromR64ToStack(out, scratch, offset - RIP_SLOT);
            break;

        case REGISTER_RSP:
            // lea offset(%rsp),%rax
            // mov %rax,0x4000-8(%rax)
            sendLeaFromStackToR64(out, offset, scratch);
            sendMovFromR64ToStack(out, scratch, offset - RSP_SLOT);
            break;

       case REGISTER_EFLAGS:
            // seto %al
            // lahf
            assert(scratch == RAX_IDX);
            fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
            fprintf(out, "%u,", 0x9f);
            sendPush(out, offset + sizeof(int64_t), before, REGISTER_RAX);
            break;

        default:
            break;
    }
    switch (reg)
    {
        case REGISTER_RIP:
        case REGISTER_RSP:
        case REGISTER_EFLAGS:
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
static bool sendPop(FILE *out, bool preserve_rax, Register reg,
    Register rscratch)
{
    // Special cases:
    switch (reg)
    {
        case REGISTER_EFLAGS:
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

            sendPop(out, false, REGISTER_RAX);
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

        case REGISTER_RIP:
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
 * Send a `mov offset(%rip),%r64' instruction.
 */
static void sendMovFromPCRelToR64(FILE *out, int32_t offset, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    const uint8_t MODRM[] =
        {0x3d, 0x35, 0x15, 0x0d, 0x05, 0x0d, 0x00, 
         0x05, 0x15, 0x1d, 0x1d, 0x2d, 0x25, 0x2d, 0x35, 0x3d, 0x25};
    fprintf(out, "%u,%u,%u,{\"rel32\":%d},",
        REX[regno], 0x8b, MODRM[regno], offset);
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
    const std::vector<Argument> &args, BinaryType type, bool clean,
    CallKind call)
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
    bool conditional = (call == CALL_CONDITIONAL ||
                        call == CALL_CONDITIONAL_JUMP);
    const int *rsave = getCallerSaveRegs(sysv, clean, state, conditional,
        args.size());
    int num_rsave = 0;
    Register rscratch = (clean || state? REGISTER_RAX: REGISTER_INVALID);
    int32_t offset = 0x4000;
    for (int i = 0; rsave[i] >= 0; i++, num_rsave++)
    {
        sendPush(out, offset, (call != CALL_AFTER), getReg(rsave[i]), rscratch);
        if (rsave[i] != RSP_IDX && rsave[i] != RIP_IDX)
            offset += sizeof(int64_t);
    }

    // Load the arguments:
    fputs("\"$loadArgs\",", out);
    if (!sysv)
    {
        // lea -0x20(%rsp),%rsp         # MS ABI red-zone
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, -0x20);
    }

    // Call the function:
    fprintf(out, "%u,\"$function\",", 0xe8);        // callq function

    // Restore the state:
    if (!sysv)
    {
        // lea 0x20(%rsp),%rsp          # MS ABI red-zone
        fprintf(out, "%u,%u,%u,%u,{\"int8\":%d},",
            0x48, 0x8d, 0x64, 0x24, 0x20);
    }
    fputs("\"$restoreState\",", out);
    
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
            fprintf(out, "%u,{\"rel8\":\".Lskip\"},", 0xe3);
            fprintf(out, "%u,%u,", 0x48, 0x91);
        }
        else
        {
            // jrcxz .Lskip
            fprintf(out, "%u,{\"rel8\":\".Lskip\"},", 0xe3);
        }

        // The result is non-zero
        if (call == CALL_CONDITIONAL_JUMP)
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
            fputs("\"$restoreRSP\",",out);

            // jmpq *%fs:0x40
            fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                0x64, 0xff, 0x24, 0x25, tls_offset);
        }
        else
        {
            fprintf(out, "%u,", (result_rax? 0x58: 0x59));
            fputs("\"$restoreRSP\",",out);
            fputs("\"$continue\",", out);
        }
 
        // The result is zero...
        fputs("\".Lskip\",", out);
        if (result_rax)
        {
            // xchg %rax,%rcx
            fprintf(out, "%u,%u,", 0x48, 0x91);
        }
        fprintf(out, "%u,", (result_rax? 0x58: 0x59));
    }

    // Restore the stack pointer.
    fputs("\"$restoreRSP\",",out);
    
    // Put instruction here for "before" instrumentation:
    switch (call)
    {
        case CALL_BEFORE: case CALL_CONDITIONAL:
        case CALL_CONDITIONAL_JUMP:
            fputs("\"$instruction\",", out);
            break;
        default:
            break;
    }

    // Return from trampoline:
    fputs("\"$continue\"", out);

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
    if (filename[0] == '/' || filename[0] == '.')
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
static void spawnBackend(const char *prog,
    const std::vector<const char *> &options, Backend &backend)
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
        const char *argv[options.size() + 2];
        prog = findBinary(prog, /*exe=*/true, /*dot=*/true);
        argv[0] = "e9patch";
        unsigned i = 1;
        for (const char *option: options)
            argv[i++] = option;
        argv[i] = nullptr;
        execvp(prog, (char * const *)argv);
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

