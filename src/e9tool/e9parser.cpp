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

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "e9frontend.h"

using namespace e9frontend;

/*
 * Operand types.
 */
#define OP_TYPE_MAGIC       0x004F5000000000ll
#define OP_TYPE(n)          (OP_TYPE_MAGIC | (n))

#define OP_TYPE_IMM         OP_TYPE(1)
#define OP_TYPE_REG         OP_TYPE(2)
#define OP_TYPE_MEM         OP_TYPE(3)

/*
 * Access types.
 */
#define ACCESS_MAGIC        0x41434300000000ll
#define ACCESS(n)           (ACCESS_MAGIC | (n))

#define ACCESS_READ         ACCESS(0x1)
#define ACCESS_WRITE        ACCESS(0x2)

/*
 * Register names.
 */
#define REG_NAME_MAGIC      0x52454700000000ll
#define REG_NAME(r)         \
    (REG_NAME_MAGIC | (regType(r) << 16) | regIdx(r))

static constexpr intptr_t regType(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_RIP:
            return 1;

        case X86_REG_EFLAGS:
            return 2;

        case X86_REG_AH: case X86_REG_BH: case X86_REG_CH:
        case X86_REG_DH:
            return 3;

        case X86_REG_AL: case X86_REG_BL: case X86_REG_CL:
        case X86_REG_BPL: case X86_REG_DL: case X86_REG_SIL:
        case X86_REG_SPL: case X86_REG_R8B: case X86_REG_R9B:
        case X86_REG_R10B: case X86_REG_R11B: case X86_REG_R12B:
        case X86_REG_R13B: case X86_REG_R14B: case X86_REG_R15B:
            return 4;

        case X86_REG_AX: case X86_REG_BP: case X86_REG_BX:
        case X86_REG_CX: case X86_REG_DX: case X86_REG_DI:
        case X86_REG_IP: case X86_REG_SI: case X86_REG_SP:
        case X86_REG_R8W: case X86_REG_R9W: case X86_REG_R10W:
        case X86_REG_R11W: case X86_REG_R12W: case X86_REG_R13W:
        case X86_REG_R14W: case X86_REG_R15W:
            return 5;

        case X86_REG_EAX: case X86_REG_EBP: case X86_REG_EBX:
        case X86_REG_ECX: case X86_REG_EDI: case X86_REG_EDX:
        case X86_REG_EIP: case X86_REG_EIZ: case X86_REG_ESI:
        case X86_REG_ESP: case X86_REG_R8D: case X86_REG_R9D:
        case X86_REG_R10D: case X86_REG_R11D: case X86_REG_R12D:
        case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
            return 6;

        case X86_REG_RAX: case X86_REG_RBP: case X86_REG_RBX:
        case X86_REG_RCX: case X86_REG_RDI: case X86_REG_RDX:
        case X86_REG_RIZ: case X86_REG_RSI: case X86_REG_RSP:
        case X86_REG_R8: case X86_REG_R9: case X86_REG_R10:
        case X86_REG_R11: case X86_REG_R12: case X86_REG_R13:
        case X86_REG_R14: case X86_REG_R15:
            return 7;

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
            return 8;

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
            return 9;

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
            return 10;

        case X86_REG_ES: case X86_REG_CS: case X86_REG_SS:
        case X86_REG_DS: case X86_REG_FS: case X86_REG_GS:
            return 11;

        case X86_REG_CR0: case X86_REG_CR1: case X86_REG_CR2:
        case X86_REG_CR3: case X86_REG_CR4: case X86_REG_CR5:
        case X86_REG_CR6: case X86_REG_CR7: case X86_REG_CR8:
        case X86_REG_CR9: case X86_REG_CR10: case X86_REG_CR11:
        case X86_REG_CR12: case X86_REG_CR13: case X86_REG_CR14:
        case X86_REG_CR15:
            return 12;
        
        case X86_REG_DR0: case X86_REG_DR1: case X86_REG_DR2:
        case X86_REG_DR3: case X86_REG_DR4: case X86_REG_DR5:
        case X86_REG_DR6: case X86_REG_DR7: case X86_REG_DR8:
        case X86_REG_DR9: case X86_REG_DR10: case X86_REG_DR11:
        case X86_REG_DR12: case X86_REG_DR13: case X86_REG_DR14:
        case X86_REG_DR15:
            return 13;
        
        case X86_REG_FP0: case X86_REG_FP1: case X86_REG_FP2:
        case X86_REG_FP3: case X86_REG_FP4: case X86_REG_FP5:
        case X86_REG_FP6: case X86_REG_FP7:
            return 14;
 
        case X86_REG_K0: case X86_REG_K1: case X86_REG_K2:
        case X86_REG_K3: case X86_REG_K4: case X86_REG_K5:
        case X86_REG_K6: case X86_REG_K7:
            return 15;
        
        case X86_REG_MM0: case X86_REG_MM1: case X86_REG_MM2:
        case X86_REG_MM3: case X86_REG_MM4: case X86_REG_MM5:
        case X86_REG_MM6: case X86_REG_MM7:
            return 16;

        case X86_REG_ST0: case X86_REG_ST1: case X86_REG_ST2:
        case X86_REG_ST3: case X86_REG_ST4: case X86_REG_ST5:
        case X86_REG_ST6: case X86_REG_ST7:
            return 17;
        
        case X86_REG_FPSW: 
            return 18;

        default:
            return UINT8_MAX;
    }
}

static constexpr intptr_t regIdx(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH: case X86_REG_AL: case X86_REG_EFLAGS:
        case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: 
        case X86_REG_XMM0: case X86_REG_YMM0: case X86_REG_ZMM0: 
        case X86_REG_ES: case X86_REG_CR0: case X86_REG_DR0:
        case X86_REG_FP0: case X86_REG_K0: case X86_REG_MM0:
        case X86_REG_ST0: case X86_REG_FPSW:
            return 0;

        case X86_REG_CH: case X86_REG_CL: case X86_REG_CX:
        case X86_REG_ECX: case X86_REG_RCX: case X86_REG_XMM1:
        case X86_REG_YMM1: case X86_REG_ZMM1: case X86_REG_CS:
        case X86_REG_CR1: case X86_REG_DR1: case X86_REG_FP1:
        case X86_REG_K1: case X86_REG_MM1: case X86_REG_ST1:
            return 1;

        case X86_REG_DH: case X86_REG_DL: case X86_REG_DX:
        case X86_REG_EDX: case X86_REG_RDX: case X86_REG_XMM2:
        case X86_REG_YMM2: case X86_REG_ZMM2: case X86_REG_SS:
        case X86_REG_CR2: case X86_REG_DR2: case X86_REG_FP2:
        case X86_REG_K2: case X86_REG_MM2: case X86_REG_ST2:
            return 2;

        case X86_REG_BH: case X86_REG_BL: case X86_REG_BX:
        case X86_REG_EBX: case X86_REG_RBX: case X86_REG_XMM3:
        case X86_REG_YMM3: case X86_REG_ZMM3: case X86_REG_DS:
        case X86_REG_CR3: case X86_REG_DR3: case X86_REG_FP3:
        case X86_REG_K3: case X86_REG_MM3: case X86_REG_ST3:
            return 3;
        
        case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP:
        case X86_REG_RSP: case X86_REG_XMM4: case X86_REG_YMM4:
        case X86_REG_ZMM4: case X86_REG_FS: case X86_REG_CR4:
        case X86_REG_DR4: case X86_REG_FP4: case X86_REG_K4:
        case X86_REG_MM4: case X86_REG_ST4:
            return 4;
        
        case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP:
        case X86_REG_RBP: case X86_REG_XMM5: case X86_REG_YMM5:
        case X86_REG_ZMM5: case X86_REG_GS: case X86_REG_CR5:
        case X86_REG_DR5: case X86_REG_FP5: case X86_REG_K5:
        case X86_REG_MM5: case X86_REG_ST5:
            return 5;
        
        case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI:
        case X86_REG_RSI: case X86_REG_XMM6: case X86_REG_YMM6:
        case X86_REG_ZMM6: case X86_REG_CR6: case X86_REG_DR6:
        case X86_REG_FP6: case X86_REG_K6: case X86_REG_MM6:
        case X86_REG_ST6:
            return 6;
        
        case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI:
        case X86_REG_RDI: case X86_REG_XMM7: case X86_REG_YMM7:
        case X86_REG_ZMM7: case X86_REG_CR7: case X86_REG_DR7:
        case X86_REG_FP7: case X86_REG_K7: case X86_REG_MM7:
        case X86_REG_ST7:
            return 7;
        
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D:
        case X86_REG_R8: case X86_REG_XMM8: case X86_REG_YMM8:
        case X86_REG_ZMM8: case X86_REG_CR8: case X86_REG_DR8:
            return 8;
        
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D:
        case X86_REG_R9: case X86_REG_XMM9: case X86_REG_YMM9:
        case X86_REG_ZMM9: case X86_REG_CR9: case X86_REG_DR9:
            return 9;
        
        case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
        case X86_REG_R10: case X86_REG_XMM10: case X86_REG_YMM10:
        case X86_REG_ZMM10: case X86_REG_CR10: case X86_REG_DR10:
            return 10;

        case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
        case X86_REG_R11: case X86_REG_XMM11: case X86_REG_YMM11:
        case X86_REG_ZMM11: case X86_REG_CR11: case X86_REG_DR11:
            return 11;
        
        case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
        case X86_REG_R12: case X86_REG_XMM12: case X86_REG_YMM12:
        case X86_REG_ZMM12: case X86_REG_CR12: case X86_REG_DR12:
            return 12;
        
        case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
        case X86_REG_R13: case X86_REG_XMM13: case X86_REG_YMM13:
        case X86_REG_ZMM13: case X86_REG_CR13: case X86_REG_DR13:
            return 13;
        
        case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
        case X86_REG_R14: case X86_REG_XMM14: case X86_REG_YMM14:
        case X86_REG_ZMM14: case X86_REG_CR14: case X86_REG_DR14:
            return 14;
        
        case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
        case X86_REG_R15: case X86_REG_XMM15: case X86_REG_YMM15:
        case X86_REG_ZMM15: case X86_REG_CR15: case X86_REG_DR15:
            return 15;
        
        case X86_REG_XMM16: case X86_REG_YMM16: case X86_REG_ZMM16:
            return 16;
        case X86_REG_XMM17: case X86_REG_YMM17: case X86_REG_ZMM17:
            return 17;
        case X86_REG_XMM18: case X86_REG_YMM18: case X86_REG_ZMM18:
            return 18;
        case X86_REG_XMM19: case X86_REG_YMM19: case X86_REG_ZMM19:
            return 19;
        case X86_REG_XMM20: case X86_REG_YMM20: case X86_REG_ZMM20:
            return 20;
        case X86_REG_XMM21: case X86_REG_YMM21: case X86_REG_ZMM21:
            return 21;
        case X86_REG_XMM22: case X86_REG_YMM22: case X86_REG_ZMM22:
            return 22;
        case X86_REG_XMM23: case X86_REG_YMM23: case X86_REG_ZMM23:
            return 23;
        case X86_REG_XMM24: case X86_REG_YMM24: case X86_REG_ZMM24:
            return 24;
        case X86_REG_XMM25: case X86_REG_YMM25: case X86_REG_ZMM25:
            return 25;
        case X86_REG_XMM26: case X86_REG_YMM26: case X86_REG_ZMM26:
            return 26;
        case X86_REG_XMM27: case X86_REG_YMM27: case X86_REG_ZMM27:
            return 27;
        case X86_REG_XMM28: case X86_REG_YMM28: case X86_REG_ZMM28:
            return 28;
        case X86_REG_XMM29: case X86_REG_YMM29: case X86_REG_ZMM29:
            return 29;
        case X86_REG_XMM30: case X86_REG_YMM30: case X86_REG_ZMM30:
            return 30;
        case X86_REG_XMM31: case X86_REG_YMM31: case X86_REG_ZMM31:
            return 31;

        default:
            return UINT8_MAX;
    }
}

/*
 * Tokens.
 */
enum Token
{
    TOKEN_ERROR = -1,
    TOKEN_END = '\0',
    TOKEN_INTEGER = 2000,
    TOKEN_STRING,
    TOKEN_REGEX,

    // Must be in alphabetical order:
    TOKEN_MACRO_AH = 3000,
    TOKEN_MACRO_AL,
    TOKEN_MACRO_AX,
    TOKEN_MACRO_BH,
    TOKEN_MACRO_BL,
    TOKEN_MACRO_BP,
    TOKEN_MACRO_BPL,
    TOKEN_MACRO_BX,
    TOKEN_MACRO_CH,
    TOKEN_MACRO_CL,
    TOKEN_MACRO_CX,
    TOKEN_MACRO_DH,
    TOKEN_MACRO_DI,
    TOKEN_MACRO_DIL,
    TOKEN_MACRO_DL,
    TOKEN_MACRO_DX,
    TOKEN_MACRO_EAX,
    TOKEN_MACRO_EBP,
    TOKEN_MACRO_EBX,
    TOKEN_MACRO_ECX,
    TOKEN_MACRO_EDI,
    TOKEN_MACRO_EDX,
    TOKEN_MACRO_ESI,
    TOKEN_MACRO_ESP,
    TOKEN_MACRO_FALSE,
    TOKEN_MACRO_IMM,
    TOKEN_MACRO_MEM,
    TOKEN_MACRO_NIL,
    TOKEN_MACRO_R10,
    TOKEN_MACRO_R10B,
    TOKEN_MACRO_R10D,
    TOKEN_MACRO_R10W,
    TOKEN_MACRO_R11,
    TOKEN_MACRO_R11B,
    TOKEN_MACRO_R11D,
    TOKEN_MACRO_R11W,
    TOKEN_MACRO_R12,
    TOKEN_MACRO_R12B,
    TOKEN_MACRO_R12D,
    TOKEN_MACRO_R12W,
    TOKEN_MACRO_R13,
    TOKEN_MACRO_R13B,
    TOKEN_MACRO_R13D,
    TOKEN_MACRO_R13W,
    TOKEN_MACRO_R14,
    TOKEN_MACRO_R14B,
    TOKEN_MACRO_R14D,
    TOKEN_MACRO_R14W,
    TOKEN_MACRO_R15,
    TOKEN_MACRO_R15B,
    TOKEN_MACRO_R15D,
    TOKEN_MACRO_R15W,
    TOKEN_MACRO_R8,
    TOKEN_MACRO_R8B,
    TOKEN_MACRO_R8D,
    TOKEN_MACRO_R8W,
    TOKEN_MACRO_R9,
    TOKEN_MACRO_R9B,
    TOKEN_MACRO_R9D,
    TOKEN_MACRO_R9W,
    TOKEN_MACRO_RAX,
    TOKEN_MACRO_RBP,
    TOKEN_MACRO_RBX,
    TOKEN_MACRO_RCX,
    TOKEN_MACRO_RDI,
    TOKEN_MACRO_RDX,
    TOKEN_MACRO_READ,
    TOKEN_MACRO_REG,
    TOKEN_MACRO_RFLAGS,
    TOKEN_MACRO_RIP,
    TOKEN_MACRO_RSI,
    TOKEN_MACRO_RSP,
    TOKEN_MACRO_RW,
    TOKEN_MACRO_SI,
    TOKEN_MACRO_SIL,
    TOKEN_MACRO_SP,
    TOKEN_MACRO_SPL,
    TOKEN_MACRO_TRUE,
    TOKEN_MACRO_WRITE,
    TOKEN_MACRO_XMM0,
    TOKEN_MACRO_XMM1,
    TOKEN_MACRO_XMM2,
    TOKEN_MACRO_XMM3,
    TOKEN_MACRO_XMM4,
    TOKEN_MACRO_XMM5,
    TOKEN_MACRO_XMM6,
    TOKEN_MACRO_XMM7,
    TOKEN_MACRO_XMM8,
    TOKEN_MACRO_XMM9,
    TOKEN_MACRO_XMM10,
    TOKEN_MACRO_XMM11,
    TOKEN_MACRO_XMM12,
    TOKEN_MACRO_XMM13,
    TOKEN_MACRO_XMM14,
    TOKEN_MACRO_XMM15,
    TOKEN_MACRO_XMM16,
    TOKEN_MACRO_XMM17,
    TOKEN_MACRO_XMM18,
    TOKEN_MACRO_XMM19,
    TOKEN_MACRO_XMM20,
    TOKEN_MACRO_XMM21,
    TOKEN_MACRO_XMM22,
    TOKEN_MACRO_XMM23,
    TOKEN_MACRO_XMM24,
    TOKEN_MACRO_XMM25,
    TOKEN_MACRO_XMM26,
    TOKEN_MACRO_XMM27,
    TOKEN_MACRO_XMM28,
    TOKEN_MACRO_XMM29,
    TOKEN_MACRO_XMM30,
    TOKEN_MACRO_XMM31,
    TOKEN_MACRO_YMM0,
    TOKEN_MACRO_YMM1,
    TOKEN_MACRO_YMM2,
    TOKEN_MACRO_YMM3,
    TOKEN_MACRO_YMM4,
    TOKEN_MACRO_YMM5,
    TOKEN_MACRO_YMM6,
    TOKEN_MACRO_YMM7,
    TOKEN_MACRO_YMM8,
    TOKEN_MACRO_YMM9,
    TOKEN_MACRO_YMM10,
    TOKEN_MACRO_YMM11,
    TOKEN_MACRO_YMM12,
    TOKEN_MACRO_YMM13,
    TOKEN_MACRO_YMM14,
    TOKEN_MACRO_YMM15,
    TOKEN_MACRO_YMM16,
    TOKEN_MACRO_YMM17,
    TOKEN_MACRO_YMM18,
    TOKEN_MACRO_YMM19,
    TOKEN_MACRO_YMM20,
    TOKEN_MACRO_YMM21,
    TOKEN_MACRO_YMM22,
    TOKEN_MACRO_YMM23,
    TOKEN_MACRO_YMM24,
    TOKEN_MACRO_YMM25,
    TOKEN_MACRO_YMM26,
    TOKEN_MACRO_YMM27,
    TOKEN_MACRO_YMM28,
    TOKEN_MACRO_YMM29,
    TOKEN_MACRO_YMM30,
    TOKEN_MACRO_YMM31,
    TOKEN_MACRO_ZMM0,
    TOKEN_MACRO_ZMM1,
    TOKEN_MACRO_ZMM2,
    TOKEN_MACRO_ZMM3,
    TOKEN_MACRO_ZMM4,
    TOKEN_MACRO_ZMM5,
    TOKEN_MACRO_ZMM6,
    TOKEN_MACRO_ZMM7,
    TOKEN_MACRO_ZMM8,
    TOKEN_MACRO_ZMM9,
    TOKEN_MACRO_ZMM10,
    TOKEN_MACRO_ZMM11,
    TOKEN_MACRO_ZMM12,
    TOKEN_MACRO_ZMM13,
    TOKEN_MACRO_ZMM14,
    TOKEN_MACRO_ZMM15,
    TOKEN_MACRO_ZMM16,
    TOKEN_MACRO_ZMM17,
    TOKEN_MACRO_ZMM18,
    TOKEN_MACRO_ZMM19,
    TOKEN_MACRO_ZMM20,
    TOKEN_MACRO_ZMM21,
    TOKEN_MACRO_ZMM22,
    TOKEN_MACRO_ZMM23,
    TOKEN_MACRO_ZMM24,
    TOKEN_MACRO_ZMM25,
    TOKEN_MACRO_ZMM26,
    TOKEN_MACRO_ZMM27,
    TOKEN_MACRO_ZMM28,
    TOKEN_MACRO_ZMM29,
    TOKEN_MACRO_ZMM30,
    TOKEN_MACRO_ZMM31,

    TOKEN_ACCESS = 4000,
    TOKEN_ADDR,
    TOKEN_AFTER,
    TOKEN_AH,
    TOKEN_AL,
    TOKEN_AND,
    TOKEN_ASM,
    TOKEN_AX,
    TOKEN_BASE,
    TOKEN_BEFORE,
    TOKEN_BH,
    TOKEN_BL,
    TOKEN_BP,
    TOKEN_BPL,
    TOKEN_BX,
    TOKEN_CALL,
    TOKEN_CH,
    TOKEN_CL,
    TOKEN_CLEAN,
    TOKEN_CONDITIONAL,
    TOKEN_CX,
    TOKEN_DH,
    TOKEN_DI,
    TOKEN_DIL,
    TOKEN_DISPL,
    TOKEN_DL,
    TOKEN_DST,
    TOKEN_DX,
    TOKEN_EAX,
    TOKEN_EBP,
    TOKEN_EBX,
    TOKEN_ECX,
    TOKEN_EDI,
    TOKEN_EDX,
    TOKEN_ESI,
    TOKEN_ESP,
    TOKEN_FALSE,
    TOKEN_GEQ,
    TOKEN_IMM,
    TOKEN_INDEX,
    TOKEN_INSTR,
    TOKEN_JUMP,
    TOKEN_LENGTH,
    TOKEN_LEQ,
    TOKEN_MEM,
    TOKEN_MNEMONIC,
    TOKEN_NAKED,
    TOKEN_NEQ,
    TOKEN_NEXT,
    TOKEN_NOT,
    TOKEN_OFFSET,
    TOKEN_OP,
    TOKEN_OR,
    TOKEN_PASSTHRU,
    TOKEN_PLUGIN,
    TOKEN_PRINT,
    TOKEN_R10,
    TOKEN_R10B,
    TOKEN_R10D,
    TOKEN_R10W,
    TOKEN_R11,
    TOKEN_R11B,
    TOKEN_R11D,
    TOKEN_R11W,
    TOKEN_R12,
    TOKEN_R12B,
    TOKEN_R12D,
    TOKEN_R12W,
    TOKEN_R13,
    TOKEN_R13B,
    TOKEN_R13D,
    TOKEN_R13W,
    TOKEN_R14,
    TOKEN_R14B,
    TOKEN_R14D,
    TOKEN_R14W,
    TOKEN_R15,
    TOKEN_R15B,
    TOKEN_R15D,
    TOKEN_R15W,
    TOKEN_R8,
    TOKEN_R8B,
    TOKEN_R8D,
    TOKEN_R8W,
    TOKEN_R9,
    TOKEN_R9B,
    TOKEN_R9D,
    TOKEN_R9W,
    TOKEN_RANDOM,
    TOKEN_RAX,
    TOKEN_RBP,
    TOKEN_RBX,
    TOKEN_RCX,
    TOKEN_RDI,
    TOKEN_RDX,
    TOKEN_READ,             // TODO: remove
    TOKEN_REG,
    TOKEN_REPLACE,
    TOKEN_RETURN,
    TOKEN_RFLAGS,
    TOKEN_RIP,
    TOKEN_RSI,
    TOKEN_RSP,
    TOKEN_SCALE,
    TOKEN_SI,
    TOKEN_SIL,
    TOKEN_SIZE,
    TOKEN_SP,
    TOKEN_SPL,
    TOKEN_SRC,
    TOKEN_STATIC_ADDR,
    TOKEN_TARGET,
    TOKEN_TRAMPOLINE,
    TOKEN_TRAP,
    TOKEN_TRUE,
    TOKEN_TYPE,
    TOKEN_WRITE             // TODO: remove
};

/*
 * Token info.
 */
struct TokenInfo
{
    const char *name;
    Token token;
};

/*
 * Macro info.
 */
struct MacroInfo
{
    Token token;
    intptr_t value;
};

/*
 * All tokens.
 */
static const TokenInfo tokens[] =
{
    {"!",           (Token)'!'},
    {"!=",          TOKEN_NEQ},
    {"&",           (Token)'&'},
    {"&&",          TOKEN_AND},
    {"(",           (Token)'('},
    {")",           (Token)')'},
    {",",           (Token)','},
    {".",           (Token)'.'},
    {"<",           (Token)'<'},
    {"<=",          TOKEN_LEQ},
    {"=",           (Token)'='},
    {"==",          (Token)'='},
    {">",           (Token)'>'},
    {">=",          TOKEN_GEQ},
    {"@",           (Token)'@'},
    {"AH",          TOKEN_MACRO_AH},
    {"AL",          TOKEN_MACRO_AL},
    {"AX",          TOKEN_MACRO_AX},
    {"BH",          TOKEN_MACRO_BH},
    {"BL",          TOKEN_MACRO_BL},
    {"BP",          TOKEN_MACRO_BP},
    {"BPL",         TOKEN_MACRO_BPL},
    {"BX",          TOKEN_MACRO_BX},
    {"CH",          TOKEN_MACRO_CH},
    {"CL",          TOKEN_MACRO_CL},
    {"CX",          TOKEN_MACRO_CX},
    {"DH",          TOKEN_MACRO_DH},
    {"DI",          TOKEN_MACRO_DI},
    {"DIL",         TOKEN_MACRO_DIL},
    {"DL",          TOKEN_MACRO_DL},
    {"DX",          TOKEN_MACRO_DX},
    {"EAX",         TOKEN_MACRO_EAX},
    {"EBP",         TOKEN_MACRO_EBP},
    {"EBX",         TOKEN_MACRO_EBX},
    {"ECX",         TOKEN_MACRO_ECX},
    {"EDI",         TOKEN_MACRO_EDI},
    {"EDX",         TOKEN_MACRO_EDX},
    {"ESI",         TOKEN_MACRO_ESI},
    {"ESP",         TOKEN_MACRO_ESP},
    {"FALSE",       TOKEN_MACRO_FALSE},
    {"IMM",         TOKEN_MACRO_IMM},
    {"MEM",         TOKEN_MACRO_MEM},
    {"NIL",         TOKEN_MACRO_NIL},
    {"R10",         TOKEN_MACRO_R10},
    {"R10B",        TOKEN_MACRO_R10B},
    {"R10D",        TOKEN_MACRO_R10D},
    {"R10W",        TOKEN_MACRO_R10W},
    {"R11",         TOKEN_MACRO_R11},
    {"R11B",        TOKEN_MACRO_R11B},
    {"R11D",        TOKEN_MACRO_R11D},
    {"R11W",        TOKEN_MACRO_R11W},
    {"R12",         TOKEN_MACRO_R12},
    {"R12B",        TOKEN_MACRO_R12B},
    {"R12D",        TOKEN_MACRO_R12D},
    {"R12W",        TOKEN_MACRO_R12W},
    {"R13",         TOKEN_MACRO_R13},
    {"R13B",        TOKEN_MACRO_R13B},
    {"R13D",        TOKEN_MACRO_R13D},
    {"R13W",        TOKEN_MACRO_R13W},
    {"R14",         TOKEN_MACRO_R14},
    {"R14B",        TOKEN_MACRO_R14B},
    {"R14D",        TOKEN_MACRO_R14D},
    {"R14W",        TOKEN_MACRO_R14W},
    {"R15",         TOKEN_MACRO_R15},
    {"R15B",        TOKEN_MACRO_R15B},
    {"R15D",        TOKEN_MACRO_R15D},
    {"R15W",        TOKEN_MACRO_R15W},
    {"R8",          TOKEN_MACRO_R8},
    {"R8B",         TOKEN_MACRO_R8B},
    {"R8D",         TOKEN_MACRO_R8D},
    {"R8W",         TOKEN_MACRO_R8W},
    {"R9",          TOKEN_MACRO_R9},
    {"R9B",         TOKEN_MACRO_R8B},
    {"R9D",         TOKEN_MACRO_R8D},
    {"R9W",         TOKEN_MACRO_R8W},
    {"RAX",         TOKEN_MACRO_RAX},
    {"RBP",         TOKEN_MACRO_RBP},
    {"RBX",         TOKEN_MACRO_RBX},
    {"RCX",         TOKEN_MACRO_RCX},
    {"RDI",         TOKEN_MACRO_RDI},
    {"RDX",         TOKEN_MACRO_RDX},
    {"READ",        TOKEN_MACRO_READ},
    {"REG",         TOKEN_MACRO_REG},
    {"RFLAGS",      TOKEN_MACRO_RFLAGS},
    {"RIP",         TOKEN_MACRO_RIP},
    {"RSI",         TOKEN_MACRO_RSI},
    {"RSP",         TOKEN_MACRO_RSP},
    {"RW",          TOKEN_MACRO_RW},
    {"SI",          TOKEN_MACRO_SI},
    {"SIL",         TOKEN_MACRO_SIL},
    {"SP",          TOKEN_MACRO_SP},
    {"SPL",         TOKEN_MACRO_SPL},
    {"TRUE",        TOKEN_MACRO_TRUE},
    {"WRITE",       TOKEN_MACRO_WRITE},
    {"XMM0",        TOKEN_MACRO_XMM0},
    {"XMM1",        TOKEN_MACRO_XMM1},
    {"XMM10",       TOKEN_MACRO_XMM10},
    {"XMM11",       TOKEN_MACRO_XMM11},
    {"XMM12",       TOKEN_MACRO_XMM12},
    {"XMM13",       TOKEN_MACRO_XMM13},
    {"XMM14",       TOKEN_MACRO_XMM14},
    {"XMM15",       TOKEN_MACRO_XMM15},
    {"XMM16",       TOKEN_MACRO_XMM16},
    {"XMM17",       TOKEN_MACRO_XMM17},
    {"XMM18",       TOKEN_MACRO_XMM18},
    {"XMM19",       TOKEN_MACRO_XMM19},
    {"XMM2",        TOKEN_MACRO_XMM2},
    {"XMM20",       TOKEN_MACRO_XMM20},
    {"XMM21",       TOKEN_MACRO_XMM21},
    {"XMM22",       TOKEN_MACRO_XMM22},
    {"XMM23",       TOKEN_MACRO_XMM23},
    {"XMM24",       TOKEN_MACRO_XMM24},
    {"XMM25",       TOKEN_MACRO_XMM25},
    {"XMM26",       TOKEN_MACRO_XMM26},
    {"XMM27",       TOKEN_MACRO_XMM27},
    {"XMM28",       TOKEN_MACRO_XMM28},
    {"XMM29",       TOKEN_MACRO_XMM29},
    {"XMM3",        TOKEN_MACRO_XMM3},
    {"XMM30",       TOKEN_MACRO_XMM30},
    {"XMM31",       TOKEN_MACRO_XMM31},
    {"XMM4",        TOKEN_MACRO_XMM4},
    {"XMM5",        TOKEN_MACRO_XMM5},
    {"XMM6",        TOKEN_MACRO_XMM6},
    {"XMM7",        TOKEN_MACRO_XMM7},
    {"XMM8",        TOKEN_MACRO_XMM8},
    {"XMM9",        TOKEN_MACRO_XMM9},
    {"YMM0",        TOKEN_MACRO_YMM0},
    {"YMM1",        TOKEN_MACRO_YMM1},
    {"YMM10",       TOKEN_MACRO_YMM10},
    {"YMM11",       TOKEN_MACRO_YMM11},
    {"YMM12",       TOKEN_MACRO_YMM12},
    {"YMM13",       TOKEN_MACRO_YMM13},
    {"YMM14",       TOKEN_MACRO_YMM14},
    {"YMM15",       TOKEN_MACRO_YMM15},
    {"YMM16",       TOKEN_MACRO_YMM16},
    {"YMM17",       TOKEN_MACRO_YMM17},
    {"YMM18",       TOKEN_MACRO_YMM18},
    {"YMM19",       TOKEN_MACRO_YMM19},
    {"YMM2",        TOKEN_MACRO_YMM2},
    {"YMM20",       TOKEN_MACRO_YMM20},
    {"YMM21",       TOKEN_MACRO_YMM21},
    {"YMM22",       TOKEN_MACRO_YMM22},
    {"YMM23",       TOKEN_MACRO_YMM23},
    {"YMM24",       TOKEN_MACRO_YMM24},
    {"YMM25",       TOKEN_MACRO_YMM25},
    {"YMM26",       TOKEN_MACRO_YMM26},
    {"YMM27",       TOKEN_MACRO_YMM27},
    {"YMM28",       TOKEN_MACRO_YMM28},
    {"YMM29",       TOKEN_MACRO_YMM29},
    {"YMM3",        TOKEN_MACRO_YMM3},
    {"YMM30",       TOKEN_MACRO_YMM30},
    {"YMM31",       TOKEN_MACRO_YMM31},
    {"YMM4",        TOKEN_MACRO_YMM4},
    {"YMM5",        TOKEN_MACRO_YMM5},
    {"YMM6",        TOKEN_MACRO_YMM6},
    {"YMM7",        TOKEN_MACRO_YMM7},
    {"YMM8",        TOKEN_MACRO_YMM8},
    {"YMM9",        TOKEN_MACRO_YMM9},
    {"ZMM0",        TOKEN_MACRO_ZMM0},
    {"ZMM1",        TOKEN_MACRO_ZMM1},
    {"ZMM10",       TOKEN_MACRO_ZMM10},
    {"ZMM11",       TOKEN_MACRO_ZMM11},
    {"ZMM12",       TOKEN_MACRO_ZMM12},
    {"ZMM13",       TOKEN_MACRO_ZMM13},
    {"ZMM14",       TOKEN_MACRO_ZMM14},
    {"ZMM15",       TOKEN_MACRO_ZMM15},
    {"ZMM16",       TOKEN_MACRO_ZMM16},
    {"ZMM17",       TOKEN_MACRO_ZMM17},
    {"ZMM18",       TOKEN_MACRO_ZMM18},
    {"ZMM19",       TOKEN_MACRO_ZMM19},
    {"ZMM2",        TOKEN_MACRO_ZMM2},
    {"ZMM20",       TOKEN_MACRO_ZMM20},
    {"ZMM21",       TOKEN_MACRO_ZMM21},
    {"ZMM22",       TOKEN_MACRO_ZMM22},
    {"ZMM23",       TOKEN_MACRO_ZMM23},
    {"ZMM24",       TOKEN_MACRO_ZMM24},
    {"ZMM25",       TOKEN_MACRO_ZMM25},
    {"ZMM26",       TOKEN_MACRO_ZMM26},
    {"ZMM27",       TOKEN_MACRO_ZMM27},
    {"ZMM28",       TOKEN_MACRO_ZMM28},
    {"ZMM29",       TOKEN_MACRO_ZMM29},
    {"ZMM3",        TOKEN_MACRO_ZMM3},
    {"ZMM30",       TOKEN_MACRO_ZMM30},
    {"ZMM31",       TOKEN_MACRO_ZMM31},
    {"ZMM4",        TOKEN_MACRO_ZMM4},
    {"ZMM5",        TOKEN_MACRO_ZMM5},
    {"ZMM6",        TOKEN_MACRO_ZMM6},
    {"ZMM7",        TOKEN_MACRO_ZMM7},
    {"ZMM8",        TOKEN_MACRO_ZMM8},
    {"ZMM9",        TOKEN_MACRO_ZMM9},
    {"[",           (Token)'['},
    {"]",           (Token)']'},
    {"access",      TOKEN_ACCESS},
    {"addr",        TOKEN_ADDR},
    {"address",     TOKEN_ADDR},
    {"after",       TOKEN_AFTER},
    {"ah",          TOKEN_AH},
    {"al",          TOKEN_AL},
    {"and",         TOKEN_AND},
    {"asm",         TOKEN_ASM},
    {"ax",          TOKEN_AX},
    {"base",        TOKEN_BASE},
    {"before",      TOKEN_BEFORE},
    {"bh",          TOKEN_BH},
    {"bl",          TOKEN_BL},
    {"bp",          TOKEN_BP},
    {"bpl",         TOKEN_BPL},
    {"bx",          TOKEN_BX},
    {"call",        TOKEN_CALL},
    {"ch",          TOKEN_CH},
    {"cl",          TOKEN_CL},
    {"clean",       TOKEN_CLEAN},
    {"conditional", TOKEN_CONDITIONAL},
    {"cx",          TOKEN_CX},
    {"dh",          TOKEN_DH},
    {"di",          TOKEN_DI},
    {"dil",         TOKEN_DIL},
    {"displ",       TOKEN_DISPL},
    {"dl",          TOKEN_DL},
    {"dst",         TOKEN_DST},
    {"dx",          TOKEN_DX},
    {"eax",         TOKEN_EAX},
    {"ebp",         TOKEN_EBP},
    {"ebx",         TOKEN_EBX},
    {"ecx",         TOKEN_ECX},
    {"edi",         TOKEN_EDI},
    {"edx",         TOKEN_EDX},
    {"esi",         TOKEN_ESI},
    {"esp",         TOKEN_ESP},
    {"false",       TOKEN_FALSE},
    {"imm",         TOKEN_IMM},
    {"index",       TOKEN_INDEX},
    {"instr",       TOKEN_INSTR},
    {"jump",        TOKEN_JUMP},
    {"len",         TOKEN_LENGTH},
    {"length",      TOKEN_LENGTH},
    {"mem",         TOKEN_MEM},
    {"mnemonic",    TOKEN_MNEMONIC},
    {"naked",       TOKEN_NAKED},
    {"next",        TOKEN_NEXT},
    {"not",         TOKEN_NOT},
    {"offset",      TOKEN_OFFSET},
    {"op",          TOKEN_OP},
    {"or",          TOKEN_OR},
    {"passthru",    TOKEN_PASSTHRU},
    {"plugin",      TOKEN_PLUGIN},
    {"print",       TOKEN_PRINT},
    {"r10",         TOKEN_R10},
    {"r10b",        TOKEN_R10B},
    {"r10d",        TOKEN_R10D},
    {"r10w",        TOKEN_R10W},
    {"r11",         TOKEN_R11},
    {"r11b",        TOKEN_R11B},
    {"r11d",        TOKEN_R11D},
    {"r11w",        TOKEN_R11W},
    {"r12",         TOKEN_R12},
    {"r12b",        TOKEN_R12B},
    {"r12d",        TOKEN_R12D},
    {"r12w",        TOKEN_R12W},
    {"r13",         TOKEN_R13},
    {"r13b",        TOKEN_R13B},
    {"r13d",        TOKEN_R13D},
    {"r13w",        TOKEN_R13W},
    {"r14",         TOKEN_R14},
    {"r14b",        TOKEN_R14B},
    {"r14d",        TOKEN_R14D},
    {"r14w",        TOKEN_R14W},
    {"r15",         TOKEN_R15},
    {"r15b",        TOKEN_R15B},
    {"r15d",        TOKEN_R15D},
    {"r15w",        TOKEN_R15W},
    {"r8",          TOKEN_R8},
    {"r8b",         TOKEN_R8B},
    {"r8d",         TOKEN_R8D},
    {"r8w",         TOKEN_R8W},
    {"r9",          TOKEN_R9},
    {"r9b",         TOKEN_R9B},
    {"r9d",         TOKEN_R9D},
    {"r9w",         TOKEN_R9W},
    {"random",      TOKEN_RANDOM},
    {"rax",         TOKEN_RAX},
    {"rbp",         TOKEN_RBP},
    {"rbx",         TOKEN_RBX},
    {"rcx",         TOKEN_RCX},
    {"rdi",         TOKEN_RDI},
    {"rdx",         TOKEN_RDX},
    {"read",        TOKEN_READ},
    {"reg",         TOKEN_REG},
    {"replace",     TOKEN_REPLACE},
    {"return",      TOKEN_RETURN},
    {"rflags",      TOKEN_RFLAGS},
    {"rip",         TOKEN_RIP},
    {"rsi",         TOKEN_RSI},
    {"rsp",         TOKEN_RSP},
    {"scale",       TOKEN_SCALE},
    {"si",          TOKEN_SI},
    {"sil",         TOKEN_SIL},
    {"size",        TOKEN_SIZE},
    {"sp",          TOKEN_SP},
    {"spl",         TOKEN_SPL},
    {"src",         TOKEN_SRC},
    {"staticAddr",  TOKEN_STATIC_ADDR},
    {"target",      TOKEN_TARGET},
    {"trampoline",  TOKEN_TRAMPOLINE},
    {"trap",        TOKEN_TRAP},
    {"true",        TOKEN_TRUE},
    {"type",        TOKEN_TYPE},
    {"write",       TOKEN_WRITE},
    {"||",          TOKEN_OR},
};

static const MacroInfo macros[] =
{
    {TOKEN_MACRO_AH,     REG_NAME(X86_REG_AH)},      
    {TOKEN_MACRO_AL,     REG_NAME(X86_REG_AL)},
    {TOKEN_MACRO_AX,     REG_NAME(X86_REG_AX)},
    {TOKEN_MACRO_BH,     REG_NAME(X86_REG_BH)},
    {TOKEN_MACRO_BL,     REG_NAME(X86_REG_BL)},
    {TOKEN_MACRO_BP,     REG_NAME(X86_REG_BP)},
    {TOKEN_MACRO_BPL,    REG_NAME(X86_REG_BPL)},
    {TOKEN_MACRO_BX,     REG_NAME(X86_REG_BX)},
    {TOKEN_MACRO_CH,     REG_NAME(X86_REG_CH)},
    {TOKEN_MACRO_CL,     REG_NAME(X86_REG_CL)},
    {TOKEN_MACRO_CX,     REG_NAME(X86_REG_CX)},
    {TOKEN_MACRO_DH,     REG_NAME(X86_REG_DH)},
    {TOKEN_MACRO_DI,     REG_NAME(X86_REG_DI)},
    {TOKEN_MACRO_DIL,    REG_NAME(X86_REG_DIL)},
    {TOKEN_MACRO_DL,     REG_NAME(X86_REG_DL)},
    {TOKEN_MACRO_DX,     REG_NAME(X86_REG_DX)},
    {TOKEN_MACRO_EAX,    REG_NAME(X86_REG_EAX)},
    {TOKEN_MACRO_EBP,    REG_NAME(X86_REG_EBP)},
    {TOKEN_MACRO_EBX,    REG_NAME(X86_REG_EBX)},
    {TOKEN_MACRO_ECX,    REG_NAME(X86_REG_ECX)},
    {TOKEN_MACRO_EDI,    REG_NAME(X86_REG_EDI)},
    {TOKEN_MACRO_EDX,    REG_NAME(X86_REG_EDX)},
    {TOKEN_MACRO_ESI,    REG_NAME(X86_REG_ESI)},
    {TOKEN_MACRO_ESP,    REG_NAME(X86_REG_ESP)},
    {TOKEN_MACRO_FALSE,  false},
    {TOKEN_MACRO_IMM,    OP_TYPE_IMM},
    {TOKEN_MACRO_MEM,    OP_TYPE_MEM},
    {TOKEN_MACRO_NIL,    0},
    {TOKEN_MACRO_R10,    REG_NAME(X86_REG_R10)},
    {TOKEN_MACRO_R10B,   REG_NAME(X86_REG_R10B)},
    {TOKEN_MACRO_R10D,   REG_NAME(X86_REG_R10D)},
    {TOKEN_MACRO_R10W,   REG_NAME(X86_REG_R10W)},
    {TOKEN_MACRO_R11,    REG_NAME(X86_REG_R11)},
    {TOKEN_MACRO_R11B,   REG_NAME(X86_REG_R11B)},
    {TOKEN_MACRO_R11D,   REG_NAME(X86_REG_R11D)},
    {TOKEN_MACRO_R11W,   REG_NAME(X86_REG_R11W)},
    {TOKEN_MACRO_R12,    REG_NAME(X86_REG_R12)},
    {TOKEN_MACRO_R12B,   REG_NAME(X86_REG_R12B)},
    {TOKEN_MACRO_R12D,   REG_NAME(X86_REG_R12D)},
    {TOKEN_MACRO_R12W,   REG_NAME(X86_REG_R12W)},
    {TOKEN_MACRO_R13,    REG_NAME(X86_REG_R13)},
    {TOKEN_MACRO_R13B,   REG_NAME(X86_REG_R13B)},
    {TOKEN_MACRO_R13D,   REG_NAME(X86_REG_R13D)},
    {TOKEN_MACRO_R13W,   REG_NAME(X86_REG_R13W)},
    {TOKEN_MACRO_R14,    REG_NAME(X86_REG_R14)},
    {TOKEN_MACRO_R14B,   REG_NAME(X86_REG_R14B)},
    {TOKEN_MACRO_R14D,   REG_NAME(X86_REG_R14D)},
    {TOKEN_MACRO_R14W,   REG_NAME(X86_REG_R14W)},
    {TOKEN_MACRO_R15,    REG_NAME(X86_REG_R15)},
    {TOKEN_MACRO_R15B,   REG_NAME(X86_REG_R15B)},
    {TOKEN_MACRO_R15D,   REG_NAME(X86_REG_R15D)},
    {TOKEN_MACRO_R15W,   REG_NAME(X86_REG_R15W)},
    {TOKEN_MACRO_R8,     REG_NAME(X86_REG_R8)},
    {TOKEN_MACRO_R8B,    REG_NAME(X86_REG_R8B)},
    {TOKEN_MACRO_R8D,    REG_NAME(X86_REG_R8D)},
    {TOKEN_MACRO_R8W,    REG_NAME(X86_REG_R8W)},
    {TOKEN_MACRO_R9,     REG_NAME(X86_REG_R9)},
    {TOKEN_MACRO_R9B,    REG_NAME(X86_REG_R9B)},
    {TOKEN_MACRO_R9D,    REG_NAME(X86_REG_R9D)},
    {TOKEN_MACRO_R9W,    REG_NAME(X86_REG_R9W)},
    {TOKEN_MACRO_RAX,    REG_NAME(X86_REG_RAX)},
    {TOKEN_MACRO_RBP,    REG_NAME(X86_REG_RBP)},
    {TOKEN_MACRO_RBX,    REG_NAME(X86_REG_RBX)},
    {TOKEN_MACRO_RCX,    REG_NAME(X86_REG_RCX)},
    {TOKEN_MACRO_RDI,    REG_NAME(X86_REG_RDI)},
    {TOKEN_MACRO_RDX,    REG_NAME(X86_REG_RDX)},
    {TOKEN_MACRO_READ,   ACCESS_READ},
    {TOKEN_MACRO_REG,    OP_TYPE_REG},
    {TOKEN_MACRO_RFLAGS, REG_NAME(X86_REG_EFLAGS)},
    {TOKEN_MACRO_RIP,    REG_NAME(X86_REG_RIP)},
    {TOKEN_MACRO_RSI,    REG_NAME(X86_REG_RSI)},
    {TOKEN_MACRO_RSP,    REG_NAME(X86_REG_RSP)},
    {TOKEN_MACRO_RW,     ACCESS_READ | ACCESS_WRITE},
    {TOKEN_MACRO_SI,     REG_NAME(X86_REG_SI)},
    {TOKEN_MACRO_SIL,    REG_NAME(X86_REG_SIL)},
    {TOKEN_MACRO_SP,     REG_NAME(X86_REG_SP)},
    {TOKEN_MACRO_SPL,    REG_NAME(X86_REG_SPL)},
    {TOKEN_MACRO_TRUE,   true},
    {TOKEN_MACRO_WRITE,  ACCESS_WRITE},
    {TOKEN_MACRO_XMM0,   REG_NAME(X86_REG_XMM0)},
    {TOKEN_MACRO_XMM1,   REG_NAME(X86_REG_XMM1)}, 
    {TOKEN_MACRO_XMM2,   REG_NAME(X86_REG_XMM2)},
    {TOKEN_MACRO_XMM3,   REG_NAME(X86_REG_XMM3)},
    {TOKEN_MACRO_XMM4,   REG_NAME(X86_REG_XMM4)}, 
    {TOKEN_MACRO_XMM5,   REG_NAME(X86_REG_XMM5)}, 
    {TOKEN_MACRO_XMM6,   REG_NAME(X86_REG_XMM6)}, 
    {TOKEN_MACRO_XMM7,   REG_NAME(X86_REG_XMM7)}, 
    {TOKEN_MACRO_XMM8,   REG_NAME(X86_REG_XMM8)},  
    {TOKEN_MACRO_XMM9,   REG_NAME(X86_REG_XMM9)},  
    {TOKEN_MACRO_XMM10,  REG_NAME(X86_REG_XMM10)},  
    {TOKEN_MACRO_XMM11,  REG_NAME(X86_REG_XMM11)},  
    {TOKEN_MACRO_XMM12,  REG_NAME(X86_REG_XMM12)},  
    {TOKEN_MACRO_XMM13,  REG_NAME(X86_REG_XMM13)},  
    {TOKEN_MACRO_XMM14,  REG_NAME(X86_REG_XMM14)},  
    {TOKEN_MACRO_XMM15,  REG_NAME(X86_REG_XMM15)},  
    {TOKEN_MACRO_XMM16,  REG_NAME(X86_REG_XMM16)},  
    {TOKEN_MACRO_XMM17,  REG_NAME(X86_REG_XMM17)},  
    {TOKEN_MACRO_XMM18,  REG_NAME(X86_REG_XMM18)},  
    {TOKEN_MACRO_XMM19,  REG_NAME(X86_REG_XMM19)},  
    {TOKEN_MACRO_XMM20,  REG_NAME(X86_REG_XMM20)},  
    {TOKEN_MACRO_XMM21,  REG_NAME(X86_REG_XMM21)},  
    {TOKEN_MACRO_XMM22,  REG_NAME(X86_REG_XMM22)},  
    {TOKEN_MACRO_XMM23,  REG_NAME(X86_REG_XMM23)},  
    {TOKEN_MACRO_XMM24,  REG_NAME(X86_REG_XMM24)},  
    {TOKEN_MACRO_XMM25,  REG_NAME(X86_REG_XMM25)},  
    {TOKEN_MACRO_XMM26,  REG_NAME(X86_REG_XMM26)},  
    {TOKEN_MACRO_XMM27,  REG_NAME(X86_REG_XMM27)},  
    {TOKEN_MACRO_XMM28,  REG_NAME(X86_REG_XMM28)},  
    {TOKEN_MACRO_XMM29,  REG_NAME(X86_REG_XMM29)},   
    {TOKEN_MACRO_XMM30,  REG_NAME(X86_REG_XMM30)},  
    {TOKEN_MACRO_XMM31,  REG_NAME(X86_REG_XMM31)},  
    {TOKEN_MACRO_YMM0,   REG_NAME(X86_REG_YMM0)},
    {TOKEN_MACRO_YMM1,   REG_NAME(X86_REG_YMM1)}, 
    {TOKEN_MACRO_YMM2,   REG_NAME(X86_REG_YMM2)},
    {TOKEN_MACRO_YMM3,   REG_NAME(X86_REG_YMM3)},
    {TOKEN_MACRO_YMM4,   REG_NAME(X86_REG_YMM4)}, 
    {TOKEN_MACRO_YMM5,   REG_NAME(X86_REG_YMM5)}, 
    {TOKEN_MACRO_YMM6,   REG_NAME(X86_REG_YMM6)}, 
    {TOKEN_MACRO_YMM7,   REG_NAME(X86_REG_YMM7)}, 
    {TOKEN_MACRO_YMM8,   REG_NAME(X86_REG_YMM8)},  
    {TOKEN_MACRO_YMM9,   REG_NAME(X86_REG_YMM9)},  
    {TOKEN_MACRO_YMM10,  REG_NAME(X86_REG_YMM10)},  
    {TOKEN_MACRO_YMM11,  REG_NAME(X86_REG_YMM11)},  
    {TOKEN_MACRO_YMM12,  REG_NAME(X86_REG_YMM12)},  
    {TOKEN_MACRO_YMM13,  REG_NAME(X86_REG_YMM13)},  
    {TOKEN_MACRO_YMM14,  REG_NAME(X86_REG_YMM14)},  
    {TOKEN_MACRO_YMM15,  REG_NAME(X86_REG_YMM15)},  
    {TOKEN_MACRO_YMM16,  REG_NAME(X86_REG_YMM16)},  
    {TOKEN_MACRO_YMM17,  REG_NAME(X86_REG_YMM17)},  
    {TOKEN_MACRO_YMM18,  REG_NAME(X86_REG_YMM18)},  
    {TOKEN_MACRO_YMM19,  REG_NAME(X86_REG_YMM19)},  
    {TOKEN_MACRO_YMM20,  REG_NAME(X86_REG_YMM20)},  
    {TOKEN_MACRO_YMM21,  REG_NAME(X86_REG_YMM21)},  
    {TOKEN_MACRO_YMM22,  REG_NAME(X86_REG_YMM22)},  
    {TOKEN_MACRO_YMM23,  REG_NAME(X86_REG_YMM23)},  
    {TOKEN_MACRO_YMM24,  REG_NAME(X86_REG_YMM24)},  
    {TOKEN_MACRO_YMM25,  REG_NAME(X86_REG_YMM25)},  
    {TOKEN_MACRO_YMM26,  REG_NAME(X86_REG_YMM26)},  
    {TOKEN_MACRO_YMM27,  REG_NAME(X86_REG_YMM27)},  
    {TOKEN_MACRO_YMM28,  REG_NAME(X86_REG_YMM28)},  
    {TOKEN_MACRO_YMM29,  REG_NAME(X86_REG_YMM29)},   
    {TOKEN_MACRO_YMM30,  REG_NAME(X86_REG_YMM30)},  
    {TOKEN_MACRO_YMM31,  REG_NAME(X86_REG_YMM31)},  
    {TOKEN_MACRO_ZMM0,   REG_NAME(X86_REG_ZMM0)},
    {TOKEN_MACRO_ZMM1,   REG_NAME(X86_REG_ZMM1)}, 
    {TOKEN_MACRO_ZMM2,   REG_NAME(X86_REG_ZMM2)},
    {TOKEN_MACRO_ZMM3,   REG_NAME(X86_REG_ZMM3)},
    {TOKEN_MACRO_ZMM4,   REG_NAME(X86_REG_ZMM4)}, 
    {TOKEN_MACRO_ZMM5,   REG_NAME(X86_REG_ZMM5)}, 
    {TOKEN_MACRO_ZMM6,   REG_NAME(X86_REG_ZMM6)}, 
    {TOKEN_MACRO_ZMM7,   REG_NAME(X86_REG_ZMM7)}, 
    {TOKEN_MACRO_ZMM8,   REG_NAME(X86_REG_ZMM8)},  
    {TOKEN_MACRO_ZMM9,   REG_NAME(X86_REG_ZMM9)},  
    {TOKEN_MACRO_ZMM10,  REG_NAME(X86_REG_ZMM10)},  
    {TOKEN_MACRO_ZMM11,  REG_NAME(X86_REG_ZMM11)},  
    {TOKEN_MACRO_ZMM12,  REG_NAME(X86_REG_ZMM12)},  
    {TOKEN_MACRO_ZMM13,  REG_NAME(X86_REG_ZMM13)},  
    {TOKEN_MACRO_ZMM14,  REG_NAME(X86_REG_ZMM14)},  
    {TOKEN_MACRO_ZMM15,  REG_NAME(X86_REG_ZMM15)},  
    {TOKEN_MACRO_ZMM16,  REG_NAME(X86_REG_ZMM16)},  
    {TOKEN_MACRO_ZMM17,  REG_NAME(X86_REG_ZMM17)},  
    {TOKEN_MACRO_ZMM18,  REG_NAME(X86_REG_ZMM18)},  
    {TOKEN_MACRO_ZMM19,  REG_NAME(X86_REG_ZMM19)},  
    {TOKEN_MACRO_ZMM20,  REG_NAME(X86_REG_ZMM20)},  
    {TOKEN_MACRO_ZMM21,  REG_NAME(X86_REG_ZMM21)},  
    {TOKEN_MACRO_ZMM22,  REG_NAME(X86_REG_ZMM22)},  
    {TOKEN_MACRO_ZMM23,  REG_NAME(X86_REG_ZMM23)},  
    {TOKEN_MACRO_ZMM24,  REG_NAME(X86_REG_ZMM24)},  
    {TOKEN_MACRO_ZMM25,  REG_NAME(X86_REG_ZMM25)},  
    {TOKEN_MACRO_ZMM26,  REG_NAME(X86_REG_ZMM26)},  
    {TOKEN_MACRO_ZMM27,  REG_NAME(X86_REG_ZMM27)},  
    {TOKEN_MACRO_ZMM28,  REG_NAME(X86_REG_ZMM28)},  
    {TOKEN_MACRO_ZMM29,  REG_NAME(X86_REG_ZMM29)},   
    {TOKEN_MACRO_ZMM30,  REG_NAME(X86_REG_ZMM30)},  
    {TOKEN_MACRO_ZMM31,  REG_NAME(X86_REG_ZMM31)},  
};

/*
 * Compare token infos.
 */
static int compareName(const void *ptr1, const void *ptr2)
{
    const TokenInfo *info1 = (const TokenInfo *)ptr1;
    const TokenInfo *info2 = (const TokenInfo *)ptr2;
    return strcmp(info1->name, info2->name);
}

/*
 * Compare macro infos.
 */
static int compareMacro(const void *ptr1, const void *ptr2)
{
    const MacroInfo *info1 = (const MacroInfo *)ptr1;
    const MacroInfo *info2 = (const MacroInfo *)ptr2;
    return (int)info1->token - (int)info2->token;
}

/*
 * Get a token from a name.
 */
static Token getTokenFromName(const char *name)
{
    TokenInfo key = {name, TOKEN_ERROR};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens,
        sizeof(tokens) / sizeof(tokens[0]), sizeof(tokens[0]), compareName);
    if (entry == nullptr)
        return TOKEN_ERROR;
    return entry->token;
}

/*
 * Expands a macro value.
 */
static intptr_t expandMacro(Token t)
{
    MacroInfo key = {t, 0};
    const MacroInfo *entry = (const MacroInfo *)bsearch(&key, macros,
        sizeof(macros) / sizeof(macros[0]), sizeof(macros[0]), compareMacro);
    if (entry == nullptr)
        return -1;
    return entry->value;
}

/*
 * Get the name of a token.
 */
static const char *getNameFromToken(Token token)
{
    // Special tokens:
    switch ((int)token)
    {
        case TOKEN_NOT:
            return "not";
        case TOKEN_AND:
            return "and";
        case TOKEN_OR:
            return "or";
        case TOKEN_ERROR:
            return "<bad-token>";
        case TOKEN_END:
            return "<end-of-input>";
        case TOKEN_INTEGER:
            return "<integer>";
        case TOKEN_STRING:
            return "<string>";
        case TOKEN_REGEX:
            return "<regex>";
        default:
            break;
    }
    const TokenInfo *entry = nullptr;
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++)
    {
        if (tokens[i].token == token)
        {
            entry = tokens + i;
            break;
        }
    }
    if (entry == nullptr)
        return "???";
    return entry->name;
}

/*
 * Action string parser.
 */
struct Parser
{
    static const unsigned TOKEN_MAXLEN = 2048;

    const char * const mode;
    const char * const buf;
    size_t pos  = 0;
    size_t prev = 0;
    int peek    = TOKEN_ERROR;
    intptr_t i  = 0;
    char s[TOKEN_MAXLEN+1];

    Parser(const char *buf, const char *mode) : buf(buf), mode(mode)
    {
        ;
    }

    int getToken()
    {
        prev = pos;
        if (peek != TOKEN_ERROR)
        {
            int t = peek;
            peek = TOKEN_ERROR;
            return t;
        }
        char c = buf[pos];
        while (isspace(c))
            c = buf[++pos];
        
        // Operators:
        switch (c)
        {
            case '\0':
                strcpy(s, "<end-of-input>");
                return TOKEN_END;
            case '[': case ']': case '@': case ',': case '(': case ')':
            case '&': case '.':
                s[0] = c; s[1] = '\0';
                pos++;
                if (c == '&' && buf[pos] == '&')
                {
                    s[1] = '&'; s[2] = '\0';
                    pos++;
                }
                return getTokenFromName(s);
            case '!': case '<': case '>': case '=':
                s[0] = c; s[1] = '\0';
                pos++;
                if (buf[pos] == '=')
                {
                    s[1] = '='; s[2] = '\0';
                    pos++;
                }
                return getTokenFromName(s);
            case '|':
                if (buf[pos+1] == '|')
                {
                    s[0] = s[1] = '|'; s[2] = '\0';
                    pos += 2;
                    return TOKEN_OR;
                }
                // Fallthrough:
            default:
                break;
        }
        
        // Integers:
        unsigned j = 0;
        if (isdigit(c) || c == '-' || c == '+')
        {
            bool neg = false;
            switch (c)
            {
                case '-':
                    neg = true;
                    // Fallthrough:
                case '+':
                    s[j++] = c;
                    c = buf[++pos];
                    break;
                default:
                    break;
            }
            int base = 10;
            if (c == '0' && buf[pos+1] == 'x')
            {
                base = 16;
                s[j++] = buf[pos++]; s[j++] = buf[pos++];
                c = buf[pos];
            }
            if (!(base == 10? isdigit(c): isxdigit(c)))
            {
                s[j++] = '\0';
                return TOKEN_ERROR;
            }
            s[j++] = c;
            pos++;
            while ((base == 10? isdigit(buf[pos]): isxdigit(buf[pos])) &&
                    j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            char *end = nullptr;
            i = (intptr_t)strtoull((neg? s+1: s), &end, base);
            if (end == nullptr || *end != '\0')
                return TOKEN_ERROR;
            i = (neg? -i: i);
            return TOKEN_INTEGER;
        }

        // Strings:
        if (c == '\"')
        {
            pos++;
            while ((c = buf[pos++]) != '\"')
            {
                if (c == '\\')
                {
                    c = buf[pos++];
                    switch (c)
                    {
                        case 'n':
                            c = '\n'; break;
                        case 't':
                            c = '\t'; break;
                        case 'r':
                            c = '\r'; break;
                        default:
                            break;
                    }
                }
                if (j >= TOKEN_MAXLEN-1)
                {
                    s[j] = '\0';
                    return TOKEN_ERROR;
                }
                s[j++] = c;
            }
            s[j] = '\0';
            return TOKEN_STRING;
        }

        // Names:
        if (isalpha(c) || c == '_')
        {
            s[j++] = c;
            pos++;
            while ((isalnum(buf[pos]) || buf[pos] == '_') && j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            Token t = getTokenFromName(s);
            if (t == TOKEN_ERROR)
                return TOKEN_STRING;
            i = expandMacro(t);
            return (i >= 0? TOKEN_INTEGER: t);
        }

        // Unknown:
        s[0] = c; s[1] = '\0';
        return TOKEN_ERROR;
    }

    int peekToken()
    {
        if (peek != TOKEN_ERROR)
            return peek;
        peek = getToken();
        return peek;
    }

    void getPositionStr(std::string &str)
    {
        for (size_t i = 0; i < prev; i++)
            str += buf[i];
        str += " <--- here";
    }

    void expectToken(int token)
    {
        if (getToken() != token)
        {
            std::string str;
            getPositionStr(str);
            error("failed to parse %s at position \"%s\"; expected token "
                "\"%s\", found \"%s\"", mode, str.c_str(),
                getNameFromToken((Token)token), s);
        }
    }

    void unexpectedToken()
    {
        std::string str;
        getPositionStr(str);
        error("failed to parse %s at position \"%s\"; unexpected token \"%s\"",
            mode, str.c_str(), s);
    }

    const char *getName(int token)
    {
        return getNameFromToken((Token)token);
    }

    int getRegex()
    {
        if (peek != TOKEN_ERROR)
            unexpectedToken();
        while (isspace(buf[pos]))
            pos++;
        if (buf[pos] == '\"')
            return getToken();
        unsigned j;
        for (j = 0; j < TOKEN_MAXLEN && buf[pos] != '\0'; j++)
        {
            if (isspace(buf[pos]))
                break;
            if (buf[pos] == '\\' && isspace(buf[pos+1]))
            {
                s[j] = buf[pos+1];
                pos += 2;
                continue;
            }
            s[j] = buf[pos++];
        }
        if (j >= TOKEN_MAXLEN)
            unexpectedToken();
        s[j] = '\0';
        return TOKEN_REGEX;
    }
};

