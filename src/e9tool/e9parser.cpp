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
 * Register names.
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

static Register getRegister(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_AH:        return REGISTER_AH;
        case X86_REG_CH:        return REGISTER_CH;
        case X86_REG_DH:        return REGISTER_DH;
        case X86_REG_BH:        return REGISTER_BH;

        case X86_REG_AL:        return REGISTER_AL;
        case X86_REG_CL:        return REGISTER_CL;
        case X86_REG_DL:        return REGISTER_DL;
        case X86_REG_BL:        return REGISTER_BL;
        case X86_REG_SPL:       return REGISTER_SPL;
        case X86_REG_BPL:       return REGISTER_BPL;
        case X86_REG_SIL:       return REGISTER_SIL;
        case X86_REG_DIL:       return REGISTER_DIL;
        case X86_REG_R8B:       return REGISTER_R8B;
        case X86_REG_R9B:       return REGISTER_R9B;
        case X86_REG_R10B:      return REGISTER_R10B;
        case X86_REG_R11B:      return REGISTER_R11B;
        case X86_REG_R12B:      return REGISTER_R12B;
        case X86_REG_R13B:      return REGISTER_R13B;
        case X86_REG_R14B:      return REGISTER_R14B;
        case X86_REG_R15B:      return REGISTER_R15B;

        case X86_REG_AX:        return REGISTER_AX;
        case X86_REG_CX:        return REGISTER_CX;
        case X86_REG_DX:        return REGISTER_DX;
        case X86_REG_BX:        return REGISTER_BX;
        case X86_REG_SP:        return REGISTER_SP;
        case X86_REG_BP:        return REGISTER_BP;
        case X86_REG_SI:        return REGISTER_SI;
        case X86_REG_DI:        return REGISTER_DI;
        case X86_REG_R8W:       return REGISTER_R8W;
        case X86_REG_R9W:       return REGISTER_R9W;
        case X86_REG_R10W:      return REGISTER_R10W;
        case X86_REG_R11W:      return REGISTER_R11W;
        case X86_REG_R12W:      return REGISTER_R12W;
        case X86_REG_R13W:      return REGISTER_R13W;
        case X86_REG_R14W:      return REGISTER_R14W;
        case X86_REG_R15W:      return REGISTER_R15W;

        case X86_REG_EFLAGS:    return REGISTER_EFLAGS;
        case X86_REG_IP:        return REGISTER_IP;

        case X86_REG_EAX:       return REGISTER_EAX;
        case X86_REG_ECX:       return REGISTER_ECX;
        case X86_REG_EDX:       return REGISTER_EDX;
        case X86_REG_EBX:       return REGISTER_EBX;
        case X86_REG_ESP:       return REGISTER_ESP;
        case X86_REG_EBP:       return REGISTER_EBP;
        case X86_REG_ESI:       return REGISTER_ESI;
        case X86_REG_EDI:       return REGISTER_EDI;
        case X86_REG_R8D:       return REGISTER_R8D;
        case X86_REG_R9D:       return REGISTER_R9D;
        case X86_REG_R10D:      return REGISTER_R10D;
        case X86_REG_R11D:      return REGISTER_R11D;
        case X86_REG_R12D:      return REGISTER_R12D;
        case X86_REG_R13D:      return REGISTER_R13D;
        case X86_REG_R14D:      return REGISTER_R14D;
        case X86_REG_R15D:      return REGISTER_R15D;
        
        case X86_REG_EIP:       return REGISTER_EIP;

        case X86_REG_RAX:       return REGISTER_RAX;
        case X86_REG_RCX:       return REGISTER_RCX;
        case X86_REG_RDX:       return REGISTER_RDX;
        case X86_REG_RBX:       return REGISTER_RBX;
        case X86_REG_RSP:       return REGISTER_RSP;
        case X86_REG_RBP:       return REGISTER_RBP;
        case X86_REG_RSI:       return REGISTER_RSI;
        case X86_REG_RDI:       return REGISTER_RDI;
        case X86_REG_R8:        return REGISTER_R8;
        case X86_REG_R9:        return REGISTER_R9;
        case X86_REG_R10:       return REGISTER_R10;
        case X86_REG_R11:       return REGISTER_R11;
        case X86_REG_R12:       return REGISTER_R12;
        case X86_REG_R13:       return REGISTER_R13;
        case X86_REG_R14:       return REGISTER_R14;
        case X86_REG_R15:       return REGISTER_R15;
        
        case X86_REG_RIP:       return REGISTER_RIP;

        case X86_REG_XMM0:      return REGISTER_XMM0;
        case X86_REG_XMM1:      return REGISTER_XMM1;
        case X86_REG_XMM2:      return REGISTER_XMM2;
        case X86_REG_XMM3:      return REGISTER_XMM3;
        case X86_REG_XMM4:      return REGISTER_XMM4;
        case X86_REG_XMM5:      return REGISTER_XMM5;
        case X86_REG_XMM6:      return REGISTER_XMM6;
        case X86_REG_XMM7:      return REGISTER_XMM7;
        case X86_REG_XMM8:      return REGISTER_XMM8;
        case X86_REG_XMM9:      return REGISTER_XMM9;
        case X86_REG_XMM10:     return REGISTER_XMM10;
        case X86_REG_XMM11:     return REGISTER_XMM11;
        case X86_REG_XMM12:     return REGISTER_XMM12;
        case X86_REG_XMM13:     return REGISTER_XMM13;
        case X86_REG_XMM14:     return REGISTER_XMM14;
        case X86_REG_XMM15:     return REGISTER_XMM15;
        case X86_REG_XMM16:     return REGISTER_XMM16;
        case X86_REG_XMM17:     return REGISTER_XMM17;
        case X86_REG_XMM18:     return REGISTER_XMM18;
        case X86_REG_XMM19:     return REGISTER_XMM19;
        case X86_REG_XMM20:     return REGISTER_XMM20;
        case X86_REG_XMM21:     return REGISTER_XMM21;
        case X86_REG_XMM22:     return REGISTER_XMM22;
        case X86_REG_XMM23:     return REGISTER_XMM23;
        case X86_REG_XMM24:     return REGISTER_XMM24;
        case X86_REG_XMM25:     return REGISTER_XMM25;
        case X86_REG_XMM26:     return REGISTER_XMM26;
        case X86_REG_XMM27:     return REGISTER_XMM27;
        case X86_REG_XMM28:     return REGISTER_XMM28;
        case X86_REG_XMM29:     return REGISTER_XMM29;
        case X86_REG_XMM30:     return REGISTER_XMM30;
        case X86_REG_XMM31:     return REGISTER_XMM31;
        
        case X86_REG_YMM0:      return REGISTER_YMM0;
        case X86_REG_YMM1:      return REGISTER_YMM1;
        case X86_REG_YMM2:      return REGISTER_YMM2;
        case X86_REG_YMM3:      return REGISTER_YMM3;
        case X86_REG_YMM4:      return REGISTER_YMM4;
        case X86_REG_YMM5:      return REGISTER_YMM5;
        case X86_REG_YMM6:      return REGISTER_YMM6;
        case X86_REG_YMM7:      return REGISTER_YMM7;
        case X86_REG_YMM8:      return REGISTER_YMM8;
        case X86_REG_YMM9:      return REGISTER_YMM9;
        case X86_REG_YMM10:     return REGISTER_YMM10;
        case X86_REG_YMM11:     return REGISTER_YMM11;
        case X86_REG_YMM12:     return REGISTER_YMM12;
        case X86_REG_YMM13:     return REGISTER_YMM13;
        case X86_REG_YMM14:     return REGISTER_YMM14;
        case X86_REG_YMM15:     return REGISTER_YMM15;
        case X86_REG_YMM16:     return REGISTER_YMM16;
        case X86_REG_YMM17:     return REGISTER_YMM17;
        case X86_REG_YMM18:     return REGISTER_YMM18;
        case X86_REG_YMM19:     return REGISTER_YMM19;
        case X86_REG_YMM20:     return REGISTER_YMM20;
        case X86_REG_YMM21:     return REGISTER_YMM21;
        case X86_REG_YMM22:     return REGISTER_YMM22;
        case X86_REG_YMM23:     return REGISTER_YMM23;
        case X86_REG_YMM24:     return REGISTER_YMM24;
        case X86_REG_YMM25:     return REGISTER_YMM25;
        case X86_REG_YMM26:     return REGISTER_YMM26;
        case X86_REG_YMM27:     return REGISTER_YMM27;
        case X86_REG_YMM28:     return REGISTER_YMM28;
        case X86_REG_YMM29:     return REGISTER_YMM29;
        case X86_REG_YMM30:     return REGISTER_YMM30;
        case X86_REG_YMM31:     return REGISTER_YMM31;

        case X86_REG_ZMM0:      return REGISTER_ZMM0;
        case X86_REG_ZMM1:      return REGISTER_ZMM1;
        case X86_REG_ZMM2:      return REGISTER_ZMM2;
        case X86_REG_ZMM3:      return REGISTER_ZMM3;
        case X86_REG_ZMM4:      return REGISTER_ZMM4;
        case X86_REG_ZMM5:      return REGISTER_ZMM5;
        case X86_REG_ZMM6:      return REGISTER_ZMM6;
        case X86_REG_ZMM7:      return REGISTER_ZMM7;
        case X86_REG_ZMM8:      return REGISTER_ZMM8;
        case X86_REG_ZMM9:      return REGISTER_ZMM9;
        case X86_REG_ZMM10:     return REGISTER_ZMM10;
        case X86_REG_ZMM11:     return REGISTER_ZMM11;
        case X86_REG_ZMM12:     return REGISTER_ZMM12;
        case X86_REG_ZMM13:     return REGISTER_ZMM13;
        case X86_REG_ZMM14:     return REGISTER_ZMM14;
        case X86_REG_ZMM15:     return REGISTER_ZMM15;
        case X86_REG_ZMM16:     return REGISTER_ZMM16;
        case X86_REG_ZMM17:     return REGISTER_ZMM17;
        case X86_REG_ZMM18:     return REGISTER_ZMM18;
        case X86_REG_ZMM19:     return REGISTER_ZMM19;
        case X86_REG_ZMM20:     return REGISTER_ZMM20;
        case X86_REG_ZMM21:     return REGISTER_ZMM21;
        case X86_REG_ZMM22:     return REGISTER_ZMM22;
        case X86_REG_ZMM23:     return REGISTER_ZMM23;
        case X86_REG_ZMM24:     return REGISTER_ZMM24;
        case X86_REG_ZMM25:     return REGISTER_ZMM25;
        case X86_REG_ZMM26:     return REGISTER_ZMM26;
        case X86_REG_ZMM27:     return REGISTER_ZMM27;
        case X86_REG_ZMM28:     return REGISTER_ZMM28;
        case X86_REG_ZMM29:     return REGISTER_ZMM29;
        case X86_REG_ZMM30:     return REGISTER_ZMM30;
        case X86_REG_ZMM31:     return REGISTER_ZMM31;

        case X86_REG_ES:        return REGISTER_ES;
        case X86_REG_CS:        return REGISTER_CS;
        case X86_REG_SS:        return REGISTER_SS;
        case X86_REG_DS:        return REGISTER_DS;
        case X86_REG_FS:        return REGISTER_FS;
        case X86_REG_GS:        return REGISTER_GS;

        case X86_REG_CR0:       return REGISTER_CR0;
        case X86_REG_CR1:       return REGISTER_CR1;
        case X86_REG_CR2:       return REGISTER_CR2;
        case X86_REG_CR3:       return REGISTER_CR3;
        case X86_REG_CR4:       return REGISTER_CR4;
        case X86_REG_CR5:       return REGISTER_CR5;
        case X86_REG_CR6:       return REGISTER_CR6;
        case X86_REG_CR7:       return REGISTER_CR7;
        case X86_REG_CR8:       return REGISTER_CR8;
        case X86_REG_CR9:       return REGISTER_CR9;
        case X86_REG_CR10:      return REGISTER_CR10;
        case X86_REG_CR11:      return REGISTER_CR11;
        case X86_REG_CR12:      return REGISTER_CR12;
        case X86_REG_CR13:      return REGISTER_CR13;
        case X86_REG_CR14:      return REGISTER_CR14;
        case X86_REG_CR15:      return REGISTER_CR15;
        
        case X86_REG_DR0:       return REGISTER_DR0;
        case X86_REG_DR1:       return REGISTER_DR1;
        case X86_REG_DR2:       return REGISTER_DR2;
        case X86_REG_DR3:       return REGISTER_DR3;
        case X86_REG_DR4:       return REGISTER_DR4;
        case X86_REG_DR5:       return REGISTER_DR5;
        case X86_REG_DR6:       return REGISTER_DR6;
        case X86_REG_DR7:       return REGISTER_DR7;
        case X86_REG_DR8:       return REGISTER_DR8;
        case X86_REG_DR9:       return REGISTER_DR9;
        case X86_REG_DR10:      return REGISTER_DR10;
        case X86_REG_DR11:      return REGISTER_DR11;
        case X86_REG_DR12:      return REGISTER_DR12;
        case X86_REG_DR13:      return REGISTER_DR13;
        case X86_REG_DR14:      return REGISTER_DR14;
        case X86_REG_DR15:      return REGISTER_DR15;
        
        case X86_REG_FP0:       return REGISTER_FP0;
        case X86_REG_FP1:       return REGISTER_FP1;
        case X86_REG_FP2:       return REGISTER_FP2;
        case X86_REG_FP3:       return REGISTER_FP3;
        case X86_REG_FP4:       return REGISTER_FP4;
        case X86_REG_FP5:       return REGISTER_FP5;
        case X86_REG_FP6:       return REGISTER_FP6;
        case X86_REG_FP7:       return REGISTER_FP7;
        
        case X86_REG_K0:       return REGISTER_K0;
        case X86_REG_K1:       return REGISTER_K1;
        case X86_REG_K2:       return REGISTER_K2;
        case X86_REG_K3:       return REGISTER_K3;
        case X86_REG_K4:       return REGISTER_K4;
        case X86_REG_K5:       return REGISTER_K5;
        case X86_REG_K6:       return REGISTER_K6;
        case X86_REG_K7:       return REGISTER_K7;
        
        case X86_REG_MM0:       return REGISTER_MM0;
        case X86_REG_MM1:       return REGISTER_MM1;
        case X86_REG_MM2:       return REGISTER_MM2;
        case X86_REG_MM3:       return REGISTER_MM3;
        case X86_REG_MM4:       return REGISTER_MM4;
        case X86_REG_MM5:       return REGISTER_MM5;
        case X86_REG_MM6:       return REGISTER_MM6;
        case X86_REG_MM7:       return REGISTER_MM7;
 
        case X86_REG_ST0:       return REGISTER_ST0;
        case X86_REG_ST1:       return REGISTER_ST1;
        case X86_REG_ST2:       return REGISTER_ST2;
        case X86_REG_ST3:       return REGISTER_ST3;
        case X86_REG_ST4:       return REGISTER_ST4;
        case X86_REG_ST5:       return REGISTER_ST5;
        case X86_REG_ST6:       return REGISTER_ST6;
        case X86_REG_ST7:       return REGISTER_ST7;

        case X86_REG_FPSW:      return REGISTER_FPSW;

        default:                return REGISTER_UNKNOWN;
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
    TOKEN_REGISTER,
    TOKEN_STRING,
    TOKEN_REGEX,

    TOKEN_ACCESS = 4000,
    TOKEN_ADDR,
    TOKEN_AFTER,
    TOKEN_AND,
    TOKEN_ASM,
    TOKEN_BASE,
    TOKEN_BEFORE,
    TOKEN_CALL,
    TOKEN_CLEAN,
    TOKEN_CONDITIONAL,
    TOKEN_DEFINED,
    TOKEN_DISPLACEMENT,
    TOKEN_DST,
    TOKEN_EXIT,
    TOKEN_FALSE,
    TOKEN_GEQ,
    TOKEN_IMM,
    TOKEN_IN,
    TOKEN_INDEX,
    TOKEN_INSTR,
    TOKEN_JUMP,
    TOKEN_LENGTH,
    TOKEN_LEQ,
    TOKEN_MATCH,
    TOKEN_MEM,
    TOKEN_MNEMONIC,
    TOKEN_NAKED,
    TOKEN_NEQ,
    TOKEN_NEXT,
    TOKEN_NIL,
    TOKEN_NONE,
    TOKEN_NOT,
    TOKEN_OFFSET,
    TOKEN_OP,
    TOKEN_OR,
    TOKEN_PASSTHRU,
    TOKEN_PATCH,
    TOKEN_PLUGIN,
    TOKEN_PRINT,
    TOKEN_RANDOM,
    TOKEN_READ,
    TOKEN_READS,
    TOKEN_REG,
    TOKEN_REGS,
    TOKEN_REPLACE,
    TOKEN_RETURN,
    TOKEN_RW,
    TOKEN_SCALE,
    TOKEN_SEGMENT,
    TOKEN_SIZE,
    TOKEN_SRC,
    TOKEN_STATIC_ADDR,
    TOKEN_TARGET,
    TOKEN_TRAMPOLINE,
    TOKEN_TRAP,
    TOKEN_TRUE,
    TOKEN_TYPE,
    TOKEN_WRITE,
    TOKEN_WRITES,
};

/*
 * Token info.
 */
struct TokenInfo
{
    const char *name;
    Token token;
    intptr_t value;
};

/*
 * All tokens.
 */
static const TokenInfo tokens[] =
{
    {"!",               (Token)'!',             0},
    {"!=",              TOKEN_NEQ,              0},
    {"&",               (Token)'&',             0},
    {"&&",              TOKEN_AND,              0},
    {"(",               (Token)'(',             0},
    {")",               (Token)')',             0},
    {",",               (Token)',',             0},
    {"-",               TOKEN_NONE,             (Access)0x0},
    {"--",              TOKEN_NONE,             (Access)0x0},
    {"-w",              TOKEN_WRITE,            ACCESS_WRITE},
    {".",               (Token)'.',             0},
    {"<",               (Token)'<',             0},
    {"<=",              TOKEN_LEQ,              0},
    {"=",               (Token)'=',             0},
    {"==",              (Token)'=',             0},
    {">",               (Token)'>',             0},
    {">=",              TOKEN_GEQ,              0},
    {"@",               (Token)'@',             0},
    {"[",               (Token)'[',             0},
    {"]",               (Token)']',             0},
    {"_",               TOKEN_NIL,              0x0},
    {"acc",             TOKEN_ACCESS,           0},
    {"access",          TOKEN_ACCESS,           0},
    {"addr",            TOKEN_ADDR,             0},
    {"address",         TOKEN_ADDR,             0},
    {"after",           TOKEN_AFTER,            0},
    {"ah",              TOKEN_REGISTER,         REGISTER_AH},
    {"al",              TOKEN_REGISTER,         REGISTER_AL},
    {"and",             TOKEN_AND,              0},
    {"asm",             TOKEN_ASM,              0},
    {"ax",              TOKEN_REGISTER,         REGISTER_AX},
    {"base",            TOKEN_BASE,             0},
    {"before",          TOKEN_BEFORE,           0},
    {"bh",              TOKEN_REGISTER,         REGISTER_BH},
    {"bl",              TOKEN_REGISTER,         REGISTER_BL},
    {"bp",              TOKEN_REGISTER,         REGISTER_BP},
    {"bpl",             TOKEN_REGISTER,         REGISTER_BPL},
    {"bx",              TOKEN_REGISTER,         REGISTER_BX},
    {"call",            TOKEN_CALL,             0},
    {"ch",              TOKEN_REGISTER,         REGISTER_CH},
    {"cl",              TOKEN_REGISTER,         REGISTER_CL},
    {"clean",           TOKEN_CLEAN,            0},
    {"conditional",     TOKEN_CONDITIONAL,      0},
    {"cs",              TOKEN_REGISTER,         REGISTER_CS},
    {"cx",              TOKEN_REGISTER,         REGISTER_CX},
    {"defined",         TOKEN_DEFINED,          0},
    {"dh",              TOKEN_REGISTER,         REGISTER_DH},
    {"di",              TOKEN_REGISTER,         REGISTER_DI},
    {"dil",             TOKEN_REGISTER,         REGISTER_DIL},
    {"disp",            TOKEN_DISPLACEMENT,     0},
    {"displacement",    TOKEN_DISPLACEMENT,     0},
    {"dl",              TOKEN_REGISTER,         REGISTER_DL},
    {"ds",              TOKEN_REGISTER,         REGISTER_DS},
    {"dst",             TOKEN_DST,              0},
    {"dx",              TOKEN_REGISTER,         REGISTER_DX},
    {"eax",             TOKEN_REGISTER,         REGISTER_EAX},
    {"ebp",             TOKEN_REGISTER,         REGISTER_EBP},
    {"ebx",             TOKEN_REGISTER,         REGISTER_EBX},
    {"ecx",             TOKEN_REGISTER,         REGISTER_ECX},
    {"edi",             TOKEN_REGISTER,         REGISTER_EDI},
    {"edx",             TOKEN_REGISTER,         REGISTER_EDX},
    {"es",              TOKEN_REGISTER,         REGISTER_ES},
    {"esi",             TOKEN_REGISTER,         REGISTER_ESI},
    {"esp",             TOKEN_REGISTER,         REGISTER_ESP},
    {"exit",            TOKEN_EXIT,             0},
    {"false",           TOKEN_FALSE,            false},
    {"fs",              TOKEN_REGISTER,         REGISTER_FS},
    {"gs",              TOKEN_REGISTER,         REGISTER_GS},
    {"imm",             TOKEN_IMM,              OP_TYPE_IMM},
    {"in",              TOKEN_IN,               0},
    {"index",           TOKEN_INDEX,            0},
    {"instr",           TOKEN_INSTR,            0},
    {"jump",            TOKEN_JUMP,             0},
    {"len",             TOKEN_LENGTH,           0},
    {"length",          TOKEN_LENGTH,           0},
    {"match",           TOKEN_MATCH,            0},
    {"mem",             TOKEN_MEM,              OP_TYPE_MEM},
    {"mnemonic",        TOKEN_MNEMONIC,         0},
    {"naked",           TOKEN_NAKED,            0},
    {"next",            TOKEN_NEXT,             0},
    {"nil",             TOKEN_NIL,              0x0},
    {"not",             TOKEN_NOT,              0},
    {"offset",          TOKEN_OFFSET,           0},
    {"op",              TOKEN_OP,               0},
    {"or",              TOKEN_OR,               0},
    {"passthru",        TOKEN_PASSTHRU,         0},
    {"patch",           TOKEN_PATCH,            0},
    {"plugin",          TOKEN_PLUGIN,           0},
    {"print",           TOKEN_PRINT,            0},
    {"r",               TOKEN_READ,             ACCESS_READ},
    {"r-",              TOKEN_READ,             ACCESS_READ},
    {"r10",             TOKEN_REGISTER,         REGISTER_R10},
    {"r10b",            TOKEN_REGISTER,         REGISTER_R10B},
    {"r10d",            TOKEN_REGISTER,         REGISTER_R10D},
    {"r10w",            TOKEN_REGISTER,         REGISTER_R10W},
    {"r11",             TOKEN_REGISTER,         REGISTER_R11},
    {"r11b",            TOKEN_REGISTER,         REGISTER_R11B},
    {"r11d",            TOKEN_REGISTER,         REGISTER_R11D},
    {"r11w",            TOKEN_REGISTER,         REGISTER_R11W},
    {"r12",             TOKEN_REGISTER,         REGISTER_R12},
    {"r12b",            TOKEN_REGISTER,         REGISTER_R12B},
    {"r12d",            TOKEN_REGISTER,         REGISTER_R12D},
    {"r12w",            TOKEN_REGISTER,         REGISTER_R12W},
    {"r13",             TOKEN_REGISTER,         REGISTER_R13},
    {"r13b",            TOKEN_REGISTER,         REGISTER_R13B},
    {"r13d",            TOKEN_REGISTER,         REGISTER_R13D},
    {"r13w",            TOKEN_REGISTER,         REGISTER_R13W},
    {"r14",             TOKEN_REGISTER,         REGISTER_R14},
    {"r14b",            TOKEN_REGISTER,         REGISTER_R14B},
    {"r14d",            TOKEN_REGISTER,         REGISTER_R14D},
    {"r14w",            TOKEN_REGISTER,         REGISTER_R14W},
    {"r15",             TOKEN_REGISTER,         REGISTER_R15},
    {"r15b",            TOKEN_REGISTER,         REGISTER_R15B},
    {"r15d",            TOKEN_REGISTER,         REGISTER_R15D},
    {"r15w",            TOKEN_REGISTER,         REGISTER_R15W},
    {"r8",              TOKEN_REGISTER,         REGISTER_R8},
    {"r8b",             TOKEN_REGISTER,         REGISTER_R8B},
    {"r8d",             TOKEN_REGISTER,         REGISTER_R8D},
    {"r8w",             TOKEN_REGISTER,         REGISTER_R8W},
    {"r9",              TOKEN_REGISTER,         REGISTER_R9},
    {"r9b",             TOKEN_REGISTER,         REGISTER_R9B},
    {"r9d",             TOKEN_REGISTER,         REGISTER_R9D},
    {"r9w",             TOKEN_REGISTER,         REGISTER_R9W},
    {"random",          TOKEN_RANDOM,           0},
    {"rax",             TOKEN_REGISTER,         REGISTER_RAX},
    {"rbp",             TOKEN_REGISTER,         REGISTER_RBP},
    {"rbx",             TOKEN_REGISTER,         REGISTER_RBX},
    {"rcx",             TOKEN_REGISTER,         REGISTER_RCX},
    {"rdi",             TOKEN_REGISTER,         REGISTER_RDI},
    {"rdx",             TOKEN_REGISTER,         REGISTER_RDX},
    {"read",            TOKEN_READ,             ACCESS_READ},
    {"reads",           TOKEN_READS,            0},
    {"reg",             TOKEN_REG,              OP_TYPE_REG},
    {"regs",            TOKEN_REGS,             0},
    {"replace",         TOKEN_REPLACE,          0},
    {"return",          TOKEN_RETURN,           0},
    {"rflags",          TOKEN_REGISTER,         REGISTER_EFLAGS},
    {"rip",             TOKEN_REGISTER,         REGISTER_RIP},
    {"rsi",             TOKEN_REGISTER,         REGISTER_RSI},
    {"rsp",             TOKEN_REGISTER,         REGISTER_RSP},
    {"rw",              TOKEN_RW,               (ACCESS_READ | ACCESS_WRITE)},
    {"scale",           TOKEN_SCALE,            0},
    {"seg",             TOKEN_SEGMENT,          0},
    {"segment",         TOKEN_SEGMENT,          0},
    {"si",              TOKEN_REGISTER,         REGISTER_SI},
    {"sil",             TOKEN_REGISTER,         REGISTER_SIL},
    {"size",            TOKEN_SIZE,             0},
    {"sp",              TOKEN_REGISTER,         REGISTER_SP},
    {"spl",             TOKEN_REGISTER,         REGISTER_SPL},
    {"src",             TOKEN_SRC,              0},
    {"ss",              TOKEN_REGISTER,         REGISTER_SS},
    {"staticAddr",      TOKEN_STATIC_ADDR,      0},
    {"target",          TOKEN_TARGET,           0},
    {"trampoline",      TOKEN_TRAMPOLINE,       0},
    {"trap",            TOKEN_TRAP,             0},
    {"true",            TOKEN_TRUE,             true},
    {"type",            TOKEN_TYPE,             0},
    {"w",               TOKEN_WRITE,            ACCESS_WRITE},
    {"write",           TOKEN_WRITE,            ACCESS_WRITE},
    {"writes",          TOKEN_WRITES,           0},
    {"xmm0",            TOKEN_REGISTER,         REGISTER_XMM0},
    {"xmm1",            TOKEN_REGISTER,         REGISTER_XMM1},
    {"xmm10",           TOKEN_REGISTER,         REGISTER_XMM10},
    {"xmm11",           TOKEN_REGISTER,         REGISTER_XMM11},
    {"xmm12",           TOKEN_REGISTER,         REGISTER_XMM12},
    {"xmm13",           TOKEN_REGISTER,         REGISTER_XMM13},
    {"xmm14",           TOKEN_REGISTER,         REGISTER_XMM14},
    {"xmm15",           TOKEN_REGISTER,         REGISTER_XMM15},
    {"xmm16",           TOKEN_REGISTER,         REGISTER_XMM16},
    {"xmm17",           TOKEN_REGISTER,         REGISTER_XMM17},
    {"xmm18",           TOKEN_REGISTER,         REGISTER_XMM18},
    {"xmm19",           TOKEN_REGISTER,         REGISTER_XMM19},
    {"xmm2",            TOKEN_REGISTER,         REGISTER_XMM2},
    {"xmm20",           TOKEN_REGISTER,         REGISTER_XMM20},
    {"xmm21",           TOKEN_REGISTER,         REGISTER_XMM21},
    {"xmm22",           TOKEN_REGISTER,         REGISTER_XMM22},
    {"xmm23",           TOKEN_REGISTER,         REGISTER_XMM23},
    {"xmm24",           TOKEN_REGISTER,         REGISTER_XMM24},
    {"xmm25",           TOKEN_REGISTER,         REGISTER_XMM25},
    {"xmm26",           TOKEN_REGISTER,         REGISTER_XMM26},
    {"xmm27",           TOKEN_REGISTER,         REGISTER_XMM27},
    {"xmm28",           TOKEN_REGISTER,         REGISTER_XMM28},
    {"xmm29",           TOKEN_REGISTER,         REGISTER_XMM29},
    {"xmm3",            TOKEN_REGISTER,         REGISTER_XMM3},
    {"xmm30",           TOKEN_REGISTER,         REGISTER_XMM30},
    {"xmm31",           TOKEN_REGISTER,         REGISTER_XMM31},
    {"xmm4",            TOKEN_REGISTER,         REGISTER_XMM4},
    {"xmm5",            TOKEN_REGISTER,         REGISTER_XMM5},
    {"xmm6",            TOKEN_REGISTER,         REGISTER_XMM6},
    {"xmm7",            TOKEN_REGISTER,         REGISTER_XMM7},
    {"xmm8",            TOKEN_REGISTER,         REGISTER_XMM8},
    {"xmm9",            TOKEN_REGISTER,         REGISTER_XMM9},
    {"ymm0",            TOKEN_REGISTER,         REGISTER_YMM0},
    {"ymm1",            TOKEN_REGISTER,         REGISTER_YMM1},
    {"ymm10",           TOKEN_REGISTER,         REGISTER_YMM10},
    {"ymm11",           TOKEN_REGISTER,         REGISTER_YMM11},
    {"ymm12",           TOKEN_REGISTER,         REGISTER_YMM12},
    {"ymm13",           TOKEN_REGISTER,         REGISTER_YMM13},
    {"ymm14",           TOKEN_REGISTER,         REGISTER_YMM14},
    {"ymm15",           TOKEN_REGISTER,         REGISTER_YMM15},
    {"ymm16",           TOKEN_REGISTER,         REGISTER_YMM16},
    {"ymm17",           TOKEN_REGISTER,         REGISTER_YMM17},
    {"ymm18",           TOKEN_REGISTER,         REGISTER_YMM18},
    {"ymm19",           TOKEN_REGISTER,         REGISTER_YMM19},
    {"ymm2",            TOKEN_REGISTER,         REGISTER_YMM2},
    {"ymm20",           TOKEN_REGISTER,         REGISTER_YMM20},
    {"ymm21",           TOKEN_REGISTER,         REGISTER_YMM21},
    {"ymm22",           TOKEN_REGISTER,         REGISTER_YMM22},
    {"ymm23",           TOKEN_REGISTER,         REGISTER_YMM23},
    {"ymm24",           TOKEN_REGISTER,         REGISTER_YMM24},
    {"ymm25",           TOKEN_REGISTER,         REGISTER_YMM25},
    {"ymm26",           TOKEN_REGISTER,         REGISTER_YMM26},
    {"ymm27",           TOKEN_REGISTER,         REGISTER_YMM27},
    {"ymm28",           TOKEN_REGISTER,         REGISTER_YMM28},
    {"ymm29",           TOKEN_REGISTER,         REGISTER_YMM29},
    {"ymm3",            TOKEN_REGISTER,         REGISTER_YMM3},
    {"ymm30",           TOKEN_REGISTER,         REGISTER_YMM30},
    {"ymm31",           TOKEN_REGISTER,         REGISTER_YMM31},
    {"ymm4",            TOKEN_REGISTER,         REGISTER_YMM4},
    {"ymm5",            TOKEN_REGISTER,         REGISTER_YMM5},
    {"ymm6",            TOKEN_REGISTER,         REGISTER_YMM6},
    {"ymm7",            TOKEN_REGISTER,         REGISTER_YMM7},
    {"ymm8",            TOKEN_REGISTER,         REGISTER_YMM8},
    {"ymm9",            TOKEN_REGISTER,         REGISTER_YMM9},
    {"zmm0",            TOKEN_REGISTER,         REGISTER_ZMM0},
    {"zmm1",            TOKEN_REGISTER,         REGISTER_ZMM1},
    {"zmm10",           TOKEN_REGISTER,         REGISTER_ZMM10},
    {"zmm11",           TOKEN_REGISTER,         REGISTER_ZMM11},
    {"zmm12",           TOKEN_REGISTER,         REGISTER_ZMM12},
    {"zmm13",           TOKEN_REGISTER,         REGISTER_ZMM13},
    {"zmm14",           TOKEN_REGISTER,         REGISTER_ZMM14},
    {"zmm15",           TOKEN_REGISTER,         REGISTER_ZMM15},
    {"zmm16",           TOKEN_REGISTER,         REGISTER_ZMM16},
    {"zmm17",           TOKEN_REGISTER,         REGISTER_ZMM17},
    {"zmm18",           TOKEN_REGISTER,         REGISTER_ZMM18},
    {"zmm19",           TOKEN_REGISTER,         REGISTER_ZMM19},
    {"zmm2",            TOKEN_REGISTER,         REGISTER_ZMM2},
    {"zmm20",           TOKEN_REGISTER,         REGISTER_ZMM20},
    {"zmm21",           TOKEN_REGISTER,         REGISTER_ZMM21},
    {"zmm22",           TOKEN_REGISTER,         REGISTER_ZMM22},
    {"zmm23",           TOKEN_REGISTER,         REGISTER_ZMM23},
    {"zmm24",           TOKEN_REGISTER,         REGISTER_ZMM24},
    {"zmm25",           TOKEN_REGISTER,         REGISTER_ZMM25},
    {"zmm26",           TOKEN_REGISTER,         REGISTER_ZMM26},
    {"zmm27",           TOKEN_REGISTER,         REGISTER_ZMM27},
    {"zmm28",           TOKEN_REGISTER,         REGISTER_ZMM28},
    {"zmm29",           TOKEN_REGISTER,         REGISTER_ZMM29},
    {"zmm3",            TOKEN_REGISTER,         REGISTER_ZMM3},
    {"zmm30",           TOKEN_REGISTER,         REGISTER_ZMM30},
    {"zmm31",           TOKEN_REGISTER,         REGISTER_ZMM31},
    {"zmm4",            TOKEN_REGISTER,         REGISTER_ZMM4},
    {"zmm5",            TOKEN_REGISTER,         REGISTER_ZMM5},
    {"zmm6",            TOKEN_REGISTER,         REGISTER_ZMM6},
    {"zmm7",            TOKEN_REGISTER,         REGISTER_ZMM7},
    {"zmm8",            TOKEN_REGISTER,         REGISTER_ZMM8},
    {"zmm9",            TOKEN_REGISTER,         REGISTER_ZMM9},
    {"||",              TOKEN_OR,               0},
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
 * Get a token info.
 */
static const TokenInfo *getTokenInfo(const char *name)
{
    TokenInfo key = {name, TOKEN_ERROR};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens,
        sizeof(tokens) / sizeof(tokens[0]), sizeof(tokens[0]), compareName);
    return entry;
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
        case TOKEN_REGISTER:
            return "<register>";
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
    size_t pos     = 0;
    size_t prev    = 0;
    int peek       = TOKEN_ERROR;
    intptr_t i     = 0;
    char s[TOKEN_MAXLEN+1];

    Parser(const char *buf, const char *mode) : buf(buf), mode(mode)
    {
        ;
    }

    Token getTokenFromName(const char *name)
    {
        const TokenInfo *info = getTokenInfo(name);
        if (info == nullptr)
            return TOKEN_ERROR;
        i = info->value;
        return info->token;
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
        if (isdigit(c) || (c == '-' && isdigit(buf[pos+1])) || c == '+')
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
        if (isalpha(c) || c == '_' || c == '-')
        {
            s[j++] = c;
            pos++;
            while ((isalnum(buf[pos]) || buf[pos] == '_' || buf[pos] == '-') &&
                    j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            Token t = getTokenFromName(s);
            if (t == TOKEN_ERROR)
                return TOKEN_STRING;
            return t;
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

