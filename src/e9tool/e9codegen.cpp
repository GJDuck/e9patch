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

#include <cassert>
#include <cstdint>
#include <cstdio>

#include "e9codegen.h"
#include "e9tool.h"
#include "e9types.h"

using namespace e9tool;

/*
 * Get argument register index.
 */
int getArgRegIdx(bool sysv, int argno)
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
Register getReg(int regno)
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
int getRegIdx(Register reg)
{
    switch (reg)
    {
        case REGISTER_DI: case REGISTER_DIL: case REGISTER_EDI:
        case REGISTER_RDI:
            return RDI_IDX;
        case REGISTER_SI: case REGISTER_SIL: case REGISTER_ESI:
        case REGISTER_RSI:
            return RSI_IDX;
        case REGISTER_DH: case REGISTER_DL:
        case REGISTER_DX: case REGISTER_EDX: case REGISTER_RDX:
            return RDX_IDX;
        case REGISTER_CH: case REGISTER_CL:
        case REGISTER_CX: case REGISTER_ECX: case REGISTER_RCX:
            return RCX_IDX;
        case REGISTER_R8B: case REGISTER_R8W: case REGISTER_R8D:
        case REGISTER_R8:
            return R8_IDX;
        case REGISTER_R9B: case REGISTER_R9W: case REGISTER_R9D:
        case REGISTER_R9:
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
        case REGISTER_BP: case REGISTER_BPL: case REGISTER_EBP:
        case REGISTER_RBP:
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
        case REGISTER_SP: case REGISTER_SPL: case REGISTER_ESP:
        case REGISTER_RSP:
            return RSP_IDX;
        default:
            return -1;
    }
}

/*
 * Convert a register into a canonical register.
 */
Register getCanonicalReg(Register reg)
{
    switch (reg)
    {
        case REGISTER_DI: case REGISTER_DIL: case REGISTER_EDI:
        case REGISTER_RDI:
            return REGISTER_RDI;
        case REGISTER_SI: case REGISTER_SIL: case REGISTER_ESI:
        case REGISTER_RSI:
            return REGISTER_RSI;
        case REGISTER_DH: case REGISTER_DL:
        case REGISTER_DX: case REGISTER_EDX: case REGISTER_RDX:
            return REGISTER_RDX;
        case REGISTER_CH: case REGISTER_CL:
        case REGISTER_CX: case REGISTER_ECX: case REGISTER_RCX:
            return REGISTER_RCX;
        case REGISTER_R8B: case REGISTER_R8W: case REGISTER_R8D:
        case REGISTER_R8:
            return REGISTER_R8;
        case REGISTER_R9B: case REGISTER_R9W: case REGISTER_R9D:
        case REGISTER_R9:
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
        case REGISTER_BP: case REGISTER_BPL: case REGISTER_EBP:
        case REGISTER_RBP:
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
        case REGISTER_SP: case REGISTER_SPL: case REGISTER_ESP:
        case REGISTER_RSP:
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
int32_t getRegSize(Register reg)
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
Type getRegType(Register reg)
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
bool isHighReg(Register reg)
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
const char *e9tool::getRegName(Register reg)
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
 * Get all callee-save registers.
 */
const int *getCallerSaveRegs(bool sysv, bool clean, bool state,
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
std::pair<bool, bool> sendPush(FILE *out, int32_t offset, bool before,
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
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstr\"}",
                    scratch);
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lbreak\"}",
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
bool sendPop(FILE *out, bool preserve_rax, Register reg, Register rscratch)
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
bool sendMovFromR64ToR64(FILE *out, int srcno, int dstno)
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
void sendMovFromR32ToR64(FILE *out, int srcno, int dstno)
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
void sendMovFromR16ToR64(FILE *out, int srcno, int dstno)
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
void sendMovFromR8ToR64(FILE *out, int srcno, bool srchi, int dstno)
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
void sendMovFromStackToR64(FILE *out, int32_t offset, int regno)
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
void sendMovFromStack32ToR64(FILE *out, int32_t offset, int regno)
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
void sendMovFromStack16ToR64(FILE *out, int32_t offset, int regno)
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
void sendMovFromStack8ToR64(FILE *out, int32_t offset, int regno)
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
void sendMovFromR64ToStack(FILE *out, int regno, int32_t offset)
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
void sendMovFromRAX16ToR64(FILE *out, int regno)
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
void sendSExtFromI32ToR64(FILE *out, const char *value, int regno)
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
void sendSExtFromI32ToR64(FILE *out, int32_t value, int regno)
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
void sendZExtFromI32ToR64(FILE *out, const char *value, int regno)
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
void sendZExtFromI32ToR64(FILE *out, int32_t value, int regno)
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
void sendMovFromI64ToR64(FILE *out, intptr_t value, int regno)
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
 * Send a `movabs $i64,%r64' instruction.
 */
void sendMovFromI64ToR64(FILE *out, const char *value, int regno)
{
    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x00,
         0x48, 0x49, 0x49, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x48};
    const uint8_t OPCODE[] =
        {0xbf, 0xbe, 0xba, 0xb9, 0xb8, 0xb9, 0x00,
         0xb8, 0xba, 0xbb, 0xbb, 0xbd, 0xbc, 0xbd, 0xbe, 0xbf, 0xbc};
    fprintf(out, "%u,%u,%s,", REX[regno], OPCODE[regno], value);
}

/*
 * Send a `lea offset(%rip),%r64' instruction.
 */
void sendLeaFromPCRelToR64(FILE *out, const char *offset, int regno)
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
void sendLeaFromPCRelToR64(FILE *out, int32_t offset, int regno)
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
void sendMovFromPCRelToR64(FILE *out, int32_t offset, int regno)
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
void sendLeaFromStackToR64(FILE *out, int32_t offset, int regno)
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

