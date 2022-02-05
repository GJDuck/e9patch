/*
 * e9x86_64.cpp
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

/*
 * Disassembler interface.
 */

#include "e9elf.h"
#include "e9misc.h"
#include "e9tool.h"

using namespace e9tool;

#include <Zydis/Zydis.h>
typedef ZydisDecodedInstruction RawInstr;

/*
 * Prototypes.
 */
static Register convert(ZydisRegister reg);
static Mnemonic convert(ZydisMnemonic mnemonic);
static uint16_t convert(ZydisInstructionCategory category, ZydisISAExt isa);

/*
 * Zydis structures.
 */
static ZydisDecoder decoder;
static ZydisDecoder decoder_minimal;
static ZydisFormatter formatter;

/*
 * Initialize the disassembler.
 */
void initDisassembler(void)
{
    ZyanStatus result = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_ADDRESS_WIDTH_64);
    if (!ZYAN_SUCCESS(result))
        error("failed to initialize disassembler decoder");
    result = ZydisDecoderInit(&decoder_minimal, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_ADDRESS_WIDTH_64);
    if (!ZYAN_SUCCESS(result))
        error("failed to initialize disassembler decoder");
    (void)ZydisDecoderEnableMode(&decoder_minimal, ZYDIS_DECODER_MODE_MINIMAL,
        ZYAN_TRUE);
    
    ZydisFormatterInit(&formatter,
        (option_intel_syntax? ZYDIS_FORMATTER_STYLE_INTEL:
                              ZYDIS_FORMATTER_STYLE_ATT));
    if (!ZYAN_SUCCESS(result))
        error("failed to initialize disassembler formatter");
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_FORCE_RELATIVE_RIPREL, ZYAN_TRUE);
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE,
        ZYDIS_PADDING_DISABLED);
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_IMM_PADDING,
        ZYDIS_PADDING_DISABLED);
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_DISP_PADDING,
        ZYDIS_PADDING_DISABLED);
    (void)ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_HEX_UPPERCASE, ZYAN_FALSE);
}

/*
 * Disassemble an instruction.
 */
bool decode(const uint8_t **code, size_t *size, off_t *offset,
    intptr_t *address, Instr *I)
{
    if (*size == 0)
        return false;

    ZydisDecodedInstruction D_0;
    ZydisDecodedInstruction *D = &D_0;
    ZyanStatus result = ZydisDecoderDecodeBuffer(&decoder_minimal, *code,
        *size, D);
    
    I->address = (size_t)*address;
    I->offset  = (size_t)*offset;
    if (ZYAN_SUCCESS(result))
    {
        I->data   = false;
        I->size   = (size_t)D->length;
        *code    += D->length;
        *size     = (*size < D->length? 0: *size - D->length);
        *offset  += D->length;
        *address += D->length;
    }
    else
    {
        // Cannot be decoded:
        I->data   = true;
        I->size   = 1;
        *code    += 1;
        *size    -= 1;
        *offset  += 1;
        *address += 1;
    }
    return true;
}

/*
 * Decompress an instruction.
 */
void e9tool::getInstrInfo(const ELF *elf, const Instr *I, InstrInfo *info,
    void *raw)
{
    off_t offset = (off_t)I->offset;
    const Elf64_Shdr *shdr = nullptr;
    ssize_t lo = 0, hi = (ssize_t)elf->exes.size()-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        const Elf64_Shdr *exe = elf->exes[mid];
        if (offset < (off_t)exe->sh_offset)
            hi = mid-1;
        else if (offset >= (off_t)exe->sh_offset + (off_t)exe->sh_size)
            lo = mid+1;
        else
        {
            shdr = exe;
            break;
        }
    }
    if (shdr == nullptr)
        error("failed to decompress instruction at address 0x%lx; section "
            "not found", I->address);

    ZydisDecodedInstruction D_0;
    ZydisDecodedInstruction *D = (ZydisDecodedInstruction *)raw;
    D = (D == nullptr? &D_0: D);

    ZyanStatus result = ZydisDecoderDecodeBuffer(&decoder,
        elf->data + I->offset, I->size, D);
    if (!ZYAN_SUCCESS(result) || I->size != D->length ||
            D->operand_count > sizeof(info->op) / sizeof(info->op[0]))
        error("failed to decompress instruction at address 0x%lx; decode "
            "failed", I->address);

    if (info != nullptr)
    {
        info->instr                  = I;
        info->raw                    = raw;
        info->data                   = elf->data + I->offset;
        info->address                = I->address;
        info->offset                 = I->offset;
        info->mnemonic               = convert(D->mnemonic);
        info->category               =
            convert(D->meta.category, D->meta.isa_ext);
        info->size                   = I->size;
        info->relative               = false;
        info->encoding.size.disp     =
            (D->raw.disp.offset != 0? D->raw.disp.size / 8: -1);
        info->encoding.size.imm      =
            (D->raw.imm[0].offset != 0? D->raw.imm[0].size / 8: -1);
        info->encoding.offset.rex    =
            (D->attributes & ZYDIS_ATTRIB_HAS_REX? D->raw.rex.offset: -1);
        info->encoding.offset.vex    =
            (D->attributes & ZYDIS_ATTRIB_HAS_VEX? D->raw.vex.offset: -1);
        info->encoding.offset.evex   =
            (D->attributes & ZYDIS_ATTRIB_HAS_EVEX? D->raw.evex.offset: -1);
        info->encoding.offset.opcode = D->raw.prefix_count;
        info->encoding.offset.modrm  =
            (D->attributes & ZYDIS_ATTRIB_HAS_MODRM? D->raw.modrm.offset: -1);
        info->encoding.offset.sib    =
            (D->attributes & ZYDIS_ATTRIB_HAS_SIB? D->raw.sib.offset: -1);
        info->encoding.offset.disp   =
            (D->raw.disp.offset != 0? D->raw.disp.offset: -1);
        info->encoding.offset.imm    =
            (D->raw.imm[0].offset != 0? D->raw.imm[0].offset: -1);

        info->flags.read = 0x0;
        if (D->cpu_flags_read & (1 << ZYDIS_CPUFLAG_CF))
            info->flags.read |= FLAG_CF;
        if (D->cpu_flags_read & (1 << ZYDIS_CPUFLAG_PF))
            info->flags.read |= FLAG_PF;
        if (D->cpu_flags_read & (1 << ZYDIS_CPUFLAG_AF))
            info->flags.read |= FLAG_AF;
        if (D->cpu_flags_read & (1 << ZYDIS_CPUFLAG_ZF))
            info->flags.read |= FLAG_ZF;
        if (D->cpu_flags_read & (1 << ZYDIS_CPUFLAG_SF))
            info->flags.read |= FLAG_SF;
        info->flags.write = 0x0;
        if (D->cpu_flags_written & (1 << ZYDIS_CPUFLAG_CF))
            info->flags.write |= FLAG_CF;
        if (D->cpu_flags_written & (1 << ZYDIS_CPUFLAG_PF))
            info->flags.write |= FLAG_PF;
        if (D->cpu_flags_written & (1 << ZYDIS_CPUFLAG_AF))
            info->flags.write |= FLAG_AF;
        if (D->cpu_flags_written & (1 << ZYDIS_CPUFLAG_ZF))
            info->flags.write |= FLAG_ZF;
        if (D->cpu_flags_written & (1 << ZYDIS_CPUFLAG_SF))
            info->flags.write |= FLAG_SF;

        unsigned j = 0, k = 0, l = 0, m = 0, n = 0;
        Register seg = REGISTER_NONE;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_CS)
            seg = REGISTER_CS;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_SS)
            seg = REGISTER_SS;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_DS)
            seg = REGISTER_DS;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_ES)
            seg = REGISTER_ES;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS)
            seg = REGISTER_FS;
        if (D->attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS)
            seg = REGISTER_GS;
        for (unsigned i0 = 0; i0 < D->operand_count; i0++)
        {
            unsigned i = (option_intel_syntax? i0: D->operand_count - i0 - 1);
            bool read =
                ((D->operands[i].actions & ZYDIS_OPERAND_ACTION_READ) != 0);
            bool write =
                ((D->operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE) != 0);
            bool condread =
                ((D->operands[i].actions & ZYDIS_OPERAND_ACTION_CONDREAD) != 0);
            bool condwrite =
                 ((D->operands[i].actions & ZYDIS_OPERAND_ACTION_CONDWRITE)
                    != 0);
            if (D->mnemonic == ZYDIS_MNEMONIC_NOP)
                condread = read = condwrite = write = false;

            switch (D->operands[i].type)
            {
                case ZYDIS_OPERAND_TYPE_REGISTER:
                {
                    Register r = convert(D->operands[i].reg.value);
                    if (read && r != REGISTER_INVALID)
                        info->regs.read[k++] = r;
                    if (write && r != REGISTER_INVALID)
                        info->regs.write[l++] = r;
                    if (condread && r != REGISTER_INVALID)
                        info->regs.condread[m++] = r;
                    if (condwrite && r != REGISTER_INVALID)
                        info->regs.condwrite[n++] = r;
                    break;
                }
                case ZYDIS_OPERAND_TYPE_MEMORY:
                {
                    if (seg != REGISTER_NONE)
                        info->regs.read[k++] = seg;
                    Register r = convert(D->operands[i].mem.base);
                    if (r != REGISTER_NONE)
                        info->regs.read[k++] = r;
                    r = convert(D->operands[i].mem.index);
                    if (r != REGISTER_NONE)
                        info->regs.read[k++] = r;
                    break;
                }
                default:
                    break;
            }
            switch (D->operands[i].visibility)
            {
                case ZYDIS_OPERAND_VISIBILITY_EXPLICIT:
                case ZYDIS_OPERAND_VISIBILITY_IMPLICIT:
                    break;
                default:
                    continue;
            }
            switch (D->operands[i].type)
            {
                case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                    info->op[j].type = OPTYPE_IMM;
                    info->op[j].imm  = (int64_t)D->operands[i].imm.value.s;
                    if (D->operands[i].imm.is_relative)
                        info->relative = true;
                    break;
                case ZYDIS_OPERAND_TYPE_REGISTER:
                    info->op[j].type = OPTYPE_REG;
                    info->op[j].reg  = convert(D->operands[i].reg.value);
                    break;
                case ZYDIS_OPERAND_TYPE_MEMORY:
                    info->op[j].type      = OPTYPE_MEM;
                    info->op[j].mem.seg   = seg;
                    info->op[j].mem.disp  =
                        (int32_t)D->operands[i].mem.disp.value;
                    info->op[j].mem.base  = convert(D->operands[i].mem.base);
                    info->op[j].mem.index = convert(D->operands[i].mem.index);
                    info->op[j].mem.scale = D->operands[i].mem.scale;
                    if (D->operands[i].mem.base == ZYDIS_REGISTER_RIP)
                        info->relative = true;
                    break;
                default:
                    continue;
            }
            info->op[j].access =
                (read || condread? ACCESS_READ: 0) |
                (write || condwrite? ACCESS_WRITE: 0);
            info->op[j].size = D->operands[i].size / 8;
            j++;
        }
        assert(k < (sizeof(info->regs.read) / sizeof(info->regs.read[0])) - 1);
        assert(l < (sizeof(info->regs.write) /
            sizeof(info->regs.write[0])) - 1);
        assert(m < (sizeof(info->regs.condread) /
            sizeof(info->regs.condread[0])) - 1);
        assert(n < (sizeof(info->regs.condwrite) /
            sizeof(info->regs.condwrite[0])) - 1);
        info->regs.read[k]      = REGISTER_INVALID;
        info->regs.write[l]     = REGISTER_INVALID;
        info->regs.condread[m]  = REGISTER_INVALID;
        info->regs.condwrite[n] = REGISTER_INVALID;
        info->op[j].type        = OPTYPE_INVALID;
        info->count.op          = j;
        info->string.section    = elf->strs + shdr->sh_name;
        result = ZydisFormatterFormatInstruction(&formatter, D,
            info->string.instr, sizeof(info->string.instr)-1, I->address);
        if (!ZYAN_SUCCESS(result))
            error("failed to decompress instruction at address 0x%lx; "
                "formatting failed", I->address);
        if (!option_intel_syntax &&
            (D->mnemonic == ZYDIS_MNEMONIC_JMP ||
             D->mnemonic == ZYDIS_MNEMONIC_CALL) &&
            (D->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER ||
             D->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY))
        {
            // ZyDis does not format the '*'?
            // This can lead to ambiguity, so we add it ourselves.
            char *s = info->string.instr;
            for (; *s != ' '; s++)
                ;
            s++;
            if (*s != '*')
            {
                char c = '*';
                for (; *s != '\0'; s++)
                {
                    char d = *s;
                    *s = c;
                    c = d;
                }
                *s++ = c;
                *s++ = '\0';
            }
        }
        info->string.mnemonic = ZydisMnemonicGetString(D->mnemonic);
    }
}

/*************************************************************************/
/* ENUM CONVERSION                                                       */
/*************************************************************************/

/*
 * ZydisRegister to Register
 */
static Register convert(ZydisRegister reg)
{
    switch (reg)
    {
        case ZYDIS_REGISTER_NONE:       return REGISTER_NONE;

        case ZYDIS_REGISTER_AH:         return REGISTER_AH;
        case ZYDIS_REGISTER_CH:         return REGISTER_CH;
        case ZYDIS_REGISTER_DH:         return REGISTER_DH;
        case ZYDIS_REGISTER_BH:         return REGISTER_BH;

        case ZYDIS_REGISTER_AL:         return REGISTER_AL;
        case ZYDIS_REGISTER_CL:         return REGISTER_CL;
        case ZYDIS_REGISTER_DL:         return REGISTER_DL;
        case ZYDIS_REGISTER_BL:         return REGISTER_BL;
        case ZYDIS_REGISTER_SPL:        return REGISTER_SPL;
        case ZYDIS_REGISTER_BPL:        return REGISTER_BPL;
        case ZYDIS_REGISTER_SIL:        return REGISTER_SIL;
        case ZYDIS_REGISTER_DIL:        return REGISTER_DIL;
        case ZYDIS_REGISTER_R8B:        return REGISTER_R8B;
        case ZYDIS_REGISTER_R9B:        return REGISTER_R9B;
        case ZYDIS_REGISTER_R10B:       return REGISTER_R10B;
        case ZYDIS_REGISTER_R11B:       return REGISTER_R11B;
        case ZYDIS_REGISTER_R12B:       return REGISTER_R12B;
        case ZYDIS_REGISTER_R13B:       return REGISTER_R13B;
        case ZYDIS_REGISTER_R14B:       return REGISTER_R14B;
        case ZYDIS_REGISTER_R15B:       return REGISTER_R15B;

        case ZYDIS_REGISTER_AX:         return REGISTER_AX;
        case ZYDIS_REGISTER_CX:         return REGISTER_CX;
        case ZYDIS_REGISTER_DX:         return REGISTER_DX;
        case ZYDIS_REGISTER_BX:         return REGISTER_BX;
        case ZYDIS_REGISTER_SP:         return REGISTER_SP;
        case ZYDIS_REGISTER_BP:         return REGISTER_BP;
        case ZYDIS_REGISTER_SI:         return REGISTER_SI;
        case ZYDIS_REGISTER_DI:         return REGISTER_DI;
        case ZYDIS_REGISTER_R8W:        return REGISTER_R8W;
        case ZYDIS_REGISTER_R9W:        return REGISTER_R9W;
        case ZYDIS_REGISTER_R10W:       return REGISTER_R10W;
        case ZYDIS_REGISTER_R11W:       return REGISTER_R11W;
        case ZYDIS_REGISTER_R12W:       return REGISTER_R12W;
        case ZYDIS_REGISTER_R13W:       return REGISTER_R13W;
        case ZYDIS_REGISTER_R14W:       return REGISTER_R14W;
        case ZYDIS_REGISTER_R15W:       return REGISTER_R15W;

        case ZYDIS_REGISTER_EFLAGS:     return REGISTER_EFLAGS;
        case ZYDIS_REGISTER_IP:         return REGISTER_IP;

        case ZYDIS_REGISTER_EAX:        return REGISTER_EAX;
        case ZYDIS_REGISTER_ECX:        return REGISTER_ECX;
        case ZYDIS_REGISTER_EDX:        return REGISTER_EDX;
        case ZYDIS_REGISTER_EBX:        return REGISTER_EBX;
        case ZYDIS_REGISTER_ESP:        return REGISTER_ESP;
        case ZYDIS_REGISTER_EBP:        return REGISTER_EBP;
        case ZYDIS_REGISTER_ESI:        return REGISTER_ESI;
        case ZYDIS_REGISTER_EDI:        return REGISTER_EDI;
        case ZYDIS_REGISTER_R8D:        return REGISTER_R8D;
        case ZYDIS_REGISTER_R9D:        return REGISTER_R9D;
        case ZYDIS_REGISTER_R10D:       return REGISTER_R10D;
        case ZYDIS_REGISTER_R11D:       return REGISTER_R11D;
        case ZYDIS_REGISTER_R12D:       return REGISTER_R12D;
        case ZYDIS_REGISTER_R13D:       return REGISTER_R13D;
        case ZYDIS_REGISTER_R14D:       return REGISTER_R14D;
        case ZYDIS_REGISTER_R15D:       return REGISTER_R15D;
        
        case ZYDIS_REGISTER_EIP:        return REGISTER_EIP;

        case ZYDIS_REGISTER_RAX:        return REGISTER_RAX;
        case ZYDIS_REGISTER_RCX:        return REGISTER_RCX;
        case ZYDIS_REGISTER_RDX:        return REGISTER_RDX;
        case ZYDIS_REGISTER_RBX:        return REGISTER_RBX;
        case ZYDIS_REGISTER_RSP:        return REGISTER_RSP;
        case ZYDIS_REGISTER_RBP:        return REGISTER_RBP;
        case ZYDIS_REGISTER_RSI:        return REGISTER_RSI;
        case ZYDIS_REGISTER_RDI:        return REGISTER_RDI;
        case ZYDIS_REGISTER_R8:         return REGISTER_R8;
        case ZYDIS_REGISTER_R9:         return REGISTER_R9;
        case ZYDIS_REGISTER_R10:        return REGISTER_R10;
        case ZYDIS_REGISTER_R11:        return REGISTER_R11;
        case ZYDIS_REGISTER_R12:        return REGISTER_R12;
        case ZYDIS_REGISTER_R13:        return REGISTER_R13;
        case ZYDIS_REGISTER_R14:        return REGISTER_R14;
        case ZYDIS_REGISTER_R15:        return REGISTER_R15;
        
        case ZYDIS_REGISTER_RIP:        return REGISTER_RIP;

        case ZYDIS_REGISTER_XMM0:       return REGISTER_XMM0;
        case ZYDIS_REGISTER_XMM1:       return REGISTER_XMM1;
        case ZYDIS_REGISTER_XMM2:       return REGISTER_XMM2;
        case ZYDIS_REGISTER_XMM3:       return REGISTER_XMM3;
        case ZYDIS_REGISTER_XMM4:       return REGISTER_XMM4;
        case ZYDIS_REGISTER_XMM5:       return REGISTER_XMM5;
        case ZYDIS_REGISTER_XMM6:       return REGISTER_XMM6;
        case ZYDIS_REGISTER_XMM7:       return REGISTER_XMM7;
        case ZYDIS_REGISTER_XMM8:       return REGISTER_XMM8;
        case ZYDIS_REGISTER_XMM9:       return REGISTER_XMM9;
        case ZYDIS_REGISTER_XMM10:      return REGISTER_XMM10;
        case ZYDIS_REGISTER_XMM11:      return REGISTER_XMM11;
        case ZYDIS_REGISTER_XMM12:      return REGISTER_XMM12;
        case ZYDIS_REGISTER_XMM13:      return REGISTER_XMM13;
        case ZYDIS_REGISTER_XMM14:      return REGISTER_XMM14;
        case ZYDIS_REGISTER_XMM15:      return REGISTER_XMM15;
        case ZYDIS_REGISTER_XMM16:      return REGISTER_XMM16;
        case ZYDIS_REGISTER_XMM17:      return REGISTER_XMM17;
        case ZYDIS_REGISTER_XMM18:      return REGISTER_XMM18;
        case ZYDIS_REGISTER_XMM19:      return REGISTER_XMM19;
        case ZYDIS_REGISTER_XMM20:      return REGISTER_XMM20;
        case ZYDIS_REGISTER_XMM21:      return REGISTER_XMM21;
        case ZYDIS_REGISTER_XMM22:      return REGISTER_XMM22;
        case ZYDIS_REGISTER_XMM23:      return REGISTER_XMM23;
        case ZYDIS_REGISTER_XMM24:      return REGISTER_XMM24;
        case ZYDIS_REGISTER_XMM25:      return REGISTER_XMM25;
        case ZYDIS_REGISTER_XMM26:      return REGISTER_XMM26;
        case ZYDIS_REGISTER_XMM27:      return REGISTER_XMM27;
        case ZYDIS_REGISTER_XMM28:      return REGISTER_XMM28;
        case ZYDIS_REGISTER_XMM29:      return REGISTER_XMM29;
        case ZYDIS_REGISTER_XMM30:      return REGISTER_XMM30;
        case ZYDIS_REGISTER_XMM31:      return REGISTER_XMM31;
        
        case ZYDIS_REGISTER_YMM0:       return REGISTER_YMM0;
        case ZYDIS_REGISTER_YMM1:       return REGISTER_YMM1;
        case ZYDIS_REGISTER_YMM2:       return REGISTER_YMM2;
        case ZYDIS_REGISTER_YMM3:       return REGISTER_YMM3;
        case ZYDIS_REGISTER_YMM4:       return REGISTER_YMM4;
        case ZYDIS_REGISTER_YMM5:       return REGISTER_YMM5;
        case ZYDIS_REGISTER_YMM6:       return REGISTER_YMM6;
        case ZYDIS_REGISTER_YMM7:       return REGISTER_YMM7;
        case ZYDIS_REGISTER_YMM8:       return REGISTER_YMM8;
        case ZYDIS_REGISTER_YMM9:       return REGISTER_YMM9;
        case ZYDIS_REGISTER_YMM10:      return REGISTER_YMM10;
        case ZYDIS_REGISTER_YMM11:      return REGISTER_YMM11;
        case ZYDIS_REGISTER_YMM12:      return REGISTER_YMM12;
        case ZYDIS_REGISTER_YMM13:      return REGISTER_YMM13;
        case ZYDIS_REGISTER_YMM14:      return REGISTER_YMM14;
        case ZYDIS_REGISTER_YMM15:      return REGISTER_YMM15;
        case ZYDIS_REGISTER_YMM16:      return REGISTER_YMM16;
        case ZYDIS_REGISTER_YMM17:      return REGISTER_YMM17;
        case ZYDIS_REGISTER_YMM18:      return REGISTER_YMM18;
        case ZYDIS_REGISTER_YMM19:      return REGISTER_YMM19;
        case ZYDIS_REGISTER_YMM20:      return REGISTER_YMM20;
        case ZYDIS_REGISTER_YMM21:      return REGISTER_YMM21;
        case ZYDIS_REGISTER_YMM22:      return REGISTER_YMM22;
        case ZYDIS_REGISTER_YMM23:      return REGISTER_YMM23;
        case ZYDIS_REGISTER_YMM24:      return REGISTER_YMM24;
        case ZYDIS_REGISTER_YMM25:      return REGISTER_YMM25;
        case ZYDIS_REGISTER_YMM26:      return REGISTER_YMM26;
        case ZYDIS_REGISTER_YMM27:      return REGISTER_YMM27;
        case ZYDIS_REGISTER_YMM28:      return REGISTER_YMM28;
        case ZYDIS_REGISTER_YMM29:      return REGISTER_YMM29;
        case ZYDIS_REGISTER_YMM30:      return REGISTER_YMM30;
        case ZYDIS_REGISTER_YMM31:      return REGISTER_YMM31;

        case ZYDIS_REGISTER_ZMM0:       return REGISTER_ZMM0;
        case ZYDIS_REGISTER_ZMM1:       return REGISTER_ZMM1;
        case ZYDIS_REGISTER_ZMM2:       return REGISTER_ZMM2;
        case ZYDIS_REGISTER_ZMM3:       return REGISTER_ZMM3;
        case ZYDIS_REGISTER_ZMM4:       return REGISTER_ZMM4;
        case ZYDIS_REGISTER_ZMM5:       return REGISTER_ZMM5;
        case ZYDIS_REGISTER_ZMM6:       return REGISTER_ZMM6;
        case ZYDIS_REGISTER_ZMM7:       return REGISTER_ZMM7;
        case ZYDIS_REGISTER_ZMM8:       return REGISTER_ZMM8;
        case ZYDIS_REGISTER_ZMM9:       return REGISTER_ZMM9;
        case ZYDIS_REGISTER_ZMM10:      return REGISTER_ZMM10;
        case ZYDIS_REGISTER_ZMM11:      return REGISTER_ZMM11;
        case ZYDIS_REGISTER_ZMM12:      return REGISTER_ZMM12;
        case ZYDIS_REGISTER_ZMM13:      return REGISTER_ZMM13;
        case ZYDIS_REGISTER_ZMM14:      return REGISTER_ZMM14;
        case ZYDIS_REGISTER_ZMM15:      return REGISTER_ZMM15;
        case ZYDIS_REGISTER_ZMM16:      return REGISTER_ZMM16;
        case ZYDIS_REGISTER_ZMM17:      return REGISTER_ZMM17;
        case ZYDIS_REGISTER_ZMM18:      return REGISTER_ZMM18;
        case ZYDIS_REGISTER_ZMM19:      return REGISTER_ZMM19;
        case ZYDIS_REGISTER_ZMM20:      return REGISTER_ZMM20;
        case ZYDIS_REGISTER_ZMM21:      return REGISTER_ZMM21;
        case ZYDIS_REGISTER_ZMM22:      return REGISTER_ZMM22;
        case ZYDIS_REGISTER_ZMM23:      return REGISTER_ZMM23;
        case ZYDIS_REGISTER_ZMM24:      return REGISTER_ZMM24;
        case ZYDIS_REGISTER_ZMM25:      return REGISTER_ZMM25;
        case ZYDIS_REGISTER_ZMM26:      return REGISTER_ZMM26;
        case ZYDIS_REGISTER_ZMM27:      return REGISTER_ZMM27;
        case ZYDIS_REGISTER_ZMM28:      return REGISTER_ZMM28;
        case ZYDIS_REGISTER_ZMM29:      return REGISTER_ZMM29;
        case ZYDIS_REGISTER_ZMM30:      return REGISTER_ZMM30;
        case ZYDIS_REGISTER_ZMM31:      return REGISTER_ZMM31;

        case ZYDIS_REGISTER_ES:         return REGISTER_ES;
        case ZYDIS_REGISTER_CS:         return REGISTER_CS;
        case ZYDIS_REGISTER_SS:         return REGISTER_SS;
        case ZYDIS_REGISTER_DS:         return REGISTER_DS;
        case ZYDIS_REGISTER_FS:         return REGISTER_FS;
        case ZYDIS_REGISTER_GS:         return REGISTER_GS;

        case ZYDIS_REGISTER_CR0:        return REGISTER_CR0;
        case ZYDIS_REGISTER_CR1:        return REGISTER_CR1;
        case ZYDIS_REGISTER_CR2:        return REGISTER_CR2;
        case ZYDIS_REGISTER_CR3:        return REGISTER_CR3;
        case ZYDIS_REGISTER_CR4:        return REGISTER_CR4;
        case ZYDIS_REGISTER_CR5:        return REGISTER_CR5;
        case ZYDIS_REGISTER_CR6:        return REGISTER_CR6;
        case ZYDIS_REGISTER_CR7:        return REGISTER_CR7;
        case ZYDIS_REGISTER_CR8:        return REGISTER_CR8;
        case ZYDIS_REGISTER_CR9:        return REGISTER_CR9;
        case ZYDIS_REGISTER_CR10:       return REGISTER_CR10;
        case ZYDIS_REGISTER_CR11:       return REGISTER_CR11;
        case ZYDIS_REGISTER_CR12:       return REGISTER_CR12;
        case ZYDIS_REGISTER_CR13:       return REGISTER_CR13;
        case ZYDIS_REGISTER_CR14:       return REGISTER_CR14;
        case ZYDIS_REGISTER_CR15:       return REGISTER_CR15;
        
        case ZYDIS_REGISTER_DR0:        return REGISTER_DR0;
        case ZYDIS_REGISTER_DR1:        return REGISTER_DR1;
        case ZYDIS_REGISTER_DR2:        return REGISTER_DR2;
        case ZYDIS_REGISTER_DR3:        return REGISTER_DR3;
        case ZYDIS_REGISTER_DR4:        return REGISTER_DR4;
        case ZYDIS_REGISTER_DR5:        return REGISTER_DR5;
        case ZYDIS_REGISTER_DR6:        return REGISTER_DR6;
        case ZYDIS_REGISTER_DR7:        return REGISTER_DR7;
        case ZYDIS_REGISTER_DR8:        return REGISTER_DR8;
        case ZYDIS_REGISTER_DR9:        return REGISTER_DR9;
        case ZYDIS_REGISTER_DR10:       return REGISTER_DR10;
        case ZYDIS_REGISTER_DR11:       return REGISTER_DR11;
        case ZYDIS_REGISTER_DR12:       return REGISTER_DR12;
        case ZYDIS_REGISTER_DR13:       return REGISTER_DR13;
        case ZYDIS_REGISTER_DR14:       return REGISTER_DR14;
        case ZYDIS_REGISTER_DR15:       return REGISTER_DR15;
        
        case ZYDIS_REGISTER_K0:         return REGISTER_K0;
        case ZYDIS_REGISTER_K1:         return REGISTER_K1;
        case ZYDIS_REGISTER_K2:         return REGISTER_K2;
        case ZYDIS_REGISTER_K3:         return REGISTER_K3;
        case ZYDIS_REGISTER_K4:         return REGISTER_K4;
        case ZYDIS_REGISTER_K5:         return REGISTER_K5;
        case ZYDIS_REGISTER_K6:         return REGISTER_K6;
        case ZYDIS_REGISTER_K7:         return REGISTER_K7;
        
        case ZYDIS_REGISTER_MM0:        return REGISTER_MM0;
        case ZYDIS_REGISTER_MM1:        return REGISTER_MM1;
        case ZYDIS_REGISTER_MM2:        return REGISTER_MM2;
        case ZYDIS_REGISTER_MM3:        return REGISTER_MM3;
        case ZYDIS_REGISTER_MM4:        return REGISTER_MM4;
        case ZYDIS_REGISTER_MM5:        return REGISTER_MM5;
        case ZYDIS_REGISTER_MM6:        return REGISTER_MM6;
        case ZYDIS_REGISTER_MM7:        return REGISTER_MM7;
 
        case ZYDIS_REGISTER_ST0:        return REGISTER_ST0;
        case ZYDIS_REGISTER_ST1:        return REGISTER_ST1;
        case ZYDIS_REGISTER_ST2:        return REGISTER_ST2;
        case ZYDIS_REGISTER_ST3:        return REGISTER_ST3;
        case ZYDIS_REGISTER_ST4:        return REGISTER_ST4;
        case ZYDIS_REGISTER_ST5:        return REGISTER_ST5;
        case ZYDIS_REGISTER_ST6:        return REGISTER_ST6;
        case ZYDIS_REGISTER_ST7:        return REGISTER_ST7;

        default:                        return REGISTER_INVALID;
    }
}

/*
 * ZydisMnemonic to Mnemonic
 */
static Mnemonic convert(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    { 
        case ZYDIS_MNEMONIC_AAA:                return MNEMONIC_AAA;                                                                  
        case ZYDIS_MNEMONIC_AAD:                return MNEMONIC_AAD;
        case ZYDIS_MNEMONIC_AAM:                return MNEMONIC_AAM;
        case ZYDIS_MNEMONIC_AAS:                return MNEMONIC_AAS;
        case ZYDIS_MNEMONIC_ADC:                return MNEMONIC_ADC;
        case ZYDIS_MNEMONIC_ADCX:               return MNEMONIC_ADCX;
        case ZYDIS_MNEMONIC_ADD:                return MNEMONIC_ADD;
        case ZYDIS_MNEMONIC_ADDPD:              return MNEMONIC_ADDPD;
        case ZYDIS_MNEMONIC_ADDPS:              return MNEMONIC_ADDPS;
        case ZYDIS_MNEMONIC_ADDSD:              return MNEMONIC_ADDSD;
        case ZYDIS_MNEMONIC_ADDSS:              return MNEMONIC_ADDSS;
        case ZYDIS_MNEMONIC_ADDSUBPD:           return MNEMONIC_ADDSUBPD;
        case ZYDIS_MNEMONIC_ADDSUBPS:           return MNEMONIC_ADDSUBPS;
        case ZYDIS_MNEMONIC_ADOX:               return MNEMONIC_ADOX;
        case ZYDIS_MNEMONIC_AESDEC:             return MNEMONIC_AESDEC;
        case ZYDIS_MNEMONIC_AESDECLAST:         return MNEMONIC_AESDECLAST;
        case ZYDIS_MNEMONIC_AESENC:             return MNEMONIC_AESENC;
        case ZYDIS_MNEMONIC_AESENCLAST:         return MNEMONIC_AESENCLAST;
        case ZYDIS_MNEMONIC_AESIMC:             return MNEMONIC_AESIMC;
        case ZYDIS_MNEMONIC_AESKEYGENASSIST:    return MNEMONIC_AESKEYGENASSIST;
        case ZYDIS_MNEMONIC_AND:                return MNEMONIC_AND;
        case ZYDIS_MNEMONIC_ANDN:               return MNEMONIC_ANDN;
        case ZYDIS_MNEMONIC_ANDNPD:             return MNEMONIC_ANDNPD;
        case ZYDIS_MNEMONIC_ANDNPS:             return MNEMONIC_ANDNPS;
        case ZYDIS_MNEMONIC_ANDPD:              return MNEMONIC_ANDPD;
        case ZYDIS_MNEMONIC_ANDPS:              return MNEMONIC_ANDPS;
        case ZYDIS_MNEMONIC_ARPL:               return MNEMONIC_ARPL;
        case ZYDIS_MNEMONIC_BEXTR:              return MNEMONIC_BEXTR;
        case ZYDIS_MNEMONIC_BLCFILL:            return MNEMONIC_BLCFILL;
        case ZYDIS_MNEMONIC_BLCI:               return MNEMONIC_BLCI;
        case ZYDIS_MNEMONIC_BLCIC:              return MNEMONIC_BLCIC;
        case ZYDIS_MNEMONIC_BLCMSK:             return MNEMONIC_BLCMSK;
        case ZYDIS_MNEMONIC_BLCS:               return MNEMONIC_BLCS;
        case ZYDIS_MNEMONIC_BLENDPD:            return MNEMONIC_BLENDPD;
        case ZYDIS_MNEMONIC_BLENDPS:            return MNEMONIC_BLENDPS;
        case ZYDIS_MNEMONIC_BLENDVPD:           return MNEMONIC_BLENDVPD;
        case ZYDIS_MNEMONIC_BLENDVPS:           return MNEMONIC_BLENDVPS;
        case ZYDIS_MNEMONIC_BLSFILL:            return MNEMONIC_BLSFILL;
        case ZYDIS_MNEMONIC_BLSI:               return MNEMONIC_BLSI;
        case ZYDIS_MNEMONIC_BLSIC:              return MNEMONIC_BLSIC;
        case ZYDIS_MNEMONIC_BLSMSK:             return MNEMONIC_BLSMSK;
        case ZYDIS_MNEMONIC_BLSR:               return MNEMONIC_BLSR;
        case ZYDIS_MNEMONIC_BNDCL:              return MNEMONIC_BNDCL;
        case ZYDIS_MNEMONIC_BNDCN:              return MNEMONIC_BNDCN;
        case ZYDIS_MNEMONIC_BNDCU:              return MNEMONIC_BNDCU;
        case ZYDIS_MNEMONIC_BNDLDX:             return MNEMONIC_BNDLDX;
        case ZYDIS_MNEMONIC_BNDMK:              return MNEMONIC_BNDMK;
        case ZYDIS_MNEMONIC_BNDMOV:             return MNEMONIC_BNDMOV;
        case ZYDIS_MNEMONIC_BNDSTX:             return MNEMONIC_BNDSTX;
        case ZYDIS_MNEMONIC_BOUND:              return MNEMONIC_BOUND;
        case ZYDIS_MNEMONIC_BSF:                return MNEMONIC_BSF;
        case ZYDIS_MNEMONIC_BSR:                return MNEMONIC_BSR;
        case ZYDIS_MNEMONIC_BSWAP:              return MNEMONIC_BSWAP;
        case ZYDIS_MNEMONIC_BT:                 return MNEMONIC_BT;
        case ZYDIS_MNEMONIC_BTC:                return MNEMONIC_BTC;
        case ZYDIS_MNEMONIC_BTR:                return MNEMONIC_BTR;
        case ZYDIS_MNEMONIC_BTS:                return MNEMONIC_BTS;
        case ZYDIS_MNEMONIC_BZHI:               return MNEMONIC_BZHI;
        case ZYDIS_MNEMONIC_CALL:               return MNEMONIC_CALL;
        case ZYDIS_MNEMONIC_CBW:                return MNEMONIC_CBW;
        case ZYDIS_MNEMONIC_CDQ:                return MNEMONIC_CDQ;
        case ZYDIS_MNEMONIC_CDQE:               return MNEMONIC_CDQE;
        case ZYDIS_MNEMONIC_CLAC:               return MNEMONIC_CLAC;
        case ZYDIS_MNEMONIC_CLC:                return MNEMONIC_CLC;
        case ZYDIS_MNEMONIC_CLD:                return MNEMONIC_CLD;
        case ZYDIS_MNEMONIC_CLDEMOTE:           return MNEMONIC_CLDEMOTE;
        case ZYDIS_MNEMONIC_CLEVICT0:           return MNEMONIC_CLEVICT0;
        case ZYDIS_MNEMONIC_CLEVICT1:           return MNEMONIC_CLEVICT1;
        case ZYDIS_MNEMONIC_CLFLUSH:            return MNEMONIC_CLFLUSH;
        case ZYDIS_MNEMONIC_CLFLUSHOPT:         return MNEMONIC_CLFLUSHOPT;
        case ZYDIS_MNEMONIC_CLGI:               return MNEMONIC_CLGI;
        case ZYDIS_MNEMONIC_CLI:                return MNEMONIC_CLI;
        case ZYDIS_MNEMONIC_CLRSSBSY:           return MNEMONIC_CLRSSBSY;
        case ZYDIS_MNEMONIC_CLTS:               return MNEMONIC_CLTS;
        case ZYDIS_MNEMONIC_CLWB:               return MNEMONIC_CLWB;
        case ZYDIS_MNEMONIC_CLZERO:             return MNEMONIC_CLZERO;
        case ZYDIS_MNEMONIC_CMC:                return MNEMONIC_CMC;
        case ZYDIS_MNEMONIC_CMOVB:              return MNEMONIC_CMOVB;
        case ZYDIS_MNEMONIC_CMOVBE:             return MNEMONIC_CMOVBE;
        case ZYDIS_MNEMONIC_CMOVL:              return MNEMONIC_CMOVL;
        case ZYDIS_MNEMONIC_CMOVLE:             return MNEMONIC_CMOVLE;
        case ZYDIS_MNEMONIC_CMOVNB:             return MNEMONIC_CMOVNB;
        case ZYDIS_MNEMONIC_CMOVNBE:            return MNEMONIC_CMOVNBE;
        case ZYDIS_MNEMONIC_CMOVNL:             return MNEMONIC_CMOVNL;
        case ZYDIS_MNEMONIC_CMOVNLE:            return MNEMONIC_CMOVNLE;
        case ZYDIS_MNEMONIC_CMOVNO:             return MNEMONIC_CMOVNO;
        case ZYDIS_MNEMONIC_CMOVNP:             return MNEMONIC_CMOVNP;
        case ZYDIS_MNEMONIC_CMOVNS:             return MNEMONIC_CMOVNS;
        case ZYDIS_MNEMONIC_CMOVNZ:             return MNEMONIC_CMOVNZ;
        case ZYDIS_MNEMONIC_CMOVO:              return MNEMONIC_CMOVO;
        case ZYDIS_MNEMONIC_CMOVP:              return MNEMONIC_CMOVP;
        case ZYDIS_MNEMONIC_CMOVS:              return MNEMONIC_CMOVS;
        case ZYDIS_MNEMONIC_CMOVZ:              return MNEMONIC_CMOVZ;
        case ZYDIS_MNEMONIC_CMP:                return MNEMONIC_CMP;
        case ZYDIS_MNEMONIC_CMPPD:              return MNEMONIC_CMPPD;
        case ZYDIS_MNEMONIC_CMPPS:              return MNEMONIC_CMPPS;
        case ZYDIS_MNEMONIC_CMPSB:              return MNEMONIC_CMPSB;
        case ZYDIS_MNEMONIC_CMPSD:              return MNEMONIC_CMPSD;
        case ZYDIS_MNEMONIC_CMPSQ:              return MNEMONIC_CMPSQ;
        case ZYDIS_MNEMONIC_CMPSS:              return MNEMONIC_CMPSS;
        case ZYDIS_MNEMONIC_CMPSW:              return MNEMONIC_CMPSW;
        case ZYDIS_MNEMONIC_CMPXCHG:            return MNEMONIC_CMPXCHG;
        case ZYDIS_MNEMONIC_CMPXCHG16B:         return MNEMONIC_CMPXCHG16B;
        case ZYDIS_MNEMONIC_CMPXCHG8B:          return MNEMONIC_CMPXCHG8B;
        case ZYDIS_MNEMONIC_COMISD:             return MNEMONIC_COMISD;
        case ZYDIS_MNEMONIC_COMISS:             return MNEMONIC_COMISS;
        case ZYDIS_MNEMONIC_CPUID:              return MNEMONIC_CPUID;
        case ZYDIS_MNEMONIC_CQO:                return MNEMONIC_CQO;
        case ZYDIS_MNEMONIC_CRC32:              return MNEMONIC_CRC32;
        case ZYDIS_MNEMONIC_CVTDQ2PD:           return MNEMONIC_CVTDQ2PD;
        case ZYDIS_MNEMONIC_CVTDQ2PS:           return MNEMONIC_CVTDQ2PS;
        case ZYDIS_MNEMONIC_CVTPD2DQ:           return MNEMONIC_CVTPD2DQ;
        case ZYDIS_MNEMONIC_CVTPD2PI:           return MNEMONIC_CVTPD2PI;
        case ZYDIS_MNEMONIC_CVTPD2PS:           return MNEMONIC_CVTPD2PS;
        case ZYDIS_MNEMONIC_CVTPI2PD:           return MNEMONIC_CVTPI2PD;
        case ZYDIS_MNEMONIC_CVTPI2PS:           return MNEMONIC_CVTPI2PS;
        case ZYDIS_MNEMONIC_CVTPS2DQ:           return MNEMONIC_CVTPS2DQ;
        case ZYDIS_MNEMONIC_CVTPS2PD:           return MNEMONIC_CVTPS2PD;
        case ZYDIS_MNEMONIC_CVTPS2PI:           return MNEMONIC_CVTPS2PI;
        case ZYDIS_MNEMONIC_CVTSD2SI:           return MNEMONIC_CVTSD2SI;
        case ZYDIS_MNEMONIC_CVTSD2SS:           return MNEMONIC_CVTSD2SS;
        case ZYDIS_MNEMONIC_CVTSI2SD:           return MNEMONIC_CVTSI2SD;
        case ZYDIS_MNEMONIC_CVTSI2SS:           return MNEMONIC_CVTSI2SS;
        case ZYDIS_MNEMONIC_CVTSS2SD:           return MNEMONIC_CVTSS2SD;
        case ZYDIS_MNEMONIC_CVTSS2SI:           return MNEMONIC_CVTSS2SI;
        case ZYDIS_MNEMONIC_CVTTPD2DQ:          return MNEMONIC_CVTTPD2DQ;
        case ZYDIS_MNEMONIC_CVTTPD2PI:          return MNEMONIC_CVTTPD2PI;
        case ZYDIS_MNEMONIC_CVTTPS2DQ:          return MNEMONIC_CVTTPS2DQ;
        case ZYDIS_MNEMONIC_CVTTPS2PI:          return MNEMONIC_CVTTPS2PI;
        case ZYDIS_MNEMONIC_CVTTSD2SI:          return MNEMONIC_CVTTSD2SI;
        case ZYDIS_MNEMONIC_CVTTSS2SI:          return MNEMONIC_CVTTSS2SI;
        case ZYDIS_MNEMONIC_CWD:                return MNEMONIC_CWD;
        case ZYDIS_MNEMONIC_CWDE:               return MNEMONIC_CWDE;
        case ZYDIS_MNEMONIC_DAA:                return MNEMONIC_DAA;
        case ZYDIS_MNEMONIC_DAS:                return MNEMONIC_DAS;
        case ZYDIS_MNEMONIC_DEC:                return MNEMONIC_DEC;
        case ZYDIS_MNEMONIC_DELAY:              return MNEMONIC_DELAY;
        case ZYDIS_MNEMONIC_DIV:                return MNEMONIC_DIV;
        case ZYDIS_MNEMONIC_DIVPD:              return MNEMONIC_DIVPD;
        case ZYDIS_MNEMONIC_DIVPS:              return MNEMONIC_DIVPS;
        case ZYDIS_MNEMONIC_DIVSD:              return MNEMONIC_DIVSD;
        case ZYDIS_MNEMONIC_DIVSS:              return MNEMONIC_DIVSS;
        case ZYDIS_MNEMONIC_DPPD:               return MNEMONIC_DPPD;
        case ZYDIS_MNEMONIC_DPPS:               return MNEMONIC_DPPS;
        case ZYDIS_MNEMONIC_EMMS:               return MNEMONIC_EMMS;
        case ZYDIS_MNEMONIC_ENCLS:              return MNEMONIC_ENCLS;
        case ZYDIS_MNEMONIC_ENCLU:              return MNEMONIC_ENCLU;
        case ZYDIS_MNEMONIC_ENCLV:              return MNEMONIC_ENCLV;
        case ZYDIS_MNEMONIC_ENDBR32:            return MNEMONIC_ENDBR32;
        case ZYDIS_MNEMONIC_ENDBR64:            return MNEMONIC_ENDBR64;
        case ZYDIS_MNEMONIC_ENQCMD:             return MNEMONIC_ENQCMD;
        case ZYDIS_MNEMONIC_ENQCMDS:            return MNEMONIC_ENQCMDS;
        case ZYDIS_MNEMONIC_ENTER:              return MNEMONIC_ENTER;
        case ZYDIS_MNEMONIC_EXTRACTPS:          return MNEMONIC_EXTRACTPS;
        case ZYDIS_MNEMONIC_EXTRQ:              return MNEMONIC_EXTRQ;
        case ZYDIS_MNEMONIC_F2XM1:              return MNEMONIC_F2XM1;
        case ZYDIS_MNEMONIC_FABS:               return MNEMONIC_FABS;
        case ZYDIS_MNEMONIC_FADD:               return MNEMONIC_FADD;
        case ZYDIS_MNEMONIC_FADDP:              return MNEMONIC_FADDP;
        case ZYDIS_MNEMONIC_FBLD:               return MNEMONIC_FBLD;
        case ZYDIS_MNEMONIC_FBSTP:              return MNEMONIC_FBSTP;
        case ZYDIS_MNEMONIC_FCHS:               return MNEMONIC_FCHS;
        case ZYDIS_MNEMONIC_FCMOVB:             return MNEMONIC_FCMOVB;
        case ZYDIS_MNEMONIC_FCMOVBE:            return MNEMONIC_FCMOVBE;
        case ZYDIS_MNEMONIC_FCMOVE:             return MNEMONIC_FCMOVE;
        case ZYDIS_MNEMONIC_FCMOVNB:            return MNEMONIC_FCMOVNB;
        case ZYDIS_MNEMONIC_FCMOVNBE:           return MNEMONIC_FCMOVNBE;
        case ZYDIS_MNEMONIC_FCMOVNE:            return MNEMONIC_FCMOVNE;
        case ZYDIS_MNEMONIC_FCMOVNU:            return MNEMONIC_FCMOVNU;
        case ZYDIS_MNEMONIC_FCMOVU:             return MNEMONIC_FCMOVU;
        case ZYDIS_MNEMONIC_FCOM:               return MNEMONIC_FCOM;
        case ZYDIS_MNEMONIC_FCOMI:              return MNEMONIC_FCOMI;
        case ZYDIS_MNEMONIC_FCOMIP:             return MNEMONIC_FCOMIP;
        case ZYDIS_MNEMONIC_FCOMP:              return MNEMONIC_FCOMP;
        case ZYDIS_MNEMONIC_FCOMPP:             return MNEMONIC_FCOMPP;
        case ZYDIS_MNEMONIC_FCOS:               return MNEMONIC_FCOS;
        case ZYDIS_MNEMONIC_FDECSTP:            return MNEMONIC_FDECSTP;
        case ZYDIS_MNEMONIC_FDISI8087_NOP:      return MNEMONIC_FDISI8087_NOP;
        case ZYDIS_MNEMONIC_FDIV:               return MNEMONIC_FDIV;
        case ZYDIS_MNEMONIC_FDIVP:              return MNEMONIC_FDIVP;
        case ZYDIS_MNEMONIC_FDIVR:              return MNEMONIC_FDIVR;
        case ZYDIS_MNEMONIC_FDIVRP:             return MNEMONIC_FDIVRP;
        case ZYDIS_MNEMONIC_FEMMS:              return MNEMONIC_FEMMS;
        case ZYDIS_MNEMONIC_FENI8087_NOP:       return MNEMONIC_FENI8087_NOP;
        case ZYDIS_MNEMONIC_FFREE:              return MNEMONIC_FFREE;
        case ZYDIS_MNEMONIC_FFREEP:             return MNEMONIC_FFREEP;
        case ZYDIS_MNEMONIC_FIADD:              return MNEMONIC_FIADD;
        case ZYDIS_MNEMONIC_FICOM:              return MNEMONIC_FICOM;
        case ZYDIS_MNEMONIC_FICOMP:             return MNEMONIC_FICOMP;
        case ZYDIS_MNEMONIC_FIDIV:              return MNEMONIC_FIDIV;
        case ZYDIS_MNEMONIC_FIDIVR:             return MNEMONIC_FIDIVR;
        case ZYDIS_MNEMONIC_FILD:               return MNEMONIC_FILD;
        case ZYDIS_MNEMONIC_FIMUL:              return MNEMONIC_FIMUL;
        case ZYDIS_MNEMONIC_FINCSTP:            return MNEMONIC_FINCSTP;
        case ZYDIS_MNEMONIC_FIST:               return MNEMONIC_FIST;
        case ZYDIS_MNEMONIC_FISTP:              return MNEMONIC_FISTP;
        case ZYDIS_MNEMONIC_FISTTP:             return MNEMONIC_FISTTP;
        case ZYDIS_MNEMONIC_FISUB:              return MNEMONIC_FISUB;
        case ZYDIS_MNEMONIC_FISUBR:             return MNEMONIC_FISUBR;
        case ZYDIS_MNEMONIC_FLD:                return MNEMONIC_FLD;
        case ZYDIS_MNEMONIC_FLD1:               return MNEMONIC_FLD1;
        case ZYDIS_MNEMONIC_FLDCW:              return MNEMONIC_FLDCW;
        case ZYDIS_MNEMONIC_FLDENV:             return MNEMONIC_FLDENV;
        case ZYDIS_MNEMONIC_FLDL2E:             return MNEMONIC_FLDL2E;
        case ZYDIS_MNEMONIC_FLDL2T:             return MNEMONIC_FLDL2T;
        case ZYDIS_MNEMONIC_FLDLG2:             return MNEMONIC_FLDLG2;
        case ZYDIS_MNEMONIC_FLDLN2:             return MNEMONIC_FLDLN2;
        case ZYDIS_MNEMONIC_FLDPI:              return MNEMONIC_FLDPI;
        case ZYDIS_MNEMONIC_FLDZ:               return MNEMONIC_FLDZ;
        case ZYDIS_MNEMONIC_FMUL:               return MNEMONIC_FMUL;
        case ZYDIS_MNEMONIC_FMULP:              return MNEMONIC_FMULP;
        case ZYDIS_MNEMONIC_FNCLEX:             return MNEMONIC_FNCLEX;
        case ZYDIS_MNEMONIC_FNINIT:             return MNEMONIC_FNINIT;
        case ZYDIS_MNEMONIC_FNOP:               return MNEMONIC_FNOP;
        case ZYDIS_MNEMONIC_FNSAVE:             return MNEMONIC_FNSAVE;
        case ZYDIS_MNEMONIC_FNSTCW:             return MNEMONIC_FNSTCW;
        case ZYDIS_MNEMONIC_FNSTENV:            return MNEMONIC_FNSTENV;
        case ZYDIS_MNEMONIC_FNSTSW:             return MNEMONIC_FNSTSW;
        case ZYDIS_MNEMONIC_FPATAN:             return MNEMONIC_FPATAN;
        case ZYDIS_MNEMONIC_FPREM:              return MNEMONIC_FPREM;
        case ZYDIS_MNEMONIC_FPREM1:             return MNEMONIC_FPREM1;
        case ZYDIS_MNEMONIC_FPTAN:              return MNEMONIC_FPTAN;
        case ZYDIS_MNEMONIC_FRNDINT:            return MNEMONIC_FRNDINT;
        case ZYDIS_MNEMONIC_FRSTOR:             return MNEMONIC_FRSTOR;
        case ZYDIS_MNEMONIC_FSCALE:             return MNEMONIC_FSCALE;
        case ZYDIS_MNEMONIC_FSETPM287_NOP:      return MNEMONIC_FSETPM287_NOP;
        case ZYDIS_MNEMONIC_FSIN:               return MNEMONIC_FSIN;
        case ZYDIS_MNEMONIC_FSINCOS:            return MNEMONIC_FSINCOS;
        case ZYDIS_MNEMONIC_FSQRT:              return MNEMONIC_FSQRT;
        case ZYDIS_MNEMONIC_FST:                return MNEMONIC_FST;
        case ZYDIS_MNEMONIC_FSTP:               return MNEMONIC_FSTP;
        case ZYDIS_MNEMONIC_FSTPNCE:            return MNEMONIC_FSTPNCE;
        case ZYDIS_MNEMONIC_FSUB:               return MNEMONIC_FSUB;
        case ZYDIS_MNEMONIC_FSUBP:              return MNEMONIC_FSUBP;
        case ZYDIS_MNEMONIC_FSUBR:              return MNEMONIC_FSUBR;
        case ZYDIS_MNEMONIC_FSUBRP:             return MNEMONIC_FSUBRP;
        case ZYDIS_MNEMONIC_FTST:               return MNEMONIC_FTST;
        case ZYDIS_MNEMONIC_FUCOM:              return MNEMONIC_FUCOM;
        case ZYDIS_MNEMONIC_FUCOMI:             return MNEMONIC_FUCOMI;
        case ZYDIS_MNEMONIC_FUCOMIP:            return MNEMONIC_FUCOMIP;
        case ZYDIS_MNEMONIC_FUCOMP:             return MNEMONIC_FUCOMP;
        case ZYDIS_MNEMONIC_FUCOMPP:            return MNEMONIC_FUCOMPP;
        case ZYDIS_MNEMONIC_FWAIT:              return MNEMONIC_FWAIT;
        case ZYDIS_MNEMONIC_FXAM:               return MNEMONIC_FXAM;
        case ZYDIS_MNEMONIC_FXCH:               return MNEMONIC_FXCH;
        case ZYDIS_MNEMONIC_FXRSTOR:            return MNEMONIC_FXRSTOR;
        case ZYDIS_MNEMONIC_FXRSTOR64:          return MNEMONIC_FXRSTOR64;
        case ZYDIS_MNEMONIC_FXSAVE:             return MNEMONIC_FXSAVE;
        case ZYDIS_MNEMONIC_FXSAVE64:           return MNEMONIC_FXSAVE64;
        case ZYDIS_MNEMONIC_FXTRACT:            return MNEMONIC_FXTRACT;
        case ZYDIS_MNEMONIC_FYL2X:              return MNEMONIC_FYL2X;
        case ZYDIS_MNEMONIC_FYL2XP1:            return MNEMONIC_FYL2XP1;
        case ZYDIS_MNEMONIC_GETSEC:             return MNEMONIC_GETSEC;
        case ZYDIS_MNEMONIC_GF2P8AFFINEINVQB:   return MNEMONIC_GF2P8AFFINEINVQB;
        case ZYDIS_MNEMONIC_GF2P8AFFINEQB:      return MNEMONIC_GF2P8AFFINEQB;
        case ZYDIS_MNEMONIC_GF2P8MULB:          return MNEMONIC_GF2P8MULB;
        case ZYDIS_MNEMONIC_HADDPD:             return MNEMONIC_HADDPD;
        case ZYDIS_MNEMONIC_HADDPS:             return MNEMONIC_HADDPS;
        case ZYDIS_MNEMONIC_HLT:                return MNEMONIC_HLT;
        case ZYDIS_MNEMONIC_HSUBPD:             return MNEMONIC_HSUBPD;
        case ZYDIS_MNEMONIC_HSUBPS:             return MNEMONIC_HSUBPS;
        case ZYDIS_MNEMONIC_IDIV:               return MNEMONIC_IDIV;
        case ZYDIS_MNEMONIC_IMUL:               return MNEMONIC_IMUL;
        case ZYDIS_MNEMONIC_IN:                 return MNEMONIC_IN;
        case ZYDIS_MNEMONIC_INC:                return MNEMONIC_INC;
        case ZYDIS_MNEMONIC_INCSSPD:            return MNEMONIC_INCSSPD;
        case ZYDIS_MNEMONIC_INCSSPQ:            return MNEMONIC_INCSSPQ;
        case ZYDIS_MNEMONIC_INSB:               return MNEMONIC_INSB;
        case ZYDIS_MNEMONIC_INSD:               return MNEMONIC_INSD;
        case ZYDIS_MNEMONIC_INSERTPS:           return MNEMONIC_INSERTPS;
        case ZYDIS_MNEMONIC_INSERTQ:            return MNEMONIC_INSERTQ;
        case ZYDIS_MNEMONIC_INSW:               return MNEMONIC_INSW;
        case ZYDIS_MNEMONIC_INT:                return MNEMONIC_INT;
        case ZYDIS_MNEMONIC_INT1:               return MNEMONIC_INT1;
        case ZYDIS_MNEMONIC_INT3:               return MNEMONIC_INT3;
        case ZYDIS_MNEMONIC_INTO:               return MNEMONIC_INTO;
        case ZYDIS_MNEMONIC_INVD:               return MNEMONIC_INVD;
        case ZYDIS_MNEMONIC_INVEPT:             return MNEMONIC_INVEPT;
        case ZYDIS_MNEMONIC_INVLPG:             return MNEMONIC_INVLPG;
        case ZYDIS_MNEMONIC_INVLPGA:            return MNEMONIC_INVLPGA;
        case ZYDIS_MNEMONIC_INVLPGB:            return MNEMONIC_INVLPGB;
        case ZYDIS_MNEMONIC_INVPCID:            return MNEMONIC_INVPCID;
        case ZYDIS_MNEMONIC_INVVPID:            return MNEMONIC_INVVPID;
        case ZYDIS_MNEMONIC_IRET:               return MNEMONIC_IRET;
        case ZYDIS_MNEMONIC_IRETD:              return MNEMONIC_IRETD;
        case ZYDIS_MNEMONIC_IRETQ:              return MNEMONIC_IRETQ;
        case ZYDIS_MNEMONIC_JB:                 return MNEMONIC_JB;
        case ZYDIS_MNEMONIC_JBE:                return MNEMONIC_JBE;
        case ZYDIS_MNEMONIC_JCXZ:               return MNEMONIC_JCXZ;
        case ZYDIS_MNEMONIC_JECXZ:              return MNEMONIC_JECXZ;
        case ZYDIS_MNEMONIC_JKNZD:              return MNEMONIC_JKNZD;
        case ZYDIS_MNEMONIC_JKZD:               return MNEMONIC_JKZD;
        case ZYDIS_MNEMONIC_JL:                 return MNEMONIC_JL;
        case ZYDIS_MNEMONIC_JLE:                return MNEMONIC_JLE;
        case ZYDIS_MNEMONIC_JMP:                return MNEMONIC_JMP;
        case ZYDIS_MNEMONIC_JNB:                return MNEMONIC_JNB;
        case ZYDIS_MNEMONIC_JNBE:               return MNEMONIC_JNBE;
        case ZYDIS_MNEMONIC_JNL:                return MNEMONIC_JNL;
        case ZYDIS_MNEMONIC_JNLE:               return MNEMONIC_JNLE;
        case ZYDIS_MNEMONIC_JNO:                return MNEMONIC_JNO;
        case ZYDIS_MNEMONIC_JNP:                return MNEMONIC_JNP;
        case ZYDIS_MNEMONIC_JNS:                return MNEMONIC_JNS;
        case ZYDIS_MNEMONIC_JNZ:                return MNEMONIC_JNZ;
        case ZYDIS_MNEMONIC_JO:                 return MNEMONIC_JO;
        case ZYDIS_MNEMONIC_JP:                 return MNEMONIC_JP;
        case ZYDIS_MNEMONIC_JRCXZ:              return MNEMONIC_JRCXZ;
        case ZYDIS_MNEMONIC_JS:                 return MNEMONIC_JS;
        case ZYDIS_MNEMONIC_JZ:                 return MNEMONIC_JZ;
        case ZYDIS_MNEMONIC_KADDB:              return MNEMONIC_KADDB;
        case ZYDIS_MNEMONIC_KADDD:              return MNEMONIC_KADDD;
        case ZYDIS_MNEMONIC_KADDQ:              return MNEMONIC_KADDQ;
        case ZYDIS_MNEMONIC_KADDW:              return MNEMONIC_KADDW;
        case ZYDIS_MNEMONIC_KAND:               return MNEMONIC_KAND;
        case ZYDIS_MNEMONIC_KANDB:              return MNEMONIC_KANDB;
        case ZYDIS_MNEMONIC_KANDD:              return MNEMONIC_KANDD;
        case ZYDIS_MNEMONIC_KANDN:              return MNEMONIC_KANDN;
        case ZYDIS_MNEMONIC_KANDNB:             return MNEMONIC_KANDNB;
        case ZYDIS_MNEMONIC_KANDND:             return MNEMONIC_KANDND;
        case ZYDIS_MNEMONIC_KANDNQ:             return MNEMONIC_KANDNQ;
        case ZYDIS_MNEMONIC_KANDNR:             return MNEMONIC_KANDNR;
        case ZYDIS_MNEMONIC_KANDNW:             return MNEMONIC_KANDNW;
        case ZYDIS_MNEMONIC_KANDQ:              return MNEMONIC_KANDQ;
        case ZYDIS_MNEMONIC_KANDW:              return MNEMONIC_KANDW;
        case ZYDIS_MNEMONIC_KCONCATH:           return MNEMONIC_KCONCATH;
        case ZYDIS_MNEMONIC_KCONCATL:           return MNEMONIC_KCONCATL;
        case ZYDIS_MNEMONIC_KEXTRACT:           return MNEMONIC_KEXTRACT;
        case ZYDIS_MNEMONIC_KMERGE2L1H:         return MNEMONIC_KMERGE2L1H;
        case ZYDIS_MNEMONIC_KMERGE2L1L:         return MNEMONIC_KMERGE2L1L;
        case ZYDIS_MNEMONIC_KMOV:               return MNEMONIC_KMOV;
        case ZYDIS_MNEMONIC_KMOVB:              return MNEMONIC_KMOVB;
        case ZYDIS_MNEMONIC_KMOVD:              return MNEMONIC_KMOVD;
        case ZYDIS_MNEMONIC_KMOVQ:              return MNEMONIC_KMOVQ;
        case ZYDIS_MNEMONIC_KMOVW:              return MNEMONIC_KMOVW;
        case ZYDIS_MNEMONIC_KNOT:               return MNEMONIC_KNOT;
        case ZYDIS_MNEMONIC_KNOTB:              return MNEMONIC_KNOTB;
        case ZYDIS_MNEMONIC_KNOTD:              return MNEMONIC_KNOTD;
        case ZYDIS_MNEMONIC_KNOTQ:              return MNEMONIC_KNOTQ;
        case ZYDIS_MNEMONIC_KNOTW:              return MNEMONIC_KNOTW;
        case ZYDIS_MNEMONIC_KOR:                return MNEMONIC_KOR;
        case ZYDIS_MNEMONIC_KORB:               return MNEMONIC_KORB;
        case ZYDIS_MNEMONIC_KORD:               return MNEMONIC_KORD;
        case ZYDIS_MNEMONIC_KORQ:               return MNEMONIC_KORQ;
        case ZYDIS_MNEMONIC_KORTEST:            return MNEMONIC_KORTEST;
        case ZYDIS_MNEMONIC_KORTESTB:           return MNEMONIC_KORTESTB;
        case ZYDIS_MNEMONIC_KORTESTD:           return MNEMONIC_KORTESTD;
        case ZYDIS_MNEMONIC_KORTESTQ:           return MNEMONIC_KORTESTQ;
        case ZYDIS_MNEMONIC_KORTESTW:           return MNEMONIC_KORTESTW;
        case ZYDIS_MNEMONIC_KORW:               return MNEMONIC_KORW;
        case ZYDIS_MNEMONIC_KSHIFTLB:           return MNEMONIC_KSHIFTLB;
        case ZYDIS_MNEMONIC_KSHIFTLD:           return MNEMONIC_KSHIFTLD;
        case ZYDIS_MNEMONIC_KSHIFTLQ:           return MNEMONIC_KSHIFTLQ;
        case ZYDIS_MNEMONIC_KSHIFTLW:           return MNEMONIC_KSHIFTLW;
        case ZYDIS_MNEMONIC_KSHIFTRB:           return MNEMONIC_KSHIFTRB;
        case ZYDIS_MNEMONIC_KSHIFTRD:           return MNEMONIC_KSHIFTRD;
        case ZYDIS_MNEMONIC_KSHIFTRQ:           return MNEMONIC_KSHIFTRQ;
        case ZYDIS_MNEMONIC_KSHIFTRW:           return MNEMONIC_KSHIFTRW;
        case ZYDIS_MNEMONIC_KTESTB:             return MNEMONIC_KTESTB;
        case ZYDIS_MNEMONIC_KTESTD:             return MNEMONIC_KTESTD;
        case ZYDIS_MNEMONIC_KTESTQ:             return MNEMONIC_KTESTQ;
        case ZYDIS_MNEMONIC_KTESTW:             return MNEMONIC_KTESTW;
        case ZYDIS_MNEMONIC_KUNPCKBW:           return MNEMONIC_KUNPCKBW;
        case ZYDIS_MNEMONIC_KUNPCKDQ:           return MNEMONIC_KUNPCKDQ;
        case ZYDIS_MNEMONIC_KUNPCKWD:           return MNEMONIC_KUNPCKWD;
        case ZYDIS_MNEMONIC_KXNOR:              return MNEMONIC_KXNOR;
        case ZYDIS_MNEMONIC_KXNORB:             return MNEMONIC_KXNORB;
        case ZYDIS_MNEMONIC_KXNORD:             return MNEMONIC_KXNORD;
        case ZYDIS_MNEMONIC_KXNORQ:             return MNEMONIC_KXNORQ;
        case ZYDIS_MNEMONIC_KXNORW:             return MNEMONIC_KXNORW;
        case ZYDIS_MNEMONIC_KXOR:               return MNEMONIC_KXOR;
        case ZYDIS_MNEMONIC_KXORB:              return MNEMONIC_KXORB;
        case ZYDIS_MNEMONIC_KXORD:              return MNEMONIC_KXORD;
        case ZYDIS_MNEMONIC_KXORQ:              return MNEMONIC_KXORQ;
        case ZYDIS_MNEMONIC_KXORW:              return MNEMONIC_KXORW;
        case ZYDIS_MNEMONIC_LAHF:               return MNEMONIC_LAHF;
        case ZYDIS_MNEMONIC_LAR:                return MNEMONIC_LAR;
        case ZYDIS_MNEMONIC_LDDQU:              return MNEMONIC_LDDQU;
        case ZYDIS_MNEMONIC_LDMXCSR:            return MNEMONIC_LDMXCSR;
        case ZYDIS_MNEMONIC_LDS:                return MNEMONIC_LDS;
        case ZYDIS_MNEMONIC_LDTILECFG:          return MNEMONIC_LDTILECFG;
        case ZYDIS_MNEMONIC_LEA:                return MNEMONIC_LEA;
        case ZYDIS_MNEMONIC_LEAVE:              return MNEMONIC_LEAVE;
        case ZYDIS_MNEMONIC_LES:                return MNEMONIC_LES;
        case ZYDIS_MNEMONIC_LFENCE:             return MNEMONIC_LFENCE;
        case ZYDIS_MNEMONIC_LFS:                return MNEMONIC_LFS;
        case ZYDIS_MNEMONIC_LGDT:               return MNEMONIC_LGDT;
        case ZYDIS_MNEMONIC_LGS:                return MNEMONIC_LGS;
        case ZYDIS_MNEMONIC_LIDT:               return MNEMONIC_LIDT;
        case ZYDIS_MNEMONIC_LLDT:               return MNEMONIC_LLDT;
        case ZYDIS_MNEMONIC_LLWPCB:             return MNEMONIC_LLWPCB;
        case ZYDIS_MNEMONIC_LMSW:               return MNEMONIC_LMSW;
        case ZYDIS_MNEMONIC_LODSB:              return MNEMONIC_LODSB;
        case ZYDIS_MNEMONIC_LODSD:              return MNEMONIC_LODSD;
        case ZYDIS_MNEMONIC_LODSQ:              return MNEMONIC_LODSQ;
        case ZYDIS_MNEMONIC_LODSW:              return MNEMONIC_LODSW;
        case ZYDIS_MNEMONIC_LOOP:               return MNEMONIC_LOOP;
        case ZYDIS_MNEMONIC_LOOPE:              return MNEMONIC_LOOPE;
        case ZYDIS_MNEMONIC_LOOPNE:             return MNEMONIC_LOOPNE;
        case ZYDIS_MNEMONIC_LSL:                return MNEMONIC_LSL;
        case ZYDIS_MNEMONIC_LSS:                return MNEMONIC_LSS;
        case ZYDIS_MNEMONIC_LTR:                return MNEMONIC_LTR;
        case ZYDIS_MNEMONIC_LWPINS:             return MNEMONIC_LWPINS;
        case ZYDIS_MNEMONIC_LWPVAL:             return MNEMONIC_LWPVAL;
        case ZYDIS_MNEMONIC_LZCNT:              return MNEMONIC_LZCNT;
        case ZYDIS_MNEMONIC_MASKMOVDQU:         return MNEMONIC_MASKMOVDQU;
        case ZYDIS_MNEMONIC_MASKMOVQ:           return MNEMONIC_MASKMOVQ;
        case ZYDIS_MNEMONIC_MAXPD:              return MNEMONIC_MAXPD;
        case ZYDIS_MNEMONIC_MAXPS:              return MNEMONIC_MAXPS;
        case ZYDIS_MNEMONIC_MAXSD:              return MNEMONIC_MAXSD;
        case ZYDIS_MNEMONIC_MAXSS:              return MNEMONIC_MAXSS;
        case ZYDIS_MNEMONIC_MCOMMIT:            return MNEMONIC_MCOMMIT;
        case ZYDIS_MNEMONIC_MFENCE:             return MNEMONIC_MFENCE;
        case ZYDIS_MNEMONIC_MINPD:              return MNEMONIC_MINPD;
        case ZYDIS_MNEMONIC_MINPS:              return MNEMONIC_MINPS;
        case ZYDIS_MNEMONIC_MINSD:              return MNEMONIC_MINSD;
        case ZYDIS_MNEMONIC_MINSS:              return MNEMONIC_MINSS;
        case ZYDIS_MNEMONIC_MONITOR:            return MNEMONIC_MONITOR;
        case ZYDIS_MNEMONIC_MONITORX:           return MNEMONIC_MONITORX;
        case ZYDIS_MNEMONIC_MONTMUL:            return MNEMONIC_MONTMUL;
        case ZYDIS_MNEMONIC_MOV:                return MNEMONIC_MOV;
        case ZYDIS_MNEMONIC_MOVAPD:             return MNEMONIC_MOVAPD;
        case ZYDIS_MNEMONIC_MOVAPS:             return MNEMONIC_MOVAPS;
        case ZYDIS_MNEMONIC_MOVBE:              return MNEMONIC_MOVBE;
        case ZYDIS_MNEMONIC_MOVD:               return MNEMONIC_MOVD;
        case ZYDIS_MNEMONIC_MOVDDUP:            return MNEMONIC_MOVDDUP;
        case ZYDIS_MNEMONIC_MOVDIR64B:          return MNEMONIC_MOVDIR64B;
        case ZYDIS_MNEMONIC_MOVDIRI:            return MNEMONIC_MOVDIRI;
        case ZYDIS_MNEMONIC_MOVDQ2Q:            return MNEMONIC_MOVDQ2Q;
        case ZYDIS_MNEMONIC_MOVDQA:             return MNEMONIC_MOVDQA;
        case ZYDIS_MNEMONIC_MOVDQU:             return MNEMONIC_MOVDQU;
        case ZYDIS_MNEMONIC_MOVHLPS:            return MNEMONIC_MOVHLPS;
        case ZYDIS_MNEMONIC_MOVHPD:             return MNEMONIC_MOVHPD;
        case ZYDIS_MNEMONIC_MOVHPS:             return MNEMONIC_MOVHPS;
        case ZYDIS_MNEMONIC_MOVLHPS:            return MNEMONIC_MOVLHPS;
        case ZYDIS_MNEMONIC_MOVLPD:             return MNEMONIC_MOVLPD;
        case ZYDIS_MNEMONIC_MOVLPS:             return MNEMONIC_MOVLPS;
        case ZYDIS_MNEMONIC_MOVMSKPD:           return MNEMONIC_MOVMSKPD;
        case ZYDIS_MNEMONIC_MOVMSKPS:           return MNEMONIC_MOVMSKPS;
        case ZYDIS_MNEMONIC_MOVNTDQ:            return MNEMONIC_MOVNTDQ;
        case ZYDIS_MNEMONIC_MOVNTDQA:           return MNEMONIC_MOVNTDQA;
        case ZYDIS_MNEMONIC_MOVNTI:             return MNEMONIC_MOVNTI;
        case ZYDIS_MNEMONIC_MOVNTPD:            return MNEMONIC_MOVNTPD;
        case ZYDIS_MNEMONIC_MOVNTPS:            return MNEMONIC_MOVNTPS;
        case ZYDIS_MNEMONIC_MOVNTQ:             return MNEMONIC_MOVNTQ;
        case ZYDIS_MNEMONIC_MOVNTSD:            return MNEMONIC_MOVNTSD;
        case ZYDIS_MNEMONIC_MOVNTSS:            return MNEMONIC_MOVNTSS;
        case ZYDIS_MNEMONIC_MOVQ:               return MNEMONIC_MOVQ;
        case ZYDIS_MNEMONIC_MOVQ2DQ:            return MNEMONIC_MOVQ2DQ;
        case ZYDIS_MNEMONIC_MOVSB:              return MNEMONIC_MOVSB;
        case ZYDIS_MNEMONIC_MOVSD:              return MNEMONIC_MOVSD;
        case ZYDIS_MNEMONIC_MOVSHDUP:           return MNEMONIC_MOVSHDUP;
        case ZYDIS_MNEMONIC_MOVSLDUP:           return MNEMONIC_MOVSLDUP;
        case ZYDIS_MNEMONIC_MOVSQ:              return MNEMONIC_MOVSQ;
        case ZYDIS_MNEMONIC_MOVSS:              return MNEMONIC_MOVSS;
        case ZYDIS_MNEMONIC_MOVSW:              return MNEMONIC_MOVSW;
        case ZYDIS_MNEMONIC_MOVSX:              return MNEMONIC_MOVSX;
        case ZYDIS_MNEMONIC_MOVSXD:             return MNEMONIC_MOVSXD;
        case ZYDIS_MNEMONIC_MOVUPD:             return MNEMONIC_MOVUPD;
        case ZYDIS_MNEMONIC_MOVUPS:             return MNEMONIC_MOVUPS;
        case ZYDIS_MNEMONIC_MOVZX:              return MNEMONIC_MOVZX;
        case ZYDIS_MNEMONIC_MPSADBW:            return MNEMONIC_MPSADBW;
        case ZYDIS_MNEMONIC_MUL:                return MNEMONIC_MUL;
        case ZYDIS_MNEMONIC_MULPD:              return MNEMONIC_MULPD;
        case ZYDIS_MNEMONIC_MULPS:              return MNEMONIC_MULPS;
        case ZYDIS_MNEMONIC_MULSD:              return MNEMONIC_MULSD;
        case ZYDIS_MNEMONIC_MULSS:              return MNEMONIC_MULSS;
        case ZYDIS_MNEMONIC_MULX:               return MNEMONIC_MULX;
        case ZYDIS_MNEMONIC_MWAIT:              return MNEMONIC_MWAIT;
        case ZYDIS_MNEMONIC_MWAITX:             return MNEMONIC_MWAITX;
        case ZYDIS_MNEMONIC_NEG:                return MNEMONIC_NEG;
        case ZYDIS_MNEMONIC_NOP:                return MNEMONIC_NOP;
        case ZYDIS_MNEMONIC_NOT:                return MNEMONIC_NOT;
        case ZYDIS_MNEMONIC_OR:                 return MNEMONIC_OR;
        case ZYDIS_MNEMONIC_ORPD:               return MNEMONIC_ORPD;
        case ZYDIS_MNEMONIC_ORPS:               return MNEMONIC_ORPS;
        case ZYDIS_MNEMONIC_OUT:                return MNEMONIC_OUT;
        case ZYDIS_MNEMONIC_OUTSB:              return MNEMONIC_OUTSB;
        case ZYDIS_MNEMONIC_OUTSD:              return MNEMONIC_OUTSD;
        case ZYDIS_MNEMONIC_OUTSW:              return MNEMONIC_OUTSW;
        case ZYDIS_MNEMONIC_PABSB:              return MNEMONIC_PABSB;
        case ZYDIS_MNEMONIC_PABSD:              return MNEMONIC_PABSD;
        case ZYDIS_MNEMONIC_PABSW:              return MNEMONIC_PABSW;
        case ZYDIS_MNEMONIC_PACKSSDW:           return MNEMONIC_PACKSSDW;
        case ZYDIS_MNEMONIC_PACKSSWB:           return MNEMONIC_PACKSSWB;
        case ZYDIS_MNEMONIC_PACKUSDW:           return MNEMONIC_PACKUSDW;
        case ZYDIS_MNEMONIC_PACKUSWB:           return MNEMONIC_PACKUSWB;
        case ZYDIS_MNEMONIC_PADDB:              return MNEMONIC_PADDB;
        case ZYDIS_MNEMONIC_PADDD:              return MNEMONIC_PADDD;
        case ZYDIS_MNEMONIC_PADDQ:              return MNEMONIC_PADDQ;
        case ZYDIS_MNEMONIC_PADDSB:             return MNEMONIC_PADDSB;
        case ZYDIS_MNEMONIC_PADDSW:             return MNEMONIC_PADDSW;
        case ZYDIS_MNEMONIC_PADDUSB:            return MNEMONIC_PADDUSB;
        case ZYDIS_MNEMONIC_PADDUSW:            return MNEMONIC_PADDUSW;
        case ZYDIS_MNEMONIC_PADDW:              return MNEMONIC_PADDW;
        case ZYDIS_MNEMONIC_PALIGNR:            return MNEMONIC_PALIGNR;
        case ZYDIS_MNEMONIC_PAND:               return MNEMONIC_PAND;
        case ZYDIS_MNEMONIC_PANDN:              return MNEMONIC_PANDN;
        case ZYDIS_MNEMONIC_PAUSE:              return MNEMONIC_PAUSE;
        case ZYDIS_MNEMONIC_PAVGB:              return MNEMONIC_PAVGB;
        case ZYDIS_MNEMONIC_PAVGUSB:            return MNEMONIC_PAVGUSB;
        case ZYDIS_MNEMONIC_PAVGW:              return MNEMONIC_PAVGW;
        case ZYDIS_MNEMONIC_PBLENDVB:           return MNEMONIC_PBLENDVB;
        case ZYDIS_MNEMONIC_PBLENDW:            return MNEMONIC_PBLENDW;
        case ZYDIS_MNEMONIC_PCLMULQDQ:          return MNEMONIC_PCLMULQDQ;
        case ZYDIS_MNEMONIC_PCMPEQB:            return MNEMONIC_PCMPEQB;
        case ZYDIS_MNEMONIC_PCMPEQD:            return MNEMONIC_PCMPEQD;
        case ZYDIS_MNEMONIC_PCMPEQQ:            return MNEMONIC_PCMPEQQ;
        case ZYDIS_MNEMONIC_PCMPEQW:            return MNEMONIC_PCMPEQW;
        case ZYDIS_MNEMONIC_PCMPESTRI:          return MNEMONIC_PCMPESTRI;
        case ZYDIS_MNEMONIC_PCMPESTRM:          return MNEMONIC_PCMPESTRM;
        case ZYDIS_MNEMONIC_PCMPGTB:            return MNEMONIC_PCMPGTB;
        case ZYDIS_MNEMONIC_PCMPGTD:            return MNEMONIC_PCMPGTD;
        case ZYDIS_MNEMONIC_PCMPGTQ:            return MNEMONIC_PCMPGTQ;
        case ZYDIS_MNEMONIC_PCMPGTW:            return MNEMONIC_PCMPGTW;
        case ZYDIS_MNEMONIC_PCMPISTRI:          return MNEMONIC_PCMPISTRI;
        case ZYDIS_MNEMONIC_PCMPISTRM:          return MNEMONIC_PCMPISTRM;
        case ZYDIS_MNEMONIC_PCONFIG:            return MNEMONIC_PCONFIG;
        case ZYDIS_MNEMONIC_PDEP:               return MNEMONIC_PDEP;
        case ZYDIS_MNEMONIC_PEXT:               return MNEMONIC_PEXT;
        case ZYDIS_MNEMONIC_PEXTRB:             return MNEMONIC_PEXTRB;
        case ZYDIS_MNEMONIC_PEXTRD:             return MNEMONIC_PEXTRD;
        case ZYDIS_MNEMONIC_PEXTRQ:             return MNEMONIC_PEXTRQ;
        case ZYDIS_MNEMONIC_PEXTRW:             return MNEMONIC_PEXTRW;
        case ZYDIS_MNEMONIC_PF2ID:              return MNEMONIC_PF2ID;
        case ZYDIS_MNEMONIC_PF2IW:              return MNEMONIC_PF2IW;
        case ZYDIS_MNEMONIC_PFACC:              return MNEMONIC_PFACC;
        case ZYDIS_MNEMONIC_PFADD:              return MNEMONIC_PFADD;
        case ZYDIS_MNEMONIC_PFCMPEQ:            return MNEMONIC_PFCMPEQ;
        case ZYDIS_MNEMONIC_PFCMPGE:            return MNEMONIC_PFCMPGE;
        case ZYDIS_MNEMONIC_PFCMPGT:            return MNEMONIC_PFCMPGT;
        case ZYDIS_MNEMONIC_PFCPIT1:            return MNEMONIC_PFCPIT1;
        case ZYDIS_MNEMONIC_PFMAX:              return MNEMONIC_PFMAX;
        case ZYDIS_MNEMONIC_PFMIN:              return MNEMONIC_PFMIN;
        case ZYDIS_MNEMONIC_PFMUL:              return MNEMONIC_PFMUL;
        case ZYDIS_MNEMONIC_PFNACC:             return MNEMONIC_PFNACC;
        case ZYDIS_MNEMONIC_PFPNACC:            return MNEMONIC_PFPNACC;
        case ZYDIS_MNEMONIC_PFRCP:              return MNEMONIC_PFRCP;
        case ZYDIS_MNEMONIC_PFRCPIT2:           return MNEMONIC_PFRCPIT2;
        case ZYDIS_MNEMONIC_PFRSQIT1:           return MNEMONIC_PFRSQIT1;
        case ZYDIS_MNEMONIC_PFSQRT:             return MNEMONIC_PFSQRT;
        case ZYDIS_MNEMONIC_PFSUB:              return MNEMONIC_PFSUB;
        case ZYDIS_MNEMONIC_PFSUBR:             return MNEMONIC_PFSUBR;
        case ZYDIS_MNEMONIC_PHADDD:             return MNEMONIC_PHADDD;
        case ZYDIS_MNEMONIC_PHADDSW:            return MNEMONIC_PHADDSW;
        case ZYDIS_MNEMONIC_PHADDW:             return MNEMONIC_PHADDW;
        case ZYDIS_MNEMONIC_PHMINPOSUW:         return MNEMONIC_PHMINPOSUW;
        case ZYDIS_MNEMONIC_PHSUBD:             return MNEMONIC_PHSUBD;
        case ZYDIS_MNEMONIC_PHSUBSW:            return MNEMONIC_PHSUBSW;
        case ZYDIS_MNEMONIC_PHSUBW:             return MNEMONIC_PHSUBW;
        case ZYDIS_MNEMONIC_PI2FD:              return MNEMONIC_PI2FD;
        case ZYDIS_MNEMONIC_PI2FW:              return MNEMONIC_PI2FW;
        case ZYDIS_MNEMONIC_PINSRB:             return MNEMONIC_PINSRB;
        case ZYDIS_MNEMONIC_PINSRD:             return MNEMONIC_PINSRD;
        case ZYDIS_MNEMONIC_PINSRQ:             return MNEMONIC_PINSRQ;
        case ZYDIS_MNEMONIC_PINSRW:             return MNEMONIC_PINSRW;
        case ZYDIS_MNEMONIC_PMADDUBSW:          return MNEMONIC_PMADDUBSW;
        case ZYDIS_MNEMONIC_PMADDWD:            return MNEMONIC_PMADDWD;
        case ZYDIS_MNEMONIC_PMAXSB:             return MNEMONIC_PMAXSB;
        case ZYDIS_MNEMONIC_PMAXSD:             return MNEMONIC_PMAXSD;
        case ZYDIS_MNEMONIC_PMAXSW:             return MNEMONIC_PMAXSW;
        case ZYDIS_MNEMONIC_PMAXUB:             return MNEMONIC_PMAXUB;
        case ZYDIS_MNEMONIC_PMAXUD:             return MNEMONIC_PMAXUD;
        case ZYDIS_MNEMONIC_PMAXUW:             return MNEMONIC_PMAXUW;
        case ZYDIS_MNEMONIC_PMINSB:             return MNEMONIC_PMINSB;
        case ZYDIS_MNEMONIC_PMINSD:             return MNEMONIC_PMINSD;
        case ZYDIS_MNEMONIC_PMINSW:             return MNEMONIC_PMINSW;
        case ZYDIS_MNEMONIC_PMINUB:             return MNEMONIC_PMINUB;
        case ZYDIS_MNEMONIC_PMINUD:             return MNEMONIC_PMINUD;
        case ZYDIS_MNEMONIC_PMINUW:             return MNEMONIC_PMINUW;
        case ZYDIS_MNEMONIC_PMOVMSKB:           return MNEMONIC_PMOVMSKB;
        case ZYDIS_MNEMONIC_PMOVSXBD:           return MNEMONIC_PMOVSXBD;
        case ZYDIS_MNEMONIC_PMOVSXBQ:           return MNEMONIC_PMOVSXBQ;
        case ZYDIS_MNEMONIC_PMOVSXBW:           return MNEMONIC_PMOVSXBW;
        case ZYDIS_MNEMONIC_PMOVSXDQ:           return MNEMONIC_PMOVSXDQ;
        case ZYDIS_MNEMONIC_PMOVSXWD:           return MNEMONIC_PMOVSXWD;
        case ZYDIS_MNEMONIC_PMOVSXWQ:           return MNEMONIC_PMOVSXWQ;
        case ZYDIS_MNEMONIC_PMOVZXBD:           return MNEMONIC_PMOVZXBD;
        case ZYDIS_MNEMONIC_PMOVZXBQ:           return MNEMONIC_PMOVZXBQ;
        case ZYDIS_MNEMONIC_PMOVZXBW:           return MNEMONIC_PMOVZXBW;
        case ZYDIS_MNEMONIC_PMOVZXDQ:           return MNEMONIC_PMOVZXDQ;
        case ZYDIS_MNEMONIC_PMOVZXWD:           return MNEMONIC_PMOVZXWD;
        case ZYDIS_MNEMONIC_PMOVZXWQ:           return MNEMONIC_PMOVZXWQ;
        case ZYDIS_MNEMONIC_PMULDQ:             return MNEMONIC_PMULDQ;
        case ZYDIS_MNEMONIC_PMULHRSW:           return MNEMONIC_PMULHRSW;
        case ZYDIS_MNEMONIC_PMULHRW:            return MNEMONIC_PMULHRW;
        case ZYDIS_MNEMONIC_PMULHUW:            return MNEMONIC_PMULHUW;
        case ZYDIS_MNEMONIC_PMULHW:             return MNEMONIC_PMULHW;
        case ZYDIS_MNEMONIC_PMULLD:             return MNEMONIC_PMULLD;
        case ZYDIS_MNEMONIC_PMULLW:             return MNEMONIC_PMULLW;
        case ZYDIS_MNEMONIC_PMULUDQ:            return MNEMONIC_PMULUDQ;
        case ZYDIS_MNEMONIC_POP:                return MNEMONIC_POP;
        case ZYDIS_MNEMONIC_POPA:               return MNEMONIC_POPA;
        case ZYDIS_MNEMONIC_POPAD:              return MNEMONIC_POPAD;
        case ZYDIS_MNEMONIC_POPCNT:             return MNEMONIC_POPCNT;
        case ZYDIS_MNEMONIC_POPF:               return MNEMONIC_POPF;
        case ZYDIS_MNEMONIC_POPFD:              return MNEMONIC_POPFD;
        case ZYDIS_MNEMONIC_POPFQ:              return MNEMONIC_POPFQ;
        case ZYDIS_MNEMONIC_POR:                return MNEMONIC_POR;
        case ZYDIS_MNEMONIC_PREFETCH:           return MNEMONIC_PREFETCH;
        case ZYDIS_MNEMONIC_PREFETCHNTA:        return MNEMONIC_PREFETCHNTA;
        case ZYDIS_MNEMONIC_PREFETCHT0:         return MNEMONIC_PREFETCHT0;
        case ZYDIS_MNEMONIC_PREFETCHT1:         return MNEMONIC_PREFETCHT1;
        case ZYDIS_MNEMONIC_PREFETCHT2:         return MNEMONIC_PREFETCHT2;
        case ZYDIS_MNEMONIC_PREFETCHW:          return MNEMONIC_PREFETCHW;
        case ZYDIS_MNEMONIC_PREFETCHWT1:        return MNEMONIC_PREFETCHWT1;
        case ZYDIS_MNEMONIC_PSADBW:             return MNEMONIC_PSADBW;
        case ZYDIS_MNEMONIC_PSHUFB:             return MNEMONIC_PSHUFB;
        case ZYDIS_MNEMONIC_PSHUFD:             return MNEMONIC_PSHUFD;
        case ZYDIS_MNEMONIC_PSHUFHW:            return MNEMONIC_PSHUFHW;
        case ZYDIS_MNEMONIC_PSHUFLW:            return MNEMONIC_PSHUFLW;
        case ZYDIS_MNEMONIC_PSHUFW:             return MNEMONIC_PSHUFW;
        case ZYDIS_MNEMONIC_PSIGNB:             return MNEMONIC_PSIGNB;
        case ZYDIS_MNEMONIC_PSIGND:             return MNEMONIC_PSIGND;
        case ZYDIS_MNEMONIC_PSIGNW:             return MNEMONIC_PSIGNW;
        case ZYDIS_MNEMONIC_PSLLD:              return MNEMONIC_PSLLD;
        case ZYDIS_MNEMONIC_PSLLDQ:             return MNEMONIC_PSLLDQ;
        case ZYDIS_MNEMONIC_PSLLQ:              return MNEMONIC_PSLLQ;
        case ZYDIS_MNEMONIC_PSLLW:              return MNEMONIC_PSLLW;
        case ZYDIS_MNEMONIC_PSMASH:             return MNEMONIC_PSMASH;
        case ZYDIS_MNEMONIC_PSRAD:              return MNEMONIC_PSRAD;
        case ZYDIS_MNEMONIC_PSRAW:              return MNEMONIC_PSRAW;
        case ZYDIS_MNEMONIC_PSRLD:              return MNEMONIC_PSRLD;
        case ZYDIS_MNEMONIC_PSRLDQ:             return MNEMONIC_PSRLDQ;
        case ZYDIS_MNEMONIC_PSRLQ:              return MNEMONIC_PSRLQ;
        case ZYDIS_MNEMONIC_PSRLW:              return MNEMONIC_PSRLW;
        case ZYDIS_MNEMONIC_PSUBB:              return MNEMONIC_PSUBB;
        case ZYDIS_MNEMONIC_PSUBD:              return MNEMONIC_PSUBD;
        case ZYDIS_MNEMONIC_PSUBQ:              return MNEMONIC_PSUBQ;
        case ZYDIS_MNEMONIC_PSUBSB:             return MNEMONIC_PSUBSB;
        case ZYDIS_MNEMONIC_PSUBSW:             return MNEMONIC_PSUBSW;
        case ZYDIS_MNEMONIC_PSUBUSB:            return MNEMONIC_PSUBUSB;
        case ZYDIS_MNEMONIC_PSUBUSW:            return MNEMONIC_PSUBUSW;
        case ZYDIS_MNEMONIC_PSUBW:              return MNEMONIC_PSUBW;
        case ZYDIS_MNEMONIC_PSWAPD:             return MNEMONIC_PSWAPD;
        case ZYDIS_MNEMONIC_PTEST:              return MNEMONIC_PTEST;
        case ZYDIS_MNEMONIC_PTWRITE:            return MNEMONIC_PTWRITE;
        case ZYDIS_MNEMONIC_PUNPCKHBW:          return MNEMONIC_PUNPCKHBW;
        case ZYDIS_MNEMONIC_PUNPCKHDQ:          return MNEMONIC_PUNPCKHDQ;
        case ZYDIS_MNEMONIC_PUNPCKHQDQ:         return MNEMONIC_PUNPCKHQDQ;
        case ZYDIS_MNEMONIC_PUNPCKHWD:          return MNEMONIC_PUNPCKHWD;
        case ZYDIS_MNEMONIC_PUNPCKLBW:          return MNEMONIC_PUNPCKLBW;
        case ZYDIS_MNEMONIC_PUNPCKLDQ:          return MNEMONIC_PUNPCKLDQ;
        case ZYDIS_MNEMONIC_PUNPCKLQDQ:         return MNEMONIC_PUNPCKLQDQ;
        case ZYDIS_MNEMONIC_PUNPCKLWD:          return MNEMONIC_PUNPCKLWD;
        case ZYDIS_MNEMONIC_PUSH:               return MNEMONIC_PUSH;
        case ZYDIS_MNEMONIC_PUSHA:              return MNEMONIC_PUSHA;
        case ZYDIS_MNEMONIC_PUSHAD:             return MNEMONIC_PUSHAD;
        case ZYDIS_MNEMONIC_PUSHF:              return MNEMONIC_PUSHF;
        case ZYDIS_MNEMONIC_PUSHFD:             return MNEMONIC_PUSHFD;
        case ZYDIS_MNEMONIC_PUSHFQ:             return MNEMONIC_PUSHFQ;
        case ZYDIS_MNEMONIC_PVALIDATE:          return MNEMONIC_PVALIDATE;
        case ZYDIS_MNEMONIC_PXOR:               return MNEMONIC_PXOR;
        case ZYDIS_MNEMONIC_RCL:                return MNEMONIC_RCL;
        case ZYDIS_MNEMONIC_RCPPS:              return MNEMONIC_RCPPS;
        case ZYDIS_MNEMONIC_RCPSS:              return MNEMONIC_RCPSS;
        case ZYDIS_MNEMONIC_RCR:                return MNEMONIC_RCR;
        case ZYDIS_MNEMONIC_RDFSBASE:           return MNEMONIC_RDFSBASE;
        case ZYDIS_MNEMONIC_RDGSBASE:           return MNEMONIC_RDGSBASE;
        case ZYDIS_MNEMONIC_RDMSR:              return MNEMONIC_RDMSR;
        case ZYDIS_MNEMONIC_RDPID:              return MNEMONIC_RDPID;
        case ZYDIS_MNEMONIC_RDPKRU:             return MNEMONIC_RDPKRU;
        case ZYDIS_MNEMONIC_RDPMC:              return MNEMONIC_RDPMC;
        case ZYDIS_MNEMONIC_RDPRU:              return MNEMONIC_RDPRU;
        case ZYDIS_MNEMONIC_RDRAND:             return MNEMONIC_RDRAND;
        case ZYDIS_MNEMONIC_RDSEED:             return MNEMONIC_RDSEED;
        case ZYDIS_MNEMONIC_RDSSPD:             return MNEMONIC_RDSSPD;
        case ZYDIS_MNEMONIC_RDSSPQ:             return MNEMONIC_RDSSPQ;
        case ZYDIS_MNEMONIC_RDTSC:              return MNEMONIC_RDTSC;
        case ZYDIS_MNEMONIC_RDTSCP:             return MNEMONIC_RDTSCP;
        case ZYDIS_MNEMONIC_RET:                return MNEMONIC_RET;
        case ZYDIS_MNEMONIC_RMPADJUST:          return MNEMONIC_RMPADJUST;
        case ZYDIS_MNEMONIC_RMPUPDATE:          return MNEMONIC_RMPUPDATE;
        case ZYDIS_MNEMONIC_ROL:                return MNEMONIC_ROL;
        case ZYDIS_MNEMONIC_ROR:                return MNEMONIC_ROR;
        case ZYDIS_MNEMONIC_RORX:               return MNEMONIC_RORX;
        case ZYDIS_MNEMONIC_ROUNDPD:            return MNEMONIC_ROUNDPD;
        case ZYDIS_MNEMONIC_ROUNDPS:            return MNEMONIC_ROUNDPS;
        case ZYDIS_MNEMONIC_ROUNDSD:            return MNEMONIC_ROUNDSD;
        case ZYDIS_MNEMONIC_ROUNDSS:            return MNEMONIC_ROUNDSS;
        case ZYDIS_MNEMONIC_RSM:                return MNEMONIC_RSM;
        case ZYDIS_MNEMONIC_RSQRTPS:            return MNEMONIC_RSQRTPS;
        case ZYDIS_MNEMONIC_RSQRTSS:            return MNEMONIC_RSQRTSS;
        case ZYDIS_MNEMONIC_RSTORSSP:           return MNEMONIC_RSTORSSP;
        case ZYDIS_MNEMONIC_SAHF:               return MNEMONIC_SAHF;
        case ZYDIS_MNEMONIC_SALC:               return MNEMONIC_SALC;
        case ZYDIS_MNEMONIC_SAR:                return MNEMONIC_SAR;
        case ZYDIS_MNEMONIC_SARX:               return MNEMONIC_SARX;
        case ZYDIS_MNEMONIC_SAVEPREVSSP:        return MNEMONIC_SAVEPREVSSP;
        case ZYDIS_MNEMONIC_SBB:                return MNEMONIC_SBB;
        case ZYDIS_MNEMONIC_SCASB:              return MNEMONIC_SCASB;
        case ZYDIS_MNEMONIC_SCASD:              return MNEMONIC_SCASD;
        case ZYDIS_MNEMONIC_SCASQ:              return MNEMONIC_SCASQ;
        case ZYDIS_MNEMONIC_SCASW:              return MNEMONIC_SCASW;
        case ZYDIS_MNEMONIC_SERIALIZE:          return MNEMONIC_SERIALIZE;
        case ZYDIS_MNEMONIC_SETB:               return MNEMONIC_SETB;
        case ZYDIS_MNEMONIC_SETBE:              return MNEMONIC_SETBE;
        case ZYDIS_MNEMONIC_SETL:               return MNEMONIC_SETL;
        case ZYDIS_MNEMONIC_SETLE:              return MNEMONIC_SETLE;
        case ZYDIS_MNEMONIC_SETNB:              return MNEMONIC_SETNB;
        case ZYDIS_MNEMONIC_SETNBE:             return MNEMONIC_SETNBE;
        case ZYDIS_MNEMONIC_SETNL:              return MNEMONIC_SETNL;
        case ZYDIS_MNEMONIC_SETNLE:             return MNEMONIC_SETNLE;
        case ZYDIS_MNEMONIC_SETNO:              return MNEMONIC_SETNO;
        case ZYDIS_MNEMONIC_SETNP:              return MNEMONIC_SETNP;
        case ZYDIS_MNEMONIC_SETNS:              return MNEMONIC_SETNS;
        case ZYDIS_MNEMONIC_SETNZ:              return MNEMONIC_SETNZ;
        case ZYDIS_MNEMONIC_SETO:               return MNEMONIC_SETO;
        case ZYDIS_MNEMONIC_SETP:               return MNEMONIC_SETP;
        case ZYDIS_MNEMONIC_SETS:               return MNEMONIC_SETS;
        case ZYDIS_MNEMONIC_SETSSBSY:           return MNEMONIC_SETSSBSY;
        case ZYDIS_MNEMONIC_SETZ:               return MNEMONIC_SETZ;
        case ZYDIS_MNEMONIC_SFENCE:             return MNEMONIC_SFENCE;
        case ZYDIS_MNEMONIC_SGDT:               return MNEMONIC_SGDT;
        case ZYDIS_MNEMONIC_SHA1MSG1:           return MNEMONIC_SHA1MSG1;
        case ZYDIS_MNEMONIC_SHA1MSG2:           return MNEMONIC_SHA1MSG2;
        case ZYDIS_MNEMONIC_SHA1NEXTE:          return MNEMONIC_SHA1NEXTE;
        case ZYDIS_MNEMONIC_SHA1RNDS4:          return MNEMONIC_SHA1RNDS4;
        case ZYDIS_MNEMONIC_SHA256MSG1:         return MNEMONIC_SHA256MSG1;
        case ZYDIS_MNEMONIC_SHA256MSG2:         return MNEMONIC_SHA256MSG2;
        case ZYDIS_MNEMONIC_SHA256RNDS2:        return MNEMONIC_SHA256RNDS2;
        case ZYDIS_MNEMONIC_SHL:                return MNEMONIC_SHL;
        case ZYDIS_MNEMONIC_SHLD:               return MNEMONIC_SHLD;
        case ZYDIS_MNEMONIC_SHLX:               return MNEMONIC_SHLX;
        case ZYDIS_MNEMONIC_SHR:                return MNEMONIC_SHR;
        case ZYDIS_MNEMONIC_SHRD:               return MNEMONIC_SHRD;
        case ZYDIS_MNEMONIC_SHRX:               return MNEMONIC_SHRX;
        case ZYDIS_MNEMONIC_SHUFPD:             return MNEMONIC_SHUFPD;
        case ZYDIS_MNEMONIC_SHUFPS:             return MNEMONIC_SHUFPS;
        case ZYDIS_MNEMONIC_SIDT:               return MNEMONIC_SIDT;
        case ZYDIS_MNEMONIC_SKINIT:             return MNEMONIC_SKINIT;
        case ZYDIS_MNEMONIC_SLDT:               return MNEMONIC_SLDT;
        case ZYDIS_MNEMONIC_SLWPCB:             return MNEMONIC_SLWPCB;
        case ZYDIS_MNEMONIC_SMSW:               return MNEMONIC_SMSW;
        case ZYDIS_MNEMONIC_SPFLT:              return MNEMONIC_SPFLT;
        case ZYDIS_MNEMONIC_SQRTPD:             return MNEMONIC_SQRTPD;
        case ZYDIS_MNEMONIC_SQRTPS:             return MNEMONIC_SQRTPS;
        case ZYDIS_MNEMONIC_SQRTSD:             return MNEMONIC_SQRTSD;
        case ZYDIS_MNEMONIC_SQRTSS:             return MNEMONIC_SQRTSS;
        case ZYDIS_MNEMONIC_STAC:               return MNEMONIC_STAC;
        case ZYDIS_MNEMONIC_STC:                return MNEMONIC_STC;
        case ZYDIS_MNEMONIC_STD:                return MNEMONIC_STD;
        case ZYDIS_MNEMONIC_STGI:               return MNEMONIC_STGI;
        case ZYDIS_MNEMONIC_STI:                return MNEMONIC_STI;
        case ZYDIS_MNEMONIC_STMXCSR:            return MNEMONIC_STMXCSR;
        case ZYDIS_MNEMONIC_STOSB:              return MNEMONIC_STOSB;
        case ZYDIS_MNEMONIC_STOSD:              return MNEMONIC_STOSD;
        case ZYDIS_MNEMONIC_STOSQ:              return MNEMONIC_STOSQ;
        case ZYDIS_MNEMONIC_STOSW:              return MNEMONIC_STOSW;
        case ZYDIS_MNEMONIC_STR:                return MNEMONIC_STR;
        case ZYDIS_MNEMONIC_STTILECFG:          return MNEMONIC_STTILECFG;
        case ZYDIS_MNEMONIC_SUB:                return MNEMONIC_SUB;
        case ZYDIS_MNEMONIC_SUBPD:              return MNEMONIC_SUBPD;
        case ZYDIS_MNEMONIC_SUBPS:              return MNEMONIC_SUBPS;
        case ZYDIS_MNEMONIC_SUBSD:              return MNEMONIC_SUBSD;
        case ZYDIS_MNEMONIC_SUBSS:              return MNEMONIC_SUBSS;
        case ZYDIS_MNEMONIC_SWAPGS:             return MNEMONIC_SWAPGS;
        case ZYDIS_MNEMONIC_SYSCALL:            return MNEMONIC_SYSCALL;
        case ZYDIS_MNEMONIC_SYSENTER:           return MNEMONIC_SYSENTER;
        case ZYDIS_MNEMONIC_SYSEXIT:            return MNEMONIC_SYSEXIT;
        case ZYDIS_MNEMONIC_SYSRET:             return MNEMONIC_SYSRET;
        case ZYDIS_MNEMONIC_T1MSKC:             return MNEMONIC_T1MSKC;
        case ZYDIS_MNEMONIC_TDPBF16PS:          return MNEMONIC_TDPBF16PS;
        case ZYDIS_MNEMONIC_TDPBSSD:            return MNEMONIC_TDPBSSD;
        case ZYDIS_MNEMONIC_TDPBSUD:            return MNEMONIC_TDPBSUD;
        case ZYDIS_MNEMONIC_TDPBUSD:            return MNEMONIC_TDPBUSD;
        case ZYDIS_MNEMONIC_TDPBUUD:            return MNEMONIC_TDPBUUD;
        case ZYDIS_MNEMONIC_TEST:               return MNEMONIC_TEST;
        case ZYDIS_MNEMONIC_TILELOADD:          return MNEMONIC_TILELOADD;
        case ZYDIS_MNEMONIC_TILELOADDT1:        return MNEMONIC_TILELOADDT1;
        case ZYDIS_MNEMONIC_TILERELEASE:        return MNEMONIC_TILERELEASE;
        case ZYDIS_MNEMONIC_TILESTORED:         return MNEMONIC_TILESTORED;
        case ZYDIS_MNEMONIC_TILEZERO:           return MNEMONIC_TILEZERO;
        case ZYDIS_MNEMONIC_TLBSYNC:            return MNEMONIC_TLBSYNC;
        case ZYDIS_MNEMONIC_TPAUSE:             return MNEMONIC_TPAUSE;
        case ZYDIS_MNEMONIC_TZCNT:              return MNEMONIC_TZCNT;
        case ZYDIS_MNEMONIC_TZCNTI:             return MNEMONIC_TZCNTI;
        case ZYDIS_MNEMONIC_TZMSK:              return MNEMONIC_TZMSK;
        case ZYDIS_MNEMONIC_UCOMISD:            return MNEMONIC_UCOMISD;
        case ZYDIS_MNEMONIC_UCOMISS:            return MNEMONIC_UCOMISS;
        case ZYDIS_MNEMONIC_UD0:                return MNEMONIC_UD0;
        case ZYDIS_MNEMONIC_UD1:                return MNEMONIC_UD1;
        case ZYDIS_MNEMONIC_UD2:                return MNEMONIC_UD2;
        case ZYDIS_MNEMONIC_UMONITOR:           return MNEMONIC_UMONITOR;
        case ZYDIS_MNEMONIC_UMWAIT:             return MNEMONIC_UMWAIT;
        case ZYDIS_MNEMONIC_UNPCKHPD:           return MNEMONIC_UNPCKHPD;
        case ZYDIS_MNEMONIC_UNPCKHPS:           return MNEMONIC_UNPCKHPS;
        case ZYDIS_MNEMONIC_UNPCKLPD:           return MNEMONIC_UNPCKLPD;
        case ZYDIS_MNEMONIC_UNPCKLPS:           return MNEMONIC_UNPCKLPS;
        case ZYDIS_MNEMONIC_V4FMADDPS:          return MNEMONIC_V4FMADDPS;
        case ZYDIS_MNEMONIC_V4FMADDSS:          return MNEMONIC_V4FMADDSS;
        case ZYDIS_MNEMONIC_V4FNMADDPS:         return MNEMONIC_V4FNMADDPS;
        case ZYDIS_MNEMONIC_V4FNMADDSS:         return MNEMONIC_V4FNMADDSS;
        case ZYDIS_MNEMONIC_VADDNPD:            return MNEMONIC_VADDNPD;
        case ZYDIS_MNEMONIC_VADDNPS:            return MNEMONIC_VADDNPS;
        case ZYDIS_MNEMONIC_VADDPD:             return MNEMONIC_VADDPD;
        case ZYDIS_MNEMONIC_VADDPS:             return MNEMONIC_VADDPS;
        case ZYDIS_MNEMONIC_VADDSD:             return MNEMONIC_VADDSD;
        case ZYDIS_MNEMONIC_VADDSETSPS:         return MNEMONIC_VADDSETSPS;
        case ZYDIS_MNEMONIC_VADDSS:             return MNEMONIC_VADDSS;
        case ZYDIS_MNEMONIC_VADDSUBPD:          return MNEMONIC_VADDSUBPD;
        case ZYDIS_MNEMONIC_VADDSUBPS:          return MNEMONIC_VADDSUBPS;
        case ZYDIS_MNEMONIC_VAESDEC:            return MNEMONIC_VAESDEC;
        case ZYDIS_MNEMONIC_VAESDECLAST:        return MNEMONIC_VAESDECLAST;
        case ZYDIS_MNEMONIC_VAESENC:            return MNEMONIC_VAESENC;
        case ZYDIS_MNEMONIC_VAESENCLAST:        return MNEMONIC_VAESENCLAST;
        case ZYDIS_MNEMONIC_VAESIMC:            return MNEMONIC_VAESIMC;
        case ZYDIS_MNEMONIC_VAESKEYGENASSIST:   return MNEMONIC_VAESKEYGENASSIST;
        case ZYDIS_MNEMONIC_VALIGND:            return MNEMONIC_VALIGND;
        case ZYDIS_MNEMONIC_VALIGNQ:            return MNEMONIC_VALIGNQ;
        case ZYDIS_MNEMONIC_VANDNPD:            return MNEMONIC_VANDNPD;
        case ZYDIS_MNEMONIC_VANDNPS:            return MNEMONIC_VANDNPS;
        case ZYDIS_MNEMONIC_VANDPD:             return MNEMONIC_VANDPD;
        case ZYDIS_MNEMONIC_VANDPS:             return MNEMONIC_VANDPS;
        case ZYDIS_MNEMONIC_VBLENDMPD:          return MNEMONIC_VBLENDMPD;
        case ZYDIS_MNEMONIC_VBLENDMPS:          return MNEMONIC_VBLENDMPS;
        case ZYDIS_MNEMONIC_VBLENDPD:           return MNEMONIC_VBLENDPD;
        case ZYDIS_MNEMONIC_VBLENDPS:           return MNEMONIC_VBLENDPS;
        case ZYDIS_MNEMONIC_VBLENDVPD:          return MNEMONIC_VBLENDVPD;
        case ZYDIS_MNEMONIC_VBLENDVPS:          return MNEMONIC_VBLENDVPS;
        case ZYDIS_MNEMONIC_VBROADCASTF128:     return MNEMONIC_VBROADCASTF128;
        case ZYDIS_MNEMONIC_VBROADCASTF32X2:    return MNEMONIC_VBROADCASTF32X2;
        case ZYDIS_MNEMONIC_VBROADCASTF32X4:    return MNEMONIC_VBROADCASTF32X4;
        case ZYDIS_MNEMONIC_VBROADCASTF32X8:    return MNEMONIC_VBROADCASTF32X8;
        case ZYDIS_MNEMONIC_VBROADCASTF64X2:    return MNEMONIC_VBROADCASTF64X2;
        case ZYDIS_MNEMONIC_VBROADCASTF64X4:    return MNEMONIC_VBROADCASTF64X4;
        case ZYDIS_MNEMONIC_VBROADCASTI128:     return MNEMONIC_VBROADCASTI128;
        case ZYDIS_MNEMONIC_VBROADCASTI32X2:    return MNEMONIC_VBROADCASTI32X2;
        case ZYDIS_MNEMONIC_VBROADCASTI32X4:    return MNEMONIC_VBROADCASTI32X4;
        case ZYDIS_MNEMONIC_VBROADCASTI32X8:    return MNEMONIC_VBROADCASTI32X8;
        case ZYDIS_MNEMONIC_VBROADCASTI64X2:    return MNEMONIC_VBROADCASTI64X2;
        case ZYDIS_MNEMONIC_VBROADCASTI64X4:    return MNEMONIC_VBROADCASTI64X4;
        case ZYDIS_MNEMONIC_VBROADCASTSD:       return MNEMONIC_VBROADCASTSD;
        case ZYDIS_MNEMONIC_VBROADCASTSS:       return MNEMONIC_VBROADCASTSS;
        case ZYDIS_MNEMONIC_VCMPPD:             return MNEMONIC_VCMPPD;
        case ZYDIS_MNEMONIC_VCMPPS:             return MNEMONIC_VCMPPS;
        case ZYDIS_MNEMONIC_VCMPSD:             return MNEMONIC_VCMPSD;
        case ZYDIS_MNEMONIC_VCMPSS:             return MNEMONIC_VCMPSS;
        case ZYDIS_MNEMONIC_VCOMISD:            return MNEMONIC_VCOMISD;
        case ZYDIS_MNEMONIC_VCOMISS:            return MNEMONIC_VCOMISS;
        case ZYDIS_MNEMONIC_VCOMPRESSPD:        return MNEMONIC_VCOMPRESSPD;
        case ZYDIS_MNEMONIC_VCOMPRESSPS:        return MNEMONIC_VCOMPRESSPS;
        case ZYDIS_MNEMONIC_VCVTDQ2PD:          return MNEMONIC_VCVTDQ2PD;
        case ZYDIS_MNEMONIC_VCVTDQ2PS:          return MNEMONIC_VCVTDQ2PS;
        case ZYDIS_MNEMONIC_VCVTFXPNTDQ2PS:     return MNEMONIC_VCVTFXPNTDQ2PS;
        case ZYDIS_MNEMONIC_VCVTFXPNTPD2DQ:     return MNEMONIC_VCVTFXPNTPD2DQ;
        case ZYDIS_MNEMONIC_VCVTFXPNTPD2UDQ:    return MNEMONIC_VCVTFXPNTPD2UDQ;
        case ZYDIS_MNEMONIC_VCVTFXPNTPS2DQ:     return MNEMONIC_VCVTFXPNTPS2DQ;
        case ZYDIS_MNEMONIC_VCVTFXPNTPS2UDQ:    return MNEMONIC_VCVTFXPNTPS2UDQ;
        case ZYDIS_MNEMONIC_VCVTFXPNTUDQ2PS:    return MNEMONIC_VCVTFXPNTUDQ2PS;
        case ZYDIS_MNEMONIC_VCVTNE2PS2BF16:     return MNEMONIC_VCVTNE2PS2BF16;
        case ZYDIS_MNEMONIC_VCVTNEPS2BF16:      return MNEMONIC_VCVTNEPS2BF16;
        case ZYDIS_MNEMONIC_VCVTPD2DQ:          return MNEMONIC_VCVTPD2DQ;
        case ZYDIS_MNEMONIC_VCVTPD2PS:          return MNEMONIC_VCVTPD2PS;
        case ZYDIS_MNEMONIC_VCVTPD2QQ:          return MNEMONIC_VCVTPD2QQ;
        case ZYDIS_MNEMONIC_VCVTPD2UDQ:         return MNEMONIC_VCVTPD2UDQ;
        case ZYDIS_MNEMONIC_VCVTPD2UQQ:         return MNEMONIC_VCVTPD2UQQ;
        case ZYDIS_MNEMONIC_VCVTPH2PS:          return MNEMONIC_VCVTPH2PS;
        case ZYDIS_MNEMONIC_VCVTPS2DQ:          return MNEMONIC_VCVTPS2DQ;
        case ZYDIS_MNEMONIC_VCVTPS2PD:          return MNEMONIC_VCVTPS2PD;
        case ZYDIS_MNEMONIC_VCVTPS2PH:          return MNEMONIC_VCVTPS2PH;
        case ZYDIS_MNEMONIC_VCVTPS2QQ:          return MNEMONIC_VCVTPS2QQ;
        case ZYDIS_MNEMONIC_VCVTPS2UDQ:         return MNEMONIC_VCVTPS2UDQ;
        case ZYDIS_MNEMONIC_VCVTPS2UQQ:         return MNEMONIC_VCVTPS2UQQ;
        case ZYDIS_MNEMONIC_VCVTQQ2PD:          return MNEMONIC_VCVTQQ2PD;
        case ZYDIS_MNEMONIC_VCVTQQ2PS:          return MNEMONIC_VCVTQQ2PS;
        case ZYDIS_MNEMONIC_VCVTSD2SI:          return MNEMONIC_VCVTSD2SI;
        case ZYDIS_MNEMONIC_VCVTSD2SS:          return MNEMONIC_VCVTSD2SS;
        case ZYDIS_MNEMONIC_VCVTSD2USI:         return MNEMONIC_VCVTSD2USI;
        case ZYDIS_MNEMONIC_VCVTSI2SD:          return MNEMONIC_VCVTSI2SD;
        case ZYDIS_MNEMONIC_VCVTSI2SS:          return MNEMONIC_VCVTSI2SS;
        case ZYDIS_MNEMONIC_VCVTSS2SD:          return MNEMONIC_VCVTSS2SD;
        case ZYDIS_MNEMONIC_VCVTSS2SI:          return MNEMONIC_VCVTSS2SI;
        case ZYDIS_MNEMONIC_VCVTSS2USI:         return MNEMONIC_VCVTSS2USI;
        case ZYDIS_MNEMONIC_VCVTTPD2DQ:         return MNEMONIC_VCVTTPD2DQ;
        case ZYDIS_MNEMONIC_VCVTTPD2QQ:         return MNEMONIC_VCVTTPD2QQ;
        case ZYDIS_MNEMONIC_VCVTTPD2UDQ:        return MNEMONIC_VCVTTPD2UDQ;
        case ZYDIS_MNEMONIC_VCVTTPD2UQQ:        return MNEMONIC_VCVTTPD2UQQ;
        case ZYDIS_MNEMONIC_VCVTTPS2DQ:         return MNEMONIC_VCVTTPS2DQ;
        case ZYDIS_MNEMONIC_VCVTTPS2QQ:         return MNEMONIC_VCVTTPS2QQ;
        case ZYDIS_MNEMONIC_VCVTTPS2UDQ:        return MNEMONIC_VCVTTPS2UDQ;
        case ZYDIS_MNEMONIC_VCVTTPS2UQQ:        return MNEMONIC_VCVTTPS2UQQ;
        case ZYDIS_MNEMONIC_VCVTTSD2SI:         return MNEMONIC_VCVTTSD2SI;
        case ZYDIS_MNEMONIC_VCVTTSD2USI:        return MNEMONIC_VCVTTSD2USI;
        case ZYDIS_MNEMONIC_VCVTTSS2SI:         return MNEMONIC_VCVTTSS2SI;
        case ZYDIS_MNEMONIC_VCVTTSS2USI:        return MNEMONIC_VCVTTSS2USI;
        case ZYDIS_MNEMONIC_VCVTUDQ2PD:         return MNEMONIC_VCVTUDQ2PD;
        case ZYDIS_MNEMONIC_VCVTUDQ2PS:         return MNEMONIC_VCVTUDQ2PS;
        case ZYDIS_MNEMONIC_VCVTUQQ2PD:         return MNEMONIC_VCVTUQQ2PD;
        case ZYDIS_MNEMONIC_VCVTUQQ2PS:         return MNEMONIC_VCVTUQQ2PS;
        case ZYDIS_MNEMONIC_VCVTUSI2SD:         return MNEMONIC_VCVTUSI2SD;
        case ZYDIS_MNEMONIC_VCVTUSI2SS:         return MNEMONIC_VCVTUSI2SS;
        case ZYDIS_MNEMONIC_VDBPSADBW:          return MNEMONIC_VDBPSADBW;
        case ZYDIS_MNEMONIC_VDIVPD:             return MNEMONIC_VDIVPD;
        case ZYDIS_MNEMONIC_VDIVPS:             return MNEMONIC_VDIVPS;
        case ZYDIS_MNEMONIC_VDIVSD:             return MNEMONIC_VDIVSD;
        case ZYDIS_MNEMONIC_VDIVSS:             return MNEMONIC_VDIVSS;
        case ZYDIS_MNEMONIC_VDPBF16PS:          return MNEMONIC_VDPBF16PS;
        case ZYDIS_MNEMONIC_VDPPD:              return MNEMONIC_VDPPD;
        case ZYDIS_MNEMONIC_VDPPS:              return MNEMONIC_VDPPS;
        case ZYDIS_MNEMONIC_VERR:               return MNEMONIC_VERR;
        case ZYDIS_MNEMONIC_VERW:               return MNEMONIC_VERW;
        case ZYDIS_MNEMONIC_VEXP223PS:          return MNEMONIC_VEXP223PS;
        case ZYDIS_MNEMONIC_VEXP2PD:            return MNEMONIC_VEXP2PD;
        case ZYDIS_MNEMONIC_VEXP2PS:            return MNEMONIC_VEXP2PS;
        case ZYDIS_MNEMONIC_VEXPANDPD:          return MNEMONIC_VEXPANDPD;
        case ZYDIS_MNEMONIC_VEXPANDPS:          return MNEMONIC_VEXPANDPS;
        case ZYDIS_MNEMONIC_VEXTRACTF128:       return MNEMONIC_VEXTRACTF128;
        case ZYDIS_MNEMONIC_VEXTRACTF32X4:      return MNEMONIC_VEXTRACTF32X4;
        case ZYDIS_MNEMONIC_VEXTRACTF32X8:      return MNEMONIC_VEXTRACTF32X8;
        case ZYDIS_MNEMONIC_VEXTRACTF64X2:      return MNEMONIC_VEXTRACTF64X2;
        case ZYDIS_MNEMONIC_VEXTRACTF64X4:      return MNEMONIC_VEXTRACTF64X4;
        case ZYDIS_MNEMONIC_VEXTRACTI128:       return MNEMONIC_VEXTRACTI128;
        case ZYDIS_MNEMONIC_VEXTRACTI32X4:      return MNEMONIC_VEXTRACTI32X4;
        case ZYDIS_MNEMONIC_VEXTRACTI32X8:      return MNEMONIC_VEXTRACTI32X8;
        case ZYDIS_MNEMONIC_VEXTRACTI64X2:      return MNEMONIC_VEXTRACTI64X2;
        case ZYDIS_MNEMONIC_VEXTRACTI64X4:      return MNEMONIC_VEXTRACTI64X4;
        case ZYDIS_MNEMONIC_VEXTRACTPS:         return MNEMONIC_VEXTRACTPS;
        case ZYDIS_MNEMONIC_VFIXUPIMMPD:        return MNEMONIC_VFIXUPIMMPD;
        case ZYDIS_MNEMONIC_VFIXUPIMMPS:        return MNEMONIC_VFIXUPIMMPS;
        case ZYDIS_MNEMONIC_VFIXUPIMMSD:        return MNEMONIC_VFIXUPIMMSD;
        case ZYDIS_MNEMONIC_VFIXUPIMMSS:        return MNEMONIC_VFIXUPIMMSS;
        case ZYDIS_MNEMONIC_VFIXUPNANPD:        return MNEMONIC_VFIXUPNANPD;
        case ZYDIS_MNEMONIC_VFIXUPNANPS:        return MNEMONIC_VFIXUPNANPS;
        case ZYDIS_MNEMONIC_VFMADD132PD:        return MNEMONIC_VFMADD132PD;
        case ZYDIS_MNEMONIC_VFMADD132PS:        return MNEMONIC_VFMADD132PS;
        case ZYDIS_MNEMONIC_VFMADD132SD:        return MNEMONIC_VFMADD132SD;
        case ZYDIS_MNEMONIC_VFMADD132SS:        return MNEMONIC_VFMADD132SS;
        case ZYDIS_MNEMONIC_VFMADD213PD:        return MNEMONIC_VFMADD213PD;
        case ZYDIS_MNEMONIC_VFMADD213PS:        return MNEMONIC_VFMADD213PS;
        case ZYDIS_MNEMONIC_VFMADD213SD:        return MNEMONIC_VFMADD213SD;
        case ZYDIS_MNEMONIC_VFMADD213SS:        return MNEMONIC_VFMADD213SS;
        case ZYDIS_MNEMONIC_VFMADD231PD:        return MNEMONIC_VFMADD231PD;
        case ZYDIS_MNEMONIC_VFMADD231PS:        return MNEMONIC_VFMADD231PS;
        case ZYDIS_MNEMONIC_VFMADD231SD:        return MNEMONIC_VFMADD231SD;
        case ZYDIS_MNEMONIC_VFMADD231SS:        return MNEMONIC_VFMADD231SS;
        case ZYDIS_MNEMONIC_VFMADD233PS:        return MNEMONIC_VFMADD233PS;
        case ZYDIS_MNEMONIC_VFMADDPD:           return MNEMONIC_VFMADDPD;
        case ZYDIS_MNEMONIC_VFMADDPS:           return MNEMONIC_VFMADDPS;
        case ZYDIS_MNEMONIC_VFMADDSD:           return MNEMONIC_VFMADDSD;
        case ZYDIS_MNEMONIC_VFMADDSS:           return MNEMONIC_VFMADDSS;
        case ZYDIS_MNEMONIC_VFMADDSUB132PD:     return MNEMONIC_VFMADDSUB132PD;
        case ZYDIS_MNEMONIC_VFMADDSUB132PS:     return MNEMONIC_VFMADDSUB132PS;
        case ZYDIS_MNEMONIC_VFMADDSUB213PD:     return MNEMONIC_VFMADDSUB213PD;
        case ZYDIS_MNEMONIC_VFMADDSUB213PS:     return MNEMONIC_VFMADDSUB213PS;
        case ZYDIS_MNEMONIC_VFMADDSUB231PD:     return MNEMONIC_VFMADDSUB231PD;
        case ZYDIS_MNEMONIC_VFMADDSUB231PS:     return MNEMONIC_VFMADDSUB231PS;
        case ZYDIS_MNEMONIC_VFMADDSUBPD:        return MNEMONIC_VFMADDSUBPD;
        case ZYDIS_MNEMONIC_VFMADDSUBPS:        return MNEMONIC_VFMADDSUBPS;
        case ZYDIS_MNEMONIC_VFMSUB132PD:        return MNEMONIC_VFMSUB132PD;
        case ZYDIS_MNEMONIC_VFMSUB132PS:        return MNEMONIC_VFMSUB132PS;
        case ZYDIS_MNEMONIC_VFMSUB132SD:        return MNEMONIC_VFMSUB132SD;
        case ZYDIS_MNEMONIC_VFMSUB132SS:        return MNEMONIC_VFMSUB132SS;
        case ZYDIS_MNEMONIC_VFMSUB213PD:        return MNEMONIC_VFMSUB213PD;
        case ZYDIS_MNEMONIC_VFMSUB213PS:        return MNEMONIC_VFMSUB213PS;
        case ZYDIS_MNEMONIC_VFMSUB213SD:        return MNEMONIC_VFMSUB213SD;
        case ZYDIS_MNEMONIC_VFMSUB213SS:        return MNEMONIC_VFMSUB213SS;
        case ZYDIS_MNEMONIC_VFMSUB231PD:        return MNEMONIC_VFMSUB231PD;
        case ZYDIS_MNEMONIC_VFMSUB231PS:        return MNEMONIC_VFMSUB231PS;
        case ZYDIS_MNEMONIC_VFMSUB231SD:        return MNEMONIC_VFMSUB231SD;
        case ZYDIS_MNEMONIC_VFMSUB231SS:        return MNEMONIC_VFMSUB231SS;
        case ZYDIS_MNEMONIC_VFMSUBADD132PD:     return MNEMONIC_VFMSUBADD132PD;
        case ZYDIS_MNEMONIC_VFMSUBADD132PS:     return MNEMONIC_VFMSUBADD132PS;
        case ZYDIS_MNEMONIC_VFMSUBADD213PD:     return MNEMONIC_VFMSUBADD213PD;
        case ZYDIS_MNEMONIC_VFMSUBADD213PS:     return MNEMONIC_VFMSUBADD213PS;
        case ZYDIS_MNEMONIC_VFMSUBADD231PD:     return MNEMONIC_VFMSUBADD231PD;
        case ZYDIS_MNEMONIC_VFMSUBADD231PS:     return MNEMONIC_VFMSUBADD231PS;
        case ZYDIS_MNEMONIC_VFMSUBADDPD:        return MNEMONIC_VFMSUBADDPD;
        case ZYDIS_MNEMONIC_VFMSUBADDPS:        return MNEMONIC_VFMSUBADDPS;
        case ZYDIS_MNEMONIC_VFMSUBPD:           return MNEMONIC_VFMSUBPD;
        case ZYDIS_MNEMONIC_VFMSUBPS:           return MNEMONIC_VFMSUBPS;
        case ZYDIS_MNEMONIC_VFMSUBSD:           return MNEMONIC_VFMSUBSD;
        case ZYDIS_MNEMONIC_VFMSUBSS:           return MNEMONIC_VFMSUBSS;
        case ZYDIS_MNEMONIC_VFNMADD132PD:       return MNEMONIC_VFNMADD132PD;
        case ZYDIS_MNEMONIC_VFNMADD132PS:       return MNEMONIC_VFNMADD132PS;
        case ZYDIS_MNEMONIC_VFNMADD132SD:       return MNEMONIC_VFNMADD132SD;
        case ZYDIS_MNEMONIC_VFNMADD132SS:       return MNEMONIC_VFNMADD132SS;
        case ZYDIS_MNEMONIC_VFNMADD213PD:       return MNEMONIC_VFNMADD213PD;
        case ZYDIS_MNEMONIC_VFNMADD213PS:       return MNEMONIC_VFNMADD213PS;
        case ZYDIS_MNEMONIC_VFNMADD213SD:       return MNEMONIC_VFNMADD213SD;
        case ZYDIS_MNEMONIC_VFNMADD213SS:       return MNEMONIC_VFNMADD213SS;
        case ZYDIS_MNEMONIC_VFNMADD231PD:       return MNEMONIC_VFNMADD231PD;
        case ZYDIS_MNEMONIC_VFNMADD231PS:       return MNEMONIC_VFNMADD231PS;
        case ZYDIS_MNEMONIC_VFNMADD231SD:       return MNEMONIC_VFNMADD231SD;
        case ZYDIS_MNEMONIC_VFNMADD231SS:       return MNEMONIC_VFNMADD231SS;
        case ZYDIS_MNEMONIC_VFNMADDPD:          return MNEMONIC_VFNMADDPD;
        case ZYDIS_MNEMONIC_VFNMADDPS:          return MNEMONIC_VFNMADDPS;
        case ZYDIS_MNEMONIC_VFNMADDSD:          return MNEMONIC_VFNMADDSD;
        case ZYDIS_MNEMONIC_VFNMADDSS:          return MNEMONIC_VFNMADDSS;
        case ZYDIS_MNEMONIC_VFNMSUB132PD:       return MNEMONIC_VFNMSUB132PD;
        case ZYDIS_MNEMONIC_VFNMSUB132PS:       return MNEMONIC_VFNMSUB132PS;
        case ZYDIS_MNEMONIC_VFNMSUB132SD:       return MNEMONIC_VFNMSUB132SD;
        case ZYDIS_MNEMONIC_VFNMSUB132SS:       return MNEMONIC_VFNMSUB132SS;
        case ZYDIS_MNEMONIC_VFNMSUB213PD:       return MNEMONIC_VFNMSUB213PD;
        case ZYDIS_MNEMONIC_VFNMSUB213PS:       return MNEMONIC_VFNMSUB213PS;
        case ZYDIS_MNEMONIC_VFNMSUB213SD:       return MNEMONIC_VFNMSUB213SD;
        case ZYDIS_MNEMONIC_VFNMSUB213SS:       return MNEMONIC_VFNMSUB213SS;
        case ZYDIS_MNEMONIC_VFNMSUB231PD:       return MNEMONIC_VFNMSUB231PD;
        case ZYDIS_MNEMONIC_VFNMSUB231PS:       return MNEMONIC_VFNMSUB231PS;
        case ZYDIS_MNEMONIC_VFNMSUB231SD:       return MNEMONIC_VFNMSUB231SD;
        case ZYDIS_MNEMONIC_VFNMSUB231SS:       return MNEMONIC_VFNMSUB231SS;
        case ZYDIS_MNEMONIC_VFNMSUBPD:          return MNEMONIC_VFNMSUBPD;
        case ZYDIS_MNEMONIC_VFNMSUBPS:          return MNEMONIC_VFNMSUBPS;
        case ZYDIS_MNEMONIC_VFNMSUBSD:          return MNEMONIC_VFNMSUBSD;
        case ZYDIS_MNEMONIC_VFNMSUBSS:          return MNEMONIC_VFNMSUBSS;
        case ZYDIS_MNEMONIC_VFPCLASSPD:         return MNEMONIC_VFPCLASSPD;
        case ZYDIS_MNEMONIC_VFPCLASSPS:         return MNEMONIC_VFPCLASSPS;
        case ZYDIS_MNEMONIC_VFPCLASSSD:         return MNEMONIC_VFPCLASSSD;
        case ZYDIS_MNEMONIC_VFPCLASSSS:         return MNEMONIC_VFPCLASSSS;
        case ZYDIS_MNEMONIC_VFRCZPD:            return MNEMONIC_VFRCZPD;
        case ZYDIS_MNEMONIC_VFRCZPS:            return MNEMONIC_VFRCZPS;
        case ZYDIS_MNEMONIC_VFRCZSD:            return MNEMONIC_VFRCZSD;
        case ZYDIS_MNEMONIC_VFRCZSS:            return MNEMONIC_VFRCZSS;
        case ZYDIS_MNEMONIC_VGATHERDPD:         return MNEMONIC_VGATHERDPD;
        case ZYDIS_MNEMONIC_VGATHERDPS:         return MNEMONIC_VGATHERDPS;
        case ZYDIS_MNEMONIC_VGATHERPF0DPD:      return MNEMONIC_VGATHERPF0DPD;
        case ZYDIS_MNEMONIC_VGATHERPF0DPS:      return MNEMONIC_VGATHERPF0DPS;
        case ZYDIS_MNEMONIC_VGATHERPF0HINTDPD:  return MNEMONIC_VGATHERPF0HINTDPD;
        case ZYDIS_MNEMONIC_VGATHERPF0HINTDPS:  return MNEMONIC_VGATHERPF0HINTDPS;
        case ZYDIS_MNEMONIC_VGATHERPF0QPD:      return MNEMONIC_VGATHERPF0QPD;
        case ZYDIS_MNEMONIC_VGATHERPF0QPS:      return MNEMONIC_VGATHERPF0QPS;
        case ZYDIS_MNEMONIC_VGATHERPF1DPD:      return MNEMONIC_VGATHERPF1DPD;
        case ZYDIS_MNEMONIC_VGATHERPF1DPS:      return MNEMONIC_VGATHERPF1DPS;
        case ZYDIS_MNEMONIC_VGATHERPF1QPD:      return MNEMONIC_VGATHERPF1QPD;
        case ZYDIS_MNEMONIC_VGATHERPF1QPS:      return MNEMONIC_VGATHERPF1QPS;
        case ZYDIS_MNEMONIC_VGATHERQPD:         return MNEMONIC_VGATHERQPD;
        case ZYDIS_MNEMONIC_VGATHERQPS:         return MNEMONIC_VGATHERQPS;
        case ZYDIS_MNEMONIC_VGETEXPPD:          return MNEMONIC_VGETEXPPD;
        case ZYDIS_MNEMONIC_VGETEXPPS:          return MNEMONIC_VGETEXPPS;
        case ZYDIS_MNEMONIC_VGETEXPSD:          return MNEMONIC_VGETEXPSD;
        case ZYDIS_MNEMONIC_VGETEXPSS:          return MNEMONIC_VGETEXPSS;
        case ZYDIS_MNEMONIC_VGETMANTPD:         return MNEMONIC_VGETMANTPD;
        case ZYDIS_MNEMONIC_VGETMANTPS:         return MNEMONIC_VGETMANTPS;
        case ZYDIS_MNEMONIC_VGETMANTSD:         return MNEMONIC_VGETMANTSD;
        case ZYDIS_MNEMONIC_VGETMANTSS:         return MNEMONIC_VGETMANTSS;
        case ZYDIS_MNEMONIC_VGF2P8AFFINEINVQB:  return MNEMONIC_VGF2P8AFFINEINVQB;
        case ZYDIS_MNEMONIC_VGF2P8AFFINEQB:     return MNEMONIC_VGF2P8AFFINEQB;
        case ZYDIS_MNEMONIC_VGF2P8MULB:         return MNEMONIC_VGF2P8MULB;
        case ZYDIS_MNEMONIC_VGMAXABSPS:         return MNEMONIC_VGMAXABSPS;
        case ZYDIS_MNEMONIC_VGMAXPD:            return MNEMONIC_VGMAXPD;
        case ZYDIS_MNEMONIC_VGMAXPS:            return MNEMONIC_VGMAXPS;
        case ZYDIS_MNEMONIC_VGMINPD:            return MNEMONIC_VGMINPD;
        case ZYDIS_MNEMONIC_VGMINPS:            return MNEMONIC_VGMINPS;
        case ZYDIS_MNEMONIC_VHADDPD:            return MNEMONIC_VHADDPD;
        case ZYDIS_MNEMONIC_VHADDPS:            return MNEMONIC_VHADDPS;
        case ZYDIS_MNEMONIC_VHSUBPD:            return MNEMONIC_VHSUBPD;
        case ZYDIS_MNEMONIC_VHSUBPS:            return MNEMONIC_VHSUBPS;
        case ZYDIS_MNEMONIC_VINSERTF128:        return MNEMONIC_VINSERTF128;
        case ZYDIS_MNEMONIC_VINSERTF32X4:       return MNEMONIC_VINSERTF32X4;
        case ZYDIS_MNEMONIC_VINSERTF32X8:       return MNEMONIC_VINSERTF32X8;
        case ZYDIS_MNEMONIC_VINSERTF64X2:       return MNEMONIC_VINSERTF64X2;
        case ZYDIS_MNEMONIC_VINSERTF64X4:       return MNEMONIC_VINSERTF64X4;
        case ZYDIS_MNEMONIC_VINSERTI128:        return MNEMONIC_VINSERTI128;
        case ZYDIS_MNEMONIC_VINSERTI32X4:       return MNEMONIC_VINSERTI32X4;
        case ZYDIS_MNEMONIC_VINSERTI32X8:       return MNEMONIC_VINSERTI32X8;
        case ZYDIS_MNEMONIC_VINSERTI64X2:       return MNEMONIC_VINSERTI64X2;
        case ZYDIS_MNEMONIC_VINSERTI64X4:       return MNEMONIC_VINSERTI64X4;
        case ZYDIS_MNEMONIC_VINSERTPS:          return MNEMONIC_VINSERTPS;
        case ZYDIS_MNEMONIC_VLDDQU:             return MNEMONIC_VLDDQU;
        case ZYDIS_MNEMONIC_VLDMXCSR:           return MNEMONIC_VLDMXCSR;
        case ZYDIS_MNEMONIC_VLOADUNPACKHD:      return MNEMONIC_VLOADUNPACKHD;
        case ZYDIS_MNEMONIC_VLOADUNPACKHPD:     return MNEMONIC_VLOADUNPACKHPD;
        case ZYDIS_MNEMONIC_VLOADUNPACKHPS:     return MNEMONIC_VLOADUNPACKHPS;
        case ZYDIS_MNEMONIC_VLOADUNPACKHQ:      return MNEMONIC_VLOADUNPACKHQ;
        case ZYDIS_MNEMONIC_VLOADUNPACKLD:      return MNEMONIC_VLOADUNPACKLD;
        case ZYDIS_MNEMONIC_VLOADUNPACKLPD:     return MNEMONIC_VLOADUNPACKLPD;
        case ZYDIS_MNEMONIC_VLOADUNPACKLPS:     return MNEMONIC_VLOADUNPACKLPS;
        case ZYDIS_MNEMONIC_VLOADUNPACKLQ:      return MNEMONIC_VLOADUNPACKLQ;
        case ZYDIS_MNEMONIC_VLOG2PS:            return MNEMONIC_VLOG2PS;
        case ZYDIS_MNEMONIC_VMASKMOVDQU:        return MNEMONIC_VMASKMOVDQU;
        case ZYDIS_MNEMONIC_VMASKMOVPD:         return MNEMONIC_VMASKMOVPD;
        case ZYDIS_MNEMONIC_VMASKMOVPS:         return MNEMONIC_VMASKMOVPS;
        case ZYDIS_MNEMONIC_VMAXPD:             return MNEMONIC_VMAXPD;
        case ZYDIS_MNEMONIC_VMAXPS:             return MNEMONIC_VMAXPS;
        case ZYDIS_MNEMONIC_VMAXSD:             return MNEMONIC_VMAXSD;
        case ZYDIS_MNEMONIC_VMAXSS:             return MNEMONIC_VMAXSS;
        case ZYDIS_MNEMONIC_VMCALL:             return MNEMONIC_VMCALL;
        case ZYDIS_MNEMONIC_VMCLEAR:            return MNEMONIC_VMCLEAR;
        case ZYDIS_MNEMONIC_VMFUNC:             return MNEMONIC_VMFUNC;
        case ZYDIS_MNEMONIC_VMINPD:             return MNEMONIC_VMINPD;
        case ZYDIS_MNEMONIC_VMINPS:             return MNEMONIC_VMINPS;
        case ZYDIS_MNEMONIC_VMINSD:             return MNEMONIC_VMINSD;
        case ZYDIS_MNEMONIC_VMINSS:             return MNEMONIC_VMINSS;
        case ZYDIS_MNEMONIC_VMLAUNCH:           return MNEMONIC_VMLAUNCH;
        case ZYDIS_MNEMONIC_VMLOAD:             return MNEMONIC_VMLOAD;
        case ZYDIS_MNEMONIC_VMMCALL:            return MNEMONIC_VMMCALL;
        case ZYDIS_MNEMONIC_VMOVAPD:            return MNEMONIC_VMOVAPD;
        case ZYDIS_MNEMONIC_VMOVAPS:            return MNEMONIC_VMOVAPS;
        case ZYDIS_MNEMONIC_VMOVD:              return MNEMONIC_VMOVD;
        case ZYDIS_MNEMONIC_VMOVDDUP:           return MNEMONIC_VMOVDDUP;
        case ZYDIS_MNEMONIC_VMOVDQA:            return MNEMONIC_VMOVDQA;
        case ZYDIS_MNEMONIC_VMOVDQA32:          return MNEMONIC_VMOVDQA32;
        case ZYDIS_MNEMONIC_VMOVDQA64:          return MNEMONIC_VMOVDQA64;
        case ZYDIS_MNEMONIC_VMOVDQU:            return MNEMONIC_VMOVDQU;
        case ZYDIS_MNEMONIC_VMOVDQU16:          return MNEMONIC_VMOVDQU16;
        case ZYDIS_MNEMONIC_VMOVDQU32:          return MNEMONIC_VMOVDQU32;
        case ZYDIS_MNEMONIC_VMOVDQU64:          return MNEMONIC_VMOVDQU64;
        case ZYDIS_MNEMONIC_VMOVDQU8:           return MNEMONIC_VMOVDQU8;
        case ZYDIS_MNEMONIC_VMOVHLPS:           return MNEMONIC_VMOVHLPS;
        case ZYDIS_MNEMONIC_VMOVHPD:            return MNEMONIC_VMOVHPD;
        case ZYDIS_MNEMONIC_VMOVHPS:            return MNEMONIC_VMOVHPS;
        case ZYDIS_MNEMONIC_VMOVLHPS:           return MNEMONIC_VMOVLHPS;
        case ZYDIS_MNEMONIC_VMOVLPD:            return MNEMONIC_VMOVLPD;
        case ZYDIS_MNEMONIC_VMOVLPS:            return MNEMONIC_VMOVLPS;
        case ZYDIS_MNEMONIC_VMOVMSKPD:          return MNEMONIC_VMOVMSKPD;
        case ZYDIS_MNEMONIC_VMOVMSKPS:          return MNEMONIC_VMOVMSKPS;
        case ZYDIS_MNEMONIC_VMOVNRAPD:          return MNEMONIC_VMOVNRAPD;
        case ZYDIS_MNEMONIC_VMOVNRAPS:          return MNEMONIC_VMOVNRAPS;
        case ZYDIS_MNEMONIC_VMOVNRNGOAPD:       return MNEMONIC_VMOVNRNGOAPD;
        case ZYDIS_MNEMONIC_VMOVNRNGOAPS:       return MNEMONIC_VMOVNRNGOAPS;
        case ZYDIS_MNEMONIC_VMOVNTDQ:           return MNEMONIC_VMOVNTDQ;
        case ZYDIS_MNEMONIC_VMOVNTDQA:          return MNEMONIC_VMOVNTDQA;
        case ZYDIS_MNEMONIC_VMOVNTPD:           return MNEMONIC_VMOVNTPD;
        case ZYDIS_MNEMONIC_VMOVNTPS:           return MNEMONIC_VMOVNTPS;
        case ZYDIS_MNEMONIC_VMOVQ:              return MNEMONIC_VMOVQ;
        case ZYDIS_MNEMONIC_VMOVSD:             return MNEMONIC_VMOVSD;
        case ZYDIS_MNEMONIC_VMOVSHDUP:          return MNEMONIC_VMOVSHDUP;
        case ZYDIS_MNEMONIC_VMOVSLDUP:          return MNEMONIC_VMOVSLDUP;
        case ZYDIS_MNEMONIC_VMOVSS:             return MNEMONIC_VMOVSS;
        case ZYDIS_MNEMONIC_VMOVUPD:            return MNEMONIC_VMOVUPD;
        case ZYDIS_MNEMONIC_VMOVUPS:            return MNEMONIC_VMOVUPS;
        case ZYDIS_MNEMONIC_VMPSADBW:           return MNEMONIC_VMPSADBW;
        case ZYDIS_MNEMONIC_VMPTRLD:            return MNEMONIC_VMPTRLD;
        case ZYDIS_MNEMONIC_VMPTRST:            return MNEMONIC_VMPTRST;
        case ZYDIS_MNEMONIC_VMREAD:             return MNEMONIC_VMREAD;
        case ZYDIS_MNEMONIC_VMRESUME:           return MNEMONIC_VMRESUME;
        case ZYDIS_MNEMONIC_VMRUN:              return MNEMONIC_VMRUN;
        case ZYDIS_MNEMONIC_VMSAVE:             return MNEMONIC_VMSAVE;
        case ZYDIS_MNEMONIC_VMULPD:             return MNEMONIC_VMULPD;
        case ZYDIS_MNEMONIC_VMULPS:             return MNEMONIC_VMULPS;
        case ZYDIS_MNEMONIC_VMULSD:             return MNEMONIC_VMULSD;
        case ZYDIS_MNEMONIC_VMULSS:             return MNEMONIC_VMULSS;
        case ZYDIS_MNEMONIC_VMWRITE:            return MNEMONIC_VMWRITE;
        case ZYDIS_MNEMONIC_VMXOFF:             return MNEMONIC_VMXOFF;
        case ZYDIS_MNEMONIC_VMXON:              return MNEMONIC_VMXON;
        case ZYDIS_MNEMONIC_VORPD:              return MNEMONIC_VORPD;
        case ZYDIS_MNEMONIC_VORPS:              return MNEMONIC_VORPS;
        case ZYDIS_MNEMONIC_VP2INTERSECTD:      return MNEMONIC_VP2INTERSECTD;
        case ZYDIS_MNEMONIC_VP2INTERSECTQ:      return MNEMONIC_VP2INTERSECTQ;
        case ZYDIS_MNEMONIC_VP4DPWSSD:          return MNEMONIC_VP4DPWSSD;
        case ZYDIS_MNEMONIC_VP4DPWSSDS:         return MNEMONIC_VP4DPWSSDS;
        case ZYDIS_MNEMONIC_VPABSB:             return MNEMONIC_VPABSB;
        case ZYDIS_MNEMONIC_VPABSD:             return MNEMONIC_VPABSD;
        case ZYDIS_MNEMONIC_VPABSQ:             return MNEMONIC_VPABSQ;
        case ZYDIS_MNEMONIC_VPABSW:             return MNEMONIC_VPABSW;
        case ZYDIS_MNEMONIC_VPACKSSDW:          return MNEMONIC_VPACKSSDW;
        case ZYDIS_MNEMONIC_VPACKSSWB:          return MNEMONIC_VPACKSSWB;
        case ZYDIS_MNEMONIC_VPACKSTOREHD:       return MNEMONIC_VPACKSTOREHD;
        case ZYDIS_MNEMONIC_VPACKSTOREHPD:      return MNEMONIC_VPACKSTOREHPD;
        case ZYDIS_MNEMONIC_VPACKSTOREHPS:      return MNEMONIC_VPACKSTOREHPS;
        case ZYDIS_MNEMONIC_VPACKSTOREHQ:       return MNEMONIC_VPACKSTOREHQ;
        case ZYDIS_MNEMONIC_VPACKSTORELD:       return MNEMONIC_VPACKSTORELD;
        case ZYDIS_MNEMONIC_VPACKSTORELPD:      return MNEMONIC_VPACKSTORELPD;
        case ZYDIS_MNEMONIC_VPACKSTORELPS:      return MNEMONIC_VPACKSTORELPS;
        case ZYDIS_MNEMONIC_VPACKSTORELQ:       return MNEMONIC_VPACKSTORELQ;
        case ZYDIS_MNEMONIC_VPACKUSDW:          return MNEMONIC_VPACKUSDW;
        case ZYDIS_MNEMONIC_VPACKUSWB:          return MNEMONIC_VPACKUSWB;
        case ZYDIS_MNEMONIC_VPADCD:             return MNEMONIC_VPADCD;
        case ZYDIS_MNEMONIC_VPADDB:             return MNEMONIC_VPADDB;
        case ZYDIS_MNEMONIC_VPADDD:             return MNEMONIC_VPADDD;
        case ZYDIS_MNEMONIC_VPADDQ:             return MNEMONIC_VPADDQ;
        case ZYDIS_MNEMONIC_VPADDSB:            return MNEMONIC_VPADDSB;
        case ZYDIS_MNEMONIC_VPADDSETCD:         return MNEMONIC_VPADDSETCD;
        case ZYDIS_MNEMONIC_VPADDSETSD:         return MNEMONIC_VPADDSETSD;
        case ZYDIS_MNEMONIC_VPADDSW:            return MNEMONIC_VPADDSW;
        case ZYDIS_MNEMONIC_VPADDUSB:           return MNEMONIC_VPADDUSB;
        case ZYDIS_MNEMONIC_VPADDUSW:           return MNEMONIC_VPADDUSW;
        case ZYDIS_MNEMONIC_VPADDW:             return MNEMONIC_VPADDW;
        case ZYDIS_MNEMONIC_VPALIGNR:           return MNEMONIC_VPALIGNR;
        case ZYDIS_MNEMONIC_VPAND:              return MNEMONIC_VPAND;
        case ZYDIS_MNEMONIC_VPANDD:             return MNEMONIC_VPANDD;
        case ZYDIS_MNEMONIC_VPANDN:             return MNEMONIC_VPANDN;
        case ZYDIS_MNEMONIC_VPANDND:            return MNEMONIC_VPANDND;
        case ZYDIS_MNEMONIC_VPANDNQ:            return MNEMONIC_VPANDNQ;
        case ZYDIS_MNEMONIC_VPANDQ:             return MNEMONIC_VPANDQ;
        case ZYDIS_MNEMONIC_VPAVGB:             return MNEMONIC_VPAVGB;
        case ZYDIS_MNEMONIC_VPAVGW:             return MNEMONIC_VPAVGW;
        case ZYDIS_MNEMONIC_VPBLENDD:           return MNEMONIC_VPBLENDD;
        case ZYDIS_MNEMONIC_VPBLENDMB:          return MNEMONIC_VPBLENDMB;
        case ZYDIS_MNEMONIC_VPBLENDMD:          return MNEMONIC_VPBLENDMD;
        case ZYDIS_MNEMONIC_VPBLENDMQ:          return MNEMONIC_VPBLENDMQ;
        case ZYDIS_MNEMONIC_VPBLENDMW:          return MNEMONIC_VPBLENDMW;
        case ZYDIS_MNEMONIC_VPBLENDVB:          return MNEMONIC_VPBLENDVB;
        case ZYDIS_MNEMONIC_VPBLENDW:           return MNEMONIC_VPBLENDW;
        case ZYDIS_MNEMONIC_VPBROADCASTB:       return MNEMONIC_VPBROADCASTB;
        case ZYDIS_MNEMONIC_VPBROADCASTD:       return MNEMONIC_VPBROADCASTD;
        case ZYDIS_MNEMONIC_VPBROADCASTMB2Q:    return MNEMONIC_VPBROADCASTMB2Q;
        case ZYDIS_MNEMONIC_VPBROADCASTMW2D:    return MNEMONIC_VPBROADCASTMW2D;
        case ZYDIS_MNEMONIC_VPBROADCASTQ:       return MNEMONIC_VPBROADCASTQ;
        case ZYDIS_MNEMONIC_VPBROADCASTW:       return MNEMONIC_VPBROADCASTW;
        case ZYDIS_MNEMONIC_VPCLMULQDQ:         return MNEMONIC_VPCLMULQDQ;
        case ZYDIS_MNEMONIC_VPCMOV:             return MNEMONIC_VPCMOV;
        case ZYDIS_MNEMONIC_VPCMPB:             return MNEMONIC_VPCMPB;
        case ZYDIS_MNEMONIC_VPCMPD:             return MNEMONIC_VPCMPD;
        case ZYDIS_MNEMONIC_VPCMPEQB:           return MNEMONIC_VPCMPEQB;
        case ZYDIS_MNEMONIC_VPCMPEQD:           return MNEMONIC_VPCMPEQD;
        case ZYDIS_MNEMONIC_VPCMPEQQ:           return MNEMONIC_VPCMPEQQ;
        case ZYDIS_MNEMONIC_VPCMPEQW:           return MNEMONIC_VPCMPEQW;
        case ZYDIS_MNEMONIC_VPCMPESTRI:         return MNEMONIC_VPCMPESTRI;
        case ZYDIS_MNEMONIC_VPCMPESTRM:         return MNEMONIC_VPCMPESTRM;
        case ZYDIS_MNEMONIC_VPCMPGTB:           return MNEMONIC_VPCMPGTB;
        case ZYDIS_MNEMONIC_VPCMPGTD:           return MNEMONIC_VPCMPGTD;
        case ZYDIS_MNEMONIC_VPCMPGTQ:           return MNEMONIC_VPCMPGTQ;
        case ZYDIS_MNEMONIC_VPCMPGTW:           return MNEMONIC_VPCMPGTW;
        case ZYDIS_MNEMONIC_VPCMPISTRI:         return MNEMONIC_VPCMPISTRI;
        case ZYDIS_MNEMONIC_VPCMPISTRM:         return MNEMONIC_VPCMPISTRM;
        case ZYDIS_MNEMONIC_VPCMPLTD:           return MNEMONIC_VPCMPLTD;
        case ZYDIS_MNEMONIC_VPCMPQ:             return MNEMONIC_VPCMPQ;
        case ZYDIS_MNEMONIC_VPCMPUB:            return MNEMONIC_VPCMPUB;
        case ZYDIS_MNEMONIC_VPCMPUD:            return MNEMONIC_VPCMPUD;
        case ZYDIS_MNEMONIC_VPCMPUQ:            return MNEMONIC_VPCMPUQ;
        case ZYDIS_MNEMONIC_VPCMPUW:            return MNEMONIC_VPCMPUW;
        case ZYDIS_MNEMONIC_VPCMPW:             return MNEMONIC_VPCMPW;
        case ZYDIS_MNEMONIC_VPCOMB:             return MNEMONIC_VPCOMB;
        case ZYDIS_MNEMONIC_VPCOMD:             return MNEMONIC_VPCOMD;
        case ZYDIS_MNEMONIC_VPCOMPRESSB:        return MNEMONIC_VPCOMPRESSB;
        case ZYDIS_MNEMONIC_VPCOMPRESSD:        return MNEMONIC_VPCOMPRESSD;
        case ZYDIS_MNEMONIC_VPCOMPRESSQ:        return MNEMONIC_VPCOMPRESSQ;
        case ZYDIS_MNEMONIC_VPCOMPRESSW:        return MNEMONIC_VPCOMPRESSW;
        case ZYDIS_MNEMONIC_VPCOMQ:             return MNEMONIC_VPCOMQ;
        case ZYDIS_MNEMONIC_VPCOMUB:            return MNEMONIC_VPCOMUB;
        case ZYDIS_MNEMONIC_VPCOMUD:            return MNEMONIC_VPCOMUD;
        case ZYDIS_MNEMONIC_VPCOMUQ:            return MNEMONIC_VPCOMUQ;
        case ZYDIS_MNEMONIC_VPCOMUW:            return MNEMONIC_VPCOMUW;
        case ZYDIS_MNEMONIC_VPCOMW:             return MNEMONIC_VPCOMW;
        case ZYDIS_MNEMONIC_VPCONFLICTD:        return MNEMONIC_VPCONFLICTD;
        case ZYDIS_MNEMONIC_VPCONFLICTQ:        return MNEMONIC_VPCONFLICTQ;
        case ZYDIS_MNEMONIC_VPDPBUSD:           return MNEMONIC_VPDPBUSD;
        case ZYDIS_MNEMONIC_VPDPBUSDS:          return MNEMONIC_VPDPBUSDS;
        case ZYDIS_MNEMONIC_VPDPWSSD:           return MNEMONIC_VPDPWSSD;
        case ZYDIS_MNEMONIC_VPDPWSSDS:          return MNEMONIC_VPDPWSSDS;
        case ZYDIS_MNEMONIC_VPERM2F128:         return MNEMONIC_VPERM2F128;
        case ZYDIS_MNEMONIC_VPERM2I128:         return MNEMONIC_VPERM2I128;
        case ZYDIS_MNEMONIC_VPERMB:             return MNEMONIC_VPERMB;
        case ZYDIS_MNEMONIC_VPERMD:             return MNEMONIC_VPERMD;
        case ZYDIS_MNEMONIC_VPERMF32X4:         return MNEMONIC_VPERMF32X4;
        case ZYDIS_MNEMONIC_VPERMI2B:           return MNEMONIC_VPERMI2B;
        case ZYDIS_MNEMONIC_VPERMI2D:           return MNEMONIC_VPERMI2D;
        case ZYDIS_MNEMONIC_VPERMI2PD:          return MNEMONIC_VPERMI2PD;
        case ZYDIS_MNEMONIC_VPERMI2PS:          return MNEMONIC_VPERMI2PS;
        case ZYDIS_MNEMONIC_VPERMI2Q:           return MNEMONIC_VPERMI2Q;
        case ZYDIS_MNEMONIC_VPERMI2W:           return MNEMONIC_VPERMI2W;
        case ZYDIS_MNEMONIC_VPERMIL2PD:         return MNEMONIC_VPERMIL2PD;
        case ZYDIS_MNEMONIC_VPERMIL2PS:         return MNEMONIC_VPERMIL2PS;
        case ZYDIS_MNEMONIC_VPERMILPD:          return MNEMONIC_VPERMILPD;
        case ZYDIS_MNEMONIC_VPERMILPS:          return MNEMONIC_VPERMILPS;
        case ZYDIS_MNEMONIC_VPERMPD:            return MNEMONIC_VPERMPD;
        case ZYDIS_MNEMONIC_VPERMPS:            return MNEMONIC_VPERMPS;
        case ZYDIS_MNEMONIC_VPERMQ:             return MNEMONIC_VPERMQ;
        case ZYDIS_MNEMONIC_VPERMT2B:           return MNEMONIC_VPERMT2B;
        case ZYDIS_MNEMONIC_VPERMT2D:           return MNEMONIC_VPERMT2D;
        case ZYDIS_MNEMONIC_VPERMT2PD:          return MNEMONIC_VPERMT2PD;
        case ZYDIS_MNEMONIC_VPERMT2PS:          return MNEMONIC_VPERMT2PS;
        case ZYDIS_MNEMONIC_VPERMT2Q:           return MNEMONIC_VPERMT2Q;
        case ZYDIS_MNEMONIC_VPERMT2W:           return MNEMONIC_VPERMT2W;
        case ZYDIS_MNEMONIC_VPERMW:             return MNEMONIC_VPERMW;
        case ZYDIS_MNEMONIC_VPEXPANDB:          return MNEMONIC_VPEXPANDB;
        case ZYDIS_MNEMONIC_VPEXPANDD:          return MNEMONIC_VPEXPANDD;
        case ZYDIS_MNEMONIC_VPEXPANDQ:          return MNEMONIC_VPEXPANDQ;
        case ZYDIS_MNEMONIC_VPEXPANDW:          return MNEMONIC_VPEXPANDW;
        case ZYDIS_MNEMONIC_VPEXTRB:            return MNEMONIC_VPEXTRB;
        case ZYDIS_MNEMONIC_VPEXTRD:            return MNEMONIC_VPEXTRD;
        case ZYDIS_MNEMONIC_VPEXTRQ:            return MNEMONIC_VPEXTRQ;
        case ZYDIS_MNEMONIC_VPEXTRW:            return MNEMONIC_VPEXTRW;
        case ZYDIS_MNEMONIC_VPGATHERDD:         return MNEMONIC_VPGATHERDD;
        case ZYDIS_MNEMONIC_VPGATHERDQ:         return MNEMONIC_VPGATHERDQ;
        case ZYDIS_MNEMONIC_VPGATHERQD:         return MNEMONIC_VPGATHERQD;
        case ZYDIS_MNEMONIC_VPGATHERQQ:         return MNEMONIC_VPGATHERQQ;
        case ZYDIS_MNEMONIC_VPHADDBD:           return MNEMONIC_VPHADDBD;
        case ZYDIS_MNEMONIC_VPHADDBQ:           return MNEMONIC_VPHADDBQ;
        case ZYDIS_MNEMONIC_VPHADDBW:           return MNEMONIC_VPHADDBW;
        case ZYDIS_MNEMONIC_VPHADDD:            return MNEMONIC_VPHADDD;
        case ZYDIS_MNEMONIC_VPHADDDQ:           return MNEMONIC_VPHADDDQ;
        case ZYDIS_MNEMONIC_VPHADDSW:           return MNEMONIC_VPHADDSW;
        case ZYDIS_MNEMONIC_VPHADDUBD:          return MNEMONIC_VPHADDUBD;
        case ZYDIS_MNEMONIC_VPHADDUBQ:          return MNEMONIC_VPHADDUBQ;
        case ZYDIS_MNEMONIC_VPHADDUBW:          return MNEMONIC_VPHADDUBW;
        case ZYDIS_MNEMONIC_VPHADDUDQ:          return MNEMONIC_VPHADDUDQ;
        case ZYDIS_MNEMONIC_VPHADDUWD:          return MNEMONIC_VPHADDUWD;
        case ZYDIS_MNEMONIC_VPHADDUWQ:          return MNEMONIC_VPHADDUWQ;
        case ZYDIS_MNEMONIC_VPHADDW:            return MNEMONIC_VPHADDW;
        case ZYDIS_MNEMONIC_VPHADDWD:           return MNEMONIC_VPHADDWD;
        case ZYDIS_MNEMONIC_VPHADDWQ:           return MNEMONIC_VPHADDWQ;
        case ZYDIS_MNEMONIC_VPHMINPOSUW:        return MNEMONIC_VPHMINPOSUW;
        case ZYDIS_MNEMONIC_VPHSUBBW:           return MNEMONIC_VPHSUBBW;
        case ZYDIS_MNEMONIC_VPHSUBD:            return MNEMONIC_VPHSUBD;
        case ZYDIS_MNEMONIC_VPHSUBDQ:           return MNEMONIC_VPHSUBDQ;
        case ZYDIS_MNEMONIC_VPHSUBSW:           return MNEMONIC_VPHSUBSW;
        case ZYDIS_MNEMONIC_VPHSUBW:            return MNEMONIC_VPHSUBW;
        case ZYDIS_MNEMONIC_VPHSUBWD:           return MNEMONIC_VPHSUBWD;
        case ZYDIS_MNEMONIC_VPINSRB:            return MNEMONIC_VPINSRB;
        case ZYDIS_MNEMONIC_VPINSRD:            return MNEMONIC_VPINSRD;
        case ZYDIS_MNEMONIC_VPINSRQ:            return MNEMONIC_VPINSRQ;
        case ZYDIS_MNEMONIC_VPINSRW:            return MNEMONIC_VPINSRW;
        case ZYDIS_MNEMONIC_VPLZCNTD:           return MNEMONIC_VPLZCNTD;
        case ZYDIS_MNEMONIC_VPLZCNTQ:           return MNEMONIC_VPLZCNTQ;
        case ZYDIS_MNEMONIC_VPMACSDD:           return MNEMONIC_VPMACSDD;
        case ZYDIS_MNEMONIC_VPMACSDQH:          return MNEMONIC_VPMACSDQH;
        case ZYDIS_MNEMONIC_VPMACSDQL:          return MNEMONIC_VPMACSDQL;
        case ZYDIS_MNEMONIC_VPMACSSDD:          return MNEMONIC_VPMACSSDD;
        case ZYDIS_MNEMONIC_VPMACSSDQH:         return MNEMONIC_VPMACSSDQH;
        case ZYDIS_MNEMONIC_VPMACSSDQL:         return MNEMONIC_VPMACSSDQL;
        case ZYDIS_MNEMONIC_VPMACSSWD:          return MNEMONIC_VPMACSSWD;
        case ZYDIS_MNEMONIC_VPMACSSWW:          return MNEMONIC_VPMACSSWW;
        case ZYDIS_MNEMONIC_VPMACSWD:           return MNEMONIC_VPMACSWD;
        case ZYDIS_MNEMONIC_VPMACSWW:           return MNEMONIC_VPMACSWW;
        case ZYDIS_MNEMONIC_VPMADCSSWD:         return MNEMONIC_VPMADCSSWD;
        case ZYDIS_MNEMONIC_VPMADCSWD:          return MNEMONIC_VPMADCSWD;
        case ZYDIS_MNEMONIC_VPMADD231D:         return MNEMONIC_VPMADD231D;
        case ZYDIS_MNEMONIC_VPMADD233D:         return MNEMONIC_VPMADD233D;
        case ZYDIS_MNEMONIC_VPMADD52HUQ:        return MNEMONIC_VPMADD52HUQ;
        case ZYDIS_MNEMONIC_VPMADD52LUQ:        return MNEMONIC_VPMADD52LUQ;
        case ZYDIS_MNEMONIC_VPMADDUBSW:         return MNEMONIC_VPMADDUBSW;
        case ZYDIS_MNEMONIC_VPMADDWD:           return MNEMONIC_VPMADDWD;
        case ZYDIS_MNEMONIC_VPMASKMOVD:         return MNEMONIC_VPMASKMOVD;
        case ZYDIS_MNEMONIC_VPMASKMOVQ:         return MNEMONIC_VPMASKMOVQ;
        case ZYDIS_MNEMONIC_VPMAXSB:            return MNEMONIC_VPMAXSB;
        case ZYDIS_MNEMONIC_VPMAXSD:            return MNEMONIC_VPMAXSD;
        case ZYDIS_MNEMONIC_VPMAXSQ:            return MNEMONIC_VPMAXSQ;
        case ZYDIS_MNEMONIC_VPMAXSW:            return MNEMONIC_VPMAXSW;
        case ZYDIS_MNEMONIC_VPMAXUB:            return MNEMONIC_VPMAXUB;
        case ZYDIS_MNEMONIC_VPMAXUD:            return MNEMONIC_VPMAXUD;
        case ZYDIS_MNEMONIC_VPMAXUQ:            return MNEMONIC_VPMAXUQ;
        case ZYDIS_MNEMONIC_VPMAXUW:            return MNEMONIC_VPMAXUW;
        case ZYDIS_MNEMONIC_VPMINSB:            return MNEMONIC_VPMINSB;
        case ZYDIS_MNEMONIC_VPMINSD:            return MNEMONIC_VPMINSD;
        case ZYDIS_MNEMONIC_VPMINSQ:            return MNEMONIC_VPMINSQ;
        case ZYDIS_MNEMONIC_VPMINSW:            return MNEMONIC_VPMINSW;
        case ZYDIS_MNEMONIC_VPMINUB:            return MNEMONIC_VPMINUB;
        case ZYDIS_MNEMONIC_VPMINUD:            return MNEMONIC_VPMINUD;
        case ZYDIS_MNEMONIC_VPMINUQ:            return MNEMONIC_VPMINUQ;
        case ZYDIS_MNEMONIC_VPMINUW:            return MNEMONIC_VPMINUW;
        case ZYDIS_MNEMONIC_VPMOVB2M:           return MNEMONIC_VPMOVB2M;
        case ZYDIS_MNEMONIC_VPMOVD2M:           return MNEMONIC_VPMOVD2M;
        case ZYDIS_MNEMONIC_VPMOVDB:            return MNEMONIC_VPMOVDB;
        case ZYDIS_MNEMONIC_VPMOVDW:            return MNEMONIC_VPMOVDW;
        case ZYDIS_MNEMONIC_VPMOVM2B:           return MNEMONIC_VPMOVM2B;
        case ZYDIS_MNEMONIC_VPMOVM2D:           return MNEMONIC_VPMOVM2D;
        case ZYDIS_MNEMONIC_VPMOVM2Q:           return MNEMONIC_VPMOVM2Q;
        case ZYDIS_MNEMONIC_VPMOVM2W:           return MNEMONIC_VPMOVM2W;
        case ZYDIS_MNEMONIC_VPMOVMSKB:          return MNEMONIC_VPMOVMSKB;
        case ZYDIS_MNEMONIC_VPMOVQ2M:           return MNEMONIC_VPMOVQ2M;
        case ZYDIS_MNEMONIC_VPMOVQB:            return MNEMONIC_VPMOVQB;
        case ZYDIS_MNEMONIC_VPMOVQD:            return MNEMONIC_VPMOVQD;
        case ZYDIS_MNEMONIC_VPMOVQW:            return MNEMONIC_VPMOVQW;
        case ZYDIS_MNEMONIC_VPMOVSDB:           return MNEMONIC_VPMOVSDB;
        case ZYDIS_MNEMONIC_VPMOVSDW:           return MNEMONIC_VPMOVSDW;
        case ZYDIS_MNEMONIC_VPMOVSQB:           return MNEMONIC_VPMOVSQB;
        case ZYDIS_MNEMONIC_VPMOVSQD:           return MNEMONIC_VPMOVSQD;
        case ZYDIS_MNEMONIC_VPMOVSQW:           return MNEMONIC_VPMOVSQW;
        case ZYDIS_MNEMONIC_VPMOVSWB:           return MNEMONIC_VPMOVSWB;
        case ZYDIS_MNEMONIC_VPMOVSXBD:          return MNEMONIC_VPMOVSXBD;
        case ZYDIS_MNEMONIC_VPMOVSXBQ:          return MNEMONIC_VPMOVSXBQ;
        case ZYDIS_MNEMONIC_VPMOVSXBW:          return MNEMONIC_VPMOVSXBW;
        case ZYDIS_MNEMONIC_VPMOVSXDQ:          return MNEMONIC_VPMOVSXDQ;
        case ZYDIS_MNEMONIC_VPMOVSXWD:          return MNEMONIC_VPMOVSXWD;
        case ZYDIS_MNEMONIC_VPMOVSXWQ:          return MNEMONIC_VPMOVSXWQ;
        case ZYDIS_MNEMONIC_VPMOVUSDB:          return MNEMONIC_VPMOVUSDB;
        case ZYDIS_MNEMONIC_VPMOVUSDW:          return MNEMONIC_VPMOVUSDW;
        case ZYDIS_MNEMONIC_VPMOVUSQB:          return MNEMONIC_VPMOVUSQB;
        case ZYDIS_MNEMONIC_VPMOVUSQD:          return MNEMONIC_VPMOVUSQD;
        case ZYDIS_MNEMONIC_VPMOVUSQW:          return MNEMONIC_VPMOVUSQW;
        case ZYDIS_MNEMONIC_VPMOVUSWB:          return MNEMONIC_VPMOVUSWB;
        case ZYDIS_MNEMONIC_VPMOVW2M:           return MNEMONIC_VPMOVW2M;
        case ZYDIS_MNEMONIC_VPMOVWB:            return MNEMONIC_VPMOVWB;
        case ZYDIS_MNEMONIC_VPMOVZXBD:          return MNEMONIC_VPMOVZXBD;
        case ZYDIS_MNEMONIC_VPMOVZXBQ:          return MNEMONIC_VPMOVZXBQ;
        case ZYDIS_MNEMONIC_VPMOVZXBW:          return MNEMONIC_VPMOVZXBW;
        case ZYDIS_MNEMONIC_VPMOVZXDQ:          return MNEMONIC_VPMOVZXDQ;
        case ZYDIS_MNEMONIC_VPMOVZXWD:          return MNEMONIC_VPMOVZXWD;
        case ZYDIS_MNEMONIC_VPMOVZXWQ:          return MNEMONIC_VPMOVZXWQ;
        case ZYDIS_MNEMONIC_VPMULDQ:            return MNEMONIC_VPMULDQ;
        case ZYDIS_MNEMONIC_VPMULHD:            return MNEMONIC_VPMULHD;
        case ZYDIS_MNEMONIC_VPMULHRSW:          return MNEMONIC_VPMULHRSW;
        case ZYDIS_MNEMONIC_VPMULHUD:           return MNEMONIC_VPMULHUD;
        case ZYDIS_MNEMONIC_VPMULHUW:           return MNEMONIC_VPMULHUW;
        case ZYDIS_MNEMONIC_VPMULHW:            return MNEMONIC_VPMULHW;
        case ZYDIS_MNEMONIC_VPMULLD:            return MNEMONIC_VPMULLD;
        case ZYDIS_MNEMONIC_VPMULLQ:            return MNEMONIC_VPMULLQ;
        case ZYDIS_MNEMONIC_VPMULLW:            return MNEMONIC_VPMULLW;
        case ZYDIS_MNEMONIC_VPMULTISHIFTQB:     return MNEMONIC_VPMULTISHIFTQB;
        case ZYDIS_MNEMONIC_VPMULUDQ:           return MNEMONIC_VPMULUDQ;
        case ZYDIS_MNEMONIC_VPOPCNTB:           return MNEMONIC_VPOPCNTB;
        case ZYDIS_MNEMONIC_VPOPCNTD:           return MNEMONIC_VPOPCNTD;
        case ZYDIS_MNEMONIC_VPOPCNTQ:           return MNEMONIC_VPOPCNTQ;
        case ZYDIS_MNEMONIC_VPOPCNTW:           return MNEMONIC_VPOPCNTW;
        case ZYDIS_MNEMONIC_VPOR:               return MNEMONIC_VPOR;
        case ZYDIS_MNEMONIC_VPORD:              return MNEMONIC_VPORD;
        case ZYDIS_MNEMONIC_VPORQ:              return MNEMONIC_VPORQ;
        case ZYDIS_MNEMONIC_VPPERM:             return MNEMONIC_VPPERM;
        case ZYDIS_MNEMONIC_VPREFETCH0:         return MNEMONIC_VPREFETCH0;
        case ZYDIS_MNEMONIC_VPREFETCH1:         return MNEMONIC_VPREFETCH1;
        case ZYDIS_MNEMONIC_VPREFETCH2:         return MNEMONIC_VPREFETCH2;
        case ZYDIS_MNEMONIC_VPREFETCHE0:        return MNEMONIC_VPREFETCHE0;
        case ZYDIS_MNEMONIC_VPREFETCHE1:        return MNEMONIC_VPREFETCHE1;
        case ZYDIS_MNEMONIC_VPREFETCHE2:        return MNEMONIC_VPREFETCHE2;
        case ZYDIS_MNEMONIC_VPREFETCHENTA:      return MNEMONIC_VPREFETCHENTA;
        case ZYDIS_MNEMONIC_VPREFETCHNTA:       return MNEMONIC_VPREFETCHNTA;
        case ZYDIS_MNEMONIC_VPROLD:             return MNEMONIC_VPROLD;
        case ZYDIS_MNEMONIC_VPROLQ:             return MNEMONIC_VPROLQ;
        case ZYDIS_MNEMONIC_VPROLVD:            return MNEMONIC_VPROLVD;
        case ZYDIS_MNEMONIC_VPROLVQ:            return MNEMONIC_VPROLVQ;
        case ZYDIS_MNEMONIC_VPRORD:             return MNEMONIC_VPRORD;
        case ZYDIS_MNEMONIC_VPRORQ:             return MNEMONIC_VPRORQ;
        case ZYDIS_MNEMONIC_VPRORVD:            return MNEMONIC_VPRORVD;
        case ZYDIS_MNEMONIC_VPRORVQ:            return MNEMONIC_VPRORVQ;
        case ZYDIS_MNEMONIC_VPROTB:             return MNEMONIC_VPROTB;
        case ZYDIS_MNEMONIC_VPROTD:             return MNEMONIC_VPROTD;
        case ZYDIS_MNEMONIC_VPROTQ:             return MNEMONIC_VPROTQ;
        case ZYDIS_MNEMONIC_VPROTW:             return MNEMONIC_VPROTW;
        case ZYDIS_MNEMONIC_VPSADBW:            return MNEMONIC_VPSADBW;
        case ZYDIS_MNEMONIC_VPSBBD:             return MNEMONIC_VPSBBD;
        case ZYDIS_MNEMONIC_VPSBBRD:            return MNEMONIC_VPSBBRD;
        case ZYDIS_MNEMONIC_VPSCATTERDD:        return MNEMONIC_VPSCATTERDD;
        case ZYDIS_MNEMONIC_VPSCATTERDQ:        return MNEMONIC_VPSCATTERDQ;
        case ZYDIS_MNEMONIC_VPSCATTERQD:        return MNEMONIC_VPSCATTERQD;
        case ZYDIS_MNEMONIC_VPSCATTERQQ:        return MNEMONIC_VPSCATTERQQ;
        case ZYDIS_MNEMONIC_VPSHAB:             return MNEMONIC_VPSHAB;
        case ZYDIS_MNEMONIC_VPSHAD:             return MNEMONIC_VPSHAD;
        case ZYDIS_MNEMONIC_VPSHAQ:             return MNEMONIC_VPSHAQ;
        case ZYDIS_MNEMONIC_VPSHAW:             return MNEMONIC_VPSHAW;
        case ZYDIS_MNEMONIC_VPSHLB:             return MNEMONIC_VPSHLB;
        case ZYDIS_MNEMONIC_VPSHLD:             return MNEMONIC_VPSHLD;
        case ZYDIS_MNEMONIC_VPSHLDD:            return MNEMONIC_VPSHLDD;
        case ZYDIS_MNEMONIC_VPSHLDQ:            return MNEMONIC_VPSHLDQ;
        case ZYDIS_MNEMONIC_VPSHLDVD:           return MNEMONIC_VPSHLDVD;
        case ZYDIS_MNEMONIC_VPSHLDVQ:           return MNEMONIC_VPSHLDVQ;
        case ZYDIS_MNEMONIC_VPSHLDVW:           return MNEMONIC_VPSHLDVW;
        case ZYDIS_MNEMONIC_VPSHLDW:            return MNEMONIC_VPSHLDW;
        case ZYDIS_MNEMONIC_VPSHLQ:             return MNEMONIC_VPSHLQ;
        case ZYDIS_MNEMONIC_VPSHLW:             return MNEMONIC_VPSHLW;
        case ZYDIS_MNEMONIC_VPSHRDD:            return MNEMONIC_VPSHRDD;
        case ZYDIS_MNEMONIC_VPSHRDQ:            return MNEMONIC_VPSHRDQ;
        case ZYDIS_MNEMONIC_VPSHRDVD:           return MNEMONIC_VPSHRDVD;
        case ZYDIS_MNEMONIC_VPSHRDVQ:           return MNEMONIC_VPSHRDVQ;
        case ZYDIS_MNEMONIC_VPSHRDVW:           return MNEMONIC_VPSHRDVW;
        case ZYDIS_MNEMONIC_VPSHRDW:            return MNEMONIC_VPSHRDW;
        case ZYDIS_MNEMONIC_VPSHUFB:            return MNEMONIC_VPSHUFB;
        case ZYDIS_MNEMONIC_VPSHUFBITQMB:       return MNEMONIC_VPSHUFBITQMB;
        case ZYDIS_MNEMONIC_VPSHUFD:            return MNEMONIC_VPSHUFD;
        case ZYDIS_MNEMONIC_VPSHUFHW:           return MNEMONIC_VPSHUFHW;
        case ZYDIS_MNEMONIC_VPSHUFLW:           return MNEMONIC_VPSHUFLW;
        case ZYDIS_MNEMONIC_VPSIGNB:            return MNEMONIC_VPSIGNB;
        case ZYDIS_MNEMONIC_VPSIGND:            return MNEMONIC_VPSIGND;
        case ZYDIS_MNEMONIC_VPSIGNW:            return MNEMONIC_VPSIGNW;
        case ZYDIS_MNEMONIC_VPSLLD:             return MNEMONIC_VPSLLD;
        case ZYDIS_MNEMONIC_VPSLLDQ:            return MNEMONIC_VPSLLDQ;
        case ZYDIS_MNEMONIC_VPSLLQ:             return MNEMONIC_VPSLLQ;
        case ZYDIS_MNEMONIC_VPSLLVD:            return MNEMONIC_VPSLLVD;
        case ZYDIS_MNEMONIC_VPSLLVQ:            return MNEMONIC_VPSLLVQ;
        case ZYDIS_MNEMONIC_VPSLLVW:            return MNEMONIC_VPSLLVW;
        case ZYDIS_MNEMONIC_VPSLLW:             return MNEMONIC_VPSLLW;
        case ZYDIS_MNEMONIC_VPSRAD:             return MNEMONIC_VPSRAD;
        case ZYDIS_MNEMONIC_VPSRAQ:             return MNEMONIC_VPSRAQ;
        case ZYDIS_MNEMONIC_VPSRAVD:            return MNEMONIC_VPSRAVD;
        case ZYDIS_MNEMONIC_VPSRAVQ:            return MNEMONIC_VPSRAVQ;
        case ZYDIS_MNEMONIC_VPSRAVW:            return MNEMONIC_VPSRAVW;
        case ZYDIS_MNEMONIC_VPSRAW:             return MNEMONIC_VPSRAW;
        case ZYDIS_MNEMONIC_VPSRLD:             return MNEMONIC_VPSRLD;
        case ZYDIS_MNEMONIC_VPSRLDQ:            return MNEMONIC_VPSRLDQ;
        case ZYDIS_MNEMONIC_VPSRLQ:             return MNEMONIC_VPSRLQ;
        case ZYDIS_MNEMONIC_VPSRLVD:            return MNEMONIC_VPSRLVD;
        case ZYDIS_MNEMONIC_VPSRLVQ:            return MNEMONIC_VPSRLVQ;
        case ZYDIS_MNEMONIC_VPSRLVW:            return MNEMONIC_VPSRLVW;
        case ZYDIS_MNEMONIC_VPSRLW:             return MNEMONIC_VPSRLW;
        case ZYDIS_MNEMONIC_VPSUBB:             return MNEMONIC_VPSUBB;
        case ZYDIS_MNEMONIC_VPSUBD:             return MNEMONIC_VPSUBD;
        case ZYDIS_MNEMONIC_VPSUBQ:             return MNEMONIC_VPSUBQ;
        case ZYDIS_MNEMONIC_VPSUBRD:            return MNEMONIC_VPSUBRD;
        case ZYDIS_MNEMONIC_VPSUBRSETBD:        return MNEMONIC_VPSUBRSETBD;
        case ZYDIS_MNEMONIC_VPSUBSB:            return MNEMONIC_VPSUBSB;
        case ZYDIS_MNEMONIC_VPSUBSETBD:         return MNEMONIC_VPSUBSETBD;
        case ZYDIS_MNEMONIC_VPSUBSW:            return MNEMONIC_VPSUBSW;
        case ZYDIS_MNEMONIC_VPSUBUSB:           return MNEMONIC_VPSUBUSB;
        case ZYDIS_MNEMONIC_VPSUBUSW:           return MNEMONIC_VPSUBUSW;
        case ZYDIS_MNEMONIC_VPSUBW:             return MNEMONIC_VPSUBW;
        case ZYDIS_MNEMONIC_VPTERNLOGD:         return MNEMONIC_VPTERNLOGD;
        case ZYDIS_MNEMONIC_VPTERNLOGQ:         return MNEMONIC_VPTERNLOGQ;
        case ZYDIS_MNEMONIC_VPTEST:             return MNEMONIC_VPTEST;
        case ZYDIS_MNEMONIC_VPTESTMB:           return MNEMONIC_VPTESTMB;
        case ZYDIS_MNEMONIC_VPTESTMD:           return MNEMONIC_VPTESTMD;
        case ZYDIS_MNEMONIC_VPTESTMQ:           return MNEMONIC_VPTESTMQ;
        case ZYDIS_MNEMONIC_VPTESTMW:           return MNEMONIC_VPTESTMW;
        case ZYDIS_MNEMONIC_VPTESTNMB:          return MNEMONIC_VPTESTNMB;
        case ZYDIS_MNEMONIC_VPTESTNMD:          return MNEMONIC_VPTESTNMD;
        case ZYDIS_MNEMONIC_VPTESTNMQ:          return MNEMONIC_VPTESTNMQ;
        case ZYDIS_MNEMONIC_VPTESTNMW:          return MNEMONIC_VPTESTNMW;
        case ZYDIS_MNEMONIC_VPUNPCKHBW:         return MNEMONIC_VPUNPCKHBW;
        case ZYDIS_MNEMONIC_VPUNPCKHDQ:         return MNEMONIC_VPUNPCKHDQ;
        case ZYDIS_MNEMONIC_VPUNPCKHQDQ:        return MNEMONIC_VPUNPCKHQDQ;
        case ZYDIS_MNEMONIC_VPUNPCKHWD:         return MNEMONIC_VPUNPCKHWD;
        case ZYDIS_MNEMONIC_VPUNPCKLBW:         return MNEMONIC_VPUNPCKLBW;
        case ZYDIS_MNEMONIC_VPUNPCKLDQ:         return MNEMONIC_VPUNPCKLDQ;
        case ZYDIS_MNEMONIC_VPUNPCKLQDQ:        return MNEMONIC_VPUNPCKLQDQ;
        case ZYDIS_MNEMONIC_VPUNPCKLWD:         return MNEMONIC_VPUNPCKLWD;
        case ZYDIS_MNEMONIC_VPXOR:              return MNEMONIC_VPXOR;
        case ZYDIS_MNEMONIC_VPXORD:             return MNEMONIC_VPXORD;
        case ZYDIS_MNEMONIC_VPXORQ:             return MNEMONIC_VPXORQ;
        case ZYDIS_MNEMONIC_VRANGEPD:           return MNEMONIC_VRANGEPD;
        case ZYDIS_MNEMONIC_VRANGEPS:           return MNEMONIC_VRANGEPS;
        case ZYDIS_MNEMONIC_VRANGESD:           return MNEMONIC_VRANGESD;
        case ZYDIS_MNEMONIC_VRANGESS:           return MNEMONIC_VRANGESS;
        case ZYDIS_MNEMONIC_VRCP14PD:           return MNEMONIC_VRCP14PD;
        case ZYDIS_MNEMONIC_VRCP14PS:           return MNEMONIC_VRCP14PS;
        case ZYDIS_MNEMONIC_VRCP14SD:           return MNEMONIC_VRCP14SD;
        case ZYDIS_MNEMONIC_VRCP14SS:           return MNEMONIC_VRCP14SS;
        case ZYDIS_MNEMONIC_VRCP23PS:           return MNEMONIC_VRCP23PS;
        case ZYDIS_MNEMONIC_VRCP28PD:           return MNEMONIC_VRCP28PD;
        case ZYDIS_MNEMONIC_VRCP28PS:           return MNEMONIC_VRCP28PS;
        case ZYDIS_MNEMONIC_VRCP28SD:           return MNEMONIC_VRCP28SD;
        case ZYDIS_MNEMONIC_VRCP28SS:           return MNEMONIC_VRCP28SS;
        case ZYDIS_MNEMONIC_VRCPPS:             return MNEMONIC_VRCPPS;
        case ZYDIS_MNEMONIC_VRCPSS:             return MNEMONIC_VRCPSS;
        case ZYDIS_MNEMONIC_VREDUCEPD:          return MNEMONIC_VREDUCEPD;
        case ZYDIS_MNEMONIC_VREDUCEPS:          return MNEMONIC_VREDUCEPS;
        case ZYDIS_MNEMONIC_VREDUCESD:          return MNEMONIC_VREDUCESD;
        case ZYDIS_MNEMONIC_VREDUCESS:          return MNEMONIC_VREDUCESS;
        case ZYDIS_MNEMONIC_VRNDFXPNTPD:        return MNEMONIC_VRNDFXPNTPD;
        case ZYDIS_MNEMONIC_VRNDFXPNTPS:        return MNEMONIC_VRNDFXPNTPS;
        case ZYDIS_MNEMONIC_VRNDSCALEPD:        return MNEMONIC_VRNDSCALEPD;
        case ZYDIS_MNEMONIC_VRNDSCALEPS:        return MNEMONIC_VRNDSCALEPS;
        case ZYDIS_MNEMONIC_VRNDSCALESD:        return MNEMONIC_VRNDSCALESD;
        case ZYDIS_MNEMONIC_VRNDSCALESS:        return MNEMONIC_VRNDSCALESS;
        case ZYDIS_MNEMONIC_VROUNDPD:           return MNEMONIC_VROUNDPD;
        case ZYDIS_MNEMONIC_VROUNDPS:           return MNEMONIC_VROUNDPS;
        case ZYDIS_MNEMONIC_VROUNDSD:           return MNEMONIC_VROUNDSD;
        case ZYDIS_MNEMONIC_VROUNDSS:           return MNEMONIC_VROUNDSS;
        case ZYDIS_MNEMONIC_VRSQRT14PD:         return MNEMONIC_VRSQRT14PD;
        case ZYDIS_MNEMONIC_VRSQRT14PS:         return MNEMONIC_VRSQRT14PS;
        case ZYDIS_MNEMONIC_VRSQRT14SD:         return MNEMONIC_VRSQRT14SD;
        case ZYDIS_MNEMONIC_VRSQRT14SS:         return MNEMONIC_VRSQRT14SS;
        case ZYDIS_MNEMONIC_VRSQRT23PS:         return MNEMONIC_VRSQRT23PS;
        case ZYDIS_MNEMONIC_VRSQRT28PD:         return MNEMONIC_VRSQRT28PD;
        case ZYDIS_MNEMONIC_VRSQRT28PS:         return MNEMONIC_VRSQRT28PS;
        case ZYDIS_MNEMONIC_VRSQRT28SD:         return MNEMONIC_VRSQRT28SD;
        case ZYDIS_MNEMONIC_VRSQRT28SS:         return MNEMONIC_VRSQRT28SS;
        case ZYDIS_MNEMONIC_VRSQRTPS:           return MNEMONIC_VRSQRTPS;
        case ZYDIS_MNEMONIC_VRSQRTSS:           return MNEMONIC_VRSQRTSS;
        case ZYDIS_MNEMONIC_VSCALEFPD:          return MNEMONIC_VSCALEFPD;
        case ZYDIS_MNEMONIC_VSCALEFPS:          return MNEMONIC_VSCALEFPS;
        case ZYDIS_MNEMONIC_VSCALEFSD:          return MNEMONIC_VSCALEFSD;
        case ZYDIS_MNEMONIC_VSCALEFSS:          return MNEMONIC_VSCALEFSS;
        case ZYDIS_MNEMONIC_VSCALEPS:           return MNEMONIC_VSCALEPS;
        case ZYDIS_MNEMONIC_VSCATTERDPD:        return MNEMONIC_VSCATTERDPD;
        case ZYDIS_MNEMONIC_VSCATTERDPS:        return MNEMONIC_VSCATTERDPS;
        case ZYDIS_MNEMONIC_VSCATTERPF0DPD:     return MNEMONIC_VSCATTERPF0DPD;
        case ZYDIS_MNEMONIC_VSCATTERPF0DPS:     return MNEMONIC_VSCATTERPF0DPS;
        case ZYDIS_MNEMONIC_VSCATTERPF0HINTDPD: return MNEMONIC_VSCATTERPF0HINTDPD;
        case ZYDIS_MNEMONIC_VSCATTERPF0HINTDPS: return MNEMONIC_VSCATTERPF0HINTDPS;
        case ZYDIS_MNEMONIC_VSCATTERPF0QPD:     return MNEMONIC_VSCATTERPF0QPD;
        case ZYDIS_MNEMONIC_VSCATTERPF0QPS:     return MNEMONIC_VSCATTERPF0QPS;
        case ZYDIS_MNEMONIC_VSCATTERPF1DPD:     return MNEMONIC_VSCATTERPF1DPD;
        case ZYDIS_MNEMONIC_VSCATTERPF1DPS:     return MNEMONIC_VSCATTERPF1DPS;
        case ZYDIS_MNEMONIC_VSCATTERPF1QPD:     return MNEMONIC_VSCATTERPF1QPD;
        case ZYDIS_MNEMONIC_VSCATTERPF1QPS:     return MNEMONIC_VSCATTERPF1QPS;
        case ZYDIS_MNEMONIC_VSCATTERQPD:        return MNEMONIC_VSCATTERQPD;
        case ZYDIS_MNEMONIC_VSCATTERQPS:        return MNEMONIC_VSCATTERQPS;
        case ZYDIS_MNEMONIC_VSHUFF32X4:         return MNEMONIC_VSHUFF32X4;
        case ZYDIS_MNEMONIC_VSHUFF64X2:         return MNEMONIC_VSHUFF64X2;
        case ZYDIS_MNEMONIC_VSHUFI32X4:         return MNEMONIC_VSHUFI32X4;
        case ZYDIS_MNEMONIC_VSHUFI64X2:         return MNEMONIC_VSHUFI64X2;
        case ZYDIS_MNEMONIC_VSHUFPD:            return MNEMONIC_VSHUFPD;
        case ZYDIS_MNEMONIC_VSHUFPS:            return MNEMONIC_VSHUFPS;
        case ZYDIS_MNEMONIC_VSQRTPD:            return MNEMONIC_VSQRTPD;
        case ZYDIS_MNEMONIC_VSQRTPS:            return MNEMONIC_VSQRTPS;
        case ZYDIS_MNEMONIC_VSQRTSD:            return MNEMONIC_VSQRTSD;
        case ZYDIS_MNEMONIC_VSQRTSS:            return MNEMONIC_VSQRTSS;
        case ZYDIS_MNEMONIC_VSTMXCSR:           return MNEMONIC_VSTMXCSR;
        case ZYDIS_MNEMONIC_VSUBPD:             return MNEMONIC_VSUBPD;
        case ZYDIS_MNEMONIC_VSUBPS:             return MNEMONIC_VSUBPS;
        case ZYDIS_MNEMONIC_VSUBRPD:            return MNEMONIC_VSUBRPD;
        case ZYDIS_MNEMONIC_VSUBRPS:            return MNEMONIC_VSUBRPS;
        case ZYDIS_MNEMONIC_VSUBSD:             return MNEMONIC_VSUBSD;
        case ZYDIS_MNEMONIC_VSUBSS:             return MNEMONIC_VSUBSS;
        case ZYDIS_MNEMONIC_VTESTPD:            return MNEMONIC_VTESTPD;
        case ZYDIS_MNEMONIC_VTESTPS:            return MNEMONIC_VTESTPS;
        case ZYDIS_MNEMONIC_VUCOMISD:           return MNEMONIC_VUCOMISD;
        case ZYDIS_MNEMONIC_VUCOMISS:           return MNEMONIC_VUCOMISS;
        case ZYDIS_MNEMONIC_VUNPCKHPD:          return MNEMONIC_VUNPCKHPD;
        case ZYDIS_MNEMONIC_VUNPCKHPS:          return MNEMONIC_VUNPCKHPS;
        case ZYDIS_MNEMONIC_VUNPCKLPD:          return MNEMONIC_VUNPCKLPD;
        case ZYDIS_MNEMONIC_VUNPCKLPS:          return MNEMONIC_VUNPCKLPS;
        case ZYDIS_MNEMONIC_VXORPD:             return MNEMONIC_VXORPD;
        case ZYDIS_MNEMONIC_VXORPS:             return MNEMONIC_VXORPS;
        case ZYDIS_MNEMONIC_VZEROALL:           return MNEMONIC_VZEROALL;
        case ZYDIS_MNEMONIC_VZEROUPPER:         return MNEMONIC_VZEROUPPER;
        case ZYDIS_MNEMONIC_WBINVD:             return MNEMONIC_WBINVD;
        case ZYDIS_MNEMONIC_WRFSBASE:           return MNEMONIC_WRFSBASE;
        case ZYDIS_MNEMONIC_WRGSBASE:           return MNEMONIC_WRGSBASE;
        case ZYDIS_MNEMONIC_WRMSR:              return MNEMONIC_WRMSR;
        case ZYDIS_MNEMONIC_WRPKRU:             return MNEMONIC_WRPKRU;
        case ZYDIS_MNEMONIC_WRSSD:              return MNEMONIC_WRSSD;
        case ZYDIS_MNEMONIC_WRSSQ:              return MNEMONIC_WRSSQ;
        case ZYDIS_MNEMONIC_WRUSSD:             return MNEMONIC_WRUSSD;
        case ZYDIS_MNEMONIC_WRUSSQ:             return MNEMONIC_WRUSSQ;
        case ZYDIS_MNEMONIC_XABORT:             return MNEMONIC_XABORT;
        case ZYDIS_MNEMONIC_XADD:               return MNEMONIC_XADD;
        case ZYDIS_MNEMONIC_XBEGIN:             return MNEMONIC_XBEGIN;
        case ZYDIS_MNEMONIC_XCHG:               return MNEMONIC_XCHG;
        case ZYDIS_MNEMONIC_XCRYPT_CBC:         return MNEMONIC_XCRYPT_CBC;
        case ZYDIS_MNEMONIC_XCRYPT_CFB:         return MNEMONIC_XCRYPT_CFB;
        case ZYDIS_MNEMONIC_XCRYPT_CTR:         return MNEMONIC_XCRYPT_CTR;
        case ZYDIS_MNEMONIC_XCRYPT_ECB:         return MNEMONIC_XCRYPT_ECB;
        case ZYDIS_MNEMONIC_XCRYPT_OFB:         return MNEMONIC_XCRYPT_OFB;
        case ZYDIS_MNEMONIC_XEND:               return MNEMONIC_XEND;
        case ZYDIS_MNEMONIC_XGETBV:             return MNEMONIC_XGETBV;
        case ZYDIS_MNEMONIC_XLAT:               return MNEMONIC_XLAT;
        case ZYDIS_MNEMONIC_XOR:                return MNEMONIC_XOR;
        case ZYDIS_MNEMONIC_XORPD:              return MNEMONIC_XORPD;
        case ZYDIS_MNEMONIC_XORPS:              return MNEMONIC_XORPS;
        case ZYDIS_MNEMONIC_XRESLDTRK:          return MNEMONIC_XRESLDTRK;
        case ZYDIS_MNEMONIC_XRSTOR:             return MNEMONIC_XRSTOR;
        case ZYDIS_MNEMONIC_XRSTOR64:           return MNEMONIC_XRSTOR64;
        case ZYDIS_MNEMONIC_XRSTORS:            return MNEMONIC_XRSTORS;
        case ZYDIS_MNEMONIC_XRSTORS64:          return MNEMONIC_XRSTORS64;
        case ZYDIS_MNEMONIC_XSAVE:              return MNEMONIC_XSAVE;
        case ZYDIS_MNEMONIC_XSAVE64:            return MNEMONIC_XSAVE64;
        case ZYDIS_MNEMONIC_XSAVEC:             return MNEMONIC_XSAVEC;
        case ZYDIS_MNEMONIC_XSAVEC64:           return MNEMONIC_XSAVEC64;
        case ZYDIS_MNEMONIC_XSAVEOPT:           return MNEMONIC_XSAVEOPT;
        case ZYDIS_MNEMONIC_XSAVEOPT64:         return MNEMONIC_XSAVEOPT64;
        case ZYDIS_MNEMONIC_XSAVES:             return MNEMONIC_XSAVES;
        case ZYDIS_MNEMONIC_XSAVES64:           return MNEMONIC_XSAVES64;
        case ZYDIS_MNEMONIC_XSETBV:             return MNEMONIC_XSETBV;
        case ZYDIS_MNEMONIC_XSHA1:              return MNEMONIC_XSHA1;
        case ZYDIS_MNEMONIC_XSHA256:            return MNEMONIC_XSHA256;
        case ZYDIS_MNEMONIC_XSTORE:             return MNEMONIC_XSTORE;
        case ZYDIS_MNEMONIC_XSUSLDTRK:          return MNEMONIC_XSUSLDTRK;
        case ZYDIS_MNEMONIC_XTEST:              return MNEMONIC_XTEST;                                                                       
        default:                                return MNEMONIC_UNKNOWN;
    }
}

/*
 * ZydisInstructionCategory to category
 */
static uint16_t convert(ZydisInstructionCategory category, ZydisISAExt isa)
{
    switch (category)
    { 
        case ZYDIS_CATEGORY_RET:
            return CATEGORY_RETURN;
        case ZYDIS_CATEGORY_CALL:
            return CATEGORY_CALL;
        case ZYDIS_CATEGORY_UNCOND_BR:
            return CATEGORY_JUMP;
        case ZYDIS_CATEGORY_COND_BR:
            return CATEGORY_CONDITIONAL | CATEGORY_JUMP;
        default:
            break;
    }
    switch (isa)
    {
        case ZYDIS_ISA_EXT_X87:
            return CATEGORY_X87;
        case ZYDIS_ISA_EXT_MMX:
            return CATEGORY_MMX;
        case ZYDIS_ISA_EXT_SSE: case ZYDIS_ISA_EXT_SSE2:
        case ZYDIS_ISA_EXT_SSE3: case ZYDIS_ISA_EXT_SSE4:
        case ZYDIS_ISA_EXT_SSE4A: case ZYDIS_ISA_EXT_SSSE3:
            return CATEGORY_SSE;
        case ZYDIS_ISA_EXT_AVX:
            return CATEGORY_AVX;
        case ZYDIS_ISA_EXT_AVX2: case ZYDIS_ISA_EXT_AVX2GATHER:
            return CATEGORY_AVX2;
        case ZYDIS_ISA_EXT_AVX512EVEX: case ZYDIS_ISA_EXT_AVX512VEX:
        case ZYDIS_ISA_EXT_AVXAES:
            return CATEGORY_AVX512;
        default:
            return 0x0;
    }
}

/*
 * Assigns a "suspiciousness" score to instructions.
 */
int suspiciousness(const uint8_t *bytes, size_t size)
{
    if (size == 0) return INT32_MAX;
    int score = 0;
    uint8_t rex = 0x0, seg = 0x0, rep = 0x0;
    int i;
    for (i = 0; i < (int)size; i++)
    {
        bool done = false;
        switch (bytes[i])
        {
            case 0x66: case 0x67:
                break;      // redundant 0x66/0x67 prefixes allowable
            case 0xf0: case 0xf2: case 0xf3:
            case 0x2e: case 0x36: case 0x3e: case 0x26: case 0x64: case 0x65:
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
            case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b:
            case 0x4c: case 0x4d: case 0x4e: case 0x4f:
                for (int j = 0; j < i; j++)
                    if (bytes[j] == bytes[i]) score++;
                break;
            default:
                done = true;
                break;
        }
        if (done) break;
        switch (bytes[i])
        {
            case 0xf2: case 0xf3:
                if (rep != 0x0) score++;
                break;
            case 0x2e: case 0x36: case 0x3e: case 0x26: case 0x64: case 0x65:
                if (seg != 0x0) score++;
                seg = bytes[i];
                break;
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
            case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b:
            case 0x4c: case 0x4d: case 0x4e: case 0x4f:
                if (rex != 0x0) score++;
                rex = bytes[i];
                break;
            default:
                break;
        }
    }
    if (i >= (int)size) return INT32_MAX;
    switch (bytes[i])
    {
        case 0x00:
            if (size == 2 && i == 0 && bytes[1] == 0x0)
                return 2;       // add %al,(%rax)
            return score;
        case 0x6c: case 0x6d: case 0x6e: case 0x6f:
        case 0xec: case 0xed: case 0xee: case 0xef:
            return INT32_MAX;   // in/out
        case 0xcf:
            return INT32_MAX;   // iret
        case 0x06: case 0x07: case 0x0e: case 0x16: case 0x17:
        case 0x1e: case 0x27: case 0x2f: case 0x37: case 0x3f:
        case 0x60: case 0x61: case 0x82: case 0x9a: case 0xd4:
        case 0xd5: case 0xd6: case 0xea: 
            return INT32_MAX;   // Invalid
        default:
            return score;
    }
}

/*
 * Get an operand.
 */
const OpInfo *getOperand(const InstrInfo *I, int idx, OpType type,
	Access access)
{
    for (uint8_t i = 0; i < I->count.op; i++)
    {
        const OpInfo *op = I->op + i;
        if ((type == OPTYPE_INVALID? true: op->type == type) &&
            (op->access & access) == access)
        {
            if (idx == 0)
                return op;
            idx--;
        }
    }
    return nullptr;
}

