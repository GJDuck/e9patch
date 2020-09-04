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

#include <cassert>

/*
 * Lookup an operand index.  Here, -1 means not an operand argument, and
 * (>=x86->op_count) means operand argument overflow, and anything else is
 * a valid operand index.
 */
static int getOperandIdx(const cs_insn *I, ArgumentKind arg)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    const cs_x86_op *op     = x86->operands;
    
    int idx = 0;
    switch (arg)
    {
        case ARGUMENT_OPERAND_0: case ARGUMENT_OPERAND_1:
        case ARGUMENT_OPERAND_2: case ARGUMENT_OPERAND_3:
        case ARGUMENT_OPERAND_4: case ARGUMENT_OPERAND_5:
        case ARGUMENT_OPERAND_6: case ARGUMENT_OPERAND_7:
            idx = (int)arg - (int)ARGUMENT_OPERAND_0;
            return idx;
        case ARGUMENT_SRC_0: case ARGUMENT_SRC_1:
        case ARGUMENT_SRC_2: case ARGUMENT_SRC_3:
        case ARGUMENT_SRC_4: case ARGUMENT_SRC_5:
        case ARGUMENT_SRC_6: case ARGUMENT_SRC_7:
            idx = (int)arg - (int)ARGUMENT_SRC_0;
            for (int i = 0, j = 0; i < (int)x86->op_count; i++)
            {
                if (op[i].type == X86_OP_IMM ||
                    (op[i].access & CS_AC_READ) != 0)
                {
                    if (j >= idx)
                        return i;
                    j++;
                }
            }
            return (int)x86->op_count+1;
        case ARGUMENT_DST_0: case ARGUMENT_DST_1:
        case ARGUMENT_DST_2: case ARGUMENT_DST_3:
        case ARGUMENT_DST_4: case ARGUMENT_DST_5:
        case ARGUMENT_DST_6: case ARGUMENT_DST_7:
            idx = (int)arg - (int)ARGUMENT_DST_0;
            for (int i = 0, j = 0; i < (int)x86->op_count; i++)
            {
                if (op[i].type != X86_OP_IMM &&
                    (op[i].access & CS_AC_WRITE) != 0)
                {
                    if (j >= idx)
                        return i;
                    j++;
                }
            }
            return (int)x86->op_count+1;
        default:
            return -1;
    }
}

/*
 * Temporarily restore a register.
 */
static void sendTemporaryRestoreReg(FILE *out, CallInfo &info, x86_reg reg,
    int argno, int slot)
{
    if (!info.isClobbered(reg))
        return;
    if (!info.isUsed(reg))
    {
        // If reg is clobbered but not used, then we simply restore it.
        sendMovFromStackToR64(out, info.getOffset(reg), getRegIdx(reg));
        info.restore(reg);
        return;
    }

    int regno = getRegIdx(reg);
    assert(regno >= 0);
    sendMovFromR64ToStack(out, regno, -(int32_t)sizeof(int64_t) * slot);
    sendMovFromStackToR64(out, info.getOffset(reg), regno);
}

/*
 * Undo sendTemporaryRestoreReg().
 */
static void sendUndoTemporaryRestoreReg(FILE *out, const CallInfo &info,
    x86_reg reg, int argno, int slot)
{
    if (!info.isClobbered(reg))
        return;

    int regno = getRegIdx(reg);
    assert(regno >= 0);
    sendMovFromStackToR64(out, -(int32_t)sizeof(int64_t) * slot, regno);
}

/*
 * Send instructions that ensure the given register is saved.
 */
static bool sendSaveRegToStack(FILE *out, CallInfo &info, x86_reg reg)
{
    if (info.isSaved(reg))
        return true;
    if (info.pushClobbersRAX(reg) && !info.isSaved(X86_REG_RAX))
    {
        sendPush(out, info.rsp_offset, X86_REG_RAX);
        info.push(X86_REG_RAX);
    }
    bool result = sendPush(out, info.rsp_offset, reg);
    info.push(reg);
    return result;
}

/*
 * Send a load (mov/lea) from a converted memory operand to a register.
 */
static void sendLoadFromConvertedMemToR64(FILE *out, const cs_insn *I,
    unsigned idx, CallInfo &info, uint8_t opcode, int regno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    const cs_x86_op *op     = x86->operands;
    op += idx;
    assert(idx < 8 && op->type == X86_OP_MEM);

    bool have_prefix = (x86->prefix[1] != 0);
    uint8_t prefix   = 0;
    if (have_prefix)
        prefix = x86->prefix[1];

    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    uint8_t rex = REX[regno] | (x86->rex & 0x03);

    uint8_t modrm = x86->modrm;
    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};
    modrm = (modrm & 0xc7) | (REG[regno] << 3);

    uint8_t mod   = (modrm >> 6) & 0x3;
    uint8_t rm    = modrm & 0x7;
    uint8_t i     = x86->encoding.modrm_offset + 1;
    uint8_t base  = 0;
    uint8_t sib   = x86->sib;
    bool have_sib = false;
    if (mod != 0x3 && rm == 0x4)        // have SIB?
    {
        have_sib = true;
        base = sib & 0x7;
        i++;
    }

    bool have_pc_rel = false;
    intptr_t disp    = 0;
    if (mod == 0x1 || mod == 0x2 || (mod == 0x0 && rm == 0x4 && base == 0x5))
    {
        disp = (intptr_t)x86->disp;
    }
    else if (mod == 0x0 && rm == 0x5)
    {
        have_pc_rel = true;
        disp        = I->address + I->size + (intptr_t)x86->disp;
    }

    x86_reg base_reg = op->mem.base;
    x86_reg index_reg = op->mem.index;

    sendTemporaryRestoreReg(out, info, base_reg, regno, 1);
    sendTemporaryRestoreReg(out, info, index_reg, regno, 2);

    intptr_t disp0 = disp;
    if (base_reg == X86_REG_RSP || base_reg == X86_REG_ESP)
        disp += info.rsp_offset;
    if (index_reg == X86_REG_RSP || index_reg == X86_REG_ESP)
        disp += info.rsp_offset;
    if (disp < INT32_MIN || disp > INT32_MAX)
    {
        // This is a corner case for nonsensical operands using %rsp
        warning("failed to load converted memory operand for instruction "
            "(%s%s%s) at address 0x%lx; the adjusted displacement is "
            "out-of-bounds", I->mnemonic, (I->op_str[0] == '\0'? "": " "),
            I->op_str, I->address);
        sendSExtFromI32ToR64(out, -1, regno);
        return;
    }
    if (disp != disp0)
    {
        switch (mod)
        {
            case 0x00:
                if (base == 0x5)
                    break;
                if (disp >= INT8_MIN && disp <= INT8_MAX)
                    modrm = (modrm & 0x3f) | (0x01 << 6);
                else
                    modrm = (modrm & 0x3f) | (0x02 << 6);
                break;
            case 0x01:
                if (disp < INT8_MIN || disp > INT8_MAX)
                    modrm = (modrm & 0x3f) | (0x02 << 6);
                break;
            default:
                break;
        }
    }

    mod = (modrm >> 6) & 0x3;
    if (have_prefix)
        fprintf(out, "%u,", prefix);
    fprintf(out, "%u,%u,%u,", rex, opcode, modrm);
    if (have_sib)
        fprintf(out, "%u,", sib);
    if (have_pc_rel)
        fprintf(out, "{\"rel32\":%d},", (int32_t)disp);
    else if (have_prefix)
        fprintf(out, "{\"int32\":%d},", (int32_t)disp);
    else if (mod == 0x1)
        fprintf(out, "{\"int8\":%d},", (int32_t)disp);
    else if (mod == 0x2 || (mod == 0x0 && base == 0x5))
        fprintf(out, "{\"int32\":%d},", (int32_t)disp);

    sendUndoTemporaryRestoreReg(out, info, base_reg, regno, 1);
    sendUndoTemporaryRestoreReg(out, info, index_reg, regno, 2);
}

/*
 * Emits instructions to load an operand into the corresponding
 * argno register.  If the operand does not exist, load -1.
 */
static void sendLoadOperandMetadata(FILE *out, const cs_insn *I,
    unsigned idx, CallInfo &info, int argno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    const cs_x86_op *op     = x86->operands;

    if (idx >= x86->op_count)
    {
        sendSExtFromI32ToR64(out, -1, argno);
        return;
    }

    switch (op[idx].type)
    {
        case X86_OP_REG:
        {
            x86_reg reg = op[idx].reg;
            if (!sendSaveRegToStack(out, info, reg))
            {
                warning("failed to generate code for operand argument "
                    "for instruction (%s%s%s) at address 0x%lx; operand uses "
                    "a register that is not yet supported", I->mnemonic,
                    (I->op_str[0] == '\0'? "": " "), I->op_str, I->address);
                goto unsupported;
            }
            sendLeaFromStackToR64(out, info.getOffset(reg), argno);
            return;
        }

        case X86_OP_MEM:
            sendLoadFromConvertedMemToR64(out, I, idx, info, /*lea=*/0x8d,
                argno);
            return;

        case X86_OP_IMM:
        {
            std::string offset("{\"rel32\":\".Limmediate_");
            offset += getRegName(argno);
            offset += "\"}";
            sendLeaFromPCRelToR64(out, offset.c_str(), argno);
            return;
        }

        default:
        unsupported:
            sendSExtFromI32ToR64(out, -1, argno);
            return;
    }
}

/*
 * Emits operand data.
 */
static void sendOperandDataMetadata(FILE *out, const cs_insn *I, unsigned idx,
    int argno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    const cs_x86_op *op     = x86->operands;

    if (idx >= x86->op_count)
        return;

    switch (op[idx].type)
    {
        case X86_OP_IMM:
            fprintf(out, "\".Limmediate_%s\",", getRegName(argno));
            switch (op->size)
            {
                case 1:
                    fprintf(out, "{\"int8\":%d},", (int32_t)op->imm);
                    break;
                case 2:
                    fprintf(out, "{\"int16\":%d},", (uint32_t)op->imm);
                    break;
                case 4:
                    fprintf(out, "{\"int32\":%d},", (uint32_t)op->imm);
                    break;
                default:
                    fputs("{\"int64\":", out),
                    sendInteger(out, op->imm);
                    fputs("},", out);
                    break;
            }
            break;

        default:
            return;
    }
}

/*
 * Emits instructions to load the jump/call/return target into the
 * corresponding argno register.  Else, if I is not a jump/call/return
 * instruction, load -1.
 */
static void sendLoadTargetMetadata(FILE *out, const cs_insn *I, CallInfo &info,
    int argno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    const cs_x86_op *op     = &x86->operands[0];

    switch (I->id)
    {
        case X86_INS_RET:
            sendMovFromStackToR64(out, info.rsp_offset, argno);
            return;
        case X86_INS_CALL:
        case X86_INS_JMP:
        case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE:
        case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA:
        case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP:
        case X86_INS_JL: case X86_INS_JGE: case X86_INS_JLE: case X86_INS_JG:
        case X86_INS_JCXZ: case X86_INS_JECXZ: case X86_INS_JRCXZ:
            if (x86->op_count == 1)
                break;
            // Fallthrough:

        default:
        unknown:

            // This is NOT a jump/call/return, so the target is set to (-1):
            sendSExtFromI32ToR64(out, -1, argno);
            return;
    }

    switch (op->type)
    {
        case X86_OP_REG:
            if (info.isClobbered(op->reg))
                sendMovFromStackToR64(out, info.getOffset(op->reg), argno);
            else
            {
                int regno = getRegIdx(op->reg);
                assert(regno >= 0);
                sendMovFromR64ToR64(out, regno, argno);
            }
            return;
        case X86_OP_MEM:
            // This is an indirect jump/call.  Convert the instruction into a
            // mov instruction that loads the target in the correct register
            sendLoadFromConvertedMemToR64(out, I, 0, info, /*mov=*/0x8b,
                argno);
            return;
        
        case X86_OP_IMM:
        {
            // This is a direct jump/call.  Emit an LEA that loads the target
            // into the correct register.

            // lea rel(%rip),%rarg
            intptr_t target = /*I->address + I->size +*/ op->imm;
            sendLeaFromPCRelToR64(out, target, argno);
            return;
        }
        default:
            goto unknown;
    }
}

/*
 * Emits instructions to load the address of the next instruction to be
 * executed by the CPU.
 */
static void sendLoadNextMetadata(FILE *out, const cs_insn *I, CallInfo &info,
    int argno)
{
    const char *regname = getRegName(argno);
    uint8_t opcode = 0x06;
    switch (I->id)
    {
        case X86_INS_RET:
        case X86_INS_CALL:
        case X86_INS_JMP:
            sendLoadTargetMetadata(out, I, info, argno);
            return;
        case X86_INS_JO:
            opcode = 0x70;
            break;
        case X86_INS_JNO:
            opcode = 0x71;
            break;
        case X86_INS_JB:
            opcode = 0x72;
            break;
        case X86_INS_JAE:
            opcode = 0x73;
            break;
        case X86_INS_JE:
            opcode = 0x74;
            break;
        case X86_INS_JNE:
            opcode = 0x75;
            break;
        case X86_INS_JBE:
            opcode = 0x76;
            break;
        case X86_INS_JA:
            opcode = 0x77;
            break;
        case X86_INS_JS:
            opcode = 0x78;
            break;
        case X86_INS_JNS:
            opcode = 0x79;
            break;
        case X86_INS_JP:
            opcode = 0x7a;
            break;
        case X86_INS_JNP:
            opcode = 0x7b;
            break;
        case X86_INS_JL:
            opcode = 0x7c;
            break;
        case X86_INS_JGE:
            opcode = 0x7d;
            break;
        case X86_INS_JLE:
            opcode = 0x7e;
            break;
        case X86_INS_JG:
            opcode = 0x7f;
            break;
        case X86_INS_JECXZ: case X86_INS_JRCXZ:
        {
            // Special handling for jecxz/jrcxz.  This is similar to other
            // jcc instructions (see below), except we must restore %rcx:
            sendTemporaryRestoreReg(out, info, X86_REG_RCX, argno, 1);
            if (I->id == X86_INS_JECXZ)
                fprintf(out, "%u,", 0x67);
            fprintf(out, "%u,{\"rel8\":\".Ltaken%s\"},", 0xe3, regname);
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
            fprintf(out, "%u,{\"rel8\":\".Lnext%s\"},", 0xeb, regname);
            fprintf(out, "\".Ltaken%s\",", regname);
            sendLoadTargetMetadata(out, I, info, argno);
            fprintf(out, "\".Lnext%s\",", regname);
            sendUndoTemporaryRestoreReg(out, info, X86_REG_RCX, argno, 1);
            return;
        }
        default:

            // leaq .Lcontinue(%rip),%rarg:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
            return;
    }

    // jcc .Ltaken
    fprintf(out, "%u,{\"rel8\":\".Ltaken%s\"},", opcode, regname);

    // .LnotTaken:
    // leaq .Lcontinue(%rip),%rarg
    // jmp .Lnext; 
    sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
    fprintf(out, "%u,{\"rel8\":\".Lnext%s\"},", 0xeb, regname);

    // .Ltaken:
    // ... load target into %rarg
    fprintf(out, "\".Ltaken%s\",", regname);
    sendLoadTargetMetadata(out, I, info, argno);
    
    // .Lnext:
    fprintf(out, "\".Lnext%s\",", regname);
}

/*
 * Emits an instruction to load the given value into the corresponding
 * argno register.
 */
static void sendLoadValueMetadata(FILE *out, intptr_t value, int argno)
{
    if (value >= INT32_MIN && value <= INT32_MAX)
        sendSExtFromI32ToR64(out, value, argno);
    else if (value >= 0 && value <= UINT32_MAX)
        sendZExtFromI32ToR64(out, value, argno);
    else
        sendMovFromI64ToR64(out, value, argno);
}

/*
 * Send string character data.
 */
static void sendStringCharData(FILE *out, char c)
{
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

/*
 * String asm string data.
 */
static void sendAsmStrData(FILE *out, const cs_insn *I,
    bool newline = false)
{
    fputc('\"', out);
    for (unsigned i = 0; I->mnemonic[i] != '\0'; i++)
        sendStringCharData(out, I->mnemonic[i]);
    if (I->op_str[0] != '\0')
    {
        sendStringCharData(out, ' ');
        for (unsigned i = 0; I->op_str[i] != '\0'; i++)
            sendStringCharData(out, I->op_str[i]);
    }
    if (newline)
        sendStringCharData(out, '\n');
    fputc('\"', out);
}

/*
 * Send integer data.
 */
static void sendIntegerData(FILE *out, unsigned size, intptr_t i)
{
    assert(size == 8 || size == 16 || size == 32 || size == 64);
    fprintf(out, "{\"int%u\":", size);
    sendInteger(out, i);
    fputc('}', out);
}

/*
 * Send bytes data.
 */
static void sendBytesData(FILE *out, const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(out, "%u%s", bytes[i], (i+1 < len? ",": ""));
}

/*
 * Build a metadata value (string).
 */
static const char *buildMetadataString(FILE *out, char *buf, long *pos)
{
    fputc('\0', out);
    if (ferror(out))
        error("failed to build metadata string: %s", strerror(errno));
    
    const char *str = buf + *pos;
    *pos = ftell(out);

    return str;
}

/*
 * Lookup a value from a CSV file based on the matching.
 */
static intptr_t makeMatchValue(MatchKind match, int idx, MatchField field,
    const cs_insn *I, intptr_t offset, intptr_t result);
static intptr_t lookupValue(const Action *action, const cs_insn *I,
    intptr_t offset, const char *basename, intptr_t idx)
{
    const Record *record = nullptr;
    for (auto &entry: action->entries)
    {
        if (entry.cmp != MATCH_CMP_EQ || entry.basename == nullptr ||
                strcmp(entry.basename, basename) != 0)
            continue;
        switch (entry.match)
        {
            case MATCH_TRUE: case MATCH_FALSE: case MATCH_ADDRESS:
            case MATCH_CALL: case MATCH_JUMP: case MATCH_OFFSET:
            case MATCH_OP: case MATCH_SRC: case MATCH_DST:
            case MATCH_PLUGIN: case MATCH_RANDOM: case MATCH_RETURN:
            case MATCH_SIZE:
            {
                intptr_t x = makeMatchValue(entry.match, entry.idx,
                    entry.field, I, offset,
                    (entry.match == MATCH_PLUGIN? entry.plugin->result: 0));
                auto i = entry.values->find(x);
                if (record != nullptr && i->second != record)
                    error("failed to lookup value from file \"%s.csv\"; "
                        "matching is ambigious", basename);
                record = i->second;
                break;
            }
            default:
                continue;
        }
    }
    if (record == nullptr)
        error("failed to lookup value from file \"%s.csv\"; matching is "
            "ambigious", basename);
    if (idx >= (intptr_t)record->size())
        error("failed to lookup value from file \"%s.csv\"; index %zd is "
            "out-of-range 0..%zu", basename, idx, record->size()-1);
    const char *str = record->at(idx);
    intptr_t x;
    const char *end = parseInt(str, x);
    if (end == nullptr || *end != '\0')
        error("failed to lookup value from file \"%s.csv\"; value \"%s\" is "
            "not a valid integer", basename, str);
    return x;
}

/*
 * Send instructions to load an argument into a register.
 */
static void sendLoadArgumentMetadata(FILE *out, CallInfo &info,
    const Action *action, const Argument &arg, const cs_insn *I, off_t offset,
    int argno)
{
    switch (arg.kind)
    {
        case ARGUMENT_USER:
        {
            intptr_t value = lookupValue(action, I, offset, arg.name,
                arg.value);
            sendLoadValueMetadata(out, value, argno);
            break;
        }
        case ARGUMENT_INTEGER:
            sendLoadValueMetadata(out, arg.value, argno);
            break;
        case ARGUMENT_OFFSET:
            sendLoadValueMetadata(out, offset, argno);
            break;
        case ARGUMENT_ADDR:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}", argno);
            break;
        case ARGUMENT_NEXT:
            if (action->before || action->replace)
                sendLoadTargetMetadata(out, I, info, argno);
            else
            {
                // If we reach here after the instruction, it means the branch
                // was NOT taken, so (next=.Lcontinue).
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    argno);
            }
            break;
        case ARGUMENT_BASE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":0}", argno);
            break;
        case ARGUMENT_STATIC_ADDR:
            sendLoadValueMetadata(out, (intptr_t)I->address, argno);
            break;
        case ARGUMENT_ASM_STR:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".LasmStr\"}", argno);
            break;
        case ARGUMENT_ASM_STR_LEN:
        {
            intptr_t len = strlen(I->mnemonic);
            if (I->op_str[0] != '\0')
                len += strlen(I->op_str) + 1;
            sendLoadValueMetadata(out, len, argno);
            break;
        }
        case ARGUMENT_BYTES:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lbytes\"}", argno);
            break;
        case ARGUMENT_BYTES_LEN:
            sendLoadValueMetadata(out, I->size, argno);
            break;
        case ARGUMENT_TARGET:
            sendLoadTargetMetadata(out, I, info, argno);
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Ltrampoline\"}", argno);
            break;
        case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
        case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RDI:
        case ARGUMENT_RSI: case ARGUMENT_R8: case ARGUMENT_R9:
        case ARGUMENT_R10: case ARGUMENT_R11: case ARGUMENT_R12:
        case ARGUMENT_R13: case ARGUMENT_R14: case ARGUMENT_R15:
        {
            x86_reg reg = getReg(arg.kind);
            if (info.isClobbered(getReg(argno)))
                sendMovFromStackToR64(out, info.getOffset(reg), argno);
            else
                sendMovFromR64ToR64(out, getRegIdx(reg), argno);
            break;
        }
        case ARGUMENT_RIP:
            if (action->before || action->replace)
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}",
                    argno);
            else
                sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                    argno);
            break;
        case ARGUMENT_RSP:
            sendLeaFromStackToR64(out, info.rsp_offset, argno);
            break;
        case ARGUMENT_RFLAGS:
            if (info.isSaved(X86_REG_EFLAGS))
                sendMovFromStack16ToR64(out, info.getOffset(X86_REG_EFLAGS),
                    argno);
            else
            {
                sendSaveRegToStack(out, info, X86_REG_RAX);
                fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto   %al
                fprintf(out, "%u,", 0x9f);                  // lahf
                sendMovFromRAX16ToR64(out, argno);
            }
            break;
        case ARGUMENT_RAX_PTR: case ARGUMENT_RBX_PTR: case ARGUMENT_RCX_PTR:
        case ARGUMENT_RDX_PTR: case ARGUMENT_RBP_PTR: case ARGUMENT_RDI_PTR:
        case ARGUMENT_RSI_PTR: case ARGUMENT_R8_PTR:  case ARGUMENT_R9_PTR:
        case ARGUMENT_R10_PTR: case ARGUMENT_R11_PTR: case ARGUMENT_R12_PTR:
        case ARGUMENT_R13_PTR: case ARGUMENT_R14_PTR: case ARGUMENT_R15_PTR:
        case ARGUMENT_RSP_PTR: case ARGUMENT_RFLAGS_PTR:
        {
            x86_reg reg = getReg(arg.kind);
            sendSaveRegToStack(out, info, reg);
            sendLeaFromStackToR64(out, info.getOffset(reg), argno);
            break;
        }
        case ARGUMENT_OPERAND_0: case ARGUMENT_OPERAND_1:
        case ARGUMENT_OPERAND_2: case ARGUMENT_OPERAND_3:
        case ARGUMENT_OPERAND_4: case ARGUMENT_OPERAND_5:
        case ARGUMENT_OPERAND_6: case ARGUMENT_OPERAND_7:
        case ARGUMENT_SRC_0: case ARGUMENT_SRC_1:
        case ARGUMENT_SRC_2: case ARGUMENT_SRC_3:
        case ARGUMENT_SRC_4: case ARGUMENT_SRC_5:
        case ARGUMENT_SRC_6: case ARGUMENT_SRC_7:
        case ARGUMENT_DST_0: case ARGUMENT_DST_1:
        case ARGUMENT_DST_2: case ARGUMENT_DST_3:
        case ARGUMENT_DST_4: case ARGUMENT_DST_5:
        case ARGUMENT_DST_6: case ARGUMENT_DST_7:
        {
            int idx = getOperandIdx(I, arg.kind);
            assert(idx >= 0);
            sendLoadOperandMetadata(out, I, idx, info, argno);
            break;
        }
        default:
            error("NYI argument (%d)", arg.kind);
    }
    info.clobber(getReg(argno));
    info.use(getReg(argno));
}

/*
 * Send argument data metadata.
 */
static void sendArgumentDataMetadata(FILE *out, const Argument &arg,
    const cs_insn *I, int argno)
{
    switch (arg.kind)
    {
        case ARGUMENT_ASM_STR:
            if (arg.duplicate)
                return;
            fputs("\".LasmStr\",{\"string\":", out);
            sendAsmStrData(out, I, /*newline=*/false);
            fputs("},", out);
            break;
        case ARGUMENT_BYTES:
            if (arg.duplicate)
                return;
            fputs("\".Lbytes\",", out);
            sendBytesData(out, I->bytes, I->size);
            fputc(',', out);
            break;
        case ARGUMENT_OPERAND_0: case ARGUMENT_OPERAND_1:
        case ARGUMENT_OPERAND_2: case ARGUMENT_OPERAND_3:
        case ARGUMENT_OPERAND_4: case ARGUMENT_OPERAND_5:
        case ARGUMENT_OPERAND_6: case ARGUMENT_OPERAND_7:
        case ARGUMENT_SRC_0: case ARGUMENT_SRC_1:
        case ARGUMENT_SRC_2: case ARGUMENT_SRC_3:
        case ARGUMENT_SRC_4: case ARGUMENT_SRC_5:
        case ARGUMENT_SRC_6: case ARGUMENT_SRC_7:
        case ARGUMENT_DST_0: case ARGUMENT_DST_1:
        case ARGUMENT_DST_2: case ARGUMENT_DST_3:
        case ARGUMENT_DST_4: case ARGUMENT_DST_5:
        case ARGUMENT_DST_6: case ARGUMENT_DST_7:
        {
            int idx = getOperandIdx(I, arg.kind);
            assert(idx >= 0);
            sendOperandDataMetadata(out, I, idx, argno);
            break;
        }
        default:
            break;
    }
}

/*
 * Build metadata.
 */
static Metadata *buildMetadata(const Action *action, const cs_insn *I,
    off_t offset, Metadata *metadata, char *buf, size_t size)
{
    if (action == nullptr || action->kind == ACTION_PASSTHRU ||
            action->kind == ACTION_TRAP || action->kind == ACTION_PLUGIN ||
            (action->kind == ACTION_CALL && action->args.size() == 0))
    {
        return nullptr;
    }

    FILE *out = fmemopen(buf, size, "w");
    if (out == nullptr)
        error("failed to open metadata stream for buffer of size %zu: %s",
            size, strerror(errno));
    setvbuf(out, NULL, _IONBF, 0);
    long pos = 0;

    switch (action->kind)
    {
        case ACTION_PRINT:
        {
            sendAsmStrData(out, I, /*newline=*/true);
            const char *asm_str = buildMetadataString(out, buf, &pos);
            intptr_t len = 1 + strlen(I->mnemonic) +
                (I->op_str[0] == '\0'? 0: 1 + strlen(I->op_str));
            sendIntegerData(out, 32, len);
            const char *asm_str_len = buildMetadataString(out, buf, &pos);

            metadata[0].name = "asmStr";
            metadata[0].data = asm_str;
            metadata[1].name = "asmStrLen";
            metadata[1].data = asm_str_len;
            metadata[2].name = nullptr;
            metadata[2].data = nullptr;
            
            break;
        }
        case ACTION_CALL:
        {
            if (action->args.size() == 0)
            {
                metadata[0].name = nullptr;
                metadata[0].data = nullptr;
                break;
            }

            int rmin = (action->clean? RBX_IDX: (int)action->args.size());
            
            // STEP (1): Load arguments.
            int argno = 0;
            CallInfo info(rmin);
            for (const auto &arg: action->args)
            {
                sendLoadArgumentMetadata(out, info, action, arg, I, offset,
                    argno);
                argno++;
            }
            for (int regno = info.rmin; regno < RMAX_IDX; regno++)
            {
                if (info.isClobbered(getReg(regno)))
                {
                    // Restore clobbered caller-save register:
                    sendMovFromStackToR64(out, info.getOffset(getReg(regno)),
                        regno);
                }
            }
            int i = 0;
            const char *md_load_args = buildMetadataString(out, buf, &pos);
            metadata[i].name = "loadArgs";
            metadata[i].data = md_load_args;
            i++;

            // STEP (2): Restore state.
            bool pop_rsp = false;
            for (int i = (int)info.pushed.size()-1; i >= info.rmin; i--)
            {
                x86_reg reg = info.pushed.at(i);
                if (reg == X86_REG_RSP)
                {
                    pop_rsp = true;
                    continue;               // Handled in the next step.
                }
                sendPop(out, reg);
            }
            const char *md_restore_state = buildMetadataString(out, buf, &pos);
            metadata[i].name = "restoreState";
            metadata[i].data = md_restore_state;
            i++;

            // STEP (3): Restore stack pointer.
            if (pop_rsp)
                sendPop(out, X86_REG_RSP);
            else
            {
                // lea 0x4000(%rsp),%rsp
                fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                    0x48, 0x8d, 0xa4, 0x24, 0x4000);
            }
            const char *md_restore_rsp = buildMetadataString(out, buf, &pos);
            metadata[i].name = "restoreRSP";
            metadata[i].data = md_restore_rsp;
            i++;

            // STEP (4): Place data (if necessary).
            argno = 0;
            for (const auto &arg: action->args)
            {
                sendArgumentDataMetadata(out, arg, I, argno);
                argno++;
            }
            const char *md_data = buildMetadataString(out, buf, &pos);
            metadata[i].name = "data";
            metadata[i].data = md_data;
            i++;

            metadata[i].name = nullptr;
            metadata[i].data = nullptr;
            break;
        }

        default:
            break;
    }

    fclose(out);
    return metadata;
}

