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

#define CONTEXT_FORMAT      "%lx: %s%s%s: "
#define CONTEXT(I)          (I)->address,                           \
                            (I)->mnemonic,                          \
                            ((I)->op_str[0] == '\0'? "": " "),      \
                            (I)->op_str

/*
 * Prototypes.
 */
static const cs_x86_op *getOperand(const cs_insn *I, int idx, x86_op_type type,
    uint8_t access);
static intptr_t makeMatchValue(MatchKind match, int idx, Field field,
    const cs_insn *I, intptr_t offset, intptr_t result, bool *defined);

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
 * Temporarily restore a register.
 */
static void sendTemporaryRestoreReg(FILE *out, CallInfo &info, x86_reg reg,
    int slot)
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
    x86_reg reg, int slot)
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
        sendPush(out, info.rsp_offset, info.before, X86_REG_RAX);
        info.push(X86_REG_RAX);
    }
    bool result = sendPush(out, info.rsp_offset, info.before, reg);
    info.push(reg);
    return result;
}

/*
 * Send a load (mov/lea) from a converted memory operand to a register.
 */
static void sendLoadFromConvertedMemToR64(FILE *out, const cs_insn *I,
    const cs_x86_op *op, CallInfo &info, uint8_t opcode0, uint8_t opcode,
    int regno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    assert(op->type == X86_OP_MEM);

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

    sendTemporaryRestoreReg(out, info, base_reg, 1);
    sendTemporaryRestoreReg(out, info, index_reg, 2);

    intptr_t disp0 = disp;
    if (base_reg == X86_REG_RSP || base_reg == X86_REG_ESP)
        disp += info.rsp_offset;
    if (index_reg == X86_REG_RSP || index_reg == X86_REG_ESP)
        disp += info.rsp_offset;
    if (disp < INT32_MIN || disp > INT32_MAX)
    {
        // This is a corner case for nonsensical operands using %rsp
        warning(CONTEXT_FORMAT "failed to load converted memory operand "
            "into register %s; the adjusted displacement is out-of-bounds",
            CONTEXT(I), getRegName(getReg(regno)));
        sendSExtFromI32ToR64(out, 0, regno);
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
    if (opcode0 != 0)
        fprintf(out, "%u,%u,%u,%u,", rex, opcode0, opcode, modrm);
    else
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

    sendUndoTemporaryRestoreReg(out, info, base_reg, 1);
    sendUndoTemporaryRestoreReg(out, info, index_reg, 2);
}

/*
 * Emits instructions to load a register by value or reference.
 */
static void sendLoadRegToArg(FILE *out, const cs_insn *I, x86_reg reg,
    bool ptr, CallInfo &info, int argno)
{
    if (ptr)
    {
        // Pass register by pointer.
        if (!sendSaveRegToStack(out, info, reg))
        {
            warning(CONTEXT_FORMAT "failed to save register %s to stack; "
                "not yet implemented", CONTEXT(I), getRegName(reg));
            sendSExtFromI32ToR64(out, 0, argno);
            return;
        }

        sendLeaFromStackToR64(out, info.getOffset(reg), argno);
    }
    else
    {
        // Pass register by value:
        int regno = getRegIdx(reg);
        if (regno < 0)
        {
            warning(CONTEXT_FORMAT "failed to move register %s into "
                "register %s; not possible or not yet implemented",
                CONTEXT(I), getRegName(reg), getRegName(getReg(argno)));
            sendSExtFromI32ToR64(out, 0, argno);
            return;
        }
        if (info.isClobbered(reg))
            sendMovFromStackToR64(out, info.getOffset(reg), argno);
        else
            sendMovFromR64ToR64(out, regno, argno);
    }
}

/*
 * Emits instructions to load an operand into the corresponding
 * regno register.  If the operand does not exist, load 0.
 */
static void sendLoadOperandMetadata(FILE *out, const cs_insn *I,
    const cs_x86_op *op, bool ptr, CallInfo &info, int argno)
{
    switch (op->type)
    {
        case X86_OP_REG:
            sendLoadRegToArg(out, I, op->reg, ptr, info, argno);
            return;

        case X86_OP_MEM:
            if (!ptr)
            {
                switch (op->size)
                {
                    case sizeof(int64_t):
                        sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x00, /*mov=*/0x8b, argno);
                        break;
                    case sizeof(int32_t):
                        sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x00, /*movslq=*/0x63, argno);
                        break;
                    case sizeof(int16_t):
                        sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x0f, /*movswq=*/0xbf, argno);
                        break;
                    case sizeof(int8_t):
                        sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x0f, /*movsbq=*/0xbe, argno);
                        break;
                    case 0:
                        sendSExtFromI32ToR64(out, 0, argno);
                        break;
                    default:
                        warning(CONTEXT_FORMAT "failed to load memory "
                            "operand contents into register %s; operand "
                            "size (%zu) is too big", CONTEXT(I),
                            getRegName(getReg(argno)), op->size);
                        sendSExtFromI32ToR64(out, 0, argno);
                        return;
                }
            }
            else
                sendLoadFromConvertedMemToR64(out, I, op, info,
                    0x00, /*lea=*/0x8d, argno);
            return;

        case X86_OP_IMM:
            if (!ptr)
                sendLoadValueMetadata(out, op->imm, argno);
            else
            {
                std::string offset("{\"rel32\":\".Limmediate_");
                offset += std::to_string(argno);
                offset += "\"}";
                sendLeaFromPCRelToR64(out, offset.c_str(), argno);
            }
            return;

        default:
            error("unknown operand type (%d)", op->type);
    }
}

/*
 * Emits operand data.
 */
static void sendOperandDataMetadata(FILE *out, const cs_insn *I,
    const cs_x86_op *op, int argno)
{
    if (op == nullptr)
        return;

    switch (op->type)
    {
        case X86_OP_IMM:
            fprintf(out, "\".Limmediate_%d\",", argno);
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
 * instruction, load 0.
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
            sendSExtFromI32ToR64(out, 0, argno);
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
            sendLoadFromConvertedMemToR64(out, I, op, info, 0x00, /*mov=*/0x8b,
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
    const char *regname = getRegName(getReg(argno))+1;
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
            sendTemporaryRestoreReg(out, info, X86_REG_RCX, 1);
            if (I->id == X86_INS_JECXZ)
                fprintf(out, "%u,", 0x67);
            fprintf(out, "%u,{\"rel8\":\".Ltaken%s\"},", 0xe3, regname);
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
            fprintf(out, "%u,{\"rel8\":\".Lnext%s\"},", 0xeb, regname);
            fprintf(out, "\".Ltaken%s\",", regname);
            sendLoadTargetMetadata(out, I, info, argno);
            fprintf(out, "\".Lnext%s\",", regname);
            sendUndoTemporaryRestoreReg(out, info, X86_REG_RCX, 1);
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
            case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
            case MATCH_PLUGIN: case MATCH_RANDOM: case MATCH_RETURN:
            case MATCH_SIZE:
            {
                bool defined = true;
                intptr_t x = makeMatchValue(entry.match, entry.idx,
                    entry.field, I, offset,
                    (entry.match == MATCH_PLUGIN? entry.plugin->result: 0),
                    &defined);
                auto i = entry.values->find(x);
                if (!defined || i == entry.values->end())
                    continue;
                if (record != nullptr && i->second != record)
                    error("failed to lookup value from file \"%s.csv\"; "
                        "matching is ambiguous", basename);
                record = i->second;
                break;
            }
            default:
                continue;
        }
    }
    if (record == nullptr)
        error("failed to lookup value from file \"%s.csv\"; matching is "
            "ambiguous", basename);
    if (idx >= (intptr_t)record->size())
        error("failed to lookup value from file \"%s.csv\"; index %zd is "
            "out-of-range 0..%zu", basename, idx, record->size()-1);
    const char *str = record->at(idx);
    intptr_t x = nameToInt(basename, str);
    return x;
}

/*
 * Send instructions to load an argument into a register.
 */
static void sendLoadArgumentMetadata(FILE *out, CallInfo &info,
    const Action *action, const Argument &arg, const cs_insn *I, off_t offset,
    int argno)
{
    int regno = getArgRegIdx(argno);
    if (regno < 0)
        error("failed to load argument; call instrumentation exceeds the "
            "maximum number of arguments (%d)", argno);
    sendSaveRegToStack(out, info, getReg(regno));

    switch (arg.kind)
    {
        case ARGUMENT_USER:
        {
            intptr_t value = lookupValue(action, I, offset, arg.name,
                arg.value);
            sendLoadValueMetadata(out, value, regno);
            break;
        }
        case ARGUMENT_INTEGER:
            sendLoadValueMetadata(out, arg.value, regno);
            break;
        case ARGUMENT_OFFSET:
            sendLoadValueMetadata(out, offset, regno);
            break;
        case ARGUMENT_ADDR:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}", regno);
            break;
        case ARGUMENT_NEXT:
            switch (action->call)
            {
                case CALL_BEFORE: case CALL_REPLACE: case CALL_CONDITIONAL:
                    sendLoadNextMetadata(out, I, info, regno);
                    break;
                case CALL_AFTER:
                    // If we reach here after the instruction, it means the
                    // branch was NOT taken, so (next=.Lcontinue).
                    sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                        regno);
                    break;
            }
            break;
        case ARGUMENT_BASE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":0}", regno);
            break;
        case ARGUMENT_STATIC_ADDR:
            sendLoadValueMetadata(out, (intptr_t)I->address, regno);
            break;
        case ARGUMENT_ASM:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".LasmStr\"}", regno);
            break;
        case ARGUMENT_ASM_SIZE: case ARGUMENT_ASM_LEN:
        {
            intptr_t len = strlen(I->mnemonic);
            if (I->op_str[0] != '\0')
                len += strlen(I->op_str) + 1;
            sendLoadValueMetadata(out,
                (arg.kind == ARGUMENT_ASM_SIZE? len+1: len), regno);
            break;
        }
        case ARGUMENT_BYTES:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lbytes\"}", regno);
            break;
        case ARGUMENT_BYTES_SIZE:
            sendLoadValueMetadata(out, I->size, regno);
            break;
        case ARGUMENT_TARGET:
            sendLoadTargetMetadata(out, I, info, regno);
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Ltrampoline\"}", regno);
            break;
        case ARGUMENT_RANDOM:
            sendLoadValueMetadata(out, rand(), regno);
            break;
        case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
        case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RDI:
        case ARGUMENT_RSI: case ARGUMENT_R8: case ARGUMENT_R9:
        case ARGUMENT_R10: case ARGUMENT_R11: case ARGUMENT_R12:
        case ARGUMENT_R13: case ARGUMENT_R14: case ARGUMENT_R15:
        {
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            x86_reg reg = getReg(arg.kind);
            if (info.isClobbered(reg))
                sendMovFromStackToR64(out, info.getOffset(reg), regno);
            else
                sendMovFromR64ToR64(out, getRegIdx(reg), regno);
            break;
        }
        case ARGUMENT_RIP:
            switch (action->call)
            {
                case CALL_BEFORE: case CALL_REPLACE: case CALL_CONDITIONAL:
                    sendLeaFromPCRelToR64(out, "{\"rel32\":\".Linstruction\"}",
                        regno);
                    break;
                case CALL_AFTER:
                    sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}",
                        regno);
                    break;
            }
            break;
        case ARGUMENT_RSP:
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            sendLeaFromStackToR64(out, info.rsp_offset, regno);
            break;
        case ARGUMENT_RFLAGS:
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            else if (info.isSaved(X86_REG_EFLAGS))
                sendMovFromStack16ToR64(out, info.getOffset(X86_REG_EFLAGS),
                    regno);
            else
            {
                sendSaveRegToStack(out, info, X86_REG_RAX);
                fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto   %al
                fprintf(out, "%u,", 0x9f);                  // lahf
                info.clobber(X86_REG_RAX);
                sendMovFromRAX16ToR64(out, regno);
            }
            break;
        ARGUMENT_REG_PTR:
        {
            x86_reg reg = getReg(arg.kind);
            sendSaveRegToStack(out, info, reg);
            sendLeaFromStackToR64(out, info.getOffset(reg), regno);
            break;
        }
        case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
        case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
        {
            uint8_t access = (arg.kind == ARGUMENT_SRC? CS_AC_READ:
                             (arg.kind == ARGUMENT_DST? CS_AC_WRITE:
                              CS_AC_READ | CS_AC_WRITE));
            x86_op_type type = (arg.kind == ARGUMENT_IMM? X86_OP_IMM:
                               (arg.kind == ARGUMENT_REG? X86_OP_REG:
                               (arg.kind == ARGUMENT_MEM? X86_OP_MEM:
                                X86_OP_INVALID)));
            const cs_x86_op *op = getOperand(I, (int)arg.value, type, access);
            if (op == nullptr)
            {
                const char *kind = "";
                switch (arg.kind)
                {
                    case ARGUMENT_SRC: kind = "src "; break;
                    case ARGUMENT_DST: kind = "dst "; break;
                    case ARGUMENT_IMM: kind = "imm "; break;
                    case ARGUMENT_REG: kind = "reg "; break;
                    case ARGUMENT_MEM: kind = "mem "; break;
                    default: break;
                }
                warning(CONTEXT_FORMAT "failed to load %soperand; index %d is "
                    "out-of-range", CONTEXT(I), kind, (int)arg.value);
                sendSExtFromI32ToR64(out, 0, regno);
                break;
            }
            sendLoadOperandMetadata(out, I, op, arg.ptr, info, regno);
            break;
        }
        default:
            error("NYI argument (%d)", arg.kind);
    }
    info.clobber(getReg(regno));
    info.use(getReg(regno));
}

/*
 * Send argument data metadata.
 */
static void sendArgumentDataMetadata(FILE *out, const Argument &arg,
    const cs_insn *I, int argno)
{
    switch (arg.kind)
    {
        case ARGUMENT_ASM:
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
        case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
        case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
        {
            if (!arg.ptr)
                return;
            uint8_t access = (arg.kind == ARGUMENT_SRC? CS_AC_READ:
                             (arg.kind == ARGUMENT_DST? CS_AC_WRITE:
                              CS_AC_READ | CS_AC_WRITE));
            x86_op_type type = (arg.kind == ARGUMENT_IMM? X86_OP_IMM:
                               (arg.kind == ARGUMENT_REG? X86_OP_REG:
                               (arg.kind == ARGUMENT_MEM? X86_OP_MEM:
                                X86_OP_INVALID)));
            const cs_x86_op *op = getOperand(I, (int)arg.value, type, access);
            sendOperandDataMetadata(out, I, op, getArgRegIdx(argno));
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
            action->kind == ACTION_TRAP || action->kind == ACTION_PLUGIN)
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
            // Load arguments.
            int argno = 0;
            bool before = (action->call != CALL_AFTER);
            bool conditional = (action->call == CALL_CONDITIONAL);
            CallInfo info(action->clean, conditional, action->args.size(),
                before);
            for (const auto &arg: action->args)
            {
                sendLoadArgumentMetadata(out, info, action, arg, I, offset,
                    argno);
                argno++;
            }
            argno = 0;
            int32_t rsp_args_offset = 0;
            for (int argno = 0; argno < (int)action->args.size(); argno++)
            {
                // Send stack arguments:
                int regno = getArgRegIdx(argno);
                if (regno != argno)
                {
                    sendPush(out, info.rsp_offset, before, getReg(regno));
                    rsp_args_offset += sizeof(int64_t);
                }
            }
            for (int regno = 0; regno < RMAX_IDX; regno++)
            {
                x86_reg reg = getReg(regno);
                if (!info.isCallerSave(reg) && info.isClobbered(reg))
                {
                    // Restore clobbered callee-save register:
                    int32_t reg_offset = rsp_args_offset;
                    reg_offset += info.getOffset(reg);
                    sendMovFromStackToR64(out, reg_offset, regno);
                }
            }
            int i = 0;
            const char *md_load_args = buildMetadataString(out, buf, &pos);
            metadata[i].name = "loadArgs";
            metadata[i].data = md_load_args;
            i++;

            // Restore state.
            if (rsp_args_offset != 0)
            {
                // lea rsp_args_offset(%rsp),%rsp
                fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                    0x48, 0x8d, 0xa4, 0x24, rsp_args_offset);
            }
            bool pop_rsp = false;
            for (int i = (int)info.pushed.size()-1; i >= 0; i--)
            {
                x86_reg reg = info.pushed.at(i);
                if (info.isCallerSave(reg))
                {
                    // The remaining registers are caller-save, so break:
                    break;
                }
                switch (reg)
                {
                    case X86_REG_RSP:
                        pop_rsp = true;
                        continue;           // %rsp is always popped last.
                    default:
                        break;
                }
                bool preserve_rax = (conditional || !action->clean);
                sendPop(out, preserve_rax, reg);
            }
            const char *md_restore_state = buildMetadataString(out, buf, &pos);
            metadata[i].name = "restoreState";
            metadata[i].data = md_restore_state;
            i++;

            // Restore %rsp.
            if (pop_rsp)
                sendPop(out, false, X86_REG_RSP);
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

            // Place data (if necessary).
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

