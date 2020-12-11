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
 * Prototypes.
 */
static const cs_x86_op *getOperand(const cs_insn *I, int idx, x86_op_type type,
    uint8_t access);
static intptr_t makeMatchValue(MatchKind match, int idx, MatchField field,
    const cs_insn *I, intptr_t offset, intptr_t result, bool *defined);

/*
 * Get the type of an operand.
 */
static Type getOperandType(const cs_insn *I, const cs_x86_op *op, bool ptr,
    FieldKind field)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;

    Type t = TYPE_NULL_PTR;
    if (op == nullptr)
        return t;

    switch (field)
    {
        case FIELD_DISPL:
            return (op->type ==  X86_OP_MEM? TYPE_INT32: t);
        case FIELD_BASE:
            t = (op->type == X86_OP_MEM? getRegType(op->mem.base): t);
            return (ptr && t != TYPE_NULL_PTR? t | TYPE_PTR: t);
        case FIELD_INDEX:
            t = (op->type == X86_OP_MEM? getRegType(op->mem.index): t);
            return (ptr && t != TYPE_NULL_PTR? t | TYPE_PTR: t);
        case FIELD_SCALE:
            return (op->type == X86_OP_MEM? TYPE_INT8: t);
        default:
            break;
    }

    switch (op->type)
    {
        case X86_OP_REG:
            t = getRegType(op->reg);
            break;
        case X86_OP_MEM:
            switch (op->size)
            {
                case sizeof(int8_t):
                    t = TYPE_INT8; break;
                case sizeof(int16_t):
                    t = TYPE_INT16; break;
                case sizeof(int32_t):
                    t = TYPE_INT32; break;
                case sizeof(int64_t):
                    t = TYPE_INT64; break;
                default:
                    t = (ptr? TYPE_INT8: t); break;
            }
            break;
        case X86_OP_IMM:
            switch (x86->encoding.imm_size)
            {
                case sizeof(int8_t):
                    t = TYPE_INT8; break;
                case sizeof(int16_t):
                    t = TYPE_INT16; break;
                case sizeof(int32_t):
                    t = TYPE_INT32; break;
                case sizeof(int64_t):
                    t = TYPE_INT64; break;
                default:
                    t = (ptr? TYPE_INT8: t); break;
            }
            if (ptr)
                t |= TYPE_CONST;
            break;
        default:
            return t;
    }
    if (ptr && t != TYPE_NULL_PTR)
        t |= TYPE_PTR;
    return t;
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
 * Temporarily move a register.
 * Returns scratch storage indicating where the current value is moved to:
 * (<0)=stack, (<RMAX)=register, else no need to save register.
 */
static int sendTemporaryMovReg(FILE *out, CallInfo &info, x86_reg reg,
    const x86_reg *exclude, int *slot)
{
    int regno = getRegIdx(reg);
    assert(regno >= 0);
    x86_reg rscratch = info.getScratch(exclude);
    int scratch;
    if (rscratch != X86_REG_INVALID)
    {
        // Save old value into a scratch register:
        scratch = getRegIdx(rscratch);
        sendMovFromR64ToR64(out, regno, scratch);
        info.clobber(rscratch);
    }
    else
    {
        // Save old value into the stack redzone:
        *slot = *slot - 1;
        scratch = *slot;
        sendMovFromR64ToStack(out, regno, (int32_t)sizeof(int64_t) * scratch);
    }
    return scratch;
}

/*
 * Temporarily save a register, allowing it to be used for another purpose.
 */
static int sendTemporarySaveReg(FILE *out, CallInfo &info, x86_reg reg,
    const x86_reg *exclude, int *slot)
{
    if (info.isClobbered(reg))
        return INT32_MAX;

    return sendTemporaryMovReg(out, info, reg, exclude, slot);
}

/*
 * Temporarily restore a register to its original value.
 */
static int sendTemporaryRestoreReg(FILE *out, CallInfo &info, x86_reg reg,
    const x86_reg *exclude, int *slot)
{
    if (!info.isClobbered(reg))
        return INT32_MAX;
    if (!info.isUsed(reg))
    {
        // If reg is clobbered but not used, then we simply restore it.
        sendMovFromStackToR64(out, info.getOffset(reg), getRegIdx(reg));
        info.restore(reg);
        return INT32_MAX;
    }

    int scratch = sendTemporaryMovReg(out, info, reg, exclude, slot);
    sendMovFromStackToR64(out, info.getOffset(reg), getRegIdx(reg));
    return scratch;
}

/*
 * Undo sendTemporaryMovReg().
 */
static void sendUndoTemporaryMovReg(FILE *out, x86_reg reg, int scratch)
{
    if (scratch > RMAX_IDX)
        return;     // Was not saved.
    int regno = getRegIdx(reg);
    assert(regno >= 0);
    if (scratch >= 0)
    {
        // Value saved in register:
        sendMovFromR64ToR64(out, scratch, regno);
    }
    else
    {
        // Value saved on stack:
        sendMovFromStackToR64(out, (int32_t)sizeof(int64_t) * scratch, regno);
    }
}

/*
 * Send instructions that ensure the given register is saved.
 */
static bool sendSaveRegToStack(FILE *out, CallInfo &info, x86_reg reg)
{
    if (info.isSaved(reg))
        return true;
    x86_reg rscratch = (info.isClobbered(X86_REG_RAX)? X86_REG_RAX:
        info.getScratch());
    auto result = sendPush(out, info.rsp_offset, info.before, reg, rscratch);
    if (result.first)
    {
        // Push was successful:
        info.push(reg);
        if (result.second)
            info.clobber(rscratch);
    }
    return result.first;
}

/*
 * Send a load (mov/lea) from a converted memory operand to a register.
 */
static bool sendLoadFromConvertedMemToR64(FILE *out, const cs_insn *I,
    const cs_x86_op *op, CallInfo &info, uint8_t opcode0, uint8_t opcode,
    int regno)
{
    const cs_detail *detail = I->detail;
    const cs_x86 *x86       = &detail->x86;
    assert(op->type == X86_OP_MEM);

    const uint8_t REX[] =
        {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c, 0x00,
         0x48, 0x4c, 0x4c, 0x48, 0x48, 0x4c, 0x4c, 0x4c, 0x4c, 0x48};
    uint8_t rex = REX[regno] | (x86->rex & 0x03);

    if (x86->encoding.modrm_offset == 0)
    {
        // This is an implicit memory operand without a ModR/M byte.  Such
        // cases cannot be handled yet.
        warning(CONTEXT_FORMAT "failed to load converted memory operand "
            "into register %s; implicit memory operands are not yet "
            "implemented", CONTEXT(I), getRegName(getReg(regno)));
        sendSExtFromI32ToR64(out, 0, regno);
        return false;
    }

    if ((op->mem.segment == X86_REG_FS || op->mem.segment == X86_REG_GS) &&
            opcode0 == 0x00 && opcode == /*LEA=*/0x8d)
    {
        // LEA assumes all segment registers are zero.  Since %fs/%gs may
        // be non-zero, these segment registers cannot be handled.
        warning(CONTEXT_FORMAT "failed to load converted memory operand "
            "into register %s; cannot load the effective address of a memory "
            "operand using segment register %s", CONTEXT(I),
            getRegName(getReg(regno)), getRegName(op->mem.segment));
        sendSExtFromI32ToR64(out, 0, regno);
        return false;
    }

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

    x86_reg exclude[4] = {getReg(regno)};
    int j = 1;
    if (base_reg != X86_REG_INVALID)
        exclude[j++] = getCanonicalReg(base_reg);
    exclude[j++] = getCanonicalReg(index_reg);
    exclude[j++] = X86_REG_INVALID;
    int slot = 0;
    int scratch_1 = sendTemporaryRestoreReg(out, info, base_reg, exclude,
        &slot);
    int scratch_2 = sendTemporaryRestoreReg(out, info, index_reg, exclude,
        &slot);

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
        return false;
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

    bool have_prefix = (x86->prefix[1] != 0);
    mod = (modrm >> 6) & 0x3;
    for (unsigned i = 1; i < 4; i++)
    {
        if (x86->prefix[i] == 0x0)
            continue;
        fprintf(out, "%u,", x86->prefix[i]);
    }
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

    sendUndoTemporaryMovReg(out, base_reg, scratch_1);
    sendUndoTemporaryMovReg(out, index_reg, scratch_2);

    return true;
}

/*
 * Load a register to an arg register.
 */
static void sendLoadRegToArg(FILE *out, x86_reg reg, CallInfo &info, int argno)
{
    size_t size = getRegSize(reg);
    if (info.isClobbered(reg))
    {
        switch (size)
        {
            case sizeof(int64_t):
            default:
                sendMovFromStackToR64(out, info.getOffset(reg), argno);
                break;
            case sizeof(int32_t):
                sendMovFromStack32ToR64(out, info.getOffset(reg), argno);
                break;
            case sizeof(int16_t):
                sendMovFromStack16ToR64(out, info.getOffset(reg), argno);
                break;
            case sizeof(int8_t):
                sendMovFromStack8ToR64(out,
                    info.getOffset(reg) + (getRegHigh(reg)? 1: 0), argno);
                break;
        }
    }
    else
    {
        switch (size)
        {
            case sizeof(int64_t):
            default:
                sendMovFromR64ToR64(out, getRegIdx(reg), argno);
                break;
            case sizeof(int32_t):
                sendMovFromR32ToR64(out, getRegIdx(reg), argno);
                break;
            case sizeof(int16_t):
                sendMovFromR16ToR64(out, getRegIdx(reg), argno);
                break;
            case sizeof(int8_t):
                sendMovFromR8ToR64(out, getRegIdx(reg), getRegHigh(reg),
                    argno);
                break;
        }
    }
}

/*
 * Emits instructions to load a register by value or reference.
 */
static bool sendLoadRegToArg(FILE *out, const cs_insn *I, x86_reg reg,
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
            return false;
        }

        sendLeaFromStackToR64(out,
            info.getOffset(reg) + (getRegHigh(reg)? 1: 0), argno);
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
            return false;
        }
        sendLoadRegToArg(out, reg, info, argno);
    }
    return true;
}

/*
 * Emits instructions to load an operand into the corresponding
 * regno register.  If the operand does not exist, load 0.
 */
static bool sendLoadOperandMetadata(FILE *out, const cs_insn *I,
    const cs_x86_op *op, bool ptr, FieldKind field, CallInfo &info, int argno)
{
    if (field != FIELD_NONE)
    {
        const char *name = nullptr;
        switch (field)
        {
            case FIELD_DISPL:
                name = "displacement"; break;
            case FIELD_BASE:
                name = "base"; break;
            case FIELD_INDEX:
                name = "index"; break;
            case FIELD_SCALE:
                name = "scale"; break;
            case FIELD_SIZE:
                name = "size"; break;
            default:
                name = "???"; break;
        }
        if (op->type != X86_OP_MEM)
        {
            warning(CONTEXT_FORMAT "failed to load %s into register %s; "
                "cannot load %s of non-memory operand", CONTEXT(I), name,
                getRegName(getReg(argno)), name);
            sendSExtFromI32ToR64(out, 0, argno);
            return false;
        }
        switch (field)
        {
            case FIELD_DISPL:
                sendLoadValueMetadata(out, op->mem.disp, argno);
                return true;
            case FIELD_BASE:
                if (op->mem.base == X86_REG_INVALID)
                {
                    warning(CONTEXT_FORMAT "failed to load memory operand "
                        "base into register %s; operand does not use a base "
                        "register", CONTEXT(I), getRegName(getReg(argno)));
                    sendSExtFromI32ToR64(out, 0, argno);
                    return false;
                }
                return sendLoadRegToArg(out, I, op->mem.base, ptr, info,
                    argno);
            case FIELD_INDEX:
                if (op->mem.index == X86_REG_INVALID)
                {
                    warning(CONTEXT_FORMAT "failed to load memory operand "
                        "index into register %s; operand does not use an "
                        "index register", CONTEXT(I),
                        getRegName(getReg(argno)));
                    sendSExtFromI32ToR64(out, 0, argno);
                    return false;
                }
                return sendLoadRegToArg(out, I, op->mem.index, ptr, info,
                    argno);
            case FIELD_SCALE:
                sendLoadValueMetadata(out, op->mem.scale, argno);
                return true;
            case FIELD_SIZE:
                sendLoadValueMetadata(out, op->size, argno);
                return true;
            default:
                error("unknown field (%d)", field);
        }
    }

    switch (op->type)
    {
        case X86_OP_REG:
            return sendLoadRegToArg(out, I, op->reg, ptr, info, argno);

        case X86_OP_MEM:
            if (!ptr)
            {
                switch (op->size)
                {
                    case sizeof(int64_t):
                        return sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x00, /*mov=*/0x8b, argno);
                    case sizeof(int32_t):
                        return sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x00, /*movslq=*/0x63, argno);
                    case sizeof(int16_t):
                        return sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x0f, /*movswq=*/0xbf, argno);
                    case sizeof(int8_t):
                        return sendLoadFromConvertedMemToR64(out, I, op, info,
                            0x0f, /*movsbq=*/0xbe, argno);
                    case 0:
                        sendSExtFromI32ToR64(out, 0, argno);
                        return true;
                    default:
                        warning(CONTEXT_FORMAT "failed to load memory "
                            "operand contents into register %s; operand "
                            "size (%zu) is too big", CONTEXT(I),
                            getRegName(getReg(argno)), op->size);
                        sendSExtFromI32ToR64(out, 0, argno);
                        return false;
                }
            }
            else
                return sendLoadFromConvertedMemToR64(out, I, op, info,
                    0x00, /*lea=*/0x8d, argno);

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
            return true;

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
            x86_reg exclude[] = {getReg(argno), X86_REG_INVALID};
            int slot = 0;
            int scratch = sendTemporaryRestoreReg(out, info, X86_REG_RCX,
                exclude, &slot);
            if (I->id == X86_INS_JECXZ)
                fprintf(out, "%u,", 0x67);
            fprintf(out, "%u,{\"rel8\":\".Ltaken%s\"},", 0xe3, regname);
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
            fprintf(out, "%u,{\"rel8\":\".Lnext%s\"},", 0xeb, regname);
            fprintf(out, "\".Ltaken%s\",", regname);
            sendLoadTargetMetadata(out, I, info, argno);
            fprintf(out, "\".Lnext%s\",", regname);
            sendUndoTemporaryMovReg(out, X86_REG_RCX, scratch);
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
static bool matchEval(csh handle, const MatchExpr *expr, const cs_insn *I,
    intptr_t offset, const char *basename = nullptr,
    const Record **record = nullptr);
static intptr_t lookupValue(csh handle, const Action *action,
    const cs_insn *I, intptr_t offset, const char *basename, intptr_t idx)
{
    const Record *record = nullptr;
    bool pass = matchEval(handle, action->match, I, offset, basename, &record);
    if (!pass || record == nullptr)
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
static Type sendLoadArgumentMetadata(FILE *out, CallInfo &info,
    csh handle, const Action *action, const Argument &arg, const cs_insn *I,
    off_t offset, int argno)
{
    int regno = getArgRegIdx(argno);
    if (regno < 0)
        error("failed to load argument; call instrumentation exceeds the "
            "maximum number of arguments (%d)", argno);
    sendSaveRegToStack(out, info, getReg(regno));

    Type t = TYPE_INT64;
    switch (arg.kind)
    {
        case ARGUMENT_USER:
        {
            intptr_t value = lookupValue(handle, action, I, offset, arg.name,
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
            t = TYPE_CONST_VOID_PTR;
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
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_BASE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":0}", regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_STATIC_ADDR:
            sendLoadValueMetadata(out, (intptr_t)I->address, regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_ASM:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".LasmStr\"}", regno);
            t = TYPE_CONST_CHAR_PTR;
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
            t = TYPE_CONST_INT8_PTR;
            break;
        case ARGUMENT_BYTES_SIZE:
            sendLoadValueMetadata(out, I->size, regno);
            break;
        case ARGUMENT_TARGET:
            sendLoadTargetMetadata(out, I, info, regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Ltrampoline\"}", regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_RANDOM:
            sendLoadValueMetadata(out, rand(), regno);
            break;

        case ARGUMENT_AL: case ARGUMENT_AH: case ARGUMENT_BL: case ARGUMENT_BH:
        case ARGUMENT_CL: case ARGUMENT_CH: case ARGUMENT_DL: case ARGUMENT_DH:
        case ARGUMENT_BPL: case ARGUMENT_DIL: case ARGUMENT_SIL:
        case ARGUMENT_R8B: case ARGUMENT_R9B: case ARGUMENT_R10B:
        case ARGUMENT_R11B: case ARGUMENT_R12B: case ARGUMENT_R13B:
        case ARGUMENT_R14B: case ARGUMENT_R15B:

        case ARGUMENT_AX: case ARGUMENT_BX: case ARGUMENT_CX:
        case ARGUMENT_DX: case ARGUMENT_BP: case ARGUMENT_DI:
        case ARGUMENT_SI: case ARGUMENT_R8W: case ARGUMENT_R9W:
        case ARGUMENT_R10W: case ARGUMENT_R11W: case ARGUMENT_R12W:
        case ARGUMENT_R13W: case ARGUMENT_R14W: case ARGUMENT_R15W:

        case ARGUMENT_EAX: case ARGUMENT_EBX: case ARGUMENT_ECX:
        case ARGUMENT_EDX: case ARGUMENT_EBP: case ARGUMENT_EDI:
        case ARGUMENT_ESI: case ARGUMENT_R8D: case ARGUMENT_R9D:
        case ARGUMENT_R10D: case ARGUMENT_R11D: case ARGUMENT_R12D:
        case ARGUMENT_R13D: case ARGUMENT_R14D: case ARGUMENT_R15D:

        case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
        case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RDI:
        case ARGUMENT_RSI: case ARGUMENT_R8: case ARGUMENT_R9:
        case ARGUMENT_R10: case ARGUMENT_R11: case ARGUMENT_R12:
        case ARGUMENT_R13: case ARGUMENT_R14: case ARGUMENT_R15:
        {
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            x86_reg reg = getReg(arg.kind);
            sendLoadRegToArg(out, I, reg, /*ptr=*/false, info, regno);
            switch (getRegSize(reg))
            {
                default:
                case sizeof(int64_t):
                    t = TYPE_INT64; break;
                case sizeof(int32_t):
                    t = TYPE_INT32; break;
                case sizeof(int16_t):
                    t = TYPE_INT16; break;
                case sizeof(int8_t):
                    t = TYPE_INT8; break;
            }
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
        case ARGUMENT_SPL: case ARGUMENT_SP: case ARGUMENT_ESP:
        case ARGUMENT_RSP:
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            sendLeaFromStackToR64(out, info.rsp_offset, regno);
            switch (arg.kind)
            {
                case ARGUMENT_ESP:
                    sendMovFromR32ToR64(out, regno, regno); break;
                case ARGUMENT_SP:
                    sendMovFromR16ToR64(out, regno, regno); break;
                case ARGUMENT_SPL:
                    sendMovFromR8ToR64(out, regno, false, regno); break;
                default:
                    break;
            }
            break;
        case ARGUMENT_RFLAGS:
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            else if (info.isSaved(X86_REG_EFLAGS))
                sendMovFromStack16ToR64(out, info.getOffset(X86_REG_EFLAGS),
                    regno);
            else
            {
                x86_reg exclude[] = {X86_REG_RAX, getReg(regno),
                    X86_REG_INVALID};
                int slot = 0;
                int scratch = sendTemporarySaveReg(out, info, X86_REG_RAX,
                    exclude, &slot);
                fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);// seto   %al
                fprintf(out, "%u,", 0x9f);                  // lahf
                sendMovFromRAX16ToR64(out, regno);
                sendUndoTemporaryMovReg(out, X86_REG_RAX, scratch);
            }
            t = TYPE_INT16;
            break;
        ARGUMENT_REG_PTR:
        {
            x86_reg reg = getReg(arg.kind);
            sendSaveRegToStack(out, info, reg);
            sendLeaFromStackToR64(out, info.getOffset(reg), regno);
            switch (getRegSize(reg))
            {
                case sizeof(int64_t):
                case sizeof(int32_t):       // type of &%r32 == (int64_t *)
                    t = TYPE_INT64; break;
                case sizeof(int16_t):
                    t = TYPE_INT16; break;
                default:
                    t = TYPE_INT8; break;
            }
            t |= TYPE_PTR;
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
            t = getOperandType(I, op, arg.ptr, arg.field);
            if (op == nullptr)
            {
                const char *kind = "???";
                switch (arg.kind)
                {
                    case ARGUMENT_OP:  kind = "op";  break;
                    case ARGUMENT_SRC: kind = "src"; break;
                    case ARGUMENT_DST: kind = "dst"; break;
                    case ARGUMENT_IMM: kind = "imm"; break;
                    case ARGUMENT_REG: kind = "reg"; break;
                    case ARGUMENT_MEM: kind = "mem"; break;
                    default: break;
                }
                warning(CONTEXT_FORMAT "failed to load %s[%d]; index is "
                    "out-of-range", CONTEXT(I), kind, (int)arg.value);
                sendSExtFromI32ToR64(out, 0, regno);
                break;
            }
            if (!arg.ptr && arg.field == FIELD_NONE && op != nullptr &&
                    op->type == X86_OP_MEM)
            {
                // Filter dangerous memory operand pass-by-value arguments:
                if (action->call == CALL_AFTER)
                {
                    warning(CONTEXT_FORMAT "failed to load memory "
                        "operand contents into register %s; operand may "
                        "be invalid after instruction",
                        CONTEXT(I), getRegName(getReg(regno)));
                    sendSExtFromI32ToR64(out, 0, regno);
                    t = TYPE_NULL_PTR;
                }
                else switch (I->id)
                {
                    default:
                        if (op->access != 0)
                            break;
                        // Fallthrough
                    case X86_INS_LEA: case X86_INS_NOP:
                        warning(CONTEXT_FORMAT "failed to load memory "
                            "operand contents into register %s; operand is "
                            "not accessed by the %s instruction",
                            CONTEXT(I), getRegName(getReg(regno)),
                            I->mnemonic);
                        sendSExtFromI32ToR64(out, 0, regno);
                        t = TYPE_NULL_PTR;
                        break;
                }
            }
            else if (!sendLoadOperandMetadata(out, I, op, arg.ptr, arg.field,
                    info, regno))
                t = TYPE_NULL_PTR;
            break;
        }
        default:
            error("NYI argument (%d)", arg.kind);
    }
    info.clobber(getReg(regno));
    info.use(getReg(regno));

    return t;
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
static Metadata *buildMetadata(csh handle, const Action *action,
    const cs_insn *I, off_t offset, Metadata *metadata, char *buf,
    size_t size)
{
    if (action == nullptr)
        return nullptr;
    switch (action->kind)
    {
        case ACTION_EXIT: case ACTION_PASSTHRU:
        case ACTION_PLUGIN: case ACTION_TRAP:
            return nullptr;
        default:
            break;
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
            TypeSig sig = TYPESIG_EMPTY;
            for (const auto &arg: action->args)
            {
                Type t = sendLoadArgumentMetadata(out, info, handle, action,
                    arg, I, offset, argno);
                sig = setType(sig, t, argno);
                argno++;
            }
            argno = 0;
            int32_t rsp_args_offset = 0;
            for (int argno = (int)action->args.size()-1; argno >= 0; argno--)
            {
                // Send stack arguments:
                int regno = getArgRegIdx(argno);
                if (regno != argno)
                {
                    sendPush(out, info.rsp_offset, before, getReg(regno));
                    rsp_args_offset += sizeof(int64_t);
                }
            }
            for (int regno = 0; !action->clean && regno < RMAX_IDX; regno++)
            {
                x86_reg reg = getReg(regno);
                if (!info.isCallerSave(reg) && info.isClobbered(reg))
                {
                    // Restore clobbered callee-save register:
                    int32_t reg_offset = rsp_args_offset;
                    reg_offset += info.getOffset(reg);
                    sendMovFromStackToR64(out, reg_offset, regno);
                    info.restore(reg);
                }
            }
            int i = 0;
            const char *md_load_args = buildMetadataString(out, buf, &pos);
            metadata[i].name = "loadArgs";
            metadata[i].data = md_load_args;
            i++;

            // Find & call the function.
            intptr_t addr = lookupSymbol(action->elf, action->symbol, sig);
            if (addr < 0 || addr > INT32_MAX)
            {
                lookupSymbolWarnings(action->elf, I, action->symbol, sig);
                std::string str;
                getSymbolString(action->symbol, sig, str);
                error(CONTEXT_FORMAT "failed to find a symbol matching \"%s\" "
                    "in binary \"%s\"", CONTEXT(I), str.c_str(),
                    action->elf->filename);
            }
            fprintf(out, "{\"rel32\":%d}", (int32_t)addr);
            const char *md_function = buildMetadataString(out, buf, &pos);
            metadata[i].name = "function";
            metadata[i].data = md_function;
            i++;
            info.call(conditional);

            // Restore state.
            if (rsp_args_offset != 0)
            {
                // lea rsp_args_offset(%rsp),%rsp
                fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                    0x48, 0x8d, 0xa4, 0x24, rsp_args_offset);
            }
            bool pop_rsp = false;
            x86_reg reg;
            while ((reg = info.pop()) != X86_REG_INVALID)
            {
                switch (reg)
                {
                    case X86_REG_RSP:
                        pop_rsp = true;
                        continue;           // %rsp is popped last.
                    default:
                        break;
                }
                bool preserve_rax = info.isUsed(X86_REG_RAX);
                x86_reg rscratch = (preserve_rax? info.getScratch():
                    X86_REG_INVALID);
                if (sendPop(out, preserve_rax, reg, rscratch))
                    info.clobber(rscratch);
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
            assert(false);
    }

    fclose(out);
    return metadata;
}

