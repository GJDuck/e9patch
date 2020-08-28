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
 * Convert a register to an argno.
 */
static int regToRegNo(x86_reg reg)
{
    switch (reg)
    {
        case X86_REG_DI: case X86_REG_DIL: case X86_REG_EDI: case X86_REG_RDI:
            return RDI;
        case X86_REG_SI: case X86_REG_SIL: case X86_REG_ESI: case X86_REG_RSI:
            return RSI;
        case X86_REG_DH: case X86_REG_DL:
        case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX:
            return RDX;
        case X86_REG_CH: case X86_REG_CL:
        case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX:
            return RCX;
        case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8:
            return R8;
        case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9:
            return R9;
        case X86_REG_EFLAGS:
            return RFLAGS;
        case X86_REG_AH: case X86_REG_AL:
        case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX:
            return RAX;
        case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D:
        case X86_REG_R10:
            return R10;
        case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D:
        case X86_REG_R11:
            return R11;
        case X86_REG_BH: case X86_REG_BL:
        case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX:
            return RBX;
        case X86_REG_BP: case X86_REG_BPL: case X86_REG_EBP: case X86_REG_RBP:
            return RBP;
        case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D:
        case X86_REG_R12:
            return R12;
        case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D:
        case X86_REG_R13:
            return R13;
        case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D:
        case X86_REG_R14:
            return R14;
        case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D:
        case X86_REG_R15:
            return R15;
        case X86_REG_SP: case X86_REG_SPL: case X86_REG_ESP: case X86_REG_RSP:
            return RSP;
        default:
            return INT32_MAX;
    }
}

/*
 * Convert an argno to a register name.
 */
static const char *argNoToRegName(int argno)
{
    switch (argno)
    {
        case 0:
            return "RDI";
        case 1:
            return "RSI";
        case 2:
            return "RDX";
        case 3:
            return "RCX";
        case 4:
            return "R8";
        case 5:
            return "R9";
        default:
            return "???";
    }
}

/*
 * Restore a register.
 */
static void sendRestoreReg(FILE *out, const CallInfo &info, x86_reg reg,
    int argno, int slot)
{
    int regno = regToRegNo(reg);
    if (!info.isClobbered(regno))
        return;

    sendMovFromR64ToStack(out, regno, -8 * slot);
    sendMovFromStackToR64(out, info.offset(regno), regno);
}

/*
 * Undo sendRestoreReg().
 */
static void sendUnrestoreReg(FILE *out, const CallInfo &info, x86_reg reg,
    int argno, int slot)
{
    int regno = regToRegNo(reg);
    if (!info.isClobbered(regno))
        return;

    sendMovFromStackToR64(out, -8 * slot, regno);
}

/*
 * Emits instructions to load the jump/call/return target into the
 * corresponding argno register.  Else, if I is not a jump/call/return
 * instruction, load -1.
 */
static void sendLoadTargetMetadata(FILE *out, const cs_insn *I,
    CallInfo &info, int argno)
{
    assert(argno < MAX_ARGNO);
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
        unsupported:

            // This is NOT a jump/call/return, so the target is set to (-1):
            sendSExtFromI32ToR64(out, -1, argno);
            return;
    }

    switch (op->type)
    {
        case X86_OP_REG:
        {
            int regno = regToRegNo(op->reg);
            if (info.isClobbered(regno))
                sendMovFromStackToR64(out, info.offset(regno), argno);
            else
                sendMovFromR64ToR64(out, regno, argno);
            return;
        }
        case X86_OP_MEM:
        {
            // This is an indirect jump/call.  Convert the instruction into a
            // mov instruction that loads the target in the correct register

            x86_reg base_reg = op->mem.base;
            x86_reg index_reg = op->mem.index;
            if (base_reg == X86_REG_RSP || base_reg == X86_REG_ESP ||
                index_reg == X86_REG_RSP || index_reg == X86_REG_ESP)
            {
                warning("failed to generate code for \"target\" argument for "
                    "instruction at address 0x%lx; memory operands using "
                    "%%rsp/%%esp are not yet supported", I->address);
                goto unsupported;
            }

            sendRestoreReg(out, info, base_reg, argno, 1);
            sendRestoreReg(out, info, index_reg, argno, 2);

            // mov operand,%reg:
            const uint8_t REX[MAX_ARGNO] =
                {0x48, 0x48, 0x48, 0x48, 0x4c, 0x4c};
            uint8_t rex = REX[argno] | (x86->rex & 0x03);
            fprintf(out, "%u,%u,", rex, 0x8b);

            uint8_t modrm = x86->modrm;
            const uint8_t R[MAX_ARGNO] =
                {0x38, 0x30, 0x10, 0x08, 0x00, 0x08};
            modrm = (modrm & 0xc7) | R[argno];
            fprintf(out, "%u,", modrm);

            uint8_t mod  = (modrm & 0xc0) >> 6;
            uint8_t rm   = modrm & 0x7;
            uint8_t i    = x86->encoding.modrm_offset + 1;
            uint8_t base = 0;
            if (mod != 0x3 && rm == 0x4)        // have SIB?
            {
                uint8_t sib = x86->sib;
                fprintf(out, "%u,", sib);
                base = sib & 0x7;
                i++;
            }
            if (mod == 0x1 || mod == 0x2 ||
                    (mod == 0x0 && rm == 0x4 && base == 0x5))
            {
                fprintf(out, "{\"int%d\":", (mod == 0x1? 8: 32));
                sendInteger(out, (intptr_t)x86->disp);
                fputs("},", out);
            }
            else if (mod == 0x0 && rm == 0x5)
            {
                // Special handling for %rip-relative memory operands.
                intptr_t addr = I->address + I->size + x86->disp;
                fputs("{\"rel32\":", out);
                sendInteger(out, addr);
                fputs("},", out);
            }

            sendUnrestoreReg(out, info, base_reg, argno, 1);
            sendUnrestoreReg(out, info, index_reg, argno, 2);
            return;
        }
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
    const char *regname = argNoToRegName(argno);
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
            sendRestoreReg(out, info, X86_REG_RCX, argno, 1);
            if (I->id == X86_INS_JECXZ)
                fprintf(out, "%u,", 0x67);
            fprintf(out, "%u,{\"rel8\":\".Ltaken%s\"},", 0xe3, regname);
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lcontinue\"}", argno);
            fprintf(out, "%u,{\"rel8\":\".Lnext%s\"},", 0xeb, regname);
            fprintf(out, "\".Ltaken%s\",", regname);
            sendLoadTargetMetadata(out, I, info, argno);
            fprintf(out, "\".Lnext%s\",", regname);
            sendUnrestoreReg(out, info, X86_REG_RCX, argno, 1);
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
static intptr_t makeMatchValue(MatchKind match, const cs_insn *I,
    intptr_t offset, intptr_t result);
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
            case MATCH_TRUE:
            case MATCH_FALSE:
            case MATCH_ADDRESS:
            case MATCH_CALL:
            case MATCH_JUMP:
            case MATCH_OFFSET:
            case MATCH_PLUGIN:
            case MATCH_RANDOM:
            case MATCH_RETURN:
            case MATCH_SIZE:
            {
                intptr_t x = makeMatchValue(entry.match, I, offset,
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
            const char *md_offset      = nullptr;
            const char *md_asm_str     = nullptr;
            const char *md_asm_str_len = nullptr;
            const char *md_bytes       = nullptr;
            const char *md_bytes_len   = nullptr;
            const char *md_static_addr = nullptr;
            CallInfo info(action->clean, action->args.size());
            int i = 0, argno = 0;
            for (auto &arg: action->args)
            {
                switch (arg.kind)
                {
                    case ARGUMENT_USER:
                    {
                        intptr_t value = lookupValue(action, I, offset,
                            arg.name, arg.value);
                        sendLoadValueMetadata(out, value, argno);
                        const char *md_load_value =
                            buildMetadataString(out, buf, &pos);
                        metadata[i].name = arg.name;
                        metadata[i].data = md_load_value;
                        i++;
                        break;
                    }

                    case ARGUMENT_OFFSET:
                        if (md_offset == nullptr)
                        {
                            sendIntegerData(out, 32, offset);
                            md_offset = buildMetadataString(out, buf, &pos);
                            metadata[i].name = "offset";
                            metadata[i].data = md_offset;
                            i++;
                        }
                        break;

                    case ARGUMENT_ASM_STR:
                        if (md_asm_str == nullptr)
                        {
                            sendAsmStrData(out, I);
                            md_asm_str = buildMetadataString(out, buf, &pos);
                            metadata[i].name = "asmStr";
                            metadata[i].data = md_asm_str;
                            i++;
                        }
                        break;

                    case ARGUMENT_ASM_STR_LEN:
                        if (md_asm_str_len == nullptr)
                        {
                            intptr_t len = strlen(I->mnemonic) +
                                (I->op_str[0] == '\0'? 0:
                                 1 + strlen(I->op_str));
                            sendIntegerData(out, 32, len);
                            md_asm_str_len =
                                buildMetadataString(out, buf, &pos);
                            metadata[i].name = "asmStrLen";
                            metadata[i].data = md_asm_str_len;
                            i++;
                        }
                        break;

                    case ARGUMENT_BYTES:
                        if (md_bytes == nullptr)
                        {
                            sendBytesData(out, I->bytes, I->size);
                            md_bytes = buildMetadataString(out, buf, &pos);
                            metadata[i].name = "bytes";
                            metadata[i].data = md_bytes;
                            i++;
                        }
                        break;

                    case ARGUMENT_BYTES_LEN:
                        if (md_bytes_len == nullptr)
                        {
                            sendIntegerData(out, 32, I->size);
                            md_bytes_len = buildMetadataString(out, buf, &pos);
                            metadata[i].name = "bytesLen";
                            metadata[i].data = md_bytes_len;
                            i++;
                        }
                        break;

                    case ARGUMENT_TARGET:
                    {
                        sendLoadTargetMetadata(out, I, info, argno);
                        const char *md_load_target =
                            buildMetadataString(out, buf, &pos);
                        metadata[i].name = getLoadTargetName(argno);
                        metadata[i].data = md_load_target;
                        i++;
                        break;
                    }

                    case ARGUMENT_NEXT:
                    {
                        if (!action->before)
                            break;
                        sendLoadNextMetadata(out, I, info, argno);
                        const char *md_load_next =
                            buildMetadataString(out, buf, &pos);
                        metadata[i].name = getLoadNextName(argno);
                        metadata[i].data = md_load_next;
                        i++;
                        break;
                    }

                    case ARGUMENT_STATIC_ADDR:
                        if (md_static_addr == nullptr)
                        {
                            sendIntegerData(out, 32, I->address);
                            md_static_addr = buildMetadataString(out, buf,
                                &pos);
                            metadata[i].name = "staticAddr";
                            metadata[i].data = md_static_addr;
                            i++;
                        }
                        break;

                    default:
                        break;
                }
                info.loadArg(arg.kind, argno);
                argno++;
            }

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

