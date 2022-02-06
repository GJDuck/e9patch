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

#include <sys/mman.h>

#include "e9action.h"
#include "e9csv.h"
#include "e9codegen.h"
#include "e9elf.h"
#include "e9metadata.h"
#include "e9misc.h"
#include "e9tool.h"
#include "e9x86_64.h"

using namespace e9tool;

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
 * Get the type of an operand.
 */
static Type getOperandType(const InstrInfo *I, const OpInfo *op, bool ptr,
    FieldKind field)
{
    Type t = TYPE_NULL_PTR;
    if (op == nullptr)
        return t;

    switch (field)
    {
        case FIELD_ACCESS: case FIELD_TYPE:
            return TYPE_INT8;
        case FIELD_SIZE:
            return TYPE_INT64;
        case FIELD_DISPL:
            return (op->type == OPTYPE_MEM? TYPE_INT32: t);
        case FIELD_BASE:
            t = (op->type == OPTYPE_MEM? getRegType(op->mem.base): t);
            return (ptr && t != TYPE_NULL_PTR? t | TYPE_PTR: t);
        case FIELD_INDEX:
            t = (op->type == OPTYPE_MEM? getRegType(op->mem.index): t);
            return (ptr && t != TYPE_NULL_PTR? t | TYPE_PTR: t);
        case FIELD_SCALE:
            return (op->type == OPTYPE_MEM? TYPE_INT8: t);
        case FIELD_NONE:
            break;
        default:
            error("unknown field (%d)", field);
    }

    switch (op->type)
    {
        case OPTYPE_REG:
            t = getRegType(op->reg);
            if (ptr && t == TYPE_INT32)
                t = TYPE_INT64;
            break;
        case OPTYPE_MEM:
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
        case OPTYPE_IMM:
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
static void sendLoadValueMetadata(FILE *out, intptr_t value, int regno)
{
    if (value >= INT32_MIN && value <= INT32_MAX)
        sendSExtFromI32ToR64(out, value, regno);
    else if (value >= 0 && value <= UINT32_MAX)
        sendZExtFromI32ToR64(out, value, regno);
    else
        sendMovFromI64ToR64(out, value, regno);
}

/*
 * Emits an instructio to load a pointer into the corresponding argno
 * register.
 */
static void sendLoadPointerMetadata(FILE *out, CallInfo &info,
    bool _static, intptr_t static_ptr, const char *dynamic_ptr, int regno)
{
    if (_static || !info.pic)
        sendLoadValueMetadata(out, static_ptr, regno);
    else
        sendLeaFromPCRelToR64(out, dynamic_ptr, regno);
}
static void sendLoadPointerMetadata(FILE *out, CallInfo &info, bool _static,
    intptr_t ptr, int regno)
{
    if (_static || !info.pic)
        sendLoadValueMetadata(out, ptr, regno);
    else
        sendLeaFromPCRelToR64(out, ptr, regno);
}

/*
 * Temporarily move a register.
 * Returns scratch storage indicating where the current value is moved to:
 * (<0)=stack, (<RMAX)=register, else no need to save register.
 */
static int sendTemporaryMovReg(FILE *out, CallInfo &info, Register reg,
    const Register *exclude, int *slot)
{
    int regno = getRegIdx(reg);
    assert(regno >= 0);
    Register rscratch = info.getScratch(exclude);
    int scratch;
    if (rscratch != REGISTER_INVALID)
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
static int sendTemporarySaveReg(FILE *out, CallInfo &info, Register reg,
    const Register *exclude, int *slot)
{
    if (info.isClobbered(reg))
        return INT32_MAX;
    return sendTemporaryMovReg(out, info, reg, exclude, slot);
}

/*
 * Temporarily restore a register to its original value.
 */
static int sendTemporaryRestoreReg(FILE *out, CallInfo &info, Register reg,
    const Register *exclude, int *slot)
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
static void sendUndoTemporaryMovReg(FILE *out, Register reg, int scratch)
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
 * Given some sratch space, return the corresponding register.
 */
static Register getScratchRegister(int slot)
{
    return (slot < 0 || slot > RMAX_IDX? REGISTER_INVALID: getReg(slot));
}

/*
 * Send instructions that ensure the given register is saved.
 */
static bool sendSaveRegToStack(FILE *out, CallInfo &info, Register reg)
{
    if (info.isSaved(reg))
        return true;
    Register rscratch = (info.isClobbered(REGISTER_RAX)? REGISTER_RAX:
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
 * Send a load (mov/lea) from a memory operand to a register.
 */
static bool sendLoadFromMemOpToR64(FILE *out, const InstrInfo *I,
    CallInfo &info, uint8_t size, Register seg_reg, int32_t disp,
    Register base_reg, Register index_reg, uint8_t scale, bool lea, int regno,
    bool asis = false)
{
    if (lea && (seg_reg == REGISTER_FS || seg_reg == REGISTER_GS))
    {
        // LEA assumes all segment registers are zero.  Since %fs/%gs may
        // be non-zero, these segment registers cannot be handled.
        warning(CONTEXT_FORMAT "failed to load converted memory operand "
            "into register %s; cannot load the effective address of a memory "
            "operand using segment register %s", CONTEXT(I),
            getRegName(getReg(regno)), getRegName(seg_reg));
        sendSExtFromI32ToR64(out, 0, regno);
        return false;
    }

    uint8_t seg_prefix = 0x00;
    switch (seg_reg)
    {
        case REGISTER_FS:
            seg_prefix = 0x64; break;
        case REGISTER_GS:
            seg_prefix = 0x65; break;
        default:
            break;
    }

    uint8_t size_prefix = 0x00;
    switch (base_reg)
    {
        case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
        case REGISTER_RBX: case REGISTER_RSP: case REGISTER_RBP:
        case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
        case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
        case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
        case REGISTER_R15: case REGISTER_RIP: case REGISTER_NONE:
            break;
        case REGISTER_EAX: case REGISTER_ECX: case REGISTER_EDX:
        case REGISTER_EBX: case REGISTER_ESP: case REGISTER_EBP:
        case REGISTER_ESI: case REGISTER_EDI: case REGISTER_R8D:
        case REGISTER_R9D: case REGISTER_R10D: case REGISTER_R11D:
        case REGISTER_R12D: case REGISTER_R13D: case REGISTER_R14D:
        case REGISTER_R15D: case REGISTER_EIP:
            size_prefix = 0x67; break;
        default:
            warning(CONTEXT_FORMAT "failed to load converted memory operand "
                "into register %s; memory operand base register %s is not "
                "supported", CONTEXT(I), getRegName(getReg(regno)),
                getRegName(base_reg));
            sendSExtFromI32ToR64(out, 0, regno);
            return false;
    }
    switch (index_reg)
    {
        case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
        case REGISTER_RBX: case REGISTER_RSP: case REGISTER_RBP:
        case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
        case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
        case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
        case REGISTER_R15: case REGISTER_NONE:
            break;
        case REGISTER_EAX: case REGISTER_ECX: case REGISTER_EDX:
        case REGISTER_EBX: case REGISTER_ESP: case REGISTER_EBP:
        case REGISTER_ESI: case REGISTER_EDI: case REGISTER_R8D:
        case REGISTER_R9D: case REGISTER_R10D: case REGISTER_R11D:
        case REGISTER_R12D: case REGISTER_R13D: case REGISTER_R14D:
        case REGISTER_R15D:
            size_prefix = 0x67; break;
        default:
            // This can be triggered by VSIB for scatter/gather
            warning(CONTEXT_FORMAT "failed to load converted memory operand "
                "into register %s; memory operand index register %s is not "
                "supported", CONTEXT(I), getRegName(getReg(regno)),
                getRegName(index_reg));
            sendSExtFromI32ToR64(out, 0, regno);
            return false;
    }

    const uint8_t B[] =
        {0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
         0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00};
    uint8_t b = (base_reg == REGISTER_NONE || base_reg == REGISTER_RIP ||
                 base_reg == REGISTER_EIP? 0x00: B[getRegIdx(base_reg)]);
    
    const uint8_t X[] =
        {0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00,
         0x00, 0x02, 0x02, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00};
    uint8_t x = (index_reg == REGISTER_NONE? 0x00: X[getRegIdx(index_reg)]);
    
    const uint8_t R[] =
        {0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x00,
         0x00, 0x04, 0x04, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x00};
    uint8_t r = R[regno];

    const uint8_t REG[] =
        {0x07, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00,
         0x00, 0x02, 0x03, 0x03, 0x05, 0x04, 0x05, 0x06, 0x07, 0x04};

    uint8_t rex       = 0x48 | r | x | b;
    uint8_t mod       = 0x00;
    uint8_t rm        = 0x00;
    uint8_t reg       = REG[regno];
    uint8_t disp_size = 0;
    uint8_t sib       = 0x00;
    bool have_sib     = false;
    bool have_rel32   = false;
    if (base_reg == REGISTER_RSP || base_reg == REGISTER_ESP)
        disp += info.rsp_offset;
    if (base_reg == REGISTER_RIP || base_reg == REGISTER_EIP)
    {
        mod         = 0x00;
        rm          = 0x05;
        disp       += I->address + I->size;
        disp_size   = sizeof(int32_t);
        have_rel32  = true;
    }
    else
    {
        if (index_reg != REGISTER_NONE ||
                (base_reg == REGISTER_RSP || base_reg == REGISTER_ESP) ||
                (base_reg == REGISTER_R12 || base_reg == REGISTER_R12D) ||
                (base_reg == REGISTER_NONE))
        {
            // Need SIB:
            assert(index_reg != REGISTER_RSP && index_reg != REGISTER_ESP);
            uint8_t ss = 0x00;
            switch (scale)
            {
                case 2:
                    ss = 0x01;
                    break;
                case 4:
                    ss = 0x02;
                    break;
                case 8:
                    ss = 0x03;
                    break;
            }
            uint8_t base = (base_reg == REGISTER_NONE? 0x05:
                REG[getRegIdx(base_reg)]);
            uint8_t index = (index_reg == REGISTER_NONE? 0x04:
                REG[getRegIdx(index_reg)]);
            sib = (ss << 6) | (index << 3) | base;
            rm  = 0x04;
            have_sib = true;
        }
        else
            rm = REG[getRegIdx(base_reg)];

        if (base_reg == REGISTER_NONE)
        {
            disp_size = sizeof(int32_t);
            mod = 0x00;
        }
        else if (disp == 0x0 &&
                base_reg != REGISTER_RBP && base_reg != REGISTER_EBP &&
                base_reg != REGISTER_R13 && base_reg != REGISTER_R13D)
        {
            disp_size = 0;
            mod = 0x00;
        }
        else if (disp >= INT8_MIN && disp <= INT8_MAX)
        {
            disp_size = sizeof(int8_t);
            mod = 0x01;
        }
        else
        {
            disp_size = sizeof(int32_t);
            mod = 0x02;
        }
    }
    if (disp < INT32_MIN || disp > INT32_MAX)
    {
        warning(CONTEXT_FORMAT "failed to load converted memory operand "
            "into register %s; the adjusted displacement is out-of-bounds",
            CONTEXT(I), getRegName(getReg(regno)));
        sendSExtFromI32ToR64(out, 0, regno);
        return false;
    }

    uint8_t modrm = (mod << 6) | (reg << 3) | rm;

    int slot = 0, scratch_1 = INT32_MAX, scratch_2 = INT32_MAX;
    if (!asis)
    {
        Register exclude[5] = {getReg(regno)};
        int j = 1;
        if (base_reg != REGISTER_NONE)
            exclude[j++] = getCanonicalReg(base_reg);
        exclude[j++] = getCanonicalReg(index_reg);
        exclude[j] = REGISTER_INVALID;
        scratch_1 = sendTemporaryRestoreReg(out, info, base_reg, exclude,
            &slot);
        exclude[j++] = getScratchRegister(scratch_1);
        exclude[j] = REGISTER_INVALID;
        if (index_reg != base_reg)
            scratch_2 = sendTemporaryRestoreReg(out, info, index_reg, exclude,
                &slot);
    }

    if (seg_prefix != 0)
        fprintf(out, "%u,", seg_prefix);
    if (size_prefix != 0)
        fprintf(out, "%u,", size_prefix);
    fprintf(out, "%u,", rex);
    if (lea)
        fprintf(out, "%u,", /*lea=*/0x8d);
    else switch (size)
    {
        case sizeof(int64_t):
            fprintf(out, "%u,", /*mov=*/0x8b); break;
        case sizeof(int32_t):
            fprintf(out, "%u,", /*movslq=*/0x63); break;
        case sizeof(int16_t):
            fprintf(out, "%u,%u,", 0x0f, /*movswq=*/0xbf); break;
        case sizeof(int8_t):
            fprintf(out, "%u,%u,", 0x0f, /*movsbq=*/0xbe); break;
        default:
            warning(CONTEXT_FORMAT "failed to load memory "
                "operand contents into register %s; operand "
                "size (%zu) is too big", CONTEXT(I),
                getRegName(getReg(regno)), size);
            sendSExtFromI32ToR64(out, 0, regno);
            return false;
    }
    fprintf(out, "%u,", modrm);
    if (have_sib)
        fprintf(out, "%u,", sib);
    if (have_rel32)
        fprintf(out, "{\"rel32\":%d},", (int32_t)disp);
    else switch (disp_size)
    {
        case sizeof(int8_t):
            fprintf(out, "{\"int8\":%d},", (int32_t)disp);
            break;
        case sizeof(int32_t):
            fprintf(out, "{\"int32\":%d},", (int32_t)disp);
            break;
    }

    if (!asis)
    {
        sendUndoTemporaryMovReg(out, base_reg, scratch_1);
        sendUndoTemporaryMovReg(out, index_reg, scratch_2);
    }
    return true;
}

/*
 * Load a register to an arg register.
 */
static void sendLoadRegToArg(FILE *out, Register reg, CallInfo &info, int regno)
{
    size_t size = getRegSize(reg);
    if (info.isClobbered(reg))
    {
        switch (size)
        {
            case sizeof(int64_t):
            default:
                sendMovFromStackToR64(out, info.getOffset(reg), regno);
                break;
            case sizeof(int32_t):
                sendMovFromStack32ToR64(out, info.getOffset(reg), regno);
                break;
            case sizeof(int16_t):
                sendMovFromStack16ToR64(out, info.getOffset(reg), regno);
                break;
            case sizeof(int8_t):
                sendMovFromStack8ToR64(out,
                    info.getOffset(reg) + (isHighReg(reg)? 1: 0), regno);
                break;
        }
    }
    else
    {
        switch (size)
        {
            case sizeof(int64_t):
            default:
                sendMovFromR64ToR64(out, getRegIdx(reg), regno);
                break;
            case sizeof(int32_t):
                sendMovFromR32ToR64(out, getRegIdx(reg), regno);
                break;
            case sizeof(int16_t):
                sendMovFromR16ToR64(out, getRegIdx(reg), regno);
                break;
            case sizeof(int8_t):
                sendMovFromR8ToR64(out, getRegIdx(reg), isHighReg(reg),
                    regno);
                break;
        }
    }
}

/*
 * Emits instructions to load a register by value or reference.
 */
static bool sendLoadRegToArg(FILE *out, const InstrInfo *I, Register reg,
    bool ptr, CallInfo &info, int regno)
{
    if (ptr)
    {
        // Pass register by pointer.
        if (!sendSaveRegToStack(out, info, reg))
        {
            warning(CONTEXT_FORMAT "failed to save register %s to stack; "
                "not yet implemented", CONTEXT(I), getRegName(reg));
            sendSExtFromI32ToR64(out, 0, regno);
            return false;
        }

        sendLeaFromStackToR64(out,
            info.getOffset(reg) + (isHighReg(reg)? 1: 0), regno);
    }
    else
    {
        // Pass register by value:
        if (getRegIdx(reg) < 0)
        {
            // We handle %rip specially:
            if (reg != REGISTER_RIP)
            {
                warning(CONTEXT_FORMAT "failed to move register %s into "
                    "register %s; not possible or not yet implemented",
                    CONTEXT(I), getRegName(reg), getRegName(getReg(regno)));
                sendSExtFromI32ToR64(out, 0, regno);
                return false;
            }
            else if (info.before)
                sendLeaFromPCRelToR64(out,
                    "{\"rel32\":\".Linstr\"}", regno);
            else
                sendLeaFromPCRelToR64(out,
                    "{\"rel32\":\".Lbreak\"}", regno);
            return true;
        }
        sendLoadRegToArg(out, reg, info, regno);
    }
    return true;
}

/*
 * Emits instructions to load an operand into the corresponding
 * regno register.  If the operand does not exist, load 0.
 */
static bool sendLoadOperandMetadata(FILE *out, const char *name,
    const InstrInfo *I, const OpInfo *op, bool ptr, FieldKind field,
    CallInfo &info, int regno)
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
            case FIELD_TYPE:
                name = "type"; break;
            case FIELD_ACCESS:
                name = "access"; break;
            default:
                name = "???"; break;
        }
        switch (field)
        {
            case FIELD_DISPL: case FIELD_BASE: case FIELD_INDEX:
            case FIELD_SCALE:
                if (op->type != OPTYPE_MEM)
                {
                    warning(CONTEXT_FORMAT "failed to load %s into register "
                        "%s; cannot load %s of non-memory operand",
                        CONTEXT(I), name, getRegName(getReg(regno)), name);
                    sendSExtFromI32ToR64(out, 0, regno);
                    return false;
                }
                break;
            default:
                break;
        }
        switch (field)
        {
            case FIELD_DISPL:
                sendLoadValueMetadata(out, op->mem.disp, regno);
                return true;
            case FIELD_BASE:
                if (op->mem.base == REGISTER_NONE)
                {
                    warning(CONTEXT_FORMAT "failed to load memory operand "
                        "base into register %s; operand does not use a base "
                        "register", CONTEXT(I), getRegName(getReg(regno)));
                    sendSExtFromI32ToR64(out, 0, regno);
                    return false;
                }
                return sendLoadRegToArg(out, I, op->mem.base, ptr, info,
                    regno);
            case FIELD_INDEX:
                if (op->mem.index == REGISTER_NONE)
                {
                    warning(CONTEXT_FORMAT "failed to load memory operand "
                        "index into register %s; operand does not use an "
                        "index register", CONTEXT(I),
                        getRegName(getReg(regno)));
                    sendSExtFromI32ToR64(out, 0, regno);
                    return false;
                }
                return sendLoadRegToArg(out, I, op->mem.index, ptr, info,
                    regno);
            case FIELD_SCALE:
                sendLoadValueMetadata(out, op->mem.scale, regno);
                return true;
            case FIELD_SIZE:
                sendLoadValueMetadata(out, op->size, regno);
                return true;
            case FIELD_TYPE:
                switch (op->type)
                {
                    case OPTYPE_IMM:
                        sendLoadValueMetadata(out, 0x1, regno); break;
                    case OPTYPE_REG:
                        sendLoadValueMetadata(out, 0x2, regno); break;
                    case OPTYPE_MEM:
                        sendLoadValueMetadata(out, 0x3, regno); break;
                    default:
                        warning(CONTEXT_FORMAT "failed to load memory operand "
                            "type into register %s; unknown operand type",
                            getRegName(getReg(regno)));
                        sendSExtFromI32ToR64(out, 0, regno);
                        return false;
                }
                return true;
            case FIELD_ACCESS:
            {
                if (op->type == OPTYPE_IMM)
                {
                    sendLoadValueMetadata(out, PROT_READ, regno);
                    return true;
                }
                Access access = op->access;
                access |= 0x80;     // Ensure non-zero
                sendLoadValueMetadata(out, access, regno);
                return true;
            }
            default:
                error("unknown field (%d)", field);
        }
    }

    switch (op->type)
    {
        case OPTYPE_REG:
            return sendLoadRegToArg(out, I, op->reg, ptr, info, regno);

        case OPTYPE_MEM:
            return sendLoadFromMemOpToR64(out, I, info, op->size,
                op->mem.seg, op->mem.disp, op->mem.base, op->mem.index,
                op->mem.scale, ptr, regno);

        case OPTYPE_IMM:
            if (!ptr)
                sendLoadValueMetadata(out, op->imm, regno);
            else
            {
                std::string offset("{\"rel32\":\".Limm");
                offset += std::to_string(regno);
                offset += '@';
                offset += name;
                offset += "\"}";
                sendLeaFromPCRelToR64(out, offset.c_str(), regno);
            }
            return true;

        default:
            error("unknown operand type (%d)", op->type);
    }
}

/*
 * Emits operand data.
 */
static void sendOperandDataMetadata(FILE *out, const char *name,
    const InstrInfo *I, const OpInfo *op, int regno)
{
    if (op == nullptr)
        return;

    switch (op->type)
    {
        case OPTYPE_IMM:
            fprintf(out, "\".Limm%d@%s\",", regno, name);
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
 * Emits instructions to translate to/from static and dynamic addresses.
 */
static void sendTranslateAddress(FILE *out, const InstrInfo *I, CallInfo &info,
    bool neg, int regno)
{
    Register exclude[] = {getReg(regno), REGISTER_INVALID};
    Register rscratch = info.getScratch(exclude);
    bool save_rax = false;
    if (rscratch == REGISTER_INVALID)
    {
        rscratch = REGISTER_RAX;
        save_rax = true;
        fprintf(out, "%u,", 0x50);      // push %rax
    }
    int regno_1 = getRegIdx(rscratch);
    sendLeaFromPCRelToR64(out, "{\"rel32\":0}", regno_1);

    int32_t disp = 0x0;
    if (neg)
    {
        // The not+lea implement %arg -= %base without affecting %rflags:
        // not %reg
        const uint8_t REX[] =
            {0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x00,
             0x48, 0x49, 0x49, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x48};
        const uint8_t MODRM[] =
            {0xd7, 0xd6, 0xd2, 0xd1, 0xd0, 0xd1, 0x00,
             0xd0, 0xd2, 0xd3, 0xd3, 0xd5, 0xd4, 0xd5, 0xd6, 0xd7, 0xd4};
        fprintf(out, "%u,%u,%u,", REX[regno_1], 0xf7, MODRM[regno_1]);
        disp = 0x1;
    }

    // lea 0x1(%arg,%reg,1),%arg
    sendLoadFromMemOpToR64(out, I, info, /*size=*/8, /*seg=*/REGISTER_NONE,
        disp, /*base=*/getReg(regno), /*index=*/rscratch,
        /*scale=*/1, /*lea=*/true, regno, /*asis=*/true);

    if (save_rax)
        fprintf(out, "%u,", 0x58);      // pop %rax
    else
        info.clobber(rscratch);
}
static void sendTranslateToStaticAddress(FILE *out, const InstrInfo *I,
    CallInfo &info, bool _static, int regno)
{
    if (!_static || !info.pic)
        return;
    sendTranslateAddress(out, I, info, /*neg=*/true, regno);
}
static void sendTranslateToDynamicAddress(FILE *out, const InstrInfo *I,
    CallInfo &info, bool _static, int regno)
{
    if (_static || !info.pic)
        return;
    sendTranslateAddress(out, I, info, /*neg=*/false, regno);
}

/*
 * Emits instructions to load the jump/call/return target into the
 * corresponding argno register.  Else, if I is not a jump/call/return
 * instruction, load 0.
 */
static void sendLoadTargetMetadata(FILE *out, const InstrInfo *I,
    CallInfo &info, bool _static, int regno)
{
    const OpInfo *op = &I->op[0];
    switch (I->mnemonic)
    {
        case MNEMONIC_RET:
            sendMovFromStackToR64(out, info.rsp_offset, regno);
            sendTranslateToStaticAddress(out, I, info, _static, regno);
            return;
        case MNEMONIC_CALL:
        case MNEMONIC_JMP:
        case MNEMONIC_JO: case MNEMONIC_JNO: case MNEMONIC_JB: case MNEMONIC_JAE:
        case MNEMONIC_JE: case MNEMONIC_JNE: case MNEMONIC_JBE: case MNEMONIC_JA:
        case MNEMONIC_JS: case MNEMONIC_JNS: case MNEMONIC_JP: case MNEMONIC_JNP:
        case MNEMONIC_JL: case MNEMONIC_JGE: case MNEMONIC_JLE: case MNEMONIC_JG:
        case MNEMONIC_JCXZ: case MNEMONIC_JECXZ: case MNEMONIC_JRCXZ:
            if (I->count.op == 1)
                break;
            // Fallthrough:

        default:
        unknown:

            // This is NOT a jump/call/return, so the target is set to 0:
            sendSExtFromI32ToR64(out, 0, regno);
            return;
    }

    switch (op->type)
    {
        case OPTYPE_REG:
            if (info.isClobbered(op->reg))
                sendMovFromStackToR64(out, info.getOffset(op->reg), regno);
            else
            {
                int regno_1 = getRegIdx(op->reg);
                assert(regno_1 >= 0);
                sendMovFromR64ToR64(out, regno_1, regno);
            }
            sendTranslateToStaticAddress(out, I, info, _static, regno);
            return;
        case OPTYPE_MEM:
            // This is an indirect jump/call.  Convert the instruction into a
            // mov instruction that loads the target in the correct register
            (void)sendLoadFromMemOpToR64(out, I, info, op->size,
                op->mem.seg, op->mem.disp, op->mem.base, op->mem.index,
                op->mem.scale, /*lea=*/false, regno);
            sendTranslateToStaticAddress(out, I, info, _static, regno);
            return;
        
        case OPTYPE_IMM:
        {
            // This is a direct jump/call.  Load the target into the correct
            // register.

            intptr_t target = I->address + I->size + op->imm;
            sendLoadPointerMetadata(out, info, _static, target, regno);
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
static void sendLoadNextMetadata(FILE *out, const char *name,
    const InstrInfo *I, CallInfo &info, bool _static, int regno)
{
    const char *regname = getRegName(getReg(regno))+1;
    uint8_t opcode = 0x06;
    switch (I->mnemonic)
    {
        case MNEMONIC_RET:
        case MNEMONIC_CALL:
        case MNEMONIC_JMP:
            sendLoadTargetMetadata(out, I, info, _static, regno);
            return;
        case MNEMONIC_JO:
            opcode = 0x70;
            break;
        case MNEMONIC_JNO:
            opcode = 0x71;
            break;
        case MNEMONIC_JB:
            opcode = 0x72;
            break;
        case MNEMONIC_JAE:
            opcode = 0x73;
            break;
        case MNEMONIC_JE:
            opcode = 0x74;
            break;
        case MNEMONIC_JNE:
            opcode = 0x75;
            break;
        case MNEMONIC_JBE:
            opcode = 0x76;
            break;
        case MNEMONIC_JA:
            opcode = 0x77;
            break;
        case MNEMONIC_JS:
            opcode = 0x78;
            break;
        case MNEMONIC_JNS:
            opcode = 0x79;
            break;
        case MNEMONIC_JP:
            opcode = 0x7a;
            break;
        case MNEMONIC_JNP:
            opcode = 0x7b;
            break;
        case MNEMONIC_JL:
            opcode = 0x7c;
            break;
        case MNEMONIC_JGE:
            opcode = 0x7d;
            break;
        case MNEMONIC_JLE:
            opcode = 0x7e;
            break;
        case MNEMONIC_JG:
            opcode = 0x7f;
            break;
        case MNEMONIC_JECXZ: case MNEMONIC_JRCXZ:
        {
            // Special handling for jecxz/jrcxz.  This is similar to other
            // jcc instructions (see below), except we must restore %rcx:
            Register exclude[] = {getReg(regno), REGISTER_INVALID};
            int slot = 0;
            int scratch = sendTemporaryRestoreReg(out, info, REGISTER_RCX,
                exclude, &slot);
            if (I->mnemonic == MNEMONIC_JECXZ)
                fprintf(out, "%u,", 0x67);
            fprintf(out, "%u,{\"rel8\":\".Ltake%s@%s\"},", 0xe3, regname,
                name);
            sendLoadPointerMetadata(out, info, _static, I->address + I->size,
                "{\"rel32\":\".Lbreak\"}", regno);
            fprintf(out, "%u,{\"rel8\":\".Lnext%s@%s\"},", 0xeb, regname,
                name);
            fprintf(out, "\".Ltake%s@%s\",", regname, name);
            sendLoadTargetMetadata(out, I, info, _static, regno);
            fprintf(out, "\".Lnext%s@%s\",", regname, name);
            sendUndoTemporaryMovReg(out, REGISTER_RCX, scratch);
            return;
        }
        default:
            sendLoadPointerMetadata(out, info, _static, I->address + I->size,
                "{\"rel32\":\".Lbreak\"}", regno);
            return;
    }

    // jcc .Ltaken
    fprintf(out, "%u,{\"rel8\":\".Ltake%s@%s\"},", opcode, regname, name);

    // .LnotTaken:
    // leaq .Lbreak(%rip),%rarg
    // jmp .Lnext;
    sendLoadPointerMetadata(out, info, _static, I->address + I->size,
        "{\"rel32\":\".Lbreak\"}", regno);
    fprintf(out, "%u,{\"rel8\":\".Lnext%s@%s\"},", 0xeb, regname, name);

    // .Ltaken:
    // ... load target into %rarg
    fprintf(out, "\".Ltake%s@%s\",", regname, name);
    sendLoadTargetMetadata(out, I, info, _static, regno);
    
    // .Lnext:
    fprintf(out, "\".Lnext%s@%s\",", regname, name);
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
static void sendAsmStrData(FILE *out, const InstrInfo *I,
    bool newline = false)
{
    fputs("{\"string\":\"", out);
    for (unsigned i = 0; I->string.instr[i] != '\0'; i++)
        sendStringCharData(out, I->string.instr[i]);
    if (newline)
        sendStringCharData(out, '\n');
    fputs("\"}", out);
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
 * Send instructions to load an argument into a register.
 */
static Type sendLoadArgumentMetadata(FILE *out, CallInfo &info,
    const ELF *elf, const Action *action, size_t idx, const Argument &arg,
    const std::vector<Instr> &Is, size_t i, const InstrInfo *I, intptr_t id,
    int argno, int regno)
{
    if (regno < 0)
        error("failed to load argument; call instrumentation exceeds the "
            "maximum number of arguments (%d)", argno);
    sendSaveRegToStack(out, info, getReg(regno));

    const Patch *patch = action->patch[idx];
    const char *name = patch->name+1;
    bool _static = arg._static;
    Type t = TYPE_INT64;
    switch (arg.kind)
    {
        case ARGUMENT_USER:
        {
            MatchVal val = getCSVValue(I->address, arg.name, arg.value);
            if (val.type != MATCH_TYPE_INTEGER)
            {
                warning(CONTEXT_FORMAT "failed to load CSV file value %s[%ld] "
                    "into register %s; entry for address 0x%lx %s",
                    CONTEXT(I), arg.name, arg.value, getRegName(getReg(regno)),
                    I->address,
                    (val.type == MATCH_TYPE_UNDEFINED? "is missing":
                                                       "is not an integer"));
                sendSExtFromI32ToR64(out, 0, regno);
                t = TYPE_NULL_PTR;
                break;
            }
            sendLoadValueMetadata(out, val.i, regno);
            break;
        }
        case ARGUMENT_INTEGER:
            sendLoadValueMetadata(out, arg.value, regno);
            break;
        case ARGUMENT_STRING:
        {
            std::string offset("{\"rel32\":\".Lstr");
            offset += std::to_string(regno);
            offset += '@';
            offset += name;
            offset += "\"}";
            sendLeaFromPCRelToR64(out, offset.c_str(), regno);
            t = TYPE_CONST_CHAR_PTR;
            break;
        }
        case ARGUMENT_OFFSET:
            sendLoadValueMetadata(out, I->offset, regno);
            break;
        case ARGUMENT_ADDR:
            sendLoadPointerMetadata(out, info, _static, I->address,
                "{\"rel32\":\".Linstr\"}", regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_ID:
            sendLoadValueMetadata(out, id, regno);
            break;
        case ARGUMENT_NEXT:
            switch (patch->pos)
            {
                case POS_AFTER:
                    // If we reach here after the instruction, it means the
                    // branch was NOT taken, so (next=.Lbreak).
                    sendLoadPointerMetadata(out, info, _static,
                        I->address + I->size, "{\"rel32\":\".Lbreak\"}",
                        regno);
                    break;
                default:
                    sendLoadNextMetadata(out, name, I, info, _static, regno);
                    break;
            }
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_BASE:
            sendLoadPointerMetadata(out, info, _static, 0x0, "{\"rel32\":0}",
                regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_CONFIG:
            // ELF = "config anywhere", PE = "config close".
            switch (elf->type)
            {
                case BINARY_TYPE_ELF_EXE: case BINARY_TYPE_ELF_DSO:
                case BINARY_TYPE_ELF_PIE:
                    sendMovFromI64ToR64(out, "{\"int64\":\".Lconfig\"}",
                        regno);
                    sendTranslateToDynamicAddress(out, I, info,
                        /*static=*/false, regno);
                    break;
                case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
                    sendLeaFromPCRelToR64(out, "{\"rel32\":\".Lconfig\"}",
                        regno);
                    break;
            }
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_ASM:
        {
            std::string offset("{\"rel32\":\".Lasm@");
            offset += name;
            offset += "\"}";
            sendLeaFromPCRelToR64(out, offset.c_str(), regno);
            t = TYPE_CONST_CHAR_PTR;
            break;
        }
        case ARGUMENT_ASM_SIZE: case ARGUMENT_ASM_LEN:
        {
            intptr_t len = strlen(I->string.instr);
            sendLoadValueMetadata(out,
                (arg.kind == ARGUMENT_ASM_SIZE? len+1: len), regno);
            break;
        }
        case ARGUMENT_BYTES:
        {
            std::string offset("{\"rel32\":\".Lbytes@");
            offset += name;
            offset += "\"}";
            sendLeaFromPCRelToR64(out, offset.c_str(), regno);
            t = TYPE_CONST_INT8_PTR;
            break;
        }
        case ARGUMENT_BYTES_SIZE:
            sendLoadValueMetadata(out, I->size, regno);
            break;
        case ARGUMENT_TARGET:
            sendLoadTargetMetadata(out, I, info, _static, regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_TRAMPOLINE:
            sendLeaFromPCRelToR64(out, "{\"rel32\":\".Ltrampoline\"}", regno);
            t = TYPE_CONST_VOID_PTR;
            break;
        case ARGUMENT_RANDOM:
            sendLoadValueMetadata(out, rand(), regno);
            break;
        case ARGUMENT_REGISTER:
            if (arg.ptr)
                goto ARGUMENT_REG_PTR;
            switch ((Register)arg.value)
            {
                case REGISTER_RIP:
                    switch (patch->pos)
                    {
                        case POS_AFTER: case POS_REPLACE:
                            sendLeaFromPCRelToR64(out,
                                "{\"rel32\":\".Lbreak\"}", regno);
                            break;
                        default:
                            sendLeaFromPCRelToR64(out,
                                "{\"rel32\":\".Linstr\"}", regno);
                            break;
                    }
                    t = TYPE_CONST_VOID_PTR;
                    break;
                case REGISTER_SPL:
                    sendLeaFromStackToR64(out, info.rsp_offset, regno);
                    sendMovFromR8ToR64(out, regno, false, regno);
                    t = TYPE_INT8;
                    break;
                case REGISTER_SP:
                    sendLeaFromStackToR64(out, info.rsp_offset, regno);
                    sendMovFromR16ToR64(out, regno, regno);
                    t = TYPE_INT16;
                    break;
                case REGISTER_ESP:
                    sendLeaFromStackToR64(out, info.rsp_offset, regno);
                    sendMovFromR32ToR64(out, regno, regno);
                    t = TYPE_INT32;
                    break;
                case REGISTER_RSP:
                    sendLeaFromStackToR64(out, info.rsp_offset, regno);
                    break;
                case REGISTER_EFLAGS:
                    if (info.isSaved(REGISTER_EFLAGS))
                        sendMovFromStack16ToR64(out,
                            info.getOffset(REGISTER_EFLAGS), regno);
                    else
                    {
                        Register exclude[] = {REGISTER_RAX, getReg(regno),
                            REGISTER_INVALID};
                        int slot = 0;
                        int scratch = sendTemporarySaveReg(out, info,
                            REGISTER_RAX, exclude, &slot);
                        // seto %al
                        // lahf
                        fprintf(out, "%u,%u,%u,", 0x0f, 0x90, 0xc0);
                        fprintf(out, "%u,", 0x9f);
                        sendMovFromRAX16ToR64(out, regno);
                        sendUndoTemporaryMovReg(out, REGISTER_RAX, scratch);
                    }
                    t = TYPE_INT16;
                    break;
                default:
                {
                    Register reg = (Register)arg.value;
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
            }
            break;
        ARGUMENT_REG_PTR:
        {
            Register reg = (Register)arg.value;
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
        case ARGUMENT_STATE:
        {
            // State is saved starting from %rflags
            Register reg = REGISTER_EFLAGS;
            sendLeaFromStackToR64(out, info.getOffset(reg), regno);
            t = TYPE_VOID | TYPE_PTR;
            break;
        }
        case ARGUMENT_SYMBOL:
        {
            t = TYPE_CONST | TYPE_VOID | TYPE_PTR;
            intptr_t val = getELFObject(elf, arg.name);
            if (val == -1)
            {
                warning(CONTEXT_FORMAT "failed to load ELF object into "
                    "register %s; symbol \"%s\" is undefined",
                    CONTEXT(I), getRegName(getReg(regno)), arg.name);
                sendSExtFromI32ToR64(out, 0, regno);
                t = TYPE_NULL_PTR;
                break;
            }
            else if (val == INTPTR_MIN)
            {
                val = getELFGOTEntry(elf, arg.name);
                if (val >= INT32_MIN && val <= INT32_MAX)
                {
                    // Dynamically load the pointer from the GOT
                    sendMovFromPCRelToR64(out, val, regno);
                    sendTranslateToStaticAddress(out, I, info, _static,
                        regno);
                    break;
                }
            }
            if (val >= INT32_MIN && val <= INT32_MAX)
            {
                sendLoadPointerMetadata(out, info, _static, val, regno);
                break;
            }
            warning(CONTEXT_FORMAT "failed to load ELF object into "
                    "register %s; object \"%s\" not found",
                    CONTEXT(I), getRegName(getReg(regno)), arg.name);
            sendSExtFromI32ToR64(out, 0, regno);
            t = TYPE_NULL_PTR;
            break;
        }
        case ARGUMENT_MEMOP:
            switch (arg.memop.size)
            {
                case sizeof(int64_t):
                    t = TYPE_INT64; break;
                case sizeof(int32_t):
                    t = TYPE_INT32; break;
                case sizeof(int16_t):
                    t = TYPE_INT16; break;
                default:
                    t = TYPE_INT8; break;
            }
            if (arg.ptr)
                t |= TYPE_PTR;

            if (!sendLoadFromMemOpToR64(out, I, info, arg.memop.size,
                    arg.memop.seg, arg.memop.disp, arg.memop.base,
                    arg.memop.index, arg.memop.scale, /*lea=*/arg.ptr, regno))
                t = TYPE_NULL_PTR;
            break;
        case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
        case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
        {
            Access access = (arg.kind == ARGUMENT_SRC? ACCESS_READ:
                            (arg.kind == ARGUMENT_DST? ACCESS_WRITE: 0));
            OpType type = (arg.kind == ARGUMENT_IMM? OPTYPE_IMM:
                          (arg.kind == ARGUMENT_REG? OPTYPE_REG:
                          (arg.kind == ARGUMENT_MEM? OPTYPE_MEM:
                                OPTYPE_INVALID)));
            const OpInfo *op = getOperand(I, (int)arg.value, type, access);
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
            bool dangerous = false;
            if (!arg.ptr && arg.field == FIELD_NONE && op != nullptr &&
                    op->type == OPTYPE_MEM)
            {
                // Filter dangerous memory operand pass-by-value arguments:
                if (patch->pos == POS_AFTER)
                {
                    warning(CONTEXT_FORMAT "failed to load memory "
                        "operand contents into register %s; operand may "
                        "be invalid after instruction",
                        CONTEXT(I), getRegName(getReg(regno)));
                    sendSExtFromI32ToR64(out, 0, regno);
                    t = TYPE_NULL_PTR;
                    dangerous = true;
                }
                else switch (I->mnemonic)
                {
                    default:
                        if (op->access != 0)
                            break;
                        // Fallthrough
                    case MNEMONIC_LEA: case MNEMONIC_NOP:
                        warning(CONTEXT_FORMAT "failed to load memory "
                            "operand contents into register %s; operand is "
                            "not accessed by the %s instruction",
                            CONTEXT(I), getRegName(getReg(regno)),
                            I->string.mnemonic);
                        sendSExtFromI32ToR64(out, 0, regno);
                        t = TYPE_NULL_PTR;
                        dangerous = true;
                        break;
                }
            }
            if (!dangerous &&
                !sendLoadOperandMetadata(out, name, I, op, arg.ptr, arg.field,
                    info, regno))
                t = TYPE_NULL_PTR;
            break;
        }
        case ARGUMENT_BB:
        {
            const BB *bb = findBB(elf->bbs, i);
            if (bb == nullptr)
            {
                sendSExtFromI32ToR64(out, 0, regno);
                t = TYPE_NULL_PTR;
                break;
            }
            switch (arg.field)
            {
                case FIELD_ADDR:
                    sendLoadPointerMetadata(out, info, _static,
                        Is[bb->lb].address, regno);
                    t = TYPE_CONST_VOID_PTR;
                    break;
                case FIELD_OFFSET:
                    sendLoadValueMetadata(out, Is[bb->lb].address, regno);
                    break;
                case FIELD_SIZE:
                    sendLoadValueMetadata(out, Is[bb->ub].address -
                        Is[bb->lb].address + Is[bb->ub].size, regno);
                    break;
                case FIELD_LEN:
                    sendLoadValueMetadata(out, bb->ub - bb->lb + 1, regno);
                    break;
                default:
                    error("unknown field (%d)", arg.field);
            }
            break;
        }
        case ARGUMENT_F:
        {
            const F *f = findF(elf->fs, i);
            if (f == nullptr)
            {
                sendSExtFromI32ToR64(out, 0, regno);
                t = TYPE_NULL_PTR;
                break;
            }
            switch (arg.field)
            {
                case FIELD_ADDR:
                    sendLoadPointerMetadata(out, info, _static,
                        Is[f->lb].address, regno);
                    t = TYPE_CONST_VOID_PTR;
                    break;
                case FIELD_OFFSET:
                    sendLoadValueMetadata(out, Is[f->lb].address, regno);
                    break;
                case FIELD_SIZE:
                    sendLoadValueMetadata(out, Is[f->ub].address -
                        Is[f->lb].address + Is[f->ub].size, regno);
                    break;
                case FIELD_LEN:
                    sendLoadValueMetadata(out, f->ub - f->lb + 1, regno);
                    break;
                case FIELD_NAME:
                {
                    if (f->name == nullptr)
                    {
                        sendSExtFromI32ToR64(out, 0, regno);
                        t = TYPE_NULL_PTR;
                        break;
                    }
                    t = TYPE_CONST_CHAR_PTR;
                    std::string offset("{\"rel32\":\".Lfn");
                    offset += std::to_string(regno);
                    offset += '@';
                    offset += name;
                    offset += "\"}";
                    sendLeaFromPCRelToR64(out, offset.c_str(), regno);
                    t = TYPE_CONST_CHAR_PTR;
                    break;
                }
                default:
                    error("unknown field (%d)", arg.field);
            }
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
static void sendArgumentDataMetadata(FILE *out, const char *name,
    const ELF *elf, const Argument &arg, size_t i, const InstrInfo *I,
    int regno)
{
    switch (arg.kind)
    {
        case ARGUMENT_STRING:
            fprintf(out, "\".Lstr%d@%s\",{\"string\":", regno, name);
            sendString(out, arg.name);
            fputs("},", out);
            break;
        case ARGUMENT_ASM:
            if (arg.duplicate)
                return;
            fprintf(out, "\".Lasm@%s\",", name);
            sendAsmStrData(out, I, /*newline=*/false);
            putc(',', out);
            break;
        case ARGUMENT_BYTES:
            if (arg.duplicate)
                return;
            fprintf(out, "\".Lbytes@%s\",", name);
            sendBytesData(out, I->data, I->size);
            fputc(',', out);
            break;
        case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
        case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
        {
            if (!arg.ptr)
                return;
            Access access = (arg.kind == ARGUMENT_SRC? ACCESS_READ:
                            (arg.kind == ARGUMENT_DST? ACCESS_WRITE: 0));
            OpType type = (arg.kind == ARGUMENT_IMM? OPTYPE_IMM:
                          (arg.kind == ARGUMENT_REG? OPTYPE_REG:
                          (arg.kind == ARGUMENT_MEM? OPTYPE_MEM:
                                OPTYPE_INVALID)));
            const OpInfo *op = getOperand(I, (int)arg.value, type, access);
            sendOperandDataMetadata(out, name, I, op, regno);
            break;
        }
        case ARGUMENT_F:
        {
            if (arg.field != FIELD_NAME || arg.duplicate)
                return;
            const F *f = findF(elf->fs, i);
            if (f == nullptr || f->name == nullptr)
                return;
            fprintf(out, "\".Lfn%d@%s\",{\"string\":", regno, name);
            sendString(out, f->name);
            fputs("},", out);
            break;
        }
        default:
            break;
    }
}

/*
 * Build metadata.
 */
void sendMetadata(FILE *out, const ELF *elf, const Action *action, size_t idx,
	const std::vector<Instr> &Is, size_t i, const InstrInfo *I, intptr_t id,
    Context *cxt)
{
    if (action == nullptr)
        return;
    const Patch *patch = action->patch[idx];
    const char *name = patch->name+1;

    switch (patch->kind)
    {
        case PATCH_PLUGIN:
        {
            const Plugin *plugin = patch->plugin;
            cxt->argv    = &plugin->argv;
            cxt->context = plugin->context;
            plugin->patchFunc(cxt, PHASE_METADATA);
            return;
        }

        case PATCH_EXIT: case PATCH_EMPTY: case PATCH_TRAP: case PATCH_BREAK:
            return;
        case PATCH_PRINT:
        {
            sendDefinitionHeader(out, name, "DATA");
            fprintf(out, "\".Lasm@print\",");
            sendAsmStrData(out, I, /*newline=*/true);
            sendDefinitionFooter(out);

            sendDefinitionHeader(out, name, "ASM_LEN");
            intptr_t len = strlen(I->string.instr) + 1;
            sendIntegerData(out, 32, len);
            sendDefinitionFooter(out);
            return;
        }
        case PATCH_CALL:
        {
            // Load arguments.
            bool state = false;
            for (const auto &arg: patch->args)
            {
                if (arg.kind == ARGUMENT_STATE)
                {
                    state = true;
                    break;
                }
            }
            bool sysv = true;
            switch (elf->type)
            {
                case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
                    sysv = false;
                    break;
                default:
                    break;
            }

            sendDefinitionHeader(out, name, "ARGS");
            int argno = 0;
            bool before = (patch->pos == POS_BEFORE);
            bool pic = (getELFType(elf) != BINARY_TYPE_ELF_EXE);
            CallInfo info(sysv, (patch->abi == ABI_CLEAN), state,
                (patch->jmp != JUMP_NONE), patch->args.size(),
                before, pic);
            TypeSig sig = TYPESIG_EMPTY;
            for (const auto &arg: patch->args)
            {
                int regno = getArgRegIdx(sysv, argno);
                Type t = sendLoadArgumentMetadata(out, info, elf, action, idx,
                    arg, Is, i, I, id, argno, regno);
                sig = setType(sig, t, argno);
                argno++;
            }
            argno = 0;
            int32_t rsp_args_offset = 0;
            for (int argno = (int)patch->args.size()-1; argno >= 0; argno--)
            {
                // Send stack arguments:
                int regno = getArgRegIdx(sysv, argno);
                switch (regno)
                {
                    case R10_IDX: case R11_IDX:
                        sendPush(out, info.rsp_offset, before, getReg(regno));
                        rsp_args_offset += sizeof(int64_t);
                        break;
                }
            }
            for (int regno = 0; patch->abi == ABI_NAKED &&
                    regno < RMAX_IDX; regno++)
            {
                Register reg = getReg(regno);
                if (!info.isCallerSave(reg) && info.isClobbered(reg))
                {
                    // Restore clobbered callee-save register:
                    int32_t reg_offset = rsp_args_offset;
                    reg_offset += info.getOffset(reg);
                    sendMovFromStackToR64(out, reg_offset, regno);
                    info.restore(reg);
                }
            }
            sendDefinitionFooter(out);

            // Find & call the function.
            sendDefinitionHeader(out, name, "FUNC");
            intptr_t addr = lookupSymbol(patch->elf, patch->symbol, sig);
            if (addr < 0 || addr > INT32_MAX)
            {
                lookupSymbolWarnings(patch->elf, I, patch->symbol, sig);
                std::string str;
                getSymbolString(patch->symbol, sig, str);
                error(CONTEXT_FORMAT "failed to find a symbol matching \"%s\" "
                    "in binary \"%s\"", CONTEXT(I), str.c_str(),
                    patch->elf->filename);
            }
            fprintf(out, "{\"rel32\":%d}", (int32_t)addr);
            sendDefinitionFooter(out);
            info.call(patch->jmp != JUMP_NONE);

            // Restore state.
            sendDefinitionHeader(out, name, "RSTOR");
            if (rsp_args_offset != 0)
            {
                // lea rsp_args_offset(%rsp),%rsp
                fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                    0x48, 0x8d, 0xa4, 0x24, rsp_args_offset);
            }
            bool pop_rsp = state;
            Register reg;
            while ((reg = info.pop()) != REGISTER_INVALID)
            {
                switch (reg)
                {
                    case REGISTER_RSP:
                        pop_rsp = true;
                        continue;           // %rsp is popped last.
                    default:
                        break;
                }
                bool preserve_rax = info.isUsed(REGISTER_RAX);
                Register rscratch = (preserve_rax? info.getScratch():
                    REGISTER_INVALID);
                if (sendPop(out, preserve_rax, reg, rscratch))
                    info.clobber(rscratch);
            }
            sendDefinitionFooter(out);

            // Restore %rsp.
            sendDefinitionHeader(out, name, "RSTOR_RSP");
            if (pop_rsp)
                sendPop(out, false, REGISTER_RSP);
            else
            {
                // lea 0x4000(%rsp),%rsp
                fprintf(out, "%u,%u,%u,%u,{\"int32\":%d},",
                    0x48, 0x8d, 0xa4, 0x24, 0x4000);
            }
            sendDefinitionFooter(out);

            // Place data (if necessary).
            sendDefinitionHeader(out, name, "DATA");
            argno = 0;
            for (const auto &arg: patch->args)
            {
                int regno = getArgRegIdx(sysv, argno);
                sendArgumentDataMetadata(out, name, elf, arg, i, I, regno);
                argno++;
            }
            sendDefinitionFooter(out);
            return;
        }
        default:
            return;
    }
}

