/*
 * e9x86_64.cpp
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
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "e9patch.h"
#include "e9x86_64.h"

/*
 * We use a "DIY decoder" rather than relying on a 3rd party disassembler.
 * This is because we only need to partially decode the instructions, so we
 * can use much *leaner* code.  Correctness was fuzz-tested against a real
 * disassembler.
 */

/*
 * Control-Flow-Transfer information.
 */
struct CFTInfo
{
    bool call;
    bool ret;
    bool jmp;
    bool jcc;
    intptr_t target;
};

/*
 * Instruction encoding.
 */
enum Encoding
{
    ENCODING_SINGLE_BYTE,
    ENCODING_TWO_BYTES_0F,
    ENCODING_THREE_BYTES_0F38,
    ENCODING_THREE_BYTES_0F3A
};

/*
 * Decode an instruction prefix.
 */
static int decodePrefix(const uint8_t *bytes, unsigned size, uint8_t &rex,
    bool &addr32)
{
    int i;
    rex = 0;
    addr32 = false;
    for (i = 0; i < (int)size; i++)
    {
        switch (bytes[i])
        {
            case 0x67:      // Address-size override
                addr32 = true;
                // Fallthrough
            case 0xf0:      // LOCK
            case 0xf2:      // REPNE/REPNZ
            case 0xf3:      // REP or REPE/REPZ
            case 0x2e:      // CS segment override
            case 0x36:      // SS segment override
            case 0x3e:      // DS segment override
            case 0x26:      // ES segment override
            case 0x64:      // FS segment override
            case 0x65:      // GS segment override
            case 0x66:      // Operand-size override
                continue;

            // REX prefixes:
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
            case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b:
            case 0x4c: case 0x4d: case 0x4e: case 0x4f:
                rex = bytes[i];
                continue;
            default:
                break;
        }
        break;
    }
    return i;
}

/*
 * Decode an instruction opcode.
 */
static int decodeOpcode(const uint8_t *bytes, unsigned size, int i,
    Encoding &encoding, uint8_t &opcode)
{
    if (i < 0 || i >= (int)size)
        return i;

    encoding = ENCODING_SINGLE_BYTE;

    // Extended encodings:
    if (bytes[i] == 0x62)
    {
        if (size - i > 4 && (~bytes[i+1] & 0x0c) == 0x0c &&
            (bytes[i+2] & 0x04) == 0x04)
        {
            // 4-byte EVEX encoding:
            switch (bytes[i+1] & 0x03)
            {
                case 0x01:
                    encoding = ENCODING_TWO_BYTES_0F;
                    break;
                case 0x02:
                    encoding = ENCODING_THREE_BYTES_0F38;
                    break;
                case 0x03:
                    encoding = ENCODING_THREE_BYTES_0F3A;
                    break;
                default:
                    return -1;
            }
            i += 4;
            opcode = bytes[i++];
            return i;
        }
        else
            return -1;
    }
    else if (bytes[i] == 0xc4 && (i > 0? (bytes[i-1] & 0xf0) != 0x40: true))
    {
        if (size - i > 3)
        {
            // 3-byte VEX encoding:
            switch (bytes[i+1] & 0x1f)
            {
                case 0x1:
                    encoding = ENCODING_TWO_BYTES_0F;
                    break;
                case 0x02:
                    encoding = ENCODING_THREE_BYTES_0F38;
                    break;
                case 0x03:
                    encoding = ENCODING_THREE_BYTES_0F3A;
                    break;
                default:
                    return -1;
            }
            i += 3;
            opcode = bytes[i++];
            return i;
        }
        else
            return -1;
    }
    else if (bytes[i] == 0xc5 && size - i > 2 &&
            (i > 0? (bytes[i-1] & 0xf0) != 0x40: true))
    {
        // 2-byte VEX:
        i += 2;
        encoding = ENCODING_TWO_BYTES_0F;
        opcode = bytes[i++];
        return i;
    }

    // "Classic" encoding:
    opcode = bytes[i++];
    if (opcode == 0x0f)
    {
        if (i >= (int)size)
            return -1;
        uint8_t next = bytes[i++];
        if (next == 0x38)
        {
            if (i >= (int)size)
                return -1;
            encoding = ENCODING_THREE_BYTES_0F38;
            opcode = bytes[i++];
        }
        else if (next == 0x3a)
        {
            if (i >= (int)size)
                return -1;
            encoding = ENCODING_THREE_BYTES_0F3A;
            opcode = bytes[i++];
        }
        else
        {
            encoding = ENCODING_TWO_BYTES_0F;
            opcode = next;
        }
    }

    return i;
}

/*
 * Push the return address for a call onto the stack.
 */
static int pushReturnAddress(intptr_t addr, intptr_t offset, unsigned size,
    bool pic, Buffer *buf, size_t start)
{
    intptr_t target = addr + size;
    if (!pic && target >= INT32_MIN && target <= INT32_MAX)
    {
        // For non-PIC, we can just push the return address.
        int32_t target32 = (int32_t)target;
        
        // push target32
        buf->push(0x68);
        buf->push((const uint8_t *)&target32, sizeof(target32));
    }
    else if (!option_Oscratch_stack)
    {
        // For PIC we must calculate the return address.
        // (wihout using memory or affecting the flags).

        // push %rax
        buf->push(0x50);
        
        // lea diff32(%rip),%rax
        intptr_t diff   = target -
            (addr + offset + buf->size(start) + /*sizeof(leaq)=*/7);
        if (diff < INT32_MIN || diff > INT32_MAX)
            return -1;
        int32_t diff32  = (int32_t)diff;
        buf->push(0x48); buf->push(0x8d); buf->push(0x05);
        buf->push((const uint8_t *)&diff32, sizeof(diff32));

        // WARNING: This instruction uses an implicit LOCK and
        //          is therefore very slow!  However, there is
        //          no great alternative AFAIK.
        //
        // xchg %rax,(%rsp)
        buf->push(0x48); buf->push(0x87); buf->push(0x04);
        buf->push(0x24);
    }
    else
    {
        // We can avoid the slow xchg instruction if the stack can be used
        // as scratch space.

        // mov %rax,-0x4000(%rsp)
        buf->push(0x48); buf->push(0x89); buf->push(0x84);
        buf->push(0x24); buf->push(0x00); buf->push(0xc0);
        buf->push(0xff); buf->push(0xff);

        // lea diff32(%rip),%rax
        intptr_t diff   = target -
            (addr + offset + buf->size(start) + /*sizeof(leaq)=*/7);
        if (diff < INT32_MIN || diff > INT32_MAX)
            return -1;
        int32_t diff32  = (int32_t)diff;
        buf->push(0x48); buf->push(0x8d); buf->push(0x05);
        buf->push((const uint8_t *)&diff32, sizeof(diff32));

        // push %rax
        buf->push(0x50);

        // mov -0x3ff8(%rsp),%rax
        buf->push(0x48); buf->push(0x8b); buf->push(0x84);
        buf->push(0x24); buf->push(0x08); buf->push(0xc0);
        buf->push(0xff); buf->push(0xff);
    }

    return 0;
}

/*
 * Relocate an instruction, rewriting it if necessary.
 * Returns (-1) if the instruction cannot be relocated.
 */
int relocateInstr(intptr_t addr, int32_t offset32, const uint8_t *bytes,
    unsigned size, bool pic, Buffer *buf, bool relax)
{
    Buffer buf_0(nullptr);
    buf = (buf == nullptr? &buf_0: buf);
    size_t start = buf->size();

    intptr_t offset = (intptr_t)offset32;

    uint8_t rex = 0;
    bool addr32 = false;
    int i = decodePrefix(bytes, size, rex, addr32);
    if (i < 0)
    {
        // Instruction is not PC-relative:
no_modification_necessary:
        buf->push(bytes, size);
        return buf->commit(start);
    }
    Encoding encoding = ENCODING_SINGLE_BYTE;
    uint8_t opcode;
    i = decodeOpcode(bytes, size, i, encoding, opcode);
    if (i < 0)
        goto no_modification_necessary;

    // Special handling of JMPs and CALLs:
    switch (encoding)
    {
        case ENCODING_SINGLE_BYTE:

        if (opcode == 0xFF && size - i >= 1)
        {
            uint8_t modRM = bytes[i];
            uint8_t mod = (modRM & 0xc0) >> 6;
            uint8_t op  = (modRM & 0x38) >> 3;
            uint8_t rm  = modRM & 0x7;

            switch (op)
            {
                case 0x02:              // CALLQ r/m32/m64
                {
                    // Check for calls that use %rsp
                    // TODO: These can be implmented by adjusting the
                    //       displacement.
                    uint8_t b = rex & 0x1;
                    switch (mod)
                    {
                        case 0x0: case 0x1: case 0x2:
                        {
                            if (rm != 0x4 || size - i < 2 || b != 0)
                                break;
                            uint8_t sib = bytes[i+1];
                            uint8_t base = sib & 0x7;
                            if (base == 0x4)
                                return -1;      // callq *displ(%rsp, ...)
                            break;
                        }   
                        case 0x3:
                            if (rm == 0x4 && b == 0)
                                return -1;      // callq *%rsp
                            break;
                    }

                    if (pushReturnAddress(addr, offset, size, pic, buf, start)
                            < 0 && !relax)
                        return -1;

                    // Convert the call into a jmp:
                    size_t buf_size = buf->size(start);
                    buf->push(bytes, i);
                    modRM = (modRM & ~0x38) | (0x04 << 3);  // jmp op
                    buf->push(modRM);

                    if (mod == 0x0 && rm == 0x05)
                    {
                        // This is a %rip-relative call, so we must adjust 
                        int32_t pcrel32 = *(uint32_t *)(bytes + i + 1);
                        intptr_t target = addr + size + (intptr_t)pcrel32;
                        intptr_t diff   = target -
                            (addr + offset + buf_size + size);
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));
                        buf->push(bytes + i + 1 + sizeof(diff32),
                            size - i - 1 - sizeof(diff32));
                    }
                    else
                        buf->push(bytes + i + 1, size - i - 1);
                }
                default:
                    break;
            }
        }

        switch (size - i)
        {
            case 1:
                switch (opcode)
                {
                    case 0xE3:          // JRCXZ pcrel8
                    {
                        // jrcxz .Ltaken
                        if (addr32)
                            buf->push(0x67);
                        buf->push(0xe3); buf->push(0x02);

                        // jmp .Lnot_taken
                        buf->push(0xeb); buf->push(0x05);

                        // .Ltaken
                        // jmp diff32
                        int8_t pcrel8 = (int8_t)bytes[i];
                        intptr_t target = addr + size + (intptr_t)pcrel8;
                        intptr_t diff   = target -
                            (addr + offset + buf->size(start) +
                                /*sizeof(jmp)=*/5);
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        buf->push(0xE9);
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));

                        // .Lnot_taken
                        return buf->commit(start);
                    }

                    case 0xEB:          // JMP pcrel8
                    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
                    case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
                    case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
                    case 0x7F:          // Jcc pcrel8
                    {
                        int8_t pcrel8 = (int8_t)bytes[i];
                        intptr_t target = addr + size + (intptr_t)pcrel8;
                        intptr_t diff   = target -
                            (addr + offset + buf->size(start) +
                                /*sizeof(jmp)=*/(opcode == 0xEB? 5: 6));
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        
                        // Promote jump to rel32 version:
                        if (opcode == 0xEB)
                            buf->push(0xE9);
                        else
                        {
                            buf->push(0x0F);
                            buf->push((opcode - 0x70) + 0x80);
                        }
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));
                        
                        return buf->commit(start);
                    }

                    default:
                        break;
                }
                break;

            case 4:
                switch (opcode)
                {
                    case 0xE8:          // CALLQ pcrel32
                    {
                        if (pushReturnAddress(addr, offset, size, pic, buf,
                                start) < 0)
                            return -1;

                        // jmpq diff32
                        int32_t pcrel32 = *(uint32_t *)(bytes + i);
                        intptr_t target = addr + size + (intptr_t)pcrel32;
                        intptr_t diff   = target -
                            (addr + offset + buf->size(start) +
                                /*sizeof(jmpq)=*/5);
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        buf->push(0xE9);
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));
                        
                        return buf->commit(start);
                    }
                    case 0xE9:          // JMPQ pcrel32
                    {
                        // jmpq diff32
                        int32_t pcrel32 = *(uint32_t *)(bytes + i);
                        intptr_t target = addr + size + (intptr_t)pcrel32;
                        intptr_t diff   = target -
                            (addr + offset + buf->size(start) +
                                /*sizeof(jmpq)=*/5);
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        buf->push(0xE9); 
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));

                        return buf->commit(start);
                    }
                    default:
                        break;
                }
            default:
                break;
        }
        break;

        case ENCODING_TWO_BYTES_0F:
        switch (size - i)
        {
            case 4:
                switch (opcode)
                {
                    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                    case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                    case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                    case 0x8F:          // Jcc pcrel32
                    {
                        // jcc diff32
                        int32_t pcrel32 = *(int32_t *)(bytes + i);
                        intptr_t target = addr + size + (intptr_t)pcrel32;
                        intptr_t diff   = target -
                            (addr + offset + buf->size(start) +
                                /*sizeof(jcc)=*/6);
                        if (!relax && (diff < INT32_MIN || diff > INT32_MAX))
                            return -1;
                        int32_t diff32  = (int32_t)diff;
                        buf->push(0x0F); buf->push(opcode); 
                        buf->push((const uint8_t *)&diff32, sizeof(diff32));
                    
                        return buf->commit(start);
                    }
                    default:
                        break;
                }
            default:
                break;
        }
        break;

        default:
        break;
    }

    // Generic handling of position-dependent instructions:
    if (size - i < 5)
    {
        // The ModRM byte + 4-byte displacement does not fit into the rest of
        // the instruction.  Thus, this instruction cannot be PC-relative.
        goto no_modification_necessary;
    }
    if (encoding == ENCODING_SINGLE_BYTE)
    {
        // Since the remainder of the instruction is >= 5bytes, we presume
        // the instruction MUST have a ModRM byte UNLESS it is a movabs.
        // This assumption has been fuzz tested and seems to hold (...?).
        switch (opcode)
        {
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD:
            case 0xBE: case 0xBF:
                goto no_modification_necessary;
            default:
                break;
        }
    }

    // If we reached here, the next byte MUST be a ModRM.
    uint32_t modRM = bytes[i++];
    uint8_t mod = (modRM & 0xc0) >> 6;
    uint8_t rm  = modRM & 0x7;
    if (mod == 0x0 && rm == 0x05)
    {
        // i points to a %rip-relative displacement.  We adjust accordingly.
        int32_t pcrel32 = *(uint32_t *)(bytes + i);
        intptr_t target = addr + size + (intptr_t)pcrel32;
        intptr_t diff   = target - (addr + offset + buf->size(start) + size);
        if (diff < INT32_MIN || diff > INT32_MAX)
            return -1;
        int32_t diff32  = (int32_t)diff;
        buf->push(bytes, i);
        buf->push((const uint8_t *)&diff32, sizeof(diff32));
        buf->push(bytes + i + sizeof(diff32), size - i - sizeof(diff32));

        return buf->commit(start);
    }

    goto no_modification_necessary;
}

/*
 * Get the index of any pcrel intermediate if it exists, else 0.
 */
unsigned getInstrPCRelativeIndex(const uint8_t *bytes, unsigned size)
{
    uint8_t rex = 0;
    bool addr32 = false;
    int i = decodePrefix(bytes, size, rex, addr32);
    if (i < 0)
        return false;
    Encoding encoding = ENCODING_SINGLE_BYTE;
    uint8_t opcode;
    i = decodeOpcode(bytes, size, i, encoding, opcode);
    if (i < 0)
        return false;

    // Special handling of PC-relative JMPs and CALLs:
    switch (encoding)
    {
        case ENCODING_SINGLE_BYTE:
            switch (size - i)
            {
                case 1:
                    switch (opcode)
                    {
                        case 0xE3:          // JRCXZ
                        case 0xEB:          // JMP pcrel8
                        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
                        case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
                        case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
                        case 0x7F:          // Jcc pcrel8
                            return i;
                        default:
                            break;
                    }
                    break;
                case 4:
                    switch (opcode)
                    {
                        case 0xE8:          // CALL pcrel32
                        case 0xE9:          // JMP pcrel32
                            return i;
                        default:
                            break;
                    }
                    break;
            }
            break;
        case ENCODING_TWO_BYTES_0F:
            switch (size - i)
            {
                case 4:
                    switch (opcode)
                    {
                        case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                        case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                        case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                        case 0x8F:          // Jcc pcrel32
                            return i;
                        default:
                            break;
                    }
                    break;
            }
            break;
        default:
            break;
    }

    if (size - i < 5)
        return false;
    if (encoding == ENCODING_SINGLE_BYTE)
    {
        switch (opcode)
        {
            case 0xA0: case 0xA1: case 0xA2: case 0xA3:
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD:
            case 0xBE: case 0xBF:
                return 0;
            default:
                break;
        }
    }

    uint32_t modRM = bytes[i++];
    uint8_t mod = (modRM & 0xc0) >> 6;
    uint8_t rm  = modRM & 0x7;
    if (mod == 0x0 && rm == 0x05)
        return i;
    else
        return 0;
}

/*
 * Get information about a Control-Flow-Transfer instruction.
 */
static bool getCFTInfo(intptr_t addr, const uint8_t *bytes, unsigned size,
    CFTInfo *CFT)
{
    CFT->call = CFT->ret = CFT->jmp = CFT->jcc = false;
    CFT->target = INTPTR_MIN;

    uint8_t rex = 0;
    bool addr32 = false;
    int i = decodePrefix(bytes, size, rex, addr32);
    if (i < 0)
        return false;
    Encoding encoding = ENCODING_SINGLE_BYTE;
    uint8_t opcode;
    i = decodeOpcode(bytes, size, i, encoding, opcode);
    if (i < 0)
        return false;
    switch (encoding)
    {
        case ENCODING_SINGLE_BYTE:
        {
            switch (opcode)
            {
                case 0xC3:          // RET
                    if (size - i != 0)
                        return false;
                    CFT->ret = true;
                    return true;
                case 0xE3:          // JRCXZ
                case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
                case 0x75: case 0x76: case 0x77: case 0x78: case 0x79:
                case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E:
                case 0x7F:          // Jcc pcrel8
                case 0xEB:          // JMP pcrel8
                {
                    if (size - i != sizeof(int8_t))
                        return false;
                    CFT->jcc = (opcode != 0xEB);
                    CFT->jmp = (opcode == 0xEB);
                    int8_t pcrel8 = (int8_t)bytes[i];
                    CFT->target = addr + i + sizeof(int8_t) + (intptr_t)pcrel8;
                    return true;
                }
                case 0xE8:          // CALL pcrel32
                case 0xE9:          // JMP  pcrel32
                {
                    if (size - i != sizeof(int32_t))
                        return false;
                    CFT->jmp  = (opcode == 0xE9);
                    CFT->call = (opcode == 0xE8);
                    int32_t pcrel32 = *(const int32_t *)(bytes + i);
                    CFT->target =
                        addr + i + sizeof(int32_t) + (intptr_t)pcrel32;
                    return true;
                }
                case 0xFF:
                {
                    // TODO: Accurate size check?
                    if (size - i < 1)
                        return false;
                    uint8_t modRM = bytes[i];
                    uint8_t op    = (modRM & 0x38) >> 3;
                    switch (op)
                    {
                        case 0x02:      // CALL r/m32/m64
                            CFT->call = true;
                            return true;
                        case 0x04:      // JMP r/m32/m64
                            CFT->jmp = true;
                            return true;
                        default:
                            return false;
                    }
                }
                default:
                    return false;
            }
            break;
        }
        case ENCODING_TWO_BYTES_0F:
        {       
            switch (opcode)
            {
                case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                case 0x8F:          // Jcc pcrel32
                {
                    if (size - i != sizeof(int32_t))
                        return false;
                    CFT->jcc = true;
                    int32_t pcrel32 = *(const int32_t *)(bytes + i);
                    CFT->target =
                        addr + i + sizeof(int32_t) + (intptr_t)pcrel32;
                    return true;
                }
                default:
                    return false;
            }
            break;
        }
        default:
            break;
    }
    return false;
}

/*
 * Returns true iff the instruction is a control-flow-transfer.
 */
bool isCFT(const uint8_t *bytes, unsigned size, int flags)
{
    CFTInfo CFT;
    if (!getCFTInfo(0x0, bytes, size, &CFT))
        return false;
    if ((flags & CFT_CALL) != 0 && CFT.call)
        return true;
    if ((flags & CFT_RET) != 0 && CFT.ret)
        return true;
    if ((flags & CFT_JMP) != 0 && CFT.jmp)
        return true;
    if ((flags & CFT_JCC) != 0 && CFT.jcc)
        return true;
    return false;
}

/*
 * Returns the control-flow-transfer target if known, else INTPTR_MIN.
 */
intptr_t getCFTTarget(intptr_t addr, const uint8_t *bytes, unsigned size,
    int flags)
{
    CFTInfo CFT;
    if (!getCFTInfo(addr, bytes, size, &CFT))
        return INTPTR_MIN;
    if (CFT.target == INTPTR_MIN)
        return INTPTR_MIN;
    if ((flags & CFT_CALL) != 0 && CFT.call)
        return CFT.target;
    if ((flags & CFT_JMP) != 0 && CFT.jmp)
        return CFT.target;
    if ((flags & CFT_JCC) != 0 && CFT.jcc)
        return CFT.target;
    return INTPTR_MIN;
}

