/*
 * e9api.cpp
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

#include <cstdlib>
#include <cstring>

#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "e9elf.h"
#include "e9emit.h"
#include "e9patch.h"
#include "e9json.h"
#include "e9tactics.h"
#include "e9x86_64.h"

/*
 * Insert an instruction into a binary.
 */
void insertInstruction(Binary *B, Instr *I)
{
    // Insert the instruction into the index:
    auto result = B->Is.insert(std::make_pair((off_t)I->offset, I));
    if (!result.second)
        error("failed to insert instruction at offset (+%zu), another "
            "instruction already exists at that offset", I->offset);
    InstrSet::iterator i = result.first;

    // Find and validate successor and predecessor instructions:
    ++i;
    if (i != B->Is.end())
    {
        Instr *J = i->second;
        if (I->offset + I->size > J->offset)
            error("failed to insert instruction at offset (+%zu), instruction "
                "overlaps with another instruction at offset (+%zu)",
                I->offset, J->offset);
        if (I->addr + I->size > J->addr)
            error("failed to insert instruction at address (%p), instruction "
                "overlaps with another instruction at address (%p)",
                (void *)I->addr, (void *)J->addr);
        I->next = J;
        J->prev = I;
    }

    i = result.first;
    if (i != B->Is.begin())
    {
        --i;
        Instr *J = i->second;
        if (J->offset + J->size > I->offset)
            error("failed to insert instruction at offset (+%zu), instruction "
                "overlaps with another instruction at offset (+%zu)",
                I->offset, J->offset);
        if (J->addr + J->size > I->addr)
            error("failed to insert instruction at address (%p), instruction "
                "overlaps with another instruction at address (%p)",
                (void *)I->addr, (void *)J->addr);
        I->prev = J;
        J->next = I;
    }

    // Initialize the state:
    for (unsigned i = 0; i < I->size; i++)
    {
        switch (I->patched.state[i])
        {
            case STATE_UNKNOWN:
                I->patched.state[i] = STATE_INSTRUCTION;
                break;
            case STATE_INSTRUCTION | STATE_LOCKED:
            case STATE_PATCHED:
            case STATE_PATCHED | STATE_LOCKED:
            case STATE_QUEUED:
            case STATE_FREE:
                error("failed to insert instruction at address (%p), the "
                    "corresponding virtual memory has already been patched",
                    (void *)(I->addr + i));
            default:
                error("failed to insert instruction at address (%p), the "
                    "corresponding virtual memory has already been allocated "
                    "with state (0x%.2X)", (void *)(I->addr + i),
                    I->patched.state[i]);
        }
    }
}

/*
 * Flush the patching queue up to the new cursor.
 */
static void queueFlush(Binary *B, intptr_t cursor)
{
    if (B->cursor <= cursor)
        error("failed to patch instruction at address 0x%lx; \"patch\" "
            "messages were not send in reverse order", cursor);
    B->cursor = cursor;

    cursor += /*max short jmp=*/ INT8_MAX + 2 + /*max instruction size=*/15 +
        /*a bit extra=*/32;
    while (!B->Q.empty() && B->Q.back().first->addr > cursor)
    {
        auto entry = B->Q.back();
        B->Q.pop_back();
        Instr *I            = entry.first;
        const Trampoline *T = entry.second;
        for (unsigned i = 0; i < I->size; i++)
        {
            assert(I->patched.state[i] == STATE_QUEUED);
            I->patched.state[i] = STATE_INSTRUCTION;
        }
        if (patch(*B, I, T))
            stat_num_patched++;
        else
            stat_num_failed++;
    }
}

/*
 * Queue an instruction for patching.
 */
static void queuePatch(Binary *B, Instr *I, const Trampoline *T)
{
    if (!option_experimental)
    {
        // Patch queues are experimental...
        if (patch(*B, I, T))
            stat_num_patched++;
        else
            stat_num_failed++;
        return;
    }

    for (unsigned i = 0; i < I->size; i++)
    {
        assert(I->patched.state[i] == STATE_INSTRUCTION);
        I->patched.state[i] = STATE_QUEUED;
    }

    B->Q.push_front({I, T});
    queueFlush(B, I->addr);
}

/*
 * Parse a binary message.
 */
static Binary *parseBinary(const Message &msg)
{
    const char *filename = nullptr;
    Mode mode = MODE_EXECUTABLE;
    bool have_mode = false, dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_FILENAME:
                dup = dup || (filename != nullptr);
                filename = msg.params[i].value.string;
                break;
            case PARAM_MODE:
                dup = dup || have_mode;
                mode = (Mode)msg.params[i].value.integer;
                have_mode = true;
                break;
            default:
                break;
        }
    }
    if (filename == nullptr)
        error("failed to parse \"binary\" message (id=%u); missing "
            "\"filename\" parameter", msg.id);
    if (dup)
        error("failed to parse \"binary\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    Binary *B = new Binary;
    B->filename = filename;
    B->mode     = mode;
    B->cursor   = INTPTR_MAX;

    // Open the binary:
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", filename,
            strerror(errno));

    // Determine the binary size:
    struct stat buf;
    if (fstat(fd, &buf) < 0)
        error("failed to get length of file \"%s\": %s", filename,
            strerror(errno));
    size_t size = (size_t)buf.st_size;
    B->size = size;

    // Allocate extra space for file extensions.
    const size_t EXTEND_SIZE = 32 * (1ull << 30);        // 32GB
    size_t ext_size = size + EXTEND_SIZE;
    void *ptr = mmap(nullptr, ext_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to reserve %zu bytes for file buffer: %s",
            ext_size, strerror(errno));

    // Map the file (for modification):
    ptr = mmap(ptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
        fd, 0);
    if (ptr == MAP_FAILED)
    {
mmap_failed:
        error("failed to map file \"%s\": %s", filename, strerror(errno));
    }
    B->patched.bytes = (uint8_t *)ptr;
    B->patched.size  = size;

    // Parse the mmaped ELF file:
    parseElf(B->allocator, B->filename, B->patched.bytes, B->size, B->mode,
        B->elf);

    // Map the file (unmodified):
    ptr = mmap(ptr, size, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED)
        goto mmap_failed;
    B->original.bytes = (const uint8_t *)ptr;
    B->original.fd    = fd;

    // Create the state:
    ext_size = size + PAGE_SIZE;
    ext_size = (ext_size % PAGE_SIZE == 0? ext_size: ext_size + PAGE_SIZE);
    ext_size = ext_size - ext_size % PAGE_SIZE;
    ptr = mmap(ptr, ext_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr == MAP_FAILED)
        error("failed to allocate state array for file \"%s\": %s",
            filename, strerror(errno));
    B->patched.state = (uint8_t *)ptr;
    memset(B->patched.state + size, STATE_OVERFLOW, ext_size - size);

    return B;
}

/*
 * Parse an instruction message.
 */
static void parseInstruction(Binary *B, const Message &msg)
{
    intptr_t address = 0;
    size_t   length  = 0;
    off_t    offset  = 0;
    bool have_address = false, have_length = false, have_offset = false,
        dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_ADDRESS:
                dup = dup || have_address;
                address = (intptr_t)msg.params[i].value.integer;
                have_address = true;
                break;
            case PARAM_LENGTH:
                dup = dup || have_length;
                length = (size_t)msg.params[i].value.integer;
                have_length = true;
                break;
            case PARAM_OFFSET:
                dup = dup || have_offset;
                offset = (off_t)msg.params[i].value.integer;
                have_offset = true;
                break;
            default:
                break;
        }
    }
    if (!have_address)
        error("failed to parse \"instruction\" message (id=%u); missing "
            "\"address\" parameter", msg.id);
    if (!have_length)
        error("failed to parse \"instruction\" message (id=%u); missing "
            "\"length\" parameter", msg.id);
    if (length == 0 || length > 15)
        error("failed to parse \"instruction\" message (id=%u); \"length\" "
            "parameter must be within the range 1..15", msg.id);
    if (!have_offset)
        error("failed to parse \"instruction\" message (id=%u); missing "
            "\"offset\" parameter", msg.id);
    if (offset < 0)
        error("failed to parse \"instruction\" message (id=%u); the "
            "instruction offset (%zd) is negative", msg.id, offset);
    if (offset + length > B->size)
        error("failed to parse \"instruction\" message (id=%u); the "
            "instruction offset+length (%zd+%zu) overflows "
            "the end-of-file \"%s\" (with size %zu)", msg.id, offset, length,
            B->filename, B->size);
    if (dup)
        error("failed to parse \"instruction\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    size_t pcrel32_idx = 0, pcrel8_idx = 0;
    unsigned pcrel_idx = getInstrPCRelativeIndex(B->original.bytes + offset,
        length);
    if (pcrel_idx != 0)
    {
        if (length - pcrel_idx < sizeof(int32_t))
            pcrel8_idx = pcrel_idx;     // Must be pcrel8
        else
            pcrel32_idx = pcrel_idx;    // Must be pcrel32
    }
    Instr *I = new Instr(offset, address, length, B->original.bytes + offset,
        B->patched.bytes + offset, B->patched.state + offset, pcrel32_idx,
        pcrel8_idx, B->elf.pic);
    insertInstruction(B, I);
}

/*
 * Parse a patch message.
 */
static void parsePatch(Binary *B, const Message &msg)
{
    const char *trampoline = nullptr;
    off_t offset = 0;
    Metadata *meta = nullptr;
    bool have_offset = false, dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_TRAMPOLINE:
                dup = dup || (trampoline != nullptr);
                trampoline = msg.params[i].value.string;
                break;
            case PARAM_OFFSET:
                dup = dup || have_offset;
                offset = (off_t)msg.params[i].value.integer;
                have_offset = true;
                break;
            case PARAM_METADATA:
                dup = dup || (meta != nullptr);
                meta = msg.params[i].value.metadata;
                break;
            default:
                break;
        }
    }
    if (trampoline == nullptr)
        error("failed to parse \"patch\" message (id=%u); missing "
            "\"trampoline\" parameter", msg.id);
    if (!have_offset)
        error("failed to parse \"patch\" message (id=%u); missing "
            "\"offset\" parameter", msg.id);
    if (dup)
        error("failed to parse \"patch\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    auto i = B->Is.find(offset);
    if (i == B->Is.end())
        error("failed to parse \"patch\" message (id=%u); no matching "
            "instruction at offset (%zd)", msg.id, offset);
    Instr *I = i->second;
    I->metadata = meta;

    auto j = B->Ts.find(trampoline);
    if (j == B->Ts.end())
        error("failed to parse \"patch\" message (id=%u); no matching "
            "trampoline with name \"%s\"", msg.id, trampoline);
    const Trampoline *T = j->second;
    queuePatch(B, I, T);
}

/*
 * Parse an emit message.
 */
static void parseEmit(Binary *B, const Message &msg)
{
    size_t mapping_size = PAGE_SIZE;
    const char *filename = nullptr;
    Format format = FORMAT_BINARY;
    bool have_format = false, have_mapping_size = false, dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_FILENAME:
                dup = dup || (filename != nullptr);
                filename = msg.params[i].value.string;
                break;
            case PARAM_FORMAT:
                dup = dup || have_format;
                format = (Format)msg.params[i].value.integer;
                have_format = true;
                break;
            case PARAM_MAPPING_SIZE:
                dup = dup || have_mapping_size;
                mapping_size = (size_t)msg.params[i].value.integer;
                have_mapping_size = true;
                break;
            default:
                break;
        }
    }
    if (filename == nullptr)
        error("failed to parse \"emit\" message (id=%u); missing "
            "\"filename\" parameter", msg.id);
    if (mapping_size % PAGE_SIZE != 0)
        error("failed to parse \"emit\" message (id=%u); mapping size "
            "must be a multiple of the page size (%u), found %zu", msg.id,
            PAGE_SIZE, mapping_size);
    if ((mapping_size & (mapping_size - 1)) != 0)
        error("failed to parse \"emit\" message (id=%u); mapping size "
            "must be a power-of-two, found %zu", msg.id, mapping_size);
    if (dup)
        error("failed to parse \"emit\" message (id=%u); duplicate "
            "parameters detected");


    // Flush the queue:
    queueFlush(B, INTPTR_MIN);
    putchar('\n');

    // Create and optimize the mappings:
    MappingSet mappings;
    buildMappings(B->allocator, mapping_size, mappings);
    optimizeMappings(mappings);
    putchar('\n');

    // Create the patched binary:
    B->patched.size = emitElf(B, mappings, mapping_size);

    // Emit the result:
    switch (format)
    {
        case FORMAT_BINARY:
            emitBinary(filename, B->patched.bytes, B->patched.size);
            break;
        case FORMAT_PATCH:
            emitPatch(filename, /*compress=*/nullptr, B->original.fd,
                B->patched.bytes, B->patched.size);
            break;
        case FORMAT_PATCH_GZ:
            emitPatch(filename, "gzip", B->original.fd, B->patched.bytes,
                B->patched.size);
            break;
        case FORMAT_PATCH_BZIP2:
            emitPatch(filename, "bzip2", B->original.fd, B->patched.bytes,
                B->patched.size);
            break;
        case FORMAT_PATCH_XZ:
            emitPatch(filename, "xz", B->original.fd, B->patched.bytes,
                B->patched.size);
            break;
        default:
            error("failed to parse \"emit\" message (id=%u); invalid "
                "\"format\" code %u", msg.id, (unsigned)format);
    }
}

/*
 * Parse a reserve message.
 */
static void parseReserve(Binary *B, const Message &msg)
{
    bool absolute     = false;
    intptr_t address  = 0;
    intptr_t init     = 0;
    intptr_t mmap     = 0;
    size_t length     = 0;
    Trampoline *bytes = nullptr;
    int protection    = PROT_READ | PROT_EXEC;
    bool have_address = false, have_protection = false, have_init = false,
        have_mmap = false, have_length = false, have_absolute = false,
        dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_ABSOLUTE:
                dup = dup || have_absolute;
                absolute = msg.params[i].value.boolean;
                have_absolute = true;
                break;
            case PARAM_ADDRESS:
                dup = dup || have_address;
                address = (intptr_t)msg.params[i].value.integer;
                have_address = true;
                break;
            case PARAM_BYTES:
                dup = dup || (bytes != nullptr);
                bytes = msg.params[i].value.trampoline;
                break;
            case PARAM_INIT:
                dup = dup || have_init;
                init = (intptr_t)msg.params[i].value.integer;
                have_init = true;
                break;
            case PARAM_LENGTH:
                dup = dup || have_length;
                length = (size_t)msg.params[i].value.integer;
                have_length = true;
                break;
            case PARAM_MMAP:
                dup = dup || have_mmap;
                mmap = (intptr_t)msg.params[i].value.integer;
                have_mmap = true;
                break;
            case PARAM_PROTECTION:
                dup = dup || have_protection;
                protection = (int)msg.params[i].value.integer;
                have_protection = true;
                break;
            default:
                break;
        }
    }
    if (!have_address)
        error("failed to parse \"reserve\" message (id=%u); missing "
            "\"address\" parameter", msg.id);
    if (bytes == nullptr && !have_length)
        error("failed to parse \"reserve\" message (id=%u); missing "
            "\"bytes\" parameter or \"length\" parameter", msg.id);
    if (bytes != nullptr && have_length)
        error("failed to parse \"reserve\" message (id=%u); only one of "
            "the \"bytes\" or \"length\" parameters can be specified",
            msg.id);
    if (absolute && B->elf.pic)
        address = ABSOLUTE_ADDRESS(address);
    if (have_init)
    {
        if (absolute && B->elf.pic)
            init = ABSOLUTE_ADDRESS(init);
        if (bytes == nullptr || init < address ||
                init >= address + bytes->entries[0].length)
            error("failed to parse \"reserve\" message (id=%u); \"init\" "
                "parameter value (" ADDRESS_FORMAT ") is out-of-bounds",
                msg.id, ADDRESS(address));
        B->inits.push_back(init);
    }
    if (have_mmap)
    {
        if (absolute && B->elf.pic)
            mmap = ABSOLUTE_ADDRESS(mmap);
        if (bytes == nullptr || mmap < address ||
                mmap >= address + bytes->entries[0].length)
            error("failed to parse \"reserve\" message (id=%u); \"mmap\" "
                "parameter value (" ADDRESS_FORMAT ") is out-of-bounds",
                msg.id, ADDRESS(address));
        if (B->mmap != INTPTR_MIN)
            error("failed to parse \"reserve\" message (id=%u); a mmap "
                "function was previously defined", msg.id);
        B->mmap = mmap;
    }
    if (dup)
        error("failed to parse \"reserve\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    if (have_protection && bytes != nullptr)
        bytes->prot = protection;
    if (bytes != nullptr)
    {
        bytes->preload = true;
        const Alloc *A = allocate(B->allocator, address, address, bytes,
            nullptr);
        if (A == nullptr)
            error("failed to reserve address space at address "
                ADDRESS_FORMAT, ADDRESS(address));
    }
    if (have_length)
    {
        if (!reserve(B->allocator, address, address + length))
            error("failed to reserve address space at address "
                ADDRESS_FORMAT, ADDRESS(address));
    }
}

/*
 * Parse a trampoline message.
 */
static void parseTrampoline(Binary *B, const Message &msg)
{
    const char *name = nullptr;
    Trampoline *T = nullptr;
    bool dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_NAME:
                dup = dup || (name != nullptr);
                name = msg.params[i].value.string;
                break;
            case PARAM_TEMPLATE:
                dup = dup || (T != nullptr);
                T = msg.params[i].value.trampoline;
                break;
            default:
                break;
        }
    }
    if (name == nullptr)
        error("failed to parse \"template\" message (id=%u); missing "
            "\"name\" parameter", msg.id);
    if (T == nullptr)
        error("failed to parse \"template\" message (id=%u); missing "
            "\"template\" parameter", msg.id);
    if (dup)
        error("failed to parse \"template\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    auto i = B->Ts.find(name);
    if (i != B->Ts.end())
        error("failed to parse \"template\" message (id=%u); a template "
            "with name \"%s\" already exists", msg.id, name);
    B->Ts.insert(std::make_pair(name, T));
}

/*
 * Parse an option message.
 */
static void parseOptions(const Message &msg)
{
    bool disable_B1 = false, disable_B2 = false,
         disable_T1 = false, disable_T2 = false,
         disable_T3 = false;
    bool have_disable_B1 = false, have_disable_B2 = false,
         have_disable_T1 = false, have_disable_T2 = false,
         have_disable_T3 = false;
    bool dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_OPTION_DISABLE_B1:
                dup = dup || have_disable_B1;
                disable_B1 = msg.params[i].value.boolean;
                have_disable_B1 = true;
                break;
            case PARAM_OPTION_DISABLE_B2:
                dup = dup || have_disable_B2;
                disable_B2 = msg.params[i].value.boolean;
                have_disable_B2 = true;
                break;
            case PARAM_OPTION_DISABLE_T1:
                dup = dup || have_disable_T1;
                disable_T1 = msg.params[i].value.boolean;
                have_disable_T1 = true;
                break;
            case PARAM_OPTION_DISABLE_T2:
                dup = dup || have_disable_T2;
                disable_T2 = msg.params[i].value.boolean;
                have_disable_T2 = true;
                break;
            case PARAM_OPTION_DISABLE_T3:
                dup = dup || have_disable_T3;
                disable_T3 = msg.params[i].value.boolean;
                have_disable_T3 = true;
                break;
            default:
                break;
        }
    }
    if (dup)
        error("failed to parse \"option\" message (id=%u); duplicate "
            "parameters detected", msg.id);
    if (have_disable_B1)
        option_disable_B1 = disable_B1;
    if (have_disable_B2)
        option_disable_B2 = disable_B2;
    if (have_disable_T1)
        option_disable_T1 = disable_T1;
    if (have_disable_T2)
        option_disable_T2 = disable_T2;
    if (have_disable_T3)
        option_disable_T3 = disable_T3;
}

/*
 * Parse the given message.
 */
Binary *parseMessage(Binary *B, Message &msg)
{
    if (msg.method != METHOD_BINARY && B == nullptr)
        error("failed to parse message stream; got \"%s\" message (id=%u) "
            "before \"binary\" message", getMethodString(msg.method), msg.id);

    switch (msg.method)
    {
        case METHOD_BINARY:
            if (B != nullptr)
                error("failed to parse message stream; got duplicate "
                    "\"binary\" message (id=%u)", msg.id);
            return parseBinary(msg);
        case METHOD_INSTRUCTION:
            parseInstruction(B, msg);
            return B;
        case METHOD_PATCH:
            parsePatch(B, msg);
            return B;
        case METHOD_EMIT:
            parseEmit(B, msg);
            return B;
        case METHOD_RESERVE:
            parseReserve(B, msg);
            return B;
        case METHOD_TRAMPOLINE:
            parseTrampoline(B, msg);
            return B;
        case METHOD_OPTION:
            parseOptions(msg);
            return B;
        default:
            error("failed to parse message stream; got unknown message "
                "method (id=%u)", msg.id);
    }
}

