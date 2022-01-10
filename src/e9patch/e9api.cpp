/*
 * e9api.cpp
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
#include "e9optimize.h"
#include "e9patch.h"
#include "e9pe.h"
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
    B->diff = (off_t)I->addr - (off_t)I->offset;

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
    while (!B->Q.empty() &&
            (B->Q.back().options || B->Q.back().I->addr > cursor))
    {
        const auto &entry = B->Q.back();
        if (!entry.options)
        {
            // Patch entry
            Instr *I            = entry.I;
            const Trampoline *T = entry.T;
            for (unsigned i = 0; i < I->size; i++)
            {
                assert(I->patched.state[i] == STATE_QUEUED);
                I->patched.state[i] = STATE_INSTRUCTION;
            }
            I->debug = (option_trap_all ||
                option_trap.find(I->addr) != option_trap.end());
            if (patch(*B, I, T))
                stat_num_patched++;
            else
                stat_num_failed++;
        }
        else
        {
            // Options entry
            char * const *argv = entry.argv;
            parseOptions(argv, /*api=*/true);
            delete[] argv;
            switch (B->mode)
            {
                case MODE_ELF_EXE: case MODE_ELF_DSO:
                    B->config = option_loader_base; break;
                default:
                    break;
            }
        }
        B->Q.pop_back();
    }
}

/*
 * Queue an instruction for patching.
 */
static void queuePatch(Binary *B, Instr *I, const Trampoline *T)
{
    for (unsigned i = 0; i < I->size; i++)
    {
        assert(I->patched.state[i] == STATE_INSTRUCTION);
        I->patched.state[i] = STATE_QUEUED;
    }

    PatchEntry entry(I, T);
    B->Q.push_front(entry);
    if (!option_batch)
        queueFlush(B, I->addr);
}

/*
 * Parse a binary message.
 */
static Binary *parseBinary(const Message &msg)
{
    const char *filename = nullptr;
    Mode mode = MODE_ELF_EXE;
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
    B->output   = nullptr;
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

    // Parse the mmap'ed binary:
    switch (B->mode)
    {
        case MODE_ELF_EXE: case MODE_ELF_DSO:
            B->pic = parseElf(B);
            break;
        case MODE_PE_EXE: case MODE_PE_DLL:
            parsePE(B);
            B->pic = true;
            break;
    }

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
        pcrel8_idx, B->pic);
    insertInstruction(B, I);
}

/*
 * Parse a patch message.
 */
static void parsePatch(Binary *B, const Message &msg)
{
    const Trampoline *T = nullptr;
    off_t offset = 0;
    Metadata *meta = nullptr;
    bool have_offset = false, dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_TRAMPOLINE:
                dup = dup || (T != nullptr);
                T = msg.params[i].value.trampoline;
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
    if (T == nullptr)
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
    if (I->patch)
        error("failed to parse \"patch\" message (id=%u); instruction "
            "at address (0x%lx) is already queued for patching", msg.id,
            I->addr);
    I->patch    = true;
    I->metadata = meta;

    queuePatch(B, I, T);
}

/*
 * Parse an emit message.
 */
static void parseEmit(Binary *B, const Message &msg)
{
    const char *filename = nullptr;
    Format format = FORMAT_BINARY;
    bool have_format = false, dup = false;
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
            default:
                break;
        }
    }
    if (filename == nullptr)
        error("failed to parse \"emit\" message (id=%u); missing "
            "\"filename\" parameter", msg.id);
    if (dup)
        error("failed to parse \"emit\" message (id=%u); duplicate "
            "parameters detected");
    B->output = filename;

    // Build trampoline entry set (b4 flush)
    buildEntrySet(B);

    // Flush the queue:
    queueFlush(B, INTPTR_MIN);
    log(COLOR_NONE, '\n');

    // Create and optimize the mappings:
    MappingSet mappings;
    size_t granularity = PAGE_SIZE;
    granularity = (B->mode == MODE_PE_EXE ||
                   B->mode == MODE_PE_DLL? WINDOWS_VIRTUAL_ALLOC_SIZE:
                    granularity);
    size_t mapping_size = std::max(granularity, option_mem_mapping_size);
    buildMappings(B->allocator, mapping_size, mappings);
    switch (option_mem_granularity)
    {
        case 128:
            optimizeMappings<Key128>(B->allocator, mapping_size, granularity,
                mappings);
            break;
        case 4096:
            optimizeMappings<Key4096>(B->allocator, mapping_size, granularity,
                mappings);
            break;
        default:
            error("unimplemented granularity (%zu)",
                option_mem_granularity);
    }

    // Post-processing & optimizations:
    flattenAllTrampolines(B);
    optimizeAllJumps(B);

    // Create the patched binary:
    switch (B->mode)
    {
        case MODE_ELF_EXE: case MODE_ELF_DSO:
            B->patched.size = emitElf(B, mappings, mapping_size);
            break;
        case MODE_PE_EXE: case MODE_PE_DLL:
            B->patched.size = emitPE(B, mappings, mapping_size);
            break;
    }

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
    intptr_t fini     = 0;
    intptr_t mmap     = 0;
    size_t length     = 0;
    Trampoline *bytes = nullptr;
    int protection    = PROT_READ | PROT_EXEC;
    bool have_address = false, have_protection = false, have_init = false,
        have_fini = false, have_mmap = false, have_length = false,
        have_absolute = false, dup = false;
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
            case PARAM_FINI:
                dup = dup || have_fini;
                fini = (intptr_t)msg.params[i].value.integer;
                have_fini = true;
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
    if (absolute && B->pic)
        address = ABSOLUTE_ADDRESS(address);
    if (have_init)
    {
        if (absolute && B->pic)
            init = ABSOLUTE_ADDRESS(init);
        if (bytes == nullptr || init < address ||
                init >= address + bytes->entries[0].length)
            error("failed to parse \"reserve\" message (id=%u); \"init\" "
                "parameter value (" ADDRESS_FORMAT ") is out-of-bounds",
                msg.id, ADDRESS(address));
        B->inits.push_back(init);
    }
    if (have_fini)
    {
        if (absolute && B->pic)
            fini = ABSOLUTE_ADDRESS(fini);
        if (bytes == nullptr || fini < address ||
                fini >= address + bytes->entries[0].length)
            error("failed to parse \"reserve\" message (id=%u); \"fini\" "
                "parameter value (" ADDRESS_FORMAT ") is out-of-bounds",
                msg.id, ADDRESS(address));
        B->finis.push_back(fini);
    }
    if (have_mmap)
    {
        if (absolute && B->pic)
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
        length = getTrampolineSize(B, bytes, nullptr);
        size_t length_lo = address % PAGE_SIZE;
        size_t length_hi = PAGE_SIZE - (length_lo + length) % PAGE_SIZE;
        intptr_t address_lo = address - length_lo;
        intptr_t address_hi = address + length;
        const unsigned num_trampolines = 3;
        Trampoline *trampolines[num_trampolines] =
            {makePadding(length_lo), bytes, makePadding(length_hi)};
        intptr_t addrs[num_trampolines] =
            {address_lo, address, address_hi};
        size_t lens[num_trampolines] = {length_lo, length, length_hi};
        for (unsigned i = 0; i < num_trampolines; i++)
        {
            if (trampolines[i] == nullptr)
                continue;
            const Alloc *A = allocate(B, addrs[i], addrs[i], trampolines[i],
                nullptr);
            if (A == nullptr)
                error("failed to reserve address space at address "
                    ADDRESS_FORMAT, ADDRESS(addrs[i]));
            debug("reserved address space [prot=%c%c%c, size=%zu, bytes="
                ADDRESS_FORMAT ".." ADDRESS_FORMAT "]",
                (protection & PROT_READ? 'r': '-'),
                (protection & PROT_WRITE? 'w': '-'),
                (protection & PROT_EXEC? 'x': '-'), lens[i], ADDRESS(addrs[i]),
                ADDRESS(addrs[i] + (intptr_t)lens[i]));
        }
    }
    if (have_length)
    {
        if (!reserve(B, address, address + length))
            error("failed to reserve address space at address "
                ADDRESS_FORMAT, ADDRESS(address));
        debug("reserved address space [prot=%c%c%c, size=%zu, range="
            ADDRESS_FORMAT ".." ADDRESS_FORMAT "]",
            (protection & PROT_READ? 'r': '-'),
            (protection & PROT_WRITE? 'w': '-'),
            (protection & PROT_EXEC? 'x': '-'), length, ADDRESS(address),
            ADDRESS(address + (intptr_t)length));
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
        error("failed to parse \"trampoline\" message (id=%u); missing "
            "\"name\" parameter", msg.id);
    if (name[0] != '$')
        error("failed to parse \"trampoline\" message (id=%u); \"name\" "
            "parameter must begin with a `$', found \"%s\"", msg.id, name);
    if (T == nullptr)
        error("failed to parse \"trampoline\" message (id=%u); missing "
            "\"template\" parameter", msg.id);
    if (dup)
        error("failed to parse \"trampoline\" message (id=%u); duplicate "
            "parameters detected", msg.id);

    auto i = B->Ts.insert(std::make_pair(name, T));
    if (!i.second)
        error("failed to parse \"trampoline\" message (id=%u); a trampoline "
            "with name \"%s\" already exists", msg.id, name);
}

/*
 * Parse an option message.
 */
static void parseOptions(Binary *B, const Message &msg)
{
    char * const *argv = nullptr;
    bool dup = false;
    for (unsigned i = 0; i < msg.num_params; i++)
    {
        switch (msg.params[i].name)
        {
            case PARAM_ARGV:
                dup = dup || (argv != nullptr);
                argv = msg.params[i].value.strings;
                break;
            default:
                break;
        }
    }
    if (argv == nullptr)
        error("failed to parse \"options\" message (id=%u); missing "
            "\"argv\" parameter", msg.id);
    if (dup)
        error("failed to parse \"options\" message (id=%u); duplicate "
            "parameters detected", msg.id);
    if (B->cursor == INTPTR_MAX)
    {
        parseOptions(argv, /*api=*/true);
        delete[] argv;
    }
    else
    {
        PatchEntry entry(argv);
        B->Q.push_front(entry);
    }
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
        case METHOD_OPTIONS:
            parseOptions(B, msg);
            return B;
        default:
            error("failed to parse message stream; got unknown message "
                "method (id=%u)", msg.id);
    }
}

