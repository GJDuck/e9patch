/*
 * Copyright (C) 2020 National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * NOTE: As a special exception, this file is under the MIT license.  The
 *       rest of the E9Patch/E9Tool source code is under the GPLv3 license.
 */

/*
 * This is an example E9Tool plugin.  It implements a limit on control-flow
 * transfer instructions such as calls, jumps, and returns.  When the limit
 * is reached, it will execute the int3 instruction generating a SIGTRAP.
 *
 * To compile:
 *          $ g++ -std=c++11 -fPIC -shared -o example.so -O2 \
 *              examples/plugins/example.cpp -I . -I capstone/include/
 * 
 * To use:
 *          $ ./e9tool -M 'plugin[example]' -A 'plugin[example]' program
 *          $ ./a.out
 *          Trace/breakpoint trap
 */

#include <sstream>
#include <string>

#include <sys/mman.h>

#include "e9plugin.h"

using namespace e9frontend;

#define COUNTERS         0x789a0000        // Arbitrary

/*
 * Initialize the counters and the trampoline.
 */
extern void *e9_plugin_init_v1(FILE *out, const e9frontend::ELF *elf)
{
    /* 
     * This example uses 3 counters (one for calls/jumps/returns).
     * We allocate and initialize the counters to UINT16_MAX (or the value
     * of the CFLIMIT environment variable) and place the counters at the
     * virtual address COUNTERS.  For this, we use a "reserve" E9Patch API
     * message.
     */
    ssize_t limit = UINT16_MAX;
    const char *limit_str = getenv("LIMIT");
    if (limit_str != nullptr)
        limit = (ssize_t)atoll(limit_str);
    const ssize_t counters[3] = {limit, limit, limit};
    sendReserveMessage(out,
        (intptr_t)COUNTERS,             // Memory virtual address
        (const uint8_t *)counters,      // Memory contents
        sizeof(counters),               // Memory size
        (PROT_READ | PROT_WRITE));      // Memory protections

    /*
     * Mext we need to define the trampoline template using a "trampoline"
     * E9Patch API message.
     */

    // The trampoline template is specified using a form of annotated
    // machine code.  For more information about the trampoline template
    // language, please see e9patch-programming-guide.md
 
    // Save state:
    // 
    // lea -0x4000(%rsp),%rsp
    // push %rax
    // seto %al
    // lahf
    // push %rax
    //
    std::stringstream code;
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << 0x00 << ',' << 0xc0 << ',' << 0xff << ',' << 0xff << ',';
    code << 0x50 << ',';
    code << 0x0f << ',' << 0x90 << ',' << 0xc0 << ',';
    code << 0x9f << ',';
    code << 0x50 << ',';

    // Increment the counter and branch if <= 0:
    //
    // mov counter(%rip),%rax
    // sub $0x1,%rax
    // mov %rax,counter(%rip)
    // jle .Ltrap
    //
    code << 0x48 << ',' << 0x8b << ',' << 0x05 << ",\"$counter\",";
    code << 0x48 << ',' << 0x83 << ',' << 0xe8 << ',' << 0x01 << ',';
    code << 0x48 << ',' << 0x89 << ',' << 0x05 << ",\"$counter\",";
    code << 0x7e << ",{\"rel8\":\".Ltrap\"},";
    
    // Restore state & return from trampoline:
    //
    // .Lcont:
    // pop %rax
    // add $0x7f,%al
    // sahf
    // pop %rax  
    // lea 0x4000(%rsp),%rsp
    // $instruction
    // $continue
    //
    code << "\".Lcont\",";
    code << 0x58 << ',';
    code << 0x04 << ',' << 0x7f << ',';
    code << 0x9e << ',';
    code << 0x58 << ',';
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << 0x00 << ',' << 0x40 << ',' << 0x00 << ',' << 0x00 << ',';
    code << "\"$instruction\",";
    code << "\"$continue\",";
    
    // Trap:
    //
    // .Ltrap:
    // int3
    // jmp .Lcont
    code << "\".Ltrap\",";
    code << 0xcc << ',';
    code << 0xeb << ",{\"rel8\":\".Lcont\"}";

    sendTrampolineMessage(out, "cflimit", code.str().c_str());

    return nullptr;
}

/*
 * We match all control-flow transfer instructions.
 */
extern intptr_t e9_plugin_match_v1(FILE *out, const e9frontend::ELF *elf,
    csh handle, off_t offset, const cs_insn *I, void *context)
{
    const cs_detail *detail = I->detail;
    for (uint8_t i = 0; i < detail->groups_count; i++)
    {
        switch (detail->groups[i])
        {
            case CS_GRP_CALL:
            case CS_GRP_JUMP:
            case CS_GRP_RET:
                return 1;
            default:
                break;
        }
    }

    return 0;
}

/*
 * Patch the selected instructions.
 */
extern void e9_plugin_patch_v1(FILE *out, const e9frontend::ELF *elf,
    csh handle, off_t offset, const cs_insn *I, void *context)
{
    Metadata metadata[2];
    const cs_detail *detail = I->detail;
    intptr_t counter = -1;
    for (uint8_t i = 0; counter < 0 && i < detail->groups_count; i++)
    {
        switch (detail->groups[i])
        {
            case CS_GRP_CALL:
                counter = COUNTERS + 0 * sizeof(size_t);
                break;
            case CS_GRP_JUMP:
                counter = COUNTERS + 1 * sizeof(size_t);
                break;
            case CS_GRP_RET:
                counter = COUNTERS + 2 * sizeof(size_t);
                break;
            default:
                break;
        }
    }
    if (counter < 0)
        return;

    // We instantiate the trampoline template with $counter pointing to
    // the counter corresponding to the instruction type:
    metadata[0].name = "counter";
    std::string buf;
    buf += "{\"rel32\":";
    buf += std::to_string(counter);
    buf += '}';
    metadata[0].data = buf.c_str();
    
    metadata[1].name = nullptr;
    metadata[1].data = nullptr;

    // Send a "patch" E9Patch API message.
    sendPatchMessage(out, "cflimit", offset, metadata);
}

