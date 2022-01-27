/*
 * Copyright (C) 2021 National University of Singapore
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
 *              examples/plugins/example.cpp -I src/e9tool/
 * 
 * To use:
 *          $ ./e9tool -M 'plugin(example).match()' \
 *                     -P 'plugin(example).patch()' program
 *          $ ./a.out
 *          Trace/breakpoint trap
 */

#include <sstream>
#include <string>

#include <sys/mman.h>
#include <getopt.h>

#include "e9plugin.h"

using namespace e9tool;

#define COUNTERS        0x789a0000        // Arbitrary

#define OPTION_ADDRESS  1
#define OPTION_LIMIT    2

static intptr_t address = COUNTERS;

/*
 * Initialize the counters and the trampoline.
 */
extern void *e9_plugin_init_v1(const Context *cxt)
{
    // The e9_plugin_init_v1() is called once per plugin by E9Tool.  This can
    // be used to emit additional E9Patch messages, such as address space
    // reservations and trampoline templates.

    static const struct option long_options[] =
    {
        {"address", required_argument, nullptr, OPTION_ADDRESS},
        {"limit",   required_argument, nullptr, OPTION_LIMIT},
        {nullptr,   no_argument      , nullptr, 0}
    };
    char * const *argv = cxt->argv->data();
    int argc = (int)cxt->argv->size();
    ssize_t limit = UINT16_MAX;
    optind = 1;
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "a:l:", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_ADDRESS: case 'a':
                address = (intptr_t)strtoull(optarg, nullptr, 0);
                break;
            case OPTION_LIMIT: case 'l':
                limit = (ssize_t)strtoull(optarg, nullptr, 0);
                break;
            default:
                fprintf(stderr, "usage:\n\n");
                fprintf(stderr, "\t-a ADDR, --address ADDR\n");
                fprintf(stderr, "\t\tPut the counters at ADDR.\n");
                fprintf(stderr, "\t-l NUM, --limit NUM\n");
                fprintf(stderr, "\t\tUse NUM as the limit.\n\n");
                exit(EXIT_FAILURE);
        }
    }

    /* 
     * This example uses 3 counters (one for calls/jumps/returns).
     * We allocate and initialize the counters.  For this, we use a
     * "reserve" E9Patch API message.
     */
    const ssize_t counters[3] = {limit, limit, limit};
    sendReserveMessage(cxt->out,
        address,                        // Memory virtual address
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

    // Increment the counter and trap if <= 0:
    //
    // mov counter(%rip),%rax
    // sub $0x1,%rax
    // mov %rax,counter(%rip)
    // jg .Lok
    // int3
    //
    code << 0x48 << ',' << 0x8b << ',' << 0x05 << ",\"$counter\",";
    code << 0x48 << ',' << 0x83 << ',' << 0xe8 << ',' << 0x01 << ',';
    code << 0x48 << ',' << 0x89 << ',' << 0x05 << ",\"$counter\",";
    code << 0x7f << ",{\"rel8\":\".Lok\"},";
    code << 0xcc << ',';
    
    // Restore state & return from trampoline:
    //
    // .Lok:
    // pop %rax
    // add $0x7f,%al
    // sahf
    // pop %rax  
    // lea 0x4000(%rsp),%rsp
    //
    code << "\".Lok\",";
    code << 0x58 << ',';
    code << 0x04 << ',' << 0x7f << ',';
    code << 0x9e << ',';
    code << 0x58 << ',';
    code << 0x48 << ',' << 0x8d << ',' << 0xa4 << ',' << 0x24 << ','
         << 0x00 << ',' << 0x40 << ',' << 0x00 << ',' << 0x00;
    
    sendTrampolineMessage(cxt->out, "$limit", code.str().c_str());

    return nullptr;
}

/*
 * We match all control-flow transfer instructions.
 */
extern intptr_t e9_plugin_match_v1(const Context *cxt)
{
    // The e9_plugin_match_v1() function is invoked once by E9Tool for each
    // disassembled instruction.  The function should return a value that is
    // used for matching.

    // For this example we return a non-zero value for all
    // control-flow-transfer instructions:
    switch (cxt->I->mnemonic)
    {
        case MNEMONIC_RET:
            return 1;
        case MNEMONIC_JB: case MNEMONIC_JBE: case MNEMONIC_JCXZ:
        case MNEMONIC_JECXZ: case MNEMONIC_JKNZD: case MNEMONIC_JKZD:
        case MNEMONIC_JL: case MNEMONIC_JLE: case MNEMONIC_JMP:
        case MNEMONIC_JNB: case MNEMONIC_JNBE: case MNEMONIC_JNL:
        case MNEMONIC_JNLE: case MNEMONIC_JNO: case MNEMONIC_JNP:
        case MNEMONIC_JNS: case MNEMONIC_JNZ: case MNEMONIC_JO:
        case MNEMONIC_JP: case MNEMONIC_JRCXZ: case MNEMONIC_JS:
        case MNEMONIC_JZ:
            return 2;
        case MNEMONIC_CALL:
            return 3;
        default:
            return 0;
    }
}

/*
 * Patch the selected instructions.
 */
extern void e9_plugin_patch_v1(const Context *cxt, Phase phase)
{
    // The e9_plugin_patch_v1() function is invoked by E9Tool in order to
    // build "patch" messages for E9Patch.  This function is invoked in three
    // main phases: CODE, DATA and METADATA, as described below.
    //
    // Patching phases:
    //
    //  - CODE    : Called once per trampoline template.
    //              Specifies the "code" part of the trampoline template that
    //              will be executed for each matching instruction.
    //
    //  - DATA    : Called once per trampoline template.
    //              Specifies the "data" part of the trampoline template that
    //              can be referenced/used by the code part.  The data must be
    //              read-only.  The data part is optional.
    //
    //  - METADATA: Called once per patched instruction.
    //              Specifies the "metadata" which instantiates any macros
    //              in the trampoline template (both code or data).  Data
    //              that is instruction-specific should be specified as
    //              metadata.  The metadata is optional.

    switch (phase)
    {
        case PHASE_CODE:
            // The trampoline code simply invokes the $limit template
            // (defined above):
            fputs("\"$limit\",", cxt->out);
            return;
        case PHASE_DATA:
            // There is no trampoline data:
            return;
        case PHASE_METADATA:
        {
            // The trampoline metadata instantiates the $counter macro with
            // the counter address corresponding to the instruction type:
            intptr_t counter = e9_plugin_match_v1(cxt);
            counter = address + (counter - 1) * sizeof(size_t);
            fprintf(cxt->out, "\"$counter\":{\"rel32\":\"0x%lx\"},", counter);
            return;
        }
        default:
            return;
    }
}

