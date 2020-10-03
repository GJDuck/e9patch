/*
 * e9patch.cpp
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

#include <cstdio>
#include <cstdlib>

#include <getopt.h>
#include <unistd.h>

#include "e9api.h"
#include "e9json.h"
#include "e9patch.h"

/*
 * Global options.
 */
bool option_is_tty        = false;
bool option_debug         = false;
bool option_disable_B1    = false;
bool option_disable_B2    = false;
bool option_disable_T1    = false;
bool option_disable_T2    = false;
bool option_disable_T3    = false;
bool option_experimental  = false;
bool option_static_loader = false;
bool option_same_page     = false;
bool option_trap_all      = false;
bool option_use_stack     = false;
intptr_t option_lb        = INTPTR_MIN;
intptr_t option_ub        = INTPTR_MAX;

/*
 * Global statistics.
 */
size_t stat_num_patched = 0;
size_t stat_num_failed  = 0;
size_t stat_num_B1 = 0;
size_t stat_num_B2 = 0;
size_t stat_num_T1 = 0;
size_t stat_num_T2 = 0;
size_t stat_num_T3 = 0;
size_t stat_num_virtual_mappings  = 0;
size_t stat_num_physical_mappings = 0;
size_t stat_num_virtual_bytes  = 0;
size_t stat_num_physical_bytes = 0;
size_t stat_input_file_size  = 0;
size_t stat_output_file_size = 0;

/*
 * Report an error and exit.
 */
void NO_RETURN error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s: ",
        (option_is_tty? "\33[31m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    
    putc('\n', stderr);

    _Exit(EXIT_FAILURE);
}

/*
 * Print a warning message.
 */
void warning(const char *msg, ...)
{
    fprintf(stderr, "%swarning%s: ",
        (option_is_tty? "\33[33m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    
    putc('\n', stderr);
}

/*
 * Print a debug message.
 */
void debugImpl(const char *msg, ...)
{
    fprintf(stderr, "%sdebug%s: ",
        (option_is_tty? "\33[35m": ""),
        (option_is_tty? "\33[0m" : ""));

    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);

    putc('\n', stderr);
}

/*
 * Options.
 */
enum Option
{
    OPTION_DEBUG,
    OPTION_DISABLE_SHRINK,
    OPTION_DISABLE_B1,
    OPTION_DISABLE_B2,
    OPTION_DISABLE_T1,
    OPTION_DISABLE_T2,
    OPTION_DISABLE_T3,
    OPTION_EXPERIMENTAL,
    OPTION_HELP,
    OPTION_INPUT,
    OPTION_LB,
    OPTION_OUTPUT,
    OPTION_SAME_PAGE,
    OPTION_STATIC_LOADER,
    OPTION_TRAP_ALL,
    OPTION_UB,
    OPTION_USE_STACK,
};

/*
 * Parse an integer from an optarg.
 */
static intptr_t parseIntOptArg(const char *option, const char *optarg,
    intptr_t lb, intptr_t ub)
{
    const char *optarg_0 = optarg;
    bool neg = (optarg[0] == '-');
    if (neg)
        optarg++;
    int base = 10;
    if (optarg[0] == '0' && optarg[1] == 'x')
        base = 16;
    errno = 0;
    char *end = nullptr;
    intptr_t r = (intptr_t)strtoul(optarg, &end, base);
    r = (neg? -r: r);
    if (errno != 0 || end == optarg ||
            (end != nullptr && *end != '\0') || r < lb || r > ub)
        error("failed to parse argument \"%s\" to option "
            "`%s'; expected a number %zd..%zd",
            option, optarg_0, lb, ub);
    return r;
}

/*
 * Usage.
 */
static void usage(FILE *stream, const char *progname)
{
    fprintf(stream, "usage: %s [OPTIONS]\n\n", progname);
    fputs("OPTIONS:\n", stream);
    fputs("\t--debug\n", stream);
    fputs("\t\tEnable debug log messages.\n", stream);
    fputc('\n', stream);
    fputs("\t--disable-B1, --disable-B2, --disable-T1, --disable-T2 "
        "--disable-T3\n", stream);
    fputs("\t\tDisable the corresponding tactic (B1/B2/T1/T2/T3).\n", stream);
    fputc('\n', stream);
    fputs("\t--experimental\n", stream);
    fputs("\t\tEnable experimental optimizations and extensions.\n", stream);
    fputc('\n', stream);
    fputs("\t--help, -h\n", stream);
    fputs("\t\tPrint this help message.\n", stream);
    fputc('\n', stream);
    fputs("\t--input FILE, -i FILE\n", stream);
    fputs("\t\tRead input from FILE instead of stdin.\n", stream);
    fputc('\n', stream);
    fputs("\t--lb LB\n", stream);
    fputs("\t\tSet LB to be the minimum allowable trampoline address.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--output FILE, -o FILE\n", stream);
    fputs("\t\tWrite output to FILE instead of stdout.\n", stream);
    fputc('\n', stream);
    fputs("\t--same-page\n", stream);
    fputs("\t\tDisallow trampolines from crossing page boundaries.\n", stream);
    fputc('\n', stream);
    fputs("\t--static-loader\n", stream);
    fputs("\t\tReplace patched pages statically.  By default, patched "
        "pages\n", stream);
    fputs("\t\tare loaded during program initialization as this is more\n",
        stream);
    fputs("\t\treliable for large/complex binaries.  However, this may "
        "bloat\n", stream);
    fputs("\t\tthe size of the output patched binary.\n", stream);
    fputc('\n', stream);
    fputs("\t--trap-all\n", stream);
    fputs("\t\tInsert a trap (int3) instruction at each trampoline entry.\n",
        stream);
    fputs("\t\tThis can be used for debugging with gdb.\n", stream);
    fputc('\n', stream);
    fputs("\t--ub UB\n", stream);
    fputs("\t\tSet UB to be the maximum allowable trampoline address.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--use-stack\n", stream);
    fputs("\t\tAllow the stack to be used as scratch space.  This allows\n",
        stream);
    fputs("\t\tfaster code to be emitted, but may break transparency.\n",
        stream);
    fputc('\n', stream);
}

/*
 * The real entry point.
 */
extern "C"
{
    int realMain(int argc, char **argv);
};
int realMain(int argc, char **argv)
{
    clock_t c0 = clock();

    option_is_tty = (isatty(STDERR_FILENO) != 0);
    if (getenv("E9PATCH_TTY") != nullptr)
        option_is_tty = true;
    if (getenv("E9PATCH_DEBUG") != nullptr)
        option_debug = true;

    static const struct option long_options[] =
    {
        {"debug",         false, nullptr, OPTION_DEBUG},
        {"disable-B1",    false, nullptr, OPTION_DISABLE_B1},
        {"disable-B2",    false, nullptr, OPTION_DISABLE_B2},
        {"disable-T1",    false, nullptr, OPTION_DISABLE_T1},
        {"disable-T2",    false, nullptr, OPTION_DISABLE_T2},
        {"disable-T3",    false, nullptr, OPTION_DISABLE_T3},
        {"experimental",  false, nullptr, OPTION_EXPERIMENTAL},
        {"help",          false, nullptr, OPTION_HELP},
        {"input",         true,  nullptr, OPTION_INPUT},
        {"lb",            true,  nullptr, OPTION_LB},
        {"output",        true,  nullptr, OPTION_OUTPUT},
        {"same-page",     false, nullptr, OPTION_SAME_PAGE},
        {"static-loader", false, nullptr, OPTION_STATIC_LOADER},
        {"trap-all",      false, nullptr, OPTION_TRAP_ALL},
        {"ub",            true,  nullptr, OPTION_UB},
        {"use-stack",     false, nullptr, OPTION_USE_STACK},
        {nullptr,         false, nullptr, 0}
    };

    std::string option_input("-"), option_output("-");
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "hi:o:", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_DEBUG:
                option_debug = true;
                break;
            case OPTION_DISABLE_B1:
                option_disable_B1 = true;
                break;
            case OPTION_DISABLE_B2:
                option_disable_B2 = true;
                break;
            case OPTION_DISABLE_T1:
                option_disable_T1 = true;
                break;
            case OPTION_DISABLE_T2:
                option_disable_T2 = true;
                break;
            case OPTION_DISABLE_T3:
                option_disable_T3 = true;
                break;
            case OPTION_EXPERIMENTAL:
                option_experimental = true;
                break;
            case 'h':
            case OPTION_HELP:
                usage(stdout, argv[0]);
                return EXIT_SUCCESS;
            case 'i':
            case OPTION_INPUT:
                option_input = optarg;
                break;
            case 'o':
            case OPTION_OUTPUT:
                option_output = optarg;
                break;
            case OPTION_TRAP_ALL:
                option_trap_all = true;
                break;
            case OPTION_SAME_PAGE:
                option_same_page = true;
                break;
            case OPTION_STATIC_LOADER:
                option_static_loader = true;
                break;
            case OPTION_LB:
                option_lb = parseIntOptArg("--lb", optarg, INTPTR_MIN,
                    INTPTR_MAX);
                break;
            case OPTION_UB:
                option_ub = parseIntOptArg("--ub", optarg, INTPTR_MIN,
                    INTPTR_MAX);
                break;
            case OPTION_USE_STACK:
                option_use_stack = true;
                break;
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
        }
    }

    if (option_input != "-")
    {
        FILE *input = freopen(option_input.c_str(), "r", stdin);
        if (input == nullptr)
            error("failed to open file \"%s\" for reading: %s",
                option_input.c_str(), strerror(errno));
    }
    if (option_output != "-")
    {
        FILE *output = freopen(option_output.c_str(), "w", stdout);
        if (output == nullptr)
            error("failed to open file \"%s\" for writing: %s",
                option_output.c_str(), strerror(errno));
    }
    if (isatty(STDIN_FILENO))
        warning("reading JSON-RPC from a terminal (this is probably not "
            "what you want, please use an E9PATCH frontend instead!)");
    
    Binary *B = nullptr;
    Message msg;
    size_t lineno = 1;
    while (getMessage(stdin, lineno, msg))
    {
        B = parseMessage(B, msg);
        lineno = msg.lineno;
    }
    if (B == nullptr)
        exit(EXIT_SUCCESS);

    clock_t c1 = clock();

    size_t stat_num_total = stat_num_patched + stat_num_failed;
    clock_t stat_time = c1 - c0;

    const size_t MAX_MAPPINGS = 65000;

    char percent[16];
    snprintf(percent, sizeof(percent)-1, "%.2f",
        (double)stat_num_patched / (double)stat_num_total * 100.0);
    bool approx = (stat_num_total != stat_num_patched &&
        strcmp(percent, "100.00") == 0);

    printf("\n\n-----------------------------------------------\n");
    printf("input_binary          = %s\n", B->filename);
    printf("input_mode            = %s\n",
        (B->mode == MODE_EXECUTABLE?  "EXECUTABLE": "SHARED_OBJECT"));
    printf("num_patched           = %zu / %zu (%s%s%%)\n",
        stat_num_patched, stat_num_total, (approx? "~": ""),
        percent);
    printf("num_patched_B1        = %zu / %zu (%.2f%%)\n",
        stat_num_B1, stat_num_total,
        (double)stat_num_B1 / (double)stat_num_total * 100.0);
    printf("num_patched_B2        = %zu / %zu (%.2f%%)\n",
        stat_num_B2, stat_num_total,
        (double)stat_num_B2 / (double)stat_num_total * 100.0);
    printf("num_patched_T1        = %zu / %zu (%.2f%%)\n",
        stat_num_T1, stat_num_total,
        (double)stat_num_T1 / (double)stat_num_total * 100.0);
    printf("num_patched_T2        = %zu / %zu (%.2f%%)\n",
        stat_num_T2, stat_num_total,
        (double)stat_num_T2 / (double)stat_num_total * 100.0);
    printf("num_patched_T3        = %zu / %zu (%.2f%%)\n",
        stat_num_T3, stat_num_total,
        (double)stat_num_T3 / (double)stat_num_total * 100.0);
    printf("num_virtual_mappings  = %s%zu%s%s\n",
        (option_is_tty && stat_num_virtual_mappings >= MAX_MAPPINGS? "\33[33m":
            ""),
        stat_num_virtual_mappings,
        (option_is_tty && stat_num_virtual_mappings >= MAX_MAPPINGS? "\33[0m":
            ""),
        (stat_num_virtual_mappings >= MAX_MAPPINGS?
            " (warning: may exceed default system limit)": ""));
    printf("num_physical_mappings = %zu (%.2f%%)\n",
        stat_num_physical_mappings,
        (double)stat_num_physical_mappings /
            (double)stat_num_virtual_mappings * 100.0);
    printf("num_virtual_bytes     = %zu\n", stat_num_virtual_bytes);
    printf("num_physical_bytes    = %zu (%.2f%%)\n", stat_num_physical_bytes,
        (double)stat_num_physical_bytes /
            (double)stat_num_virtual_bytes * 100.0);
    printf("input_file_size       = %zu\n", stat_input_file_size);
    printf("output_file_size      = %zu (%.2f%%)\n",
        stat_output_file_size,
        (double)stat_output_file_size / (double)stat_input_file_size * 100.0);
    printf("time_elapsed          = %zdms\n",
        stat_time * 1000 / CLOCKS_PER_SEC);
    printf("-----------------------------------------------\n");

    exit(EXIT_SUCCESS);
}

/*
 * The initial entry point.
 *
 * This includes a test-suite for e9test.sh.  The test suite includes some
 * jumps that are calculated dynamically, which is no problem for e9patch.
 */
asm (
    /*
     * Test #2: the jrcxz instruction:
     */
    ".Ltest_2:\n"
    "xor %ecx,%ecx\n"
    "inc %ecx\n"
    ".Ljrcx_loop:\n"
    "jrcxz .Lrcx_is_zero\n"
    "dec %ecx\n"
    "jmp .Ljrcx_loop\n"
    ".Lrcx_is_zero:\n"
    "jmp .Ltest_3\n"

    /*
     * Test #1: indirect jump that depends on argc:
     */
    ".Ltest_1:\n"
    "mov %rdi,%r11\n"
    "sar $48,%r11\n"
    "lea (.Ltest_2-777)(%rip),%r10\n"
    "lea 777(%r10,%r11,8),%r10\n"
    "push %r10\n"
    "ret\n"
    "ud2\n"

    /*
     * Entry point:
     */
    ".globl main\n"
    ".type main,@function\n"
    "main:\n"
    "test %rsi,%rsi\n"
    "jz .Lskip_123\n"
    "cmp $0xFFFF,%rdi\n"
    "jb .Lskip_123\n"
    "jmp .Ltest_1\n"
    ".Lskip_123:\n"

    /*
     * Test #4: a semi-obsfuscated indirect jump to realMain().
     */
    ".Ltest_4:\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "nop\n"
    "movabs $(realMain-main)-0x14159265, %rax\n"
    "leaq main+0x6b1db77(%rip), %rbp\n"
    "leaq 0xd63b6ee(%rbp, %rax), %rax\n"
    "jmpq *%rax\n"

    /*
     * Test #3: Dynamically calculated jump target:
     */
    ".Ltest_3:\n"
    "leaq .Ltest_3(%rip),%r10\n"
    "mov $(.Ltest_3-.Ltest_4)*(.Ltest_3-.Ltest_4),%rax\n"
    "pxor %xmm0,%xmm0\n"
    "cvtsi2ss %rax,%xmm0\n"
    "sqrtss %xmm0,%xmm1\n"
    "comiss %xmm1,%xmm1\n"
    "cvttss2si %xmm1,%rax\n"
    "neg %rax\n"
    "lea 4(%r10,%rax),%rax\n"
    "cmp $255,%rax\n"
    "jle .Lskip\n"
    "jmp *%rax\n"
    ".Lskip:\n"
);

