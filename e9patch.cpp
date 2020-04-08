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
bool option_is_tty         = false;
bool option_debug          = false;
bool option_disable_B1     = false;
bool option_disable_B2     = false;
bool option_disable_T1     = false;
bool option_disable_T2     = false;
bool option_disable_T3     = false;
bool option_dynamic_loader = false;
int option_aggressiveness  = 100;

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
    OPTION_AGGRESSIVENESS,
    OPTION_DEBUG,
    OPTION_DISABLE_B1,
    OPTION_DISABLE_B2,
    OPTION_DISABLE_T1,
    OPTION_DISABLE_T2,
    OPTION_DISABLE_T3,
    OPTION_DYNAMIC_LOADER,
};

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
        {"aggressiveness", true,  nullptr, OPTION_AGGRESSIVENESS},
        {"debug",          false, nullptr, OPTION_DEBUG},
        {"disable-B1",     false, nullptr, OPTION_DISABLE_B1},
        {"disable-B2",     false, nullptr, OPTION_DISABLE_B2},
        {"disable-T1",     false, nullptr, OPTION_DISABLE_T1},
        {"disable-T2",     false, nullptr, OPTION_DISABLE_T2},
        {"disable-T3",     false, nullptr, OPTION_DISABLE_T3},
        {"dynamic-loader", false, nullptr, OPTION_DYNAMIC_LOADER},
        {nullptr,          false, nullptr, 0}
    };

    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_AGGRESSIVENESS:
            {
                errno = 0;
                char *end = nullptr;
                unsigned long r = strtoul(optarg, &end, 10);
                if (errno != 0 || end == optarg ||
                        (end != nullptr && *end != '\0') || r > 100)
                    error("failed to parse argument \"%s\" to option "
                        "`--aggressiveness'; expected a number 0..100",
                        optarg);
                option_aggressiveness = r;
                break;
            }
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
            case OPTION_DYNAMIC_LOADER:
                option_dynamic_loader = true;
                break;
            default:
                error("failed to parse command-line options");
        }
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

    return 0;
}

/*
 * The initial entry point.
 */
#include <math.h>
static uintptr_t target;
int __attribute__((__section__(".text"))) main(int argc, char **argv)
{
    asm (
        "nop\n"
        "nop\n"
        "nop\n"
    );

    /*
     * Test #1: the jrcxz instruction:
     */
    asm volatile (
        "xor %ecx,%ecx\n"
        "inc %ecx\n"
        ".Ljrcx_loop:\n"
        "jrcxz .Lrcx_is_zero\n"
        "dec %ecx\n"
        "jmp .Ljrcx_loop\n"
        ".Lrcx_is_zero:\n"
    );

    /*
     * Test #2: Dynamically calculated jump target:
     */
    off_t x;
    asm volatile (
        ".Lbase:\n"
        "leaq .Lbase(%%rip),%0\n"
        "mov %0,%1\n"
        "mov $(.Ltarget-.Lbase)*(.Ltarget-.Lbase),%0\n" : "=r"(x),
            "=m"(target)
    );
    float y = (float)x;
    y = sqrt(y);
    x = (off_t)y;
    target += x;
    asm volatile (
        "jmp *%0\n"
        ".Ltarget:\n" : : "m"(target)
    );

    /*
     * Test #3: a semi-obsfuscated indirect jump to realMain().
     */
    asm volatile (
        "movabs $(realMain-main)-0x14159265, %rax\n"
        "leaq main+0x6b1db77(%rip), %rbp\n"
        "leaq 0xd63b6ee(%rbp, %rax), %rax\n"
        "jmpq *%rax\n"
        "ud2\n"
    );

    __builtin_unreachable();
}

