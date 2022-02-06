/*
 * e9patch.cpp
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

#include <string>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <getopt.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#include "e9api.h"
#include "e9json.h"
#include "e9patch.h"

/*
 * Global options.
 */
bool option_is_tty             = false;
bool option_debug              = false;
bool option_batch              = false;
bool option_tactic_B1          = true;
bool option_tactic_B2          = true;
bool option_tactic_T1          = true;
bool option_tactic_T2          = true;
bool option_tactic_T3          = true;
bool option_tactic_backward_T3 = true;
unsigned option_Oepilogue      = 0;
unsigned option_Oepilogue_size = 64;
bool option_Oorder             = false;
bool option_Opeephole          = true;
unsigned option_Oprologue      = 0;
unsigned option_Oprologue_size = 64;
bool option_Oscratch_stack     = false;
intptr_t option_loader_base    = 0x20e9e9000;
int option_loader_phdr         = -1;
bool option_loader_static      = false;
size_t option_mem_granularity  = 128;
intptr_t option_mem_lb         = RELATIVE_ADDRESS_MIN;
intptr_t option_mem_ub         = RELATIVE_ADDRESS_MAX;
size_t option_mem_mapping_size = PAGE_SIZE;
bool option_mem_multi_page     = true;
intptr_t option_mem_rebase     = 0x0;
std::set<intptr_t> option_trap;
bool option_trap_all           = false;
bool option_trap_entry         = false;
static std::string option_input("-");
static std::string option_output("-");
bool option_loader_base_set    = false;
bool option_loader_phdr_set    = false;
bool option_loader_static_set  = false;
bool option_mem_rebase_set     = false;
bool option_log                = true;
int option_log_color           = COLOR_NONE;

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
 * Print logging information.
 */
void logSetColor(int color)
{
    option_log_color = color;
    if (!option_is_tty || !option_log)
        return;
    switch (color)
    {
        case COLOR_NONE:
            fputs("\33[0m", stdout); break;
        case COLOR_RED:
            fputs("\33[31m", stdout); break;
        case COLOR_GREEN:
            fputs("\33[32m", stdout); break;
        case COLOR_BLUE:
            fputs("\33[34m", stdout); break;
        case COLOR_CYAN:
            fputs("\33[36m", stdout); break;
        case COLOR_MAGENTA:
            fputs("\33[35m", stdout); break;
        case COLOR_YELLOW:
            fputs("\33[33m", stdout); break;
    }
}

/*
 * Parse an integer from an optarg.
 */
static intptr_t parseIntOptArg(const char *option, const char *optarg,
    intptr_t lb, intptr_t ub, bool hex = false)
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
    {
        if (!hex)
            error("failed to parse argument \"%s\" for the `%s' option; "
                "expected a number within the range %zd..%zd", option,
                optarg_0, lb, ub);
        else
            error("failed to parse argument \"%s\" for the `%s' option; "
                "expected a number within the range %s0x%lx..%s0x%lx",
                option, optarg_0,
                (lb < 0? "-": ""), std::abs(lb),
                (ub < 0? "-": ""), std::abs(ub));
    }
    return r;
}

/*
 * Parse a Boolean from an optarg.
 */
static bool parseBoolOptArg(const char *option, const char *optarg)
{
    if (optarg == nullptr)
        return true;
    if (strcmp(optarg, "true") == 0 || strcmp(optarg, "1") == 0)
        return true;
    else if (strcmp(optarg, "false") == 0 || strcmp(optarg, "0") == 0)
        return false;
    error("failed to parse argument \"%s\" for the `%s' option; "
        "expected a Boolean [true, false]", option, optarg);
}

/*
 * Usage.
 */
static void usage(FILE *stream, const char *progname)
{
    fprintf(stream, "usage: %s [OPTIONS]\n\n"
        "OPTIONS:\n"
        "\n"
        "\t-Oepilogue=N\n"
        "\t\tAppend a epilogue of up to N instructions to the end of each\n"
        "\t\ttrampoline.  This may enhance -Opeephole.\n"
        "\t\tDefault: 0 (disabled)\n"
        "\n"
        "\t-Oepilogue-size=N\n"
        "\t\tAdditionally limits -Oepilogue to N instruction bytes.\n"
        "\t\tDefault: 64\n"
        "\n"
        "\t-Oorder[=false]\n"
        "\t\tEnables [disables] the ordering of trampolines with respect\n"
        "\t\tto the original instruction ordering (as much as is possible).\n"
        "\t\tThis may enhance -Opeephole.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t-Opeephole[=false]\n"
        "\t\tEnables [disables] jump peephole optimization.\n"
        "\t\tDefault: true (enabled)\n"
        "\n"
        "\t-Oprologue=N\n"
        "\t\tPrepend a prologue of up to N instructions to the start of each\n"
        "\t\ttrampoline.  This may enhance -Opeephole.  Requires --batch.\n"
        "\t\tDefault: 0 (disabled)\n"
        "\n"
        "\t-Oprologue-size=N\n"
        "\t\tAdditionally limits -Oprologue to N instruction bytes.\n"
        "\t\tDefault: 64\n"
        "\n"
        "\t-Oscratch-stack[=false]\n"
        "\t\tAllow the stack to be used as scratch space.  This allows\n"
        "\t\tfaster code to be emitted, but may break transparency.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t--batch[=false]\n"
        "\t\tRewrite the binary in one batch rather than incrementally.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t--debug[=false]\n"
        "\t\tEnable [disable] debug log messages.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t--help, -h\n"
        "\t\tPrint this help message.\n"
        "\n"
        "\t--input FILE, -i FILE\n"
        "\t\tRead input from FILE instead of stdin.\n"
        "\n"
        "\t--output FILE, -o FILE\n"
        "\t\tWrite output to FILE instead of stdout.\n"
        "\n"
        "\t--loader-base=ADDR\n"
        "\t\tSet ADDR to be the base address of the program loader.\n"
        "\t\tOnly relevant for ELF binaries.\n"
        "\t\tDefault: 0x20e9e9000\n"
        "\n"
        "\t--loader-phdr=PHDR\n"
        "\t\tOverwrite the corresponding PHDR to load the loader.  Valid\n"
        "\t\tvalues are \"note\", \"relro\", and \"stack\" for PT_NOTE, "
            "PT_RELRO\n"
        "\t\tand PT_GNU_STACK respectively, or \"any\" to select any of the\n"
        "\t\tabove values.  Note that selecting any value other than "
            "\"note\"\n"
        "\t\tmay relax the memory permissions in the patched binary.\n"
        "\t\tOnly relevant for ELF binaries.\n"
        "\t\tDefault: note\n"
        "\n"
        "\t--loader-static[=false]\n"
        "\t\tEnable [disable] the static loading of patched pages.  By\n"
        "\t\tdefault, patched pages are loaded dynamically during program\n"
        "\t\tinitialization (this is more reliable for complex binaries).\n"
        "\t\tHowever, this can also bloat patched binary size.\n"
        "\t\tOnly relevant for ELF binaries.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t--log=[false]\n"
        "\t\tEnable [disable] log output.\n"
        "\t\tDefault: true (enabled)\n"
        "\n"
        "\t--mem-granularity=SIZE\n"
        "\t\tSet SIZE to be the granularity used for the physical page\n"
        "\t\tgrouping memory optimization.  Higher values result in\n"
        "\t\thigher CPU+memory usage during rewriting, but also smaller\n"
        "\t\toutput binary files (i.e., better compression).  Here, SIZE\n"
        "\t\tmust be one of {128,4096}.\n"
        "\t\tDefault: 128\n"
        "\n"
        "\t--mem-lb=LB\n"
        "\t\tSet LB to be the minimum allowable trampoline address.\n"
        "\n"
        "\t--mem-ub=UB\n"
        "\t\tSet UB to be the maximum allowable trampoline address.\n"
        "\n"
        "\t--mem-mapping-size=SIZE\n"
        "\t\tSet the mapping size to SIZE which must be a power-of-two\n"
        "\t\tmultiple of the page size (%zu).  Larger values result in\n"
        "\t\tless virtual mappings being used, but larger output binary\n"
        "\t\tfiles (i.e., worse compression).\n"
        "\t\tDefault: %zu\n"
        "\n"
        "\t--mem-multi-page[=false]\n"
        "\t\tEnable [disable] trampolines that cross page boundaries.\n"
        "\t\tDefault: true (enabled)\n"
        "\n"
        "\t--mem-rebase[=ADDR]\n"
        "\t\tRebase the binary to the absolute address ADDR.  Only\n"
        "\t\trelevant for Windows PE binaries.  The special values \"auto\"\n"
        "\t\tor \"random\" will cause a suitable base address to be chosen\n"
        "\t\tautomatically/randomly.  The special value \"none\" leaves the\n"
        "\t\toriginal base intact.\n"
        "\t\tDefault: none (disabled)\n"
        "\n"
        "\t--tactic-B1[=false]\n"
        "\t--tactic-B2[=false]\n"
        "\t--tactic-T1[=false]\n"
        "\t--tactic-T2[=false]\n"
        "\t--tactic-T3[=false]\n"
        "\t\tEnables [disables] the corresponding tactic (B1/B2/T1/T2/T3).\n"
        "\t\tDefault: true (enabled)\n"
        "\n"
        "\t--tactic-backward-T3[=false]\n"
        "\t\tEnable [disables] backward jumps for tactic T3.\n"
        "\t\tDefault: true (enabled)\n"
        "\n"
        "\t--trap=ADDR\n"
        "\t\tInsert a trap (int3) instruction at the trampoline entry for\n"
        "\t\tthe instruction at address ADDR.  This can be used to debug\n"
        "\t\tthe trampoline using GDB.\n"
        "\n"
        "\t--trap-all[=false]\n"
        "\t\tEnable [disable] the insertion of a trap (int3) instruction at\n"
        "\t\tall trampoline entries.\n"
        "\t\tDefault: false (disabled)\n"
        "\n"
        "\t--trap-entry[=false]\n"
        "\t\tEnable [disable] the insertion of a trap (int3) at the program\n"
        "\t\tloader entry-point.\n"
        "\t\tDefault: false (disabled)\n"
        "\n",
        progname, PAGE_SIZE, PAGE_SIZE);
}

/*
 * Options.
 */
enum Option
{
    OPTION_BATCH,
    OPTION_DEBUG,
    OPTION_HELP,
    OPTION_INPUT,
    OPTION_LOADER_BASE,
    OPTION_LOADER_PHDR,
    OPTION_LOADER_STATIC,
    OPTION_LOG,
    OPTION_MEM_GRANULARITY,
    OPTION_MEM_LB,
    OPTION_MEM_MAPPING_SIZE,
    OPTION_MEM_MULTI_PAGE,
    OPTION_MEM_REBASE,
    OPTION_MEM_UB,
    OPTION_OEPILOGUE,
    OPTION_OEPILOGUE_SIZE,
    OPTION_OORDER,
    OPTION_OPEEPHOLE,
    OPTION_OPROLOGUE,
    OPTION_OPROLOGUE_SIZE,
    OPTION_OSCRATCH_STACK,
    OPTION_OUTPUT,
    OPTION_TACTIC_B1,
    OPTION_TACTIC_B2,
    OPTION_TACTIC_T1,
    OPTION_TACTIC_T2,
    OPTION_TACTIC_T3,
    OPTION_TACTIC_BACKWARD_T3,
    OPTION_TRAP,
    OPTION_TRAP_ALL,
    OPTION_TRAP_ENTRY,
};

/*
 * Parse options.
 */
void parseOptions(char * const argv[], bool api)
{
    int argc;
    for (argc = 0; argv[argc] != nullptr; argc++)
        ;
    const int req_arg = required_argument, opt_arg = optional_argument,
              no_arg  = no_argument;
    static const struct option long_options[] =
    {
        {"Oepilogue",          req_arg, nullptr, OPTION_OEPILOGUE},
        {"Oepilogue-size",     req_arg, nullptr, OPTION_OEPILOGUE_SIZE},
        {"Oorder",             opt_arg, nullptr, OPTION_OORDER},
        {"Opeephole",          opt_arg, nullptr, OPTION_OPEEPHOLE},
        {"Oprologue",          req_arg, nullptr, OPTION_OPROLOGUE},
        {"Oprologue-size",     req_arg, nullptr, OPTION_OPROLOGUE_SIZE},
        {"Oscratch-stack",     opt_arg, nullptr, OPTION_OSCRATCH_STACK},
        {"batch",              opt_arg, nullptr, OPTION_BATCH},
        {"debug",              opt_arg, nullptr, OPTION_DEBUG},
        {"help",               no_arg,  nullptr, OPTION_HELP},
        {"input",              req_arg, nullptr, OPTION_INPUT},
        {"loader-base",        req_arg, nullptr, OPTION_LOADER_BASE},
        {"loader-phdr",        req_arg, nullptr, OPTION_LOADER_PHDR},
        {"loader-static",      opt_arg, nullptr, OPTION_LOADER_STATIC},
        {"log",                opt_arg, nullptr, OPTION_LOG},
        {"mem-granularity",    req_arg, nullptr, OPTION_MEM_GRANULARITY},
        {"mem-lb",             req_arg, nullptr, OPTION_MEM_LB},
        {"mem-mapping-size",   req_arg, nullptr, OPTION_MEM_MAPPING_SIZE},
        {"mem-multi-page",     opt_arg, nullptr, OPTION_MEM_MULTI_PAGE},
        {"mem-rebase",         req_arg, nullptr, OPTION_MEM_REBASE},
        {"mem-ub",             req_arg, nullptr, OPTION_MEM_UB},
        {"output",             req_arg, nullptr, OPTION_OUTPUT},
        {"tactic-B1",          opt_arg, nullptr, OPTION_TACTIC_B1},
        {"tactic-B2",          opt_arg, nullptr, OPTION_TACTIC_B2},
        {"tactic-T1",          opt_arg, nullptr, OPTION_TACTIC_T1},
        {"tactic-T2",          opt_arg, nullptr, OPTION_TACTIC_T2},
        {"tactic-T3",          opt_arg, nullptr, OPTION_TACTIC_T3},
        {"tactic-backward-T3", opt_arg, nullptr, OPTION_TACTIC_BACKWARD_T3},
        {"trap",               req_arg, nullptr, OPTION_TRAP},
        {"trap-all",           opt_arg, nullptr, OPTION_TRAP_ALL},
        {"trap-entry",         opt_arg, nullptr, OPTION_TRAP_ENTRY},
        {nullptr,              no_arg,  nullptr, 0}
    };

    optind = 1;
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "hi:o:", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_HELP: case OPTION_INPUT: case OPTION_OUTPUT:
            case 'h': case 'i': case 'o':
                if (api)
                    error("option `%s' cannot be invoked via the JSON-RPC API",
                        argv[optind-1]);
                break;
            default:
                break;
        }
        switch (opt)
        {
            case OPTION_BATCH:
                option_batch = parseBoolOptArg("--batch", optarg);
                break;
            case OPTION_DEBUG:
                option_debug = parseBoolOptArg("--debug", optarg);
                break;
            case 'h':
            case OPTION_HELP:
                usage(stdout, argv[0]);
                exit(EXIT_SUCCESS);
            case 'i':
            case OPTION_INPUT:
                option_input = optarg;
                break;
            case OPTION_OEPILOGUE:
                option_Oepilogue =
                    (unsigned)parseIntOptArg("-Oepilogue", optarg, 0, 64);
                break;
            case OPTION_OEPILOGUE_SIZE:
                option_Oepilogue_size =
                    (unsigned)parseIntOptArg("-Oepilogue-size", optarg, 0,
                        512);
                break;
            case OPTION_OORDER:
                option_Oorder = parseBoolOptArg("-Oorder", optarg);
                break;
            case OPTION_OPEEPHOLE:
                option_Opeephole = parseBoolOptArg("-Opeephole", optarg);
                break;
            case OPTION_OPROLOGUE:
                option_Oprologue =
                    (unsigned)parseIntOptArg("-Oprologue", optarg, 0, 64);
                break;
            case OPTION_OPROLOGUE_SIZE:
                option_Oprologue_size =
                    (unsigned)parseIntOptArg("-Oprologue-size", optarg, 0,
                        512);
                break;
            case OPTION_OSCRATCH_STACK:
                option_Oscratch_stack =
                    parseBoolOptArg("-Oscratch-stack", optarg);
                break;
            case 'o':
            case OPTION_OUTPUT:
                option_output = optarg;
                break;
            case OPTION_TACTIC_B1:
                option_tactic_B1 =
                    parseBoolOptArg("--tactic-B1", optarg);
                break;
            case OPTION_TACTIC_B2:
                option_tactic_B2 =
                    parseBoolOptArg("--tactic-B2", optarg);
                break;
            case OPTION_TACTIC_T1:
                option_tactic_T1 =
                    parseBoolOptArg("--tactic-T1", optarg);
                break;
            case OPTION_TACTIC_T2:
                option_tactic_T2 =
                    parseBoolOptArg("--tactic-T2", optarg);
                break;
            case OPTION_TACTIC_T3:
                option_tactic_T3 =
                    parseBoolOptArg("--tactic-T3", optarg);
                break;
            case OPTION_TACTIC_BACKWARD_T3:
                option_tactic_backward_T3 =
                    parseBoolOptArg("--tactic-backward-T3", optarg);
                break;
            case OPTION_TRAP:
                option_trap.insert(parseIntOptArg("--trap", optarg, 0,
                    INTPTR_MAX, /*hex=*/true));
                break;
            case OPTION_TRAP_ALL:
                option_trap_all = parseBoolOptArg("--trap-all", optarg);
                break;
            case OPTION_TRAP_ENTRY:
                option_trap_entry = parseBoolOptArg("--trap-entry", optarg);
                break;
            case OPTION_LOADER_BASE:
                option_loader_base_set = true;
                option_loader_base = parseIntOptArg("--loader-base", optarg,
                    0x0, 0x800000000, /*hex=*/true);
                if (option_loader_base % PAGE_SIZE != 0)
                    error("failed to parse argument \"%s\" for the "
                        "`--loader-base' option; the loader base address "
                        "must be a multiple of the page size (%d)", optarg,
                        PAGE_SIZE);
                break;
            case OPTION_LOADER_PHDR:
                option_loader_phdr_set = true;
                if (strcmp(optarg, "any") == 0)
                    option_loader_phdr = -1;
                else if (strcmp(optarg, "relro") == 0)
                    option_loader_phdr = PT_GNU_RELRO;
                else if (strcmp(optarg, "stack") == 0)
                    option_loader_phdr = PT_GNU_STACK;
                else if (strcmp(optarg, "note") == 0)
                    option_loader_phdr = PT_NOTE;
                else
                    error("failed to parse argument \"%s\" for the "
                        "`--loader-phdr' option; argument must be one of "
                        "{note,relro,stack,any}", optarg);
                break;
            case OPTION_LOADER_STATIC:
                option_loader_static_set = true;
                option_loader_static =
                    parseBoolOptArg("--loader-static", optarg);
                break;
            case OPTION_LOG:
                option_log = parseBoolOptArg("--log", optarg);
                break;
            case OPTION_MEM_GRANULARITY:
                option_mem_granularity = parseIntOptArg("--mem-granularity",
                    optarg, INTPTR_MIN, INTPTR_MAX);
                switch (option_mem_granularity)
                {
                    case 128: case 4096:
                        break;
                    default:
                        error("failed to parse argument \"%s\" for the "
                            "`--mem-granularity' option; granularity size "
                            "must be one of {128,4096}", optarg);
                }
                break;
            case OPTION_MEM_LB:
                option_mem_lb = parseIntOptArg("--mem-lb", optarg,
                    RELATIVE_ADDRESS_MIN, RELATIVE_ADDRESS_MAX, /*hex=*/true);
                break;
            case OPTION_MEM_UB:
                option_mem_ub = parseIntOptArg("--mem-ub", optarg,
                    RELATIVE_ADDRESS_MIN, RELATIVE_ADDRESS_MAX, /*hex=*/true);
                break;
            case OPTION_MEM_MAPPING_SIZE:
                option_mem_mapping_size = parseIntOptArg("--mem-mapping-size",
                    optarg, INTPTR_MIN, INTPTR_MAX);
                if (option_mem_mapping_size % PAGE_SIZE != 0)
                    error("failed to parse argument \"%s\" for the "
                        "`--mem-mapping-size' option; mapping size must be "
                        "a multiple of the page size (%d)", optarg,
                        PAGE_SIZE);
                if ((option_mem_mapping_size & (option_mem_mapping_size - 1))
                        != 0)
                    error("failed to parse argument \"%s\" for the "
                        "`--mem-mapping-size' option; mapping size must be "
                        "a power-of-two", optarg);
                break;
            case OPTION_MEM_MULTI_PAGE:
                option_mem_multi_page =
                    parseBoolOptArg("--mem-multi-page", optarg);
                break;
            case OPTION_MEM_REBASE:
                option_mem_rebase_set = true;
                if (strcmp(optarg, "auto") == 0)
                    option_mem_rebase = OPTION_REBASE_AUTO;
                else if (strcmp(optarg, "random") == 0)
                    option_mem_rebase = OPTION_REBASE_RANDOM;
                else if (strcmp(optarg, "none") == 0)
                    option_mem_rebase = OPTION_REBASE_NONE;
                else
                    option_mem_rebase = parseIntOptArg("--mem-rebase", optarg,
                        0x100000000ll, 0xffff00000000ll, /*hex=*/true);
                break;
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
        }
    }
    if (optind != argc)
        error("failed to parse command-line options; extraneous non-option "
            "argument \"%s\", try `--help' for more information",
            argv[optind]);
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
    option_is_tty = (isatty(STDERR_FILENO) != 0);
    parseOptions(argv);

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
            "what you want, please use E9Tool instead!)");
    
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

    struct rusage usage;
    memset(&usage, 0x0, sizeof(usage));
    if (getrusage(RUSAGE_SELF, &usage) < 0)
        warning("failed to get resource usage measures: %s", strerror(errno));

    size_t stat_num_total = stat_num_patched + stat_num_failed;
    size_t stat_time = usage.ru_utime.tv_sec * 1000 +
                       usage.ru_utime.tv_usec / 1000 +
                       usage.ru_stime.tv_sec * 1000 +
                       usage.ru_stime.tv_usec / 1000;
    size_t stat_memory = usage.ru_maxrss;

    ssize_t MAX_MAPPINGS = 65530;
    const ssize_t MAX_MAPPINGS_DELTA = 128;
    FILE *stream = fopen("/proc/sys/vm/max_map_count", "r");
    if (stream != nullptr)
    {
        if (fscanf(stream, "%zd", &MAX_MAPPINGS) != 1)
            ;
        fclose(stream);
    }

    char percent[16];
    snprintf(percent, sizeof(percent)-1, "%.2f",
        (double)stat_num_patched / (double)stat_num_total * 100.0);
    bool approx = (stat_num_total != stat_num_patched &&
        strcmp(percent, "100.00") == 0);

    const char *mode_str = "???";
    switch (B->mode)
    {
        case MODE_ELF_EXE:
            mode_str = "Linux ELF executable"; break;
        case MODE_ELF_DSO:
            mode_str = "Linux ELF dynamic shared object"; break;
        case MODE_PE_EXE:
            mode_str = "Windows PE executable"; break;
        case MODE_PE_DLL:
            mode_str = "Windows PE dynamic link library"; break;
    }

    log(COLOR_NONE, '\n');
    printf("-----------------------------------------------\n");
    printf("mode                  = %s\n", mode_str);
    printf("input_binary          = %s\n", B->filename);
    printf("output_binary         = %s\n", B->output);
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
    printf("num_virtual_mappings  = %s%zu%s\n",
        (option_is_tty &&
            (ssize_t)stat_num_virtual_mappings >=
                MAX_MAPPINGS - MAX_MAPPINGS_DELTA?
            "\33[33m": ""),
        stat_num_virtual_mappings,
        (option_is_tty &&
            (ssize_t)stat_num_virtual_mappings >=
                MAX_MAPPINGS - MAX_MAPPINGS_DELTA?
            "\33[0m": ""));
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
    printf("time_elapsed          = %zums\n", stat_time);
    printf("memory_used           = %zuKB\n", stat_memory);
    printf("-----------------------------------------------\n");

    if ((ssize_t)stat_num_virtual_mappings >= MAX_MAPPINGS - MAX_MAPPINGS_DELTA)
        warning("the number of virtual mappings (%zu) %s the default "
            "system limit (%zd); this can be fixed by either:\n"
            "\t(1) raising the limit, e.g.:\n"
            "\t    sudo sysctl -w vm.max_map_count=%zu\n"
            "\t(2) rewriting the binary with a larger mapping size\n"
            "\t    (see the `--compression' option for E9Tool).",
                stat_num_virtual_mappings,
                ((ssize_t)stat_num_virtual_mappings >= MAX_MAPPINGS?
                    "exceeds": "may exceed"),
                MAX_MAPPINGS, stat_num_virtual_mappings + 1000,
                option_mem_mapping_size);

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

#ifndef NDEBUG
/*
 * ASAN options.
 */
extern "C"
{
    /*
     * E9Patch deliberately leaks memory & leaves it to the OS to clean-up.
     */
    const char *__asan_default_options()
    {
        return "detect_leaks=0";
    }
}
#endif

