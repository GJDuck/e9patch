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

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <regex>
#include <set>
#include <string>

#include <dlfcn.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <elf.h>

#define PAGE_SIZE       4096
#define MAX_ACTIONS     (1 << 16)

/*
 * Options.
 */
static std::string option_format("binary");
static std::string option_output("");
static std::vector<std::pair<const char *, char *>> option_plugin;

#include "e9action.h"
#include "e9csv.h"
#include "e9elf.h"
#include "e9metadata.h"
#include "e9misc.h"
#include "e9parser.h"
#include "e9plugin.h"
#include "e9tool.h"
#include "e9x86_64.h"

using namespace e9tool;

/*
 * Backend info.
 */
struct Backend
{
    FILE *out;                      // JSON RPC output.
    pid_t pid;                      // Backend process ID.
};

/*
 * Excluded locations.
 */
struct Exclude
{
    intptr_t lo;
    intptr_t hi;
};

/*
 * Disassembler desync information.
 */
struct Desync
{
    intptr_t lo;
    intptr_t hi;
    intptr_t addr;
    const char *section;
    uint8_t byte;
};

/*
 * Spawn e9patch backend instance.
 */
static void spawnBackend(const char *prog,
    const std::vector<const char *> &options, Backend &backend)
{
    int fds[2];
    if (pipe(fds) != 0)
        error("failed to open pipe to backend process: %s", strerror(errno));
    pid_t pid = fork();
    if (pid == 0)
    {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0)
            error("failed to dup backend process pipe file descriptor "
                "(%d): %s", fds[0], strerror(errno));
        close(fds[0]);
        const char *argv[options.size() + 2];
        prog = findBinary(prog, /*exe=*/true, /*dot=*/true);
        argv[0] = "e9patch";
        unsigned i = 1;
        for (const char *option: options)
            argv[i++] = option;
        argv[i] = nullptr;
        execvp(prog, (char * const *)argv);
        error("failed to execute backend process \"%s\": %s", argv[0],
            strerror(errno));
    }
    else if (pid < 0)
        error("failed to fork backend process: %s", strerror(errno));

    close(fds[0]);
    FILE *out = fdopen(fds[1], "w");
    if (out == nullptr)
        error("failed to open backend process stream: %s", strerror(errno));

    backend.out = out;
    backend.pid = pid;
}

/*
 * Wait for e9patch instance to terminate.
 */
static void waitBackend(const Backend &backend)
{
    fclose(backend.out);

    if (backend.pid == 0)
        return;
    int status;
    do
    {
        if (waitpid(backend.pid, &status, WUNTRACED | WCONTINUED) < 0)
            error("failed to wait for backend process (%d): %s",
                backend.pid, strerror(errno));
    }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        error("backend process (%d) exitted with a non-zero status (%d)",
            backend.pid, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        error("backend process (%d) killed by signal (%s)", backend.pid,
            strsignal(WTERMSIG(status)));
}

/*
 * Open a new plugin object.
 */
static std::map<const char *, Plugin *, CStrCmp> plugins;
Plugin *openPlugin(const char *basename)
{
    std::string filename(basename);
    if (!hasSuffix(filename, ".so"))
        filename += ".so";
    const char *pathname = realpath(filename.c_str(), nullptr);
    if (pathname == nullptr)
        error("failed to create path for plugin \"%s\"; %s", basename,
            strerror(errno));
    auto i = plugins.find(pathname);
    if (i != plugins.end())
    {
        free((char *)pathname);
        return i->second;
    }

    void *handle = dlopen(pathname, RTLD_LOCAL | RTLD_LAZY);
    if (handle == nullptr)
        error("failed to load plugin \"%s\": %s", pathname, dlerror());

    Plugin *plugin = new Plugin;
    plugin->filename  = pathname;
    plugin->handle    = handle;
    plugin->context   = nullptr;
    plugin->result    = 0;
    plugin->initFunc  = (PluginInit)dlsym(handle, "e9_plugin_init_v1");
    plugin->eventFunc = (PluginEvent)dlsym(handle, "e9_plugin_event_v1");
    plugin->matchFunc = (PluginMatch)dlsym(handle, "e9_plugin_match_v1");
    plugin->patchFunc = (PluginPatch)dlsym(handle, "e9_plugin_patch_v1");
    plugin->finiFunc  = (PluginFini)dlsym(handle, "e9_plugin_fini_v1");
    if (plugin->initFunc == nullptr &&
            plugin->eventFunc == nullptr &&
            plugin->patchFunc == nullptr &&
            plugin->finiFunc == nullptr)
        error("failed to load plugin \"%s\"; the shared "
            "object does not export any plugin API functions",
            plugin->filename);

    plugin->argv.push_back(strDup(basename));
    for (auto &entry: option_plugin)
    {
        if (entry.first == nullptr)
            continue;
        if (strcmp(entry.first, basename) != 0)
            continue;
        if (entry.second != nullptr)
            plugin->argv.push_back(entry.second);
        delete entry.first;
        entry.first = entry.second = nullptr;
    }
    plugin->argv.shrink_to_fit();
    plugins.insert({plugin->filename, plugin});
    return plugin;
}

/*
 * Notify all plugins of a new instruction.
 */
static void notifyPlugins(FILE *out, const ELF *elf,
    const std::vector<Instr> &Is, Event event)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->eventFunc == nullptr)
            continue;
        Context cxt = {out, &plugin->argv, plugin->context, elf, &Is, -1,
            nullptr, -1};
        plugin->eventFunc(&cxt, event);
    }
}

/*
 * Get the match value for all plugins.
 */
static void matchPlugins(FILE *out, const ELF *elf,
    const std::vector<Instr> &Is, size_t idx, const InstrInfo *I)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->matchFunc == nullptr)
            continue;
        Context cxt = {out, &plugin->argv, plugin->context, elf, &Is,
            (ssize_t)idx, I, -1};
        plugin->result = plugin->matchFunc(&cxt);
    }
}

/*
 * Initialize all plugins.
 */
static void initPlugins(FILE *out, const ELF *elf)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->initFunc == nullptr)
            continue;
        Context cxt = {out, &plugin->argv, nullptr, elf, nullptr, -1,
            nullptr, -1};
        plugin->context = plugin->initFunc(&cxt);
    }
}

/*
 * Finalize all plugins.
 */
static void finiPlugins(FILE *out, const ELF *elf)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->finiFunc == nullptr)
            continue;
        Context cxt = {out, &plugin->argv, plugin->context, elf, nullptr,
            -1, nullptr, -1};
        plugin->finiFunc(&cxt);
    }
}

/*
 * Deprecated feature error.
 */
NO_RETURN void deprecatedPatch(const char *what)
{
    error(
        "the \"%s\" syntax has been deprecated!\n"
        "\n"
        "Please use the following syntax instead:%s\n"
        "\t--action PATCH            ---> --patch PATCH\n"
        "\t-A PATCH                  ---> -P PATCH\n"
        "\tpassthru                  ---> empty\n"
        "\tcall f(...)@bin           ---> f(...)@bin\n"
        "\tcall[after] f(...)@bin    ---> after f(...)@bin\n"
        "\tcall[replace] f(...)@bin  ---> replace f(...)@bin\n"
        "\tcall[naked] f(...)@bin    ---> f<naked>(...)@bin\n"
        "\tcall[cond] f(...)#bin     ---> if f(...)@bin break\n"
        "\tcall[condjump] f(...)@bin ---> if f(...)@bin goto%s\n"
        "\n"
        "Note that the behaviour of matching/patching option combinations has "
            "also\n"
        "changed.  See the e9tool-user-guide.md for more information.\n",
        what, (option_is_tty? "\33[33m": ""), (option_is_tty? "\33[0m": ""));
}

/*
 * Parse an exclusion.
 */
static Exclude parseExcludeBound(Parser &parser, const char *str,
    const ELF &elf)
{
    Exclude bound = {INTPTR_MAX, INTPTR_MIN};
    int t = parser.getToken();
    bool neg = false;
    switch (t)
    {
        case '-':
            neg = true;
            // Fallthrough:
        case '+':
            parser.expectToken(TOKEN_INTEGER);
            // Fallthrough:
        case TOKEN_INTEGER:
        {
            intptr_t b = (neg? -parser.i: parser.i);
            bound = {b, b};
            break;
        }
        case '&':
            t = parser.getToken();
            // Fallthrough:
        default:
        {
            std::string name;
            if (t == '.')
            {
                t = parser.getToken();
                name += '.';
            }
            if (t != TOKEN_STRING && t != TOKEN_NAME)
                parser.unexpectedToken();
            name += parser.s;
            const Elf64_Shdr *shdr = getELFSection(&elf, name.c_str());
            if (shdr != nullptr)
            {
                bound = {elf.base + (intptr_t)shdr->sh_addr,
                         elf.base + (intptr_t)shdr->sh_addr +
                            (intptr_t)shdr->sh_size};
                break;
            }
            const Elf64_Sym *sym = getELFDynSym(&elf, name.c_str());
            if (sym == nullptr)
                sym = getELFSym(&elf, name.c_str());
            if (sym != nullptr && sym->st_shndx != SHN_UNDEF)
            {
                bound = {elf.base + (intptr_t)sym->st_value,
                         elf.base + (intptr_t)sym->st_value};
                break;
            }

            intptr_t val = getELFPLTEntry(&elf, name.c_str());
            if (val != INTPTR_MIN)
            {
                bound = {val, val};
                break;
            }
            warning("ignoring exclusion \"%s\"; no such symbol or "
                "section \"%s\" in \"%s\"", str, name.c_str(), elf.filename);
            return bound;
        }
    }
    if (parser.peekToken() == '.')
    {
        parser.getToken();
        switch (parser.getToken())
        {
            case TOKEN_START:
                bound.hi = bound.lo;
                break;
            case TOKEN_END:
                bound.lo = bound.hi;
                break;
            default:
                parser.unexpectedToken();
        }
    }
    neg = false;
    intptr_t offset = 0;
    switch (parser.peekToken())
    {
        case '-':
            neg = true;
            // Fallthrough
        case '+':
            parser.getToken();
            parser.expectToken(TOKEN_INTEGER);
            offset = parser.i;
            if (offset < INT32_MIN || offset > INT32_MAX)
                error("failed to parse exclusion \"%s\"; offset %ld is "
                    "out-of-range %zd..%zd", str, offset, INT32_MIN,
                    INT32_MAX);
            offset = (neg? -offset: offset);
            bound.lo += offset;
            bound.hi += offset;
            break;
        default:
            break;
    }
    return bound;
}
static Exclude parseExclude(const ELF &elf, const char *str)
{
    Parser parser(str, "exclusion", elf);

    Exclude lb = parseExcludeBound(parser, str, elf);
    if (lb.lo == INTPTR_MAX && lb.hi == INTPTR_MIN)
        return lb;
    Exclude ub = lb;
    if (parser.peekToken() == TOKEN_DOTDOT)
    {
        parser.getToken();
        ub = parseExcludeBound(parser, str, elf);
        if (ub.lo == INTPTR_MAX && lb.hi == INTPTR_MIN)
            return ub;
    }
    parser.expectToken(TOKEN_EOF);
    Exclude exclude = {std::min(lb.lo, ub.hi), std::max(lb.lo, ub.hi)};
    if (exclude.lo == exclude.hi)
        warning("ignoring empty exclusion \"%s\" (0x%lx..0x%lx)",
            str, exclude.lo, exclude.hi);
    else
        debug("excluding \"%s\" (0x%lx..0x%lx)", str, exclude.lo, exclude.hi);
    return exclude;
}

/*
 * Matching.
 */
struct Matching
{
    std::vector<Action *> actions;
    
    Matching(std::vector<Action *> &&actions) : actions(std::move(actions))
    {
        ;
    }
};
struct MatchingCmp
{
    bool operator()(const Matching *m1, const Matching *m2)
    {
        for (size_t i = 0; ; i++)
        {
            if (i >= m1->actions.size())
                return (i < m2->actions.size());
            else if (i >= m2->actions.size())
                return false;
            if (m1->actions[i] < m2->actions[i])
                return true;
            if (m1->actions[i] > m2->actions[i])
                return false;
        }
    }
};
struct MatchingCache
{
    std::map<const Matching *, size_t, MatchingCmp> cache;
    std::vector<const Matching *> matchings;
};

/*
 * Matching.
 */
static void match(const std::vector<Action *> &actions, const ELF &elf,
    const std::vector<Instr> &Is, size_t idx, const InstrInfo *I,
    std::vector<Action *> &matching)
{
    for (auto *action: actions)
    {
        if (!matchEval(action->match, elf, Is, idx, I))
            continue;
        matching.push_back(action);
    }
}

/*
 * Save matching.
 */
static size_t saveMatching(std::vector<Action *> &matching, const InstrInfo *I,
    MatchingCache &Ms)
{
    // Check for existing:
    Matching M(std::move(matching));
    auto i = Ms.cache.find(&M);
    if (i != Ms.cache.end())
        return i->second;

    // Check if valid (at most one replace):
    bool seen_replace = false, seen_break = false;
    for (const auto *action: matching)
        for (const auto *patch: action->patch)
            seen_break = seen_break ||
                (patch->kind == PATCH_BREAK && patch->pos == POS_BEFORE);
    for (const auto *action: matching)
    {
        for (const auto *patch: action->patch)
        {
            if (patch->pos != POS_REPLACE)
                continue;
            if (seen_replace && !seen_break)
                error("multiple matching \"replace\" trampolines detected "
                    "for instruction \"%s\" at address 0x%lx", I->string.instr,
                    I->address);
            seen_replace = true;
            seen_break = seen_break || (patch->kind == PATCH_BREAK);
        }
    }

    // Add to cache:
    size_t idx = Ms.matchings.size();
    Matching *N = new Matching(std::move(M.actions));
    Ms.cache.insert({N, idx});
    Ms.matchings.push_back(N);
    return idx;
}

/*
 * Exclusion.
 */
static size_t exclude(const std::vector<Exclude> &excludes, intptr_t addr)
{
    if (excludes.size() == 0)
        return 0;
    ssize_t lo = 0, hi = (ssize_t)excludes.size()-1;
    while (lo <= hi)
    {
        ssize_t mid = (lo + hi) / 2;
        const Exclude &exclude = excludes[mid];
        if (addr < exclude.lo)
            hi = mid-1;
        else if (addr > exclude.hi)
            lo = mid+1;
        else
            return exclude.hi - addr;
    }
    return 0;
}

/*
 * Send an instruction message (if necessary).
 */
static bool sendInstructionMessage(FILE *out, Instr &I, intptr_t addr)
{
    if (std::abs((intptr_t)I.address - addr) >
            INT8_MAX + /*sizeof(short jmp)=*/2 + /*max instruction size=*/15)
        return false;
    if (I.emitted)
        return true;
    I.emitted = true;
    sendInstructionMessage(out, I.address, I.size, I.offset);
    return true;
}

/*
 * Metadata.
 */
struct Metadata
{
    const Action * const action;
    size_t idx;
};

/*
 * Send a trampoline.
 */
static bool sendTrampoline(FILE *out, const Action *action, size_t idx,
    Context *cxt, std::vector<Metadata> &metadata)
{
    const Patch *patch = action->patch[idx];

    const Plugin *plugin = nullptr;
    if (patch->kind == PATCH_PLUGIN)
    {
        plugin = patch->plugin;
        if (plugin->patchFunc != nullptr)
        {
            cxt->argv    = &plugin->argv;
            cxt->context = plugin->context;
            plugin->patchFunc(cxt, PHASE_CODE);
        }
    }
    else
    {
        sendString(out, patch->name);
        sendSeparator(out);
        if (patch->kind == PATCH_BREAK)
            return true;
    }

    bool found = false;
    switch (patch->kind)
    {
        case PATCH_PLUGIN:
            plugin = patch->plugin;
            if (plugin->patchFunc == nullptr)
                break;
            // Fallthrough
        case PATCH_PRINT: case PATCH_CALL:
            for (const auto &entry: metadata)
            {
                const Patch *prev = entry.action->patch[entry.idx];
                if (strcmp(prev->name, patch->name) == 0)
                {
                    found = true;
                    break;
                }
            }
            if (found)
                break;
            metadata.push_back({action, idx});
            break;
        default:
            break;
    }
    return false;
}

/*
 * Check if the target is compatible with the input binary.
 */
#define CONFIG_ERRNO        0x1
#define CONFIG_MUTEX        0x2
static void checkCompatible(const ELF &elf, const ELF &target)
{
    const Elf64_Sym *config = getELFDynSym(&target, "_stdlib_config");
    switch (elf.type)
    {
        case BINARY_TYPE_PE_EXE: case BINARY_TYPE_PE_DLL:
            if (config != nullptr)
                error("binary \"%s\" is incompatible with Windows/PE "
                    "instrumentation; the \"stdlib.c\" library supports "
                    "Linux/ELF only", target.filename);
            return;
        case BINARY_TYPE_ELF_EXE:
            if (elf.dynlink || config == nullptr)
                return;
            if ((config->st_value & CONFIG_ERRNO) == 0 ||
                    (config->st_value & CONFIG_MUTEX) == 0)
                error("binary \"%s\" is incompatible with statically linked "
                    "Linux/ELF executable instrumentation; please recompile "
                    "with the `-DNO_GLIBC=1' option",
                    target.filename);
            return;
        default:
            return;
    }
}

/*
 * Options.
 */
enum Option
{
    OPTION_ACTION,
    OPTION_BACKEND,
    OPTION_COMPRESSION,
    OPTION_DSYNC,
    OPTION_DTHRESHOLD,
    OPTION_DEBUG,
    OPTION_EXCLUDE,
    OPTION_EXECUTABLE,
    OPTION_FORMAT,
    OPTION_HELP,
    OPTION_MATCH,
    OPTION_NO_WARNINGS,
    OPTION_PATCH,
    OPTION_PLT,
    OPTION_PLUGIN,
    OPTION_OPTION,
    OPTION_OUTPUT,
    OPTION_SEED,
    OPTION_SHARED,
    OPTION_STATIC_LOADER,
    OPTION_SYNTAX,
    OPTION_TRAP,
    OPTION_TRAP_ALL,
};

/*
 * Action parsing.
 */
struct ActionEntry
{
    std::vector<std::string> match;
    std::vector<std::string> patch;
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
    {
        error("failed to parse argument \"%s\" for the `%s' option; "
            "expected a number within the range %zd..%zd", option,
            optarg_0, lb, ub);
    }
    return r;
}

/*
 * Entry.
 */
int main_2(int argc, char **argv)
{
    /*
     * Parse options.
     */
    const int req_arg = required_argument, /*opt_arg = optional_argument,*/
              no_arg  = no_argument;
    static const struct option long_options[] =
    {
        {"action",        req_arg, nullptr, OPTION_ACTION},
        {"backend",       req_arg, nullptr, OPTION_BACKEND},
        {"compression",   req_arg, nullptr, OPTION_COMPRESSION},
        {"Dsync",         req_arg, nullptr, OPTION_DSYNC},
        {"Dthreshold",    req_arg, nullptr, OPTION_DTHRESHOLD},
        {"debug",         no_arg,  nullptr, OPTION_DEBUG},
        {"exclude",       req_arg, nullptr, OPTION_EXCLUDE},
        {"executable",    no_arg,  nullptr, OPTION_EXECUTABLE},
        {"format",        req_arg, nullptr, OPTION_FORMAT},
        {"help",          no_arg,  nullptr, OPTION_HELP},
        {"match",         req_arg, nullptr, OPTION_MATCH},
        {"no-warnings",   no_arg,  nullptr, OPTION_NO_WARNINGS},
        {"patch",         req_arg, nullptr, OPTION_PATCH},
        {"plt",           no_arg,  nullptr, OPTION_PLT},
        {"plugin",        req_arg, nullptr, OPTION_PLUGIN},
        {"option",        req_arg, nullptr, OPTION_OPTION},
        {"output",        req_arg, nullptr, OPTION_OUTPUT},
        {"seed",          req_arg, nullptr, OPTION_SEED},
        {"shared",        no_arg,  nullptr, OPTION_SHARED},
        {"static-loader", no_arg,  nullptr, OPTION_STATIC_LOADER},
        {"syntax",        req_arg, nullptr, OPTION_SYNTAX},
        {"trap",          req_arg, nullptr, OPTION_TRAP},
        {"trap-all",      no_arg,  nullptr, OPTION_TRAP_ALL},
        {nullptr,         no_arg,  nullptr, 0}
    }; 
    option_is_tty = isatty(STDERR_FILENO);
    std::vector<const char *> option_options;
    unsigned option_compression_level = 9;
    bool option_plt = false;
    char option_optimization_level = '2';
    bool option_executable = false, option_shared = false,
        option_static_loader = false;
    std::string option_backend("");
    std::set<intptr_t> option_trap;
    std::vector<std::string> option_match;
    std::vector<std::string> option_patch;
    std::vector<ActionEntry> option_actions;
    std::vector<std::string> option_exclude;
    int option_sync = 64, option_threshold = 2;
    srand(0xe9e9e9e9);
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "A:c:E:hM:o:O:P:s",
            long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_ACTION:
            case 'A':
                deprecatedPatch("--action/-A");
            case OPTION_BACKEND:
                option_backend = optarg;
                break;
            case OPTION_COMPRESSION:
            case 'c':
                option_compression_level = (unsigned)parseIntOptArg(
                    "--compression/-c", optarg, 0, 9);
                break;
            case OPTION_DSYNC:
                option_sync = (int)parseIntOptArg("--Dsync", optarg,
                    0, UINT16_MAX);
                break;
            case OPTION_DTHRESHOLD:
                option_threshold = (int)parseIntOptArg("--Dthreshold", optarg,
                    0, 10);
                break;
            case OPTION_DEBUG:
                option_debug = true;
                break;
            case OPTION_EXCLUDE:
            case 'E':
                option_exclude.push_back(optarg);
                break;
            case OPTION_EXECUTABLE:
                option_executable = true;
                break;
            case OPTION_FORMAT:
                option_format = optarg;
                if (option_format != "binary" &&
                        option_format != "json" &&
                        option_format != "patch" &&
                        option_format != "patch.gz" &&
                        option_format != "patch.bz2" &&
                        option_format != "patch.xz")
                    error("bad value \"%s\" for `--format' option; "
                        "expected one of \"binary\", \"json\", \"patch\", "
                        "\"patch.gz\", \"patch.bz2\", or \"patch.xz\"",
                        optarg);
                break;
            case OPTION_HELP:
            case 'h':
                usage(stdout, argv[0]);
                return EXIT_SUCCESS;

            case OPTION_OPTION:
                option_options.push_back(optarg);
                break;
            case OPTION_MATCH:
            case 'M':
            {
                if (option_patch.size() > 0)
                {
                    ActionEntry entry;
                    entry.match.swap(option_match);
                    entry.patch.swap(option_patch);
                    option_actions.emplace_back(entry);
                }
                std::string match(optarg);
                option_match.emplace_back(match);
                break;
            }
            case OPTION_PATCH:
            case 'P':
            {
                if (option_match.size() == 0)
                    error("failed to parse command-line arguments; "
                        "the `--patch'/`-P' option must be preceded by "
                        "one or more `--match'/`-M' options");
                std::string patch(optarg);
                option_patch.emplace_back(patch);
                break;
            }
            case OPTION_PLT:
                option_plt = true;
                break;
            case OPTION_PLUGIN:
            {
                size_t i;
                for (i = 0; optarg[i] != '\0' && optarg[i] != ':'; i++)
                    ;
                if (optarg[i] != ':')
                    error("bad value \"%s\" for `--plugin'; "
                        "expected a plugin:option pair", optarg);
                char *key = strDup(optarg, i);
                char *val = strDup(optarg+i+1);
                option_plugin.push_back({key, val});
                break;
            }
            case OPTION_OUTPUT:
            case 'o':
                option_output = optarg;
                break;
            case 'O':
                option_optimization_level = -1;
                switch (optarg[0])
                {
                    case '0': case '1': case '2': case '3': case 's':
                        option_optimization_level = optarg[0];
                        break;
                }
                if (option_optimization_level < 0 || optarg[1] != '\0')
                    error("bad value \"%s\" for `-O' option; "
                        "expected one of -O0,-O1,-O2,-O3,-Os", optarg);
                break;
            case OPTION_NO_WARNINGS:
                option_no_warnings = true;
                break;
            case OPTION_SEED:
            {
                unsigned long r = (unsigned long)parseIntOptArg(
                    "--seed", optarg, 0, RAND_MAX);
                srand((unsigned)r);
                break;
            }
            case OPTION_SHARED:
                option_shared = true;
                break;
            case OPTION_STATIC_LOADER:
            case 's':
                option_static_loader = true;
                break;
            case OPTION_SYNTAX:
                if (strcmp(optarg, "ATT") == 0)
                    option_intel_syntax = false;
                else if (strcmp(optarg, "intel") == 0)
                    option_intel_syntax = true;
                else
                    error("bad value \"%s\" for `--syntax' option; "
                        "expected \"ATT\" or \"intel\"", optarg);
                break;
            case OPTION_TRAP:
            {
                errno = 0;
                char *end = nullptr;
                unsigned long r = strtoul(optarg, &end, 0);
                if (errno != 0 || end == optarg ||
                        (end != nullptr && *end != '\0') || r > INTPTR_MAX)
                    error("bad value \"%s\" for `--trap' option; "
                        "expected an address", optarg);
                option_trap.insert(r);
                break;
            }
            case OPTION_TRAP_ALL:
                option_trap_all = true;
                break;
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
                return EXIT_FAILURE;
        }
    }
    if (optind != argc-1)
    {
        error("missing input file; try `--help' for more information");
        return EXIT_FAILURE;
    }
    if (option_match.size() > 0)
    {
        if (option_patch.size() == 0)
            error("failed to parse command-line arguments; the `--match'/`-M' "
                "option must be followed by one or more `--patch'/`-P' "
                "options");
        ActionEntry entry;
        entry.match.swap(option_match);
        entry.patch.swap(option_patch);
        option_actions.emplace_back(entry);
    }
    if (option_actions.size() > MAX_ACTIONS)
        error("failed to parse command-line arguments; the total number of "
            "match/patch pairs (%zu) exceeds the maximum (%zu)",
            option_actions.size(), MAX_ACTIONS);
    if (option_shared && option_executable)
        error("failed to parse command-line arguments; both the `--shared' "
            "and `--executable' options cannot be used at the same time");

    /*
     * Parse the ELF file.
     */
    const char *filename = argv[optind];
    bool exe = (option_executable? true:
               (option_shared? false: !isLibraryFilename(filename)));
    filename = findBinary(filename, exe, /*dot=*/true);
    ELF &elf = *parseBinary(filename);

    /*
     * Patch the match/action pairs.
     */
    std::vector<Action *> actions;
    for (const auto &entry: option_actions)
    {
        if (entry.match.size() == 0)
            error("failed to parse action; the `--action' or `-A' option "
                "must be preceded by one or more `--match' or `-M' options");
        
        MatchExpr *match = nullptr;
        for (const auto &str: entry.match)
        {
            MatchExpr *expr = parseMatch(elf, str.c_str());
            match = (match == nullptr? expr:
                new MatchExpr(MATCH_OP_AND, match, expr));
        }
        std::vector<const Patch *> patch;
        for (const auto &str: entry.patch)
        {
            const Patch *P = parsePatch(elf, str.c_str());
            patch.push_back(P);
            if (P->kind == PATCH_BREAK)
                break;
        }
        Action *action = new Action(match, std::move(patch));
        actions.push_back(action);
    }
    option_actions.clear();
    for (auto &entry: option_plugin)
    {
        if (entry.first != nullptr)
            error("failed to find plugin \"%s\" for `--plugin=%s:%s'",
                entry.first, entry.first, entry.second);
    }
    option_plugin.clear();

    /*
     * Parse exclusions.
     */
    std::vector<Exclude> excludes;
    for (const auto &str: option_exclude)
    {
        Exclude exclude = parseExclude(elf, str.c_str());
        if (exclude.lo < exclude.hi)
            excludes.push_back(exclude);
    }
    std::map<intptr_t, Exclude> eidx;
    for (auto exclude: excludes)
    {
        auto i = eidx.lower_bound(exclude.lo);
        while (i != eidx.end())
        {
            auto &entry = i->second;
            if (entry.hi >= exclude.lo && entry.lo <= exclude.hi)
            {
                // Overlaps, so absorb it
                exclude.lo = std::min(exclude.lo, entry.lo);
                exclude.hi = std::max(exclude.hi, entry.hi);
                eidx.erase(i++);
            }
            else if (entry.lo > exclude.hi)
                break;
            else
                ++i;
        }
        eidx.insert({exclude.hi, exclude});
    }
    excludes.clear();
    for (const auto &entry: eidx)
        excludes.push_back(entry.second);
    eidx.clear();

    /*
     * The ELF file seems OK, spawn and initialize the e9patch backend.
     */
    if (option_output == "")
    {
        // Choose a default name:
        switch (elf.type)
        {
            case BINARY_TYPE_ELF_DSO:
                option_output = "a.so"; break;
            case BINARY_TYPE_ELF_PIE: case BINARY_TYPE_ELF_EXE:
                option_output = "a.out"; break;
            case BINARY_TYPE_PE_EXE:
                option_output = "a.exe"; break;
            case BINARY_TYPE_PE_DLL:
                option_output = "a.dll"; break;
        }
    }
    Backend backend;
    std::vector<const char *> options;
    if (option_format == "json")
    {
        // Pseudo-backend:
        backend.pid = 0;
        if (option_output == "-")
            backend.out = stdout;
        else
        {
            std::string filename(option_output);
            if (!hasSuffix(option_output, ".json"))
                filename += ".json";
            backend.out = fopen(filename.c_str(), "w");
            if (backend.out == nullptr)
                error("failed to open output file \"%s\": %s",
                    filename.c_str(), strerror(errno));
        }
    }
    else
    {
        if (option_backend == "")
        {
            // By default, we use the "e9patch" that exists in the same dir
            // as "e9tool".
            getExePath(option_backend);
            option_backend += "e9patch";
        }
        spawnBackend(option_backend.c_str(), options, backend);
    }
    FILE *out = backend.out;

    /*
     * Send binary message.
     */
    const char *mode = "???";
    switch (elf.type)
    {
        case BINARY_TYPE_ELF_DSO:
            mode = (option_executable? "elf.exe": "elf.dso"); break;
        case BINARY_TYPE_ELF_PIE:
            mode = (option_shared? "elf.dso": "elf.exe"); break;
        case BINARY_TYPE_ELF_EXE:
            mode = "elf.exe"; break;
        case BINARY_TYPE_PE_EXE:
            mode = "pe.exe"; break;
        case BINARY_TYPE_PE_DLL:
            mode = "pe.dll"; break;
    }
    sendBinaryMessage(out, mode, filename);
 
    /*
     * Send options message.
     */
    const char *mapping_size[10] = {"2097152", "1048576", "524288", "262144",
        "131072", "65536", "32768", "16384", "8192", "4096"};
    if (option_compression_level != 9)
    {
        options.push_back("--mem-mapping-size");
        options.push_back(mapping_size[option_compression_level]);
    }
    if (option_static_loader)
        options.push_back("--loader-static");
    if (option_trap_all)
        options.push_back("--trap-all");
    switch (option_optimization_level)
    {
        case '0':
            options.push_back("-Oprologue=0");
            options.push_back("-Oprologue-size=0");
            options.push_back("-Oepilogue=0");
            options.push_back("-Oepilogue-size=0");
            options.push_back("-Opeephole=false");
            options.push_back("-Oorder=false");
            options.push_back("-Oscratch-stack=false");
            options.push_back("--mem-granularity=128");
            break;
        case '1':
            options.push_back("-Oprologue=0");
            options.push_back("-Oprologue-size=0");
            options.push_back("-Oepilogue=8");
            options.push_back("-Oepilogue-size=16");
            options.push_back("-Oorder=false");
            options.push_back("-Opeephole=true");
            options.push_back("-Oscratch-stack=true");
            options.push_back("--mem-granularity=128");
            break;
        case '2':
            options.push_back("-Oprologue=0");
            options.push_back("-Oprologue-size=0");
            options.push_back("-Oepilogue=32");
            options.push_back("-Oepilogue-size=64");
            options.push_back("-Oorder=true");
            options.push_back("-Opeephole=true");
            options.push_back("-Oscratch-stack=true");
            options.push_back("--mem-granularity=128");
            break;
        case '3':
            options.push_back("--batch");
            options.push_back("-Oprologue=64");
            options.push_back("-Oprologue-size=512");
            options.push_back("-Oepilogue=64");
            options.push_back("-Oepilogue-size=512");
            options.push_back("-Oorder=true");
            options.push_back("-Opeephole=true");
            options.push_back("-Oscratch-stack=true");
            options.push_back("--mem-granularity=4096");
            break;
        case 's':
            options.push_back("-Oprologue=0");
            options.push_back("-Oprologue-size=0");
            options.push_back("-Oepilogue=0");
            options.push_back("-Oepilogue-size=0");
            options.push_back("-Opeephole=true");
            options.push_back("-Oorder=true");
            options.push_back("-Oscratch-stack=true");
            options.push_back("--mem-granularity=4096");
            break;
    }
    for (const char *option: option_options)
        options.push_back(option);
    if (options.size() > 0)
        sendOptionsMessage(out, options);
    for (auto addr: option_trap)
    {
        options.clear();
        options.push_back("--trap");
        std::string val;
        val += std::to_string(addr);
        options.push_back(val.c_str());
        sendOptionsMessage(out, options);
    }

    /*
     * Initialize all plugins:
     */
    initPlugins(out, &elf);

    /*
     * Send trampoline definitions:
     */
    bool have_print = false, have_empty = false, have_trap = false;
    std::map<const char *, ELF *, CStrCmp> files;
    std::set<const char *, CStrCmp> have_call;
    std::set<int> have_exit;
    intptr_t file_addr = 0x70000000;
    for (auto *action: actions)
    {
        for (const auto *patch: action->patch)
        {
            switch (patch->kind)
            {
                case PATCH_PRINT:
                    have_print = true;
                    break;
                case PATCH_EMPTY:
                    have_empty = true;
                    break;
                case PATCH_TRAP:
                    have_trap = true;
                    break;
                case PATCH_EXIT:
                {
                    int status = patch->status;
                    auto i = have_exit.find(status);
                    if (i == have_exit.end())
                    {
                        sendExitTrampolineMessage(out, elf.type, 
                            status);
                        have_exit.insert(status);
                    }
                    break;
                }
                case PATCH_CALL:
                {
                    // Step (1): Ensure the ELF file is loaded:
                    ELF *target = nullptr;
                    auto i = files.find(patch->filename);
                    if (i == files.end())
                    {
                        // Load the called ELF file into the address space:
                        target = parseELF(patch->filename, file_addr);
                        checkCompatible(elf, *target);
                        sendELFFileMessage(out, target);
                        files.insert({patch->filename, target});
                        file_addr  = target->end + 2 * PAGE_SIZE;
                        file_addr -= file_addr % PAGE_SIZE;
                    }
                    else
                        target = i->second;
                    patch->elf = target;

                    // Step (2): Create the trampoline:
                    auto j = have_call.find(patch->name);
                    if (j == have_call.end())
                    {
                        sendCallTrampolineMessage(out, patch->name,
                            patch->args, elf.type, patch->abi, patch->jmp,
                            patch->pos);
                        have_call.insert(patch->name);
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }
    if (have_empty)
        sendEmptyTrampolineMessage(out);
    if (have_print)
        sendPrintTrampolineMessage(out, elf.type);
    if (have_trap)
        sendTrapTrampolineMessage(out);

    /*
     * Disassemble the ELF file.
     */
    initDisassembler();
    std::vector<Instr> Is;
    std::vector<Desync> desyncs;
    // Step (1): Find the locations of all instructions:
    for (const auto *shdr: elf.exes)
    {
        const char *section   = elf.strs + shdr->sh_name;
        if (!option_plt &&
                (strcmp(section, ".plt") == 0 ||
                 strcmp(section, ".plt.got") == 0))
            continue;   // Exclude .plt/,plt.got by default
        size_t section_size   = (size_t)shdr->sh_size;
        off_t section_offset  = (off_t)shdr->sh_offset;
        intptr_t section_addr = (intptr_t)shdr->sh_addr;

        const uint8_t *start = elf.data + section_offset;
        const uint8_t *code  = start, *end = start + section_size;
        size_t size          = section_size;
        off_t offset         = section_offset;
        intptr_t address     = section_addr;

        int sync = 0;
        bool first = true;
        while (true)
        {
            size_t skip = exclude(excludes, address);
            if (skip > 0)
            {
                address += skip;
                offset  += skip;
                size     = (skip > size? 0: size - skip);
                code    += skip;
                sync     = 0;
                first    = true;
            }

            Instr I;
            const uint8_t *bytes = code;
            if (!decode(&code, &size, &offset, &address, &I))
                break;
            I.first = first;
            first = false;

            int score = suspiciousness(bytes, I.size);
            if (option_debug && !I.data)
            {
                InstrInfo J;
                getInstrInfo(&elf, &I, &J);
                debug("%s0x%lx%s: disassemble %s%s%s%s",
                    (option_is_tty? "\33[31m": ""),
                    J.address,
                    (option_is_tty? "\33[0m": ""),
                    (option_is_tty? "\33[32m": ""),
                    J.string.instr,
                    (option_is_tty? "\33[0m": ""),
                    (score >= option_threshold? " <data?>": ""));
            }

            if (I.data || score >= option_threshold)
            {
                // Data has been detected in the code segment.  We attempt to
                // handle this by nuking +/- option_sync instructions which
                // may also be data.  This a very crude heuristic, so the
                // user will be warned (below).
                intptr_t lo = I.address, hi = lo + I.size;
                for (int i = 0; Is.size() > 0 && i < option_sync; i++)
                {
                    const Instr J = Is.back();
                    Is.pop_back();
                    lo = J.address;
                    if (J.first)
                        break;
                    if (J.sus)
                        i = 0;
                }
                if (desyncs.size() > 0 && lo <= desyncs.back().hi)
                    desyncs.back().hi = hi;
                else if (sync >= 0)
                    desyncs.push_back({lo, hi, (intptr_t)I.address, section,
                        *bytes});
                sync = -option_sync;
                continue;
            }
            I.sus = (score > 0);
            if (++sync >= 0)
                Is.push_back(I);
            else
            {
                if (I.sus)
                    sync = -option_sync;
                desyncs.back().hi = I.address + I.size;
            }
        }
        if (code < end)
            error("failed to disassemble the \"%s\" section 0x%lx..0x%lx; "
                "could only disassemble the range 0x%lx..0x%lx",
                section, section_addr, section_addr + section_size,
                section_addr, section_addr + (code - start));
    }
    Is.shrink_to_fit();
    notifyPlugins(out, &elf, Is, EVENT_DISASSEMBLY_COMPLETE);
    size_t count = Is.size();

    // Step (1a): CFG Analysis (if necessary).
    if (option_targets)
        buildTargets(&elf, Is.data(), Is.size(), elf.targets);
    if (option_bbs)
        buildBBs(&elf, Is.data(), Is.size(), elf.targets, elf.bbs);
    if (option_fs)
        buildFs(&elf, Is.data(), Is.size(), elf.targets, elf.fs);

    // Step (2): Find all matching instructions:
    std::vector<Action *> matching;
    MatchingCache Ms;
    for (size_t i = 0; i < count; i++)
    {
        matching.clear();
        InstrInfo I;
        getInstrInfo(&elf, &Is[i], &I);
        matchPlugins(out, &elf, Is, i, &I);
        match(actions, elf, Is, i, &I, matching);
        bool matched = (matching.size() > 0);
        if (matched)
        {
            Is[i].patch    = true;
            Is[i].matching = saveMatching(matching, &I, Ms);
        }
        debug("%s0x%lx%s: match %s%s%s%s",
            (option_is_tty? "\33[31m": ""),
            I.address,
            (option_is_tty? "\33[0m": ""),
            (matched && option_is_tty? "\33[32m": ""),
            I.string.instr,
            (matched && option_is_tty? "\33[0m": ""),
            (matched && !option_is_tty? " (matched)": ""));
        if (I.size >= /*sizeof(jmpq)=*/5 &&
                ((I.category & CATEGORY_JUMP) != 0 ||
                 (I.category & CATEGORY_CALL) != 0))
            Is[i].jump = true;
    }
    notifyPlugins(out, &elf, Is, EVENT_MATCHING_COMPLETE);

    // Step (3): Send all composite trampolines:
    size_t tid = 0;
    std::map<const Matching *, size_t, MatchingCmp> tmps;
    std::vector<Metadata> metadata;
    std::vector<std::vector<Metadata>> metadatas;
    Context cxt = {out, nullptr, nullptr, &elf, &Is, -1, nullptr, -1};
    for (const auto *M: Ms.matchings)
    {
        sendMessageHeader(out, "trampoline");
        sendParamHeader(out, "name");
        fprintf(out, "\"$tmp_%zu\"", tid);
        sendSeparator(out);
        sendParamHeader(out, "template");
        fputs("[\".Ltrampoline\",", out);

        // BEFORE trampolines:
        bool seen_break = false;
        for (const auto *action: M->actions)
        {
            for (size_t j = 0, n = action->patch.size(); j < n; j++)
            {
                if (action->patch[j]->pos != POS_BEFORE || seen_break)
                    continue;
                seen_break = sendTrampoline(out, action, j, &cxt, metadata);
            }
        }

        // REPLACE trampoline:
        bool seen_replace = false;
        for (const auto *action: M->actions)
        {
            for (size_t j = 0, n = action->patch.size(); j < n; j++)
            {
                if (action->patch[j]->pos != POS_REPLACE || seen_break)
                    continue;
                seen_replace = true;
                seen_break = sendTrampoline(out, action, j, &cxt, metadata);
            }
        }
        if (!seen_replace && !seen_break)
            fprintf(out, "\"$instr\",");

        // AFTER trampolines:
        for (const auto *action: M->actions)
        {
            for (size_t j = 0, n = action->patch.size(); j < n; j++)
            {
                if (action->patch[j]->pos != POS_AFTER || seen_break)
                    continue;
                seen_break = sendTrampoline(out, action, j, &cxt, metadata);
            }
        }
        if (!seen_break)
            fputs("\"$BREAK\",", out);

        // DATA:
        for (const auto &entry: metadata)
        {
            const Patch *patch = entry.action->patch[entry.idx];
            if (patch->kind == PATCH_PLUGIN)
            {
                const Plugin *plugin = patch->plugin;
                cxt.context = plugin->context;
                plugin->patchFunc(&cxt, PHASE_DATA);
            }
            else
                fprintf(out, "\"$DATA@%s\",", patch->name+1);
        }
        fputc(']', out);
        sendSeparator(out, /*last=*/true);
        sendMessageFooter(out, /*sync=*/true);

        metadatas.emplace_back();
        metadatas[tid].swap(metadata);
        tmps.insert({M, tid});
        tid++;
    }

    /*
     * Send instructions & patches.  Note: this MUST be done in reverse!
     */
    debug("--------------------------------------");
    intptr_t id = -1;
    for (ssize_t i = (ssize_t)count - 1; i >= 0; i--)
    {
        switch (option_optimization_level)
        {
            case '2': case '3': case 's':
                if (!Is[i].emitted && Is[i].jump)
                {
                    // Always emits jump/calls for -Opeephole
                    Is[i].emitted = true;
                    sendInstructionMessage(out, Is[i].address,
                        Is[i].size, Is[i].offset);
                }
                break;
        }
        if (!Is[i].patch)
            continue;

        // Disassmble the instruction again.
        InstrInfo I;
        getInstrInfo(&elf, &Is[i], &I);
        bool done = false;
        for (ssize_t j = i; !done && j >= 0; j--)
            done = !sendInstructionMessage(out, Is[j], Is[i].address);
        done = false;
        for (size_t j = i + 1; !done && j < count; j++)
            done = !sendInstructionMessage(out, Is[j], Is[i].address);

        // Send the "patch" message.
        id++;
        Context cxt = {out, nullptr, nullptr, &elf, &Is, i, &I, id};
        const Matching *M = Ms.matchings[Is[i].matching];
        size_t tid = tmps[M];

        if (option_debug)
        {
            std::string s;
            bool prev = false;
            for (const auto *action: M->actions)
            {
                for (size_t j = 0, n = action->patch.size(); j < n; j++)
                {
                    if (prev)
                        s += ',';
                    prev = true;
                    s += action->patch[j]->name;
                }
            }
            debug("%s0x%lx%s: patch %s%s%s [%s] #%zu",
                (option_is_tty? "\33[31m": ""),
                I.address,
                (option_is_tty? "\33[0m": ""),
                (option_is_tty? "\33[32m": ""),
                I.string.instr,
                (option_is_tty? "\33[0m": ""),
                s.c_str(), tid);
        }

        sendMessageHeader(out, "patch");
        sendParamHeader(out, "trampoline");
        fprintf(out, "\"$tmp_%zu\",", tid);
        if (metadatas[tid].size() > 0)
        {
            sendParamHeader(out, "metadata");
            sendMetadataHeader(out);
            for (const auto &entry: metadatas[tid])
                sendMetadata(out, &elf, entry.action, entry.idx, Is,
                    (size_t)i, &I, id, &cxt);
            sendMetadataFooter(out);
            sendSeparator(out);
        }
        sendParamHeader(out, "offset");
        sendInteger(out, I.offset);
        sendSeparator(out, /*last=*/true);
        sendMessageFooter(out, /*sync=*/true);
    }
    notifyPlugins(out, &elf, Is, EVENT_PATCHING_COMPLETE);
    Is.clear();

    /*
     * Emit the final binary/patch file.
     */
    if (option_format == "patch" && !hasSuffix(option_output, ".patch"))
        option_output += ".patch";
    else if (option_format == "patch.gz" &&
            !hasSuffix(option_output, ".patch.gz"))
        option_output += ".patch.gz";
    else if (option_format == "patch.bz2" &&
            !hasSuffix(option_output, ".patch.bz2"))
        option_output += ".patch.bz2";
    else if (option_format == "patch.xz" &&
            !hasSuffix(option_output, ".patch.xz"))
        option_output += ".patch.xz";
    else if (option_format == "json")
    {
        option_output = "a.out";
        option_format = "binary";
    }
    sendEmitMessage(out, option_output.c_str(), option_format.c_str());

    /*
     * Wait for E9Patch to complete.
     */
    waitBackend(backend);

    /*
     * Finalize all plugins.
     */
    finiPlugins(out, &elf);

    /*
     * Give warnings if disassembly failed.
     */
    std::string exs;
    for (const auto &entry: desyncs)
    {
        warning("failed to disassemble byte 0x%.2X at address 0x%lx in "
            "section \"%s\"", entry.byte, entry.addr, entry.section);
        char buf[BUFSIZ];
        ssize_t r = snprintf(buf, sizeof(buf)-1, "\t\t-E 0x%lx..0x%lx\n",
            entry.lo, entry.hi);
        if (r > 0 && (size_t)r < sizeof(buf)-1)
            exs += buf;
    }
    if (exs.size() > 0)
        warning("failed to cleanly disassemble the binary \"%s\"; data was "
            "detected in the code section(s):\n"
            "\t(1) the following exclusions were automatically applied "
                "(see --sync):\n%s"
            "\t(2) some data may not have been detected.\n"
            "\t(3) manually refine the exlusions (see -E) to resolve the "
                "problem.",
            filename, exs.c_str());

    return 0;
}

/*
 * Main.
 */
int main(int argc, char **argv)
{
    try
    {
        main_2(argc, argv);
    }
    catch (const std::exception& e)
    {
        error("uncaught exception: %s", e.what());
    }
    catch (...)
    {
        error("uncaught exception");
    }
}

#ifndef NDEBUG
/*
 * ASAN options.
 */
extern "C"
{
    /*
     * E9Tool deliberately leaks memory & leaves it to the OS to clean-up.
     */
    const char *__asan_default_options()
    {
        return "detect_leaks=0";
    }
}
#endif

