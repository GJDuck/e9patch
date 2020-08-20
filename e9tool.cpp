/*
 *        ___  _              _ 
 *   ___ / _ \| |_ ___   ___ | |
 *  / _ \ (_) | __/ _ \ / _ \| |
 * |  __/\__, | || (_) | (_) | |
 *  \___|  /_/ \__\___/ \___/|_|
 *                              
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

#include <regex>
#include <set>
#include <string>

#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <elf.h>

#define PAGE_SIZE       4096

#define MAX_ACTIONS     (1 << 10)

#include "e9plugin.h"
#include "e9frontend.cpp"

/*
 * Options.
 */
static bool option_trap_all = false;
static bool option_detail    = false;
static bool option_debug     = false;
static std::string option_format("binary");
static std::string option_output("a.out");
static std::string option_syntax("ATT");

/*
 * Instruction location.
 */
struct Location
{
    const uint64_t offset:48;
    const uint64_t size:4;
    uint64_t       emitted:1;
    const uint64_t patch:1;
    const uint64_t action:10;

    Location(off_t offset, size_t size, bool patch, unsigned action) :
        offset(offset), size(size), emitted(0), patch(patch), action(action)
    {
        ;
    }
};

/*
 * C-string comparator.
 */
struct CStrCmp
{
    bool operator()(const char* a, const char* b) const
    {
        return (strcmp(a, b) < 0);
    }
};

/*
 * Match kinds.
 */
enum MatchKind
{
    MATCH_INVALID,
    MATCH_TRUE,
    MATCH_FALSE,
    MATCH_ASSEMBLY,
    MATCH_ADDRESS,
    MATCH_OFFSET,
    MATCH_RANDOM,
    MATCH_SIZE,
};

/*
 * Match comparison operator.
 */
enum MatchCmp
{
    MATCH_CMP_INVALID,
    MATCH_CMP_NEQ_ZERO,
    MATCH_CMP_EQ,
    MATCH_CMP_NEQ,
    MATCH_CMP_LT,
    MATCH_CMP_LEQ,
    MATCH_CMP_GT,
    MATCH_CMP_GEQ
};

/*
 * Action kinds.
 */
enum ActionKind
{
    ACTION_INVALID,
    ACTION_CALL,
    ACTION_PASSTHRU,
    ACTION_PLUGIN,
    ACTION_PRINT,
    ACTION_TRAP,
};

/*
 * A match entry.
 */
struct MatchEntry
{
    const MatchKind match;
    const MatchCmp  cmp;
    const std::string string;
    std::regex regex;
    std::set<intptr_t> values;

    MatchEntry(MatchEntry &&entry) :
        match(entry.match), cmp(entry.cmp), regex(std::move(entry.regex)),
        string(std::move(entry.string)), values(std::move(entry.values))
    {
        ;
    }

    MatchEntry(MatchKind match, MatchCmp cmp, const char *s) :
        string(s), cmp(cmp), match(match)
    {
        ;
    }
};
typedef std::vector<MatchEntry> MatchEntries;

/*
 * Actions.
 */
struct Action
{
    const std::string string;
    const MatchEntries entries;
    const ActionKind kind;
    const char * const name;
    const char * const filename;
    const char * const symbol;
    void *handle;
    PluginInit initFunc;
    PluginInstr instrFunc;
    PluginPatch patchFunc;
    PluginFini finiFunc;
    void *context;
    std::vector<Argument> args;
    bool clean;
    bool before;
    bool replace;

    Action(const char *string, MatchEntries &&entries, ActionKind kind,
            const char *name, const char *filename, const char *symbol,
            const std::vector<Argument> &&args,  bool clean, bool before,
            bool replace) :
            string(string), entries(std::move(entries)), kind(kind),
            name(name), filename(filename), symbol(symbol), handle(nullptr),
            initFunc(nullptr), instrFunc(nullptr), patchFunc(nullptr),
            context(nullptr), args(args), clean(clean),
            before(before), replace(replace)
    {
        ;
    }
};
typedef std::map<size_t, Action *> Actions;

/*
 * Implementation.
 */
#include "e9metadata.cpp"

/*
 * Action string parser.
 */
struct Parser
{
    const char * const buf;
    size_t i = 0;
    char s[BUFSIZ+1];

    Parser(const char *buf) : buf(buf)
    {
        ;
    }

    char getToken()
    {
        char c = buf[i];
        while (isspace(c))
            c = buf[++i];
        switch (c)
        {
            case '\0':
                return (s[0] = '\0');
            case '[': case ']': case '@': case ',': case '(': case ')':
                s[0] = c; s[1] = '\0';
                i++;
                return c;
            default:
                break;
        }
        if (isalnum(c) || buf[i] == '_' || buf[i] == '-')
        {
            unsigned j = 0;
            s[j++] = c;
            i++;
            while (isalnum(buf[i]) || buf[i] == '_')
                s[j++] = buf[i++];
            s[j++] = '\0';
            return c;
        }
        s[0] = c; s[1] = '\0';
        return EOF;
    }
};

/*
 * Parse an integer.
 */
static const char *parseInt(const char *s, intptr_t &x)
{
    bool neg = false;
    if (s[0] == '+')
        s++;
    else if (s[0] == '-')
    {
        neg = true;
        s++;
    }
    int base = (s[0] == '0' && s[1] == 'x'? 16: 10);
    char *end = nullptr;
    x = (intptr_t)strtoull(s, &end, base);
    if (end == nullptr || end == s)
        return nullptr;
    x = (neg? -x: x);
    return end;
}

/*
 * Parse a list of values.
 */
static void parseValues(const char *s, std::set<intptr_t> &values)
{
    if (*s == '\0')
        return;
    while (true)
    {
        intptr_t x = 0;
        const char *end = parseInt(s, x);
        if (end == nullptr)
            error("failed to parse integer from string \"%.30s%s\"", s,
                (strlen(s) > 30? "...": ""));
        values.insert(x);
        switch (*end)
        {
            case ',': case '|':
                s = end+1;
                break;
            case '\0':
                return;
            default:
                error("failed to parse integer list; unexpected character "
                    "`%c' in string \"%.30s%s\"", *end, s,
                    (strlen(s) > 30? "...": ""));
        }
    }
}

/*
 * Parse a match.
 */
static void parseMatch(const char *str, MatchEntries &entries)
{
    MatchKind match = MATCH_INVALID;
    char name[32];
    size_t i = 0;
    for (; isspace(str[i]); i++)
        ;
    size_t j = 0;
    for (; isalpha(str[i]) && str[i] != '\0' &&
            j < sizeof(name)-1; i++, j++)
        name[j] = str[i];
    if (isalpha(str[i]))
        error("failed to parse matching \"%s\"; name is too long", str);
    name[j] = '\0';
    for (; isspace(str[i]); i++)
        ;
    switch (name[0])
    {
        case 'a':
            if (strcmp(name, "asm") == 0)
                match = MATCH_ASSEMBLY;
            else if (strcmp(name, "addr") == 0)
                match = MATCH_ADDRESS;
            break;
        case 'f':
            if (strcmp(name, "false") == 0)
                match = MATCH_FALSE;
            break;
        case 'o':
            if (strcmp(name, "offset") == 0)
                match = MATCH_OFFSET;
            break;
        case 'r':
            if (strcmp(name, "random") == 0)
                match = MATCH_RANDOM;
            break;
        case 's':
            if (strcmp(name, "size") == 0)
                match = MATCH_SIZE;
            break;
        case 't':
            if (strcmp(name, "true") == 0)
                match = MATCH_TRUE;
            break;
    }
    MatchCmp cmp = MATCH_CMP_INVALID;
    switch (str[i++])
    {
        case '!':
            if (str[i++] == '=')
                cmp = MATCH_CMP_NEQ;
            break;
        case '<':
            cmp = MATCH_CMP_LT;
            if (str[i] == '=')
            {
                cmp = MATCH_CMP_LEQ;
                i++;
            }
            break;
        case '>':
            cmp = MATCH_CMP_GT;
            if (str[i] == '=')
            {
                cmp = MATCH_CMP_GEQ;
                i++;
            }
            break;
        case '=':
            cmp = MATCH_CMP_EQ;
            if (str[i] == '=')
                i++;
            break;
        case '\0':
            cmp = MATCH_CMP_NEQ_ZERO;
            break;
    }
    if (cmp == MATCH_CMP_INVALID)
        error("failed to parse matching \"%s\"; missing comparison "
            "operator", str);
    switch (match)
    {
        case MATCH_INVALID:
            error("failed to parse matching \"%s\"; invalid match-"
                "kind \"%s\"", name, str);
        case MATCH_ASSEMBLY:
            if (cmp != MATCH_CMP_EQ && cmp != MATCH_CMP_NEQ)
                error("failed to parse matching \"%s\"; invalid match "
                    "comparison operator for match-kind %s", str, name);
            break;
        default:
            break;
    }
 
    for (; isspace(str[i]); i++)
        ;
    MatchEntry entry(match, cmp, str+i);
    switch (match)
    {
        case MATCH_ASSEMBLY:
            entry.regex = str+i;
            break;
        case MATCH_TRUE:
        case MATCH_FALSE:
        case MATCH_ADDRESS:
        case MATCH_OFFSET:
        case MATCH_RANDOM:
        case MATCH_SIZE:
            if (cmp == MATCH_CMP_NEQ_ZERO)
                break;
            parseValues(str+i, entry.values);
            break;
        default:
            break;
    }
    entries.push_back(std::move(entry));
}

/*
 * Parse an action.
 */
static Action *parseAction(const char *str, MatchEntries &entries)
{
    if (entries.size() == 0)
        error("failed to parse action; the `--action' or `-A' option must be "
            "preceded by one or more `--match' or `-M' options");

    ActionKind kind = ACTION_INVALID;
    Parser parser(str);
    switch (parser.getToken())
    {
        case 'c':
            if (strcmp(parser.s, "call") == 0)
                kind = ACTION_CALL;
            break;
        case 'p':
            if (strcmp(parser.s, "passthru") == 0)
                kind = ACTION_PASSTHRU;
            else if (strcmp(parser.s, "print") == 0)
                kind = ACTION_PRINT;
            else if (strcmp(parser.s, "plugin") == 0)
            {
                option_detail = true;
                kind = ACTION_PLUGIN;
            }
            break;
        case 't':
            if (strcmp(parser.s, "trap") == 0)
                kind = ACTION_TRAP;
            break;
    }
    if (kind == ACTION_INVALID)
        error("failed to parse action string \"%s\"; invalid instrumentation-"
            "kind \"%s\"", str, parser.s);

    // Step (5): parse call (if necessary):
    bool option_clean = false, option_naked = false, option_before = false,
         option_after = false, option_replace = false;
    const char *symbol   = nullptr;
    const char *filename = nullptr;
    std::vector<Argument> args;
    if (kind == ACTION_PLUGIN)
    {
        while (isspace(parser.buf[parser.i]))
            parser.i++;
        filename = strDup(parser.buf + parser.i);
    }
    else if (kind == ACTION_CALL)
    {
        char c = parser.getToken();
        if (c == '[')
        {
            while (true)
            {
                c = parser.getToken();
                bool ok = false;
                switch (c)
                {
                    case 'a':
                        if (strcmp(parser.s, "after") == 0)
                            ok = option_after = true;
                        break;
                    case 'b':
                        if (strcmp(parser.s, "before") == 0)
                            ok = option_before = true;
                        break;
                    case 'c':
                        if (strcmp(parser.s, "clean") == 0)
                            ok = option_clean = true;
                        break;
                    case 'n':
                        if (strcmp(parser.s, "naked") == 0)
                            ok = option_naked = true;
                        break;
                    case 'r':
                        if (strcmp(parser.s, "replace") == 0)
                            ok = option_replace = true;
                        break;
                }
                if (!ok)
                    error("failed to parse call action; expected call "
                        "attribute, found `%s'", parser.s);
                c = parser.getToken();
                if (c == ']')
                    break;
                if (c != ',')
                    error("failed to parse call action; expected `]' or `,', "
                        "found `%s'", parser.s);
            }
            c = parser.getToken();
        }
        if (!isalpha(c) && c != '_')
            error("failed to parse call action; expected symbol name, found "
                "`%s'", parser.s);
        symbol = strDup(parser.s);
        c = parser.getToken();
        if (c == '(')
        {
            while (true)
            {
                c = parser.getToken();
                const char *s = parser.s;
                ArgumentKind arg = ARGUMENT_INVALID;
                intptr_t value = 0x0;
                switch (c)
                {
                    case 'a':
                        if (strcmp(s, "asmStr") == 0)
                            arg = ARGUMENT_ASM_STR;
                        else if (strcmp(s, "asmStrLen") == 0)
                            arg = ARGUMENT_ASM_STR_LEN;
                        else if (strcmp(s, "addr") == 0)
                            arg = ARGUMENT_ADDR;
                        break;
                    case 'i':
                        if (strcmp(s, "instr") == 0)
                            arg = ARGUMENT_BYTES;
                        else if (strcmp(s, "instrLen") == 0)
                            arg = ARGUMENT_BYTES_LEN;
                        break;
                    case 'n':
                        if (strcmp(s, "next") == 0)
                            arg = ARGUMENT_NEXT;
                        break;
                    case 'o':
                        if (strcmp(s, "offset") == 0)
                            arg = ARGUMENT_OFFSET;
                        break;
                    case 'r':
                        if (strcmp(s, "rax") == 0)
                            arg = ARGUMENT_RAX;
                        else if (strcmp(s, "rbx") == 0)
                            arg = ARGUMENT_RBX;
                        else if (strcmp(s, "rcx") == 0)
                            arg = ARGUMENT_RCX;
                        else if (strcmp(s, "rdx") == 0)
                            arg = ARGUMENT_RDX;
                        else if (strcmp(s, "rbp") == 0)
                            arg = ARGUMENT_RBP;
                        else if (strcmp(s, "rdi") == 0)
                            arg = ARGUMENT_RDI;
                        else if (strcmp(s, "rsi") == 0)
                            arg = ARGUMENT_RSI;
                        else if (strcmp(s, "r8") == 0)
                            arg = ARGUMENT_R8;
                        else if (strcmp(s, "r9") == 0)
                            arg = ARGUMENT_R9;
                        else if (strcmp(s, "r10") == 0)
                            arg = ARGUMENT_R10;
                        else if (strcmp(s, "r11") == 0)
                            arg = ARGUMENT_R11;
                        else if (strcmp(s, "r12") == 0)
                            arg = ARGUMENT_R12;
                        else if (strcmp(s, "r13") == 0)
                            arg = ARGUMENT_R13;
                        else if (strcmp(s, "r14") == 0)
                            arg = ARGUMENT_R14;
                        else if (strcmp(s, "r15") == 0)
                            arg = ARGUMENT_R15;
                        else if (strcmp(s, "rflags") == 0)
                            arg = ARGUMENT_RFLAGS;
                        else if (strcmp(s, "rip") == 0)
                            arg = ARGUMENT_RIP;
                        else if (strcmp(s, "rsp") == 0)
                            arg = ARGUMENT_RSP;
                        break;
                    case 't':
                        if (strcmp(s, "target") == 0)
                        {
                            option_detail = true;
                            arg = ARGUMENT_TARGET;
                        }
                        else if (strcmp(s, "trampoline") == 0)
                            arg = ARGUMENT_TRAMPOLINE;
                        break;
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                    case '-':
                    {
                        const char *end = parseInt(s, value);
                        if (end == nullptr || *end != '\0')
                            break;
                        arg = ARGUMENT_INTEGER;
                        break;
                    }
                }
                if (arg == ARGUMENT_INVALID)
                    error("failed to parse call action; expected call "
                        "argument, found `%s'", s);
                args.push_back({arg, value});
                c = parser.getToken();
                if (c == ')')
                    break;
                if (c != ',')
                    error("failed to parse call action; expected `)' or `,', "
                        "found `%s'", s);
            }
            c = parser.getToken();
        }
        if (c != '@')
            error("failed to parse call action; expected `@', found `%s'",
                parser.s);
        filename = strDup(parser.buf + parser.i);
        if (filename[0] == '\0')
            error("failed to parse call action; expected filename");
        if (option_clean && option_naked)
            error("failed to parse call action; `clean' and `naked' "
                "attributes cannot be used together");
        option_clean = (option_clean? true: !option_naked);
        if ((int)option_before + (int)option_after + (int)option_replace > 1)
            error("failed to parse call action; only one of the `before', "
                "`after' and `replace' attributes can be used together");
        option_before = (option_before? true: !option_after);
    }
    else if (parser.getToken() != '\0')
        error("failed to parse action; expected end-of-string, found `%s'",
            parser.s);

    // Step(5): Build the action:
    const char *name = nullptr;
    switch (kind)
    {
        case ACTION_PRINT:
            name = "print";
            break;
        case ACTION_PASSTHRU:
            name = "passthru";
            break;
        case ACTION_TRAP:
            name = "trap";
            break;
        case ACTION_CALL:
        {
            std::string call_name("call_");
            call_name += (option_clean? 'C': 'N');
            call_name += (option_replace? 'R': (option_before? 'B': 'A'));
            call_name += '_';
            call_name += symbol;
            call_name += '_';
            call_name += filename;
            name = strDup(call_name.c_str());
            break;
        }
        case ACTION_PLUGIN:
        {
            std::string plugin_name("plugin_");
            plugin_name += filename;
            name = strDup(plugin_name.c_str());
            break;
        }
        default:
            break;
    }

    Action *action = new Action(str, std::move(entries), kind, name, filename,
        symbol, std::move(args), option_clean, option_before, option_replace);
    return action;
}

/*
 * Create match string.
 */
static const char *makeMatchString(MatchKind match, const cs_insn *I,
    char *buf, size_t buf_size)
{
    switch (match)
    {
        case MATCH_ASSEMBLY:
            if (I->op_str[0] == '\0')
                return I->mnemonic;
            else
            {
                ssize_t r = snprintf(buf, buf_size, "%s %s",
                    I->mnemonic, I->op_str);
                if (r < 0 || r >= (ssize_t)buf_size)
                    error("failed to create assembly string of size %zu",
                        buf_size);
                return buf;
            }
        default:
            return "";
    }
}

/*
 * Create match value.
 */
static intptr_t makeMatchValue(MatchKind match, const cs_insn *I,
    intptr_t text_addr, off_t text_offset)
{
    switch (match)
    {
        case MATCH_TRUE:
            return 1;
        case MATCH_FALSE:
            return 0;
        case MATCH_ADDRESS:
            return I->address;
        case MATCH_OFFSET:
            return (intptr_t)(I->address - text_addr) + text_offset;
        case MATCH_RANDOM:
            return (intptr_t)rand();
        case MATCH_SIZE:
            return I->size;
        default:
            return 0;
    }
}

/*
 * Match an action.
 */
static bool matchAction(csh handle, const Action *action, const cs_insn *I,
    intptr_t text_addr, off_t text_offset)
{
    for (auto &entry: action->entries)
    {
        bool pass = false;
        switch (entry.match)
        {
            case MATCH_ASSEMBLY:
            {
                char buf[BUFSIZ];
                const char *str = makeMatchString(entry.match, I, buf,
                    sizeof(buf)-1);
                std::cmatch cmatch;
                pass = std::regex_match(str, cmatch, entry.regex);
                pass = (entry.cmp == MATCH_CMP_NEQ? !pass: pass);
                break;
            }
            case MATCH_TRUE:
            case MATCH_FALSE:
            case MATCH_ADDRESS:
            case MATCH_OFFSET:
            case MATCH_RANDOM:
            case MATCH_SIZE:
            {
                intptr_t x = makeMatchValue(entry.match, I, text_addr,
                    text_offset);
                switch (entry.cmp)
                {
                    case MATCH_CMP_NEQ_ZERO:
                        pass = (x != 0);
                        break;
                    case MATCH_CMP_EQ:
                        pass = (entry.values.find(x) != entry.values.end());
                        break;
                    case MATCH_CMP_NEQ:
                        pass = (entry.values.find(x) == entry.values.end());
                        break;
                    case MATCH_CMP_LT:
                        pass = (x < *entry.values.rbegin());
                        break;
                    case MATCH_CMP_LEQ:
                        pass = (x <= *entry.values.rbegin());
                        break;
                    case MATCH_CMP_GT:
                        pass = (x > *entry.values.begin());
                        break;
                    case MATCH_CMP_GEQ:
                        pass = (x >= *entry.values.begin());
                        break;
                    default:
                        return false;
                }
                break;
            }
            default:
                return false;
        }
        if (!pass)
            return false;
    }
    if (option_debug)
    {
        fprintf(stderr, "%s0x%lx%s: match ",
            (option_is_tty? "\33[32m": ""),
            I->address,
            (option_is_tty? "\33[0m": ""));
        bool prev = false;
        for (auto &entry: action->entries)
        {
            fprintf(stderr, "%s%s%s%s ",
                (prev? "and ": ""),
                (option_is_tty? "\33[33m": ""),
                entry.string.c_str(),
                (option_is_tty? "\33[0m": ""));
            prev = true;
        }
        fprintf(stderr, "action %s%s%s\n",
            (option_is_tty? "\33[33m": ""),
            action->string.c_str(),
            (option_is_tty? "\33[0m": ""));
    }
    return true;
}

/*
 * Send an instruction message (if necessary).
 */
static bool sendInstructionMessage(FILE *out, Location &loc, intptr_t addr,
    intptr_t text_addr, off_t text_offset)
{
    if (std::abs((intptr_t)(text_addr + loc.offset) - addr) >
            INT8_MAX + /*sizeof(short jmp)=*/2 + /*max instruction size=*/15)
        return false;

    if (loc.emitted)
        return true;
    loc.emitted = true;

    addr = text_addr + loc.offset;
    off_t offset = text_offset + loc.offset;
    size_t size = loc.size;

    sendInstructionMessage(out, addr, size, offset);
    return true;
}

/*
 * Convert a positon into an address.
 */
static intptr_t positionToAddr(const ELF &elf, const char *option,
    const char *pos)
{
    // Case #1: absolute address:
    if (pos[0] == '0' && pos[1] == 'x')
    {
        const char *str = pos + 2;
        errno = 0;
        char *end = nullptr;
        intptr_t abs_addr = strtoull(str, &end, 16);
        if (end != nullptr && *end != '\0')
            error("bad value for `%s' option; invalid absolute position "
                "string \"%s\"", option, pos);
        return abs_addr;
    }

    // Case #2: symbolic address:
    const Elf64_Sym *sym = elf.dynamic_symtab;
    const Elf64_Sym *sym_end = sym + (elf.dynamic_symsz / sizeof(Elf64_Sym));
    for (; sym < sym_end; sym++)
    {
        if (sym->st_name == 0 || sym->st_name >= elf.dynamic_strsz)
            continue;
        const char *name = elf.dynamic_strtab + sym->st_name;
        if (strcmp(pos, name) == 0)
        {
            intptr_t sym_addr = (intptr_t)sym->st_value;
            if (sym_addr < elf.text_addr ||
                    sym_addr >= elf.text_addr + (ssize_t)elf.text_size)
                error("bad value for `%s' option; dynamic symbol \"%s\" "
                    "points outside of the (.text) section", option, name);
            return sym_addr;
        }
    }
    error("bad value for `%s' option; failed to find dynamic symbol "
        "\"%s\"", option, pos);
}

/*
 * Usage.
 */
static void usage(FILE *stream, const char *progname)
{
    fputs("        ___  _              _\n", stream);
    fputs("   ___ / _ \\| |_ ___   ___ | |\n", stream);
    fputs("  / _ \\ (_) | __/ _ \\ / _ \\| |\n", stream);
    fputs(" |  __/\\__, | || (_) | (_) | |\n", stream);
    fputs("  \\___|  /_/ \\__\\___/ \\___/|_|\n", stream);
    fputc('\n', stream);
    fprintf(stream, "usage: %s [OPTIONS] --match MATCH --action ACTION ... "
        "input-file\n\n", progname);
    
    fputs("MATCH\n", stream);
    fputs("=====\n", stream);
    fputc('\n', stream);
    fputs("Matchings determine which instructions should be rewritten.  "
        "Matchings are\n", stream);
    fputs("specified using the `--match'/`-M' option:\n", stream);
    fputc('\n', stream);
    fputs("\t--match MATCH, -M MATCH\n", stream);
    fputs("\t\tSpecifies an instruction matching MATCH in the following "
        "form:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tMATCH     ::= ATTRIBUTE [ CMP VALUES ]\n", stream);
    fputs("\t\t\tATTRIBUTE ::=   'true'\n", stream);
    fputs("\t\t\t              | 'false'\n", stream);
    fputs("\t\t\t              | 'asm'\n", stream);
    fputs("\t\t\t              | 'addr'\n", stream);
    fputs("\t\t\t              | 'offset'\n", stream);
    fputs("\t\t\t              | 'random'\n", stream);
    fputs("\t\t\t              | 'size'\n", stream);
    fputs("\t\t\tCMP       ::=   '='\n", stream);
    fputs("\t\t\t              | '=='\n", stream);
    fputs("\t\t\t              | '!='\n", stream);
    fputs("\t\t\t              | '>'\n", stream);
    fputs("\t\t\t              | '>='\n", stream);
    fputs("\t\t\t              | '<'\n", stream);
    fputs("\t\t\t              | '<='\n", stream);
    fputc('\n', stream);
    fputs("\t\tHere ATTRIBUTE is an instruction attribute, such as assembly\n",
        stream);
    fputs("\t\tor address (see below), CMP is a comparison operator "
        "(equal,\n", stream);
    fputs("\t\tless-than, etc.) and VALUES is either a comma separated list\n",
        stream);
    fputs("\t\tof integers (for integer attributes) or a regular expression\n",
        stream);
    fputs("\t\t(for string attributes):\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tVALUES ::=   REGULAR-EXPRESSION\n", stream);
    fputs("\t\t\t           | INTEGER [ ',' INTEGER ] *\n", stream);
    fputc('\n', stream);
    fputs("\t\tIf the CMP and VALUES are omitted, it is treated the same as\n",
        stream);
    fputs("\t\tATTRIBUTE != 0.\n", stream);
    fputc('\n', stream);
    fputs("\t\tPossible ATTRIBUTEs and attribute TYPEs are:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"true\"      : the value 1.\n", stream);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fputs("\t\t\t- \"false\"     : the value 0.\n", stream);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fputs("\t\t\t- \"asm\"       : the instruction assembly string.  E.g.:\n",
        stream);
    fputs("\t\t\t                \"cmpb %r11b, 0x436fe0(%rdi)\"\n", stream);
    fputs("\t\t\t                TYPE: string\n", stream);
    fputs("\t\t\t- \"addr\"      : the instruction address.  E.g.:\n", stream);
    fputs("\t\t\t                0x4234a7\n", stream);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fputs("\t\t\t- \"offset\"    : the instruction file offset.  E.g.:\n",
        stream);
    fputs("\t\t\t                +49521\n", stream);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fprintf(stream, "\t\t\t- \"random\"    : a random value [0..%lu].\n",
        (uintptr_t)RAND_MAX);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fputs("\t\t\t- \"size\"      : the instruction size in bytes. E.g.: 3\n",
        stream);
    fputs("\t\t\t                TYPE: integer\n", stream);
    fputc('\n', stream);
    fputs("\t\tMultiple `--match'/`-M' options can be combined, which will\n",
        stream);
    fputs("\t\tbe interpreted as the logical AND of the matching conditions.\n",
        stream);
    fputs("\t\tThe sequence of `--match'/`-M' options must also be "
        "terminated\n", stream);
    fputs("\t\tby an `--action'/`-A' option, as described below.\n", stream);

    fputc('\n', stream);
    fputs("ACTION\n", stream);
    fputs("======\n", stream);
    fputc('\n', stream);
    fputs("Actions determine how matching instructions should be rewritten.  "
        "Actions are\n", stream);
    fputs("specified using the `--action'/`-A' option:\n", stream);
    fputc('\n', stream);
    fputs("\t--action ACTION, -A ACTION\n", stream);
    fputs("\t\tThe ACTION specifies how instructions matching the preceding\n",
        stream);
    fputs("\t\t`--match'/`-M' options are to be rewritten.  Possible ACTIONs\n",
        stream);
    fputs("\t\tinclude:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tACTION ::=   'passthru'\n", stream);
    fputs("\t\t\t           | 'print' \n", stream);
    fputs("\t\t\t           | 'trap' \n", stream);
    fputs("\t\t\t           | CALL \n", stream);
    fputs("\t\t\t           | PLUGIN \n", stream);
    fputc('\n', stream);
    fputs("\t\tWhere:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"passthru\": empty (NOP) instrumentation;\n", stream);
    fputs("\t\t\t- \"print\"   : instruction printing instrumentation.\n",
        stream);
    fputs("\t\t\t- \"trap\"    : SIGTRAP instrumentation.\n", stream);
    fputs("\t\t\t- CALL      : call user instrumentation (see below).\n",
        stream);
    fputs("\t\t\t- PLUGIN    : plugin instrumentation (see below).\n",
        stream);
    fputc('\n', stream);
    fputs("\t\tThe CALL INSTRUMENTATION makes it possible to invoke a\n",
        stream);
    fputs("\t\tuser-function defined in an ELF file.  The ELF file can be\n",
        stream);
    fputs("\t\timplemented in C and compiled using the special "
        "\"e9compile.sh\"\n", stream);
    fputs("\t\tshell script.  This will generate a compatible ELF binary\n",
        stream);
    fputs("\t\tfile (BINARY).  The syntax for CALL is:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tCALL ::= 'call' [OPTIONS] FUNCTION [ARGS] '@' BINARY\n",
        stream);
    fputs("\t\t\tOPTIONS ::= '[' OPTION ',' ... ']'\n", stream);
    fputs("\t\t\tARGS ::= '(' ARG ',' ... ')'\n", stream);
    fputc('\n', stream);
    fputs("\t\tWhere:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- OPTION is one of:\n", stream);
    fputs("\t\t\t  * \"clean\"/\"naked\" for clean/naked calls.\n", stream);
    fputs("\t\t\t  * \"before\"/\"after\"/\"replace\" for inserting the\n",
        stream);
    fputs("\t\t\t    call before/after the instruction, or replacing\n",
        stream);
    fputs("\t\t\t    the instruction by the call.\n", stream);
    fputs("\t\t\t- ARG is one of:\n", stream);
    fputs("\t\t\t  * \"asmStr\" is a pointer to the string\n", stream);
    fputs("\t\t\t    representation of the instruction.\n", stream);
    fputs("\t\t\t  * \"asmStrLen\" is the length of \"asmStr\".\n",
        stream);
    fputs("\t\t\t  * \"offset\" is the file offset of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"addr\" is the address of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"instr\" is the bytes of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"instrLen\" is the length of \"instr\".\n",
        stream);
    fputs("\t\t\t  * \"next\" is the address of the next instruction.\n",
        stream);
    fputs("\t\t\t  * \"target\" is the jump/call target, else -1.\n",
        stream);
    fputs("\t\t\t  * \"trampoline\" is the address of the trampoline.\n",
        stream);
    fputs("\t\t\t  * \"rax\"...\"r15\", \"rip\", \"rflags\" is the\n",
        stream);
    fputs("\t\t\t    corresponding register value.\n", stream);
    fputs("\t\t\t  * An integer constant.\n", stream);
    fputs("\t\t\t  NOTE: a maximum of 6 arguments are supported.\n", stream);
    fputs("\t\t\t- FUNCTION is the name of the function to call from\n",
        stream);
    fputs("\t\t\t  the binary.\n", stream);
    fputs("\t\t\t- BINARY is a suitable ELF binary file.  You can use\n",
        stream);
    fputs("\t\t\t  the `e9compile.sh' script to compile C programs into\n",
        stream);
    fputs("\t\t\t  the correct binary format.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe PLUGIN INSTRUMENTATION lets a shared object plugin "
        "drive\n", stream);
    fputs("\t\tthe binary instrumentation/rewriting.  The syntax for "
        "PLUGIN\n", stream);
    fputs("\t\tis:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tPLUGIN ::= 'plugin' FILENAME\n", stream);
    fputc('\n', stream);
    fputs("\t\twhere FILENAME is the path to the plugin shared object.  "
        "See\n", stream);
    fputs("\t\tthe `e9plugin.h' file for the plugin API documentation.\n",
        stream);
    fputc('\n', stream);
    fputs("\t\tIt is possible to specify multiple actions that will be\n",
        stream);
    fputs("\t\tapplied in the command-line order.\n", stream);

    fputc('\n', stream);
    fputs("OTHER OPTIONS\n", stream);
    fputs("=============\n", stream);
    fputc('\n', stream);
    fputs("\t--backend PROG\n", stream);
    fputs("\t\tUse PROG as the backend.  The default is \"e9patch\".\n",
        stream);
    fputc('\n', stream);
    fputs("\t--compression N, -c N\n", stream);
    fputs("\t\tSet the compression level to be N, where N is a number within\n",
        stream);
    fputs("\t\tthe range 0..9.  The default is 9 for maximum compression.\n",
        stream);
    fputs("\t\tHigher compression makes the output binary smaller, but also\n",
        stream);
    fputs("\t\tincreases the number of mappings (mmap() calls) required.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--debug\n", stream);
    fputs("\t\tEnable debug output.\n", stream);
    fputc('\n', stream);
    fputs("\t--end END\n", stream);
    fputs("\t\tOnly patch the (.text) section up to the address or symbol\n",
        stream);
    fputs("\t\tEND.  By default, the whole (.text) section is patched.\n",
        stream);
    fputc('\n', stream);
    fputs("\t--executable\n", stream);
    fputs("\t\tTreat the input file as an executable, even if it appears "
        "to\n", stream);
    fputs("\t\tbe a shared library.  See the `--shared' option for more\n",
        stream);
    fputs("\t\tinformation.\n", stream);
    fputc('\n', stream);
    fputs("\t--format FORMAT\n", stream);
    fputs("\t\tSet the output format to FORMAT which is one of {binary,\n",
        stream);
    fputs("\t\tjson, patch, patch.gz, patch,bz2, patch.xz}.  Here:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"binary\" is a modified ELF executable file;\n", stream);
    fputs("\t\t\t- \"json\" is the raw JSON RPC stream for the e9patch\n",
        stream);
    fputs("\t\t\t  backend; or\n", stream);
    fputs("\t\t\t- \"patch\", \"patch.gz\", \"patch.bz2\" and \"patch.xz\"\n",
        stream);
    fputs("\t\t\t  are (compressed) binary diffs in xxd format.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe default format is \"binary\".\n", stream);
    fputc('\n', stream);
    fputs("\t--help, -h\n", stream);
    fputs("\t\tPrint this message and exit.\n", stream);
    fputc('\n', stream);
    fputs("\t--option OPTION\n", stream);
    fputs("\t\tPass OPTION to the e9patch backend.\n", stream);
    fputc('\n', stream);
    fputs("\t--output FILE, -o FILE\n", stream);
    fputs("\t\tSpecifies the path to the output file.  The default filename "
        "is\n", stream);
    fputs("\t\t\"a.out\".\n", stream);
    fputc('\n', stream);
    fputs("\t--shared\n", stream);
    fputs("\t\tTreat the input file as a shared library, even if it appears "
        "to\n", stream);
    fputs("\t\tbe an executable.  By default, the input file will only be\n",
        stream);
    fputs("\t\ttreated as a shared library if (1) it is a dynamic "
        "executable\n", stream);
    fputs("\t\t(ET_DYN) and (2) has a filename of the form:\n",
        stream);
    fputc('\n', stream);
    fputs("\t\t\t[PATH/]lib*.so[.VERSION]\n", stream);
    fputc('\n', stream);
    fputs("\t--start START\n", stream);
    fputs("\t\tOnly patch the (.text) section beginning from address or "
        "symbol\n", stream);
    fputs("\t\tSTART.  By default, the whole (.text) section is patched\n",
        stream);
    fputc('\n', stream);
    fputs("\t--static-loader, -s\n", stream);
    fputs("\t\tReplace patched pages statically.  By default, patched "
        "pages\n", stream);
    fputs("\t\tare loaded during program initialization as this is more\n",
        stream);
    fputs("\t\treliable for large/complex binaries.  However, this may "
        "bloat\n", stream);
    fputs("\t\tthe size of the output patched binary.\n", stream);
    fputc('\n', stream);
    fputs("\t--sync N\n", stream);
    fputs("\t\tSkip N instructions after the disassembler desyncs.  This\n",
        stream);
    fputs("\t\tcan be a useful hack if the disassembler (capstone) fails, "
        "or\n", stream);
    fputs("\t\tif the .text section contains data.\n", stream);
    fputc('\n', stream);
    fputs("\t--syntax SYNTAX\n", stream);
    fputs("\t\tSelects the assembly syntax to be SYNTAX.  Possible values "
        "are:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"ATT\"  : X86_64 ATT asm syntax; or\n", stream);
    fputs("\t\t\t- \"intel\": X86_64 Intel asm syntax.\n", stream);
    fputc('\n', stream);
    fputs("\t\tThe default syntax is \"ATT\".\n", stream);
    fputc('\n', stream);
    fputs("\t--trap-all\n", stream);
    fputs("\t\tInsert a trap (int3) instruction at each trampoline entry.\n",
        stream);
    fputs("\t\tThis can be used for debugging with gdb.\n", stream);
    fputc('\n', stream);
}

/*
 * Options.
 */
enum Option
{
    OPTION_ACTION,
    OPTION_BACKEND,
    OPTION_COMPRESSION,
    OPTION_DEBUG,
    OPTION_END,
    OPTION_EXECUTABLE,
    OPTION_FORMAT,
    OPTION_HELP,
    OPTION_MATCH,
    OPTION_OPTION,
    OPTION_OUTPUT,
    OPTION_SHARED,
    OPTION_START,
    OPTION_STATIC_LOADER,
    OPTION_SYNC,
    OPTION_SYNTAX,
    OPTION_TRAP_ALL,
};

/*
 * Entry.
 */
int main(int argc, char **argv)
{
    /*
     * Parse options.
     */
    static const struct option long_options[] =
    {
        {"action",         true,  nullptr, OPTION_ACTION},
        {"backend",        true,  nullptr, OPTION_BACKEND},
        {"compression",    true,  nullptr, OPTION_COMPRESSION},
        {"debug",          false, nullptr, OPTION_DEBUG},
        {"end",            true,  nullptr, OPTION_END},
        {"executable",     false, nullptr, OPTION_EXECUTABLE},
        {"format",         true,  nullptr, OPTION_FORMAT},
        {"help",           false, nullptr, OPTION_HELP},
        {"match",          true,  nullptr, OPTION_MATCH},
        {"option",         true,  nullptr, OPTION_OPTION},
        {"output",         true,  nullptr, OPTION_OUTPUT},
        {"shared",         false, nullptr, OPTION_SHARED},
        {"start",          true,  nullptr, OPTION_START},
        {"static-loader",  false, nullptr, OPTION_STATIC_LOADER},
        {"sync",           true,  nullptr, OPTION_SYNC},
        {"syntax",         true,  nullptr, OPTION_SYNTAX},
        {"trap-all",       false, nullptr, OPTION_TRAP_ALL},
        {nullptr,          false, nullptr, 0}
    }; 
    option_is_tty = isatty(STDERR_FILENO);
    std::vector<Action *> option_actions;
    std::vector<char *> option_options;
    unsigned option_compression_level = 9;
    ssize_t option_sync = -1;
    bool option_executable = false, option_shared = false,
        option_static_loader = false;
    std::string option_start(""), option_end(""), option_backend("./e9patch");
    MatchEntries option_match;
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "A:c:hM:o:s", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_ACTION:
            case 'A':
            {
                Action *action = parseAction(optarg, option_match);
                option_actions.push_back(action);
                break;
            }
            case OPTION_BACKEND:
                option_backend = optarg;
                break;
            case OPTION_COMPRESSION:
            case 'c':
                if (!isdigit(optarg[0]) || optarg[1] != '\0')
                    error("bad value \"%s\" for `--compression' "
                        "option; expected a number 0..9", optarg);
                option_compression_level = optarg[0] - '0';
                break;
            case OPTION_DEBUG:
                option_debug = true;
                break;
            case OPTION_END:
                option_end = optarg;
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
                option_options.push_back(strDup(optarg));
                break;
            case OPTION_MATCH:
            case 'M':
                parseMatch(optarg, option_match);
                break;
            case OPTION_OUTPUT:
            case 'o':
                option_output = optarg;
                break;
            case OPTION_SHARED:
                option_shared = true;
                break;
            case OPTION_STATIC_LOADER:
            case 's':
                option_static_loader = true;
                break;
            case OPTION_START:
                option_start = optarg;
                break;
            case OPTION_SYNC:
            {
                errno = 0;
                char *end = nullptr;
                unsigned long r = strtoul(optarg, &end, 10);
                if (errno != 0 || end == optarg ||
                        (end != nullptr && *end != '\0') || r > 1000)
                    error("bad value \"%s\" for `--sync' option; "
                        "expected an integer 0..1000", optarg);
                option_sync = (ssize_t)r;
                break;
            }
            case OPTION_SYNTAX:
                option_syntax = optarg;
                if (option_syntax != "ATT" && option_syntax != "intel")
                    error("bad value \"%s\" for `--syntax' option; "
                        "expected \"ATT\" or \"intel\"", optarg);
                break;
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
    if (option_match.size() != 0)
        error("failed to parse command-line arguments; detected extraneous "
            "matching option(s) (`--match' or `-M') that are not paired "
            "with a corresponding action (`--action' or `-A')"); 
    if (option_actions.size() > MAX_ACTIONS)
        error("failed to parse command-line arguments; the total number of "
            "actions (%zu) exceeds the maximum (%zu)",
            option_actions.size(), MAX_ACTIONS);
    if (option_shared && option_executable)
        error("failed to parse command-line arguments; both the `--shared' "
            "and `--executable' options cannot be used at the same time");
    srand(0xe9e9e9e9);

    /*
     * Parse the ELF file.
     */
    const char *filename = argv[optind];
    ELF elf;
    parseELF(filename, 0x0, elf);

    /*
     * The ELF file seems OK, spawn and initialize the e9patch backend.
     */
    Backend backend;
    if (option_static_loader)
        option_options.push_back(strDup("--static-loader"));
    if (option_trap_all)
        option_options.push_back(strDup("--trap-all"));
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
        spawnBackend(option_backend.c_str(), option_options, backend);
    const char *mode = 
        (option_executable? "exe":
        (option_shared?     "dso":
        (elf.dso? "dso": "exe")));
    sendBinaryMessage(backend.out, mode, filename);

    /*
     * Send trampoline definitions:
     */
    bool have_print = false, have_passthru = false, have_trap = false;
    std::map<const char *, ELF *, CStrCmp> files;
    std::set<const char *, CStrCmp> have_call;
    intptr_t file_addr = elf.free_addr + 0x1000000;     // XXX
    for (const auto action: option_actions)
    {
        switch (action->kind)
        {
            case ACTION_PRINT:
                have_print = true;
                break;
            case ACTION_PASSTHRU:
                have_passthru = true;
                break;
            case ACTION_TRAP:
                have_trap = true;
                break;
            case ACTION_CALL:
            {
                // Step (1): Ensure the ELF file is loaded:
                ELF *target_elf = nullptr;
                auto i = files.find(action->filename);
                if (i == files.end())
                {
                    // Load the called ELF file into the address space:
                    intptr_t free_addr = file_addr + 8 * PAGE_SIZE;
                    free_addr = (free_addr % PAGE_SIZE == 0? free_addr:
                        (free_addr + PAGE_SIZE) - (free_addr % PAGE_SIZE));
                    target_elf = new ELF;
    
                    parseELF(action->filename, free_addr, *target_elf);
                    sendELFFileMessage(backend.out, *target_elf);
                    files.insert({action->filename, target_elf});
                    size_t size = (size_t)target_elf->free_addr;
                    free_addr += size;
                    file_addr = free_addr;
                }
                else
                    target_elf = i->second;

                // Step (2): Create the trampoline:
                auto j = have_call.find(action->name);
                if (j == have_call.end())
                {
                    sendCallTrampolineMessage(backend.out, *target_elf,
                        action->filename, action->symbol, action->name,
                        action->args, action->clean, action->before,
                        action->replace);
                    have_call.insert(action->name);
                }
                break;
            }
            case ACTION_PLUGIN:
            {
                void *handle = dlopen(action->filename,
                    RTLD_LOCAL | RTLD_LAZY);
                if (handle == nullptr)
                    error("failed to load plugin \"%s\": %s", action->filename,
                        dlerror());
                action->initFunc = (PluginInit)dlsym(handle,
                    "e9_plugin_init_v1");
                action->instrFunc = (PluginInstr)dlsym(handle,
                    "e9_plugin_instr_v1");
                action->patchFunc = (PluginPatch)dlsym(handle,
                    "e9_plugin_patch_v1");
                action->finiFunc = (PluginFini)dlsym(handle,
                    "e9_plugin_fini_v1");
                if (action->initFunc == nullptr &&
                        action->instrFunc == nullptr &&
                        action->patchFunc == nullptr &&
                        action->finiFunc == nullptr)
                    error("failed to load plugin \"%s\"; the shared "
                        "object does not export any plugin API functions",
                        action->filename);
                if (action->initFunc != nullptr)
                    action->context = action->initFunc(backend.out, &elf);
                action->handle = handle;
                break;
            }
            default:
                break;
        }
    }
    if (have_passthru)
        sendPassthruTrampolineMessage(backend.out);
    if (have_print)
        sendPrintTrampolineMessage(backend.out);
    if (have_trap)
        sendTrapTrampolineMessage(backend.out);

    /*
     * Find the offset to disassemble from, if any.
     */
    if (option_start != "")
    {
        intptr_t start_addr = positionToAddr(elf, "--start",
            option_start.c_str());
        off_t offset = start_addr - elf.text_addr;
        elf.text_offset += offset;
        elf.text_addr   += offset;
        elf.text_size   -= offset;
    }
    if (option_end != "")
    {
        intptr_t end_addr = positionToAddr(elf, "--end", option_end.c_str());
        off_t offset = (elf.text_addr + elf.text_size) - end_addr;
        elf.text_size -= offset;
    }

    /*
     * Disassemble the ELF file.
     */
    csh handle;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != 0)
        error("failed to open capstone handle (err = %u)", err);
    if (option_detail)
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (option_syntax != "intel")
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    std::vector<Location> locs;
    const uint8_t *start = elf.data + elf.text_offset;
    const uint8_t *code  = start, *end = start + elf.text_size;
    size_t size = elf.text_size;
    uint64_t address = elf.text_addr;
    cs_insn *I = cs_malloc(handle);
    bool failed = false;
    unsigned sync = 0;
    while (cs_disasm_iter(handle, &code, &size, &address, I))
    {
        if (sync > 0)
        {
            sync--;
            continue;
        }
        if (I->mnemonic[0] == '.')
        {
            warning("failed to disassemble (%s %s) at address 0x%lx",
                I->mnemonic, I->op_str, I->address);
            failed = true;
            sync = option_sync;
            continue;
        }

        bool patch = false;
        unsigned i = 0, index = 0;
        off_t offset = ((intptr_t)I->address - elf.text_addr);
        for (const auto action: option_actions)
        {
            bool veto_patch = false;
            if (action->kind == ACTION_PLUGIN && action->instrFunc != nullptr)
                veto_patch = !action->instrFunc(backend.out, &elf, handle,
                    offset, I, action->context);
            if (!patch && !veto_patch &&
                matchAction(handle, action, I, elf.text_addr, elf.text_offset))
            {
                index = i;
                patch = true;
            }
            i++;
        }

        Location loc(offset, I->size, patch, index);
        locs.push_back(loc);
    }
    if (code != end)
        error("failed to disassemble the full (.text) section 0x%lx..0x%lx; "
            "could only disassemble the range 0x%lx..0x%lx",
            elf.text_addr, elf.text_addr + elf.text_size, elf.text_addr,
                elf.text_addr + (code - start));
    if (failed)
    {
        if (option_sync < 0)
            error("failed to disassemble the .text section of \"%s\"; "
                "this may be caused by (1) data in the .text section, or (2) "
                "a bug in the third party disassembler (capstone)", filename);
        else
            warning("failed to disassemble the .text section of \"%s\"; "
                "the rewritten binary may be corrupt", filename);
    }

    /*
     * Send instructions & patches.  Note: this MUST be done in reverse!
     */
    size_t count = locs.size();
    for (ssize_t i = (ssize_t)count - 1; i >= 0; i--)
    {
        Location &loc = locs[i];
        if (!loc.patch)
            continue;

        off_t offset = (off_t)loc.offset;
        intptr_t addr = elf.text_addr + offset;
        offset += elf.text_offset;

        // Disassmble the instruction again.
        const uint8_t *code = elf.data + offset;
        uint64_t address = (uint64_t)addr;
        size_t size = loc.size;
        bool ok = cs_disasm_iter(handle, &code, &size, &address, I);
        if (!ok)
            error("failed to disassemble instruction at address 0x%lx", addr);

        bool done = false;
        for (ssize_t j = i; !done && j >= 0; j--)
            done = !sendInstructionMessage(backend.out, locs[j], addr,
                elf.text_addr, elf.text_offset);
        done = false;
        for (size_t j = i + 1; !done && j < count; j++)
            done = !sendInstructionMessage(backend.out, locs[j], addr,
                elf.text_addr, elf.text_offset);

        const Action *action = option_actions[loc.action];
        if (action->kind == ACTION_PLUGIN &&
            action->patchFunc != nullptr)
        {
            // Special handling for plugins:
            action->patchFunc(backend.out, &elf, handle, offset, I,
                action->context);
        }
        else
        {
            // Builtin actions:
            char buf[4096];
            Metadata metadata_buf[MAX_ARGNO+1];
            Metadata *metadata = buildMetadata(action, I, offset,
                metadata_buf, buf, sizeof(buf)-1);
            sendPatchMessage(backend.out, action->name, offset, metadata);
        }
    }
    cs_free(I, 1);
    cs_close(&handle);

    /*
     * Finalize all plugins.
     */
    for (const auto action: option_actions)
    {
        if (action->kind != ACTION_PLUGIN)
            continue;
        if (action->finiFunc != nullptr)
            action->finiFunc(backend.out, &elf, action->context);
        action->context = nullptr;
        dlclose(action->handle);
    }

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
    size_t mapping_size = PAGE_SIZE * (1 << (9 - option_compression_level));
    sendEmitMessage(backend.out, option_output.c_str(),
        option_format.c_str(), mapping_size);

    /*
     * Wait for the e9patch to complete.
     */
    waitBackend(backend);

    return 0;
}

