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
static bool option_cfg          = false;
static bool option_trap_all     = false;
static bool option_intel_syntax = false;
static std::string option_format("binary");
static std::string option_output("");

#include "e9plugin.h"
#include "e9frontend.cpp"
#include "e9cfg.cpp"
#include "e9x86_64.cpp"

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
 * Plugins.
 */
struct Plugin
{
    const char *filename;
    void *handle;
    void *context;
    intptr_t result;
    PluginInit initFunc;
    PluginEvent eventFunc;
    PluginMatch matchFunc;
    PluginPatch patchFunc;
    PluginFini finiFunc;
};

/*
 * Match kinds.
 */
enum MatchKind
{
    MATCH_INVALID,
    MATCH_TRUE,
    MATCH_FALSE,
    MATCH_PLUGIN,
    MATCH_ASSEMBLY,
    MATCH_ADDRESS,
    MATCH_CALL,
    MATCH_CONDJUMP,
    MATCH_JUMP,
    MATCH_MMX,
    MATCH_MNEMONIC,
    MATCH_OFFSET,
    MATCH_RANDOM,
    MATCH_RETURN,
    MATCH_SECTION,
    MATCH_SIZE,
    MATCH_TARGET,
    MATCH_X87,
    MATCH_SSE,
    MATCH_AVX,
    MATCH_AVX2,
    MATCH_AVX512,

    MATCH_BB_ENTRY,

    MATCH_OP,
    MATCH_SRC,
    MATCH_DST,
    MATCH_IMM,
    MATCH_REG,
    MATCH_MEM,

    MATCH_REGS,
    MATCH_READS,
    MATCH_WRITES,
};

/*
 * Match fields.
 */
enum MatchField
{
    MATCH_FIELD_NONE,
    MATCH_FIELD_TYPE,
    MATCH_FIELD_ACCESS,
    MATCH_FIELD_SIZE,
    MATCH_FIELD_SEG,
    MATCH_FIELD_DISPL,
    MATCH_FIELD_BASE,
    MATCH_FIELD_INDEX,
    MATCH_FIELD_SCALE,
};

/*
 * Match types.
 */
typedef unsigned MatchType;
#define MATCH_TYPE_UNDEFINED    0x00
#define MATCH_TYPE_NIL          0x01
#define MATCH_TYPE_INTEGER      0x02
#define MATCH_TYPE_OPERAND      0x04
#define MATCH_TYPE_ACCESS       0x08
#define MATCH_TYPE_REGISTER     0x10
#define MATCH_TYPE_MEMORY       0x20
#define MATCH_TYPE_STRING       0x40

/*
 * Parser implementation.
 */
#include "e9parser.cpp"

/*
 * Match value.
 */
struct MatchValue
{
    MatchType type;
    union
    {
        intptr_t i;
        OpType op;
        Access access;
        Register reg;
    };

    int compare(const MatchValue &value) const
    {
        if (value.type < type)
            return 1;
        if (value.type > type)
            return -1;
        switch (type)
        {
            case MATCH_TYPE_INTEGER:
                return (value.i < i? 1:
                       (value.i > i? -1: 0));
            case MATCH_TYPE_OPERAND:
                return (value.op < op? 1:
                       (value.op > op? -1: 0));
            case MATCH_TYPE_ACCESS:
                return (value.access < access? 1:
                       (value.access > access? -1: 0));
            case MATCH_TYPE_REGISTER:
                return (value.reg < reg? 1:
                       (value.reg > reg? -1: 0));
            default:
                return 0;
        }
    }

    bool operator==(const MatchValue &value) const
    {
        return (compare(value) == 0);
    }
    bool operator<(const MatchValue &value) const
    {
        return (compare(value) < 0);
    }
    bool operator<=(const MatchValue &value) const
    {
        return (compare(value) <= 0);
    }
    bool operator>(const MatchValue &value) const
    {
        return (compare(value) > 0);
    }
    bool operator>=(const MatchValue &value) const
    {
        return (compare(value) >= 0);
    }
};

/*
 * Match comparison operator.
 */
enum MatchCmp
{
    MATCH_CMP_INVALID,
    MATCH_CMP_DEFINED,
    MATCH_CMP_EQ_ZERO,
    MATCH_CMP_NEQ_ZERO,
    MATCH_CMP_EQ,
    MATCH_CMP_NEQ,
    MATCH_CMP_LT,
    MATCH_CMP_LEQ,
    MATCH_CMP_GT,
    MATCH_CMP_GEQ,
    MATCH_CMP_IN
};

/*
 * CSV implementation.
 */
#include "e9csv.cpp"

/*
 * A match entry.
 */
struct MatchTest
{
    const MatchKind  match;
    const int        idx;
    const MatchField field;
    const MatchCmp   cmp;
    const char *     basename;
    Plugin * const   plugin;
    union
    {
        void *data;
        std::regex *regex;
        Index<MatchValue> *values;
        std::set<Register> *regs;
    };

    MatchTest(MatchKind match, int idx, MatchField field, MatchCmp cmp,
            Plugin *plugin, const char *basename) :
        match(match), field(field), idx(idx), cmp(cmp), basename(basename),
        plugin(plugin)
    {
        data = nullptr;
    }
};

/*
 * Match operations.
 */
enum MatchOp
{
    MATCH_OP_NOT,
    MATCH_OP_AND,
    MATCH_OP_OR,
    MATCH_OP_TEST,
};

/*
 * A match expression.
 */
struct MatchExpr
{
    const MatchOp op;
    union
    {
        const MatchExpr *arg1;
        const MatchTest *test;
    };
    const MatchExpr *arg2;

    MatchExpr(MatchOp op, const MatchExpr *arg) :
        op(op), arg1(arg), arg2(nullptr)
    {
        assert(op == MATCH_OP_NOT);
    }

    MatchExpr(MatchOp op, const MatchExpr *arg1, const MatchExpr *arg2) :
        op(op), arg1(arg1), arg2(arg2)
    {
        assert(op == MATCH_OP_AND || op == MATCH_OP_OR);
    }

    MatchExpr(MatchOp op, const MatchTest *test) : op(op), test(test),
        arg2(nullptr)
    {
        assert(op == MATCH_OP_TEST);
    }
};

/*
 * Patch kind.
 */
enum PatchKind
{
    PATCH_EMPTY,
    PATCH_BREAK,
    PATCH_TRAP,
    PATCH_PRINT,
    PATCH_EXIT,
    PATCH_CALL,
    PATCH_PLUGIN,
};

/*
 * Patch.
 */
struct Patch
{
    const char * const name;
    const PatchKind kind;
    const PatchPos pos;

    int status = 0;
    const CallABI abi = ABI_CLEAN;
    const CallJump jmp = JUMP_NONE;
    const char * const symbol = nullptr;
    const std::vector<Argument> args;
    const char * const filename = nullptr;
    mutable const ELF * elf = nullptr;
    Plugin * const plugin = nullptr;

    Patch(const char *name, PatchKind kind, PatchPos pos) :
        name(name), kind(kind), pos(pos)
    {
        assert(kind == PATCH_EMPTY || kind == PATCH_BREAK ||
            kind == PATCH_PRINT || kind == PATCH_TRAP);
    };

    Patch(const char *name, PatchKind kind, PatchPos pos, int status) :
        name(name), kind(kind), pos(pos), status(status)
    {
        assert(kind == PATCH_EXIT);
    }

    Patch(const char *name, PatchKind kind, PatchPos pos, CallABI abi,
            CallJump jmp, const char *symbol, const std::vector<Argument> &args,
            const char *filename) :
        name(name), kind(kind), pos(pos),
        abi(abi), jmp(jmp), symbol(symbol), args(args), filename(filename)
    {
        assert(kind == PATCH_CALL);
    }

    Patch(const char *name, PatchKind kind, PatchPos pos, Plugin *plugin) :
        name(name), kind(kind), pos(pos), plugin(plugin)
    {
        assert(kind == PATCH_PLUGIN);
    }
};

/*
 * An "action" is a match/patch pair.
 */
struct Action
{
    const MatchExpr * const match;
    const std::vector<const Patch *> patch;

    Action(const MatchExpr * match, std::vector<const Patch *> &&patch) :
        match(match), patch(patch)
    {
        ;
    }
};

/*
 * Metadata implementation.
 */
#include "e9metadata.cpp"

/*
 * Open a new plugin object.
 */
static std::map<const char *, Plugin *, CStrCmp> plugins;
static Plugin *openPlugin(const char *basename)
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

    plugins.insert({plugin->filename, plugin});
    return plugin;
}

/*
 * Notify all plugins of a new instruction.
 */
static void notifyPlugins(FILE *out, const ELF *elf, const Instr *Is,
    size_t size, Event event)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->eventFunc == nullptr)
            continue;
        Context cxt = {out, plugin->context, elf, Is, (ssize_t)size, -1,
            nullptr, -1};
        plugin->eventFunc(&cxt, event);
    }
}

/*
 * Get the match value for all plugins.
 */
static void matchPlugins(FILE *out, const ELF *elf, const Instr *Is,
    size_t size, size_t idx, const InstrInfo *I)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->matchFunc == nullptr)
            continue;
        Context cxt = {out, plugin->context, elf, Is, (ssize_t)size,
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
        Context cxt = {out, nullptr, elf, nullptr, -1, -1, nullptr, -1};
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
        Context cxt = {out, plugin->context, elf, nullptr, -1, -1, nullptr,
            -1};
        plugin->finiFunc(&cxt);
    }
}

/*
 * Deprecated feature error.
 */
static NO_RETURN void deprecated(const char *what)
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
 * Parse and index.
 */
static intptr_t parseIndex(Parser &parser, intptr_t lb, intptr_t ub)
{
    parser.expectToken('[');
    parser.expectToken(TOKEN_INTEGER);
    intptr_t idx = parser.i;
    parser.expectToken(']');
    if (idx < lb || idx > ub)
        error("failed to parse %s; expected index within the range "
            "%ld..%ld, found %ld", parser.mode, lb, ub, idx);
    return idx;
}

/*
 * Parse a symbolic value.
 */
static intptr_t parseSymbol(Parser &parser, const char *symbol)
{
    intptr_t val = getELFObject(parser.elf, symbol);
    if (val == -1)
    {
        warning("symbol \"%s\" is undefined and therefore has value 0x0",
            symbol);
        return 0x0;
    }
    else if (val == INTPTR_MIN)
        error("failed to parse %s; \"%s\" does not correspond to "
            "any section or symbol name", parser.mode, symbol);
    return val;
}

/*
 * Parse values.
 */
static void parseValues(Parser &parser, MatchType type, MatchCmp cmp,
    Index<MatchValue> &index)
{
    while (true)
    {
        MatchValue value = {0};
        bool neg = false;
        switch (parser.getToken())
        {
            case '&':
                parser.expectToken2(TOKEN_STRING, TOKEN_NAME);
                value.type = MATCH_TYPE_INTEGER;
                value.i = parseSymbol(parser, parser.s);
                break;
            case TOKEN_NIL:
                value.type = MATCH_TYPE_NIL;
                break;
            case '-':
                if (parser.peekToken() != TOKEN_INTEGER)
                {
                    value.type   = MATCH_TYPE_ACCESS;
                    value.access = (Access)0x0;
                    break;
                }
                neg = true;
                // Fallthrough:
            case '+':
                parser.expectToken(TOKEN_INTEGER);
                // Fallthrough:
            case TOKEN_INTEGER:
                value.type = MATCH_TYPE_INTEGER;
                value.i    = (neg? -parser.i: parser.i);
                break;
            case TOKEN_REGISTER:
                value.type = MATCH_TYPE_REGISTER;
                value.reg  = (Register)parser.i;
                break;
            case TOKEN_IMM: case TOKEN_REG: case TOKEN_MEM:
                value.type = MATCH_TYPE_OPERAND;
                value.op   = (OpType)parser.i;
                break;
            case TOKEN_NONE: case TOKEN_READ: case TOKEN_WRITE: case TOKEN_RW:
                value.type   = MATCH_TYPE_ACCESS;
                value.access = (Access)parser.i;
                break;
            default:
                parser.unexpectedToken();
        }
        if ((type & value.type) == 0)
            parser.unexpectedToken();       // Type error
        index.insert({value, nullptr});
        if (cmp != MATCH_CMP_EQ || parser.peekToken() != ',')
            break;
        parser.getToken();
    }
}

/*
 * Parse a match test.
 */
static MatchTest *parseTest(Parser &parser)
{
    int t = parser.getToken();
    MatchKind match = MATCH_INVALID;
    MatchType type  = MATCH_TYPE_INTEGER;
    MatchCmp  cmp   = MATCH_CMP_INVALID;
    std::set<Register> regs;
    if (t == TOKEN_DEFINED)
    {
        parser.expectToken('(');
        cmp = MATCH_CMP_DEFINED;
        t = parser.getToken();
    }
    switch (t)
    {
        case TOKEN_ASM:
            type = MATCH_TYPE_STRING;
            match = MATCH_ASSEMBLY; break;
        case TOKEN_ADDR:
            match = MATCH_ADDRESS; break;
        case TOKEN_CALL:
            match = MATCH_CALL; break;
        case TOKEN_DST:
            match = MATCH_DST; break;
        case TOKEN_FALSE:
            match = MATCH_FALSE; break;
        case TOKEN_IMM:
            match = MATCH_IMM; break;
        case TOKEN_CONDJUMP:
            match = MATCH_CONDJUMP; break;
        case TOKEN_JUMP:
            match = MATCH_JUMP; break;
        case TOKEN_MEM:
            match = MATCH_MEM; break;
        case TOKEN_MNEMONIC:
            type = MATCH_TYPE_STRING;
            match = MATCH_MNEMONIC; break;
        case TOKEN_OFFSET:
            match = MATCH_OFFSET; break;
        case TOKEN_OP:
            match = MATCH_OP; break;
        case TOKEN_PLUGIN:
            match = MATCH_PLUGIN; break;
        case TOKEN_RANDOM:
            match = MATCH_RANDOM; break;
        case TOKEN_REG:
            match = MATCH_REG; break;
        case TOKEN_RETURN:
            match = MATCH_RETURN; break;
        case TOKEN_SECTION:
            type = MATCH_TYPE_STRING;
            match = MATCH_SECTION; break;
        case TOKEN_SIZE: case TOKEN_LENGTH:
            match = MATCH_SIZE; break;
        case TOKEN_SRC:
            match = MATCH_SRC; break;
        case TOKEN_TARGET:
            match = MATCH_TARGET; break;
        case TOKEN_TRUE:
            match = MATCH_TRUE; break;
        case TOKEN_REGISTER:
            cmp = MATCH_CMP_IN;
            regs.insert((Register)parser.i);
            while (parser.peekToken() == ',')
            {
                parser.getToken();
                parser.expectToken(TOKEN_REGISTER);
                regs.insert((Register)parser.i);
            }
            parser.expectToken(TOKEN_IN);
            t = parser.getToken();
            // Fallthrough:
        case TOKEN_READS: case TOKEN_WRITES: case TOKEN_REGS:
            if (cmp == MATCH_CMP_INVALID)
                parser.unexpectedToken();
            switch (t)
            {
                case TOKEN_REGS:
                    match = MATCH_REGS; break;
                case TOKEN_READS:
                    match = MATCH_READS; break;
                case TOKEN_WRITES:
                    match = MATCH_WRITES; break;
                default:
                    parser.unexpectedToken();
            }
            break;
        case TOKEN_AVX:
            match = MATCH_AVX; break;
        case TOKEN_AVX2:
            match = MATCH_AVX2; break;
        case TOKEN_AVX512:
            match = MATCH_AVX512; break;
        case TOKEN_MMX:
            match = MATCH_MMX; break;
        case TOKEN_SSE:
            match = MATCH_SSE; break;
        case TOKEN_X87:
            match = MATCH_X87; break;
        case TOKEN_BB:
            parser.expectToken('.');
            switch (parser.getToken())
            {
                case TOKEN_ENTRY:
                    match = MATCH_BB_ENTRY; break;
                default:
                    parser.unexpectedToken();
            }
            option_cfg = true;
            break;
        default:
            parser.unexpectedToken();
    }
    int attr = t;
    Plugin *plugin = nullptr;
    int idx = -1;
    MatchField field = MATCH_FIELD_NONE;
    switch (match)
    {
        case MATCH_PLUGIN:
        {
            parser.expectToken('(');
            parser.expectToken2(TOKEN_STRING, TOKEN_NAME);
            std::string filename(parser.s);
            parser.expectToken(')');
            parser.expectToken('.');
            parser.expectToken(TOKEN_MATCH);
            parser.expectToken('(');
            parser.expectToken(')');
            plugin = openPlugin(filename.c_str());
            if (plugin->matchFunc == nullptr)
                error("failed to parse matching; plugin \"%s\" does not "
                    "export the \"e9_plugin_match_v1\" function",
                    plugin->filename);
            break;
        }

        case MATCH_OP: case MATCH_SRC: case MATCH_DST:
        case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
            switch (parser.peekToken())
            {
                case '.':
                    break;
                case '[':
                    idx = (unsigned)parseIndex(parser, 0, 7);
                    break;
                default:
                    parser.unexpectedToken();
            }
            if (parser.peekToken() == '.')
            {
                parser.getToken();
                bool need_idx = true;
                switch (parser.peekToken())
                {
                    case TOKEN_TYPE:
                        type = MATCH_TYPE_OPERAND;
                        field = MATCH_FIELD_TYPE; break;
                    case TOKEN_ACCESS:
                        type = MATCH_TYPE_ACCESS;
                        field = MATCH_FIELD_ACCESS; break;
                    case TOKEN_SIZE: case TOKEN_LENGTH:
                        need_idx = false;
                        field = MATCH_FIELD_SIZE; break;
                    case TOKEN_SEGMENT:
                        type = MATCH_TYPE_REGISTER | MATCH_TYPE_NIL;
                        field = MATCH_FIELD_SEG; break;
                    case TOKEN_DISPLACEMENT:
                        field = MATCH_FIELD_DISPL; break;
                    case TOKEN_BASE:
                        type = MATCH_TYPE_REGISTER | MATCH_TYPE_NIL;
                        field = MATCH_FIELD_BASE; break;
                    case TOKEN_INDEX:
                        type = MATCH_TYPE_REGISTER | MATCH_TYPE_NIL;
                        field = MATCH_FIELD_INDEX; break;
                    case TOKEN_SCALE:
                        field = MATCH_FIELD_SCALE; break;
                    default:
                        parser.unexpectedToken();
                }
                if (need_idx && idx < 0)
                    parser.unexpectedToken();
                parser.getToken();
            }
            else if (idx >= 0)
                type = MATCH_TYPE_INTEGER | MATCH_TYPE_REGISTER;
            break;

        default:
            break;
    }

    if (cmp == MATCH_CMP_DEFINED)
        parser.expectToken(')');
    else if (cmp != MATCH_CMP_IN)
    {
        switch (parser.peekToken())
        {
            case '=':
                cmp = MATCH_CMP_EQ; break;
            case TOKEN_NEQ:
                cmp = MATCH_CMP_NEQ; break;
            case '<':
                cmp = MATCH_CMP_LT; break;
            case TOKEN_LEQ:
                cmp = MATCH_CMP_LEQ; break;
            case '>':
                cmp = MATCH_CMP_GT; break;
            case TOKEN_GEQ:
                cmp = MATCH_CMP_GEQ; break;
            default:
                cmp = MATCH_CMP_NEQ_ZERO; break;
        }
        if (cmp != MATCH_CMP_NEQ_ZERO)
            (void)parser.getToken();
    }
    switch (match)
    {
        case MATCH_ASSEMBLY: case MATCH_MNEMONIC: case MATCH_SECTION:
            if (cmp != MATCH_CMP_EQ && cmp != MATCH_CMP_NEQ &&
                    cmp != MATCH_CMP_DEFINED)
                error("failed to parse matching; invalid match "
                    "comparison operator \"%s\" for attribute \"%s\"",
                    parser.s, parser.getName(attr));
            break;
        default:
            break;
    }

    MatchTest *test = new MatchTest(match, idx, field, cmp, plugin, nullptr);
    if (cmp == MATCH_CMP_DEFINED)
        return test;
    else if (cmp == MATCH_CMP_IN)
    {
        test->regs = new std::set<Register>;
        test->regs->swap(regs);
    }
    else if (type == MATCH_TYPE_STRING)
    {
        t = parser.getBlob();
        std::string str;
        switch (t)
        {
            case TOKEN_REGEX:
                str = parser.s;
                break;
            case TOKEN_STRING: case TOKEN_NAME:
                str += parser.s;
                break;
            default:
                parser.unexpectedToken();
        }
        test->regex = new std::regex(str);
    }
    else
    {
        if (cmp == MATCH_CMP_EQ_ZERO || cmp == MATCH_CMP_NEQ_ZERO)
            return test;
        test->values = new Index<MatchValue>;
        if (parser.peekToken() == TOKEN_STRING ||
                parser.peekToken() == TOKEN_NAME)
        {
            parser.getToken();
            if ((type & MATCH_TYPE_INTEGER) == 0)
                parser.unexpectedToken();
            test->basename = strDup(parser.s);
            std::string filename(parser.s);
            filename += ".csv";
            intptr_t idx = parseIndex(parser, INTPTR_MIN, INTPTR_MAX);
            Data *data = parseCSV(filename.c_str());
            buildIntIndex(test->basename, *data, idx, *test->values);
        }
        else
            parseValues(parser, type, cmp, *test->values);
    }
    return test;
}

/*
 * Parse a match test expr.
 */
static MatchExpr *parseMatchExpr(Parser &parser, MatchOp op);
static MatchExpr *parseTestExpr(Parser &parser)
{
    MatchExpr *expr = nullptr;
    switch (parser.peekToken())
    {
        case '(':
            (void)parser.getToken();
            expr = parseMatchExpr(parser, MATCH_OP_OR);
            parser.expectToken(')');
            break;
        case '!': case TOKEN_NOT:
            (void)parser.getToken();
            expr = parseMatchExpr(parser, MATCH_OP_OR);
            expr = new MatchExpr(MATCH_OP_NOT, expr);
            break;
        default:
        {
            MatchTest *test = parseTest(parser);
            expr = new MatchExpr(MATCH_OP_TEST, test);
            break;
        }
    }
    return expr;
}

/*
 * Parse a match expr.
 */
static MatchExpr *parseMatchExpr(Parser &parser, MatchOp op)
{
    MatchExpr *expr = nullptr;
    if (op == MATCH_OP_AND)
        expr = parseTestExpr(parser);
    else
        expr = parseMatchExpr(parser, MATCH_OP_AND);
    while (true)
    {
        MatchExpr *arg = nullptr;
        switch (parser.peekToken())
        {
            case TOKEN_AND:
                (void)parser.getToken();
                arg = parseTestExpr(parser);
                expr = new MatchExpr(MATCH_OP_AND, expr, arg);
                break;
            case TOKEN_OR:
                (void)parser.getToken();
                arg = parseMatchExpr(parser, MATCH_OP_AND);
                expr = new MatchExpr(MATCH_OP_OR, expr, arg);
                break;
            default:
                return expr;
        }
    }
}

/*
 * Parse a match expr.
 */
static MatchExpr *parseMatch(const ELF &elf, const char *str)
{
    Parser parser(str, "matching", elf);
    MatchExpr *expr = parseMatchExpr(parser, MATCH_OP_OR);
    parser.expectToken(TOKEN_EOF);
    return expr;
}

/*
 * Parse a memory operand.
 */
static void parseMemOp(Parser &parser, int t, MemOp &memop)
{
    switch (t)
    {
        case TOKEN_MEM8:
            memop.size = sizeof(int8_t); break;
        case TOKEN_MEM16:
            memop.size = sizeof(int8_t); break;
        case TOKEN_MEM32:
            memop.size = sizeof(int8_t); break;
        case TOKEN_MEM64:
            memop.size = sizeof(int8_t); break;
        default:
            parser.unexpectedToken();
    }

    intptr_t disp64 = 0x0;
    intptr_t scale64 = 1;
    memop.seg   = REGISTER_NONE;
    memop.disp  = 0x0;
    memop.base  = REGISTER_NONE;
    memop.index = REGISTER_NONE;
    memop.scale = 1;

    parser.expectToken('<');
    if (parser.peekToken() == TOKEN_REGISTER)
    {
        parser.getToken();
        memop.seg = (Register)parser.i;
        parser.expectToken(':');
    }
    bool neg = false;
    switch (parser.peekToken())
    {
        case '-':
            neg = true;
            // Fallthrough:
        case '+':
            parser.getToken();
            // Fallthrough:
        case TOKEN_INTEGER:
            parser.expectToken(TOKEN_INTEGER);
            disp64 = (neg? -parser.i: parser.i);
            break;
        default:
            break;
    }

    if (parser.peekToken() != '(')
        goto memop_validate;
    parser.getToken();

    switch (parser.getToken())
    {
        case ',':
            break;
        case TOKEN_NIL: case TOKEN_REGISTER:
            memop.base = (Register)parser.i;
            switch (parser.getToken())
            {
                case ')':
                    goto memop_validate;
                case ',':
                    break;
                default:
                    parser.unexpectedToken();
            }
            break;
        case ')':
            goto memop_validate;
        default:
            parser.unexpectedToken();
    }

    switch (parser.getToken())
    {
        case ',':
            break;
        case TOKEN_NIL: case TOKEN_REGISTER:
            memop.index = (Register)parser.i;
            switch (parser.getToken())
            {
                case ')':
                    goto memop_validate;
                case ',':
                    break;
                default:
                    parser.unexpectedToken();
            }
            break;
        case ')':
            goto memop_validate;
        default:
            parser.unexpectedToken();
    }

    parser.expectToken(TOKEN_INTEGER);
    scale64 = parser.i;
    parser.expectToken(')');

memop_validate:
    parser.expectToken('>');

    if (disp64 < INT32_MIN || disp64 > INT32_MAX)
        error("failed to parse %s; expected displacement within the range "
            "%ld..%ld, found %ld", parser.mode, INT32_MIN, INT32_MAX, disp64);
    switch (memop.seg)
    {
        case REGISTER_NONE:
        case REGISTER_ES: case REGISTER_CS: case REGISTER_SS:
        case REGISTER_DS: case REGISTER_FS: case REGISTER_GS:
            break;
        default:
            error("failed to parse %s; invalid memory operand "
                "segment register %s ", parser.mode,
                getRegName(getReg(memop.seg)));
    }
    switch (memop.base)
    {
        case REGISTER_NONE:
        case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
        case REGISTER_RBX: case REGISTER_RSP: case REGISTER_RBP:
        case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
        case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
        case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
        case REGISTER_R15: case REGISTER_RIP:
        case REGISTER_EAX: case REGISTER_ECX: case REGISTER_EDX:
        case REGISTER_EBX: case REGISTER_ESP: case REGISTER_EBP:
        case REGISTER_ESI: case REGISTER_EDI: case REGISTER_R8D:
        case REGISTER_R9D: case REGISTER_R10D: case REGISTER_R11D:
        case REGISTER_R12D: case REGISTER_R13D: case REGISTER_R14D:
        case REGISTER_R15D:
            break;
        default:
            error("failed to parse %s; invalid memory operand "
                "base register %s ", parser.mode,
                getRegName(getReg(memop.base)));
    }
    switch (memop.index)
    {
        case REGISTER_NONE:
        case REGISTER_RAX: case REGISTER_RCX: case REGISTER_RDX:
        case REGISTER_RBX: case REGISTER_RBP:
        case REGISTER_RSI: case REGISTER_RDI: case REGISTER_R8:
        case REGISTER_R9: case REGISTER_R10: case REGISTER_R11:
        case REGISTER_R12: case REGISTER_R13: case REGISTER_R14:
        case REGISTER_R15:
        case REGISTER_EAX: case REGISTER_ECX: case REGISTER_EDX:
        case REGISTER_EBX: case REGISTER_EBP:
        case REGISTER_ESI: case REGISTER_EDI: case REGISTER_R8D:
        case REGISTER_R9D: case REGISTER_R10D: case REGISTER_R11D:
        case REGISTER_R12D: case REGISTER_R13D: case REGISTER_R14D:
        case REGISTER_R15D:
            break;
        default:
            error("failed to parse %s; invalid memory operand "
                "index register %s ", parser.mode,
                getRegName(getReg(memop.index)));
    }
    switch (scale64)
    {
        case 1: case 2: case 4: case 8:
            break;
        default:
            error("failed to parse %s; expected scale with value "
                "{1,2,4,8}, found %ld", parser.mode, scale64);
    }
    if (memop.base == REGISTER_RIP && memop.index != REGISTER_NONE &&
            memop.scale != 1)
        error("failed to parse %s; invalid memory operand with "
            "%rip base register and non-empty index/scale", parser.mode);
    memop.disp  = (int32_t)disp64;
    memop.scale = (uint8_t)scale64;
}

/*
 * Parse a function name.
 */
static const char *parseFunctionName(Parser &parser)
{
    if (!isalpha(parser.s[0]) && parser.s[0] != '_')
        parser.unexpectedToken();
    for (unsigned i = 1; parser.s[i] != '\0'; i++)
    {
        if (!isalpha(parser.s[i]) && !isdigit(parser.s[i]) &&
                parser.s[i] != '_')
            parser.unexpectedToken();
    }
    switch (parser.getTokenFromName(parser.s))
    {
        case TOKEN_IF: case TOKEN_GOTO:
            parser.unexpectedToken();
        default:
            break;
    }
    return strDup(parser.s);
}

/*
 * Parse a patch.
 */
static const Patch *parsePatch(const ELF &elf, const char *str)
{
    PatchKind kind;
    Parser parser(str, "patch", elf);

    PatchPos pos = POS_BEFORE;
    switch (parser.peekToken())
    {
        case TOKEN_BEFORE:
            parser.getToken(); pos = POS_BEFORE; break;
        case TOKEN_REPLACE:
            parser.getToken(); pos = POS_REPLACE; break;
        case TOKEN_AFTER:
            parser.getToken(); pos = POS_AFTER; break;
        default:
            break;
    }

    bool conditional = false;
    const char *symbol = nullptr;
    switch (parser.getToken())
    {
        case TOKEN_BREAK:
            kind = PATCH_BREAK; break;
        case TOKEN_CALL:
            deprecated("call ...");
        case TOKEN_EMPTY:
            kind = PATCH_EMPTY; break;
        case TOKEN_EXIT:
            kind = PATCH_EXIT; break;
        case TOKEN_PASSTHRU:
            deprecated("passthru");
        case TOKEN_PRINT:
            kind = PATCH_PRINT; break;
        case TOKEN_PLUGIN:
            kind = PATCH_PLUGIN; break;
        case TOKEN_TRAP:
            kind = PATCH_TRAP; break;
        case TOKEN_IF:
            conditional = true;
            parser.getToken();
            // Fallthrough
        default:
            symbol = parseFunctionName(parser);
            kind = PATCH_CALL; break;
    }

    // Parse the rest of the patch (if necessary):
    const char *filename = nullptr;
    Plugin *plugin = nullptr;
    CallABI abi = ABI_CLEAN;
    CallJump jmp = JUMP_NONE;
    std::vector<Argument> args;
    int status = 0;
    int t = 0;
    switch (kind)
    {
        case PATCH_EXIT:
            parser.expectToken('(');
            parser.expectToken(TOKEN_INTEGER);
            if (parser.i < 0 || parser.i > 255)
                error("failed to parse exit trampoline; the exit status "
                    " must be an integer within the range 0..255");
            status = (int)parser.i;
            parser.expectToken(')');
            break;

        case PATCH_PLUGIN:
            parser.expectToken('(');
            parser.expectToken2(TOKEN_STRING, TOKEN_NAME);
            filename = strDup(parser.s);
            parser.expectToken(')');
            parser.expectToken('.');
            parser.expectToken(TOKEN_PATCH);
            parser.expectToken('(');
            parser.expectToken(')');
            plugin = openPlugin(filename);
            break;
        
        case PATCH_CALL:
        {
            t = parser.expectToken2('(', '<');
            if (t == '<')
            {
                t = parser.expectToken2(TOKEN_CLEAN, TOKEN_NAKED);
                abi = (t == TOKEN_CLEAN? ABI_CLEAN: ABI_NAKED);
                parser.expectToken('>');
                parser.expectToken('(');
            }
            while (true)
            {
                t = parser.getToken();
                if (t == ')' && args.size() == 0)
                    break;
                bool ptr = false, neg = false, _static = false;
                switch (t)
                {
                    case TOKEN_STATIC:
                        _static = true;
                        t = parser.getToken();
                        if (t != '&')
                            break;
                        // Fallthrough
                    case '&':
                        ptr = true;
                        t = parser.getToken();
                        break;
                }
                ArgumentKind arg = ARGUMENT_INVALID;
                FieldKind field  = FIELD_NONE;
                MemOp memop = {REGISTER_NONE, 0, REGISTER_NONE,
                    REGISTER_NONE, 1, 0};
                intptr_t value = 0x0;
                int arg_token = t;
                const char *name = nullptr;
                switch (t)
                {
                    case TOKEN_ASM:
                        arg = ARGUMENT_ASM;
                        if (parser.peekToken() != '.')
                            break;
                        parser.getToken();
                        switch (parser.getToken())
                        {
                            case TOKEN_LENGTH:
                                arg = ARGUMENT_ASM_LEN; break;
                            case TOKEN_SIZE:
                                arg = ARGUMENT_ASM_SIZE; break;
                            default:
                                parser.unexpectedToken();
                        }
                        break;
                    case TOKEN_ADDR:
                        arg = ARGUMENT_ADDR; break;
                    case TOKEN_BASE:
                        arg = ARGUMENT_BASE; break;
                    case TOKEN_DST:
                        arg = ARGUMENT_DST; break;
                    case TOKEN_CONFIG:
                        arg = ARGUMENT_CONFIG; break;
                    case TOKEN_ID:
                        arg = ARGUMENT_ID; break;
                    case TOKEN_IMM:
                        arg = ARGUMENT_IMM; break;
                    case TOKEN_INSTR:
                        arg = ARGUMENT_BYTES; break;
                    case TOKEN_MEM:
                        arg = ARGUMENT_MEM; break;
                    case TOKEN_MEM8: case TOKEN_MEM16: case TOKEN_MEM32:
                    case TOKEN_MEM64:
                        arg = ARGUMENT_MEMOP;
                        parseMemOp(parser, t, memop);
                        break;
                    case TOKEN_NEXT:
                        arg = ARGUMENT_NEXT; break;
                    case TOKEN_OFFSET:
                        arg = ARGUMENT_OFFSET; break;
                    case TOKEN_OP:
                        arg = ARGUMENT_OP; break;
                    case TOKEN_RANDOM:
                        arg = ARGUMENT_RANDOM; break;
                    case TOKEN_REG:
                        arg = ARGUMENT_REG; break;
                    case TOKEN_SIZE: case TOKEN_LENGTH:
                        arg = ARGUMENT_BYTES_SIZE; break;
                    case TOKEN_STATE:
                        arg = ARGUMENT_STATE; break;
                    case TOKEN_SRC:
                        arg = ARGUMENT_SRC; break;
                    case TOKEN_TARGET:
                        arg = ARGUMENT_TARGET; break;
                    case TOKEN_TRAMPOLINE:
                        arg = ARGUMENT_TRAMPOLINE; break;
                    case TOKEN_REGISTER:
                        value = parser.i;
                        arg = ARGUMENT_REGISTER;
                        break;
                    case '-':
                        neg = true;
                        // Fallthrough:
                    case '+':
                        parser.expectToken(TOKEN_INTEGER);
                        // Fallthrough:
                    case TOKEN_INTEGER:
                        value = (neg? -parser.i: parser.i);
                        arg = ARGUMENT_INTEGER;
                        break;
                    case TOKEN_STRING:
                        name = strDup(parser.s);
                        arg = (parser.peekToken() == '['? ARGUMENT_USER:
                            ARGUMENT_STRING);
                        break;
                    case TOKEN_NAME:
                        name = strDup(parser.s);
                        arg = (parser.peekToken() == '['? ARGUMENT_USER:
                            ARGUMENT_SYMBOL);
                        break;
                    default:
                        parser.unexpectedToken();
                }
                switch (arg)
                {
                    case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
                    case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
                        value = parseIndex(parser, 0, 7);
                        if (parser.peekToken() == '.')
                        {
                            parser.getToken();
                            t = parser.getToken();
                            switch (t)
                            {
                                case TOKEN_BASE:
                                    field = FIELD_BASE; break;
                                case TOKEN_INDEX:
                                    field = FIELD_INDEX; break;
                                case TOKEN_DISPLACEMENT:
                                    field = FIELD_DISPL; break;
                                case TOKEN_SCALE:
                                    field = FIELD_SCALE; break;
                                case TOKEN_SIZE: case TOKEN_LENGTH:
                                    field = FIELD_SIZE; break;
                                case TOKEN_TYPE:
                                    field = FIELD_TYPE; break;
                                case TOKEN_ACCESS:
                                    field = FIELD_ACCESS; break;
                                default:
                                    parser.unexpectedToken();
                            }
                            if (ptr &&
                                (field != FIELD_BASE && field != FIELD_INDEX))
                            {
                                error("failed to parse call trampoline; "
                                    "cannot pass field `%s' by pointer",
                                    parser.getName(t));
                            }
                        }
                        break;

                    case ARGUMENT_MEMOP: case ARGUMENT_SYMBOL:
                        break;

                    case ARGUMENT_REGISTER:
                        if ((Register)value == REGISTER_RIP)
                            goto not_a_ptr;
                        break;

                    case ARGUMENT_USER:
                        value = parseIndex(parser, INTPTR_MIN, INTPTR_MAX);
                        // Fallthrough:

                    default:
                    not_a_ptr:
                        if (ptr)
                            error("failed to parse call trampoline; cannot "
                                "pass argument `%s' by pointer",
                                parser.getName(arg_token));
                }
                if (_static)
                {
                    switch (arg)
                    {
                        case ARGUMENT_ADDR: case ARGUMENT_NEXT:
                        case ARGUMENT_SYMBOL: case ARGUMENT_TARGET:
                            break;
                        default:
                            error("failed to parse call trampoline; cannot "
                                "use `static' with `%s' argument",
                                parser.getName(arg_token));
                    }
                }
                bool duplicate = false;
                for (const auto &prevArg: args)
                {
                    if (prevArg.kind == arg)
                    {
                        duplicate = true;
                        break;
                    }
                }
                args.push_back({arg, field, ptr, _static, duplicate, value,
                    memop, name});
                t = parser.getToken();
                if (t == ')')
                    break;
                if (t != ',')
                    parser.unexpectedToken();
            }
            parser.expectToken('@');
            parser.getBlob();
            filename = strDup(parser.s);
            if (conditional)
            {
                switch (parser.expectToken2(TOKEN_BREAK, TOKEN_GOTO))
                {
                    case TOKEN_BREAK:
                        jmp = JUMP_BREAK; break;
                    case TOKEN_GOTO:
                        jmp = JUMP_GOTO; break;
                }
            }
            break;
        }
        default:
            break;
    }
    parser.expectToken(TOKEN_EOF);

    // Build the patch:
    std::string name;
    static size_t id = 1;
    switch (kind)
    {
        case PATCH_PRINT:
            return new Patch("$print", PATCH_PRINT, pos);
        case PATCH_EMPTY:
            return new Patch("$empty", PATCH_EMPTY, pos);
        case PATCH_BREAK:
            return new Patch("$BREAK", PATCH_BREAK, pos);
        case PATCH_TRAP:
            return new Patch("$trap", PATCH_TRAP, pos);
        case PATCH_CALL:
            name += "$call_";
            name += std::to_string(id++);
            return new Patch(strDup(name.c_str()), PATCH_CALL, pos, abi, jmp,
                symbol, std::move(args), filename);
        case PATCH_EXIT:
            name += "$exit_";
            name += std::to_string(status);
            return new Patch(strDup(name.c_str()), PATCH_EXIT, pos, status);
        case PATCH_PLUGIN:
            name += "$plugin_";
            name += std::to_string(id++);
            return new Patch(strDup(name.c_str()), PATCH_PLUGIN, pos, plugin);
        default:
            return nullptr;
    }
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
 * Create match string.
 */
static const char *makeMatchString(MatchKind match, const InstrInfo *I)
{
    switch (match)
    {
        case MATCH_ASSEMBLY:
            return I->string.instr;
        case MATCH_MNEMONIC:
            return I->string.mnemonic;
        case MATCH_SECTION:
            return I->string.section;
        default:
            return "";
    }
}

/*
 * Get an operand.
 */
static const OpInfo *getOperand(const InstrInfo *I, int idx, OpType type,
    Access access)
{
    for (uint8_t i = 0; i < I->count.op; i++)
    {
        const OpInfo *op = I->op + i;
        if ((type == OPTYPE_INVALID? true: op->type == type) &&
            (op->access & access) == access)
        {
            if (idx == 0)
                return op;
            idx--;
        }
    }
    return nullptr;
}

/*
 * Get number of operands.
 */
static intptr_t getNumOperands(const InstrInfo *I, OpType type, Access access)
{
    intptr_t n = 0;
    for (uint8_t i = 0; i < I->count.op; i++)
    {
        const OpInfo *op = I->op + i;
        if ((type == OPTYPE_INVALID? true: op->type == type) &&
            (op->access & access) == access)
        {
            n++;
        }
    }
    return n;
}

/*
 * Create match value.
 */
static MatchValue makeMatchValue(MatchKind match, int idx, MatchField field,
    const Targets &targets, const InstrInfo *I, intptr_t plugin_val)
{
    MatchValue result = {0};
    result.type = MATCH_TYPE_INTEGER;
    const OpInfo *op = nullptr;
    OpType type = OPTYPE_INVALID;
    uint8_t access = 0;
    switch (match)
    {
        case MATCH_SRC:
            access = ACCESS_READ; break;
        case MATCH_DST:
            access = ACCESS_WRITE; break;
        case MATCH_IMM:
            type = OPTYPE_IMM; break;
        case MATCH_REG:
            type = OPTYPE_REG; break;
        case MATCH_MEM:
            type = OPTYPE_MEM; break;
        default:
            break;
    }
    switch (match)
    {
        case MATCH_TRUE:
            result.i = true; return result;
        case MATCH_FALSE:
            result.i = false; return result;
        case MATCH_ADDRESS:
            result.i = (intptr_t)I->address; return result;
        case MATCH_CALL:
            result.i = ((I->category & CATEGORY_CALL) != 0); return result;
        case MATCH_CONDJUMP:
            result.i = (((I->category & CATEGORY_JUMP) != 0) &&
                         ((I->category & CATEGORY_CONDITIONAL) != 0));
            return result;
        case MATCH_JUMP:
            result.i = ((I->category & CATEGORY_JUMP) != 0); return result;
        case MATCH_OP: case MATCH_SRC: case MATCH_DST:
        case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
            if (idx < 0)
            {
                switch (field)
                {
                    case MATCH_FIELD_SIZE:
                        result.i = getNumOperands(I, type, access);
                        return result;
                    default:
                        goto undefined;
                }
            }
            else
            {
                op = getOperand(I, idx, type, access);
                if (op == nullptr)
                    goto undefined;
                switch (field)
                {
                    case MATCH_FIELD_NONE:
                        switch (op->type)
                        {
                            case OPTYPE_IMM:
                                result.i = (intptr_t)op->imm;
                                if (I->relative)
                                    result.i += (intptr_t)I->address +
                                                (intptr_t)I->size;
                                return result;
                            case OPTYPE_REG:
                                result.type = MATCH_TYPE_REGISTER;
                                result.reg  = op->reg;
                                return result;
                            case OPTYPE_MEM:
                                result.type = MATCH_TYPE_MEMORY;
                                return result;
                            default:
                                goto undefined;
                        }
                    case MATCH_FIELD_SIZE:
                        result.i = (intptr_t)op->size; return result;
                    case MATCH_FIELD_TYPE:
                        result.type = MATCH_TYPE_OPERAND;
                        result.op   = op->type;
                        return result;
                    case MATCH_FIELD_ACCESS:
                        result.type   = MATCH_TYPE_ACCESS;
                        result.access = op->access;
                        return result;
                    case MATCH_FIELD_SEG:
                        if (op->type != OPTYPE_MEM)
                            goto undefined;
                        if (op->mem.seg == REGISTER_NONE)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = op->mem.seg;
                        return result;
                    case MATCH_FIELD_DISPL:
                        if (op->type != OPTYPE_MEM)
                            goto undefined;
                        result.i = (intptr_t)op->mem.disp;
                        return result;
                    case MATCH_FIELD_BASE:
                        if (op->type != OPTYPE_MEM)
                            goto undefined;
                        if (op->mem.base == REGISTER_NONE)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = op->mem.base;
                        return result;
                    case MATCH_FIELD_INDEX:
                        if (op->type != OPTYPE_MEM)
                            goto undefined;
                        if (op->mem.index == REGISTER_NONE)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = op->mem.index;
                        return result;
                    case MATCH_FIELD_SCALE:
                        if (op->type != OPTYPE_MEM)
                            goto undefined;
                        result.i = (intptr_t)op->mem.scale;
                        return result;
                    default:
                        goto undefined;
                }
            }
            goto undefined;
        case MATCH_OFFSET:
            result.i = (intptr_t)I->offset; return result;
        case MATCH_PLUGIN:
            result.i = plugin_val; return result;
        case MATCH_RANDOM:
            result.i = (intptr_t)rand(); return result;
        case MATCH_RETURN:
            result.i = ((I->category & CATEGORY_RETURN) != 0); return result;
        case MATCH_SIZE:
            result.i = (intptr_t)I->size; return result;
        case MATCH_TARGET:
            if ((I->category & CATEGORY_CALL) != 0 ||
                (I->category & CATEGORY_JUMP) != 0)
            {
                if (I->count.op != 1 || I->op[0].type != OPTYPE_IMM)
                    goto undefined;
                result.i = (intptr_t)I->op[0].imm + (intptr_t)I->address +
                    (intptr_t)I->size;
                return result;
            }
            goto undefined;
        case MATCH_AVX:
            result.i = ((I->category & CATEGORY_AVX) != 0); return result;
        case MATCH_AVX2:
            result.i = ((I->category & CATEGORY_AVX2) != 0); return result;
        case MATCH_AVX512:
            result.i = ((I->category & CATEGORY_AVX512) != 0); return result;
        case MATCH_MMX:
            result.i = ((I->category & CATEGORY_MMX) != 0); return result;
        case MATCH_SSE:
            result.i = ((I->category & CATEGORY_SSE) != 0); return result;
        case MATCH_X87:
            result.i = ((I->category & CATEGORY_X87) != 0); return result;
        case MATCH_BB_ENTRY:
            result.i = (targets.find((intptr_t)I->address) != targets.end());
            return result;
        default:
        undefined:
            result.type = MATCH_TYPE_UNDEFINED;
            return result;
    }
}

/*
 * Evaluate a matching.
 */
static bool matchEval(const MatchExpr *expr, const Targets &targets,
    const InstrInfo *I, const char *basename, const Record **record)
{
    if (expr == nullptr)
        return true;
    bool pass = false;
    const MatchTest *test = nullptr;
    switch (expr->op)
    {
        case MATCH_OP_NOT:
            pass = matchEval(expr->arg1, targets, I, nullptr, nullptr);
            return !pass;
        case MATCH_OP_AND:
            pass = matchEval(expr->arg1, targets, I, basename, record);
            if (!pass)
                return false;
            return matchEval(expr->arg2, targets, I, basename, record);
        case MATCH_OP_OR:
            pass = matchEval(expr->arg1, targets, I, basename, record);
            if (pass)
                return true;
            return matchEval(expr->arg2, targets, I, basename, record);
        case MATCH_OP_TEST:
            test = expr->test;
            break;
        default:
            return false;
    }

    switch (test->match)
    {
        case MATCH_ASSEMBLY: case MATCH_MNEMONIC: case MATCH_SECTION:
        {
            if (test->cmp == MATCH_CMP_DEFINED)
            {
                pass = true;
                break;
            }
            const char *str = makeMatchString(test->match, I);
            std::cmatch cmatch;
            pass = std::regex_match(str, cmatch, *test->regex);
            pass = (test->cmp == MATCH_CMP_NEQ? !pass: pass);
            break;
        }
        case MATCH_READS: case MATCH_WRITES: case MATCH_REGS:
        {
            if (test->cmp == MATCH_CMP_DEFINED)
            {
                pass = true;
                break;
            }
            for (uint8_t i = 0; !pass && test->match != MATCH_WRITES &&
                    I->regs.read[i] != REGISTER_INVALID; i++)
            {
                auto j = test->regs->find(I->regs.read[i]);
                pass = (j != test->regs->end());
            }
            for (uint8_t i = 0; !pass && test->match != MATCH_READS &&
                    I->regs.write[i] != REGISTER_INVALID; i++)
            {
                auto j = test->regs->find(I->regs.write[i]);
                pass = (j != test->regs->end());
            }
            break;
        }
        case MATCH_TRUE: case MATCH_FALSE: case MATCH_ADDRESS:
        case MATCH_CALL: case MATCH_JUMP: case MATCH_OFFSET:
        case MATCH_OP: case MATCH_SRC: case MATCH_DST:
        case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
        case MATCH_PLUGIN: case MATCH_RANDOM: case MATCH_RETURN:
        case MATCH_SIZE: case MATCH_TARGET: case MATCH_CONDJUMP:
        case MATCH_AVX: case MATCH_AVX2: case MATCH_AVX512:
        case MATCH_MMX: case MATCH_SSE: case MATCH_X87:
        case MATCH_BB_ENTRY:
        {
            if (test->cmp != MATCH_CMP_EQ_ZERO &&
                test->cmp != MATCH_CMP_NEQ_ZERO &&
                test->cmp != MATCH_CMP_DEFINED && test->values->size() == 0)
                break;
            MatchValue x = makeMatchValue(test->match, test->idx,
                test->field, targets, I, 
                (test->match == MATCH_PLUGIN? test->plugin->result: 0));
            switch (test->cmp)
            {
                case MATCH_CMP_DEFINED:
                    pass = true;
                    break;
                case MATCH_CMP_EQ_ZERO:
                    pass = (x.type == MATCH_TYPE_INTEGER && x.i == 0);
                    break;
                case MATCH_CMP_NEQ_ZERO:
                    pass = (x.type == MATCH_TYPE_INTEGER && x.i != 0);
                    break;
                case MATCH_CMP_EQ:
                    pass = (test->values->find(x) != test->values->end());
                    break;
                case MATCH_CMP_NEQ:
                    pass = (test->values->size() == 1?
                            test->values->find(x) == test->values->end():
                            true);
                    break;
                case MATCH_CMP_LT:
                    pass = (x < test->values->rbegin()->first);
                    break;
                case MATCH_CMP_LEQ:
                    pass = (x <= test->values->rbegin()->first);
                    break;
                case MATCH_CMP_GT:
                    pass = (x > test->values->begin()->first);
                    break;
                case MATCH_CMP_GEQ:
                    pass = (x >= test->values->begin()->first);
                    break;
                default:
                    return false;
            }
            if (x.type == MATCH_TYPE_UNDEFINED)
                pass = false;
    
            if (pass && basename != nullptr && record != nullptr && 
                test->cmp == MATCH_CMP_EQ &&
                strcmp(test->basename, basename) == 0)
            {
                auto i = test->values->find(x);
                if (i != test->values->end())
                {
                    if (*record != nullptr && i->second != *record)
                        error("failed to lookup value from file \"%s.csv\"; "
                            "matching is ambiguous", basename);
                    *record = i->second;
                }
            }
            break;
        }
        case MATCH_INVALID:
        default:
            return false;
    }

    return pass;
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
static void match(const std::vector<Action *> &actions, const Targets &targets,
    const InstrInfo *I, std::vector<Action *> &matching)
{
    for (auto *action: actions)
    {
        if (!matchEval(action->match, targets, I))
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
 * Usage.
 */
static void usage(FILE *stream, const char *progname)
{
    fprintf(stream,
        "        ___  _              _\n"
        "   ___ / _ \\| |_ ___   ___ | |\n"
        "  / _ \\ (_) | __/ _ \\ / _ \\| |\n"
        " |  __/\\__, | || (_) | (_) | |\n"
        "  \\___|  /_/ \\__\\___/ \\___/|_|\n"
        "\n"
        "usage: %s [OPTIONS] --match MATCH --patch PATCH ... input-file\n"
        "\n"
        "MATCH\n"
        "=====\n"
        "\n"
        "Matchings determine which instructions should be rewritten.  "
            "Matchings are\n"
        "specified using the `--match'/`-M' option:\n"
        "\n"
        "\t--match MATCH, -M MATCH\n"
        "\t\tSpecifies an instruction matching MATCH.\n"
        "\n"
        "Please see the e9tool-user-guide for more information.\n"
        "\n"
        "PATCH\n"
        "=====\n"
        "\n"
        "Patches determine how matching instructions should be rewritten.  "
            "Patches are\n"
        "specified using the `--patch'/`-P' option:\n"
        "\n"
        "\t--patch PATCH, -P patch\n"
        "\t\tThe PATCH specifies how instructions matching the preceding\n"
        "\t\t`--match'/`-M' options are to be rewritten.\n"
        "\n"
        "Please see the e9tool-user-guide for more information.\n"
        "\n"
        "OTHER OPTIONS\n"
        "=============\n"
        "\n"
        "\t--backend PROG\n"
        "\t\tUse PROG as the backend.  The default is \"e9patch\".\n"
        "\n"
        "\t--compression N, -c N\n"
        "\t\tSet the compression level to be N, where N is a number within\n"
        "\t\tthe range 0..9.  The default is 9 for maximum compression.\n"
        "\t\tHigher compression makes the output binary smaller, but also\n"
        "\t\tincreases the number of mappings (mmap() calls) required.\n"
        "\n"
        "\t--Dsync N\n"
        "\t\tIf the disassembler desyncs (e.g., data in the code section),\n"
        "\t\tthen automatically exclude N surrounding instructions.\n"
        "\t\tThe default is 64.\n"
        "\n"
        "\t--Dthreshold N\n"
        "\t\tTreat suspicious instructions as data.  Lower numbers means\n"
        "\t\tless tolerance.  The default is 2.\n"
        "\n"
        "\t--debug\n"
        "\t\tEnable debug output.\n"
        "\n"
        "\t--exclude RANGE, -E RANGE\n"
        "\t\tExclude the address RANGE from disassembly and rewriting.\n"
        "\t\tHere, RANGE has the format `LB .. UB', where LB/UB are\n"
        "\t\tinteger addresses, section names or symbols.  The address\n"
        "\t\trange [LB..UB) will be excluded, and UB must point to the\n"
        "\t\tfirst instruction where disassembly should resume.\n"
        "\n"
        "\t--executable\n"
        "\t\tTreat the input file as an executable, even if it appears to\n"
        "\t\tbe a shared library.  See the `--shared' option for more\n"
        "\t\tinformation.\n"
        "\n"
        "\t--format FORMAT\n"
        "\t\tSet the output format to FORMAT which is one of {binary,\n"
        "\t\tjson, patch, patch.gz, patch,bz2, patch.xz}.  Here:\n"
        "\n"
        "\t\t\t- \"binary\" is a modified ELF executable file;\n"
        "\t\t\t- \"json\" is the raw JSON RPC stream for the e9patch\n"
        "\t\t\t  backend; or\n"
        "\t\t\t- \"patch\" \"patch.gz\" \"patch.bz2\" and \"patch.xz\"\n"
        "\t\t\t  are (compressed) binary diffs in xxd format.\n"
        "\n"
        "\t\tThe default format is \"binary\".\n"
        "\n"
        "\t--help, -h\n"
        "\t\tPrint this message and exit.\n"
        "\n"
        "\t--no-warnings\n"
        "\t\tDo not print warning messages.\n"
        "\n"
        "\t--plt\n"
        "\t\tEnable the disassembly/rewriting of the .plt/.plt.got sections.\n"
        "\t\tThese sections are excluded by default.\n"
        "\n"
        "\t-O0, -O1, -O2, -O3, -Os\n"
        "\t\tSet the optimization level.  Here:\n"
        "\n"
        "\t\t\t-O0 disables all optimization,\n"
        "\t\t\t-O1 conservatively optimizes for performance,\n"
        "\t\t\t-O2 optimizes for performance,\n"
        "\t\t\t-O3 aggressively optimizes for performance, and \n"
        "\t\t\t-Os optimizes for space.\n"
        "\n"
        "\t\tThe default is -O2.\n"
        "\n"
        "\t--option OPTION\n"
        "\t\tPass OPTION to the e9patch backend.\n"
        "\n"
        "\t--output FILE, -o FILE\n"
        "\t\tSpecifies the path to the output file.  The default filename is\n"
        "\t\tone of {\"a.out\", \"a.so\", \"a.exe\", \"a.dll\"}, depending on\n"
        "\t\tthe input binary type.\n"
        "\n"
        "\t--seed=SEED\n"
        "\t\tSet SEED to be the random number seed.\n"
        "\n"
        "\t--shared\n"
        "\t\tTreat the input file as a shared library, even if it appears to\n"
        "\t\tbe an executable.  By default, the input file will only be\n"
        "\t\ttreated as a shared library if (1) it is a dynamic executable\n"
        "\t\t(ET_DYN) and (2) has a filename of the form:\n"
        "\n"
        "\t\t\t[PATH/]lib*.so[.VERSION]\n"
        "\n"
        "\t--static-loader, -s\n"
        "\t\tReplace patched pages statically.  By default, patched pages\n"
        "\t\tare loaded during program initialization as this is more\n"
        "\t\treliable for large/complex binaries.  However, this may bloat\n"
        "\t\tthe size of the output patched binary.\n"
        "\n"
        "\t--syntax SYNTAX\n"
        "\t\tSelects the assembly syntax to be SYNTAX.  Possible values are:\n"
        "\n"
        "\t\t\t- \"ATT\"  : X86_64 ATT asm syntax; or\n"
        "\t\t\t- \"intel\": X86_64 Intel asm syntax.\n"
        "\n"
        "\t\tThe default syntax is \"ATT\".\n"
        "\n"
        "\t--trap=ADDR, --trap-all\n"
        "\t\tInsert a trap (int3) instruction at the corresponding\n"
        "\t\ttrampoline entry.  This can be used for debugging with gdb.\n"
        "\n", progname);
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
 * Get executable path.
 */
static void getExePath(std::string &path)
{
    char buf[PATH_MAX+1];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len < 0 || (size_t)len > sizeof(buf)-1)
        error("failed to read executable path: %s", strerror(errno));
    buf[len] = '\0';
    char *dir = dirname(buf);
    path += dir;
    if (path.size() > 0 && path[path.size()-1] != '/')
        path += '/';
}

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
int main(int argc, char **argv)
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
                deprecated("--action/-A");
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
    notifyPlugins(out, &elf, Is.data(), Is.size(), EVENT_DISASSEMBLY_COMPLETE);
    size_t count = Is.size();

    // Step (1a): CFG Analysis (if necessary).
    if (option_cfg)
        CFGAnalysis(&elf, Is.data(), Is.size(), elf.targets);

    // Step (2): Find all matching instructions:
    std::vector<Action *> matching;
    MatchingCache Ms;
    for (size_t i = 0; i < count; i++)
    {
        matching.clear();
        RawInstr raw;
        InstrInfo I;
        getInstrInfo(&elf, &Is[i], &I, &raw);
        matchPlugins(out, &elf, Is.data(), Is.size(), i, &I);
        match(actions, elf.targets, &I, matching);
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
    notifyPlugins(out, &elf, Is.data(), Is.size(), EVENT_MATCHING_COMPLETE);

    // Step (3): Send all composite trampolines:
    size_t tid = 0;
    std::map<const Matching *, size_t, MatchingCmp> tmps;
    std::vector<Metadata> metadata;
    std::vector<std::vector<Metadata>> metadatas;
    Context cxt = {out, nullptr, &elf, Is.data(), (ssize_t)count, -1, nullptr,
        -1};
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
        RawInstr raw;
        InstrInfo I;
        getInstrInfo(&elf, &Is[i], &I, &raw);
        bool done = false;
        for (ssize_t j = i; !done && j >= 0; j--)
            done = !sendInstructionMessage(out, Is[j], Is[i].address);
        done = false;
        for (size_t j = i + 1; !done && j < count; j++)
            done = !sendInstructionMessage(out, Is[j], Is[i].address);

        // Send the "patch" message.
        id++;
        Context cxt = {out, nullptr, &elf, Is.data(), (ssize_t)count, i, &I,
            id};
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
                sendMetadata(out, &elf, entry.action, entry.idx, &I, id,
                    &cxt);
            sendMetadataFooter(out);
            sendSeparator(out);
        }
        sendParamHeader(out, "offset");
        sendInteger(out, I.offset);
        sendSeparator(out, /*last=*/true);
        sendMessageFooter(out, /*sync=*/true);
    }
    notifyPlugins(out, &elf, Is.data(), Is.size(), EVENT_PATCHING_COMPLETE);
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

