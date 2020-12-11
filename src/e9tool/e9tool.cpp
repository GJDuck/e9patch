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
static bool option_detail   = false;
static bool option_debug    = false;
static bool option_notify   = false;
static std::string option_format("binary");
static std::string option_output("a.out");
static std::string option_syntax("ATT");

/*
 * Instruction location.
 */
struct Location
{
    uint64_t offset:48;
    uint64_t size:4;
    uint64_t emitted:1;
    uint64_t patch:1;
    uint64_t action:10;

    Location(off_t offset, size_t size, bool patch, unsigned action) :
        offset(offset), size(size), emitted(0), patch(patch), action(action)
    {
        ;
    }
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
    PluginInstr instrFunc;
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
    MATCH_JUMP,
    MATCH_MNEMONIC,
    MATCH_OFFSET,
    MATCH_RANDOM,
    MATCH_RETURN,
    MATCH_SIZE,

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
 * Operand types.
 */
enum OpType
{
    OP_TYPE_IMM = 1,
    OP_TYPE_REG,
    OP_TYPE_MEM
};

/*
 * Access types.
 */
typedef unsigned Access;
#define ACCESS_READ             0x01
#define ACCESS_WRITE            0x02

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
 * Action kinds.
 */
enum ActionKind
{
    ACTION_INVALID,
    ACTION_CALL,
    ACTION_EXIT,
    ACTION_PASSTHRU,
    ACTION_PLUGIN,
    ACTION_PRINT,
    ACTION_TRAP,
};

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
 * Actions.
 */
struct Action
{
    const std::string string;
    const MatchExpr *match;
    const ActionKind kind;
    const char * const name;
    const char * const filename;
    const char * const symbol;
    const ELF * elf;
    Plugin * const plugin;
    void *context;
    const std::vector<Argument> args;
    const bool clean;
    const CallKind call;
    int status;

    Action(const char *string, const MatchExpr *match, ActionKind kind,
            const char *name, const char *filename, const char *symbol,
            Plugin *plugin, const std::vector<Argument> &&args, bool clean,
            CallKind call, int status) :
            string(string), match(match), kind(kind), name(name),
            filename(filename), symbol(symbol), elf(nullptr),
            plugin(plugin), context(nullptr), args(args), clean(clean),
            call(call), status(status)
    {
        ;
    }
};
typedef std::map<size_t, Action *> Actions;

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
    plugin->instrFunc = (PluginInstr)dlsym(handle, "e9_plugin_instr_v1");
    plugin->matchFunc = (PluginMatch)dlsym(handle, "e9_plugin_match_v1");
    plugin->patchFunc = (PluginPatch)dlsym(handle, "e9_plugin_patch_v1");
    plugin->finiFunc  = (PluginFini)dlsym(handle, "e9_plugin_fini_v1");
    if (plugin->initFunc == nullptr &&
            plugin->instrFunc == nullptr &&
            plugin->patchFunc == nullptr &&
            plugin->finiFunc == nullptr)
        error("failed to load plugin \"%s\"; the shared "
            "object does not export any plugin API functions",
            plugin->filename);

    plugins.insert({plugin->filename, plugin});
    option_notify = option_notify || (plugin->instrFunc != nullptr);
    return plugin;
}

/*
 * Notify all plugins of a new instruction.
 */
static void notifyPlugins(FILE *out, const ELF *elf, csh handle, off_t offset,
    const cs_insn *I)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->instrFunc == nullptr)
            continue;
        plugin->instrFunc(out, elf, handle, offset, I, plugin->context);
    }
}

/*
 * Get the match value for all plugins.
 */
static void matchPlugins(FILE *out, const ELF *elf, csh handle, off_t offset,
    const cs_insn *I)
{
    for (auto i: plugins)
    {
        Plugin *plugin = i.second;
        if (plugin->matchFunc == nullptr)
            continue;
        plugin->result = plugin->matchFunc(out, elf, handle, offset, I,
            plugin->context);
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
        plugin->context = plugin->initFunc(out, elf);
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
        plugin->finiFunc(out, elf, plugin->context);
    }
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
 * Parse values.
 */
static void parseValues(Parser &parser, MatchType type,
    MatchCmp cmp, Index<MatchValue> &index)
{
    while (true)
    {
        MatchValue value = {0};
        switch (parser.getToken())
        {
            case TOKEN_NIL:
                value.type = MATCH_TYPE_NIL;
                break;
            case TOKEN_INTEGER:
                value.type = MATCH_TYPE_INTEGER;
                value.i    = parser.i;
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
        case TOKEN_SIZE: case TOKEN_LENGTH:
            match = MATCH_SIZE; break;
        case TOKEN_SRC:
            match = MATCH_SRC; break;
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
            parser.expectToken(TOKEN_STRING);
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
        case MATCH_ASSEMBLY: case MATCH_MNEMONIC:
            if (cmp != MATCH_CMP_EQ && cmp != MATCH_CMP_NEQ &&
                    cmp != MATCH_CMP_DEFINED)
                error("failed to parse matching; invalid match "
                    "comparison operator \"%s\" for attribute \"%s\"",
                    parser.s, parser.getName(attr));
            break;
        case MATCH_CALL: case MATCH_JUMP: case MATCH_RETURN: case MATCH_PLUGIN:
        case MATCH_OP: case MATCH_SRC: case MATCH_DST:
        case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
        case MATCH_READS: case MATCH_WRITES: case MATCH_REGS:
            option_detail = true;
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
        t = parser.getRegex();
        std::string str;
        switch (t)
        {
            case TOKEN_REGEX:
                str = parser.s;
                break;
            case TOKEN_STRING:
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
        if (parser.peekToken() == TOKEN_STRING)
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
static MatchExpr *parseMatch(const char *str)
{
    Parser parser(str, "matching");
    MatchExpr *expr = parseMatchExpr(parser, MATCH_OP_OR);
    parser.expectToken(TOKEN_END);
    return expr;
}

/*
 * Parse an action.
 */
static Action *parseAction(const char *str, const MatchExpr *expr)
{
    if (expr == nullptr)
        error("failed to parse action; the `--action' or `-A' option must be "
            "preceded by one or more `--match' or `-M' options");

    ActionKind kind = ACTION_INVALID;
    Parser parser(str, "action");
    switch (parser.getToken())
    {
        case TOKEN_CALL:
            kind = ACTION_CALL; break;
        case TOKEN_EXIT:
            kind = ACTION_EXIT; break;
        case TOKEN_PASSTHRU:
            kind = ACTION_PASSTHRU; break;
        case TOKEN_PRINT:
            kind = ACTION_PRINT; break;
        case TOKEN_PLUGIN:
            kind = ACTION_PLUGIN; break;
        case TOKEN_TRAP:
            kind = ACTION_TRAP; break;
        default:
            parser.unexpectedToken();
    }

    // Parse the rest of the action (if necessary):
    CallKind call = CALL_BEFORE;
    bool clean = false, naked = false, before = false, after = false,
         replace = false, conditional = false;
    const char *symbol   = nullptr;
    const char *filename = nullptr;
    Plugin *plugin = nullptr;
    std::vector<Argument> args;
    int status = 0;
    if (kind == ACTION_EXIT)
    {
        parser.expectToken('(');
        parser.expectToken(TOKEN_INTEGER);
        if (parser.i < 0 || parser.i > 255)
            error("failed to parse action; exit status must be an "
                "integer within the range 0..255");
        status = (int)parser.i;
        parser.expectToken(')');
    }
    else if (kind == ACTION_PLUGIN)
    {
        parser.expectToken('(');
        parser.expectToken(TOKEN_STRING);
        filename = strDup(parser.s);
        parser.expectToken(')');
        parser.expectToken('.');
        parser.expectToken(TOKEN_PATCH);
        parser.expectToken('(');
        parser.expectToken(')');
        plugin = openPlugin(filename);
        option_detail = true;
    }
    else if (kind == ACTION_CALL)
    {
        int t = parser.peekToken();
        if (t == '[')
        {
            parser.getToken();
            while (true)
            {
                t = parser.getToken();
                switch (t)
                {
                    case TOKEN_AFTER:
                        after = true; break;
                    case TOKEN_BEFORE:
                        before = true; break;
                    case TOKEN_CLEAN:
                        clean = true; break;
                    case TOKEN_CONDITIONAL:
                        conditional = true; break;
                    case TOKEN_NAKED:
                        naked = true; break;
                    case TOKEN_REPLACE:
                        replace = true; break;
                    default:
                        parser.unexpectedToken();
                }
                t = parser.getToken();
                if (t == ']')
                    break;
                if (t != ',')
                    parser.unexpectedToken();
            }
        }
        parser.expectToken(TOKEN_STRING);
        symbol = strDup(parser.s);
        t = parser.peekToken();
        if (t == '(')
        {
            parser.getToken();
            while (true)
            {
                t = parser.getToken();
                bool ptr = false;
                if (t == '&')
                {
                    ptr = true;
                    t = parser.getToken();
                }
                ArgumentKind arg = ARGUMENT_INVALID;
                FieldKind field  = FIELD_NONE;
                intptr_t value = 0x0;
                int arg_token = t;
                const char *basename = nullptr;
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
                    case TOKEN_IMM:
                        arg = ARGUMENT_IMM; break;
                    case TOKEN_INSTR:
                        arg = ARGUMENT_BYTES; break;
                    case TOKEN_MEM:
                        arg = ARGUMENT_MEM; break;
                    case TOKEN_NEXT:
                        option_detail = true;
                        arg = ARGUMENT_NEXT;
                        break;
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
                    case TOKEN_STATIC_ADDR:
                        arg = ARGUMENT_STATIC_ADDR; break;
                    case TOKEN_SRC:
                        arg = ARGUMENT_SRC; break;
                    case TOKEN_TARGET:
                        option_detail = true;
                        arg = ARGUMENT_TARGET;
                        break;
                    case TOKEN_TRAMPOLINE:
                        arg = ARGUMENT_TRAMPOLINE; break;

                    case TOKEN_REGISTER:
                        switch ((Register)parser.i)
                        {
                            case REGISTER_AL:
                                arg = ARGUMENT_AL; break;
                            case REGISTER_AH:
                                arg = ARGUMENT_AH; break;
                            case REGISTER_BL:
                                arg = ARGUMENT_BL; break;
                            case REGISTER_BH:
                                arg = ARGUMENT_BH; break;
                            case REGISTER_CL:
                                arg = ARGUMENT_CL; break;
                            case REGISTER_CH:
                                arg = ARGUMENT_CH; break;
                            case REGISTER_DL:
                                arg = ARGUMENT_DL; break;
                            case REGISTER_DH:
                                arg = ARGUMENT_DH; break;
                            case REGISTER_BPL:
                                arg = ARGUMENT_BPL; break;
                            case REGISTER_SPL:
                                arg = ARGUMENT_SPL; break; 
                            case REGISTER_DIL:
                                arg = ARGUMENT_DIL; break;
                            case REGISTER_SIL: 
                                arg = ARGUMENT_SIL; break; 
                            case REGISTER_R8B:
                                arg = ARGUMENT_R8B; break;
                            case REGISTER_R9B:
                                arg = ARGUMENT_R9B; break;
                            case REGISTER_R10B:
                                arg = ARGUMENT_R10B; break;
                            case REGISTER_R11B:
                                arg = ARGUMENT_R11B; break;
                            case REGISTER_R12B:
                                arg = ARGUMENT_R12B; break;
                            case REGISTER_R13B:
                                arg = ARGUMENT_R13B; break;
                            case REGISTER_R14B:
                                arg = ARGUMENT_R14B; break;
                            case REGISTER_R15B:
                                arg = ARGUMENT_R15B; break;
                            
                            case REGISTER_AX:
                                arg = ARGUMENT_AX; break;
                            case REGISTER_BX:
                                arg = ARGUMENT_BX; break;
                            case REGISTER_CX:
                                arg = ARGUMENT_CX; break;
                            case REGISTER_DX:
                                arg = ARGUMENT_DX; break;
                            case REGISTER_BP:
                                arg = ARGUMENT_BP; break;
                            case REGISTER_SP:
                                arg = ARGUMENT_SP; break; 
                            case REGISTER_DI:
                                arg = ARGUMENT_DI; break;
                            case REGISTER_SI: 
                                arg = ARGUMENT_SI; break; 
                            case REGISTER_R8W:
                                arg = ARGUMENT_R8W; break;
                            case REGISTER_R9W:
                                arg = ARGUMENT_R9W; break;
                            case REGISTER_R10W:
                                arg = ARGUMENT_R10W; break;
                            case REGISTER_R11W:
                                arg = ARGUMENT_R11W; break;
                            case REGISTER_R12W:
                                arg = ARGUMENT_R12W; break;
                            case REGISTER_R13W:
                                arg = ARGUMENT_R13W; break;
                            case REGISTER_R14W:
                                arg = ARGUMENT_R14W; break;
                            case REGISTER_R15W:
                                arg = ARGUMENT_R15W; break;
                            
                            case REGISTER_EAX:
                                arg = ARGUMENT_EAX; break;
                            case REGISTER_EBX:
                                arg = ARGUMENT_EBX; break;
                            case REGISTER_ECX:
                                arg = ARGUMENT_ECX; break;
                            case REGISTER_EDX:
                                arg = ARGUMENT_EDX; break;
                            case REGISTER_EBP:
                                arg = ARGUMENT_EBP; break;
                            case REGISTER_ESP:
                                arg = ARGUMENT_ESP; break; 
                            case REGISTER_EDI:
                                arg = ARGUMENT_EDI; break;
                            case REGISTER_ESI: 
                                arg = ARGUMENT_ESI; break; 
                            case REGISTER_R8D:
                                arg = ARGUMENT_R8D; break;
                            case REGISTER_R9D:
                                arg = ARGUMENT_R9D; break;
                            case REGISTER_R10D:
                                arg = ARGUMENT_R10D; break;
                            case REGISTER_R11D:
                                arg = ARGUMENT_R11D; break;
                            case REGISTER_R12D:
                                arg = ARGUMENT_R12D; break;
                            case REGISTER_R13D:
                                arg = ARGUMENT_R13D; break;
                            case REGISTER_R14D:
                                arg = ARGUMENT_R14D; break;
                            case REGISTER_R15D:
                                arg = ARGUMENT_R15D; break;
                            
                            case REGISTER_RAX:
                                arg = ARGUMENT_RAX; break;
                            case REGISTER_RBX:
                                arg = ARGUMENT_RBX; break;
                            case REGISTER_RCX:
                                arg = ARGUMENT_RCX; break;
                            case REGISTER_RDX:
                                arg = ARGUMENT_RDX; break;
                            case REGISTER_RBP:
                                arg = ARGUMENT_RBP; break;
                            case REGISTER_RSP:
                                arg = ARGUMENT_RSP; break;
                            case REGISTER_RSI:
                                arg = ARGUMENT_RSI; break;
                            case REGISTER_RDI:
                                arg = ARGUMENT_RDI; break;
                            case REGISTER_R8:
                                arg = ARGUMENT_R8; break;
                            case REGISTER_R9:
                                arg = ARGUMENT_R9; break;
                            case REGISTER_R10:
                                arg = ARGUMENT_R10; break;
                            case REGISTER_R11:
                                arg = ARGUMENT_R11; break;
                            case REGISTER_R12:
                                arg = ARGUMENT_R12; break;
                            case REGISTER_R13:
                                arg = ARGUMENT_R13; break;
                            case REGISTER_R14:
                                arg = ARGUMENT_R14; break;
                            case REGISTER_R15:
                                arg = ARGUMENT_R15; break;

                            case REGISTER_EFLAGS:
                                arg = ARGUMENT_RFLAGS; break;
                            case REGISTER_RIP:
                                arg = ARGUMENT_RIP; break;
 
                            default:
                                parser.unexpectedToken();
                        }
                        break;
                    
                    case TOKEN_INTEGER:
                        value = parser.i;
                        arg = ARGUMENT_INTEGER;
                        break;
                    case TOKEN_STRING:
                        basename = strDup(parser.s);
                        arg = ARGUMENT_USER;
                        break;
                    default:
                        parser.unexpectedToken();
                }
                switch (arg)
                {
                    case ARGUMENT_OP: case ARGUMENT_SRC: case ARGUMENT_DST:
                    case ARGUMENT_IMM: case ARGUMENT_REG: case ARGUMENT_MEM:
                        option_detail = true;
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
                                default:
                                    parser.unexpectedToken();
                            }
                            if (ptr &&
                                (field != FIELD_BASE && field != FIELD_INDEX))
                            {
                                error("failed to parse call action; cannot "
                                    "pass field `%s' by pointer",
                                    parser.getName(t));
                            }
                        }
                        break;

                    case ARGUMENT_AL: case ARGUMENT_AH: case ARGUMENT_BL:
                    case ARGUMENT_BH: case ARGUMENT_CL: case ARGUMENT_CH:
                    case ARGUMENT_DL: case ARGUMENT_DH: case ARGUMENT_BPL:
                    case ARGUMENT_DIL: case ARGUMENT_SIL: case ARGUMENT_R8B:
                    case ARGUMENT_R9B: case ARGUMENT_R10B: case ARGUMENT_R11B:
                    case ARGUMENT_R12B: case ARGUMENT_R13B: case ARGUMENT_R14B:
                    case ARGUMENT_R15B:

                    case ARGUMENT_AX: case ARGUMENT_BX: case ARGUMENT_CX:
                    case ARGUMENT_DX: case ARGUMENT_BP: case ARGUMENT_DI:
                    case ARGUMENT_SI: case ARGUMENT_R8W: case ARGUMENT_R9W:
                    case ARGUMENT_R10W: case ARGUMENT_R11W: case ARGUMENT_R12W:
                    case ARGUMENT_R13W: case ARGUMENT_R14W: case ARGUMENT_R15W:

                    case ARGUMENT_EAX: case ARGUMENT_EBX: case ARGUMENT_ECX:
                    case ARGUMENT_EDX: case ARGUMENT_EBP: case ARGUMENT_EDI:
                    case ARGUMENT_ESI: case ARGUMENT_R8D: case ARGUMENT_R9D:
                    case ARGUMENT_R10D: case ARGUMENT_R11D: case ARGUMENT_R12D:
                    case ARGUMENT_R13D: case ARGUMENT_R14D: case ARGUMENT_R15D:

                    case ARGUMENT_RAX: case ARGUMENT_RBX: case ARGUMENT_RCX:
                    case ARGUMENT_RDX: case ARGUMENT_RBP: case ARGUMENT_RSP:
                    case ARGUMENT_RSI: case ARGUMENT_RDI: case ARGUMENT_R8:
                    case ARGUMENT_R9: case ARGUMENT_R10: case ARGUMENT_R11:
                    case ARGUMENT_R12: case ARGUMENT_R13: case ARGUMENT_R14:
                    case ARGUMENT_R15: case ARGUMENT_RFLAGS:
                        break;

                    case ARGUMENT_USER:
                        value = parseIndex(parser, INTPTR_MIN, INTPTR_MAX);
                        // Fallthrough:

                    default:
                        if (ptr)
                            error("failed to parse call action; cannot "
                                "pass argument `%s' by pointer",
                                parser.getName(arg_token));
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
                args.push_back({arg, field, ptr, duplicate, value, basename});
                t = parser.getToken();
                if (t == ')')
                    break;
                if (t != ',')
                    parser.unexpectedToken();
            }
        }
        parser.expectToken('@');
        parser.getToken();          // Accept any token as filename.
        filename = strDup(parser.s);
        if (clean && naked)
            error("failed to parse call action; `clean' and `naked' "
                "attributes cannot be used together");
        if ((int)before + (int)after + (int)replace + (int)conditional> 1)
            error("failed to parse call action; only one of the `before', "
                "`after', `replace' and `conditional' attributes can be used "
                "together");
        clean = (clean? true: !naked);
        call = (after? CALL_AFTER:
               (replace? CALL_REPLACE:
               (conditional? CALL_CONDITIONAL: CALL_BEFORE)));
    }
    parser.expectToken(TOKEN_END);

    // Build the action:
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
            call_name += (clean? "clean_": "naked_");
            switch (call)
            {
                case CALL_BEFORE:
                    call_name += "before_"; break;
                case CALL_AFTER:
                    call_name += "after_"; break;
                case CALL_REPLACE:
                    call_name += "replace_"; break;
                case CALL_CONDITIONAL:
                    call_name += "conditional_"; break;
            }
            call_name += symbol;
            call_name += '_';
            call_name += filename;
            name = strDup(call_name.c_str());
            break;
        }
        case ACTION_EXIT:
        {
            std::string exit_name("exit_");
            exit_name += std::to_string(status);
            name = strDup(exit_name.c_str());
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

    Action *action = new Action(str, expr, kind, name, filename, symbol,
        plugin, std::move(args), clean, call, status);
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
        case MATCH_MNEMONIC:
            return I->mnemonic;
        default:
            return "";
    }
}

/*
 * Get an operand.
 */
static const cs_x86_op *getOperand(const cs_insn *I, int idx, x86_op_type type,
    uint8_t access)
{
    const cs_x86 *x86 = &I->detail->x86;
    for (uint8_t i = 0; i < x86->op_count; i++)
    {
        const cs_x86_op *op = x86->operands + i;
        if ((type == X86_OP_INVALID? true: op->type == type) &&
            ((op->access & access) != 0 ||
             (op->type == X86_OP_IMM && (access & CS_AC_READ) != 0)))
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
static intptr_t getNumOperands(const cs_insn *I, x86_op_type type,
    uint8_t access)
{
    const cs_x86 *x86 = &I->detail->x86;
    intptr_t n = 0;
    for (uint8_t i = 0; i < x86->op_count; i++)
    {
        const cs_x86_op *op = x86->operands + i;
        if ((type == X86_OP_INVALID? true: op->type == type) &&
            ((op->access & access) != 0 ||
             (op->type == X86_OP_IMM && (access & CS_AC_READ) != 0)))
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
    const cs_insn *I, intptr_t offset, intptr_t plugin_val)
{
    MatchValue result = {0};
    result.type = MATCH_TYPE_INTEGER;
    const cs_detail *detail = I->detail;
    const cs_x86_op *op = nullptr;
    x86_op_type type = X86_OP_INVALID;
    uint8_t access = CS_AC_READ | CS_AC_WRITE;
    bool found = false;
    switch (match)
    {
        case MATCH_SRC:
            access = CS_AC_READ; break;
        case MATCH_DST:
            access = CS_AC_WRITE; break;
        case MATCH_IMM:
            type = X86_OP_IMM; break;
        case MATCH_REG:
            type = X86_OP_REG; break;
        case MATCH_MEM:
            type = X86_OP_MEM; break;
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
            for (uint8_t i = 0; !found && i < detail->groups_count; i++)
                if (detail->groups[i] == CS_GRP_CALL)
                    found = true;
            result.i = found;
            return result;
        case MATCH_JUMP:
            for (uint8_t i = 0; !found && i < detail->groups_count; i++)
                if (detail->groups[i] == CS_GRP_JUMP)
                    found = true;
            result.i = found;
            return result;
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
                            case X86_OP_IMM:
                                result.i = (intptr_t)op->imm;
                                return result;
                            case X86_OP_REG:
                                result.type = MATCH_TYPE_REGISTER;
                                result.reg  = getRegister(op->reg);
                                return result;
                            case X86_OP_MEM:
                                result.type = MATCH_TYPE_MEMORY;
                                return result;
                            default:
                                goto undefined;
                        }
                    case MATCH_FIELD_SIZE:
                        result.i = (intptr_t)op->size; return result;
                    case MATCH_FIELD_TYPE:
                        result.type = MATCH_TYPE_OPERAND;
                        switch (op->type)
                        {
                            case X86_OP_IMM:
                                result.op = OP_TYPE_IMM; return result;
                            case X86_OP_REG:
                                result.op = OP_TYPE_REG; return result;
                            case X86_OP_MEM:
                                result.op = OP_TYPE_MEM; return result;
                            default:
                                goto undefined;
                        }
                    case MATCH_FIELD_ACCESS:
                    {
                        result.type = MATCH_TYPE_ACCESS;
                        if (op->type == X86_OP_IMM)
                        {
                            result.access = ACCESS_READ;
                            return result;
                        }
                        Access access = 0;
                        if ((op->access & CS_AC_READ) != 0)
                            access |= ACCESS_READ;
                        if ((op->access & CS_AC_WRITE) != 0)
                            access |= ACCESS_WRITE;
                        if (op->type == X86_OP_MEM &&
                                (I->id == X86_INS_LEA || I->id == X86_INS_NOP))
                            access = 0;     // Capstone bug workaround
                        result.access = access;
                        return result;
                    }
                    case MATCH_FIELD_SEG:
                        if (op->type != X86_OP_MEM)
                            goto undefined;
                        if (op->mem.segment == X86_REG_INVALID)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = getRegister(op->mem.segment);
                        return result;
                    case MATCH_FIELD_DISPL:
                        if (op->type != X86_OP_MEM)
                            goto undefined;
                        result.i = (intptr_t)op->mem.disp;
                        return result;
                    case MATCH_FIELD_BASE:
                        if (op->type != X86_OP_MEM)
                            goto undefined;
                        if (op->mem.base == X86_REG_INVALID)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = getRegister(op->mem.base);
                        return result;
                    case MATCH_FIELD_INDEX:
                        if (op->type != X86_OP_MEM)
                            goto undefined;
                        if (op->mem.index == X86_REG_INVALID)
                        {
                            result.type = MATCH_TYPE_NIL;
                            return result;
                        }
                        result.type = MATCH_TYPE_REGISTER;
                        result.reg  = getRegister(op->mem.index);
                        return result;
                    case MATCH_FIELD_SCALE:
                        if (op->type != X86_OP_MEM)
                            goto undefined;
                        result.i = (intptr_t)op->mem.scale;
                        return result;
                    default:
                        goto undefined;
                }
            }
            goto undefined;
        case MATCH_OFFSET:
            result.i = offset; return result;
        case MATCH_PLUGIN:
            result.i = plugin_val; return result;
        case MATCH_RANDOM:
            result.i = (intptr_t)rand(); return result;
        case MATCH_RETURN:
            for (uint8_t i = 0; !found && i < detail->groups_count; i++)
                if (detail->groups[i] == CS_GRP_RET)
                    found = true;
            result.i = found;
            return result;
        case MATCH_SIZE:
            result.i = (intptr_t)I->size; return result;
        default:
        undefined:
            result.type = MATCH_TYPE_UNDEFINED;
            return result;
    }
}

/*
 * Evaluate a matching.
 */
static bool matchEval(csh handle, const MatchExpr *expr, const cs_insn *I,
    intptr_t offset, const char *basename, const Record **record)
{
    if (expr == nullptr)
        return true;
    bool pass = false;
    const MatchTest *test = nullptr;
    switch (expr->op)
    {
        case MATCH_OP_NOT:
            pass = matchEval(handle, expr->arg1, I, offset, nullptr, nullptr);
            return !pass;
        case MATCH_OP_AND:
            pass = matchEval(handle, expr->arg1, I, offset, basename, record);
            if (!pass)
                return false;
            return matchEval(handle, expr->arg2, I, offset, basename, record);
        case MATCH_OP_OR:
            pass = matchEval(handle, expr->arg1, I, offset, basename, record);
            if (pass)
                return true;
            return matchEval(handle, expr->arg2, I, offset, basename, record);
        case MATCH_OP_TEST:
            test = expr->test;
            break;
        default:
            return false;
    }

    switch (test->match)
    {
        case MATCH_ASSEMBLY: case MATCH_MNEMONIC:
        {
            if (test->cmp == MATCH_CMP_DEFINED)
            {
                pass = true;
                break;
            }
            char buf[BUFSIZ];
            const char *str = makeMatchString(test->match, I, buf,
                sizeof(buf)-1);
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
            cs_regs reads, writes;
            uint8_t reads_len, writes_len;
            cs_err err = cs_regs_access(handle, I, reads, &reads_len,
                writes, &writes_len);
            if (err != 0)
                error("failed to get registers for instruction");
            for (uint8_t i = 0; !pass && test->match != MATCH_WRITES &&
                    i < reads_len; i++)
            {
                auto j = test->regs->find(getRegister((x86_reg)reads[i]));
                pass = (j != test->regs->end());
            }
            for (uint8_t i = 0; !pass && test->match != MATCH_READS &&
                    i < writes_len; i++)
            {
                auto j = test->regs->find(getRegister((x86_reg)writes[i]));
                pass = (j != test->regs->end());
            }
            break;
        }
        case MATCH_TRUE: case MATCH_FALSE: case MATCH_ADDRESS:
        case MATCH_CALL: case MATCH_JUMP: case MATCH_OFFSET:
        case MATCH_OP: case MATCH_SRC: case MATCH_DST:
        case MATCH_IMM: case MATCH_REG: case MATCH_MEM:
        case MATCH_PLUGIN: case MATCH_RANDOM: case MATCH_RETURN:
        case MATCH_SIZE:
        {
            if (test->cmp != MATCH_CMP_EQ_ZERO &&
                test->cmp != MATCH_CMP_NEQ_ZERO &&
                test->cmp != MATCH_CMP_DEFINED && test->values->size() == 0)
                break;
            MatchValue x = makeMatchValue(test->match, test->idx,
                test->field, I, offset,
                (test->match == MATCH_PLUGIN?  test->plugin->result: 0));
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
static bool matchAction(csh handle, const Action *action, const cs_insn *I,
    intptr_t offset)
{
#if 0
    // TODO: fix option_debug
    if (option_debug)
    {
        fprintf(stderr, "%s0x%lx%s [%s%s%s]:",
            (option_is_tty? "\33[36m": ""),
            I->address,
            (option_is_tty? "\33[0m": ""),
            I->mnemonic,
            (I->op_str[0] == '\0'? "": " "),
            I->op_str);
    }
#endif
    bool pass = matchEval(handle, action->match, I, offset);
#if 0
        if (option_debug)
        {
            fprintf(stderr, " [%s%s%s]",
                (option_is_tty? (pass? "\33[32m": "\33[31m"): ""),
                entry.string.c_str(),
                (option_is_tty? "\33[0m": ""));
        }
        if (!pass)
            break;
    }
    if (option_debug)
    {
        if (!pass)
        {
            fputc('\n', stderr);
            return false;
        }
        fprintf(stderr, " action %s%s%s\n",
            (option_is_tty? "\33[33m": ""),
            action->string.c_str(),
            (option_is_tty? "\33[0m": ""));
    }
#endif
    return pass;
}

/*
 * Matching.
 */
static int match(csh handle, const std::vector<Action *> &actions,
    const cs_insn *I, off_t offset)
{
    int idx = 0;
    for (const auto action: actions)
    {
        if (matchAction(handle, action, I, offset))
            return idx;
        idx++;
    }
    return -1;
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
    fputs("\t\t\tMATCH     ::=   TEST\n", stream);
    fputs("\t\t\t              | '(' MATCH ')'\n", stream);
    fputs("\t\t\t              | 'not' MATCH\n", stream);
    fputs("\t\t\t              | MATCH 'and' MATCH\n", stream);
    fputs("\t\t\t              | MATCH 'or' MATCH\n", stream);
    fputs("\t\t\tTEST      ::=   'defined' '(' ATTRIBUTE ')'\n", stream);
    fputs("\t\t\t              | VALUES 'in' ATTRIBUTE\n", stream);
    fputs("\t\t\t              | ATTRIBUTE [ CMP VALUES ]\n", stream);
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
    fputs("\t\tless-than, etc.) and VALUES is either a regular expression\n",
        stream);
    fputs("\t\t(for string attributes), comma separated list of integers "
        "(for\n", stream);
    fputs("\t\tinteger attributes), or values read from a Comma Separated\n",
        stream);
    fputs("\t\tValue (CSV) file (for integer attributes):\n", stream);
    fputc('\n', stream);
    fputs("\t\t\tVALUES ::=   REGULAR-EXPRESSION\n", stream);
    fputs("\t\t\t           | VALUE [ ',' VALUE ] *\n", stream);
    fputs("\t\t\t           | BASENAME '[' INTEGER ']'\n", stream);
    fputc('\n', stream);
    fputs("\t\tHere, BASENAME is the basename of a CSV file, and the "
        "integer\n", stream);
    fputs("\t\tis the column index.\n", stream);
    fputc('\n', stream);
    fputs("\t\tIf the CMP and VALUES are omitted, it is treated the same as\n",
        stream);
    fputs("\t\tATTRIBUTE != 0.\n", stream);
    fputc('\n', stream);
    fputs("\t\tPossible ATTRIBUTEs and attribute TYPEs are:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"true\" is the integer 1.\n", stream);
    fputs("\t\t\t- \"false\" is the integer 0.\n", stream);
    fputs("\t\t\t- \"asm\" is the instruction assembly string, e.g.:\n",
        stream);
    fputs("\t\t\t    \"cmpb %r11b, 0x436fe0(%rdi)\".  [TYPE=string]\n", stream);
    fputs("\t\t\t- \"addr\" is the instruction address, e.g.: 0x4234a7.\n",
        stream);
    fputs("\t\t\t    [TYPE=integer]\n", stream);
    fputs("\t\t\t- \"call\" is 1 for call instructions, else 0.\n", stream);
    fputs("\t\t\t- \"jump\" is 1 for jump instructions, else 0.\n", stream);
    fputs("\t\t\t- \"mnemonic\" is the instruction mnemomic, e.g.:\n",
        stream);
    fputs("\t\t\t    \"cmpb\".  [TYPE=string]\n", stream);
    fputs("\t\t\t- \"offset\" is the instruction file offset, e.g.:\n",
        stream);
    fputs("\t\t\t    +49521.  [TYPE=integer]\n", stream);
    fprintf(stream, "\t\t\t- \"random\" is a random integer [0..%lu].\n",
        (uintptr_t)RAND_MAX);
    fputs("\t\t\t- \"return\" is 1 for return instructions, else 0.\n",
        stream);
    fputs("\t\t\t- \"size\" is the instruction size in bytes.\n", stream);
    fputs("\t\t\t    [TYPE=integer]\n", stream);
    fputs("\t\t\t- \"op.size\", \"src.size\", \"dst.size\",\n", stream);
    fputs("\t\t\t  \"imm.size\", \"reg.size\", \"mem.size\"\n", stream);
    fputs("\t\t\t    are the number of operands, source operands,\n",
        stream);
    fputs("\t\t\t    destination operands, immediate operands,\n",
        stream);
    fputs("\t\t\t    register operands, and memory operands\n", stream);
    fputs("\t\t\t    respectively.  [TYPE=integer]\n", stream);
    fputs("\t\t\t- \"op[i]\", \"src[i]\", \"dst[i]\",\n", stream);
    fputs("\t\t\t  \"imm[i]\", \"reg[i]\", \"mem[i]\"\n", stream);
    fputs("\t\t\t    is the ith operand, source operand,\n",
        stream);
    fputs("\t\t\t    destination operand, immediate operand,\n",
        stream);
    fputs("\t\t\t    register operand, and memory operand\n", stream);
    fputs("\t\t\t    respectively.  The TYPE is an integer for\n", stream);
    fputs("\t\t\t    immediate operands, and a register name for\n",
        stream);
    fputs("\t\t\t    register operands.\n", stream);
    fputs("\t\t\t- \"op[i].FIELD\", \"src[i].FIELD\", \"dst[i].FIELD\",\n",
        stream);
    fputs("\t\t\t  \"imm[i].FIELD\", \"reg[i].FIELD\", \"mem[i].FIELD\"\n",
        stream);
    fputs("\t\t\t    where FIELD is:\n", stream);
    fputs("\t\t\t      - \"access\" is the operand access mode.\n",
        stream);
    fputs("\t\t\t          [TYPE={-,r,w,rw}]\n", stream);
    fputs("\t\t\t      - \"base\" is the memory operand base register.\n",
        stream);
    fputs("\t\t\t          [TYPE=register]\n", stream);
    fputs("\t\t\t      - \"disp\" is the memory operand displacement.\n",
        stream);
    fputs("\t\t\t          [TYPE=integer]\n", stream);
    fputs("\t\t\t      - \"index\" is the memory operand index register.\n",
        stream);
    fputs("\t\t\t          [TYPE=register]\n", stream);
    fputs("\t\t\t      - \"scale\" is the memory operand scale.\n",
        stream);
    fputs("\t\t\t          [TYPE=integer]\n", stream);
    fputs("\t\t\t      - \"seg\" is the memory operand segment register.\n",
        stream);
    fputs("\t\t\t          [TYPE=register]\n", stream);
    fputs("\t\t\t      - \"size\" is the operand size.  [TYPE=integer]\n",
        stream);
    fputs("\t\t\t      - \"type\" is the operand type.\n", stream);
    fputs("\t\t\t          [TYPE={imm,reg,mem}]\n", stream);
    fputs("\t\t\t- \"regs\", \"reads\", \"writes\" is respectively the "
        "set of\n", stream);
    fputs("\t\t\t    all registers, set of all read-from registers, and\n",
        stream);
    fputs("\t\t\t    the set of all written-to registers, used by the\n",
        stream);
    fputs("\t\t\t    instruction.  [TYPE=set of register]\n", stream);
    fputs("\t\t\t- \"plugin(NAME).match()\" is the value returned by\n",
        stream);
    fputs("\t\t\t    NAME.so's e9_plugin_match_v1() function.\n", stream);
    fputs("\t\t\t    [TYPE=integer]\n", stream);
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
    fputs("\t\t\t           | 'exit' '(' CODE ')'\n", stream);
    fputs("\t\t\t           | CALL \n", stream);
    fputs("\t\t\t           | 'plugin' '[' NAME ']'\n", stream);
    fputc('\n', stream);
    fputs("\t\tWhere:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- \"passthru\"   : empty (NOP) instrumentation;\n", stream);
    fputs("\t\t\t- \"print\"      : instruction printing instrumentation.\n",
        stream);
    fputs("\t\t\t- \"trap\"       : SIGTRAP instrumentation.\n", stream);
    fputs("\t\t\t- \"exit(CODE)\" : exit with CODE instrumentation.\n",
        stream);
    fputs("\t\t\t- CALL         : call user instrumentation (see below).\n",
        stream);
    fputs("\t\t\t- \"plugin(NAME).patch()\"\n", stream);
    fputs("\t\t\t               : plugin instrumentation (see below).\n",
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
    fputs("\t\t\tARGS    ::= '(' ARG ',' ... ')'\n", stream);
    fputs("\t\t\tARG     ::=   INTEGER\n", stream);
    fputs("\t\t\t            | NAME\n", stream);
    fputs("\t\t\t            | BASENAME '[' INTEGER ']'\n", stream);
    fputc('\n', stream);
    fputs("\t\tWhere:\n", stream);
    fputc('\n', stream);
    fputs("\t\t\t- OPTION is one of:\n", stream);
    fputs("\t\t\t  * \"clean\"/\"naked\" for clean/naked calls.\n", stream);
    fputs("\t\t\t  * \"before\"/\"after\"/\"replace\"/\"conditional\" for\n",
        stream);
    fputs("\t\t\t    inserting the call before/after the instruction, or\n",
        stream);
    fputs("\t\t\t    (conditionally) replacing the instruction by the\n",
        stream);
    fputs("\t\t\t    call.\n", stream);
    fputs("\t\t\t- ARG is one of:\n", stream);
    fputs("\t\t\t  * \"asm\" is a pointer to a string representation\n",
        stream);
    fputs("\t\t\t    of the instruction.\n", stream);
    fputs("\t\t\t  * \"asm.size\" is the number of bytes in \"asm\".\n",
        stream);
    fputs("\t\t\t  * \"asm.len\" is the string length of \"asm\".\n",
        stream);
    fputs("\t\t\t  * \"base\" is the PIC base address.\n", stream);
    fputs("\t\t\t  * \"addr\" is the address of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"instr\" is the bytes of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"next\" is the address of the next instruction.\n",
        stream);
    fputs("\t\t\t  * \"offset\" is the file offset of the instruction.\n",
        stream);
    fputs("\t\t\t  * \"target\" is the jump/call/return target, else -1.\n",
        stream);
    fputs("\t\t\t  * \"trampoline\" is the address of the trampoline.\n",
        stream);
    fprintf(stream, "\t\t\t  * \"random\" is a random value [0..%lu].\n",
        (uintptr_t)RAND_MAX);
    fputs("\t\t\t  * \"size\" is the number of bytes in \"instr\".\n",
        stream);
    fputs("\t\t\t  * \"staticAddr\" is the (static) address of the\n",
        stream);
    fputs("\t\t\t    instruction.\n", stream);
    fputs("\t\t\t  * \"ah\"...\"dh\", \"al\"...\"r15b\",\n", stream);
    fputs("\t\t\t    \"ax\"...\"r15w\", \"eax\"...\"r15d\",\n", stream);
    fputs("\t\t\t    \"rax\"...\"r15\", \"rip\", \"rflags\" is the\n",
        stream);
    fputs("\t\t\t    corresponding register value.\n", stream);
    fputs("\t\t\t  * \"&ah\"...\"&dh\", \"&al\"...\"&r15b\",\n", stream);
    fputs("\t\t\t    \"&ax\"...\"&r15w\", \"&eax\"...\"&r15d\",\n", stream);
    fputs("\t\t\t    \"&rax\"...\"&r15\", \"&rflags\" is the corresponding\n",
        stream);
    fputs("\t\t\t    register value but passed-by-pointer.\n", stream);
    fputs("\t\t\t  * \"op[i]\", \"src[i]\", \"dst[i]\", \"imm[i]\", "
        "\"reg[i]\",\n", stream);
    fputs("\t\t\t    \"mem[i]\" is the ith operand, source operand,\n",
        stream);
    fputs("\t\t\t    destination operand, immediate operand, register\n",
        stream);
    fputs("\t\t\t    operand, memory operand respectively.\n", stream);
    fputs("\t\t\t  * \"&op[i]\", \"&src[i]\", \"&dst[i]\", \"&imm[i]\",\n",
        stream);
    fputs("\t\t\t    \"&reg[i]\", \"&mem[i]\" is the same as above\n",
        stream);
    fputs("\t\t\t    but passed-by-pointer.\n", stream);
    fputs("\t\t\t  * An integer constant.\n", stream);
    fputs("\t\t\t  * A file lookup of the form \"basename[index]\" where\n",
        stream);
    fputs("\t\t\t    \"basename\" is the basename of a CSV file used in\n",
        stream);
    fputs("\t\t\t    the matching, and \"index\" is a column index.\n",
        stream);
    fputs("\t\t\t    Note that the matching must select a unique row.\n",
        stream);
    fprintf(stream, "\t\t\t  NOTE: a maximum of %d arguments are supported.\n",
        MAX_ARGNO);
    fputs("\t\t\t- FUNCTION is the name of the function to call from\n",
        stream);
    fputs("\t\t\t  the binary.\n", stream);
    fputs("\t\t\t- BINARY is a suitable ELF binary file.  You can use\n",
        stream);
    fputs("\t\t\t  the `e9compile.sh' script to compile C programs into\n",
        stream);
    fputs("\t\t\t  the correct binary format.\n", stream);
    fputc('\n', stream);
    fputs("\t\tPLUGIN instrumentation lets a shared object plugin "
        "drive the\n", stream);
    fputs("\t\tbinary instrumentation/rewriting.  See the plugin API\n",
        stream);
    fputs("\t\tdocumentation for more information.\n", stream);
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
    fputs("\t--no-warnings\n", stream);
    fputs("\t\tDo not print warning messages.\n", stream);
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
    OPTION_NO_WARNINGS,
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
        {"no-warnings",    false, nullptr, OPTION_NO_WARNINGS},
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
    MatchExpr *option_match = nullptr;
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
                option_match = nullptr;
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
            {
                MatchExpr *expr = parseMatch(optarg);
                option_match = (option_match == nullptr? expr:
                    new MatchExpr(MATCH_OP_AND, option_match, expr));
                break;
            }
            case OPTION_OUTPUT:
            case 'o':
                option_output = optarg;
                break;
            case OPTION_NO_WARNINGS:
                option_no_warnings = true;
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
    if (option_match != nullptr)
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
    bool exe = (option_executable? true:
               (option_shared? false: !isLibraryFilename(filename)));
    filename = findBinary(filename, exe, /*dot=*/true);
    ELF &elf = *parseELF(filename, 0x0);

    /*
     * The ELF file seems OK, spawn and initialize the e9patch backend.
     */
    Backend backend;
    if (option_static_loader)
        option_options.push_back(strDup("--static-loader"));
    if (option_trap_all)
        option_options.push_back(strDup("--trap-all"));
    option_options.push_back(strDup("--experimental"));
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
     * Initialize all plugins:
     */
    initPlugins(backend.out, &elf);

    /*
     * Send trampoline definitions:
     */
    bool have_print = false, have_passthru = false, have_trap = false;
    std::map<const char *, ELF *, CStrCmp> files;
    std::set<const char *, CStrCmp> have_call;
    std::set<int> have_exit;
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
            case ACTION_EXIT:
            {
                auto i = have_exit.find(action->status);
                if (i == have_exit.end())
                {
                    sendExitTrampolineMessage(backend.out, action->status);
                    have_exit.insert(action->status);
                }
                break;
            }
            case ACTION_CALL:
            {
                // Step (1): Ensure the ELF file is loaded:
                ELF *target = nullptr;
                auto i = files.find(action->filename);
                if (i == files.end())
                {
                    // Load the called ELF file into the address space:
                    intptr_t free_addr = file_addr + 8 * PAGE_SIZE;
                    free_addr = (free_addr % PAGE_SIZE == 0? free_addr:
                        (free_addr + PAGE_SIZE) - (free_addr % PAGE_SIZE));
                    target = parseELF(action->filename, free_addr);
                    sendELFFileMessage(backend.out, target);
                    files.insert({action->filename, target});
                    size_t size = (size_t)target->free_addr;
                    free_addr += size;
                    file_addr = free_addr;
                }
                else
                    target = i->second;
                action->elf = target;

                // Step (2): Create the trampoline:
                auto j = have_call.find(action->name);
                if (j == have_call.end())
                {
                    sendCallTrampolineMessage(backend.out, action->name,
                        action->args, action->clean, action->call);
                    have_call.insert(action->name);
                }
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
            warning("failed to disassemble (%s%s%s) at address 0x%lx",
                I->mnemonic, (I->op_str[0] == '\0'? "": " "), I->op_str,
                I->address);
            failed = true;
            sync = option_sync;
            continue;
        }

        int idx = -1;
        off_t offset = ((intptr_t)I->address - elf.text_addr);

        if (option_notify)
            notifyPlugins(backend.out, &elf, handle, offset, I);
        else
        {
            matchPlugins(backend.out, &elf, handle, offset, I);
            idx = match(handle, option_actions, I, offset);
        }

        Location loc(offset, I->size, (idx >= 0), idx);
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
    locs.shrink_to_fit();
    if (option_notify)
    {
        // The first disassembly pass was used for notifications.
        // We employ a second disassembly pass for matching.
 
        size_t count = locs.size();
        for (size_t i = 0; i < count; i++)
        {
            Location &loc = locs[i];
            off_t text_offset = (off_t)loc.offset;
            uint64_t address = (uint64_t)elf.text_addr + text_offset;
            off_t offset = elf.text_offset + text_offset;
            const uint8_t *code = elf.data + offset;
            size_t size = loc.size;
            bool ok = cs_disasm_iter(handle, &code, &size, &address, I);
            if (!ok)
                error("failed to disassemble instruction at address 0x%lx",
                    address);
            matchPlugins(backend.out, &elf, handle, offset, I);
            int idx = match(handle, option_actions, I, offset);
            if (idx >= 0)
            {
                Location new_loc(text_offset, I->size, true, idx);
                locs[i] = new_loc;
            }
        }
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
        if (action->kind == ACTION_PLUGIN)
        {
            // Special handling for plugins:
            if (action->plugin->patchFunc != nullptr)
            {
                action->plugin->patchFunc(backend.out, &elf, handle, offset,
                    I, action->context);
            }
        }
        else
        {
            // Builtin actions:
            char buf[4096];
            Metadata metadata_buf[MAX_ARGNO+1];
            Metadata *metadata = buildMetadata(handle, action, I, offset,
                metadata_buf, buf, sizeof(buf)-1);
            sendPatchMessage(backend.out, action->name, offset, metadata);
        }
    }
    cs_free(I, 1);

    /*
     * Finalize all plugins.
     */
    finiPlugins(backend.out, &elf);
    cs_close(&handle);

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

