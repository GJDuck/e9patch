/*
 * Copyright (C) 2022 National University of Singapore
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

NO_RETURN void deprecatedPatch(const char *what);
Plugin *openPlugin(const char *basename);

/*
 * Deprecated feature error.
 */
static NO_RETURN void deprecatedMatch(const char *what)
{
    error("the \"%s\" syntax has been deprecated!\n"
        "\n"
        "Please use the following (example) syntax instead:%s\n"
        "\tasm=j.*                ---> asm=/j.*/\n"
        "\taddr=0x123,0x456,0x789 ---> addr in {0x123,0x456,0x789}%s\n"
        "\n"
        "Note that the behaviour of CSV file matching has also changed.\n"
        "Please see the e9tool-user-guide.md for more information.\n",
        what, (option_is_tty? "\33[33m": ""), (option_is_tty? "\33[0m": ""));
}

/*
 * Parse and index.
 */
static intptr_t parseIndex(Parser &parser, intptr_t lb, intptr_t ub)
{
    parser.expectToken('[');
    bool neg = false;
    if (parser.peekToken() == '-')
    {
        neg = true;
        parser.getToken();
    }
    parser.expectToken(TOKEN_INTEGER);
    intptr_t idx = parser.i;
    idx = (neg? -idx: idx);
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
 * Parse a memory operand.
 */
static MemOp parseMemOp(Parser &parser, int t)
{
    MemOp memop;
    switch (t)
    {
        case TOKEN_MEM8:
            memop.size = sizeof(int8_t); break;
        case TOKEN_MEM16:
            memop.size = sizeof(int16_t); break;
        case TOKEN_MEM32:
            memop.size = sizeof(int32_t); break;
        case TOKEN_MEM64:
            memop.size = sizeof(int64_t); break;
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
            error("failed to parse %s; invalid memory operand segment "
                "register %s ", parser.mode, getRegName(memop.seg));
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
            error("failed to parse %s; invalid memory operand base register "
                " %s ", parser.mode, getRegName(memop.base));
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
            error("failed to parse %s; invalid memory operand index register "
                "%s ", parser.mode, getRegName(memop.index));
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
    return memop;
}

/*
 * Parse a match argument.
 */
static const MatchArg parseMatchArg(Parser &parser, bool val = false)
{
    bool neg = false;
    int t = parser.getToken();

    // Step (1): attempt to parse a value:
    switch (t)
    {
        case TOKEN_STRING:
            return MatchArg(new MatchVal(strDup(parser.s)));
        case TOKEN_REGEX:
            try
            {
                return MatchArg(new MatchVal(new MatchRegex(parser.s)));
            }
            catch (const std::regex_error &e)
            {
                error("failed to parse regular expression \"%s\"", parser.s);
            }
        case '&':
            parser.expectToken2(TOKEN_STRING, TOKEN_NAME);
            return MatchArg(new MatchVal(parseSymbol(parser, parser.s)));
        case TOKEN_NIL:
            return MatchArg(new MatchVal(nullptr));
        case '-':
            if (parser.peekToken() != TOKEN_INTEGER)
                return MatchArg(new MatchVal((Access)0x0));
            neg = true;
            // Fallthrough
        case '+':
            parser.expectToken(TOKEN_INTEGER);
            // Fallthrough
        case TOKEN_INTEGER:
            return MatchArg(new MatchVal((neg? -parser.i: parser.i)));
        case TOKEN_REGISTER:
            return MatchArg(new MatchVal((Register)parser.i));
        case TOKEN_MEM: case TOKEN_REG: case TOKEN_IMM:
        {
            OpType type = (OpType)parser.i;
            if (parser.peekToken() == '[' || parser.peekToken() == '.')
                break;
            return MatchArg(new MatchVal(type));
        }
        case TOKEN_NONE: case TOKEN_READ: case TOKEN_WRITE: case TOKEN_RW:
            return MatchArg(new MatchVal((Access)parser.i));
        case TOKEN_MEM8: case TOKEN_MEM16: case TOKEN_MEM32: case TOKEN_MEM64:
            return MatchArg(new MatchVal(parseMemOp(parser, t)));   
        case '{':
        {
            if (val)
                parser.unexpectedToken();
            std::vector<const MatchVal *> tmp;
            if (parser.peekToken() != '}')
            {
                tmp.push_back(parseMatchArg(parser, /*val=*/true).val);
                while (parser.expectToken2(',', '}') != '}')
                    tmp.push_back(parseMatchArg(parser, /*val=*/true).val);
            }
            tmp.push_back(new MatchVal());
            MatchVal *vals = new MatchVal[tmp.size()];
            for (size_t i = 0; i < tmp.size(); i++)
            {
                vals[i] = *tmp[i];
                delete tmp[i];
            }
            return MatchArg(new MatchVal(vals));
        }
        default:
            break;
    }

    if (val)
        parser.unexpectedToken();

    // Step (2): attempt to parse a variable:
    MatchSet set = MATCH_Is;
    bool spec = false;
    switch (t)
    {
        case TOKEN_BB:
            option_targets = option_bbs = true;
            if (parser.peekToken() != '[')
                break;
            spec = true;
            set = MATCH_BBs;
            break;
        case TOKEN_F:
            option_targets = option_fs = true;
            if (parser.peekToken() != '[')
                break;
            spec = true;
            set = MATCH_Fs;
            break;
        case TOKEN_I:
            spec = true;
            set = MATCH_Is;
            break;
        default:
            break;
    }
    int i = 0;
    if (spec)
    {
        i = (int)parseIndex(parser, INT32_MIN, INT32_MAX);
        if (parser.peekToken() != '.')
            return MatchArg(new MatchVar(set, i, MATCH_TRUE, 0,
                MATCH_FIELD_NONE, nullptr, nullptr));
        (void)parser.getToken();
        t = parser.getToken();
    }
    MatchKind match = MATCH_INVALID;
    const char *basename = nullptr;
    switch (t)
    {
        case TOKEN_ASM:
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
            match = MATCH_SECTION; break;
        case TOKEN_SIZE: case TOKEN_LENGTH:
            match = MATCH_SIZE; break;
        case TOKEN_SRC:
            match = MATCH_SRC; break;
        case TOKEN_TARGET:
            match = MATCH_TARGET; break;
        case TOKEN_TRUE:
            match = MATCH_TRUE; break;
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
        case TOKEN_NAME:
            basename = strDup(parser.s);
            match = MATCH_CSV;
            break;
        case TOKEN_BB:
            if (parser.peekToken() == '.')
            {
                parser.getToken();
                switch (parser.getToken())
                {
                    case TOKEN_SIZE:
                        match = MATCH_BB_SIZE; break;
                    case TOKEN_LENGTH:
                        match = MATCH_BB_LEN; break;
                    case TOKEN_ADDR:
                        match = MATCH_BB_ADDR; break;
                    case TOKEN_OFFSET:
                        match = MATCH_BB_OFFSET; break;
                    case TOKEN_ENTRY:
                        match = MATCH_BB_ENTRY; break;
                    case TOKEN_EXIT:
                        match = MATCH_BB_EXIT; break;
                    case TOKEN_BEST:
                        match = MATCH_BB_BEST; break;
                    default:
                        parser.unexpectedToken();
                }
            }
            else
                match = MATCH_BB_ADDR;
            break;
        case TOKEN_F:
            if (parser.peekToken() == '.')
            {
                parser.getToken();
                switch (parser.getToken())
                {
                    case TOKEN_SIZE:
                        match = MATCH_F_SIZE; break;
                    case TOKEN_LENGTH:
                        match = MATCH_F_LEN; break;
                    case TOKEN_ADDR:
                        match = MATCH_F_ADDR; break;
                    case TOKEN_OFFSET:
                        match = MATCH_F_OFFSET; break;
                    case TOKEN_ENTRY:
                        match = MATCH_F_ENTRY; break;
                    case TOKEN_BEST:
                        match = MATCH_F_BEST; break;
                    case TOKEN_NAME_2:
                        match = MATCH_F_NAME; break;
                    default:
                        parser.unexpectedToken();
                }
            }
            else
                match = MATCH_F_ADDR;
            break;
        case TOKEN_READS:
            match = MATCH_READS; break;
        case TOKEN_WRITES:
            match = MATCH_WRITES; break;
        case TOKEN_REGS:
            match = MATCH_REGS; break;
        default:
            parser.unexpectedToken();
    }
    Plugin *plugin = nullptr;
    int j = -1;
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
                    j = (unsigned)parseIndex(parser, 0, 7);
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
                        field = MATCH_FIELD_TYPE; break;
                    case TOKEN_ACCESS:
                        field = MATCH_FIELD_ACCESS; break;
                    case TOKEN_SIZE: case TOKEN_LENGTH:
                        need_idx = false;
                        field = MATCH_FIELD_SIZE; break;
                    case TOKEN_SEGMENT:
                        field = MATCH_FIELD_SEG; break;
                    case TOKEN_DISPLACEMENT:
                        field = MATCH_FIELD_DISPL; break;
                    case TOKEN_BASE:
                        field = MATCH_FIELD_BASE; break;
                    case TOKEN_INDEX:
                        field = MATCH_FIELD_INDEX; break;
                    case TOKEN_SCALE:
                        field = MATCH_FIELD_SCALE; break;
                    default:
                        parser.unexpectedToken();
                }
                if (need_idx && j < 0)
                    parser.unexpectedToken();
                parser.getToken();
            }
            break;

        case MATCH_CSV:
            if (parser.peekToken() == '.')
            {
                // This is "probably" an attempt to use the old regex syntax
                deprecatedMatch("regular expression");
            }
            j = (unsigned)parseIndex(parser, 0, UINT16_MAX);
            break;

        default:
            break;
    }
    return MatchArg(new MatchVar(set, i, match, j, field, basename, plugin));
}

/*
 * Parse a match test.
 */
static MatchTest *parseTest(Parser &parser)
{
    if (parser.peekToken() == TOKEN_DEFINED)
    {
        parser.getToken();
        parser.expectToken('(');
        auto arg = parseMatchArg(parser);
        parser.expectToken(')');
        return new MatchTest(MATCH_CMP_DEFINED, arg);
    }
    auto larg = parseMatchArg(parser);
    MatchCmp cmp = MATCH_CMP_INVALID;
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
        case TOKEN_IN:
            cmp = MATCH_CMP_IN; break;
        default:
            cmp = MATCH_CMP_NOT_ZERO; break;
    }
    if (cmp == MATCH_CMP_NOT_ZERO)
        return new MatchTest(cmp, larg);
    parser.getToken();
    auto rarg = parseMatchArg(parser);
    return new MatchTest(larg, cmp, rarg);
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
            expr = parseTestExpr(parser);
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
            case ',':
                deprecatedMatch("comma syntax");
            default:
                return expr;
        }
    }
}

/*
 * Parse a match expr.
 */
MatchExpr *parseMatch(const ELF &elf, const char *str)
{
    Parser parser(str, "matching", elf);
    MatchExpr *expr = parseMatchExpr(parser, MATCH_OP_OR);
    parser.expectToken(TOKEN_EOF);
    return expr;
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
const Patch *parsePatch(const ELF &elf, const char *str)
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
            deprecatedPatch("call ...");
        case TOKEN_EMPTY:
            kind = PATCH_EMPTY; break;
        case TOKEN_EXIT:
            kind = PATCH_EXIT; break;
        case TOKEN_PASSTHRU:
            deprecatedPatch("passthru");
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
                MemOp memop = {0, REGISTER_NONE, REGISTER_NONE, REGISTER_NONE,
                    1, 0};
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
                    case TOKEN_BB:
                        option_targets = option_bbs = true;
                        arg = ARGUMENT_BB; break;
                    case TOKEN_DST:
                        arg = ARGUMENT_DST; break;
                    case TOKEN_CONFIG:
                        arg = ARGUMENT_CONFIG; break;
                    case TOKEN_F:
                        option_targets = option_fs = true;
                        arg = ARGUMENT_F; break;
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
                        memop = parseMemOp(parser, t);
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
                    case ARGUMENT_BB: case ARGUMENT_F:
                        field = FIELD_ADDR;
                        if (parser.peekToken() == '.')
                        {
                            parser.getToken();
                            switch (parser.getToken())
                            {
                                case TOKEN_ADDR:
                                    field = FIELD_ADDR; break;
                                case TOKEN_OFFSET:
                                    field = FIELD_OFFSET; break;
                                case TOKEN_SIZE:
                                    field = FIELD_SIZE; break;
                                case TOKEN_LENGTH:
                                    field = FIELD_LEN; break;
                                case TOKEN_NAME_2:
                                    if (arg != ARGUMENT_F)
                                        parser.unexpectedToken();
                                    field = FIELD_NAME; break;
                                default:
                                    parser.unexpectedToken();
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
                        case ARGUMENT_BB: case ARGUMENT_F:
                            if (field == FIELD_ADDR)
                                break;
                            // Fallthrough:
                        default:
                            error("failed to parse call trampoline; cannot "
                                "use `static' with `%s' argument",
                                parser.getName(arg_token));
                    }
                }
                bool duplicate = false;
                for (const auto &prevArg: args)
                {
                    if (prevArg.kind == arg && prevArg.field == field)
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
 * Dump a value.
 */
static void dumpVal(const MatchVal &val, std::string &str)
{
    switch (val.type)
    {
        case MATCH_TYPE_UNDEFINED:
            str += "undefined"; return;
        case MATCH_TYPE_NIL:
            str += "nil"; return;
        case MATCH_TYPE_INTEGER:
            str += std::to_string(val.i); return;
        case MATCH_TYPE_OPERAND:
            switch (val.op)
            {
                case OPTYPE_IMM:
                    str += "imm"; return;
                case OPTYPE_REG:
                    str += "reg"; return;
                case OPTYPE_MEM:
                    str += "mem"; return;
                default:
                    str += "???"; return;
            }
        case MATCH_TYPE_ACCESS:
            switch (val.access)
            {
                case 0:
                    str += '-'; return;
                case ACCESS_READ:
                    str += 'r'; return;
                case ACCESS_WRITE:
                    str += 'w'; return;
                case ACCESS_READ | ACCESS_WRITE:
                    str += "rw"; return;
                default:
                    str += "???"; return;
            }
        case MATCH_TYPE_REGISTER:
            str += getRegName(val.reg); return;
        case MATCH_TYPE_MEMORY:
            str += "mem";
            str += std::to_string(8 * val.mem.size);
            str += '<';
            if (val.mem.seg != REGISTER_NONE)
            {
                str += getRegName(val.mem.seg);
                str += ':';
            }
            if (val.mem.disp != 0)
                str += std::to_string(val.mem.disp);
            str += '(';
            str +=
                (val.mem.base != REGISTER_NONE? getRegName(val.mem.base): "");
            str += ',';
            str +=
                (val.mem.index != REGISTER_NONE? getRegName(val.mem.index): "");
            str += ',';
            str += std::to_string(val.mem.scale);
            str += '>';
            return;
        case MATCH_TYPE_STRING:
            str += '\"';
            for (size_t i = 0; val.str[i] != '\0'; i++)
            {
                switch (val.str[i])
                {
                    case '\n': str += "\\n"; continue;
                    case '\r': str += "\\r"; continue;
                    case '\t': str += "\\t"; continue;
                    case '\\': str += "\\\\"; continue;
                    case '"':  str += "\\\""; continue;
                    default: break;
                }
                str += val.str[i]; 
            }
            str += '\"';
            return;
        case MATCH_TYPE_REGEX:
            str += '/';
            str += val.regex->str;
            str += '/';
            return;
        case MATCH_TYPE_SET:
        {
            const MatchVal *vals = val.vals;
            std::set<MatchVal> tmp;
            for (size_t i = 0; vals[i].type != MATCH_TYPE_UNDEFINED; i++)
                tmp.insert(vals[i]);
            str += '{';
            bool prev = false;
            for (const auto &val: tmp)
            {
                if (prev)
                    str += ',';
                prev = true;
                dumpVal(val, str);
            }
            str += '}';
            return;
        }
        default:
            str += "???"; return;
    }
}

/*
 * Value (dis)equality.
 */
bool MatchVal::operator==(const MatchVal &val) const
{
	switch (type)
    {
        case MATCH_TYPE_STRING:
        {
            if (val.type != MATCH_TYPE_REGEX)
                break;
            return val.regex->match(str);
        }
        case MATCH_TYPE_REGEX:
        {
            if (val.type != MATCH_TYPE_STRING)
                break;
            return regex->match(val.str);
        }
        default:
            break;
    }
    return (compare(val) == 0);
}

/*
 * Set membership.
 */
static bool isMember(const MatchVal *val, const MatchVal *set)
{
    if (set->type != MATCH_TYPE_SET)
        return false;
    const MatchVal *vals = set->vals;
    for (size_t i = 0; vals[i].type != MATCH_TYPE_UNDEFINED; i++)
    {
        if (*val == vals[i])
            return true;
    }
    return false;
}

/*
 * Set subset.
 */
static bool isSubset(const MatchVal *set1, const MatchVal *set2)
{
    if (set1->type != MATCH_TYPE_SET) 
        return false;
    const MatchVal *vals = set1->vals;
    for (size_t i = 0; vals[i].type != MATCH_TYPE_UNDEFINED; i++)
    {
        if (!isMember(&vals[i], set2))
            return false;
    }
    return true;
}

/*
 * Set comparison.
 */
static int setCompare(const MatchVal *set1, const MatchVal *set2)
{
    const MatchVal *vals1 = set1->vals, *vals2 = set2->vals;
    const MatchVal *min1 = nullptr, *min2 = nullptr;
    for (size_t i = 0; vals1[i].type != MATCH_TYPE_UNDEFINED; i++)
    {
        if (isMember(&vals1[i], set2))
            continue;
        if (min1 == nullptr || vals1[i] < *min1)
            min1 = &vals1[i];
    }
    for (size_t i = 0; vals2[i].type != MATCH_TYPE_UNDEFINED; i++)
    {
        if (isMember(&vals2[i], set1))
            continue;
        if (min2 == nullptr || vals2[i] < *min2)
            min2 = &vals2[i];
    }
    if (min1 == nullptr)
        return (min2 == nullptr? 0: 1);
    else if (min2 == nullptr)
        return -1;
    return (*min1 < *min2? -1: 1);
}

/*
 * Value comparison.
 */
int MatchVal::compare(const MatchVal &val) const
{
    if (val.type < type)
        return 1;
    if (val.type > type)
        return -1;
    switch (type)
    {
        case MATCH_TYPE_NIL:
            return 0;
        case MATCH_TYPE_INTEGER:
            return (val.i < i? 1:
                   (val.i > i? -1: 0));
        case MATCH_TYPE_OPERAND:
            return (val.op < op? 1:
                   (val.op > op? -1: 0));
        case MATCH_TYPE_ACCESS:
            return (val.access < access? 1:
                   (val.access > access? -1: 0));
        case MATCH_TYPE_REGISTER:
            return (val.reg < reg? 1:
                   (val.reg > reg? -1: 0));
        case MATCH_TYPE_MEMORY:
            if (val.mem.seg != mem.seg)
                return (val.mem.seg < mem.seg? 1: -1);
            if (val.mem.base != mem.base)
                return (val.mem.base < mem.base? 1: -1);
            if (val.mem.index != mem.index)
                return (val.mem.index < mem.index? 1: -1);
            if (val.mem.scale != mem.scale)
                return (val.mem.scale < mem.scale? 1: -1);
            if (val.mem.disp != mem.disp)
                return (val.mem.disp < mem.disp? 1: -1);
            if (val.mem.size != mem.size)
                return (val.mem.size < mem.size? 1: -1);
            return 0;
        case MATCH_TYPE_STRING:
        {
            int cmp = strcmp(str, val.str);
            return (cmp < 0? -1: (cmp > 0? 1: 0));
        }
        case MATCH_TYPE_REGEX:
        {
            std::string str1, str2;
            dumpVal(*this, str1);
            dumpVal(val, str2);
            error("regular exression values %s and %s cannot be compared",
                str1.c_str(), str2.c_str());
        }
        case MATCH_TYPE_SET:
            return setCompare(&val, this);
        default:
            error("unknown type (0x%x)", type);
    }
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
static MatchVal makeMatchValue(const MatchVar *var, const ELF *elf,
    const std::vector<Instr> &Is, size_t idx, const InstrInfo *I,
    MatchVal *buf)
{
    MatchKind match  = var->match;
    MatchField field = var->field;
    MatchVal result;
    result.type = MATCH_TYPE_INTEGER;
    result.i    = 0x0;
    const OpInfo *op = nullptr;
    OpType type = OPTYPE_INVALID;
    uint8_t access = 0;
    const BB *bb = nullptr;
    const F *f   = nullptr;
    InstrInfo info;
    uint8_t j = 0;

    if (var->i != 0 || var->set != MATCH_Is)
    {
        ssize_t i = (ssize_t)idx + var->i;
        if (i < 0 || i >= (ssize_t)Is.size())
            goto undefined;
        switch (var->set)
        {
            case MATCH_BBs:
            {
                const BB *bb = findBB(elf->bbs, idx);
                if (bb == nullptr || i < (ssize_t)bb->lb || i > (ssize_t)bb->ub)
                    goto undefined;
                break;
            }
            case MATCH_Fs:
            {
                const F *f = findF(elf->fs, idx);
                if (f == nullptr || i < (ssize_t)f->lb || i > (ssize_t)f->ub)
                    goto undefined;
                break;
            }
            case MATCH_Is:
                break;
        }
        if (var->i != 0)
        {
            getInstrInfo(elf, &Is[i], &info);
            I = &info;
            idx = (size_t)i;
        }
    }
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
        case MATCH_BB_ENTRY: case MATCH_BB_EXIT: case MATCH_BB_BEST:
        case MATCH_BB_SIZE: case MATCH_BB_LEN: case MATCH_BB_ADDR:
        case MATCH_BB_OFFSET:
            bb = findBB(elf->bbs, idx);
            if (bb == nullptr)
                goto undefined;
            break;
        case MATCH_F_ENTRY: case MATCH_F_BEST:
        case MATCH_F_SIZE: case MATCH_F_LEN: case MATCH_F_ADDR:
        case MATCH_F_OFFSET: case MATCH_F_NAME:
            f = findF(elf->fs, idx);
            if (f == nullptr)
                goto undefined;
            break;
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
            if (var->j < 0)
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
                op = getOperand(I, var->j, type, access);
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
                            {
                                MemOp memop = {op->mem.disp, op->mem.seg,
                                    op->mem.base, op->mem.index,
                                    (op->mem.scale == 0? (uint8_t)1:
                                        op->mem.scale), op->size};
                                result.type = MATCH_TYPE_MEMORY;
                                result.mem  = memop;
                                return result;
                            }
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
            result.i = var->plugin->result; return result;
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
            result.i = (idx == bb->lb); return result;
        case MATCH_BB_EXIT:
            result.i = (idx == bb->ub); return result;
        case MATCH_BB_LEN:
            result.i = (intptr_t)(bb->ub - bb->lb  + 1); return result;
        case MATCH_BB_SIZE:
            result.i = (Is[bb->ub].address - Is[bb->lb].address +
                Is[bb->ub].size);
            return result;
        case MATCH_BB_ADDR:
            result.i = (intptr_t)Is[bb->lb].address; return result;
        case MATCH_BB_OFFSET:
            result.i = (intptr_t)Is[bb->lb].offset; return result;
        case MATCH_BB_BEST:
            result.i = (idx == bb->best); return result;
        case MATCH_F_ENTRY:
            result.i = (idx == f->lb); return result;
        case MATCH_F_LEN:
            result.i = (intptr_t)(f->ub - f->lb  + 1); return result;
        case MATCH_F_SIZE:
            result.i = (Is[f->ub].address - Is[f->lb].address +
                Is[f->ub].size);
            return result;
        case MATCH_F_ADDR:
            result.i = (intptr_t)Is[f->lb].address; return result;
        case MATCH_F_OFFSET:
            result.i = (intptr_t)Is[f->lb].offset; return result;
        case MATCH_F_BEST:
            result.i = (idx == f->best); return result;
        case MATCH_ASSEMBLY:
            result.type = MATCH_TYPE_STRING;
            result.str  = I->string.instr;
            return result;
        case MATCH_MNEMONIC:
            result.type = MATCH_TYPE_STRING;
            result.str  = I->string.mnemonic;
            return result;
        case MATCH_SECTION:
            result.type = MATCH_TYPE_STRING;
            result.str  = I->string.section;
            return result;
        case MATCH_F_NAME:
            if (f == nullptr || f->name == nullptr)
                goto undefined;
            result.type = MATCH_TYPE_STRING;
            result.str  = f->name;
            return result;
        case MATCH_READS:
            if (I->flags.read != 0x0)
                buf[j++] = REGISTER_EFLAGS;
            for (uint8_t i = 0; I->regs.read[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.read[i]);
            for (uint8_t i = 0; I->regs.condread[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.condread[i]);
            buf[j++] = MatchVal();
            result.type = MATCH_TYPE_SET;
            result.vals = buf;
            return result;
        case MATCH_WRITES:
            if (I->flags.write != 0x0)
                buf[j++] = REGISTER_EFLAGS;
            for (uint8_t i = 0; I->regs.write[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.write[i]);
            for (uint8_t i = 0; I->regs.condwrite[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.condwrite[i]);
            buf[j++] = MatchVal();
            result.type = MATCH_TYPE_SET;
            result.vals = buf;
            return result;
        case MATCH_REGS:
            if ((I->flags.read | I->flags.write) != 0x0)
                buf[j++] = REGISTER_EFLAGS;
            for (uint8_t i = 0; I->regs.read[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.read[i]);
            for (uint8_t i = 0; I->regs.condread[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.condread[i]);
            for (uint8_t i = 0; I->regs.write[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.write[i]);
            for (uint8_t i = 0; I->regs.condwrite[i] != REGISTER_INVALID; i++)
                buf[j++] = MatchVal(I->regs.condwrite[i]);
            buf[j++] = MatchVal();
            result.type = MATCH_TYPE_SET;
            result.vals = buf;
            return result;
        case MATCH_CSV:
            result = getCSVValue(I->address, var->basename, var->j);
            return result;
        default:
        undefined:
            result.type = MATCH_TYPE_UNDEFINED;
            return result;
    }
}

/*
 * Evaluate a test.
 */
static bool matchEvalTest(const MatchTest *test, const MatchVal *lval,
        const MatchVal *rval)
{
    if (test->cmp == MATCH_CMP_DEFINED)
        return (lval->type != MATCH_TYPE_UNDEFINED);
    if (lval->type == MATCH_TYPE_UNDEFINED)
        return false;
    if (test->cmp == MATCH_CMP_NOT_ZERO)
        return (lval->type == MATCH_TYPE_INTEGER && lval->i != 0);
    if (rval->type == MATCH_TYPE_UNDEFINED)
        return false;
    switch (test->cmp)
    {
        case MATCH_CMP_EQ:
            return (*lval == *rval);
        case MATCH_CMP_NEQ:
            return (*lval != *rval);
        case MATCH_CMP_LT:
            return (*lval < *rval);
        case MATCH_CMP_LEQ:
            return (*lval <= *rval);
        case MATCH_CMP_GT:
            return (*lval > *rval);
        case MATCH_CMP_GEQ:
            return (*lval >= *rval);
        case MATCH_CMP_IN:
        {
            if (rval->type != MATCH_TYPE_SET)
                return false;
            else if (lval->type != MATCH_TYPE_SET)
                return isMember(lval, rval);
            else
                return isSubset(lval, rval);
        }
        default:
            error("unexpected cmp");
    }
}

/*
 * Evaluate a matching.
 */
bool matchEval(const MatchExpr *expr, const ELF &elf,
    const std::vector<Instr> &Is, size_t idx, const InstrInfo *I)
{
    if (expr == nullptr)
        return true;
    const MatchTest *test = nullptr;
    switch (expr->op)
    {
        case MATCH_OP_NOT:
            return !matchEval(expr->arg1, elf, Is, idx, I);
        case MATCH_OP_AND:
            return matchEval(expr->arg1, elf, Is, idx, I) &&
                   matchEval(expr->arg2, elf, Is, idx, I);
        case MATCH_OP_OR:
            return matchEval(expr->arg1, elf, Is, idx, I) ||
                   matchEval(expr->arg2, elf, Is, idx, I);
        case MATCH_OP_TEST:
            test = expr->test;
            break;
        default:
            return false;
    }

    MatchVal LVAL, RVAL;
    const MatchVal *lval = nullptr, *rval = nullptr;
    MatchVal lbuf[64], rbuf[64];
    switch (test->lhs.inst)
    {
        case MATCH_INST_VAL:
            lval = test->lhs.val;
            break;
        case MATCH_INST_VAR:
            LVAL = makeMatchValue(test->lhs.var, &elf, Is, idx, I, lbuf);
            lval = &LVAL;
            break;
        default:
            error("unexpected inst");
    }
    switch (test->rhs.inst)
    {
        case MATCH_INST_VAL:
            rval = test->rhs.val;
            break;
        case MATCH_INST_VAR:
            RVAL = makeMatchValue(test->rhs.var, &elf, Is, idx, I, rbuf);
            rval = &RVAL;
            break;
        case MATCH_INST_EMPTY:
            break;
    }
    bool pass = matchEvalTest(test, lval, rval);
    if (option_debug)
    {
        std::string str;
        if (test->cmp == MATCH_CMP_DEFINED)
            str += "defined(";
        dumpVal(*lval, str);
        switch (test->cmp)
        {
            case MATCH_CMP_EQ:  str += " == "; break;
            case MATCH_CMP_NEQ: str += " != "; break;
            case MATCH_CMP_LT:  str += " < ";  break;
            case MATCH_CMP_LEQ: str += " <= "; break;
            case MATCH_CMP_GT:  str += " > ";  break;
            case MATCH_CMP_GEQ: str += " >= "; break;
            case MATCH_CMP_IN:  str += " in "; break;
            default: break;
        }
        switch (test->cmp)
        {
            case MATCH_CMP_DEFINED:
                str += ')'; break;
            case MATCH_CMP_NOT_ZERO:
                str += " != 0"; break;
            default:
                dumpVal(*rval, str); break;
        }
        debug("    %s0x%lx%s test (%s) = %s%s%s",
            (option_is_tty? "\33[31m": ""), I->address,
            (option_is_tty? "\33[0m": ""), str.c_str(),
            (option_is_tty? (pass? "\33[32m": "\33[31m"): ""),
            (pass? "TRUE": "FALSE"),
            (option_is_tty? "\33[0m": ""));
    }
    return pass;
}

