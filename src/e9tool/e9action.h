/*
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
#ifndef __E9ACTION_H
#define __E9ACTION_H

#include <cassert>
#include <cstdint>

#include <map>
#include <regex>
#include <set>
#include <vector>

#include "e9tool.h"
#include "e9plugin.h"

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
 * Match value.
 */
struct MatchValue
{
    MatchType type;
    union
    {
        intptr_t i;
        e9tool::OpType op;
        e9tool::Access access;
        e9tool::Register reg;
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

    MATCH_BB_BEST,
    MATCH_BB_ENTRY,
    MATCH_BB_EXIT,
    MATCH_BB_ADDR,
    MATCH_BB_OFFSET,
    MATCH_BB_SIZE,
    MATCH_BB_LEN,

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
 * Match sets.
 */
enum MatchSet
{
    MATCH_Is,                   // Instructions
    MATCH_BBs                   // Basic blocks
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
 * An index.
 */
typedef std::vector<const char *> Record;
typedef std::vector<Record> Data;
template <typename T, class Cmp = std::less<T>>
using Index = std::map<T, const Record *, Cmp>;

/*
 * A match entry.
 */
struct MatchTest
{
    const MatchSet   set;
    const int        i;
    const MatchKind  match;
    const int        j;
    const MatchField field;
    const MatchCmp   cmp;
    const char *     basename;
    Plugin * const   plugin;
    union
    {
        void *data;
        std::regex *regex;
        Index<MatchValue> *values;
        std::set<e9tool::Register> *regs;
    };

    MatchTest(MatchSet set, int i, MatchKind match, int j, MatchField field,
            MatchCmp cmp, Plugin *plugin, const char *basename) :
        set(set), i(i), match(match), field(field), j(j), cmp(cmp),
        basename(basename), plugin(plugin)
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
    const e9tool::PatchPos pos;

    int status = 0;
    const e9tool::CallABI abi = e9tool::ABI_CLEAN;
    const e9tool::CallJump jmp = e9tool::JUMP_NONE;
    const char * const symbol = nullptr;
    const std::vector<e9tool::Argument> args;
    const char * const filename = nullptr;
    mutable const e9tool::ELF * elf = nullptr;
    Plugin * const plugin = nullptr;

    Patch(const char *name, PatchKind kind, e9tool::PatchPos pos) :
        name(name), kind(kind), pos(pos)
    {
        assert(kind == PATCH_EMPTY || kind == PATCH_BREAK ||
            kind == PATCH_PRINT || kind == PATCH_TRAP);
    };

    Patch(const char *name, PatchKind kind, e9tool::PatchPos pos, int status) :
        name(name), kind(kind), pos(pos), status(status)
    {
        assert(kind == PATCH_EXIT);
    }

    Patch(const char *name, PatchKind kind, e9tool::PatchPos pos,
            e9tool::CallABI abi, e9tool::CallJump jmp, const char *symbol,
            const std::vector<e9tool::Argument> &args, const char *filename) :
        name(name), kind(kind), pos(pos),
        abi(abi), jmp(jmp), symbol(symbol), args(args), filename(filename)
    {
        assert(kind == PATCH_CALL);
    }

    Patch(const char *name, PatchKind kind, e9tool::PatchPos pos,
            Plugin *plugin) :
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
 * Prototypes.
 */
extern bool matchEval(const MatchExpr *expr, const e9tool::ELF *elf,
    const std::vector<e9tool::Instr> &Is, size_t idx,
    const e9tool::InstrInfo *I, const char *basename = nullptr,
    const Record **record = nullptr);

#endif
