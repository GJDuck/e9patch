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
    std::vector<char *> argv;
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
 * Match regex.
 */
struct MatchRegex
{
    const std::regex regex;
    const std::string str;

    MatchRegex(const char *str) : str(str), regex(str)
    {
        ;
    }

    bool match(const char *str) const
    {
        std::cmatch cmatch;
        return std::regex_match(str, cmatch, regex);
    }
};

/*
 * Match types.
 */
typedef uint16_t MatchType;
#define MATCH_TYPE_UNDEFINED    0x0000
#define MATCH_TYPE_NIL          0x0001
#define MATCH_TYPE_INTEGER      0x0002
#define MATCH_TYPE_OPERAND      0x0004
#define MATCH_TYPE_ACCESS       0x0008
#define MATCH_TYPE_REGISTER     0x0010
#define MATCH_TYPE_MEMORY       0x0020
#define MATCH_TYPE_STRING       0x0040
#define MATCH_TYPE_REGEX        0x0080
#define MATCH_TYPE_SET          0x0100

/*
 * Match value.
 */
struct MatchVal
{
    union
    {
        intptr_t i;
        const char *str;
        e9tool::OpType op;
        e9tool::Access access;
        e9tool::Register reg;
        e9tool::MemOp mem;
        const MatchRegex *regex;
        const MatchVal *vals;
    };
    MatchType type;

    MatchVal() : type(MATCH_TYPE_UNDEFINED), i(0)
    {
        ;
    }
    MatchVal(std::nullptr_t) : type(MATCH_TYPE_NIL), i(0)
    {
        ;
    }
    MatchVal(intptr_t i) : type(MATCH_TYPE_INTEGER), i(i)
    {
        ;
    }
    MatchVal(const char *str) : type(MATCH_TYPE_STRING), str(str)
    {
        ;
    }
    MatchVal(e9tool::OpType op) : type(MATCH_TYPE_OPERAND), op(op)
    {
        ;
    }
    MatchVal(e9tool::Access access) : type(MATCH_TYPE_ACCESS), access(access)
    {
        ;
    }
    MatchVal(e9tool::Register reg) : type(MATCH_TYPE_REGISTER), reg(reg)
    {
        ;
    }
    MatchVal(const e9tool::MemOp &mem) : type(MATCH_TYPE_MEMORY), mem(mem)
    {
        ;
    }
    MatchVal(const MatchRegex *regex) : type(MATCH_TYPE_REGEX), regex(regex)
    {
        ;
    }
    MatchVal(const MatchVal *vals) : type(MATCH_TYPE_SET), vals(vals)
    {
        ;
    }

    int compare(const MatchVal &val) const;

    bool operator==(const MatchVal &val) const;
    bool operator!=(const MatchVal &val) const
    {
        return !(MatchVal::operator==(val));
    }
    bool operator<(const MatchVal &val) const
    {
        return (compare(val) < 0);
    }
    bool operator<=(const MatchVal &val) const
    {
        return (compare(val) <= 0);
    }
    bool operator>(const MatchVal &val) const
    {
        return (compare(val) > 0);
    }
    bool operator>=(const MatchVal &val) const
    {
        return (compare(val) >= 0);
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

    MATCH_CSV,

    MATCH_BB_BEST,
    MATCH_BB_ENTRY,
    MATCH_BB_EXIT,
    MATCH_BB_ADDR,
    MATCH_BB_OFFSET,
    MATCH_BB_SIZE,
    MATCH_BB_LEN,

    MATCH_F_BEST,
    MATCH_F_ENTRY,
    MATCH_F_ADDR,
    MATCH_F_OFFSET,
    MATCH_F_SIZE,
    MATCH_F_LEN,
    MATCH_F_NAME,

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
    MATCH_Is,                           // Instructions
    MATCH_BBs,                          // Basic blocks
    MATCH_Fs,                           // Functions
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
 * Match variable.
 */
struct MatchVar
{
    const MatchSet     set;             // Instruction set
    const int          i;               // Instruction set index
    const MatchKind    match;           // Variable name
    const int          j;               // Variable index
    const MatchField   field;           // Variable field
    const char * const basename;        // Basename (if applicable)
    Plugin * const     plugin;          // Plugin (if applicable)

    MatchVar(MatchSet set, int i, MatchKind match, int j, MatchField field,
            const char *basename, Plugin *plugin) :
        set(set), i(i), match(match), j(j), field(field), basename(basename),
        plugin(plugin)
    {
        ;
    }
};

/*
 * Match comparison.
 */
enum MatchCmp
{
    MATCH_CMP_INVALID,
    MATCH_CMP_DEFINED,
    MATCH_CMP_NOT_ZERO,
    MATCH_CMP_EQ,
    MATCH_CMP_NEQ,
    MATCH_CMP_LT,
    MATCH_CMP_LEQ,
    MATCH_CMP_GT,
    MATCH_CMP_GEQ,
    MATCH_CMP_IN
};

/*
 * Match instantiation.
 */
enum MatchInst : uint8_t
{
    MATCH_INST_VAL,
    MATCH_INST_VAR,
    MATCH_INST_EMPTY
};

/*
 * A match arg.
 */
struct MatchArg
{
    union
    {
        const MatchVar * const var;
        const MatchVal * const val;
    };
    const MatchInst inst;

    MatchArg(const MatchVal *val) : inst(MATCH_INST_VAL), val(val)
    {
        ;
    }
    MatchArg(const MatchVar *var) : inst(MATCH_INST_VAR), var(var)
    {
        ;
    }
    MatchArg() : inst(MATCH_INST_EMPTY), val(nullptr)
    {
        ;
    }
};

/*
 * A match test.
 */
struct MatchTest
{
    const MatchArg lhs;                     // LHS
    const MatchCmp cmp;                     // Comparator
    const MatchArg rhs;                     // RHS

    MatchTest(MatchCmp cmp, const MatchArg arg) :
        cmp(cmp), lhs(arg)
    {
        ;
    }
    MatchTest(const MatchArg larg, MatchCmp cmp, const MatchArg rarg) :
        cmp(cmp), lhs(larg), rhs(rarg)
    {
        ;
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
extern MatchExpr *parseMatch(const e9tool::ELF &elf, const char *str);
extern const Patch *parsePatch(const e9tool::ELF &elf, const char *str);
extern bool matchEval(const MatchExpr *expr, const e9tool::ELF &elf,
    const std::vector<e9tool::Instr> &Is, size_t idx,
    const e9tool::InstrInfo *I);

#endif
