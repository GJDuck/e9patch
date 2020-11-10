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

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "e9frontend.h"

using namespace e9frontend;

/*
 * Operand types.
 */
#define OP_TYPE_MAGIC       0x004F5000000000ull
#define OP_TYPE(n)          (OP_TYPE_MAGIC | (n))

#define OP_TYPE_IMM         OP_TYPE(1)
#define OP_TYPE_REG         OP_TYPE(2)
#define OP_TYPE_MEM         OP_TYPE(3)

/*
 * Access types.
 */
#define ACCESS_MAGIC        0x41434300000000ull
#define ACCESS(n)           (ACCESS_MAGIC | (n))

#define ACCESS_READ         ACCESS(0x1)
#define ACCESS_WRITE        ACCESS(0x2)

/*
 * Register names.
 */
#define REG_NAME_MAGIC      0x52454700000000ull
#define REG_NAME(b, h, n)   (REG_NAME_MAGIC | (b) | ((h) << 8) | ((n) << 16))

#define REG_NAME_AL         REG_NAME(8, 0, 0)
#define REG_NAME_AH         REG_NAME(8, 1, 0)
#define REG_NAME_AX         REG_NAME(16, 0, 0)
#define REG_NAME_EAX        REG_NAME(32, 0, 0)
#define REG_NAME_RAX        REG_NAME(64, 0, 0)

#define REG_NAME_CL         REG_NAME(8, 0, 1)
#define REG_NAME_CH         REG_NAME(8, 1, 1)
#define REG_NAME_CX         REG_NAME(16, 0, 1)
#define REG_NAME_ECX        REG_NAME(32, 0, 1)
#define REG_NAME_RCX        REG_NAME(64, 0, 1)

#define REG_NAME_DL         REG_NAME(8, 0, 2)
#define REG_NAME_DH         REG_NAME(8, 1, 2)
#define REG_NAME_DX         REG_NAME(16, 0, 2)
#define REG_NAME_EDX        REG_NAME(32, 0, 2)
#define REG_NAME_RDX        REG_NAME(64, 0, 2)

#define REG_NAME_BL         REG_NAME(8, 0, 3)
#define REG_NAME_BH         REG_NAME(8, 1, 3)
#define REG_NAME_BX         REG_NAME(16, 0, 3)
#define REG_NAME_EBX        REG_NAME(32, 0, 3)
#define REG_NAME_RBX        REG_NAME(64, 0, 3)

#define REG_NAME_SPL        REG_NAME(8, 0, 4)
#define REG_NAME_SP         REG_NAME(16, 0, 4)
#define REG_NAME_ESP        REG_NAME(32, 0, 4)
#define REG_NAME_RSP        REG_NAME(64, 0, 4)

#define REG_NAME_BPL        REG_NAME(8, 0, 5)
#define REG_NAME_BP         REG_NAME(16, 0, 5)
#define REG_NAME_EBP        REG_NAME(32, 0, 5)
#define REG_NAME_RBP        REG_NAME(64, 0, 5)

#define REG_NAME_SIL        REG_NAME(8, 0, 6)
#define REG_NAME_SI         REG_NAME(16, 0, 6)
#define REG_NAME_ESI        REG_NAME(32, 0, 6)
#define REG_NAME_RSI        REG_NAME(64, 0, 6)

#define REG_NAME_DIL        REG_NAME(8, 0, 7)
#define REG_NAME_DI         REG_NAME(16, 0, 7)
#define REG_NAME_EDI        REG_NAME(32, 0, 7)
#define REG_NAME_RDI        REG_NAME(64, 0, 7)

#define REG_NAME_R8B        REG_NAME(8, 0, 8)
#define REG_NAME_R8W        REG_NAME(16, 0, 8)
#define REG_NAME_R8D        REG_NAME(32, 0, 8)
#define REG_NAME_R8         REG_NAME(64, 0, 8)

#define REG_NAME_R9B        REG_NAME(8, 0, 9)
#define REG_NAME_R9W        REG_NAME(16, 0, 9)
#define REG_NAME_R9D        REG_NAME(32, 0, 9)
#define REG_NAME_R9         REG_NAME(64, 0, 9)

#define REG_NAME_R10B       REG_NAME(8, 0, 10)
#define REG_NAME_R10W       REG_NAME(16, 0, 10)
#define REG_NAME_R10D       REG_NAME(32, 0, 10)
#define REG_NAME_R10        REG_NAME(64, 0, 10)

#define REG_NAME_R11B       REG_NAME(8, 0, 11)
#define REG_NAME_R11W       REG_NAME(16, 0, 11)
#define REG_NAME_R11D       REG_NAME(32, 0, 11)
#define REG_NAME_R11        REG_NAME(64, 0, 11)

#define REG_NAME_R12B       REG_NAME(8, 0, 12)
#define REG_NAME_R12W       REG_NAME(16, 0, 12)
#define REG_NAME_R12D       REG_NAME(32, 0, 12)
#define REG_NAME_R12        REG_NAME(64, 0, 12)

#define REG_NAME_R13B       REG_NAME(8, 0, 13)
#define REG_NAME_R13W       REG_NAME(16, 0, 13)
#define REG_NAME_R13D       REG_NAME(32, 0, 13)
#define REG_NAME_R13        REG_NAME(64, 0, 13)

#define REG_NAME_R14B       REG_NAME(8, 0, 14)
#define REG_NAME_R14W       REG_NAME(16, 0, 14)
#define REG_NAME_R14D       REG_NAME(32, 0, 14)
#define REG_NAME_R14        REG_NAME(64, 0, 14)

#define REG_NAME_R15B       REG_NAME(8, 0, 15)
#define REG_NAME_R15W       REG_NAME(16, 0, 15)
#define REG_NAME_R15D       REG_NAME(32, 0, 15)
#define REG_NAME_R15        REG_NAME(64, 0, 15)

#define REG_NAME_RIP        REG_NAME(64, 0, 16)
#define REG_NAME_RFLAGS     REG_NAME(16, 0, 17)

/*
 * Tokens.
 */
enum Token
{
    TOKEN_ERROR = -1,
    TOKEN_END = '\0',
    TOKEN_INTEGER = 2000,
    TOKEN_STRING,
    TOKEN_REGEX,

    // Must be in alphabetical order:
    TOKEN_MACRO_AH = 3000,
    TOKEN_MACRO_AL,
    TOKEN_MACRO_AX,
    TOKEN_MACRO_BH,
    TOKEN_MACRO_BL,
    TOKEN_MACRO_BP,
    TOKEN_MACRO_BPL,
    TOKEN_MACRO_BX,
    TOKEN_MACRO_CH,
    TOKEN_MACRO_CL,
    TOKEN_MACRO_CX,
    TOKEN_MACRO_DH,
    TOKEN_MACRO_DI,
    TOKEN_MACRO_DIL,
    TOKEN_MACRO_DL,
    TOKEN_MACRO_DX,
    TOKEN_MACRO_EAX,
    TOKEN_MACRO_EBP,
    TOKEN_MACRO_EBX,
    TOKEN_MACRO_ECX,
    TOKEN_MACRO_EDI,
    TOKEN_MACRO_EDX,
    TOKEN_MACRO_ESI,
    TOKEN_MACRO_ESP,
    TOKEN_MACRO_FALSE,
    TOKEN_MACRO_IMM,
    TOKEN_MACRO_MEM,
    TOKEN_MACRO_NIL,
    TOKEN_MACRO_R10,
    TOKEN_MACRO_R10B,
    TOKEN_MACRO_R10D,
    TOKEN_MACRO_R10W,
    TOKEN_MACRO_R11,
    TOKEN_MACRO_R11B,
    TOKEN_MACRO_R11D,
    TOKEN_MACRO_R11W,
    TOKEN_MACRO_R12,
    TOKEN_MACRO_R12B,
    TOKEN_MACRO_R12D,
    TOKEN_MACRO_R12W,
    TOKEN_MACRO_R13,
    TOKEN_MACRO_R13B,
    TOKEN_MACRO_R13D,
    TOKEN_MACRO_R13W,
    TOKEN_MACRO_R14,
    TOKEN_MACRO_R14B,
    TOKEN_MACRO_R14D,
    TOKEN_MACRO_R14W,
    TOKEN_MACRO_R15,
    TOKEN_MACRO_R15B,
    TOKEN_MACRO_R15D,
    TOKEN_MACRO_R15W,
    TOKEN_MACRO_R8,
    TOKEN_MACRO_R8B,
    TOKEN_MACRO_R8D,
    TOKEN_MACRO_R8W,
    TOKEN_MACRO_R9,
    TOKEN_MACRO_R9B,
    TOKEN_MACRO_R9D,
    TOKEN_MACRO_R9W,
    TOKEN_MACRO_RAX,
    TOKEN_MACRO_RBP,
    TOKEN_MACRO_RBX,
    TOKEN_MACRO_RCX,
    TOKEN_MACRO_RDI,
    TOKEN_MACRO_RDX,
    TOKEN_MACRO_READ,
    TOKEN_MACRO_REG,
    TOKEN_MACRO_RFLAGS,
    TOKEN_MACRO_RIP,
    TOKEN_MACRO_RSI,
    TOKEN_MACRO_RSP,
    TOKEN_MACRO_RW,
    TOKEN_MACRO_SI,
    TOKEN_MACRO_SIL,
    TOKEN_MACRO_SP,
    TOKEN_MACRO_SPL,
    TOKEN_MACRO_TRUE,
    TOKEN_MACRO_WRITE,

    TOKEN_ACCESS = 4000,
    TOKEN_ADDR,
    TOKEN_AFTER,
    TOKEN_AH,
    TOKEN_AL,
    TOKEN_AND,
    TOKEN_ASM,
    TOKEN_AX,
    TOKEN_BASE,
    TOKEN_BEFORE,
    TOKEN_BH,
    TOKEN_BL,
    TOKEN_BP,
    TOKEN_BPL,
    TOKEN_BX,
    TOKEN_CALL,
    TOKEN_CH,
    TOKEN_CL,
    TOKEN_CLEAN,
    TOKEN_CONDITIONAL,
    TOKEN_CX,
    TOKEN_DH,
    TOKEN_DI,
    TOKEN_DIL,
    TOKEN_DISPL,
    TOKEN_DL,
    TOKEN_DST,
    TOKEN_DX,
    TOKEN_EAX,
    TOKEN_EBP,
    TOKEN_EBX,
    TOKEN_ECX,
    TOKEN_EDI,
    TOKEN_EDX,
    TOKEN_ESI,
    TOKEN_ESP,
    TOKEN_FALSE,
    TOKEN_GEQ,
    TOKEN_IMM,
    TOKEN_INDEX,
    TOKEN_INSTR,
    TOKEN_JUMP,
    TOKEN_LENGTH,
    TOKEN_LEQ,
    TOKEN_MEM,
    TOKEN_MNEMONIC,
    TOKEN_NAKED,
    TOKEN_NEQ,
    TOKEN_NEXT,
    TOKEN_NOT,
    TOKEN_OFFSET,
    TOKEN_OP,
    TOKEN_OR,
    TOKEN_PASSTHRU,
    TOKEN_PLUGIN,
    TOKEN_PRINT,
    TOKEN_R10,
    TOKEN_R10B,
    TOKEN_R10D,
    TOKEN_R10W,
    TOKEN_R11,
    TOKEN_R11B,
    TOKEN_R11D,
    TOKEN_R11W,
    TOKEN_R12,
    TOKEN_R12B,
    TOKEN_R12D,
    TOKEN_R12W,
    TOKEN_R13,
    TOKEN_R13B,
    TOKEN_R13D,
    TOKEN_R13W,
    TOKEN_R14,
    TOKEN_R14B,
    TOKEN_R14D,
    TOKEN_R14W,
    TOKEN_R15,
    TOKEN_R15B,
    TOKEN_R15D,
    TOKEN_R15W,
    TOKEN_R8,
    TOKEN_R8B,
    TOKEN_R8D,
    TOKEN_R8W,
    TOKEN_R9,
    TOKEN_R9B,
    TOKEN_R9D,
    TOKEN_R9W,
    TOKEN_RANDOM,
    TOKEN_RAX,
    TOKEN_RBP,
    TOKEN_RBX,
    TOKEN_RCX,
    TOKEN_RDI,
    TOKEN_RDX,
    TOKEN_READ,             // TODO: remove
    TOKEN_REG,
    TOKEN_REPLACE,
    TOKEN_RETURN,
    TOKEN_RFLAGS,
    TOKEN_RIP,
    TOKEN_RSI,
    TOKEN_RSP,
    TOKEN_SCALE,
    TOKEN_SI,
    TOKEN_SIL,
    TOKEN_SIZE,
    TOKEN_SP,
    TOKEN_SPL,
    TOKEN_SRC,
    TOKEN_STATIC_ADDR,
    TOKEN_TARGET,
    TOKEN_TRAMPOLINE,
    TOKEN_TRAP,
    TOKEN_TRUE,
    TOKEN_TYPE,
    TOKEN_WRITE             // TODO: remove
};

/*
 * Token info.
 */
struct TokenInfo
{
    const char *name;
    Token token;
};

/*
 * Macro info.
 */
struct MacroInfo
{
    Token token;
    intptr_t value;
};

/*
 * All tokens.
 */
static const TokenInfo tokens[] =
{
    {"!",           (Token)'!'},
    {"!=",          TOKEN_NEQ},
    {"&",           (Token)'&'},
    {"&&",          TOKEN_AND},
    {"(",           (Token)'('},
    {")",           (Token)')'},
    {",",           (Token)','},
    {".",           (Token)'.'},
    {"<",           (Token)'<'},
    {"<=",          TOKEN_LEQ},
    {"=",           (Token)'='},
    {"==",          (Token)'='},
    {">",           (Token)'>'},
    {">=",          TOKEN_GEQ},
    {"@",           (Token)'@'},
    {"AH",          TOKEN_MACRO_AH},
    {"AL",          TOKEN_MACRO_AL},
    {"AX",          TOKEN_MACRO_AX},
    {"BH",          TOKEN_MACRO_BH},
    {"BL",          TOKEN_MACRO_BL},
    {"BP",          TOKEN_MACRO_BP},
    {"BPL",         TOKEN_MACRO_BPL},
    {"BX",          TOKEN_MACRO_BX},
    {"CH",          TOKEN_MACRO_CH},
    {"CL",          TOKEN_MACRO_CL},
    {"CX",          TOKEN_MACRO_CX},
    {"DH",          TOKEN_MACRO_DH},
    {"DI",          TOKEN_MACRO_DI},
    {"DIL",         TOKEN_MACRO_DIL},
    {"DL",          TOKEN_MACRO_DL},
    {"DX",          TOKEN_MACRO_DX},
    {"EAX",         TOKEN_MACRO_EAX},
    {"EBP",         TOKEN_MACRO_EBP},
    {"EBX",         TOKEN_MACRO_EBX},
    {"ECX",         TOKEN_MACRO_ECX},
    {"EDI",         TOKEN_MACRO_EDI},
    {"EDX",         TOKEN_MACRO_EDX},
    {"ESI",         TOKEN_MACRO_ESI},
    {"ESP",         TOKEN_MACRO_ESP},
    {"FALSE",       TOKEN_MACRO_FALSE},
    {"IMM",         TOKEN_MACRO_IMM},
    {"MEM",         TOKEN_MACRO_MEM},
    {"NIL",         TOKEN_MACRO_NIL},
    {"R10",         TOKEN_MACRO_R10},
    {"R10B",        TOKEN_MACRO_R10B},
    {"R10D",        TOKEN_MACRO_R10D},
    {"R10W",        TOKEN_MACRO_R10W},
    {"R11",         TOKEN_MACRO_R11},
    {"R11B",        TOKEN_MACRO_R11B},
    {"R11D",        TOKEN_MACRO_R11D},
    {"R11W",        TOKEN_MACRO_R11W},
    {"R12",         TOKEN_MACRO_R12},
    {"R12B",        TOKEN_MACRO_R12B},
    {"R12D",        TOKEN_MACRO_R12D},
    {"R12W",        TOKEN_MACRO_R12W},
    {"R13",         TOKEN_MACRO_R13},
    {"R13B",        TOKEN_MACRO_R13B},
    {"R13D",        TOKEN_MACRO_R13D},
    {"R13W",        TOKEN_MACRO_R13W},
    {"R14",         TOKEN_MACRO_R14},
    {"R14B",        TOKEN_MACRO_R14B},
    {"R14D",        TOKEN_MACRO_R14D},
    {"R14W",        TOKEN_MACRO_R14W},
    {"R15",         TOKEN_MACRO_R15},
    {"R15B",        TOKEN_MACRO_R15B},
    {"R15D",        TOKEN_MACRO_R15D},
    {"R15W",        TOKEN_MACRO_R15W},
    {"R8",          TOKEN_MACRO_R8},
    {"R8B",         TOKEN_MACRO_R8B},
    {"R8D",         TOKEN_MACRO_R8D},
    {"R8W",         TOKEN_MACRO_R8W},
    {"R9",          TOKEN_MACRO_R9},
    {"R9B",         TOKEN_MACRO_R8B},
    {"R9D",         TOKEN_MACRO_R8D},
    {"R9W",         TOKEN_MACRO_R8W},
    {"RAX",         TOKEN_MACRO_RAX},
    {"RBP",         TOKEN_MACRO_RBP},
    {"RBX",         TOKEN_MACRO_RBX},
    {"RCX",         TOKEN_MACRO_RCX},
    {"RDI",         TOKEN_MACRO_RDI},
    {"RDX",         TOKEN_MACRO_RDX},
    {"READ",        TOKEN_MACRO_READ},
    {"REG",         TOKEN_MACRO_REG},
    {"RFLAGS",      TOKEN_MACRO_RFLAGS},
    {"RIP",         TOKEN_MACRO_RIP},
    {"RSI",         TOKEN_MACRO_RSI},
    {"RSP",         TOKEN_MACRO_RSP},
    {"RW",          TOKEN_MACRO_RW},
    {"SI",          TOKEN_MACRO_SI},
    {"SIL",         TOKEN_MACRO_SIL},
    {"SP",          TOKEN_MACRO_SP},
    {"SPL",         TOKEN_MACRO_SPL},
    {"TRUE",        TOKEN_MACRO_TRUE},
    {"WRITE",       TOKEN_MACRO_WRITE},
    {"[",           (Token)'['},
    {"]",           (Token)']'},
    {"access",      TOKEN_ACCESS},
    {"addr",        TOKEN_ADDR},
    {"address",     TOKEN_ADDR},
    {"after",       TOKEN_AFTER},
    {"ah",          TOKEN_AH},
    {"al",          TOKEN_AL},
    {"and",         TOKEN_AND},
    {"asm",         TOKEN_ASM},
    {"ax",          TOKEN_AX},
    {"base",        TOKEN_BASE},
    {"before",      TOKEN_BEFORE},
    {"bh",          TOKEN_BH},
    {"bl",          TOKEN_BL},
    {"bp",          TOKEN_BP},
    {"bpl",         TOKEN_BPL},
    {"bx",          TOKEN_BX},
    {"call",        TOKEN_CALL},
    {"ch",          TOKEN_CH},
    {"cl",          TOKEN_CL},
    {"clean",       TOKEN_CLEAN},
    {"conditional", TOKEN_CONDITIONAL},
    {"cx",          TOKEN_CX},
    {"dh",          TOKEN_DH},
    {"di",          TOKEN_DI},
    {"dil",         TOKEN_DIL},
    {"displ",       TOKEN_DISPL},
    {"dl",          TOKEN_DL},
    {"dst",         TOKEN_DST},
    {"dx",          TOKEN_DX},
    {"eax",         TOKEN_EAX},
    {"ebp",         TOKEN_EBP},
    {"ebx",         TOKEN_EBX},
    {"ecx",         TOKEN_ECX},
    {"edi",         TOKEN_EDI},
    {"edx",         TOKEN_EDX},
    {"esi",         TOKEN_ESI},
    {"esp",         TOKEN_ESP},
    {"false",       TOKEN_FALSE},
    {"imm",         TOKEN_IMM},
    {"index",       TOKEN_INDEX},
    {"instr",       TOKEN_INSTR},
    {"jump",        TOKEN_JUMP},
    {"len",         TOKEN_LENGTH},
    {"length",      TOKEN_LENGTH},
    {"mem",         TOKEN_MEM},
    {"mnemonic",    TOKEN_MNEMONIC},
    {"naked",       TOKEN_NAKED},
    {"next",        TOKEN_NEXT},
    {"not",         TOKEN_NOT},
    {"offset",      TOKEN_OFFSET},
    {"op",          TOKEN_OP},
    {"or",          TOKEN_OR},
    {"passthru",    TOKEN_PASSTHRU},
    {"plugin",      TOKEN_PLUGIN},
    {"print",       TOKEN_PRINT},
    {"r10",         TOKEN_R10},
    {"r10b",        TOKEN_R10B},
    {"r10d",        TOKEN_R10D},
    {"r10w",        TOKEN_R10W},
    {"r11",         TOKEN_R11},
    {"r11b",        TOKEN_R11B},
    {"r11d",        TOKEN_R11D},
    {"r11w",        TOKEN_R11W},
    {"r12",         TOKEN_R12},
    {"r12b",        TOKEN_R12B},
    {"r12d",        TOKEN_R12D},
    {"r12w",        TOKEN_R12W},
    {"r13",         TOKEN_R13},
    {"r13b",        TOKEN_R13B},
    {"r13d",        TOKEN_R13D},
    {"r13w",        TOKEN_R13W},
    {"r14",         TOKEN_R14},
    {"r14b",        TOKEN_R14B},
    {"r14d",        TOKEN_R14D},
    {"r14w",        TOKEN_R14W},
    {"r15",         TOKEN_R15},
    {"r15b",        TOKEN_R15B},
    {"r15d",        TOKEN_R15D},
    {"r15w",        TOKEN_R15W},
    {"r8",          TOKEN_R8},
    {"r8b",         TOKEN_R8B},
    {"r8d",         TOKEN_R8D},
    {"r8w",         TOKEN_R8W},
    {"r9",          TOKEN_R9},
    {"r9b",         TOKEN_R9B},
    {"r9d",         TOKEN_R9D},
    {"r9w",         TOKEN_R9W},
    {"random",      TOKEN_RANDOM},
    {"rax",         TOKEN_RAX},
    {"rbp",         TOKEN_RBP},
    {"rbx",         TOKEN_RBX},
    {"rcx",         TOKEN_RCX},
    {"rdi",         TOKEN_RDI},
    {"rdx",         TOKEN_RDX},
    {"read",        TOKEN_READ},
    {"reg",         TOKEN_REG},
    {"replace",     TOKEN_REPLACE},
    {"return",      TOKEN_RETURN},
    {"rflags",      TOKEN_RFLAGS},
    {"rip",         TOKEN_RIP},
    {"rsi",         TOKEN_RSI},
    {"rsp",         TOKEN_RSP},
    {"scale",       TOKEN_SCALE},
    {"si",          TOKEN_SI},
    {"sil",         TOKEN_SIL},
    {"size",        TOKEN_SIZE},
    {"sp",          TOKEN_SP},
    {"spl",         TOKEN_SPL},
    {"src",         TOKEN_SRC},
    {"staticAddr",  TOKEN_STATIC_ADDR},
    {"target",      TOKEN_TARGET},
    {"trampoline",  TOKEN_TRAMPOLINE},
    {"trap",        TOKEN_TRAP},
    {"true",        TOKEN_TRUE},
    {"type",        TOKEN_TYPE},
    {"write",       TOKEN_WRITE},
    {"||",          TOKEN_OR},
};

static const MacroInfo macros[] =
{
    {TOKEN_MACRO_AH,     REG_NAME_AH},      
    {TOKEN_MACRO_AL,     REG_NAME_AL},
    {TOKEN_MACRO_AX,     REG_NAME_AX},
    {TOKEN_MACRO_BH,     REG_NAME_BH},
    {TOKEN_MACRO_BL,     REG_NAME_BL},
    {TOKEN_MACRO_BP,     REG_NAME_BP},
    {TOKEN_MACRO_BPL,    REG_NAME_BPL},
    {TOKEN_MACRO_BX,     REG_NAME_BX},
    {TOKEN_MACRO_CH,     REG_NAME_CH},
    {TOKEN_MACRO_CL,     REG_NAME_CL},
    {TOKEN_MACRO_CX,     REG_NAME_CX},
    {TOKEN_MACRO_DH,     REG_NAME_DH},
    {TOKEN_MACRO_DI,     REG_NAME_DI},
    {TOKEN_MACRO_DIL,    REG_NAME_DIL},
    {TOKEN_MACRO_DL,     REG_NAME_DL},
    {TOKEN_MACRO_DX,     REG_NAME_DX},
    {TOKEN_MACRO_EAX,    REG_NAME_EAX},
    {TOKEN_MACRO_EBP,    REG_NAME_EBP},
    {TOKEN_MACRO_EBX,    REG_NAME_EBX},
    {TOKEN_MACRO_ECX,    REG_NAME_ECX},
    {TOKEN_MACRO_EDI,    REG_NAME_EDI},
    {TOKEN_MACRO_EDX,    REG_NAME_EDX},
    {TOKEN_MACRO_ESI,    REG_NAME_ESI},
    {TOKEN_MACRO_ESP,    REG_NAME_ESP},
    {TOKEN_MACRO_FALSE,  false},
    {TOKEN_MACRO_IMM,    OP_TYPE_IMM},
    {TOKEN_MACRO_MEM,    OP_TYPE_MEM},
    {TOKEN_MACRO_NIL,    0},
    {TOKEN_MACRO_R10,    REG_NAME_R10},
    {TOKEN_MACRO_R10B,   REG_NAME_R10B},
    {TOKEN_MACRO_R10D,   REG_NAME_R10D},
    {TOKEN_MACRO_R10W,   REG_NAME_R10W},
    {TOKEN_MACRO_R11,    REG_NAME_R11},
    {TOKEN_MACRO_R11B,   REG_NAME_R11B},
    {TOKEN_MACRO_R11D,   REG_NAME_R11D},
    {TOKEN_MACRO_R11W,   REG_NAME_R11W},
    {TOKEN_MACRO_R12,    REG_NAME_R12},
    {TOKEN_MACRO_R12B,   REG_NAME_R12B},
    {TOKEN_MACRO_R12D,   REG_NAME_R12D},
    {TOKEN_MACRO_R12W,   REG_NAME_R12W},
    {TOKEN_MACRO_R13,    REG_NAME_R13},
    {TOKEN_MACRO_R13B,   REG_NAME_R13B},
    {TOKEN_MACRO_R13D,   REG_NAME_R13D},
    {TOKEN_MACRO_R13W,   REG_NAME_R13W},
    {TOKEN_MACRO_R14,    REG_NAME_R14},
    {TOKEN_MACRO_R14B,   REG_NAME_R14B},
    {TOKEN_MACRO_R14D,   REG_NAME_R14D},
    {TOKEN_MACRO_R14W,   REG_NAME_R14W},
    {TOKEN_MACRO_R15,    REG_NAME_R15},
    {TOKEN_MACRO_R15B,   REG_NAME_R15B},
    {TOKEN_MACRO_R15D,   REG_NAME_R15D},
    {TOKEN_MACRO_R15W,   REG_NAME_R15W},
    {TOKEN_MACRO_R8,     REG_NAME_R8},
    {TOKEN_MACRO_R8B,    REG_NAME_R8B},
    {TOKEN_MACRO_R8D,    REG_NAME_R8D},
    {TOKEN_MACRO_R8W,    REG_NAME_R8W},
    {TOKEN_MACRO_R9,     REG_NAME_R9},
    {TOKEN_MACRO_R9B,    REG_NAME_R9B},
    {TOKEN_MACRO_R9D,    REG_NAME_R9D},
    {TOKEN_MACRO_R9W,    REG_NAME_R9W},
    {TOKEN_MACRO_RAX,    REG_NAME_RAX},
    {TOKEN_MACRO_RBP,    REG_NAME_RBP},
    {TOKEN_MACRO_RBX,    REG_NAME_RBX},
    {TOKEN_MACRO_RCX,    REG_NAME_RCX},
    {TOKEN_MACRO_RDI,    REG_NAME_RDI},
    {TOKEN_MACRO_RDX,    REG_NAME_RDX},
    {TOKEN_MACRO_READ,   ACCESS_READ},
    {TOKEN_MACRO_REG,    OP_TYPE_REG},
    {TOKEN_MACRO_RFLAGS, REG_NAME_RFLAGS},
    {TOKEN_MACRO_RIP,    REG_NAME_RIP},
    {TOKEN_MACRO_RSI,    REG_NAME_RSI},
    {TOKEN_MACRO_RSP,    REG_NAME_RSP},
    {TOKEN_MACRO_RW,     ACCESS_READ | ACCESS_WRITE},
    {TOKEN_MACRO_SI,     REG_NAME_SI},
    {TOKEN_MACRO_SIL,    REG_NAME_SIL},
    {TOKEN_MACRO_SP,     REG_NAME_SP},
    {TOKEN_MACRO_SPL,    REG_NAME_SPL},
    {TOKEN_MACRO_TRUE,   true},
    {TOKEN_MACRO_WRITE,  ACCESS_WRITE},
};

/*
 * Compare token infos.
 */
static int compareName(const void *ptr1, const void *ptr2)
{
    const TokenInfo *info1 = (const TokenInfo *)ptr1;
    const TokenInfo *info2 = (const TokenInfo *)ptr2;
    return strcmp(info1->name, info2->name);
}

/*
 * Compare macro infos.
 */
static int compareMacro(const void *ptr1, const void *ptr2)
{
    const MacroInfo *info1 = (const MacroInfo *)ptr1;
    const MacroInfo *info2 = (const MacroInfo *)ptr2;
    return (int)info1->token - (int)info2->token;
}

/*
 * Get a token from a name.
 */
static Token getTokenFromName(const char *name)
{
    TokenInfo key = {name, TOKEN_ERROR};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens,
        sizeof(tokens) / sizeof(tokens[0]), sizeof(tokens[0]), compareName);
    if (entry == nullptr)
        return TOKEN_ERROR;
    return entry->token;
}

/*
 * Expands a macro value.
 */
static intptr_t expandMacro(Token t)
{
    MacroInfo key = {t, 0};
    const MacroInfo *entry = (const MacroInfo *)bsearch(&key, macros,
        sizeof(macros) / sizeof(macros[0]), sizeof(macros[0]), compareMacro);
    if (entry == nullptr)
        return -1;
    return entry->value;
}

/*
 * Get the name of a token.
 */
static const char *getNameFromToken(Token token)
{
    // Special tokens:
    switch ((int)token)
    {
        case TOKEN_NOT:
            return "not";
        case TOKEN_AND:
            return "and";
        case TOKEN_OR:
            return "or";
        case TOKEN_ERROR:
            return "<bad-token>";
        case TOKEN_END:
            return "<end-of-input>";
        case TOKEN_INTEGER:
            return "<integer>";
        case TOKEN_STRING:
            return "<string>";
        case TOKEN_REGEX:
            return "<regex>";
        default:
            break;
    }
    const TokenInfo *entry = nullptr;
    for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++)
    {
        if (tokens[i].token == token)
        {
            entry = tokens + i;
            break;
        }
    }
    if (entry == nullptr)
        return "???";
    return entry->name;
}

/*
 * Action string parser.
 */
struct Parser
{
    static const unsigned TOKEN_MAXLEN = 2048;

    const char * const mode;
    const char * const buf;
    size_t pos  = 0;
    size_t prev = 0;
    int peek    = TOKEN_ERROR;
    intptr_t i  = 0;
    char s[TOKEN_MAXLEN+1];

    Parser(const char *buf, const char *mode) : buf(buf), mode(mode)
    {
        ;
    }

    int getToken()
    {
        prev = pos;
        if (peek != TOKEN_ERROR)
        {
            int t = peek;
            peek = TOKEN_ERROR;
            return t;
        }
        char c = buf[pos];
        while (isspace(c))
            c = buf[++pos];
        
        // Operators:
        switch (c)
        {
            case '\0':
                strcpy(s, "<end-of-input>");
                return TOKEN_END;
            case '[': case ']': case '@': case ',': case '(': case ')':
            case '&': case '.':
                s[0] = c; s[1] = '\0';
                pos++;
                if (c == '&' && buf[pos] == '&')
                {
                    s[1] = '&'; s[2] = '\0';
                    pos++;
                }
                return getTokenFromName(s);
            case '!': case '<': case '>': case '=':
                s[0] = c; s[1] = '\0';
                pos++;
                if (buf[pos] == '=')
                {
                    s[1] = '='; s[2] = '\0';
                    pos++;
                }
                return getTokenFromName(s);
            case '|':
                if (buf[pos+1] == '|')
                {
                    s[0] = s[1] = '|'; s[2] = '\0';
                    pos += 2;
                    return TOKEN_OR;
                }
                // Fallthrough:
            default:
                break;
        }
        
        // Integers:
        unsigned j = 0;
        if (isdigit(c) || c == '-' || c == '+')
        {
            bool neg = false;
            switch (c)
            {
                case '-':
                    neg = true;
                    // Fallthrough:
                case '+':
                    s[j++] = c;
                    c = buf[++pos];
                    break;
                default:
                    break;
            }
            int base = 10;
            if (c == '0' && buf[pos+1] == 'x')
            {
                base = 16;
                s[j++] = buf[pos++]; s[j++] = buf[pos++];
                c = buf[pos];
            }
            if (!(base == 10? isdigit(c): isxdigit(c)))
            {
                s[j++] = '\0';
                return TOKEN_ERROR;
            }
            s[j++] = c;
            pos++;
            while ((base == 10? isdigit(buf[pos]): isxdigit(buf[pos])) &&
                    j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            char *end = nullptr;
            i = (intptr_t)strtoull((neg? s+1: s), &end, base);
            if (end == nullptr || *end != '\0')
                return TOKEN_ERROR;
            i = (neg? -i: i);
            return TOKEN_INTEGER;
        }

        // Strings:
        if (c == '\"')
        {
            pos++;
            while ((c = buf[pos++]) != '\"')
            {
                if (c == '\\')
                {
                    c = buf[pos++];
                    switch (c)
                    {
                        case 'n':
                            c = '\n'; break;
                        case 't':
                            c = '\t'; break;
                        case 'r':
                            c = '\r'; break;
                        default:
                            break;
                    }
                }
                if (j >= TOKEN_MAXLEN-1)
                {
                    s[j] = '\0';
                    return TOKEN_ERROR;
                }
                s[j++] = c;
            }
            s[j] = '\0';
            return TOKEN_STRING;
        }

        // Names:
        if (isalpha(c) || c == '_')
        {
            s[j++] = c;
            pos++;
            while ((isalnum(buf[pos]) || buf[pos] == '_') && j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            Token t = getTokenFromName(s);
            if (t == TOKEN_ERROR)
                return TOKEN_STRING;
            i = expandMacro(t);
            return (i >= 0? TOKEN_INTEGER: t);
        }

        // Unknown:
        s[0] = c; s[1] = '\0';
        return TOKEN_ERROR;
    }

    int peekToken()
    {
        if (peek != TOKEN_ERROR)
            return peek;
        peek = getToken();
        return peek;
    }

    void getPositionStr(std::string &str)
    {
        for (size_t i = 0; i < prev; i++)
            str += buf[i];
        str += " <--- here";
    }

    void expectToken(int token)
    {
        if (getToken() != token)
        {
            std::string str;
            getPositionStr(str);
            error("failed to parse %s at position \"%s\"; expected token "
                "\"%s\", found \"%s\"", mode, str.c_str(),
                getNameFromToken((Token)token), s);
        }
    }

    void unexpectedToken()
    {
        std::string str;
        getPositionStr(str);
        error("failed to parse %s at position \"%s\"; unexpected token \"%s\"",
            mode, str.c_str(), s);
    }

    const char *getName(int token)
    {
        return getNameFromToken((Token)token);
    }

    int getRegex()
    {
        if (peek != TOKEN_ERROR)
            unexpectedToken();
        while (isspace(buf[pos]))
            pos++;
        if (buf[pos] == '\"')
            return getToken();
        unsigned j;
        for (j = 0; j < TOKEN_MAXLEN && buf[pos] != '\0'; j++)
        {
            if (isspace(buf[pos]))
                break;
            if (buf[pos] == '\\' && isspace(buf[pos+1]))
            {
                s[j] = buf[pos+1];
                pos += 2;
                continue;
            }
            s[j] = buf[pos++];
        }
        if (j >= TOKEN_MAXLEN)
            unexpectedToken();
        s[j] = '\0';
        return TOKEN_REGEX;
    }
};

