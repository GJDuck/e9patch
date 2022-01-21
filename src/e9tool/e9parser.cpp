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

#include "e9parser.h"
#include "e9tool.h"

using namespace e9tool;

/*
 * Token info.
 */
struct TokenInfo
{
    const char *name;
    Token token;
    intptr_t value;
};

/*
 * All tokens.
 */
static const TokenInfo tokens[] =
{
    {"!",               (Token)'!',             0},
    {"!=",              TOKEN_NEQ,              0},
    {"&",               (Token)'&',             0},
    {"&&",              TOKEN_AND,              0},
    {"(",               (Token)'(',             0},
    {")",               (Token)')',             0},
    {"+",               (Token)'+',             0},
    {",",               (Token)',',             0},
    {"-",               (Token)'-',             0},
    {"--",              TOKEN_NONE,             (Access)0x0},
    {"-w",              TOKEN_WRITE,            ACCESS_WRITE},
    {".",               (Token)'.',             0},
    {"..",              TOKEN_DOTDOT,           0},
    {":",               (Token)':',             0},
    {"<",               (Token)'<',             0},
    {"<=",              TOKEN_LEQ,              0},
    {"=",               (Token)'=',             0},
    {"==",              (Token)'=',             0},
    {">",               (Token)'>',             0},
    {">=",              TOKEN_GEQ,              0},
    {"@",               (Token)'@',             0},
    {"BB",              TOKEN_BB,               0},
    {"F",               TOKEN_F,                0},
    {"I",               TOKEN_I,                0},
    {"[",               (Token)'[',             0},
    {"]",               (Token)']',             0},
    {"_",               TOKEN_NIL,              0x0},
    {"acc",             TOKEN_ACCESS,           0},
    {"access",          TOKEN_ACCESS,           0},
    {"addr",            TOKEN_ADDR,             0},
    {"address",         TOKEN_ADDR,             0},
    {"after",           TOKEN_AFTER,            0},
    {"ah",              TOKEN_REGISTER,         REGISTER_AH},
    {"al",              TOKEN_REGISTER,         REGISTER_AL},
    {"and",             TOKEN_AND,              0},
    {"asm",             TOKEN_ASM,              0},
    {"avx",             TOKEN_AVX,              0},
    {"avx2",            TOKEN_AVX2,             0},
    {"avx512",          TOKEN_AVX512,           0},
    {"ax",              TOKEN_REGISTER,         REGISTER_AX},
    {"base",            TOKEN_BASE,             0},
    {"before",          TOKEN_BEFORE,           0},
    {"best",            TOKEN_BEST,             0},
    {"bh",              TOKEN_REGISTER,         REGISTER_BH},
    {"bl",              TOKEN_REGISTER,         REGISTER_BL},
    {"bp",              TOKEN_REGISTER,         REGISTER_BP},
    {"bpl",             TOKEN_REGISTER,         REGISTER_BPL},
    {"break",           TOKEN_BREAK,            0},
    {"bx",              TOKEN_REGISTER,         REGISTER_BX},
    {"call",            TOKEN_CALL,             0},
    {"ch",              TOKEN_REGISTER,         REGISTER_CH},
    {"cl",              TOKEN_REGISTER,         REGISTER_CL},
    {"clean",           TOKEN_CLEAN,            0},
    {"condjump",        TOKEN_CONDJUMP,         0},
    {"config",          TOKEN_CONFIG,           0},
    {"cs",              TOKEN_REGISTER,         REGISTER_CS},
    {"cx",              TOKEN_REGISTER,         REGISTER_CX},
    {"defined",         TOKEN_DEFINED,          0},
    {"dh",              TOKEN_REGISTER,         REGISTER_DH},
    {"di",              TOKEN_REGISTER,         REGISTER_DI},
    {"dil",             TOKEN_REGISTER,         REGISTER_DIL},
    {"disp",            TOKEN_DISPLACEMENT,     0},
    {"displacement",    TOKEN_DISPLACEMENT,     0},
    {"dl",              TOKEN_REGISTER,         REGISTER_DL},
    {"ds",              TOKEN_REGISTER,         REGISTER_DS},
    {"dst",             TOKEN_DST,              0},
    {"dx",              TOKEN_REGISTER,         REGISTER_DX},
    {"eax",             TOKEN_REGISTER,         REGISTER_EAX},
    {"ebp",             TOKEN_REGISTER,         REGISTER_EBP},
    {"ebx",             TOKEN_REGISTER,         REGISTER_EBX},
    {"ecx",             TOKEN_REGISTER,         REGISTER_ECX},
    {"edi",             TOKEN_REGISTER,         REGISTER_EDI},
    {"edx",             TOKEN_REGISTER,         REGISTER_EDX},
    {"empty",           TOKEN_EMPTY,            0},
    {"end",             TOKEN_END,              0},
    {"entry",           TOKEN_ENTRY,            0},
    {"es",              TOKEN_REGISTER,         REGISTER_ES},
    {"esi",             TOKEN_REGISTER,         REGISTER_ESI},
    {"esp",             TOKEN_REGISTER,         REGISTER_ESP},
    {"exit",            TOKEN_EXIT,             0},
    {"false",           TOKEN_FALSE,            false},
    {"fs",              TOKEN_REGISTER,         REGISTER_FS},
    {"goto",            TOKEN_GOTO,             0},
    {"gs",              TOKEN_REGISTER,         REGISTER_GS},
    {"id",              TOKEN_ID,               0},
    {"if",              TOKEN_IF,               0},
    {"imm",             TOKEN_IMM,              OPTYPE_IMM},
    {"in",              TOKEN_IN,               0},
    {"index",           TOKEN_INDEX,            0},
    {"instr",           TOKEN_INSTR,            0},
    {"jump",            TOKEN_JUMP,             0},
    {"len",             TOKEN_LENGTH,           0},
    {"length",          TOKEN_LENGTH,           0},
    {"match",           TOKEN_MATCH,            0},
    {"mem",             TOKEN_MEM,              OPTYPE_MEM},
    {"mem16",           TOKEN_MEM16,            0},
    {"mem32",           TOKEN_MEM32,            0},
    {"mem64",           TOKEN_MEM64,            0},
    {"mem8",            TOKEN_MEM8,             0},
    {"mmx",             TOKEN_MMX,              0},
    {"mnemonic",        TOKEN_MNEMONIC,         0},
    {"naked",           TOKEN_NAKED,            0},
    {"name",            TOKEN_NAME_2,           0},
    {"next",            TOKEN_NEXT,             0},
    {"nil",             TOKEN_NIL,              0x0},
    {"not",             TOKEN_NOT,              0},
    {"offset",          TOKEN_OFFSET,           0},
    {"op",              TOKEN_OP,               0},
    {"or",              TOKEN_OR,               0},
    {"passthru",        TOKEN_PASSTHRU,         0},
    {"patch",           TOKEN_PATCH,            0},
    {"plugin",          TOKEN_PLUGIN,           0},
    {"print",           TOKEN_PRINT,            0},
    {"r",               TOKEN_READ,             ACCESS_READ},
    {"r-",              TOKEN_READ,             ACCESS_READ},
    {"r10",             TOKEN_REGISTER,         REGISTER_R10},
    {"r10b",            TOKEN_REGISTER,         REGISTER_R10B},
    {"r10d",            TOKEN_REGISTER,         REGISTER_R10D},
    {"r10w",            TOKEN_REGISTER,         REGISTER_R10W},
    {"r11",             TOKEN_REGISTER,         REGISTER_R11},
    {"r11b",            TOKEN_REGISTER,         REGISTER_R11B},
    {"r11d",            TOKEN_REGISTER,         REGISTER_R11D},
    {"r11w",            TOKEN_REGISTER,         REGISTER_R11W},
    {"r12",             TOKEN_REGISTER,         REGISTER_R12},
    {"r12b",            TOKEN_REGISTER,         REGISTER_R12B},
    {"r12d",            TOKEN_REGISTER,         REGISTER_R12D},
    {"r12w",            TOKEN_REGISTER,         REGISTER_R12W},
    {"r13",             TOKEN_REGISTER,         REGISTER_R13},
    {"r13b",            TOKEN_REGISTER,         REGISTER_R13B},
    {"r13d",            TOKEN_REGISTER,         REGISTER_R13D},
    {"r13w",            TOKEN_REGISTER,         REGISTER_R13W},
    {"r14",             TOKEN_REGISTER,         REGISTER_R14},
    {"r14b",            TOKEN_REGISTER,         REGISTER_R14B},
    {"r14d",            TOKEN_REGISTER,         REGISTER_R14D},
    {"r14w",            TOKEN_REGISTER,         REGISTER_R14W},
    {"r15",             TOKEN_REGISTER,         REGISTER_R15},
    {"r15b",            TOKEN_REGISTER,         REGISTER_R15B},
    {"r15d",            TOKEN_REGISTER,         REGISTER_R15D},
    {"r15w",            TOKEN_REGISTER,         REGISTER_R15W},
    {"r8",              TOKEN_REGISTER,         REGISTER_R8},
    {"r8b",             TOKEN_REGISTER,         REGISTER_R8B},
    {"r8d",             TOKEN_REGISTER,         REGISTER_R8D},
    {"r8w",             TOKEN_REGISTER,         REGISTER_R8W},
    {"r9",              TOKEN_REGISTER,         REGISTER_R9},
    {"r9b",             TOKEN_REGISTER,         REGISTER_R9B},
    {"r9d",             TOKEN_REGISTER,         REGISTER_R9D},
    {"r9w",             TOKEN_REGISTER,         REGISTER_R9W},
    {"random",          TOKEN_RANDOM,           0},
    {"rax",             TOKEN_REGISTER,         REGISTER_RAX},
    {"rbp",             TOKEN_REGISTER,         REGISTER_RBP},
    {"rbx",             TOKEN_REGISTER,         REGISTER_RBX},
    {"rcx",             TOKEN_REGISTER,         REGISTER_RCX},
    {"rdi",             TOKEN_REGISTER,         REGISTER_RDI},
    {"rdx",             TOKEN_REGISTER,         REGISTER_RDX},
    {"read",            TOKEN_READ,             ACCESS_READ},
    {"reads",           TOKEN_READS,            0},
    {"reg",             TOKEN_REG,              OPTYPE_REG},
    {"regs",            TOKEN_REGS,             0},
    {"replace",         TOKEN_REPLACE,          0},
    {"return",          TOKEN_RETURN,           0},
    {"rflags",          TOKEN_REGISTER,         REGISTER_EFLAGS},
    {"rip",             TOKEN_REGISTER,         REGISTER_RIP},
    {"rsi",             TOKEN_REGISTER,         REGISTER_RSI},
    {"rsp",             TOKEN_REGISTER,         REGISTER_RSP},
    {"rw",              TOKEN_RW,               (ACCESS_READ | ACCESS_WRITE)},
    {"scale",           TOKEN_SCALE,            0},
    {"section",         TOKEN_SECTION,          0},
    {"seg",             TOKEN_SEGMENT,          0},
    {"segment",         TOKEN_SEGMENT,          0},
    {"si",              TOKEN_REGISTER,         REGISTER_SI},
    {"sil",             TOKEN_REGISTER,         REGISTER_SIL},
    {"size",            TOKEN_SIZE,             0},
    {"sp",              TOKEN_REGISTER,         REGISTER_SP},
    {"spl",             TOKEN_REGISTER,         REGISTER_SPL},
    {"src",             TOKEN_SRC,              0},
    {"ss",              TOKEN_REGISTER,         REGISTER_SS},
    {"sse",             TOKEN_SSE,              0},
    {"start",           TOKEN_START,            0},
    {"state",           TOKEN_STATE,            0},
    {"static",          TOKEN_STATIC,           0},
    {"target",          TOKEN_TARGET,           0},
    {"trampoline",      TOKEN_TRAMPOLINE,       0},
    {"trap",            TOKEN_TRAP,             0},
    {"true",            TOKEN_TRUE,             true},
    {"type",            TOKEN_TYPE,             0},
    {"w",               TOKEN_WRITE,            ACCESS_WRITE},
    {"write",           TOKEN_WRITE,            ACCESS_WRITE},
    {"writes",          TOKEN_WRITES,           0},
    {"x87",             TOKEN_X87,              0},
    {"xmm0",            TOKEN_REGISTER,         REGISTER_XMM0},
    {"xmm1",            TOKEN_REGISTER,         REGISTER_XMM1},
    {"xmm10",           TOKEN_REGISTER,         REGISTER_XMM10},
    {"xmm11",           TOKEN_REGISTER,         REGISTER_XMM11},
    {"xmm12",           TOKEN_REGISTER,         REGISTER_XMM12},
    {"xmm13",           TOKEN_REGISTER,         REGISTER_XMM13},
    {"xmm14",           TOKEN_REGISTER,         REGISTER_XMM14},
    {"xmm15",           TOKEN_REGISTER,         REGISTER_XMM15},
    {"xmm16",           TOKEN_REGISTER,         REGISTER_XMM16},
    {"xmm17",           TOKEN_REGISTER,         REGISTER_XMM17},
    {"xmm18",           TOKEN_REGISTER,         REGISTER_XMM18},
    {"xmm19",           TOKEN_REGISTER,         REGISTER_XMM19},
    {"xmm2",            TOKEN_REGISTER,         REGISTER_XMM2},
    {"xmm20",           TOKEN_REGISTER,         REGISTER_XMM20},
    {"xmm21",           TOKEN_REGISTER,         REGISTER_XMM21},
    {"xmm22",           TOKEN_REGISTER,         REGISTER_XMM22},
    {"xmm23",           TOKEN_REGISTER,         REGISTER_XMM23},
    {"xmm24",           TOKEN_REGISTER,         REGISTER_XMM24},
    {"xmm25",           TOKEN_REGISTER,         REGISTER_XMM25},
    {"xmm26",           TOKEN_REGISTER,         REGISTER_XMM26},
    {"xmm27",           TOKEN_REGISTER,         REGISTER_XMM27},
    {"xmm28",           TOKEN_REGISTER,         REGISTER_XMM28},
    {"xmm29",           TOKEN_REGISTER,         REGISTER_XMM29},
    {"xmm3",            TOKEN_REGISTER,         REGISTER_XMM3},
    {"xmm30",           TOKEN_REGISTER,         REGISTER_XMM30},
    {"xmm31",           TOKEN_REGISTER,         REGISTER_XMM31},
    {"xmm4",            TOKEN_REGISTER,         REGISTER_XMM4},
    {"xmm5",            TOKEN_REGISTER,         REGISTER_XMM5},
    {"xmm6",            TOKEN_REGISTER,         REGISTER_XMM6},
    {"xmm7",            TOKEN_REGISTER,         REGISTER_XMM7},
    {"xmm8",            TOKEN_REGISTER,         REGISTER_XMM8},
    {"xmm9",            TOKEN_REGISTER,         REGISTER_XMM9},
    {"ymm0",            TOKEN_REGISTER,         REGISTER_YMM0},
    {"ymm1",            TOKEN_REGISTER,         REGISTER_YMM1},
    {"ymm10",           TOKEN_REGISTER,         REGISTER_YMM10},
    {"ymm11",           TOKEN_REGISTER,         REGISTER_YMM11},
    {"ymm12",           TOKEN_REGISTER,         REGISTER_YMM12},
    {"ymm13",           TOKEN_REGISTER,         REGISTER_YMM13},
    {"ymm14",           TOKEN_REGISTER,         REGISTER_YMM14},
    {"ymm15",           TOKEN_REGISTER,         REGISTER_YMM15},
    {"ymm16",           TOKEN_REGISTER,         REGISTER_YMM16},
    {"ymm17",           TOKEN_REGISTER,         REGISTER_YMM17},
    {"ymm18",           TOKEN_REGISTER,         REGISTER_YMM18},
    {"ymm19",           TOKEN_REGISTER,         REGISTER_YMM19},
    {"ymm2",            TOKEN_REGISTER,         REGISTER_YMM2},
    {"ymm20",           TOKEN_REGISTER,         REGISTER_YMM20},
    {"ymm21",           TOKEN_REGISTER,         REGISTER_YMM21},
    {"ymm22",           TOKEN_REGISTER,         REGISTER_YMM22},
    {"ymm23",           TOKEN_REGISTER,         REGISTER_YMM23},
    {"ymm24",           TOKEN_REGISTER,         REGISTER_YMM24},
    {"ymm25",           TOKEN_REGISTER,         REGISTER_YMM25},
    {"ymm26",           TOKEN_REGISTER,         REGISTER_YMM26},
    {"ymm27",           TOKEN_REGISTER,         REGISTER_YMM27},
    {"ymm28",           TOKEN_REGISTER,         REGISTER_YMM28},
    {"ymm29",           TOKEN_REGISTER,         REGISTER_YMM29},
    {"ymm3",            TOKEN_REGISTER,         REGISTER_YMM3},
    {"ymm30",           TOKEN_REGISTER,         REGISTER_YMM30},
    {"ymm31",           TOKEN_REGISTER,         REGISTER_YMM31},
    {"ymm4",            TOKEN_REGISTER,         REGISTER_YMM4},
    {"ymm5",            TOKEN_REGISTER,         REGISTER_YMM5},
    {"ymm6",            TOKEN_REGISTER,         REGISTER_YMM6},
    {"ymm7",            TOKEN_REGISTER,         REGISTER_YMM7},
    {"ymm8",            TOKEN_REGISTER,         REGISTER_YMM8},
    {"ymm9",            TOKEN_REGISTER,         REGISTER_YMM9},
    {"zmm0",            TOKEN_REGISTER,         REGISTER_ZMM0},
    {"zmm1",            TOKEN_REGISTER,         REGISTER_ZMM1},
    {"zmm10",           TOKEN_REGISTER,         REGISTER_ZMM10},
    {"zmm11",           TOKEN_REGISTER,         REGISTER_ZMM11},
    {"zmm12",           TOKEN_REGISTER,         REGISTER_ZMM12},
    {"zmm13",           TOKEN_REGISTER,         REGISTER_ZMM13},
    {"zmm14",           TOKEN_REGISTER,         REGISTER_ZMM14},
    {"zmm15",           TOKEN_REGISTER,         REGISTER_ZMM15},
    {"zmm16",           TOKEN_REGISTER,         REGISTER_ZMM16},
    {"zmm17",           TOKEN_REGISTER,         REGISTER_ZMM17},
    {"zmm18",           TOKEN_REGISTER,         REGISTER_ZMM18},
    {"zmm19",           TOKEN_REGISTER,         REGISTER_ZMM19},
    {"zmm2",            TOKEN_REGISTER,         REGISTER_ZMM2},
    {"zmm20",           TOKEN_REGISTER,         REGISTER_ZMM20},
    {"zmm21",           TOKEN_REGISTER,         REGISTER_ZMM21},
    {"zmm22",           TOKEN_REGISTER,         REGISTER_ZMM22},
    {"zmm23",           TOKEN_REGISTER,         REGISTER_ZMM23},
    {"zmm24",           TOKEN_REGISTER,         REGISTER_ZMM24},
    {"zmm25",           TOKEN_REGISTER,         REGISTER_ZMM25},
    {"zmm26",           TOKEN_REGISTER,         REGISTER_ZMM26},
    {"zmm27",           TOKEN_REGISTER,         REGISTER_ZMM27},
    {"zmm28",           TOKEN_REGISTER,         REGISTER_ZMM28},
    {"zmm29",           TOKEN_REGISTER,         REGISTER_ZMM29},
    {"zmm3",            TOKEN_REGISTER,         REGISTER_ZMM3},
    {"zmm30",           TOKEN_REGISTER,         REGISTER_ZMM30},
    {"zmm31",           TOKEN_REGISTER,         REGISTER_ZMM31},
    {"zmm4",            TOKEN_REGISTER,         REGISTER_ZMM4},
    {"zmm5",            TOKEN_REGISTER,         REGISTER_ZMM5},
    {"zmm6",            TOKEN_REGISTER,         REGISTER_ZMM6},
    {"zmm7",            TOKEN_REGISTER,         REGISTER_ZMM7},
    {"zmm8",            TOKEN_REGISTER,         REGISTER_ZMM8},
    {"zmm9",            TOKEN_REGISTER,         REGISTER_ZMM9},
    {"{",               (Token)'{',             0},
    {"||",              TOKEN_OR,               0},
    {"}",               (Token)'}',             0},
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
 * Get a token info.
 */
static const TokenInfo *getTokenInfo(const char *name)
{
    TokenInfo key = {name, TOKEN_ERROR};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens,
        sizeof(tokens) / sizeof(tokens[0]), sizeof(tokens[0]), compareName);
    return entry;
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
        case TOKEN_EOF:
            return "<end-of-input>";
        case TOKEN_INTEGER:
            return "<integer>";
        case TOKEN_REGISTER:
            return "<register>";
        case TOKEN_STRING:
            return "<string>";
        case TOKEN_NAME:
            return "<name>";
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
 * Get token from name.
 */
Token Parser::getTokenFromName(const char *name)
{
    bool reg = (name[0] == '%');
    if (reg)
        name++;
    const TokenInfo *info = getTokenInfo(name);
    if (info == nullptr)
        return TOKEN_ERROR;
    if (reg && info->token != TOKEN_REGISTER)
        return TOKEN_ERROR;
    i = info->value;
    return info->token;
}

/*
 * Get the next token.
 */
int Parser::getToken()
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
            return TOKEN_EOF;
        case '[': case ']': case '@': case ',': case '(': case ')':
        case '&': case '.': case ':': case '+': case '{': case '}':
            s[0] = c; s[1] = '\0';
            pos++;
            if ((c == '&' || c == '.') && buf[pos] == c)
            {
                s[1] = c; s[2] = '\0';
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
        case '-':
            s[0] = c; s[1] = '\0';
            pos++;
            if (buf[pos] == '-' || buf[pos] == 'w')
            {
                s[1] = buf[pos]; s[2] = '\0';
                pos++;
            }
            return getTokenFromName(s);
        case 'r':
            if (buf[pos+1] == '-')
            {
                s[0] = 'r'; s[1] = '-'; s[2] = '\0';
                pos += 2;
                return getTokenFromName(s);
            }
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
    if (isdigit(c))
    {
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
        i = (intptr_t)strtoull(s, &end, base);
        if (end == nullptr || *end != '\0')
            return TOKEN_ERROR;
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

    // Regexes:
    if (c == '/')
    {
        pos++;
        while ((c = buf[pos++]) != '/')
        {
            if (c == '\\' && buf[pos+1] == '/')
            {
                c = '/';
                pos++;
            }
            if (j >= TOKEN_MAXLEN-1)
            {
                s[j] = '\0';
                return TOKEN_ERROR;
            }
            s[j++] = c;
        }
        s[j] = '\0';
        return TOKEN_REGEX;
    }

    // Names:
    if (isalpha(c) || c == '_' || c == '%')
    {
        s[j++] = c;
        pos++;
        while ((isalnum(buf[pos]) || buf[pos] == '_') &&
                j < TOKEN_MAXLEN)
            s[j++] = buf[pos++];
        s[j] = '\0';
        if (j >= TOKEN_MAXLEN)
            return TOKEN_ERROR;
        Token t = getTokenFromName(s);
        if (t == TOKEN_ERROR)
            return TOKEN_NAME;
        return t;
    }

    // Unknown:
    s[0] = c; s[1] = '\0';
    return TOKEN_ERROR;
}

/*
 * Peek at the next token without consuming it.
 */
int Parser::peekToken()
{
    if (peek != TOKEN_ERROR)
        return peek;
    peek = getToken();
    return peek;
}

/*
 * Position string for error messages.
 */
void Parser::getPositionStr(std::string &str) const
{
    for (size_t i = 0; i < prev; i++)
        str += buf[i];
    str += " <--- here";
}

/*
 * Expect a specific token, else error.
 */
void Parser::expectToken(int token)
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

/*
 * Expect one of two tokens, else error.
 */
int Parser::expectToken2(int token1, int token2)
{
    int t = getToken();
    if (t != token1 && t != token2)
    {
        std::string str;
        getPositionStr(str);
        error("failed to parse %s at position \"%s\"; expected token "
            "\"%s\" or \"%s\", found \"%s\"", mode, str.c_str(),
            getNameFromToken((Token)token1),
            getNameFromToken((Token)token2), s);
    }
    return t;
}

/*
 * Unexpected token error.
 */
NO_RETURN void Parser::unexpectedToken() const
{
    std::string str;
    getPositionStr(str);
    error("failed to parse %s at position \"%s\"; unexpected token \"%s\"",
        mode, str.c_str(), s);
}

/*
 * Get the name of a token.
 */
const char *Parser::getName(int token) const
{
    return getNameFromToken((Token)token);
}

/*
 * Get a "blob" of characters.  Used for regex and filename tokens.
 */
int Parser::getBlob()
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
    return TOKEN_STRING;
}

