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
 * Tokens.
 */
enum Token
{
    TOKEN_ERROR = -1,
    TOKEN_END = '\0',
    TOKEN_INTEGER = 3000,
    TOKEN_STRING,
    TOKEN_REGEX,

    TOKEN_NEQ,
    TOKEN_LEQ,
    TOKEN_GEQ,

    TOKEN_MACRO_FALSE,
    TOKEN_MACRO_IMM,
    TOKEN_MACRO_MEM,
    TOKEN_MACRO_REG,
    TOKEN_MACRO_TRUE,

    // Must be in alphabetical order:
    TOKEN_ADDR,
    TOKEN_AFTER,
    TOKEN_ASM,
    TOKEN_BASE,
    TOKEN_BEFORE,
    TOKEN_CALL,
    TOKEN_CLEAN,
    TOKEN_COUNT,
    TOKEN_DST,
    TOKEN_FALSE,
    TOKEN_IMM,
    TOKEN_INSTR,
    TOKEN_JUMP,
    TOKEN_LENGTH,
    TOKEN_MEM,
    TOKEN_MNEMONIC,
    TOKEN_NAKED,
    TOKEN_NEXT,
    TOKEN_OFFSET,
    TOKEN_OP,
    TOKEN_PASSTHRU,
    TOKEN_PLUGIN,
    TOKEN_PRINT,
    TOKEN_R10,
    TOKEN_R11,
    TOKEN_R12,
    TOKEN_R13,
    TOKEN_R14,
    TOKEN_R15,
    TOKEN_R8,
    TOKEN_R9,
    TOKEN_RANDOM,
    TOKEN_RAX,
    TOKEN_RBP,
    TOKEN_RBX,
    TOKEN_RCX,
    TOKEN_RDI,
    TOKEN_RDX,
    TOKEN_READ,
    TOKEN_REG,
    TOKEN_REPLACE,
    TOKEN_RETURN,
    TOKEN_RFLAGS,
    TOKEN_RIP,
    TOKEN_RSI,
    TOKEN_RSP,
    TOKEN_SIZE,
    TOKEN_SRC,
    TOKEN_STATIC_ADDR,
    TOKEN_TARGET,
    TOKEN_TRAMPOLINE,
    TOKEN_TRAP,
    TOKEN_TRUE,
    TOKEN_TYPE,
    TOKEN_WRITE
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
 * All tokens.
 */
static const TokenInfo tokens[] =
{
    {nullptr,       TOKEN_ERROR},
    {"!",           (Token)'!'},
    {"!=",          TOKEN_NEQ},
    {"&",           (Token)'&'},
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
    {"FALSE",       TOKEN_MACRO_FALSE},
    {"IMM",         TOKEN_MACRO_IMM},
    {"MEM",         TOKEN_MACRO_MEM},
    {"REG",         TOKEN_MACRO_REG},
    {"TRUE",        TOKEN_MACRO_TRUE},
    {"[",           (Token)'['},
    {"]",           (Token)']'},
    {"addr",        TOKEN_ADDR},
    {"address",     TOKEN_ADDR},
    {"after",       TOKEN_AFTER},
    {"asm",         TOKEN_ASM},
    {"base",        TOKEN_BASE},
    {"before",      TOKEN_BEFORE},
    {"call",        TOKEN_CALL},
    {"clean",       TOKEN_CLEAN},
    {"count",       TOKEN_COUNT},
    {"dst",         TOKEN_DST},
    {"false",       TOKEN_FALSE},
    {"imm",         TOKEN_IMM},
    {"instr",       TOKEN_INSTR},
    {"jump",        TOKEN_JUMP},
    {"len",         TOKEN_LENGTH},
    {"length",      TOKEN_LENGTH},
    {"mem",         TOKEN_MEM},
    {"mnemonic",    TOKEN_MNEMONIC},
    {"naked",       TOKEN_NAKED},
    {"next",        TOKEN_NEXT},
    {"offset",      TOKEN_OFFSET},
    {"op",          TOKEN_OP},
    {"passthru",    TOKEN_PASSTHRU},
    {"plugin",      TOKEN_PLUGIN},
    {"print",       TOKEN_PRINT},
    {"r10",         TOKEN_R10},
    {"r11",         TOKEN_R11},
    {"r12",         TOKEN_R12},
    {"r13",         TOKEN_R13},
    {"r14",         TOKEN_R14},
    {"r15",         TOKEN_R15},
    {"r8",          TOKEN_R8},
    {"r9",          TOKEN_R9},
    {"random",      TOKEN_RANDOM},
    {"rax",         TOKEN_RAX},
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
    {"size",        TOKEN_SIZE},
    {"src",         TOKEN_SRC},
    {"staticAddr",  TOKEN_STATIC_ADDR},
    {"target",      TOKEN_TARGET},
    {"trampoline",  TOKEN_TRAMPOLINE},
    {"trap",        TOKEN_TRAP},
    {"true",        TOKEN_TRUE},
    {"type",        TOKEN_TYPE},
    {"write",       TOKEN_WRITE}
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
static int compareToken(const void *ptr1, const void *ptr2)
{
    const TokenInfo *info1 = (const TokenInfo *)ptr1;
    const TokenInfo *info2 = (const TokenInfo *)ptr2;
    return (int)info1->token - (int)info2->token;
}

/*
 * Get a token from a name.
 */
static Token getTokenFromName(const char *name)
{
    TokenInfo key = {name, TOKEN_ERROR};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens + 1,
        sizeof(tokens) / sizeof(tokens[0]) - 1, sizeof(tokens[0]),
        compareName);
    if (entry == nullptr)
        return TOKEN_ERROR;
    return entry->token;
}

/*
 * Expands a macro value.
 */
static intptr_t expandMacro(Token t)
{
    switch (t)
    {
        case TOKEN_MACRO_TRUE:
            return 1;
        case TOKEN_MACRO_FALSE:
            return 0;
        case TOKEN_MACRO_IMM:
            return OP_TYPE_IMM;
        case TOKEN_MACRO_MEM:
            return OP_TYPE_MEM;
        case TOKEN_MACRO_REG:
            return OP_TYPE_REG;
        default:
            return -1;
    }
}

/*
 * Get the name of a token.
 */
static const char *getNameFromToken(Token token)
{
    // Special or unordered tokens:
    switch ((int)token)
    {
        case TOKEN_NEQ:
            return "!=";
        case TOKEN_LEQ:
            return "<=";
        case TOKEN_GEQ:
            return ">=";
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
    TokenInfo key = {nullptr, token};
    const TokenInfo *entry = (const TokenInfo *)bsearch(&key, tokens + 1,
        sizeof(tokens) / sizeof(tokens[0]) - 1, sizeof(tokens[0]),
        compareToken);
    if (entry == nullptr)
        return "???";
    while ((entry-1)->token == token)
        entry--;
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
                return (Token)c;
            case '!': case '<': case '>': case '=':
                s[0] = c; s[1] = '\0';
                pos++;
                if (buf[pos] == '=')
                {
                    s[1] = '='; s[2] = '\0';
                    pos++;
                }
                return getTokenFromName(s);
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
                pos += 2;
                c = buf[pos];
            }
            if (!isdigit(c))
                return TOKEN_ERROR;
            s[j++] = c;
            pos++;
            while (isdigit(buf[pos]) && j < TOKEN_MAXLEN)
                s[j++] = buf[pos++];
            s[j] = '\0';
            if (j >= TOKEN_MAXLEN)
                return TOKEN_ERROR;
            char *end = nullptr;
            i = (intptr_t)strtoull(s, &end, base);
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
        if (prev >= 4)
            str += "...";
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
        for (unsigned j = 0; j < TOKEN_MAXLEN && buf[pos] != '\0'; j++)
            s[j] = buf[pos++];
        if (buf[pos] != '\0')
            unexpectedToken();
        return TOKEN_REGEX;
    }
};

