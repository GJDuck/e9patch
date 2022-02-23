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
#ifndef __E9PARSER_H
#define __E9PARSER_H

#include <string>

#include "e9tool.h"

/*
 * Tokens.
 */
enum Token
{
    TOKEN_ERROR = -1,
    TOKEN_EOF = '\0',
    TOKEN_INTEGER = 2000,
    TOKEN_REGISTER,
    TOKEN_STRING,
    TOKEN_NAME,
    TOKEN_REGEX,

    TOKEN_ACCESS = 4000,
    TOKEN_ADDR,
    TOKEN_AFTER,
    TOKEN_AND,
    TOKEN_ASM,
    TOKEN_AVX,
    TOKEN_AVX2,
    TOKEN_AVX512,
    TOKEN_BASE,
    TOKEN_BB,
    TOKEN_BEFORE,
    TOKEN_BEST,
    TOKEN_BREAK,
    TOKEN_CALL,
    TOKEN_CLEAN,
    TOKEN_CONDJUMP,
    TOKEN_CONFIG,
    TOKEN_DEFINED,
    TOKEN_DISPLACEMENT,
    TOKEN_DOTDOT,
    TOKEN_DST,
    TOKEN_EMPTY,
    TOKEN_END,
    TOKEN_ENTRY,
    TOKEN_EXIT,
    TOKEN_F,
    TOKEN_FALSE,
    TOKEN_GEQ,
    TOKEN_GOTO,
    TOKEN_I,
    TOKEN_ID,
    TOKEN_IF,
    TOKEN_IMM,
    TOKEN_IN,
    TOKEN_INDEX,
    TOKEN_INSTR,
    TOKEN_JUMP,
    TOKEN_LENGTH,
    TOKEN_LEQ,
    TOKEN_MATCH,
    TOKEN_MEM,
    TOKEN_MEM16,
    TOKEN_MEM32,
    TOKEN_MEM64,
    TOKEN_MEM8,
    TOKEN_MMX,
    TOKEN_MNEMONIC,
    TOKEN_NAKED,
    TOKEN_NAME_2,
    TOKEN_NEQ,
    TOKEN_NEXT,
    TOKEN_NIL,
    TOKEN_NONE,
    TOKEN_NOT,
    TOKEN_OFFSET,
    TOKEN_OP,
    TOKEN_OR,
    TOKEN_PASSTHRU,
    TOKEN_PATCH,
    TOKEN_PLUGIN,
    TOKEN_PRINT,
    TOKEN_RANDOM,
    TOKEN_READ,
    TOKEN_READS,
    TOKEN_REG,
    TOKEN_REGS,
    TOKEN_REPLACE,
    TOKEN_RETURN,
    TOKEN_RW,
    TOKEN_SCALE,
    TOKEN_SECTION,
    TOKEN_SEGMENT,
    TOKEN_SIZE,
    TOKEN_SRC,
    TOKEN_SSE,
    TOKEN_START,
    TOKEN_STATE,
    TOKEN_STATIC,
    TOKEN_TARGET,
    TOKEN_TRAMPOLINE,
    TOKEN_TRAP,
    TOKEN_TRUE,
    TOKEN_TYPE,
    TOKEN_WRITE,
    TOKEN_WRITES,
    TOKEN_X87,
};

/*
 * Parser
 */
struct Parser
{
    static const unsigned TOKEN_MAXLEN = 2048;

    const e9tool::ELF * elf;
    const char * const mode;
    const char * const buf;
    size_t pos  = 0;
    size_t prev = 0;
    int peek    = TOKEN_ERROR;
    intptr_t i  = 0;
    char s[TOKEN_MAXLEN+1];

    Parser(const char *buf, const char *mode, const e9tool::ELF &elf) :
        buf(buf), mode(mode), elf(&elf)
    {
        ;
    }

    Token getTokenFromName(const char *name);
    const char *getName(int token) const;
    int getToken();
    int peekToken();
    void expectToken(int token);
    int expectToken2(int token1, int token2);
    NO_RETURN void unexpectedToken() const;
    int getBlob();

    void getPositionStr(std::string &str) const;
};

#endif
