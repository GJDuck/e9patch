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
#ifndef __E9TYPES_H
#define __E9TYPES_H

#include <string>

#include <cassert>
#include <cstdint>

#include "e9tool.h"

typedef uint8_t Type;

#define TYPE_NONE                   0x00
#define TYPE_CHAR                   0x01
#define TYPE_INT8                   0x02
#define TYPE_INT16                  0x03
#define TYPE_INT32                  0x04
#define TYPE_INT64                  0x05
#define TYPE_VOID                   0x06
#define TYPE_NULL_PTR               0x07
#define TYPE_PTR                    0x10
#define TYPE_PTR_PTR                0x20
#define TYPE_CONST                  0x40

#define TYPE_VOID_PTR               (TYPE_VOID | TYPE_PTR)
#define TYPE_CONST_VOID_PTR         (TYPE_CONST | TYPE_VOID | TYPE_PTR)
#define TYPE_CONST_CHAR_PTR         (TYPE_CONST | TYPE_CHAR | TYPE_PTR)
#define TYPE_CONST_INT8_PTR         (TYPE_CONST | TYPE_INT8 | TYPE_PTR)

typedef uint64_t TypeSig;

#define TYPESIG_MIN     0
#define TYPESIG_MAX     UINT64_MAX

#define TYPESIG_EMPTY   0
#define TYPESIG_UNTYPED (UINT64_MAX-1)

static inline Type getType(TypeSig sig, unsigned idx)
{
    return (Type)(sig >> (64 - 8 * (idx + 1)));
}

static inline TypeSig setType(TypeSig sig, Type t, unsigned idx)
{
    assert(((t & TYPE_PTR_PTR) != 0? (t & TYPE_PTR) == 0: true));
    assert(((t & TYPE_PTR_PTR) != 0? t != TYPE_NULL_PTR: true));
    assert(((t & TYPE_PTR) != 0? t != TYPE_NULL_PTR: true));
    assert(((t & TYPE_PTR) == 0? (t & TYPE_CONST) == 0: true));

    unsigned shift = (64 - 8 * (idx + 1));
    sig &= ~(0xFFull << shift);
    sig |= ((TypeSig)t << shift);
    return sig;
}

extern TypeSig getInitSig(bool env);
extern TypeSig getMMapSig();
extern void getSymbolString(const char *name, TypeSig sig, std::string &str);
extern intptr_t lookupSymbol(const e9tool::ELF *elf, const char *name,
    TypeSig sig);
extern void lookupSymbolWarnings(const e9tool::ELF *elf,
    const e9tool::InstrInfo *I, const char *name, TypeSig sig);

#endif
