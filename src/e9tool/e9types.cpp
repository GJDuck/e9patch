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

#include <cstdint>
#include <climits>

#include <map>
#include <vector>

#include "e9elf.h"
#include "e9misc.h"
#include "e9tool.h"
#include "e9types.h"

using namespace e9tool;

/*
 * Get init() signature.
 */
TypeSig getInitSig(bool env)
{
    TypeSig sig = TYPESIG_EMPTY;
    sig = setType(sig, TYPE_INT32, 0);                          // argc
    sig = setType(sig, (TYPE_PTR_PTR | TYPE_CHAR), 1);          // argv
    if (env)
        sig = setType(sig, (TYPE_PTR_PTR | TYPE_CHAR), 2);      // envp
    return sig;
}

/*
 * Get mmap() signature.
 */
TypeSig getMMapSig()
{
    TypeSig sig = TYPESIG_EMPTY;
    sig = setType(sig, (TYPE_PTR | TYPE_VOID), 0);              // addr
    sig = setType(sig, TYPE_INT64, 1);                          // size
    sig = setType(sig, TYPE_INT32, 2);                          // prot
    sig = setType(sig, TYPE_INT32, 3);                          // flags
    sig = setType(sig, TYPE_INT32, 4);                          // fd
    sig = setType(sig, TYPE_INT64, 5);                          // offset
    return sig;
}

/*
 * Check if t can be coerced into u.
 */
static long coercible(Type t, Type u)
{
    if (t == u)
        return 0;
    if (t > u)
        return -1;

    switch (t)
    {
        case TYPE_INT8: case TYPE_INT16: case TYPE_INT32:
        case TYPE_INT64:
            switch (u)
            {
                case TYPE_INT8: case TYPE_INT16: case TYPE_INT32:
                case TYPE_INT64:
                    return u - t;
                default:
                    return -1;
            }
        default:
            break;
    }

    if (t == TYPE_NULL_PTR && (u & TYPE_PTR) != 0)
        return 4;
    if ((t & TYPE_PTR) != 0 && (u & TYPE_PTR) != 0)
    {
        if (u == (t | TYPE_CONST))
            return 1;       // (T *) --> (const T *)
        if ((t & TYPE_CONST) == 0 && u == (TYPE_VOID | TYPE_PTR))
            return 5;       // (T *) --> (void *)
        if (u == (TYPE_CONST | TYPE_VOID | TYPE_PTR))
            return 9;       // (T *) or (const T *) --> (const void *)
    }
    if ((t & TYPE_PTR_PTR) != 0 && (u & TYPE_PTR_PTR) != 0)
    {
        if (u == (t | TYPE_CONST))
            return 1;       // (T **) --> (const T **)
        if ((t & TYPE_CONST) == 0 && u == (TYPE_VOID | TYPE_PTR_PTR))
            return 5;       // (T **) --> (void **)
        if (u == (TYPE_CONST | TYPE_VOID | TYPE_PTR_PTR))
            return 9;       // (T **) or (const T **) --> (const void **)
    }
                
    return -1;
}

/*
 * Check if sig1 can be coerced into sig2.  Return a score that represents
 * how close the signatures match, else -1 for no match.
 */
static long coercible(TypeSig sig1, TypeSig sig2)
{
    if (sig2 == TYPESIG_UNTYPED)
        return LONG_MAX-1;
    long score = 0;
    for (unsigned i = 0; i < MAX_ARGNO; i++)
    {
        long s = coercible(getType(sig1, i), getType(sig2, i));
        if (s < 0)
            return -1;
        score *= 16;
        score += s;
    }
    return score;
}

/*
 * Convert a symbol into a human-readable string.
 */
static void getSymbolString(const Symbol &sym, std::string &str)
{
    str += sym.name;
    if (sym.sig == TYPESIG_UNTYPED)
        return;
    str += '(';
    bool prev = false;
    for (unsigned i = 0; i < MAX_ARGNO; i++)
    {
        Type t = getType(sym.sig, i);
        if (t == TYPE_NONE)
            break;
        if (prev)
            str += ',';
        prev = true;
        if ((t & TYPE_CONST) != 0)
            str += "const ";
        switch (t & ~(TYPE_CONST | TYPE_PTR | TYPE_PTR_PTR))
        {
            case TYPE_CHAR:
                str += "char"; break;
            case TYPE_INT8:
                str += "int8_t"; break;
            case TYPE_INT16:
                str += "int16_t"; break;
            case TYPE_INT32:
                str += "int32_t"; break;
            case TYPE_INT64:
                str += "int64_t"; break;
            case TYPE_VOID:
                str += "void"; break;
            case TYPE_NULL_PTR:
                str += "std::nullptr_t"; break;
            default:
                str += "???"; break;
        }
        if ((t & TYPE_PTR) != 0)
            str += " *";
        else if ((t & TYPE_PTR_PTR) != 0)
            str += " **";
    }
    str += ')';
}
void getSymbolString(const char *name, TypeSig sig, std::string &str)
{
    Symbol sym(name, sig);
    getSymbolString(sym, str);
}

/*
 * Add a symbol to the cache.
 */
static bool insertSymbol(Symbols &symbols, const char *name, TypeSig sig,
    intptr_t addr)
{
    Symbol key(strDup(name), sig);
    return symbols.insert({key, addr}).second;
}

/*
 * Parse a symbol from a C++ mangled name.
 */
static bool parseSymbol(Symbols &symbols, const char *name, intptr_t addr)
{
    const char *s = name;
    if (*s++ != '_' || *s++ != 'Z')
        return insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);
    char c = *s++;
    if (!isdigit(c) || c == '0')
        return insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);
    size_t len = (size_t)(c - '0');
    for (unsigned i = 0; isdigit(c = *s); i++, s++)
    {
        if (i > 3)
            return false;
        len *= 10;
        len += (size_t)(c - '0');
    }
    const char *n = s;
    if (len >= strlen(n))
        return insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);
    s += len;
    if (*s == 'v' && s[1] == '\0')
        s++;
    TypeSig sig = TYPESIG_EMPTY;
    unsigned i;
    Type dict[128];
    unsigned d = 0;
    for (i = 0; i < MAX_ARGNO && *s != '\0'; i++)
    {
        if (*s == 'S')
        {
            s++;
            unsigned j = 0;
            bool z = true;
            for (unsigned k = 0; isdigit(*s) && k < 2; k++)
            {
                z = false;
                j *= 10;
                j += *s - '0';
                s++;
            }
            j = (!z? j+1: j);
            if (*s++ != '_' || j >= d)
                return insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);
            sig = setType(sig, dict[j], i);
            continue;
        }
        if (*s == 'D' && s[1] == 'n')
        {
            sig = setType(sig, TYPE_NULL_PTR, i);
            s += 2;
            continue;
        }
        Type t = TYPE_NONE;
        if (*s == 'P')
        {
            s++;
            if (*s == 'P')
            {
                t |= TYPE_PTR_PTR;
                s++;
            }
            else
                t |= TYPE_PTR;
            if (*s == 'K')
            {
                t |= TYPE_CONST;
                s++;
            }
        }
        switch (*s++)
        {
            case 'c':
                t |= TYPE_CHAR;
                break;
            case 'a': case 'h':
                t |= TYPE_INT8;
                break;
            case 's': case 't':
                t |= TYPE_INT16;
                break;
            case 'i': case 'j':
                t |= TYPE_INT32;
                break;
            case 'l': case 'm':
                t |= TYPE_INT64;
                break;
            case 'v':
                t |= TYPE_VOID;
                break;
            default:
                return insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);
        }
        sig = setType(sig, t, i);
        if ((t & TYPE_PTR_PTR) != 0)
        {
            if ((t & TYPE_CONST) != 0)
                dict[d++] = (t & ~TYPE_PTR_PTR);
            dict[d++] = (t & ~TYPE_PTR_PTR) | TYPE_PTR;
            dict[d++] = t;
        }
        else if ((t & TYPE_PTR) != 0)
        {
            if ((t & TYPE_CONST) != 0)
                dict[d++] = (t & ~TYPE_PTR);
            dict[d++] = t;
        }
    }
    if (i >= MAX_ARGNO)
        insertSymbol(symbols, name, TYPESIG_UNTYPED, addr);

    char nname[len+1];
    memcpy(nname, n, len);
    nname[len] = '\0';

    return insertSymbol(symbols, nname, sig, addr);
}

/*
 * Lookup a symbol from the cache.  If no match is found, attempt to find the
 * optimal coercion to an existing symbol and cache the result.
 */
intptr_t lookupSymbol(const ELF *elf, const char *name, TypeSig sig)
{
    Symbols &symbols = elf->symbols;
    if (symbols.size() == 0)
    {
        // Build symbol cache:
        for (const auto &entry: elf->dynsyms)
        {
            const Elf64_Sym *sym = entry.second;
            if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                continue;
            intptr_t addr = elf->base + (intptr_t)sym->st_value;
            parseSymbol(symbols, entry.first, addr);
        }
    }

    Symbol key(name, sig);
    auto i = symbols.find(key);
    if (i != symbols.end())
    {
        intptr_t addr = i->second;
        if (addr == INTPTR_MIN)
            return addr;        // Missing
        if (addr < 0)
            return -addr;       // Derived
        else
            return addr;        // Original
    }

    // Attempt to find the optimal coercion:
    Symbol min(name, TYPESIG_MIN), max(name, TYPESIG_MAX);
    auto j = symbols.lower_bound(min);
    auto jend = symbols.upper_bound(max);
    long score = LONG_MAX;
    intptr_t addr = INTPTR_MIN;
    for (; j != jend; j++)
    {
        long nscore = coercible(sig, j->first.sig);
        if (nscore < 0)
            continue;       // Not coercible.
        if (j->second != INTPTR_MIN && nscore < score)
        {
            score = nscore;
            addr  = std::abs(j->second);
        }
    }

    // Add result to cache (note: INTPTR_MIN is a valid value):
    insertSymbol(symbols, name, sig, (addr > 0? -addr: addr));
    return addr;
}

/*
 * Print warning for symbol mismatch.
 */
void lookupSymbolWarnings(const ELF *elf, const InstrInfo *I, const char *name,
    TypeSig sig)
{
    Symbols &symbols = elf->symbols;
    Symbol min(name, TYPESIG_MIN), max(name, TYPESIG_MAX);
    auto j = symbols.lower_bound(min);
    auto jend = symbols.upper_bound(max);
    for (; j != jend; j++)
    {
        if (j->second < 0 || coercible(sig, j->first.sig) >= 0)
            continue;
        std::string str;
        getSymbolString(j->first, str);
        warning(CONTEXT_FORMAT "failed to match symbol candidate \"%s\"",
            CONTEXT(I), str.c_str());
    }
}

