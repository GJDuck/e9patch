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
#ifndef __E9ELF_H
#define __E9ELF_H

#include <list>
#include <map>
#include <string>
#include <vector>

#include <cstdint>

#include <elf.h>

#include "e9tool.h"
#include "e9types.h"

/*
 * Symbol.
 */
struct Symbol
{
    const char * const name;            // Symbol name
    const TypeSig      sig;             // Symbol typesig.

    bool operator<(const Symbol &sym) const
    {
        int cmp = strcmp(name, sym.name);
        if (cmp != 0)
            return (cmp < 0);
        return (sig < sym.sig);
    }

    Symbol(const char *name, TypeSig sig) : name(name), sig(sig)
    {
        ;
    }
};

/*
 * Symbol cache.  INTPTR_MIN=missing, (>0)=original, (<0)=derived.
 */
typedef std::map<Symbol, intptr_t> Symbols;

/*
 * ELF file.
 */
namespace e9tool
{
    struct ELF
    {
        // Data
        const char *filename;           // Filename.
        const uint8_t *data;            // File data.
        size_t size;                    // File size.
        intptr_t base;                  // Base address.
        intptr_t end;                   // End address.

        // Strtab
        const char *strs;

        // Program headers
        const Elf64_Phdr *phdrs;        // Elf PHDRs.
        size_t phnum;                   // Number of PHDRs.

        // Sections
        SectionInfo sections;

        // Executable sections (sorted by offset)
        std::vector<const Elf64_Shdr *> exes;

        // Symbols
        SymbolInfo dynsyms;
        SymbolInfo syms;                // Only if not stripped

        // GOT
        GOTInfo got;

        // PLT
        PLTInfo plt;

        BinaryType type;                // Binary type.
        bool reloc;                     // Needs relocation?
        bool dynlink;                   // Dynamically linked?

        Targets targets;                // Jump/Call targets [optional]
        BBs bbs;                        // Basic blocks [optional]
        Fs fs;                          // Functions [optional]

        mutable Symbols symbols;        // Symbol cache.
        std::list<Elf64_Shdr> sec_cache;// Extra allocated sections (PE).
        std::string str_cache;          // Extra allocated strings (PE).
    };
};

#endif
