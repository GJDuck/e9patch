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

#ifndef PT_GNU_PROPERTY
#define PT_GNU_PROPERTY                     0x6474e553
#define NT_GNU_PROPERTY_TYPE_0              5
#define GNU_PROPERTY_X86_FEATURE_1_AND      0xc0000002
#define GNU_PROPERTY_X86_FEATURE_1_IBT      0x1
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK    0x2
#endif

/*
 * GNU_PROPERTY handling.
 */
struct property_s
{
    uint32_t type;
    uint32_t datasz;
    uint8_t data[];
};

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
        struct
        {
            bool ibt;                   // Intel CET: Indirect Branch Tracking
            bool shstk;                 // Intel CET: Shadow Stack
        } cet;

        Targets targets;                // Jump/Call targets [optional]
        BBs bbs;                        // Basic blocks [optional]
        Fs fs;                          // Functions [optional]

        mutable Symbols symbols;        // Symbol cache.
        std::list<Elf64_Shdr> sec_cache;// Extra allocated sections (PE).
        std::list<Elf64_Sym> sym_cache; // Extra allocated symbols (PE).
        std::string str_cache;          // Extra allocated strings (PE).
    };
};

#endif
