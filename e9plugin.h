/*
 * e9plugin.h
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

#ifndef __E9PLUGIN_H
#define __E9PLUGIN_H

#include <cstdio>

#include "e9frontend.h"

/*
 * See the e9path-programming-guide.md file for documentation.
 */

#include <capstone/platform.h>
#include <capstone/capstone.h>

extern "C"
{
    typedef void *(*PluginInit)(FILE *out, const e9frontend::ELF *elf);
    typedef void (*PluginInstr)(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    typedef intptr_t (*PluginMatch)(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    typedef void (*PluginPatch)(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    typedef void (*PluginFini)(FILE *out, const e9frontend::ELF *elf,
        void *context);

    extern void *e9_plugin_init_v1(FILE *out, const e9frontend::ELF *elf);
    extern void e9_plugin_instr_v1(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    extern intptr_t e9_plugin_match_v1(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    extern void e9_plugin_patch_v1(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    extern void e9_plugin_fini_v1(FILE *out, const e9frontend::ELF *elf,
        void *context);
}

#endif
