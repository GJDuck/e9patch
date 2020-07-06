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
 * E9TOOL PLUGIN API DOCUMENTATION:
 *
 * E9Tool is the default frontend for E9Patch.  Although it is possible to
 * create new frontends for E9Patch, for some applications this can be quite
 * complicated and require a lot of boilerplate code.  To help address this,
 * we added a plugin mechanism for E9Tool, as documented below.
 *
 * A plugin is a shared object that exports specific functions, as outlined
 * below.  These functions will be invoked by E9Tool at different stages of
 * the patching process.  Mundane tasks, such as disassembly, will be handled
 * by the E9Tool frontend.
 *
 * The E9Tool plugin API is very simple and consists of just four functions:
 *
 *      (1) e9_plugin_init_v1(FILE *out, const ELF *in, ...):
 *          Called once before the binary is disassembled.
 *
 *      (2) e9_plugin_instr_v1(FILE *out, const ELF *in, ...):
 *          Called once for each disassembled instruction.
 *
 *      (3) e9_plugin_patch_v1(FILE *out, const ELF *in, ...):
 *          Called for each patch location.
 *
 *      (4) e9_plugin_fini_v1(FILE *out, const ELF *in, ...):
 *          Called once after all instructions have been patched.
 *
 * Note that each function is optional, and the plugin can choose not to
 * define it.  However, The plugin must define at least one of these functions
 * to be considered valid.
 *
 * Each function takes at least two arguments, namely:
 *
 *      - out: is the JSON-RPC output stream that is sent to the E9Patch
 *        backend; and
 *      - in: a representation of the input ELF file, see e9frontend.h for
 *        more information.
 *
 * Some functions take additional arguments, including:
 *
 *      - handle: Capstone handle.
 *      - offset: File offset of instruction (if applicable).
 *      - I: Instruction (if applicable).
 *      - context: An optional plugin-defined context returned by the
 *        e9_plugin_init_v1() function.
 *
 * Some API function return a value, including:
 *
 *      - e9_plugin_init_v1() returns an optional `context' that will be
 *        passed to all other API calls.
 *      - e9_plugin_instr_v1() returns a Boolean `true' or `false'.  If
 *        `false' is returned, then the instruction will not be patched,
 *        regardless of the `--action' filter.  This effectively implements
 *        a veto.
 *
 * The API is meant to be highly flexible.  Basically, the plugin API
 * functions are expected to send JSON-RPC messages directly to the E9Patch
 * backend by writing to the `out' output stream.
 *
 * Normally, the e9_plugin_init_v1() function will do the following tasks
 * (as required):
 *
 *      (1) Initialize the plugin (if necessary)
 *      (2) Setup trampolines
 *      (3) Reserve parts of the virtual address space
 *      (4) Load ELF binaries into the virtual address space
 *      (5) Create and return the context (if necessary)
 *
 * The e9_plugin_instr_v1() function will do the following:
 *
 *      (1) Analyze or remember the instruction (if necessary)
 *      (2) Setup additional trampolines (if necessary)
 *      (3) Veto the patching decision (optional)
 *
 * The e9_plugin_patch_v1() function will do the following:
 *
 *      (1) Setup additional trampolines (if necessary)
 *      (2) Send a "patch" JSON-RPC message with appropriate meta data.
 *
 * The e9_plugin_fini_v1() function will do any cleanup if necessary.
 *
 * See the `e9frontend.h' file for useful functions that can assist in these
 * tasks.  Otherwise, there are no limitations on what these functions can do,
 * just provided the E9Patch backend can parse the JSON-RPC messages sent by
 * the plugin.  This makes the plugin API very powerful.
 */

#include <capstone/platform.h>
#include <capstone/capstone.h>

extern "C"
{
    typedef void *(*PluginInit)(FILE *out, const e9frontend::ELF *elf);
    typedef bool (*PluginInstr)(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    typedef void (*PluginPatch)(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    typedef void (*PluginFini)(FILE *out, const e9frontend::ELF *elf,
        void *context);

    extern void *e9_plugin_init_v1(FILE *out, const e9frontend::ELF *elf);
    extern bool e9_plugin_instr_v1(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    extern void e9_plugin_patch_v1(FILE *out, const e9frontend::ELF *elf,
        csh handle, off_t offset, const cs_insn *I, void *context);
    extern void e9_plugin_fini_v1(FILE *out, const e9frontend::ELF *elf,
        void *context);
}

#endif
