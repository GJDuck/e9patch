/*
 * e9plugin.h
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

#ifndef __E9PLUGIN_H
#define __E9PLUGIN_H

#include <cstdio>

#include "e9tool.h"

/*
 * See the e9path-programming-guide.md file for documentation.
 */

extern "C"
{
    /*
     * Events.
     */
    enum Event
    {
        EVENT_DISASSEMBLY_COMPLETE,
        EVENT_MATCHING_COMPLETE,
        EVENT_PATCHING_COMPLETE,
    };

    /*
     * Patching phases.
     */
    enum Phase
    {
        PHASE_CODE,
        PHASE_DATA,
        PHASE_METADATA
    };

    /*
     * Context
     */
    struct Context
    {
        FILE *out;                              // The output stream
        const std::vector<char *> *argv;        // Plugin command-line args
        void *context;                          // The user context
        const e9tool::ELF * const elf;          // Input ELF file
        const std::vector<e9tool::Instr> *Is;   // All disasm instructions
        ssize_t idx;                            // Current instruction idx
        const e9tool::InstrInfo * const I;      // Current instruction info
        intptr_t id;                            // Current patch ID
    };

    typedef void *(*PluginInit)(const Context *cxt);
    typedef void (*PluginEvent)(const Context *cxt, Event event);
    typedef intptr_t (*PluginMatch)(const Context *cxt);
    typedef void (*PluginPatch)(const Context *cxt, Phase phase);
    typedef void (*PluginFini)(const Context *cxt);

    extern void *e9_plugin_init_v1(const Context *cxt);
    extern void e9_plugin_event_v1(const Context *cxt, Event event);
    extern intptr_t e9_plugin_match_v1(const Context *cxt);
    extern void e9_plugin_patch_v1(const Context *cxt, Phase phase);
    extern void e9_plugin_fini_v1(const Context *cxt);
}

#endif
