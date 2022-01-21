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
#ifndef __E9MISC_H
#define __E9MISC_H

#include <cstdio>
#include <cstdlib>

#include <string>

#ifndef PAGE_SIZE
#define PAGE_SIZE   4096
#endif

#define CONTEXT_FORMAT      "%lx: %s%s%s: "
#define CONTEXT(I)          (I)->address,                           \
                            (option_is_tty? "\33[32m": ""),         \
                            (I)->string.instr,                      \
                            (option_is_tty? "\33[0m": "")

extern char *strDup(const char *old_str, size_t n = SIZE_MAX);
extern bool hasSuffix(const std::string &str, const char *suffix);
extern void getExePath(std::string &path);
extern bool isLibraryFilename(const char *filename);
extern const char *findBinary(const char *filename, bool exe = true,
    bool dot = false);
extern void usage(FILE *stream, const char *progname);

/*
 * Options.
 */
extern bool option_is_tty;
extern bool option_no_warnings;
extern bool option_debug;
extern bool option_intel_syntax;
extern bool option_targets;
extern bool option_bbs;
extern bool option_fs;
extern bool option_trap_all;

#endif
