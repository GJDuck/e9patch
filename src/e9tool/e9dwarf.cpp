/*
 * e9dwarf.cpp
 * Copyright (C) 2024 National University of Singapore
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

#include <cstddef>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>

#include "e9elf.h"
#include "e9misc.h"
#include "e9tool.h"

#include "libdw.h"

using namespace e9tool;

/*
 * Check if lines are the same.
 */
static bool sameLine(const Line &line_1, const Line &line_2)
{
    if (line_1.line != line_2.line)
        return false;
    if (line_1.dir == nullptr && line_2.dir != nullptr)
        return false;
    if (line_1.dir != nullptr && line_2.dir == nullptr)
        return false;
    if (line_1.dir != nullptr && line_2.dir != nullptr &&
            strcmp(line_1.dir, line_2.dir) != 0)
        return false;
    if (strcmp(line_1.file, line_2.file) != 0)
        return false;
    return true;
}

/*
 * Build source line information.
 */
extern void e9tool::buildLines(const ELF *elf, const Instr *Is, size_t size,
    Lines &Ls)
{
    int fd = open(elf->filename, O_RDONLY, 0);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", elf->filename,
            strerror(errno));

    Dwarf *dbg = dwarf_begin(fd, DWARF_C_READ);
    if (dbg == nullptr)
    {
        const char *err = dwarf_errmsg(0);
        if (strcmp(err, "no DWARF information") != 0)
            error("failed to read debug information (DWARF) from file "
                "\"%s\": %s", elf->filename, err);
        warning("no debug information (DWARF) found in \"%s\"; line/file "
            "information is undefined", elf->filename);
        return;
    }

    Dwarf_Off offset = 0, last = 0;
    size_t hdr_size;
    Lines Tmp;
    while (dwarf_nextcu(dbg, offset, &offset, &hdr_size, 0, 0, 0) == 0)
    {
        Dwarf_Die cudie_obj, *cudie;
        cudie = dwarf_offdie(dbg, last + hdr_size, &cudie_obj);
        last = offset;
        if (cudie == nullptr)
            continue;
        Dwarf_Lines *lines = nullptr;
        Dwarf_Files *files = nullptr;
        size_t nlines = 0, nfiles = 0, ndirs = 0;
        if (dwarf_getsrclines(cudie, &lines, &nlines) != 0)
            continue;
        if (dwarf_getsrcfiles(cudie, &files, &nfiles) != 0)
            continue;
        const char *const *dirs = nullptr;
        if (dwarf_getsrcdirs(files, &dirs, &ndirs) != 0)
            continue;
        const char *dir = (dirs[0] != nullptr? strCache(dirs[0]): nullptr);
        for (size_t i = 0; i < nlines; i++)
        {
            Dwarf_Line *line = dwarf_onesrcline(lines, i);
            if (line == nullptr)
                continue;
            Dwarf_Addr addr;
            if (dwarf_lineaddr(line, &addr) != 0)
                continue;
            const char *file = dwarf_linesrc(line, nullptr, nullptr);
            if (file == nullptr)
                continue;
            int lineno;
            if (dwarf_lineno(line, &lineno) != 0)
                continue;
            file = strCache(file);
            const char *tmp = (dir != nullptr && file[0] != '/'? dir: nullptr);
            Tmp.emplace(std::piecewise_construct,
                std::forward_as_tuple((intptr_t)addr),
                std::forward_as_tuple((intptr_t)addr, INTPTR_MAX, tmp, file,
                    (unsigned)lineno));
        }
    }
    for (auto i = Tmp.begin(), iend = Tmp.end(); i != iend; )
    {
        const Line &line = i->second;
        for (++i; i != iend && sameLine(i->second, line); ++i)
            ;
        intptr_t lb = line.lb;
        intptr_t ub = (i != iend? i->second.lb: INTPTR_MAX);
        if (ub == INTPTR_MAX)
        {
            // Alternative method for end-case
            ub = lb;
            for (ssize_t i = findInstr(Is, size, lb);
                    i >= 0 && (size_t)i < size && Is[i].address == (size_t)ub;
                    i++)
                ub = Is[i].address + Is[i].size;
        }
        Ls.emplace(std::piecewise_construct,
            std::forward_as_tuple(lb),
            std::forward_as_tuple(lb, ub, line.dir, line.file, line.line));
    }

#if 0
    for (const auto &E: Ls)
    {
        const Line &L = E.second;
        fprintf(stderr, "0x%lx..0x%lx [%zu]: %s:%u\n", L.lb, L.ub,
            L.ub - L.lb, L.file, L.line);
    }
#endif

    dwarf_end(dbg);
}

/*
 * Find the line associated with the given address.
 */
extern const Line *e9tool::findLine(const Lines &Ls, intptr_t addr)
{
    auto i = Ls.lower_bound(addr);
    if (i == Ls.end())
        return nullptr;
    if (i->second.lb == addr)
        return &i->second;
    auto j = Ls.begin();
    if (i == j)
        return nullptr;
    i--;
    if (i->second.lb <= addr && addr < i->second.ub)
        return &i->second;
    else
        return nullptr;
}

