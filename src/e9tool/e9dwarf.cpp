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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>

#include "e9elf.h"
#include "e9tool.h"

using namespace e9tool;

#define DWARF_C_READ    0

typedef Elf64_Off Dwarf_Off;
typedef Elf64_Addr Dwarf_Addr;
typedef Elf64_Xword Dwarf_Word;
typedef struct Dwarf Dwarf;
typedef struct Dwarf_Abbrev Dwarf_Abbrev;
typedef struct Dwarf_CU Dwarf_CU;
typedef struct Dwarf_Lines_s Dwarf_Lines;
typedef struct Dwarf_Line_s Dwarf_Line;
typedef struct
{
    void *addr;
    struct Dwarf_CU *cu;
    Dwarf_Abbrev *abbrev;
    long int padding__;
} Dwarf_Die;

typedef Dwarf *(*dwarf_begin_t)(int fildes, int cmd);
typedef int (*dwarf_end_t)(Dwarf *dwarf);
typedef int (*dwarf_nextcu_t)(Dwarf *dwarf, Dwarf_Off off, Dwarf_Off *next_off,
    size_t *header_sizep, Dwarf_Off *abbrev_offsetp,
    uint8_t *address_sizep, uint8_t *offset_sizep);
typedef Dwarf_Die *(*dwarf_offdie_t)(Dwarf *dbg, Dwarf_Off offset,
    Dwarf_Die *result);
typedef int (*dwarf_getsrclines_t)(Dwarf_Die *cudie, Dwarf_Lines **lines,
    size_t *nlines);
typedef Dwarf_Line *(*dwarf_onesrcline_t)(Dwarf_Lines *lines, size_t idx);
typedef int (*dwarf_lineaddr_t)(Dwarf_Line *line, Dwarf_Addr *addrp);
typedef int (*dwarf_lineno_t)(Dwarf_Line *line, int *linep);
typedef int (*dwarf_linecol_t)(Dwarf_Line *line, int *linep);
typedef const char *(*dwarf_linesrc_t)(Dwarf_Line *line, Dwarf_Word *mtime,
    Dwarf_Word *length);
typedef const char *(*dwarf_errmsg_t)(int err);

static dwarf_begin_t dwarf_begin             = nullptr;
static dwarf_end_t dwarf_end                 = nullptr;
static dwarf_nextcu_t dwarf_nextcu           = nullptr;
static dwarf_offdie_t dwarf_offdie           = nullptr;
static dwarf_getsrclines_t dwarf_getsrclines = nullptr;
static dwarf_onesrcline_t dwarf_onesrcline   = nullptr;
static dwarf_lineaddr_t dwarf_lineaddr       = nullptr;
static dwarf_lineno_t dwarf_lineno           = nullptr;
static dwarf_linecol_t dwarf_linecol         = nullptr;
static dwarf_linesrc_t dwarf_linesrc         = nullptr;
static dwarf_errmsg_t dwarf_errmsg           = nullptr;

/*
 * Load a symbol from the library.
 */
static void *getSym(void *handle, const char *lib, const char *name)
{
    void *sym = dlsym(handle, name);
    if (sym == nullptr)
        error("failed to load symbol \"%s\" from library \"%s\": %s",
            name, lib, dlerror());
    return sym;
}

/*
 * Build source line information.
 */
extern void e9tool::buildLines(const ELF *elf, Lines &Ls)
{
    const char *libname = "libdw.so";
    void *handle = dlopen(libname, RTLD_LAZY);
    if (handle == nullptr)
        error("failed to load library \"%s\" (not installed?): %s", libname,
            dlerror());

    dwarf_begin       = (dwarf_begin_t)      getSym(handle, libname, "dwarf_begin");
    dwarf_end         = (dwarf_end_t)        getSym(handle, libname, "dwarf_end");
    dwarf_nextcu      = (dwarf_nextcu_t)     getSym(handle, libname, "dwarf_nextcu");
    dwarf_offdie      = (dwarf_offdie_t)     getSym(handle, libname, "dwarf_offdie");
    dwarf_getsrclines = (dwarf_getsrclines_t)getSym(handle, libname, "dwarf_getsrclines");
    dwarf_onesrcline  = (dwarf_onesrcline_t) getSym(handle, libname, "dwarf_onesrcline");
    dwarf_lineaddr    = (dwarf_lineaddr_t)   getSym(handle, libname, "dwarf_lineaddr");
    dwarf_lineno      = (dwarf_lineno_t)     getSym(handle, libname, "dwarf_lineno");
    dwarf_linecol     = (dwarf_linecol_t)    getSym(handle, libname, "dwarf_linecol");
    dwarf_linesrc     = (dwarf_linesrc_t)    getSym(handle, libname, "dwarf_linesrc");
    dwarf_errmsg      = (dwarf_errmsg_t)     getSym(handle, libname, "dwarf_errmsg");

    int fd = open(elf->filename, O_RDONLY, 0);
    if (fd < 0)
        error("failed to open file \"%s\" for reading: %s", elf->filename,
            strerror(errno));

    Dwarf *dbg = dwarf_begin(fd, DWARF_C_READ);
    if (dbg == nullptr)
        error("failed to read DWARF information from file \"%s\": %s",
            elf->filename, dwarf_errmsg(0));

    Dwarf_Off offset = 0, last = 0;
    size_t hdr_size;
    while (dwarf_nextcu(dbg, offset, &offset, &hdr_size, 0, 0, 0) == 0)
    {
        Dwarf_Die cudie_obj, *cudie;
        cudie = dwarf_offdie(dbg, last + hdr_size, &cudie_obj);
        last = offset;
        if (cudie == nullptr)
            continue;
        Dwarf_Lines *lines = nullptr;
        size_t nlines = 0;
        if (dwarf_getsrclines(cudie, &lines, &nlines) != 0)
            continue;
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
            Ls.emplace(std::piecewise_construct,
                std::forward_as_tuple((intptr_t)addr),
                std::forward_as_tuple(file, (unsigned)lineno));
        }
    }

    dwarf_end(dbg);
    dlclose(handle);
}
