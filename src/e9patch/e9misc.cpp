/*
 * e9misc.cpp
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

#include <cerrno>
#include <cstdlib>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "e9patch.h"

#ifdef NDEBUG
#define BASE    0xbe000000000ull
#define INC     0x00100000000ull
#define MASK    0x00FFFFFF000ull
#else
#define BASE    0x00060000000ull        // For ASAN
#define INC     0x00001000000ull
#define MASK    0x00000000000ull
#endif

const Binary *Instr::B = nullptr;

/*
 * Instruction set constructor.
 */
InstrSet::InstrSet()
{
    static uintptr_t base = 0x0;
    if (base == 0x0)
    {
        base = BASE;
        uintptr_t r;
        syscall(SYS_getrandom, &r, sizeof(r), 0);
        base |= (r & MASK);
        base -= (base % PAGE_SIZE);
    }
    else
        base += INC;

    ub = (Instr *)base;
    ub--;   // Allocate sentinel.
    lb = ub;

    base -= extend * PAGE_SIZE;
    errno = 0;
    void *ptr = mmap((void *)base, extend * PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr != (void *)base && errno != 0)
        error("failed to allocate instruction buffer: %s", strerror(errno));
    if (ptr != (void *)base && errno == 0)
        error("failed to allocate instruction buffer; expected %p, got %p",
            (void *)base, ptr);
    limit = ptr;
}

/*
 * Instruction set allocate.
 */
void *InstrSet::alloc()
{
    lb--;
    Instr *I = lb;
    Instr *S = I - 1;

    if ((void *)S < limit)
    {
        intptr_t base = (uintptr_t)limit;
        extend = (extend >= 256? 256: 2 * extend);
        base -= extend * PAGE_SIZE;
        errno = 0;
        void *ptr =
            mmap((void *)base, extend * PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (ptr != (void *)base && errno != 0)
            error("failed to extend instruction buffer: %s", strerror(errno));
        if (ptr != (void *)base && errno == 0)
            error("failed to extend instruction buffer; expected %p, got %p",
                (void *)base, ptr);
        limit = ptr;
    }
    return (void *)I;
}

/*
 * Find the first instruction >= the offset.
 */
Instr *InstrSet::lower_bound(off_t offset) const
{
    if (lb == ub) return nullptr;
    const Instr *Is = lb;
    ssize_t lo = 0, hi = (ub - lb) - 1, mid = 0;
    while (lo <= hi)
    {
        mid = (lo + hi) / 2;
        if (offset > (off_t)Is[mid].offset)
            lo = mid+1;
        else if (offset < (off_t)Is[mid].offset)
            hi = mid-1;
        else
            return (Instr *)&Is[mid];
    }
    if ((off_t)Is[mid].offset < offset)
        mid++;
    return (Is[mid].offset == 0? nullptr: (Instr *)&Is[mid]);
}

/*
 * Find the instruction for the given offset.
 */
Instr *InstrSet::find(off_t offset) const
{
    Instr *I = lower_bound(offset);
    return (I == nullptr || (off_t)I->offset != offset? nullptr: I);
}

