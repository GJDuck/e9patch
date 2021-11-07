/*
 * e9x86_64.h
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

#ifndef __E9X86_64_H
#define __E9X86_64_H

#include <cstdint>

int relocateInstr(intptr_t addr, int32_t offset32, const uint8_t *bytes,
    unsigned size, bool pic, Buffer *buf = nullptr, bool relax = false);
unsigned getInstrPCRelativeIndex(const uint8_t *bytes, unsigned size);

#define CFT_CALL    0x01
#define CFT_RET     0x02
#define CFT_JMP     0x04
#define CFT_JCC     0x08
#define CFT_ANY     0xFF

bool isCFT(const uint8_t *bytes, unsigned size, int flags);
intptr_t getCFTTarget(intptr_t addr, const uint8_t *bytes, unsigned size,
    int flags);

#endif
