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
    unsigned size, bool pic, uint8_t *new_bytes);
unsigned getInstrPCRelativeIndex(const uint8_t *bytes, unsigned size);
intptr_t getJumpTarget(intptr_t addr, const uint8_t *bytes, unsigned size);
intptr_t getJccTarget(intptr_t addr, const uint8_t *bytes, unsigned size);

#endif
