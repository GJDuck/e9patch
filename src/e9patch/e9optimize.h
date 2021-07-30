/*
 * e9optimize.h
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

#ifndef __E9OPTIMIZE_H
#define __E9OPTIMIZE_H

#include "e9patch.h"

void buildEntrySet(Binary *B);
const Instr *getTrampolinePrologueStart(const EntrySet &Es, const Instr *I);
intptr_t getTrampolineEntry(const EntrySet &Es, const Instr *I);
void setTrampolineEntry(EntrySet &Es, const Instr *I, intptr_t addr);
void optimizeJump(const Binary *B, intptr_t addr, uint8_t *bytes, size_t size);
void optimizeAllJumps(Binary *B);

#endif
