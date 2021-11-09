/*
 * e9trampoline.h
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

#ifndef __E9TRAMPOLINE_H
#define __E9TRAMPOLINE_H

#include "e9patch.h"

#define TRAMPOLINE_MAX      4096

int getTrampolineSize(const Binary *B, const Trampoline *T, const Instr *I);
int getTrampolinePrologueSize(const Binary *B, const Instr *I);
Bounds getTrampolineBounds(const Binary *B, const Trampoline *T,
    const Instr *I);
void flattenAllTrampolines(Binary *B);

#endif
