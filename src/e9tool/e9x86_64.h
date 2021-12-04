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
#ifndef __E9X86_64_H
#define __E9X86_64_H

#include <cstdint>

#include "e9tool.h"

extern void initDisassembler(void);
extern bool decode(const uint8_t **code, size_t *size, off_t *offset,
    intptr_t *address, e9tool::Instr *I);
extern int suspiciousness(const uint8_t *bytes, size_t size);
extern const e9tool::OpInfo *getOperand(const e9tool::InstrInfo *I, int idx,
    e9tool::OpType type, e9tool::Access access);

#endif
