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
#ifndef __E9METADATA_H
#define __E9METADATA_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "e9action.h"
#include "e9plugin.h"
#include "e9tool.h"

extern void sendMetadata(FILE *out, const e9tool::ELF *elf,
	const Action *action, size_t idx, const std::vector<e9tool::Instr> &Is,
    size_t i, const e9tool::InstrInfo *I, intptr_t id, Context *cxt);

#endif
