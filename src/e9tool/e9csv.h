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
#ifndef __E9CSV_H
#define __E9CSV_H

#include "e9action.h"

extern MatchVal getCSVValue(intptr_t addr, const char *basename, uint16_t idx);
void parseAddrs(const char *filename, std::vector<intptr_t> &As);
void parseTargets(const char *filename, const e9tool::Instr *Is, size_t size,
    e9tool::Targets &targets);
void dumpInfo(const std::string basename, const e9tool::Instr *Is,
    size_t size, const e9tool::Targets &targets, const e9tool::BBs &bbs,
    const e9tool::Fs &fs);

#endif
