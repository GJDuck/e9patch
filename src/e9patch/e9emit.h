/*
 * e9emit.h
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

#ifndef __E9EMIT_H
#define __E9EMIT_H

#include <cstdint>
#include <cstdlib>

void emitBinary(const char *filename, const uint8_t *bin, size_t len);
void emitPatch(const char *filename, const char *compress, int fd1,
    const uint8_t *bin2, size_t len2);

#endif
