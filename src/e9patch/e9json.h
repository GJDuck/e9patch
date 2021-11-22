/*
 * e9json.h
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

#ifndef __E9JSON_H
#define __E9JSON_H

#include <cstdint>
#include <cstdio>

#include "e9trampoline.h"

/*
 * Supported methods.
 */
enum Method
{
    METHOD_UNKNOWN,
    METHOD_BINARY,
    METHOD_EMIT,
    METHOD_INSTRUCTION,
    METHOD_OPTIONS,
    METHOD_PATCH,
    METHOD_RESERVE,
    METHOD_TRAMPOLINE,
};

/*
 * Supported parameters.
 */
enum ParamName
{
    PARAM_UNKNOWN,
    PARAM_ABSOLUTE,
    PARAM_ADDRESS,
    PARAM_ARGV,
    PARAM_BYTES,
    PARAM_FILENAME,
    PARAM_FINI,
    PARAM_FORMAT,
    PARAM_INIT,
    PARAM_LENGTH,
    PARAM_METADATA,
    PARAM_MMAP,
    PARAM_MODE,
    PARAM_NAME,
    PARAM_OFFSET,
    PARAM_PROTECTION,
    PARAM_TEMPLATE,
    PARAM_TRAMPOLINE,
};

/*
 * Supported formats.
 */
enum Format
{
    FORMAT_BINARY,
    FORMAT_PATCH,
    FORMAT_PATCH_GZ,
    FORMAT_PATCH_BZIP2,
    FORMAT_PATCH_XZ
};

/*
 * Parameter values.
*/
union ParamValue
{
    bool boolean;                       // Boolean
    int64_t integer;                    // Integer
    const char *string;                 // String
    char * const *strings;              // Strings
    Trampoline *trampoline;             // Trampoline template
    Metadata *metadata;                 // Instruction metadata
};

/*
 * Parameters.
 */
struct Param
{
    ParamName name;                     // Parameter name
    ParamValue value;                   // Parameter value
};

/*
 * Messages.
 */
#define PARAM_MAX           8
struct Message
{
    Method method;                      // Message method
    size_t lineno;                      // Line number
    unsigned id;                        // Message ID
    unsigned num_params;                // Length of `params'.
    Param params[PARAM_MAX];            // Message params
};

bool getMessage(FILE *stream, size_t lineno, Message &msg);
const char *getMethodString(Method method);
Trampoline *makePadding(size_t size);

#endif
