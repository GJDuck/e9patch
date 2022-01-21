/*
 *        ___  _              _ 
 *   ___ / _ \| |_ ___   ___ | |
 *  / _ \ (_) | __/ _ \ / _ \| |
 * |  __/\__, | || (_) | (_) | |
 *  \___|  /_/ \__\___/ \___/|_|
 *                              
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

#include <cstdint>
#include <cstdio>

#include <map>

#include "e9action.h"
#include "e9csv.h"
#include "e9tool.h"
#include "e9misc.h"

using namespace e9tool;

/*
 * CSV stream representation.
 */
struct CSV
{
    FILE *stream;                   // Input stream
    const char *filename;           // Filename
    int length;                     // Record length
    unsigned lineno;                // Lineno
};

/*
 * CSV data representation.
 */
typedef std::vector<MatchVal> Record;
typedef std::map<intptr_t, Record> Data;

/*
 * CSV data cache.
 */
typedef std::map<const char *, Data, CStrCmp> Cache;

/*
 * Convert an entry into an integer.
 */
static bool entryToInt(const char *entry, intptr_t *val)
{
    const char *s = entry;
    while (isspace(*s))
        s++;
    bool neg = false;
    if (s[0] == '+')
        s++;
    else if (s[0] == '-')
    {
        neg = true;
        s++;
    }
    int base = (s[0] == '0' && s[1] == 'x'? 16: 10);
    char *end = nullptr;
    intptr_t x = (intptr_t)strtoull(s, &end, base);
    if (end == nullptr || end == s)
        return false;
    while (isspace(*end))
        end++;
    if (*end != '\0')
        return false;
    *val = (neg? -x: x);
    return true;
}

/*
 * Checked getc.
 */
static char getChar(CSV &csv)
{
    char c = getc(csv.stream);
    if (ferror(csv.stream))
        error("failed to parse CSV file \"%s\" at line %u: %s", csv.filename,
            csv.lineno, strerror(errno));
    if (feof(csv.stream))
        return EOF;
    if (!isascii(c))
        error("failed to parse CSV file \"%s\" at line %u; file contains a "
            "non-ASCII character `\\x%.2X'", csv.filename, csv.lineno,
            (unsigned)c);
    if (c == '\n')
        csv.lineno++;
    return c;
}

/*
 * Checked ungetc
 */
static void unGetChar(char c, CSV &csv)
{
    switch (c)
    {
        case EOF:
            return;
        case '\n':
            csv.lineno--;
            break;
        default:
            break;
    }
    ungetc(c, csv.stream);
}

/*
 * Parse a CSV entry.
 */
static bool parseEntry(CSV &csv, MatchVal &val)
{
    std::string entry;
    char c = getChar(csv);
    switch (c)
    {
        case EOF:
            return false;
        case '\r': case '\n': case ',':
            val = MatchVal();
            unGetChar(c, csv);
            return true;
        case '\"':
            while (true)
            {
                c = getChar(csv);
                switch (c)
                {
                    case EOF:
                        error("failed to parse CSV file \"%s\" at line %u; "
                            "unexpected end-of-file", csv.filename,
                            csv.lineno);
                    case '\"':
                        c = getChar(csv);
                        if (c != '\"')
                        {
                            unGetChar(c, csv);
                            val = MatchVal(strDup(entry.c_str()));
                            return true;
                        }
                        break;
                }
                entry += c;
            }
        default:
            entry += c;
            while (true)
            {
                c = getChar(csv);
                switch (c)
                {
                    case ',': case '\n': case '\r': case EOF:
                    {
                        unGetChar(c, csv);
                        intptr_t x;
                        if (entryToInt(entry.c_str(), &x))
                            val = MatchVal(x);
                        else
                            val = MatchVal(strDup(entry.c_str()));
                        return true;
                    }
                    default:
                        entry += c;
                        break;
                }
            }
    }
}

/*
 * Parse a CSV record.
 */
static bool parseRecord(CSV &csv, Record &record)
{
    MatchVal val;
    if (!parseEntry(csv, val))
        return false;
    record.push_back(val);

    while (true)
    {
        char c = getChar(csv);
        switch (c)
        {
            case '\r':
                c = getChar(csv);
                if (c != '\n')
                    error("failed to parse CSV file \"%s\" at line %u; "
                        "expected newline after carriage return", csv.filename,
                        csv.lineno);
                return true;
            case '\n': case EOF:
                return true;
            case ',':
                break;
            default:
                error("failed to parse CSV file \"%s\" at line %u; unexpected "
                    "character `%c'", csv.filename, csv.lineno);
        }
        if (!parseEntry(csv, val))
            return false;
        record.push_back(val);
    }
}

/*
 * Parse a CSV file.
 */
static void parseCSV(const char *filename, Data &data)
{
    FILE *stream = fopen(filename, "r");
    if (stream == nullptr)
        error("failed to open CSV file \"%s\" for reading: %s", filename,
            strerror(errno));

    CSV csv = {stream, filename, -1, 0};
    while (true)
    {
        Record record;
        if (!parseRecord(csv, record))
            break;
        if (csv.length < 0)
            csv.length = (unsigned)record.size();
        else if ((unsigned)record.size() != (unsigned)csv.length)
            error("failed to parse CSV file \"%s\" at line %u; record with "
                "invalid length %zu (expected %u)", csv.filename,
                csv.lineno, record.size(), csv.length);
        MatchVal &addr = record[0];
        if (addr.type != MATCH_TYPE_INTEGER)
            error("failed to parse CSV file \"%s\" at line %u; first record "
                "entry must be an address", csv.filename, csv.lineno);
        auto r = data.emplace(std::piecewise_construct,
            std::make_tuple(addr.i), std::make_tuple());
        if (!r.second)
            error("failed to parse CSV file \"%s\" at line %u; duplicate "
                "record with address 0x%lx", csv.filename, csv.lineno,
                addr);
        record.shrink_to_fit();
        record.swap(r.first->second);
    }

    fclose(stream);
}

/*
 * Lookup a value from a CSV file.
 */
MatchVal getCSVValue(intptr_t addr, const char *basename, uint16_t idx)
{
    static Cache cache;
    auto r = cache.emplace(std::piecewise_construct,
        std::make_tuple(basename), std::make_tuple());
    Data &data = r.first->second;
    if (r.second)
    {
        std::string filename(basename);
        filename += ".csv";
        parseCSV(filename.c_str(), data);
    }
    auto i = data.find(addr);
    if (i == data.end())
        return MatchVal();
    const Record &record = i->second;
    if (idx >= record.size())
        return MatchVal();
    return record[idx];
}

