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

/*
 * C-string comparator.
 */
struct CStrCmp
{
    bool operator()(const char* a, const char* b) const
    {
        return (strcmp(a, b) < 0);
    }
};

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
typedef std::vector<const char *> Record;
typedef std::vector<Record> Data;
template <typename T, class Cmp = std::less<T>>
using Index = std::map<T, const Record *, Cmp>;

/*
 * CSV data cache.
 */
typedef std::map<const char *, Data *, CStrCmp> Cache;
static Cache cache;

/*
 * Checked getc.
 */
static char getChar(CSV &csv)
{
    char c = getc(csv.stream);
    if (ferror(csv.stream))
        error("failed to parse CSV file \"%s\" line %u: %s", csv.filename,
            csv.lineno, strerror(errno));
    if (feof(csv.stream))
        return EOF;
    if (!isascii(c))
        error("failed to parse CSV file \"%s\" line %u; file contains a "
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
 * Parse a CSV name.
 */
static bool parseName(CSV &csv, std::string &name)
{
    char c = getChar(csv);
    switch (c)
    {
        case EOF:
            return false;
        case '\r': case '\n': case ',':
            unGetChar(c, csv);
            return true;
        case '\"':
            while (true)
            {
                c = getChar(csv);
                switch (c)
                {
                    case EOF:
                        error("failed to parse CSV file \"%s\" line %u; "
                            "unexpected end-of-file", csv.filename,
                            csv.lineno);
                    case '\"':
                        c = getChar(csv);
                        if (c != '\"')
                        {
                            unGetChar(c, csv);
                            return true;
                        }
                        break;
                }
                name += c;
            }
        default:
            name += c;
            while (true)
            {
                c = getChar(csv);
                switch (c)
                {
                    case ',': case '\n': case '\r': case EOF:
                        unGetChar(c, csv);
                        return true;
                    default:
                        name += c;
                        break;
                }
            }
    }
}

/*
 * Parse a CSV record.
 */
static bool parseRecord(CSV &csv, Record &record, std::string &name)
{
    if (!parseName(csv, name))
        return false;
    record.push_back(strDup(name.c_str()));
    name.clear();

    while (true)
    {
        char c = getChar(csv);
        switch (c)
        {
            case '\r':
                c = getChar(csv);
                if (c != '\n')
                    error("failed to parse CSV file \"%s\" line %u; expected "
                        "newline after carriage return", csv.filename,
                        csv.lineno);
                return true;
            case '\n': case EOF:
                return true;
            case ',':
                break;
            default:
                error("failed to parse CSV file \"%s\" line %u; unexpected "
                    "character `%c'", csv.filename, csv.lineno);
        }
        parseName(csv, name);
        record.push_back(strDup(name.c_str()));
        name.clear();
    }
}

/*
 * Parse a CSV file.
 */
static Data *parseCSV(const char *filename)
{
    char *path = realpath(filename, nullptr);
    if (path == nullptr)
        error("failed to get real path for \"%s\": %s", filename, 
            strerror(errno));
    auto i = cache.find(path);
    if (i != cache.end())
    {
        free(path);
        return i->second;
    }

    FILE *stream = fopen(path, "r");
    if (stream == nullptr)
        error("failed to open CSV file \"%s\" for reading: %s", filename,
            strerror(errno));

    Data *data = new Data;
    CSV csv = {stream, filename, -1, 0};
    std::string name;
   
    while (true)
    {
        Record record;
        if (!parseRecord(csv, record, name))
        {
            fclose(stream);
            break;
        }
        if (csv.length < 0)
            csv.length = (unsigned)record.size();
        else if ((unsigned)record.size() != (unsigned)csv.length)
            error("failed to parse CSV file \"%s\" line %u; record with "
                "invalid length %zu (expected %u)", csv.filename,
                csv.lineno, record.size(), csv.length);

        record.shrink_to_fit();
        data->push_back(std::move(record));
    }

    data->shrink_to_fit();
    cache.insert({path, data});
    return data;
}

/*
 * Convert a name into an integer.
 */
static intptr_t nameToInt(const char *basename, const char *name)
{
    const char *s = name;
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
    {
parse_error:
        error("failed to convert value \"%s\" from CSV file \"%s.csv\" "
            "into an integer", name, basename);
    }
    while (isspace(*end))
        end++;
    if (*end != '\0')
        goto parse_error;
    x = (neg? -x: x);
    return x;
}

/*
 * Build an integer index.
 */
static void buildIntIndex(const char *basename, const Data &data, unsigned i,
    Index<MatchValue> &index)
{
    for (const auto &record: data)
    {
        if (i >= record.size())
            error("failed to build index for CSV file \"%s.csv\"; index %u is "
                "out-of-range (0..%zu)\n", basename, i, record.size()-1);
        const char *name = record[i];
        intptr_t x = nameToInt(basename, name);
        MatchValue key = {0};
        key.type = MATCH_TYPE_INTEGER;
        key.i    = x;
        auto i = index.find(key);
        if (i != index.end())
            error("failed to build index for CSV file \"%s.csv\"; duplicate "
                "value \"%s\"", basename, name);
        index.insert(i, {key, &record});
    }
}

