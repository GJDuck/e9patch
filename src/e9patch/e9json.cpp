/*
 * e9json.cpp
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

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <set>
#include <vector>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "e9json.h"
#include "e9patch.h"
#include "e9trampoline.h"

/*
 * Bytes cache entry.
 */
struct Bytes
{
    const uint8_t *bytes;
    size_t len;
};
struct BytesCmp
{
    bool operator()(const Bytes &a, const Bytes &b) const
    {
        if (a.len != b.len)
            return (a.len < b.len);
        int cmp = memcmp(a.bytes, b.bytes, a.len);
        return (cmp < 0);
    }
};

/*
 * We implement our own JSON parser.  Most existing C++ JSON parsers are
 * too general-purpose and too slow for our application.
 */

#define STRING_MAX          1024
#define NUMBER_MAX          12

#define TOKEN_NONE          '\0'
#define TOKEN_NULL          '0'
#define TOKEN_BOOL          'B'
#define TOKEN_STRING        'S'
#define TOKEN_NUMBER        'N'

/*
 * Parse error.
 */
#define parse_error(parser, msg, ...)                                   \
    error("line %zu: " msg, (parser).lineno, ##__VA_ARGS__)

/*
 * JSON parser.
 */
struct Parser
{
    FILE * const stream;                // Input stream
    size_t lineno;                      // Line number
    char peek = '\0';                   // Peek'ed token
    bool b;                             // Boolean value
    bool pipe = false;                  // Input is a pipe?
    int32_t i;                          // Integer value
    char s[STRING_MAX];                 // String value

    Parser(FILE *stream, size_t lineno) : stream(stream), lineno(lineno)
    {
        struct stat buf;
        if (fstat(fileno(stream), &buf) == 0 && S_ISFIFO(buf.st_mode))
            pipe = true;
    }

    char getc()
    {
        char c = ::getc(stream);
        if (c == '\n')
            lineno++;
        return c;
    }

    void ungetc(char c)
    {
        if (c == '\n')
            lineno--;
        ::ungetc(c, stream);
    }
};

/*
 * Get the token name for error reporting.
 */
static const char *getTokenName(char token)
{
    switch (token)
    {
        case ':':
            return ":";
        case ',':
            return ",";
        case '{':
            return "{";
        case '}':
            return "}";
        case '[':
            return "[";
        case ']':
            return "]";
        case EOF:
            return "<end-of-file>";
        case TOKEN_BOOL:
            return "<bool>";
        case TOKEN_NUMBER:
            return "<number>";
        case TOKEN_STRING:
            return "<string>";
        case TOKEN_NULL:
            return "<null>";
        default:
            return "???";
    }
}

/*
 * Duplicate a string.
 */
static const char *dupString(const char *str)
{
    static std::set<const char *, CStrCmp> cache;
    auto i = cache.find(str);
    if (i != cache.end())
        return *i;

    char *new_str = strdup(str);
    if (new_str == nullptr)
        error("failed to duplicate string \"%s\": %s", str, strerror(ENOMEM));
    cache.insert(new_str);
    return new_str;
}

/*
 * Duplicate bytes.
 */
static std::set<Bytes, BytesCmp> bytes_cache;
static const uint8_t *dupBytes(const std::vector<uint8_t> &bytes)
{
    size_t len = bytes.size();
    Bytes key = {bytes.data(), len};
    auto i = bytes_cache.find(key);
    if (i != bytes_cache.end())
        return i->bytes;

    uint8_t *new_bytes = new uint8_t[len];
    memcpy(new_bytes, bytes.data(), len);
    bytes_cache.insert({new_bytes, len});
    return new_bytes;
}
static const uint8_t *dupBytes(const char *str)
{
    size_t len = strlen(str)+1;
    Bytes key = {(const uint8_t *)str, len};
    auto i = bytes_cache.find(key);
    if (i != bytes_cache.end())
        return i->bytes;

    uint8_t *new_bytes = new uint8_t[len];
    memcpy(new_bytes, str, len);
    bytes_cache.insert({new_bytes, len});
    return new_bytes;
}

/*
 * Duplicate trampolines.
 */
static Trampoline *dupTrampoline(const std::vector<Entry> &entries)
{
    size_t num_entries = entries.size();
    uint8_t *ptr =
        new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
    Trampoline *T  = (Trampoline *)ptr;
    T->prot        = PROT_READ | PROT_EXEC;
    T->preload     = false;
    T->num_entries = num_entries;
    memcpy(T->entries, &entries[0], num_entries * sizeof(Entry));

    static std::set<Trampoline *, TrampolineCmp> cache;
    auto i = cache.insert(T);
    if (!i.second)
    {
        delete[] ptr;
        return *i.first;
    }
    return T;
}

/*
 * Peek at the next token.
 */
static char peekToken(Parser &parser)
{
    if (parser.peek != TOKEN_NONE)
        return parser.peek;

    char c;
    while (isspace(c = parser.getc()))
        ;
    switch (c)
    {
        case ':': case ',': case '{': case '}': case '[': case ']': case EOF:
            return (parser.peek = c);
        case 't':
            if (parser.getc() != 'r' || parser.getc() != 'u' ||
                    parser.getc() != 'e')
                goto bad_token;
            parser.b = true;
            return (parser.peek = TOKEN_BOOL);
        case 'f':
            if (parser.getc() != 'a' || parser.getc() != 'l' ||
                    parser.getc() != 's' || parser.getc() != 'e')
                goto bad_token;
            parser.b = false;
            return (parser.peek = TOKEN_BOOL);
        case 'n':
            if (parser.getc() != 'u' || parser.getc() != 'l' ||
                    parser.getc() != 'l')
                goto bad_token;
            return (parser.peek = TOKEN_NULL);
        case '-': case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        {
            unsigned len = 0;
            parser.s[len++] = c;
            while (true)
            {
                if (len >= NUMBER_MAX)
                    parse_error(parser, "failed to read JSON number, maximum "
                        "length (%u) was exceeded", NUMBER_MAX);
                c = parser.getc();
                if (!isdigit(c))
                {
                    parser.ungetc(c);
                    parser.s[len++] = '\0';
                    break;
                }
                parser.s[len++] = c;
            }
            if (parser.s[0] == '-' && parser.s[1] == '\0')
            {
                c = '-';
                goto bad_token;
            }
            int64_t x = (int64_t)strtoll(parser.s, nullptr, 10);
            if (x < INT32_MIN || x > INT32_MAX)
                parse_error(parser, "failed to read JSON number, value is "
                    "out of range (%d..%d)", INT32_MIN, INT32_MAX);
            parser.i = (int32_t)x;
            return (parser.peek = TOKEN_NUMBER);
        }
        case '\"':
        {
            unsigned len = 0;
            while (true)
            {
                if (len >= STRING_MAX)
                    parse_error(parser, "failed to read JSON string, maximum "
                        "length (%u) was exceeded", STRING_MAX);
                c = parser.getc();
                switch (c)
                {
                    case EOF:
bad_string_eof:
                        if (parser.pipe)
                            exit(EXIT_FAILURE);
                        parse_error(parser, "failed to read JSON string, "
                            "reached end-of-file before string terminator "
                            "(`\"')");
                    case '\"':
                        parser.s[len++] = '\0';
                        break;
                    case '\\':
                        c = parser.getc();
                        switch (c)
                        {
                            case EOF:
                                goto bad_string_eof;
                            case 'u':
                                parse_error(parser, "failed to read JSON "
                                    "string, unicode escape sequences are not "
                                    "yet supported");
                            case 't':
                                parser.s[len++] = '\t';
                                break;
                            case 'n':
                                parser.s[len++] = '\n';
                                break;
                            case 'r':
                                parser.s[len++] = '\r';
                                break;
                            case 'b':
                                parser.s[len++] = '\b';
                                break;
                            case 'f':
                                parser.s[len++] = '\f';
                                break;
                            default:
                                parser.s[len++] = c;
                                break;
                        }
                        break;
                    default:
                        parser.s[len++] = c;
                        break;
                }
                if (c == '\"')
                    break;
            }
            return (parser.peek = TOKEN_STRING);
        }
        default:
bad_token:
            parse_error(parser, "failed to read JSON token; bad character "
                "`%c'", c);
    }
}

/*
 * Get (consume) the next token.
 */
static char getToken(Parser &parser)
{
    char token = parser.peek;
    if (token != TOKEN_NONE)
    {
        parser.peek = TOKEN_NONE;
        return token;
    }
    token = peekToken(parser);
    parser.peek = TOKEN_NONE;

    return token;
}

/*
 * Unexpected token error.
 */
static NO_RETURN void unexpectedToken(Parser &parser, const char *object,
    char token)
{
    if (parser.pipe && token == EOF)
        exit(EXIT_FAILURE);
    parse_error(parser, "failed to parse %s; unexpcted token `%s'",
        object, getTokenName(token));
}

/*
 * Expect `token'.
 */
static void expectToken(Parser &parser, char token)
{
    char got = getToken(parser);
    if (got == token)
        return;
    if (parser.pipe && token == EOF)
        exit(EXIT_FAILURE);
    parse_error(parser, "failed to parse JSON message; expected token `%s', "
        "got token `%s'", getTokenName(token), getTokenName(got));
}

/*
 * Expect `token1' or `token2'.
 */
static char expectToken2(Parser &parser, char token1, char token2)
{
    char got = getToken(parser);
    if (got == token1 || got == token2)
        return got;
    if (parser.pipe && got == EOF)
        exit(EXIT_FAILURE);
    parse_error(parser, "failed to parse JSON message; expected token "
        "`%s' or `%s', got token `%s'", getTokenName(token1),
        getTokenName(token2), getTokenName(got));
}

/*
 * Convert a string into a number.
 */
static intptr_t stringToNumber(const Parser &parser)
{
    bool neg = false;
    const char *s = parser.s;
    if (s[0] == '-')
    {
        neg = true;
        s++;
    }
    int base = 10;
    if (s[0] == '0' && s[1] == 'x')
        base = 16;
    char *end = nullptr;
    errno = 0;
    intptr_t x = (intptr_t)strtoull(s, &end, base);
    if (errno != 0 || (end != nullptr && *end != '\0'))
        parse_error(parser, "failed to parse number from JSON string \"%s\"",
            parser.s);
    return (neg? -x: x);
}

/*
 * Expect the specific string token.
 */
static NO_INLINE void expectString(Parser &parser, const char *str)
{
    expectToken(parser, TOKEN_STRING);
    if (strcmp(parser.s, str) != 0)
        parse_error(parser, "failed to parse JSON message; expected string "
            "\"%s\", got \"%s\"", str, parser.s);
}

/*
 * Parses and discards a JSON object.
 */
static void parseAndDiscardObject(Parser &parser)
{
    char token = getToken(parser);

    switch (token)
    {
        case '{':
            token = expectToken2(parser, '}', TOKEN_STRING);
            if (token == '}')
                return;
            while (true)
            {
                expectToken(parser, ':');
                parseAndDiscardObject(parser);
                token = expectToken2(parser, ',', '}');
                if (token == '}')
                    return;
                expectToken(parser, TOKEN_STRING);
            }
        case '[':
            token = peekToken(parser);
            if (token == ']')
            {
                getToken(parser);
                return;
            }
            while (true)
            {
                parseAndDiscardObject(parser);
                token = expectToken2(parser, ',', ']');
                if (token == ']')
                    return;
            }
        case TOKEN_BOOL:
        case TOKEN_NUMBER:
        case TOKEN_STRING:
            break;
        default:
            unexpectedToken(parser, "JSON object", token);
    }
}

/*
 * Match parameter names against methods.
 */
static bool validateParam(Method method, ParamName paramName)
{
    switch (method)
    {
        case METHOD_BINARY:
            switch (paramName)
            {
                case PARAM_FILENAME:
                case PARAM_MODE:
                    return true;
                default:
                    return false;
            }
        case METHOD_INSTRUCTION:
            switch (paramName)
            {
                case PARAM_ADDRESS:
                case PARAM_LENGTH:
                case PARAM_OFFSET:
                    return true;
                default:
                    return false;
            }
        case METHOD_PATCH:
            switch (paramName)
            {
                case PARAM_METADATA:
                case PARAM_OFFSET:
                case PARAM_TRAMPOLINE:
                    return true;
                default:
                    return false;
            }
        case METHOD_EMIT:
            switch (paramName)
            {
                case PARAM_FILENAME:
                case PARAM_FORMAT:
                    return true;
                default:
                    return false;
            }
        case METHOD_RESERVE:
            switch (paramName)
            {
                case PARAM_ABSOLUTE:
                case PARAM_ADDRESS:
                case PARAM_BYTES:
                case PARAM_FINI:
                case PARAM_INIT:
                case PARAM_LENGTH:
                case PARAM_MMAP:
                case PARAM_PROTECTION:
                    return true;
                default:
                    return false;
            }
        case METHOD_TRAMPOLINE:
            switch (paramName)
            {
                case PARAM_NAME:
                case PARAM_TEMPLATE:
                    return true;
                default:
                    return false;
            }
        case METHOD_OPTIONS:
            switch (paramName)
            {
                case PARAM_ARGV:
                    return true;
                default:
                    return false;
            }
        default:
            return false;
    }
}

/*
 * Create a BYTES template entry.
 */
static Entry makeBytesEntry(std::vector<uint8_t> &bytes)
{
    Entry entry;
    entry.kind   = ENTRY_BYTES;
    entry.length = (unsigned)bytes.size();
    entry.bytes  = dupBytes(bytes);
    return entry;
}

/*
 * Create a MACRO template entry.
 */
static Entry makeMacroEntry(const char *macro)
{
    Entry entry;
    entry.kind   = ENTRY_MACRO;
    entry.length = 0;
    entry.macro  = nullptr;

    // Check for built-in macros:
    switch (macro[1])
    {
        case 'B':
            if (strcmp(macro, "$BREAK") == 0)
            {
                entry.kind = ENTRY_BREAK;
                entry.optimize = true;
                return entry;
            }
            break;
        case 'b':
            if (strcmp(macro, "$bytes") == 0)
            {
                entry.kind = ENTRY_INSTR_BYTES;
                return entry;
            }
            else if (strcmp(macro, "$break") == 0)
            {
                entry.kind = ENTRY_BREAK;
                return entry;
            }
            break;
        case 'i':
            if (strcmp(macro, "$instr") == 0)
            {
                entry.kind = ENTRY_INSTR;
                return entry;
            }
            break;
        case 't':
            if (strcmp(macro, "$take") == 0)
            {
                entry.kind = ENTRY_TAKE;
                return entry;
            }
            break;
        default:
            break;
    }

    // User-define macro:
    entry.macro = dupString(macro);
    return entry;
}

/*
 * Create a LABEL template entry.
 */
static Entry makeLabelEntry(const char *label)
{
    Entry entry;
    entry.kind   = ENTRY_LABEL;
    entry.length = 0;
    entry.label  = dupString(label);
    return entry;
}

/*
 * Create a DEBUG template entry.
 */
static Entry makeDebugEntry(void)
{
    Entry entry;
    entry.kind   = ENTRY_DEBUG;
    entry.length = 0;
    entry.macro  = nullptr;
    return entry;
}

/*
 * Create a ZEROES template entry.
 */
static Entry makeZeroesEntry(size_t len)
{
    Entry entry;
    entry.kind   = ENTRY_ZEROES;
    entry.length = (unsigned)len;
    return entry;
}

/*
 * Make padding.
 */
Trampoline *makePadding(size_t len)
{
    if (len == 0)
        return nullptr;
    size_t num_entries = 1;
    uint8_t *ptr =
        new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
    Trampoline *T  = (Trampoline *)ptr;
    T->prot        = PROT_READ | PROT_EXEC;
    T->num_entries = num_entries;
    T->preload     = false;
    T->entries[0]  = makeZeroesEntry(len);

    return T;
}

/*
 * Convert an integer.
 */
static uintptr_t convertInteger(const Parser &parser, intptr_t x,
    intptr_t min, intptr_t max, unsigned bits)
{
    if (x < min || x > max)
        parse_error(parser, "failed to parse %u-bit integer; value %zd is "
            "not within the range %zd..%zd", bits, x, min, max);
    if (x < 0)
        x += (max + 1);
    return x;
}

/*
 * Create a data template entry.
 */
static Entry makeDataEntry(Parser &parser)
{
    expectToken(parser, TOKEN_STRING);
    Entry entry; 
    memset(&entry, 0x0, sizeof(entry));
    entry.kind   = ENTRY_LABEL;

    switch (parser.s[0])
    {
        case 'i':
            if (strcmp(parser.s, "int8") == 0)
                entry.kind = ENTRY_INT8;
            else if (strcmp(parser.s, "int16") == 0)
                entry.kind = ENTRY_INT16;
            else if (strcmp(parser.s, "int32") == 0)
                entry.kind = ENTRY_INT32;
            else if (strcmp(parser.s, "int64") == 0)
                entry.kind = ENTRY_INT64;
            else
                goto type_error;
            break;
        case 'r':
            if (strcmp(parser.s, "rel8") == 0)
                entry.kind = ENTRY_REL8;
            else if (strcmp(parser.s, "rel32") == 0)
                entry.kind = ENTRY_REL32;
            else
                goto type_error;
            break;
        case 's':
            if (strcmp(parser.s, "string") == 0)
                entry.kind = ENTRY_BYTES;
            else
                goto type_error;
            break;
        case 'z':
            if (strcmp(parser.s, "zeroes") == 0)
                entry.kind = ENTRY_ZEROES;
            break;
        default:
type_error:
            parse_error(parser, "failed to data type; unknown type name "
                "\"%s\"", parser.s);
    }

    expectToken(parser, ':');
    switch (entry.kind)
    {
        case ENTRY_BYTES:
        {
            expectToken(parser, TOKEN_STRING);
            entry.length = strlen(parser.s)+1;
            entry.bytes  = dupBytes(parser.s);
            break;
        }
        case ENTRY_ZEROES:
        {
            expectToken(parser, TOKEN_NUMBER);
            entry.length = (unsigned)parser.i;
            break;
        }

        case ENTRY_INT8:
        case ENTRY_INT16:
        case ENTRY_INT32:
        case ENTRY_INT64:
        {
            char token = expectToken2(parser, TOKEN_NUMBER, TOKEN_STRING);
            if (token == TOKEN_STRING && parser.s[0] == '.' &&
                    parser.s[1] == 'L')
            {
                entry.use = true;
                entry.label = dupString(parser.s);
            }
            else
            {
                intptr_t x;
                if (token == TOKEN_NUMBER)
                    x = (intptr_t)parser.i;
                else
                    x = stringToNumber(parser);
                switch (entry.kind)
                {
                    case ENTRY_INT8:
                        entry.uint8 = (uint8_t)convertInteger(parser, x,
                            INT8_MIN, UINT8_MAX, 8);
                        break;
                    case ENTRY_INT16:
                        entry.uint16 = (uint16_t)convertInteger(parser, x,
                            INT16_MIN, UINT16_MAX, 16);
                        break;
                    case ENTRY_INT32:
                        entry.uint32 = (uint32_t)convertInteger(parser, x,
                            INT32_MIN, UINT32_MAX, 32);
                        break;
                    default:
                        entry.uint64 = (uint64_t)x;
                        break;
                }
            }
            break;
        }

        case ENTRY_REL8:
        case ENTRY_REL32:
        {
            char token = expectToken2(parser, TOKEN_NUMBER, TOKEN_STRING);
            if (token == TOKEN_STRING && parser.s[0] == '.' &&
                    parser.s[1] == 'L')
            {
                entry.use = true;
                entry.label = dupString(parser.s);
            }
            else
            {
                entry.use = false;
                if (token == TOKEN_NUMBER)
                    entry.uint64 = (uint64_t)parser.i;
                else
                    entry.uint64 = (uint64_t)stringToNumber(parser);
            }
            break;
        }

        default:
            break;
    }
    expectToken(parser, '}');

    return entry;
}

/*
 * Parse a template object.
 */
static Trampoline *parseTrampoline(Parser &parser, bool debug = false)
{
    std::vector<uint8_t> bytes;
    std::vector<Entry> entries;

    if (debug)
        entries.push_back(makeDebugEntry());

    char token = getToken(parser);
    bool once  = true;
    if (token == '[')
    {
        once = false;
        token = getToken(parser);
    }
    while (token != ']')
    {
        if (token == TOKEN_NUMBER)
        {
            if (parser.i < 0 || parser.i > UINT8_MAX)
                parse_error(parser, "failed to parse byte; value (%zd) is "
                    "outside of the byte range (%d..%d)", parser.i, 0,
                    UINT8_MAX);
            bytes.push_back((uint8_t)parser.i);
        }
        else
        {
            if (bytes.size() > 0)
            {
                entries.push_back(makeBytesEntry(bytes));
                bytes.clear();
            }
            switch (token)
            {
                case TOKEN_STRING:
                    switch (parser.s[0])
                    {
                        case '$':
                            entries.push_back(makeMacroEntry(parser.s));
                            break;
                        case '.':
                            if (parser.s[1] == 'L')
                            {
                                entries.push_back(makeLabelEntry(parser.s));
                                break;
                            }
                            // Fallthrough:
                        default:
                            unexpectedToken(parser, "template entry", token);
                    }
                    break;

                case '{':
                    entries.push_back(makeDataEntry(parser));
                    break;
 
                case TOKEN_NULL:
                    break;

                default:
                    unexpectedToken(parser, "template entry", token);
            }
        }
        if (once)
            break;
        token = expectToken2(parser, ',', ']');
        if (token == ',')
            token = getToken(parser);
    }
    if (bytes.size() > 0)
        entries.push_back(makeBytesEntry(bytes));

    return dupTrampoline(entries);
};

/*
 * Parse a bytes object.
 */
static Trampoline *parseBytes(Parser &parser)
{
    std::vector<uint8_t> bytes;

    expectToken(parser, '[');
    char token = getToken(parser);
    while (token != ']')
    {
        if (token != TOKEN_NUMBER)
            unexpectedToken(parser, "bytes entry", token);
        if (parser.i < 0 || parser.i > UINT8_MAX)
            parse_error(parser, "failed to parse byte; value (%zd) is "
                "outside of the byte range (%d..%d)", parser.i, 0, UINT8_MAX);
        bytes.push_back((uint8_t)parser.i);
        token = expectToken2(parser, ',', ']');
        if (token == ',')
            token = getToken(parser);
    }

    size_t num_entries = 1;
    uint8_t *ptr =
        new uint8_t[sizeof(Trampoline) + num_entries * sizeof(Entry)];
    Trampoline *T  = (Trampoline *)ptr;
    T->prot        = PROT_READ | PROT_EXEC;
    T->num_entries = num_entries;
    T->preload     = false;
    T->entries[0]  = makeBytesEntry(bytes);
    
    return T;
}

/*
 * Parse instruction metadata.
 */
static Metadata *parseMetadata(Parser &parser)
{
    std::map<const char *, Trampoline *, CStrCmp> entries;

    expectToken(parser, '{');
    char token = expectToken2(parser, '}', TOKEN_STRING);
    while (token != '}')
    {
        if (parser.s[0] != '$')
            parse_error(parser, "failed to parse instruction metadata; "
                "macro name must begin with a `$', found \"%s\"", parser.s);
        auto i = entries.find(parser.s);
        if (i != entries.end())
            parse_error(parser, "failed to parse instruction metadata; "
                "duplicate entry for \"%s\"", parser.s);
        const char *name = dupString(parser.s);
        expectToken(parser, ':');
        Trampoline *T = parseTrampoline(parser);
        entries.insert(std::make_pair(name, T));
        token = expectToken2(parser, ',', '}');
        if (token == ',')
             token = getToken(parser);
    }

    size_t num_entries = entries.size();
    uint8_t *ptr = new uint8_t[sizeof(Metadata) +
        num_entries * sizeof(MetaEntry)];
    Metadata *meta = (Metadata *)ptr;
    meta->num_entries = num_entries;
    size_t i = 0;
    for (auto pair: entries)
    {
        meta->entries[i].name = pair.first;
        meta->entries[i].T    = pair.second;
        i++;
    }
    return meta;
}

/*
 * Parse strings.
 */
static char * const *parseStrings(Parser &parser, const char *first = nullptr)
{
    std::vector<const char *> strings;
    if (first != nullptr)
        strings.push_back(dupString(first));

    expectToken(parser, '[');
    char token = expectToken2(parser, ']', TOKEN_STRING);
    while (token != ']')
    {
        if (token != TOKEN_STRING)
            unexpectedToken(parser, "strings entry", token);
        strings.push_back(dupString(parser.s));
        token = expectToken2(parser, ',', ']');
        if (token == ',')
            token = getToken(parser);
    }

    char **ss = new char *[strings.size()+1];
    size_t i;
    for (i = 0; i < strings.size(); i++)
        ss[i] = (char *)strings[i];
    ss[i] = nullptr;
    return (char * const *)ss;
}

/*
 * Parse a protection.
 */
static int parseProtection(const Parser &parser, unsigned i, char c, int prot)
{
    const char *str = parser.s;
    if (str[i] == c)
        return prot;
    else if (str[i] == '-')
        return 0;
    else
        parse_error(parser, "failed to parse protection string \"%s\"; "
            "expected `%c' or '-', found `%c'", str, c, str[i]);
}

/*
 * Parse a parameter object.
 */
static void parseParams(Parser &parser, Message &msg)
{
    msg.num_params = 0;
    expectToken(parser, '{');
    char token = expectToken2(parser, '}', TOKEN_STRING);
    if (token == '}')
        return;
    while (true)
    {
        ParamName name = PARAM_UNKNOWN;
        switch (parser.s[0])
        {
            case 'a':
                if (strcmp(parser.s, "address") == 0)
                    name = PARAM_ADDRESS;
                else if (strcmp(parser.s, "absolute") == 0)
                    name = PARAM_ABSOLUTE;
                else if (strcmp(parser.s, "argv") == 0)
                    name = PARAM_ARGV;
                break;
            case 'b':
                if (strcmp(parser.s, "bytes") == 0)
                    name = PARAM_BYTES;
                break;
            case 'f':
                if (strcmp(parser.s, "filename") == 0)
                    name = PARAM_FILENAME;
                else if (strcmp(parser.s, "format") == 0)
                    name = PARAM_FORMAT;
                else if (strcmp(parser.s, "fini") == 0)
                    name = PARAM_FINI;
                break;
            case 'i':
                if (strcmp(parser.s, "init") == 0)
                    name = PARAM_INIT;
                break;
            case 'l':
                if (strcmp(parser.s, "length") == 0)
                    name = PARAM_LENGTH;
                break;
            case 'o':
                if (strcmp(parser.s, "offset") == 0)
                    name = PARAM_OFFSET;
                break;
            case 'p':
                if (strcmp(parser.s, "protection") == 0)
                    name = PARAM_PROTECTION;
                break;
            case 'm':
                if (strcmp(parser.s, "metadata") == 0)
                    name = PARAM_METADATA;
                else if (strcmp(parser.s, "mode") == 0)
                    name = PARAM_MODE;
                else if (strcmp(parser.s, "mmap") == 0)
                    name = PARAM_MMAP;
                break;
            case 'n':
                if (strcmp(parser.s, "name") == 0)
                    name = PARAM_NAME;
                break;
            case 't':
                if (strcmp(parser.s, "trampoline") == 0)
                    name = PARAM_TRAMPOLINE;
                else if (strcmp(parser.s, "template") == 0)
                    name = PARAM_TEMPLATE;
                break;
        }
        expectToken(parser, ':');
        if (!validateParam(msg.method, name))
            parseAndDiscardObject(parser);
        else
        {
            ParamValue value;
            value.string = nullptr;
            switch (name)
            {
                case PARAM_ADDRESS:
                case PARAM_OFFSET:
                case PARAM_LENGTH:
                case PARAM_INIT:
                case PARAM_FINI:
                case PARAM_MMAP:
                    token = expectToken2(parser, TOKEN_NUMBER, TOKEN_STRING);
                    if (token == TOKEN_NUMBER)
                        value.integer = (intptr_t)parser.i;
                    else
                        value.integer = stringToNumber(parser);
                    break;
                case PARAM_ABSOLUTE:
                    expectToken(parser, TOKEN_BOOL);
                    value.boolean = parser.b;
                    break;
                case PARAM_ARGV:
                    value.strings = parseStrings(parser, "<option>");
                    break;
                case PARAM_FILENAME:
                case PARAM_NAME:
                    expectToken(parser, TOKEN_STRING);
                    value.string = dupString(parser.s);
                    break;
                case PARAM_TRAMPOLINE:
                    value.trampoline = parseTrampoline(parser, /*debug=*/true);
                    break;
                case PARAM_TEMPLATE:
                    value.trampoline = parseTrampoline(parser);
                    break;
                case PARAM_METADATA:
                    value.metadata = parseMetadata(parser);
                    break;
                case PARAM_PROTECTION:
                {
                    expectToken(parser, TOKEN_STRING);
                    int prot = PROT_NONE;
                    prot |= parseProtection(parser, 0, 'r', PROT_READ);
                    prot |= parseProtection(parser, 1, 'w', PROT_WRITE);
                    prot |= parseProtection(parser, 2, 'x', PROT_EXEC);
                    if (parser.s[3] != '\0')
                        parse_error(parser, "failed to parse protection "
                            "string \"%s\"; string length must be 3",
                            parser.s, parser.s[0]);
                    value.integer = (intptr_t)prot;
                    break;
                }
                case PARAM_BYTES:
                    value.trampoline = parseBytes(parser);
                    break;
                case PARAM_FORMAT:
                    expectToken(parser, TOKEN_STRING);
                    if (strcmp(parser.s, "binary") == 0)
                        value.integer = (intptr_t)FORMAT_BINARY;
                    else if (strcmp(parser.s, "patch") == 0)
                        value.integer = (intptr_t)FORMAT_PATCH;
                    else if (strcmp(parser.s, "patch.gz") == 0)
                        value.integer = (intptr_t)FORMAT_PATCH_GZ;
                    else if (strcmp(parser.s, "patch.bz2") == 0)
                        value.integer = (intptr_t)FORMAT_PATCH_BZIP2;
                    else if (strcmp(parser.s, "patch.xz") == 0)
                        value.integer = (intptr_t)FORMAT_PATCH_XZ;
                    else
                        parse_error(parser, "failed to parse format string "
                            "\"%s\"; expected one of {\"binary\", \"patch\", "
                            "\"patch.gz\", \"patch.bz2\", \"patch.xz\"}",
                            parser.s);
                    break;
                case PARAM_MODE:
                    expectToken(parser, TOKEN_STRING);
                    if (strcmp(parser.s, "elf.exe") == 0)
                        value.integer = (intptr_t)MODE_ELF_EXE;
                    else if (strcmp(parser.s, "elf.dso") == 0)
                        value.integer = (intptr_t)MODE_ELF_DSO;
                    else if (strcmp(parser.s, "pe.exe") == 0)
                        value.integer = (intptr_t)MODE_PE_EXE;
                    else if (strcmp(parser.s, "pe.dll") == 0)
                        value.integer = (intptr_t)MODE_PE_DLL;
                    else
                        parse_error(parser, "failed to parse mode string "
                            "\"%s\"; expected one of {\"elf.exe\", "
                            "\"elf.dso\", \"pe.exe\", \"pe.dll\"}", parser.s);
                    break;
                case PARAM_UNKNOWN:
                    parseAndDiscardObject(parser);
                    break;
            }
            if (msg.num_params >= PARAM_MAX)
                parse_error(parser, "failed to parse JSON message; number of "
                    "parameters exceeds the maximum (%u)", PARAM_MAX);
            msg.params[msg.num_params].name  = name;
            msg.params[msg.num_params].value = value;
            msg.num_params++;
        }
        token = expectToken2(parser, '}', ',');
        if (token == '}')
            return;
        token = expectToken2(parser, TOKEN_STRING, '}');
        if (token == '}')
            return;
    }
}

/*
 * Convert a method into a string for error reporting.
 */
const char *getMethodString(Method method)
{
    switch (method)
    {
        case METHOD_BINARY:
            return "binary";
        case METHOD_INSTRUCTION:
            return "instruction";
        case METHOD_PATCH:
            return "patch";
        case METHOD_TRAMPOLINE:
            return "trampoline";
        case METHOD_EMIT:
            return "emit";
        default:
            return "???";
    }
}

/*
 * Parse a message from the given stream.
 */
bool getMessage(FILE *stream, size_t lineno, Message &msg)
{
    Parser parser(stream, lineno);

    char token = expectToken2(parser, '{', EOF);
    if (token == EOF)
        return false;
    expectString(parser, "jsonrpc");
    expectToken(parser, ':');
    expectString(parser, "2.0");
    expectToken(parser, ',');
    expectString(parser, "method");
    expectToken(parser, ':');
    expectToken(parser, TOKEN_STRING);
    msg.method = METHOD_UNKNOWN;
    switch (parser.s[0])
    {
        case 'b':
            if (strcmp(parser.s, "binary") == 0)
                msg.method = METHOD_BINARY;
            break;
        case 'e':
            if (strcmp(parser.s, "emit") == 0)
                msg.method = METHOD_EMIT;
            break;
        case 'i':
            if (strcmp(parser.s, "instruction") == 0)
                msg.method = METHOD_INSTRUCTION;
            break;
        case 'o':
            if (strcmp(parser.s, "options") == 0)
                msg.method = METHOD_OPTIONS;
            break;
        case 'p':
            if (strcmp(parser.s, "patch") == 0)
                msg.method = METHOD_PATCH;
            break;
        case 'r':
            if (strcmp(parser.s, "reserve") == 0)
                msg.method = METHOD_RESERVE;
            break;
        case 't':
            if (strcmp(parser.s, "trampoline") == 0)
                msg.method = METHOD_TRAMPOLINE;
            break;
    }
    expectToken(parser, ',');
    expectString(parser, "params");
    expectToken(parser, ':');
    parseParams(parser, msg);
    expectToken(parser, ',');
    expectString(parser, "id");
    expectToken(parser, ':');
    expectToken(parser, TOKEN_NUMBER);
    msg.lineno = parser.lineno;
    msg.id = parser.i;
    expectToken(parser, '}');
    return true;
}

