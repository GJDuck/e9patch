/*
 * e9loader.cpp
 * Copyright (C) 2021 National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * NOTE: As a special exception, this file is under the MIT license.  The
 *       rest of the E9Patch/E9Tool source code is under the GPLv3 license.
 */

/*
 * Common loader functions/definitions.
 */

#include "e9loader.h"

#define NO_INLINE    __attribute__((__noinline__))
#define NO_RETURN   __attribute__((__noreturn__))

#define BUFSIZ      8192
#define PAGE_SIZE   4096

/*
 * Low-level string formatting routines.
 */
static char *e9write_str(char *str, const char *s)
{
    while (*s != '\0')
        *str++ = *s++;
    return str;
}
static char *e9write_char(char *str, char c)
{
    *str++ = c;
    return str;
}
static NO_INLINE char *e9write_hex(char *str, uint64_t x)
{
    if (x == 0)
    {
        *str++ = '0';
        return str;
    }
    bool zero = false;
    int n = 15;
    do
    {
        unsigned digit = (unsigned)((x >> (n * 4)) & 0xF);
        n--;
        if (digit == 0 && !zero)
            continue;
        zero = true;
        if (digit <= 9)
            *str++ = '0' + digit;
        else
            *str++ = 'a' + (digit - 10);
    }
    while (n >= 0);
    return str;
}
static NO_INLINE char *e9write_num(char *str, uint64_t x)
{
    if (x == 0)
    {
        *str++ = '0';
        return str;
    }
    bool zero = false;
    uint64_t r = 10000000000000000000ull;
    do
    {
        unsigned digit = (unsigned)(x / r);
        x %= r;
        r /= 10;
        if (digit == 0 && !zero)
            continue;
        zero = true;
        *str++ = '0' + digit;
    }
    while (r > 0);
    return str;
}
static NO_INLINE char *e9write_format(char *str, const char *msg, va_list ap)
{
    char c;
    while ((c = *msg++) != '\0')
    {
        if (c == '%')
        {
            c = *msg++;
            const char *s;
            const wchar_t *S;
            uint64_t x;
            int64_t i;
            switch (c)
            {
                case '%':
                    str = e9write_char(str, '%');
                    break;
                case 'c':
                    c = (char)va_arg(ap, int);
                    str = e9write_char(str, c);
                    break;
                case 's':
                    s = va_arg(ap, const char *);
                    str = e9write_str(str, s);
                    break;
                case 'S':
                    S = va_arg(ap, const wchar_t *);
                    for (; *S != L'\0'; S++)
                        str = e9write_char(str, (*S < L'~'? (char)*S: '?'));
                    break;
                case 'p':
                    str = e9write_str(str, "0x");
                    // Fallthrough
                case 'x': case 'X':
                    x = (c == 'x'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    str = e9write_hex(str, x);
                    break;
                case 'u': case 'U':
                    x = (c == 'u'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    str = e9write_num(str, x);
                    break;
                case 'd': case 'D':
                    i = (c == 'd'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    if (i < 0)
                        str = e9write_char(str, '-');
                    str = e9write_num(str, (uint64_t)(i < 0? -i: i));
                    break;
            }
            continue;
        }
        str = e9write_char(str, c);
    }
    return str;
}
static char *e9write_format(char *str, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    return str;
}

