/*
 * Windows implementation of PRINT instrumentation (print.c)
 *
 * Example usage:
 *
 *    ./e9compile.sh examples/win64_demo.c -mabi=ms
 *    ./e9tool \
 *          -M 'asm=/xor.*/' \
 *          -P 'entry(config,addr,instr,size,asm)@win64_demo' \
 *          prog.exe
 *
 * NOTE: Do not forget to pass `-mabi=ms' to e9compile.sh else the demo will
 *       crash.
 */

/*
 * Notes:
 *  - This is mainly for proof-of-concept/testing.
 *  - There is currently no stdlib.c for Windows, so everything must be
 *    programmed from scratch...
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "../src/e9patch/e9loader.h"

typedef int (*set_console_text_attribute_t)(intptr_t, int16_t);
typedef int (*write_file_t)(intptr_t, void *, size_t, void *, void *);

/*
 * Windows library functions.
 */
#define FOREGROUND_BLUE      0x1
#define FOREGROUND_GREEN     0x2
#define FOREGROUND_RED       0x4
#define FOREGROUND_YELLOW    (FOREGROUND_RED | FOREGROUND_GREEN)
#define FOREGROUND_WHITE    \
    (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
static e9_safe_call_t safe_call = NULL;
static set_console_text_attribute_t set_console_text_attribute_fn = NULL;
static write_file_t write_file_fn = NULL;
static int SetConsoleTextAttribute(intptr_t handle, int16_t attr)
{
    return (int)safe_call(set_console_text_attribute_fn, handle, attr);
}
static int WriteFile(intptr_t handle, void *buf, size_t len, void *x,
    void *y)
{
    return (int)safe_call(write_file_fn, handle, buf, len, x, y);
}

/*
 * Get the stderr handle (& do some init if required).
 */
static intptr_t get_stderr(const struct e9_config_s *config)
{
    const struct e9_config_pe_s *config_pe =
        (const struct e9_config_pe_s *)(config + 1);
    if (safe_call == NULL)
        safe_call = config_pe->safe_call;
    if (set_console_text_attribute_fn == NULL)
        set_console_text_attribute_fn =
            (set_console_text_attribute_t)config_pe->get_proc_address(
                config_pe->kernel32, "SetConsoleTextAttribute");
    if (write_file_fn == NULL)
        write_file_fn =
            (write_file_t)config_pe->get_proc_address(
                config_pe->kernel32, "WriteFile");
    if (set_console_text_attribute_fn == NULL || write_file_fn == NULL)
        asm volatile ("ud2");
    return config_pe->stderr_handle;
}

/*
 * fprintf(...) adatped from stdlib.c
 */
#define PRINTF_FLAG_NEG        0x0001
#define PRINTF_FLAG_UPPER      0x0002
#define PRINTF_FLAG_HEX        0x0004
#define PRINTF_FLAG_PLUS       0x0008
#define PRINTF_FLAG_HASH       0x0010
#define PRINTF_FLAG_SPACE      0x0020
#define PRINTF_FLAG_RIGHT      0x0040
#define PRINTF_FLAG_ZERO       0x0080
#define PRINTF_FLAG_PRECISION  0x0100
#define PRINTF_FLAG_8          0x0200
#define PRINTF_FLAG_16         0x0400
#define PRINTF_FLAG_64         0x0800
static int isdigit(int c)
{
        return (c >= '0' && c <= '9');
}
static size_t strlen(const char *s)
{
    size_t len = 0;
    while (*s++ != '\0')
        len++;
    return len;
}
static __attribute__((__noinline__)) size_t printf_put_char(char *str,
    size_t size, size_t idx, char c)
{
    if (str == NULL || idx >= size)
        return idx+1;
    str[idx++] = c;
    return idx;
}
static __attribute__((__noinline__)) size_t printf_put_num(char *str,
    size_t size, size_t idx, unsigned flags, size_t width, size_t precision,
    unsigned long long x)
{
    char prefix[2] = {'\0', '\0'};
    char buf[32];
    size_t i = 0;
    if (flags & PRINTF_FLAG_HEX)
    {
        if (flags & PRINTF_FLAG_HASH)
        {
            prefix[0] = '0';
            prefix[1] = (flags & PRINTF_FLAG_UPPER? 'X': 'x');
        }
        const char digs[] = "0123456789abcdef";
        const char DIGS[] = "0123456789ABCDEF";
        const char *ds = (flags & PRINTF_FLAG_UPPER? DIGS: digs);
        int shift = (15 * 4);
        bool seen = false;
        while (shift >= 0)
        {
            char c = ds[(x >> shift) & 0xF];
            shift -= 4;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    else
    {
        if (flags & PRINTF_FLAG_NEG)
            prefix[0] = '-';
        else if (flags & PRINTF_FLAG_PLUS)
            prefix[0] = '+';
        else if (flags & PRINTF_FLAG_SPACE)
            prefix[0] = ' ';
        unsigned long long r = 10000000000000000000ull;
        bool seen = false;
        while (r != 0)
        {
            char c = '0' + x / r;
            x %= r;
            r /= 10;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    if ((flags & PRINTF_FLAG_ZERO) && !(flags & PRINTF_FLAG_PRECISION))
    {
        precision = width;
        width = 0;
    }
    size_t len_0 = i;
    size_t len_1 = (len_0 < precision? precision: len_0);
    size_t len   =
        len_1 + (prefix[0] != '\0'? 1 + (prefix[1] != '\0'? 1: 0): 0);
    if (!(flags & PRINTF_FLAG_RIGHT))
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    if (prefix[0] != '\0')
    {
        idx = printf_put_char(str, size, idx, prefix[0]);
        if (prefix[1] != '\0')
            idx = printf_put_char(str, size, idx, prefix[1]);
    }
    for (size_t i = 0; precision > len_0 && i < precision - len_0; i++)
        idx = printf_put_char(str, size, idx, '0');
    for (size_t i = 0; i < len_0; i++)
        idx = printf_put_char(str, size, idx, buf[i]);
    if (flags & PRINTF_FLAG_RIGHT)
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    return idx;
}
static int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    size_t idx = 0;
    for (; *format != '\0'; format++)
    {
        if (*format != '%')
        {
            idx = printf_put_char(str, size, idx, *format);
            continue;
        }
        format++;
        unsigned flags = 0x0;
        for (; true; format++)
        {
            switch (*format)
            {
                case ' ':
                    flags |= PRINTF_FLAG_SPACE;
                    continue;
                case '+':
                    flags |= PRINTF_FLAG_PLUS;
                    continue;
                case '-':
                    if (!(flags & PRINTF_FLAG_ZERO))
                        flags |= PRINTF_FLAG_RIGHT;
                    continue;
                case '#':
                    flags |= PRINTF_FLAG_HASH;
                    continue;
                case '0':
                    flags &= ~PRINTF_FLAG_RIGHT;
                    flags |= PRINTF_FLAG_ZERO;
                    continue;
                default:
                    break;
            }
            break;
        }

        size_t width = 0;
        if (*format == '*')
        {
            format++;
            int tmp = va_arg(ap, int);
            if (tmp < 0)
            {
                flags |= (!(flags & PRINTF_FLAG_ZERO)? PRINTF_FLAG_RIGHT: 0);
                width = (size_t)-tmp;
            }
            else
                width = (size_t)tmp;
        }
        else
        {
            for (; isdigit(*format); format++)
            {
                width *= 10;
                width += (unsigned)(*format - '0');
                width = (width > INT32_MAX? INT32_MAX: width);
            }
        }
        width = (width > INT16_MAX? INT16_MAX: width);

        size_t precision = 0;
        if (*format == '.')
        {
            flags |= PRINTF_FLAG_PRECISION;
            format++;
            if (*format == '*')
            {
                format++;
                int tmp = va_arg(ap, int);
                tmp = (tmp < 0? 0: tmp);
                precision = (size_t)tmp;
            }
            else
            {
                for (; isdigit(*format); format++)
                {
                    precision *= 10;
                    precision += (unsigned)(*format - '0');
                    precision = (precision > INT32_MAX? INT32_MAX: precision);
                }
            }
        }
        switch (*format)
        {
            case 'l':
                flags |= PRINTF_FLAG_64;
                format++;
                if (*format == 'l')
                    format++;
                break;
            case 'h':
                format++;
                if (*format == 'h')
                {
                    format++;
                    flags |= PRINTF_FLAG_8;
                }
                else
                    flags |= PRINTF_FLAG_16;
                break;
            case 'z': case 'j': case 't':
                format++;
                flags |= PRINTF_FLAG_64;
                break;
        }

        int64_t x;
        uint64_t y;
        const char *s;
        size_t len;
        bool end = false;
        switch (*format)
        {
            case '\0':
                end = true;
                break;
            case 'c':
                x = (int64_t)(char)va_arg(ap, int);
                idx = printf_put_char(str, size, idx, (char)x);
                break;
            case 'd': case 'i':
                if (flags & PRINTF_FLAG_8)
                    x = (int64_t)(int8_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_16)
                    x = (int64_t)(int16_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_64)
                    x = va_arg(ap, int64_t);
                else
                    x = (int64_t)va_arg(ap, int);
                if (x < 0)
                {
                    flags |= PRINTF_FLAG_NEG;
                    x = -x;
                }
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, (uint64_t)x);
                break;
            case 'X':
                flags |= PRINTF_FLAG_UPPER;
                // Fallthrough
            case 'x':
                flags |= PRINTF_FLAG_HEX;
                // Fallthrough
            case 'u':
                if (flags & PRINTF_FLAG_8)
                    y = (uint64_t)(uint8_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_16)
                    y = (uint64_t)(uint16_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_64)
                    y = va_arg(ap, uint64_t);
                else
                    y = (uint64_t)va_arg(ap, unsigned);
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 'p':
                y = (uint64_t)va_arg(ap, const void *);
                flags |= PRINTF_FLAG_HASH | PRINTF_FLAG_HEX;
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 's':
                s = va_arg(ap, const char *);
                s = (s == NULL? "(null)": s);
                len = strlen(s);
                len = ((flags & PRINTF_FLAG_PRECISION) && precision < len?
                    precision: len);
                if (!(flags & PRINTF_FLAG_RIGHT))
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                for (size_t i = 0; i < len; i++)
                    idx = printf_put_char(str, size, idx, s[i]);
                if (flags & PRINTF_FLAG_RIGHT)
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                break;
            default:
                idx = printf_put_char(str, size, idx, *format);
                break;
        }
        if (end)
            break;
    }
    (void)printf_put_char(str, size, idx, '\0');
    if (idx > INT32_MAX)
        return -1;
    return (int)idx;
}
static int vfprintf(intptr_t handle, const char *format, va_list ap)
{
    va_list ap1; 
    va_copy(ap1, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result < 0)
        return result;
    char buf[result+1];
    result = vsnprintf(buf, result+1, format, ap1);
    if (result < 0)
        return result;
    if (!WriteFile(handle, buf, strlen(buf), NULL, NULL))
        return -1;
    return result;
}
static int fprintf(intptr_t handle, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfprintf(handle, format, ap);
    va_end(ap);
    return result;
}

/*
 * Entry point.
 */
void entry(const struct e9_config_s *config, const void *addr,
	const uint8_t *instr, size_t size, const char *_asm)
{
    intptr_t stderr = get_stderr(config);

    SetConsoleTextAttribute(stderr, FOREGROUND_RED);
    fprintf(stderr, "%.16lx", addr);
    SetConsoleTextAttribute(stderr, FOREGROUND_WHITE);
    fprintf(stderr, ": ");
    SetConsoleTextAttribute(stderr, FOREGROUND_YELLOW);
    int i;
    for (i = 0; i < size; i++)
    {
        fprintf(stderr, "%.2x ", instr[i]);
        if (i == 7 && size > 8)
        {
            SetConsoleTextAttribute(stderr, FOREGROUND_GREEN);
            fprintf(stderr, "%s", _asm);
            SetConsoleTextAttribute(stderr, FOREGROUND_WHITE);
            fprintf(stderr, "\n                  ");
            SetConsoleTextAttribute(stderr, FOREGROUND_YELLOW);
        }
    }
    if (i <= 8)
    {
        for (; i < 8; i++)
            fprintf(stderr, "   ");
        SetConsoleTextAttribute(stderr, FOREGROUND_GREEN);
        fprintf(stderr, "%s", _asm);
    }
    SetConsoleTextAttribute(stderr, FOREGROUND_WHITE);
    fprintf(stderr, "\n");
}

