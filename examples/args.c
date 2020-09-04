/*
 * ARGS instrumentation.
 */

#include <stdint.h>

/*
 * strcat()
 */
static char *str_cat(const char *string, char *str)
{
    char c;
    while ((c = *string++) != '\0')
        *str++ = c;
    return str;
}

/*
 * Print hex.
 */
static const char digs[] = "0123456789abcdef";
static char *hex_to_str(intptr_t x, char *str)
{
    int shift = (15 * 4);
    while (shift >= 0)
    {
        char c = digs[(x >> shift) & 0xF];
        shift -= 4;
        *str++ = c;
    }
    return str;
}

/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8)
{
    char buf[512];
    char *str = buf;

    str = str_cat("\33[33m", str);
    str = hex_to_str(arg1, str);
    str = str_cat(" \33[0m", str);
    str = hex_to_str(arg2, str);
    str = str_cat(" \33[33m", str);
    str = hex_to_str(arg3, str);
    str = str_cat(" \33[0m", str);
    str = hex_to_str(arg4, str);
    str = str_cat(" \33[33m", str);
    str = hex_to_str(arg5, str);
    str = str_cat(" \33[0m", str);
    str = hex_to_str(arg6, str);
    str = str_cat(" \33[33m", str);
    str = hex_to_str(arg7, str);
    str = str_cat(" \33[0m", str);
    str = hex_to_str(arg8, str);
    *str++ = '\n';

    register const char *str_ptr asm("rsi") = buf;
    register unsigned long long str_len asm("rdx") = str - buf;
    
    asm volatile (
        "mov $0x2,%%edi\n"
        "mov $0x1,%%eax\n"
        "syscall\n": : "r"(str_ptr), "r"(str_len):
            "rdi", "rax", "rcx", "r11");
}

