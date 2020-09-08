/*
 * PRINT instrumentation.
 */

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
static char *hex_to_str(unsigned long long x, char *str)
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
 * Print byte.
 */
static char *byte_to_str(unsigned char x, char *str)
{
    *str++ = digs[x >> 4];
    *str++ = digs[x & 0xF];
    return str;
}

/*
 * Entry point.
 *
 * call entry(addr,instr,instr.count,asm)@print
 */
void entry(void *addr, const unsigned char *instr, unsigned instr_count,
    const char *_asm)
{
    char buf[512];
    char *str = buf;

    unsigned i;
    str = str_cat("\33[31m", str);
    str = hex_to_str((unsigned long long)addr, str);
    for (i = (unsigned)(str - buf); i < 16; i++)
        *str++ = ' ';
    str = str_cat("\33[0m: \33[33m", str);
    for (i = 0; i < instr_count; i++)
    {
        str = byte_to_str(instr[i], str);
        *str++ = ' ';
        if (i == 7 && instr_count > 8)
        {
            str = str_cat("\33[32m", str);
            str = str_cat(_asm, str);
            str = str_cat("\33[33m\n                  ", str);
        }
    }
    if (i < 8)
    {
        for (; i < 8; i++)
            str = str_cat("   ", str);
        str = str_cat("\33[32m", str);
        str = str_cat(_asm, str);
    }
    str = str_cat("\33[0m\n", str);

    register const char *str_ptr asm("rsi") = buf;
    register unsigned long long str_len asm("rdx") = str - buf;
    
    asm volatile (
        "mov $0x2,%%edi\n"
        "mov $0x1,%%eax\n"
        "syscall\n": : "r"(str_ptr), "r"(str_len):
            "rdi", "rax", "rcx", "r11");
}

