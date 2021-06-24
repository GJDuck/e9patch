/*
 * instrumentation.
 */

#include "stdlib.c"

/*
 * Entry point.
 *
 * call entry(val0,val1,val2,instr,size,asm)@print
 */
void entry(const void *val0, const void *val1, const void *val2,
    const uint8_t *instr, size_t size, const char *_asm)
{
    clearerr_unlocked(stderr);
    fprintf_unlocked(stderr, "%.16lx:%.16lx:%.16lx: ", val0, val1, val2);
    int i;
    for (i = 0; i < size; i++)
    {
        fprintf_unlocked(stderr, "%.2x ", instr[i]);
        if (i == 7 && size > 8)
            fprintf_unlocked(stderr, "%s\n                                "
                "                    ", _asm);
    }
    if (i <= 8)
    {
        for (; i < 8; i++)
            fputs_unlocked("   ", stderr);
        fprintf_unlocked(stderr, "%s", _asm);
    }
    fputc_unlocked('\n', stderr);
    fflush_unlocked(stderr);
}

void init(void)
{
    setvbuf(stderr, NULL, _IOFBF, 0);
}



