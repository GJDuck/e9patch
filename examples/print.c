/*
 * PRINT instrumentation.
 */

/*
 * Prints information about the currently executing instruction to stderr.
 *
 * EXAMPLE USAGE:
 *  $ e9compile print.c
 *  $ e9tool -M jmp -P 'entry((static)addr,bytes,size,asm)@print' xterm
 *  $ ./a.out
 */

#include "stdlib.c"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 */
void entry(const void *addr, const uint8_t *instr, size_t size,
    const char *_asm)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    if (mutex_lock(&mutex) < 0)
        return;

    clearerr(stderr);
    fprintf(stderr, RED "%.16lx" WHITE ": " YELLOW, addr);
    int i;
    for (i = 0; i < size; i++)
    {
        fprintf(stderr, "%.2x ", instr[i]);
        if (i == 7 && size > 8)
            fprintf(stderr, GREEN "%s" WHITE "\n                  "
                YELLOW, _asm);
    }
    if (i <= 8)
    {
        for (; i < 8; i++)
            fputs("   ", stderr);
        fprintf(stderr, GREEN "%s", _asm);
    }
    fputs(WHITE "\n", stderr);
    fflush(stderr);

    mutex_unlock(&mutex);
}

/*
 * Init.
 */
void init(void)
{
    setvbuf(stderr, NULL, _IOFBF, 0);
}

