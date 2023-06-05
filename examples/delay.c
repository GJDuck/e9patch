/*
 * DELAY instrumentation
 */

/*
 * Adds a configurable busy-loop delay to each instruction.
 *
 * EXAMPLE USAGE:
 *  $ e9compile delay.c
 *  $ e9tool -M jmp -P 'entry()@delay' xterm
 *  $ DELAY=100000 ./a.out
 */

#include "stdlib.c"

static unsigned delay = 0;

void entry(void)
{
    for (unsigned i = 0; i < delay; i++)
        asm volatile ("");
}

void init(int argc, char **argv, char **envp)
{
    environ = envp;
    const char *val = getenv("DELAY");
    if (val != NULL)
        delay = (unsigned)atoi(val);
}

