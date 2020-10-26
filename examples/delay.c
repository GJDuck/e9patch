/*
 * configurable DELAY instrumentation (does nothing, but slowly).
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

