/*
 * fini.
 */

#include "stdlib.c"

void trap(void)
{
    asm ("int3");
}

void fini(void)
{
    fprintf(stderr, "fini() called on exit()\n");
}

