/*
 * ARGS instrumentation.
 */

#include "stdlib.c"

#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 *
 * call entry(...)
 */
void entry(intptr_t arg1, intptr_t arg2, intptr_t arg3, intptr_t arg4,
    intptr_t arg5, intptr_t arg6, intptr_t arg7, intptr_t arg8)
{
    fprintf(stderr, YELLOW "%.16lx" WHITE " %.16lx "
                    YELLOW "%.16lx" WHITE " %.16lx "
                    YELLOW "%.16lx" WHITE " %.16lx "
                    YELLOW "%.16lx" WHITE " %.16lx\n",
           arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}

