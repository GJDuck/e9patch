/*
 * I/O instrumentation.
 */

/*
 * This exports "printf" from stdlib.c allowing it to be called directly
 * from the command-line, e.g.:
 *
 *  $ e9tool -M ... -P 'printf("addr=0x%lx\n",addr)@io'
 */

#define printf  __hide__printf
#include <stdio.h>
#undef printf

#include "stdlib.c"

#undef printf
void printf(const char *msg, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t arg7)
{
    e9_printf(msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

