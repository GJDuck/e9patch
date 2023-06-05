/*
 * PRINTF instrumentation.
 */

/*
 * Exports "printf" from stdlib.c so it can be called directly.
 *
 * EXAMPLE USAGE:
 *  $ e9compile printf.c
 *  $ e9tool -M jmp -P 'printf("0x%lx: %s\n",(static)addr,asm)@printf' xterm
 *  $ ./a.out
 */

#define printf e9_printf        // Hack to rename stdlib printf
#include "stdlib.c"
#undef printf

void printf(const char *msg, intptr_t arg1, intptr_t arg2, intptr_t arg3,
    intptr_t arg4, intptr_t arg5, intptr_t arg6, intptr_t arg7)
{
    e9_printf(msg, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

