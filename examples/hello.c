/*
 * "Hello World" instrumentation.
 */

/*
 * Prints "Hello World" for each matching instruction.
 *
 * EXAMPLE USAGE:
 *  $ e9compile hello.c
 *  $ e9tool -M jmp -P 'entry()@hello' xterm
 *  $ ./a.out
 */

#include "stdlib.c"

/*
 * Entry point.
 */
void entry(void)
{
    puts("Hello World!");
}

