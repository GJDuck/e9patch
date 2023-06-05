/*
 * NOP instrumentation.
 */

/*
 * Does nothing.
 *
 * EXAMPLE USAGE:
 *  $ e9compile nop.c
 *  $ e9tool -M jmp -P 'entry()@nop' xterm
 *  $ ./a.out
 */

void entry(void)
{
    return;
}

