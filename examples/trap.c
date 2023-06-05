/*
 * TRAP instrumentation.
 */

/*
 * Causes a trap (int3) to be executed for each matching instruction.
 *
 * EXAMPLE USAGE:
 *  $ e9compile trap.c
 *  $ e9tool -M jmp -P 'entry()@trap' xterm
 *  $ ./a.out
 */

void entry(void)
{
    asm volatile ("int3");
}

