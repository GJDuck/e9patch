/*
 * COUNT instrumentation.
 */

/*
 * Instruction counting instrumentation.
 * Will periodically print the count to the terminal (controlled by FREQ).
 *
 * EXAMPLE USAGE:
 *  $ e9compile count.c
 *  $ e9tool -M jmp -P 'entry()@count' xterm
 *  $ FREQ=1000 ./a.out
 */

#include "stdlib.c"

/*
 * The counter.
 */
static size_t freq      = 0;
static size_t counter_2 = 0;
static size_t counter   = 0;

/*
 * Entry Point.
 */
void entry(void)
{
    counter++;
    if (counter == freq)
    {
        counter = 0;
        counter_2++;
        fprintf(stderr, "count = %zu\n", freq * counter_2);
    }
}

/*
 * Init.
 */
void init(int argc, char **argv, char **envp)
{
    environ = envp;
    freq = 1000000;
    const char *val = getenv("FREQ");
    if (val != NULL)
        freq = atoll(val);
}

