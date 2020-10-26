/*
 * Instruction counting instrumentation.
 */

#include "stdlib.c"

/*
 * The counter.
 */
static size_t freq      = 0;
static size_t counter_2 = 0;
static size_t counter   = 0;

/*
 * Instrumentation (note: not thread-safe!).
 *
 * call entry@counter
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
 * Initialization.
 */
void init(int argc, char **argv, char **envp)
{
    environ = envp;
    freq = 1000000;
    const char *val = getenv("FREQ");
    if (val != NULL)
        freq = atoll(val);
}

