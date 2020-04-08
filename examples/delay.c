/*
 * configurable DELAY instrumentation (does nothing, but slowly).
 */

#define NULL ((void *)0x0)

static unsigned delay = 0;

void entry(void)
{
    for (unsigned i = 0; i < delay; i++)
        asm volatile ("");
}

void init(int argc, char **argv, char **envp)
{
    for (; envp && *envp != NULL; envp++)
    {
        char *var = *envp;
        if (var[0] == 'D' &&
            var[1] == 'E' &&
            var[2] == 'L' &&
            var[3] == 'A' &&
            var[4] == 'Y' &&
            var[5] == '=')
        {
            unsigned val = 0;
            for (unsigned i = 6; var[i] >= '0' && var[i] <= '9'; i++)
                val = 10 * val + (var[i] - '0');
            delay = val;
            break;
        }
    }
}

