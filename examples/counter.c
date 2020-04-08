/*
 * Instruction counting instrumentation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * The counter.
 */
static size_t freq      = 0;
static size_t counter_2 = 0;
static size_t counter   = 0;

/*
 * Number-to-string helper.
 */
static char *num_to_str(size_t x, char *str)
{
    if (x == 0)
    {
        *str++ = '0';
        return str;
    }
    size_t r = 10000000000000000000ull;
    int seen = 0;
    while (r != 0)
    {
        char c = '0' + x / r;
        x %= r;
        r /= 10;
        if (!seen && c == '0')
            continue;
        seen = 1;
        *str++ = c;
    }
    return str;
}

/*
 * Print number helper.
 */
static __attribute__((__noinline__)) void print_counter(size_t r)
{
    char buf[BUFSIZ];
    char *str = buf;

    static const char *header = "count = ";
    for (unsigned i = 0; header[i] != '\0'; i++)
        *str++ = header[i];
    
    str = num_to_str(r, str);
    *str++ = '\n';

    register int fd asm("rdi") = STDERR_FILENO;
    register const char *buf1 asm("rsi") = buf;
    register size_t len asm("rdx") = str - buf;
    register int err asm("rax");
    asm volatile (
        "mov $1, %%eax\n\t"             // SYS_WRITE
        "syscall"
        : "=rax"(err) : "r"(fd), "r"(buf1), "r"(len) : "rcx", "r11");
}

/*
 * Instrumentation (note: not thread-safe!).
 */
void entry(void)
{
    counter++;
    if (counter == freq)
    {
        counter = 0;
        counter_2++;
        print_counter(freq * counter_2);
    }
}

/*
 * Initialization.
 */
void init(int argc, char **argv, char **envp)
{
    freq = 1000000;
    for (; envp && *envp != NULL; envp++)
    {
        char *var = *envp;
        if (var[0] == 'F' &&
            var[1] == 'R' &&
            var[2] == 'E' &&
            var[3] == 'Q' &&
            var[4] == '=')
        {
            unsigned val = 0;
            for (unsigned i = 5; var[i] >= '0' && var[i] <= '9'; i++)
                val = 10 * val + (var[i] - '0');
            freq = val;
            break;
        }
    }
}

