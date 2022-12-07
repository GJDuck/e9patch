#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef putchar
#undef putchar
#endif

asm (
    ".globl entry\n"
    ".set entry,0x0\n"
);

static __attribute__((__noinline__)) void init_msg(char *msg)
{
    msg[0] = 'H';
    msg[1] = 'e';
    msg[2] = 'l';
    msg[3] = 'l';
    msg[4] = 'o';
    msg[5] = ' ';
    msg[6] = 'w';
    msg[7] = 'o';
    msg[8] = 'r';
    msg[9] = 'l';
    msg[10] = 'd';
    msg[11] = '!';
    msg[12] = '\n';
    msg[13] = '\0';
}

__attribute__((__noinline__)) size_t fib(size_t n)
{
    if (n == 0)
        return 1;       // BUG!
    else if (n == 1)
        return 1;
    else
        return fib(n-1) + fib(n-2);
}

__attribute__((__noinline__)) bool is_prime(size_t n)
{
    if (n == 0 || n == 1)
        return false;
    if (n % 2 == 0)
        return false;
    for (size_t i = 3; i < n / 2; i++)
    {
        if (n % i == 0)
            return false;
    }
    return true;
}

__attribute__((__noinline__)) void triforce(ssize_t n)
{
    for (ssize_t i = 0; i <= n; i++)
    {
        for (ssize_t j = 0; j <= 2*n; j++)
            putchar(
                (j > n-i-1 && j < n+i+1 && !(i > n/2 && j > n-(n-i)-1 && j < n+(n-i)+1)?
                    '*': ' '));
        putchar('\n');
    }
}

void data_func_2(void)
{
    printf("invoked data_func()\n");
    asm volatile ("nop");
}

static void data_func(void)
{
    asm volatile (
        "xchg %r15, %r15\n"
        "callq data_func_2");
}

struct call_s
{
    void (*f)(void);
    const char *name;
};

static const struct call_s call_info = {data_func, "data_func"};

__attribute__((__noinline__)) void invoke(const struct call_s *info)
{
    printf("invoke %s()\n", info->name);
    fflush(stdout);
    info->f();
}

int main(void)
{
    printf("Hello world!\n");
    fflush(stdout);

    size_t size = strlen("Hello world!\n")+1;
    char *s = (char *)malloc(size);
    if (s == NULL)
    {
        fprintf(stderr, "error: failed to allocate %zu bytes!\n", size);
        abort();
    }
    init_msg(s);
    fputs(s, stdout);
    fflush(stdout);
    free(s);

    printf("fib = %zu\n", fib(10));
    printf("prime(121) = %d\n", is_prime(121));
    printf("prime(131) = %d\n", is_prime(131));
    triforce(9);

    fflush(stdout);
    invoke(&call_info);

    return 0;
}

