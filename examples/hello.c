/*
 * "Hello World" instrumentation.
 */

#include <stdlib.h>
#include <unistd.h>

/*
 * Print "Hello World!"
 */
void entry(void)
{
    static const char string[] = "Hello World!\n";
    register int fd asm("rdi") = STDOUT_FILENO;
    register const char *buf asm("rsi") = string;
    register size_t len asm("rdx") = sizeof(string)-1;
    register int err asm("rax");
    asm volatile (
        "mov $1, %%eax\n\t"             // SYS_WRITE
        "syscall"
        : "=rax"(err) : "r"(fd), "r"(buf), "r"(len) : "rcx", "r11");
}

/*
 * Initialization.
 */
void _start(void)
{
    return;
}

