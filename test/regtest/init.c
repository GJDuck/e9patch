/*
 * Mmap & init.
 */

#include "stdlib.c"

void *_mmap(void *addr, size_t length, int prot, int flags, int fd,
    off_t offset)
{
    static bool seen = false;
    if (!seen)
        fprintf(stderr, "mmap() intercepted\n");
    seen = true;
    prot |= PROT_WRITE;
    return mmap(addr, length, prot, flags, fd, offset);
}

asm
(
    ".section .preinit, \"ax\"\n"
    "mov $1,%eax\n"
    "mov $2,%edi\n"
    "lea .LPREINIT(%rip),%rsi\n"
    "mov $8,%edx\n"
    "syscall\n"
    "retq\n"
    ".LPREINIT:\n"
    ".ascii \"preinit\\n\"\n"
);

asm
(
    ".section .postinit, \"ax\"\n"
    "mov $1,%eax\n"
    "mov $2,%edi\n"
    "lea .LPOSTINIT(%rip),%rsi\n"
    "mov $9,%edx\n"
    "syscall\n"
    "retq\n"
    ".LPOSTINIT:\n"
    ".ascii \"postinit\\n\"\n"
);

void init(int argc, char **argv, char **envp, void *dynamic)
{
    fprintf(stderr, "init argv = ");
    for (int i = 0; i < argc; i++)
        fprintf(stderr, "\"%s\" ", argv[i]);
    fputc('\n', stderr);
}

void nop(void)
{
    ;
}

const void *once(uint8_t *trampoline, const void *addr, const void *next,
    char *_asm)
{
    fprintf(stderr, "%p: %s\n", addr, _asm);
    trampoline[0] = /*int3=*/0xcc;
    if (addr == (void *)0xa00028a)
        return (void *)0xa000100;
    return next;
}

