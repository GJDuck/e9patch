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

