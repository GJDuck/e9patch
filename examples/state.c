/*
 * PRINT STATE instrumentation.
 */

/*
 * Prints the register state.
 *
 * EXAMPLE USAGE:
 *  $ e9compile state.c
 *  $ e9tool -M jmp -P 'entry(state,asm)@state' xterm
 *  $ ./a.out
 */

#include "stdlib.c"

/*
 * Colors.
 */
#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 */
void entry(const struct STATE *state, const char *_asm)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    if (mutex_lock(&mutex) < 0)
        return;
    clearerr(stderr);
    fprintf(stderr, RED "%.16lx" WHITE ": " GREEN "%s" WHITE "\n",
        state->rip, _asm);
    fprintf(stderr, "\t%rax    = 0x%.16lx (%ld)\n", state->rax, state->rax);
    fprintf(stderr, "\t%rcx    = 0x%.16lx (%ld)\n", state->rcx, state->rcx);
    fprintf(stderr, "\t%rdx    = 0x%.16lx (%ld)\n", state->rdx, state->rdx);
    fprintf(stderr, "\t%rbx    = 0x%.16lx (%ld)\n", state->rbx, state->rbx);
    fprintf(stderr, "\t%rsp    = 0x%.16lx (%ld)\n", state->rsp, state->rsp);
    fprintf(stderr, "\t%rbp    = 0x%.16lx (%ld)\n", state->rbp, state->rbp);
    fprintf(stderr, "\t%rsi    = 0x%.16lx (%ld)\n", state->rsi, state->rsi);
    fprintf(stderr, "\t%rdi    = 0x%.16lx (%ld)\n", state->rdi, state->rdi);
    fprintf(stderr, "\t%r8     = 0x%.16lx (%ld)\n", state->r8 , state->r8);
    fprintf(stderr, "\t%r9     = 0x%.16lx (%ld)\n", state->r9 , state->r9);
    fprintf(stderr, "\t%r10    = 0x%.16lx (%ld)\n", state->r10, state->r10);
    fprintf(stderr, "\t%r11    = 0x%.16lx (%ld)\n", state->r11, state->r11);
    fprintf(stderr, "\t%r12    = 0x%.16lx (%ld)\n", state->r12, state->r12);
    fprintf(stderr, "\t%r13    = 0x%.16lx (%ld)\n", state->r13, state->r13);
    fprintf(stderr, "\t%r14    = 0x%.16lx (%ld)\n", state->r14, state->r14);
    fprintf(stderr, "\t%r15    = 0x%.16lx (%ld)\n", state->r15, state->r15);
    fprintf(stderr, "\t%rflags = %c%c%c%c%c\n\n",
        (state->rflags & SF? 'S': '-'),
        (state->rflags & ZF? 'Z': '-'),
        (state->rflags & AF? 'A': '-'),
        (state->rflags & PF? 'P': '-'),
        (state->rflags & CF? 'C': '-'),
        (state->rflags & OF? 'O': '-'));
    fflush(stderr);
    mutex_unlock(&mutex);
}

/*
 * Init.
 */
void init(void)
{
    setvbuf(stderr, NULL, _IOFBF, 0);
}

