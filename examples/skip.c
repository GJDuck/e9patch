/*
 * SKIP instrumentation
 */

/*
 * Skip over an instruction (without executing it).
 *
 * EXAMPLE USAGE:
 *  $ e9compile skip.c
 *  $ e9tool -M 'asm=/nop.*?/' -P 'entry(state,size,asm)@skip' xterm
 *  $ ./a.out
 */

#include "stdlib.c"

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

void entry(struct STATE *state, size_t size, const char *_asm)
{
    fprintf(stderr, RED "%.16lx" WHITE ": " GREEN "%s" WHITE "\n",
        state->rip, _asm);
    state->rip += size;     // Adjust %rip to next instruction.
    jump(state);            // Jump directly to next instruction.

    // Not reached
}

