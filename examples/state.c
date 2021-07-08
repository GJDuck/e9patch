/*
 * PRINT STATE instrumentation.
 */

#include "stdlib.c"

/*
 * Representation of the state structure.
 */
struct STATE
{
    union
    {
        uint16_t rflags;
        uint64_t __padding;
    };
    union
    {
        int64_t r15;
        int32_t r15d;
        int16_t r15w;
        int8_t r15b;
    };
    union
    {
        int64_t r14;
        int32_t r14d;
        int16_t r14w;
        int8_t r14b;
    };
    union
    {
        int64_t r13;
        int32_t r13d;
        int16_t r13w;
        int8_t r13b;
    };
    union
    {
        int64_t r12;
        int32_t r12d;
        int16_t r12w;
        int8_t r12b;
    };
    union
    {
        int64_t r11;
        int32_t r11d;
        int16_t r11w;
        int8_t r11b;
    };
    union
    {
        int64_t r10;
        int32_t r10d;
        int16_t r10w;
        int8_t r10b;
    };
    union
    {
        int64_t r9;
        int32_t r9d;
        int16_t r9w;
        int8_t r9b;
    };
    union
    {
        int64_t r8;
        int32_t r8d;
        int16_t r8w;
        int8_t r8b;
    };
    union
    {
        int64_t rdi;
        int32_t edi;
        int16_t di;
        int8_t dil;
    };
    union
    {
        int64_t rsi;
        int32_t esi;
        int16_t si;
        int8_t sil;
    };
    union
    {
        int64_t rbp;
        int32_t ebp;
        int16_t bp;
        int8_t bpl;
    };
    union
    {
        int64_t rbx;
        int32_t ebx;
        int16_t bx;
        struct
        {
            int8_t bl;
            int8_t bh;
        };
    };
    union
    {
        int64_t rdx;
        int32_t edx;
        int16_t dx;
        struct
        {
            int8_t dl;
            int8_t dh;
        };
    };
    union
    {
        int64_t rcx;
        int32_t ecx;
        int16_t cx;
        struct
        {
            int8_t cl;
            int8_t ch;
        };
    };
    union
    {
        int64_t rax;
        int32_t eax;
        int16_t ax;
        struct
        {
            int8_t al;
            int8_t ah;
        };
    };
    union
    {
        int64_t rsp;
        int32_t esp;
        int16_t sp;
        int16_t spl;
    };
    const union
    {
        int64_t rip;
        int32_t eip;
        int16_t ip;
    };
};

/*
 * Flags.
 */
#define OF      0x0001
#define CF      0x0100
#define PF      0x0400
#define AF      0x1000
#define ZF      0x4000
#define SF      0x8000

/*
 * Colors.
 */
#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE   "\33[0m"

/*
 * Entry point.
 *
 * call entry(state,asm)@state
 */
void entry(const struct STATE *state, const char *_asm)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    if (mutex_lock(&mutex) < 0)
        return;

    clearerr_unlocked(stderr);
    fprintf_unlocked(stderr, RED "%.16lx" WHITE ": " GREEN "%s" WHITE "\n",
        state->rip, _asm);
    fprintf_unlocked(stderr, "\t%rax    = 0x%.16lx (%ld)\n", state->rax, state->rax);
    fprintf_unlocked(stderr, "\t%rcx    = 0x%.16lx (%ld)\n", state->rcx, state->rcx);
    fprintf_unlocked(stderr, "\t%rdx    = 0x%.16lx (%ld)\n", state->rdx, state->rdx);
    fprintf_unlocked(stderr, "\t%rbx    = 0x%.16lx (%ld)\n", state->rbx, state->rbx);
    fprintf_unlocked(stderr, "\t%rsp    = 0x%.16lx (%ld)\n", state->rsp, state->rsp);
    fprintf_unlocked(stderr, "\t%rbp    = 0x%.16lx (%ld)\n", state->rbp, state->rbp);
    fprintf_unlocked(stderr, "\t%rsi    = 0x%.16lx (%ld)\n", state->rsi, state->rsi);
    fprintf_unlocked(stderr, "\t%rdi    = 0x%.16lx (%ld)\n", state->rdi, state->rdi);
    fprintf_unlocked(stderr, "\t%r8     = 0x%.16lx (%ld)\n", state->r8 , state->r8);
    fprintf_unlocked(stderr, "\t%r9     = 0x%.16lx (%ld)\n", state->r9 , state->r9);
    fprintf_unlocked(stderr, "\t%r10    = 0x%.16lx (%ld)\n", state->r10, state->r10);
    fprintf_unlocked(stderr, "\t%r11    = 0x%.16lx (%ld)\n", state->r11, state->r11);
    fprintf_unlocked(stderr, "\t%r12    = 0x%.16lx (%ld)\n", state->r12, state->r12);
    fprintf_unlocked(stderr, "\t%r13    = 0x%.16lx (%ld)\n", state->r13, state->r13);
    fprintf_unlocked(stderr, "\t%r14    = 0x%.16lx (%ld)\n", state->r14, state->r14);
    fprintf_unlocked(stderr, "\t%r15    = 0x%.16lx (%ld)\n", state->r15, state->r15);
    fprintf_unlocked(stderr, "\t%rflags = %c%c%c%c%c\n\n",
        (state->rflags & SF? 'S': '-'),
        (state->rflags & ZF? 'Z': '-'),
        (state->rflags & AF? 'A': '-'),
        (state->rflags & PF? 'P': '-'),
        (state->rflags & CF? 'C': '-'),
        (state->rflags & OF? 'O': '-'));
    fflush_unlocked(stderr);
    mutex_unlock(&mutex);
}

void init(void)
{
    setvbuf(stderr, NULL, _IOFBF, 0);
}

