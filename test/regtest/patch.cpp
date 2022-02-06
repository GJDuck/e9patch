/*
 * Patching.
 */

#include "stdlib.c"
#include <cstddef>

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

template <typename T>
static void do_cmp(T x, T y, uint16_t *flags)
{
    asm volatile (
        "cmp %1,%2\n"
        "seto %%al\n"
        "lahf\n"
        "mov %%ax,%0\n"
        : "=m"(*flags) : "r"(x), "r"(y): "rax");
}

void cmp(int64_t x, int64_t y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm); 
    do_cmp(x, y, flags);
}
void cmp(int32_t x, int32_t y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm); 
    do_cmp(x, y, flags);
}
void cmp(int16_t x, int16_t y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm); 
    do_cmp(x, y, flags);
}
void cmp(int8_t x, int8_t y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm); 
    do_cmp(x, y, flags);
}

void cmp_and_clr_z(int64_t x, int64_t y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm); 
    do_cmp(x, y, flags);
    *flags &= ~0x4000;
}

template <typename T>
static void do_add(T x, T *y, uint16_t *flags)
{
    asm volatile (
        "add %2,%1\n"
        "seto %%al\n"
        "lahf\n"
        "mov %%ax,%0\n"
        : "=m"(*flags), "=m"(*y) : "r"(x) : "rax");
}

void add64(int64_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_add(x, y, flags);
}
void add64(int32_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_add((int64_t)x, y, flags);
}
void add32(int32_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    int32_t y32 = (int32_t)*y;
    do_add(x, &y32, flags);
    *y = (int64_t)(uint32_t)y32;
}
void add32(int32_t x, int32_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_add(x, y, flags);
}
void add16(int16_t x, int16_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_add(x, y, flags);
}
void add8(int8_t x, int8_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_add(x, y, flags);
}

template <typename T>
static void do_sub(T x, T *y, uint16_t *flags)
{
    asm volatile (
        "sub %2,%1\n"
        "seto %%al\n"
        "lahf\n"
        "mov %%ax,%0\n"
        : "=m"(*flags), "=m"(*y) : "r"(x) : "rax");
}

void sub64(int64_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_sub(x, y, flags);
}
void sub64(int32_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_sub((int64_t)x, y, flags);
}
void sub32(int32_t x, int64_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    int32_t y32 = (int32_t)*y;
    do_sub(x, &y32, flags);
    *y = (int64_t)(uint32_t)y32;
}
void sub32(int32_t x, int32_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_sub(x, y, flags);
}
void sub16(int16_t x, int16_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_sub(x, y, flags);
}
void sub8(int8_t x, int8_t *y, uint16_t *flags, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    do_sub(x, y, flags);
}

void lea(int32_t disp, int64_t base, int64_t index, int8_t scale, int64_t *dst)
{
    *dst = (int64_t)disp + base + (int64_t)scale * index;
    fprintf(stderr, "LEA 0x%x(0x%lx,0x%lx,%u) = 0x%lx\n", disp, base, index,
        scale, *dst);
}
void lea(int32_t disp, int64_t base, std::nullptr_t index, int8_t scale,
    int64_t *dst)
{
    *dst = (int64_t)disp + base;
    fprintf(stderr, "LEA 0x%x(0x%lx) = 0x%lx\n", disp, base, *dst);
}

const void *never_take(const void *addr, size_t size, const char *_asm)
{
    const uint8_t *next = (const uint8_t *)addr + size;
    fprintf(stderr, "%s\t# NO_TAKE %p\n", _asm, next);
    return (const void *)next;
}
const void *always_take(const void *target, const char *_asm)
{
    fprintf(stderr, "%s\t# TAKE %p\n", _asm, target);
    return target;
}
const void *jump(const void *target, const char *_asm)
{
    fprintf(stderr, "%s\t# JUMP %p\n", _asm, target);
    return target;
}

void swap(intptr_t *a, intptr_t *b, const char *_asm)
{
    fprintf(stderr, "%s\t# SWAP\n", _asm);
    intptr_t tmp = *a;
    *a = *b;
    *b = tmp;
}

void zero(void *state_0, const char *_asm)
{
    fprintf(stderr, "%s\t# ZERO ALL REGS\n", _asm);
    STATE *state = (STATE *)state_0;
    state->rax = state->rcx = state->rdx = state->rbx = 
        state->rbp = state->rsi = state->rdi = state->r8 =
        state->r9 = state->r10 = state->r11 = state->r12 =
        state->r13 = state->r14 = state->r15 = 0x0;
}

void zero_flags(uint16_t *rflags, const char *_asm)
{
    fprintf(stderr, "%s\t# ZERO FLAGS %c%c%c%c%c\n", _asm,
        (*rflags & 0x8000? 'S': '-'),
        (*rflags & 0x4000? 'Z': '-'),
        (*rflags & 0x1000? 'A': '-'),
        (*rflags & 0x0400? 'P': '-'),
        (*rflags & 0x0001? 'O': '-'));
    *rflags = 0x0;
}

void zero_flags(void *state_0, const char *_asm)
{
    STATE *state = (STATE *)state_0;
    zero_flags(&state->rflags, _asm);
}

void sum(intptr_t x, const char *_asm)
{
    static intptr_t s = 0;
    s += x;
    fprintf(stderr, "%s # %zd\n", _asm, s);
}

void dst_zero(int64_t *dst, const char *_asm)
{
    fprintf(stderr, "%s # DST %.16lX --> 0x0\n", _asm, *dst);
    *dst = 0x0;
}

intptr_t ret_0(const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    return 0;
}

intptr_t ret_1(const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    return 1;
}

void imm_by_ptr(const int32_t *imm_ptr, const char *_asm)
{
    fprintf(stderr, "%s # IMM = 0x%.8X\n", _asm, (unsigned)*imm_ptr);
}

void rax_by_ptr(const uint64_t *rax_ptr, const char *_asm)
{
    fprintf(stderr, "%s # %%rax = 0x%.16lX\n", _asm, *rax_ptr);
}

asm
(
    ".globl naked\n"
    ".type naked, @function\n"
    "naked:\n"
    "pushfq\n"
    "push %rax\n"
    "push %rsi\n"
    "push %rdx\n"
    "push %rcx\n"
    "push %r11\n"
    "mov %rdi,%rdx\n"
    ".Lloop:\n"
    "cmpb $0x0,(%rdx)\n"
    "je .Lexit\n"
    "inc %rdx\n"
    "jmp .Lloop\n"
    ".Lexit:\n"
    "sub %rdi,%rdx\n"
    "mov %rdi,%rsi\n"
    "mov $1,%eax\n"     // SYS_write
    "mov $2,%edi\n"     // stderr
    "syscall\n"
    "lea .Lnewline(%rip),%rsi\n"
    "mov $1,%eax\n"     // SYS_write
    "mov $2,%edi\n"     // stderr
    "mov $1,%edx\n"
    "syscall\n"
    "pop %r11\n"
    "pop %rcx\n"
    "pop %rdx\n"
    "pop %rsi\n"
    "pop %rax\n"
    "popfq\n"
    "retq\n"
    ".Lnewline:\n"
    ".byte 0x0a\n"      // newline

    ".globl ret_0x0\n"
    ".type ret_0x0, @function\n"
    "ret_0x0:\n"
    "mov $0x0, %eax\n"
    "retq\n"

    ".globl ret_0x1\n"
    ".type ret_0x1, @function\n"
    "ret_0x1:\n"
    "mov $0x1, %eax\n"
    "retq\n"

    ".global nop\n"
    ".type nop, @function\n"
    "nop:\n"
    "retq\n"

    ".global naked_bug\n"
    ".type naked_bug, @function\n"
    "naked_bug:\n"
    "pushfq\n"
    "cmp $0x44332211,%edi\n"
    "jne .Lexit2\n"
    "push %rax\n"
    "push %rsi\n"
    "push %rdx\n"
    "push %rcx\n"
    "push %r11\n"
    "mov $1,%eax\n"     // SYS_write
    "mov $2,%edi\n"     // stderr
    "lea .Lstring(%rip),%rsi\n"
    "mov $5,%edx\n"
    "syscall\n"
    "pop %r11\n"
    "pop %rcx\n"
    "pop %rdx\n"
    "pop %rsi\n"
    "pop %rax\n"
    "jmp .Lexit2\n"
    ".Lstring:\n"
    ".ascii \"PASS\\n\"\n"
    "int3\n"
    "int3\n"
    "int3\n"
    "int3\n"
    "int3\n"
    ".Lexit2:\n"
    "popfq\n"
    "retq\n"
);

void string(const char *s)
{
    fprintf(stderr, "%s\n", s);
}

void bug_18(void)
{
    int size = 8192;
    char *buf = (char *)malloc((size_t) size * sizeof(char));

    for (int i = 0; i < size; i += 1)
        buf[i] = 'a';
    buf[size-1] = '\0';

    fprintf(stderr, "buf = \"%.10s...\", strlen(buf) = %zu\n", buf, strlen(buf));
}

void rip_to_rsp(void *state_0, const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
    STATE *state = (STATE *)state_0;
    if (state->rip == 0xa000122)
    {
        fprintf(stderr, "setting %%rsp to %%rip=%p\n", (void *)state->rip);
        state->rsp = state->rip;
    }
}

void rotate(void *state_0, const char *_asm)
{
    STATE *state = (STATE *)state_0;
    fprintf(stderr, "%s [%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:"
        "%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:%.16lX:]\n", _asm,
        state->rax, state->rcx, state->rdx, state->rbx, state->rbp,
        state->rsi, state->rdi, state->r8, state->r9, state->r10,
        state->r11, state->r12, state->r13, state->r14, state->r15);
    int64_t tmp = state->rax;
    state->rax = state->rcx;
    state->rcx = state->rdx;
    state->rdx = state->rbx;
    state->rbx = state->rbp;
    state->rbp = state->rsi;
    state->rsi = state->rdi;
    state->rdi = state->r8;
    state->r8 = state->r9;
    state->r9 = state->r10;
    state->r10 = state->r11;
    state->r11 = state->r12;
    state->r12 = state->r13;
    state->r13 = state->r14;
    state->r14 = state->r15;
    state->r15 = tmp;
}

void trunc32(void *state_0, const char *_asm)
{
    STATE *state = (STATE *)state_0;
    state->rax &= 0xFFFFFFFFull;
    state->rcx &= 0xFFFFFFFFull;
    state->rdx &= 0xFFFFFFFFull;
    state->rbx &= 0xFFFFFFFFull;
    state->rbp &= 0xFFFFFFFFull;
    state->rsi &= 0xFFFFFFFFull;
    state->rdi &= 0xFFFFFFFFull;
    state->r8  &= 0xFFFFFFFFull;
    state->r9  &= 0xFFFFFFFFull;
    state->r10 &= 0xFFFFFFFFull;
    state->r11 &= 0xFFFFFFFFull;
    state->r12 &= 0xFFFFFFFFull;
    state->r13 &= 0xFFFFFFFFull;
    state->r14 &= 0xFFFFFFFFull;
    state->r15 &= 0xFFFFFFFFull;
    fprintf(stderr, "%s [%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:"
        "%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:%.8lX:]\n", _asm,
        state->rax, state->rcx, state->rdx, state->rbx, state->rbp,
        state->rsi, state->rdi, state->r8, state->r9, state->r10,
        state->r11, state->r12, state->r13, state->r14, state->r15);
}

const void *skip(void *state_0, intptr_t addr, const char *_asm)
{
    STATE *state = (STATE *)state_0;
    fprintf(stderr, "%s # %%rax=0x%.16lx %%rbx=0x%.16lx\n", _asm,
        state->rax, state->rbx);
    if (state->rax == state->rbx)
    {
        state->rax++;
        return (const void *)addr;
    }
    return NULL;
}

const void *next(const void *addr, const void *base, const void *next,
    const char *_asm)
{
    fprintf(stderr, "%p: %s # goto %p\n", addr, _asm, next);
    return (const void *)((const uint8_t *)base + (intptr_t)next);
}

const void *stack_overflow(const void *addr, intptr_t *rsp, const char *_asm)
{
    *rsp -= 0x1000;
    fprintf(stderr, "%p: %s # %%rsp=%p\n", addr, _asm, (void *)*rsp);
    return addr;        // loop
}

void diff(const void *a, const void *b, const char *_asm)
{
    intptr_t diff = (intptr_t)b - (intptr_t)a;
    fprintf(stderr, "%s # diff = 0x%lx\n", _asm, diff);
}

void print(const char *_asm)
{
    fprintf(stderr, "%s\n", _asm);
}

void write(const char *str)
{
    fputs(str, stderr);
}

void state_check(const void *addr, const void *state_0, intptr_t rsp,
    intptr_t rax, intptr_t r15)
{
    const STATE *state = (const STATE *)state_0;
    if (rsp != state->rsp)
    {
        fprintf(stderr, "%p: %%rsp mismatch (0x%lx vs 0x%lx)\n", addr, rsp,
            state->rsp);
        abort();
    }
    if ((intptr_t)addr != state->rip)
    {
        fprintf(stderr, "%p: %%rip mismatch (0x%p vs 0x%lx)\n", addr, addr,
            state->rip);
        abort();
    }
    if (rax != state->rax)
    {
        fprintf(stderr, "%p: %%rax mismatch (0x%lx vs 0x%lx)\n", addr, rax,
            state->rax);
        abort();
    }
    if (r15 != state->r15)
    {
        fprintf(stderr, "%p: %%r15 mismatch (0x%lx vs 0x%lx)\n", addr, r15,
            state->r15);
        abort();
    }
}

struct NODE
{
    intptr_t val;
    struct NODE *next;
};

void record(const void *addr, intptr_t val)
{
    static struct NODE *vals = nullptr;
    struct NODE *n;
    for (n = vals; n != nullptr; n = n->next)
    {
        if (val == n->val)
            return;
    }
    fprintf(stderr, "%p: add 0x%.16lx\n", addr, val);
    n = (struct NODE *)malloc(sizeof(struct NODE));
    if (n == NULL)
    {
        fprintf(stderr, "malloc() failed (%s)\n", strerror(errno));
        abort();
    }
    n->val  = val;
    n->next = vals;
    vals = n;
}

struct ENTRY
{
    const void *addr;
    intptr_t val;
};

void log(const void *addr, intptr_t val)
{
    static struct ENTRY **log = nullptr;
    static size_t log_size = 0;
    static size_t log_ptr  = 0;

    struct ENTRY *entry = (struct ENTRY *)malloc(sizeof(struct ENTRY));
    if (entry == nullptr)
    {
        fprintf(stderr, "malloc() failed (%s)\n", strerror(errno));
        abort();
    }
    entry->addr = addr;
    entry->val  = val;
    if (log_ptr >= log_size)
    {
        log_size = (log_size == 0? 1: 2 * log_size);
        log = (struct ENTRY **)realloc(log, log_size * sizeof(struct ENTRY *));
        if (log == nullptr)
        {
            fprintf(stderr, "realloc() failed (%s)\n", strerror(errno));
            abort();
        }
    }
    log[log_ptr++] = entry;
    if (addr != (const void *)0xa0002ac)
        return;
    fputc('{', stderr);
    for (size_t i = 0; i < log_ptr; i++)
    {
        fprintf(stderr, "<%p:0x%lx>%s", log[i]->addr, log[i]->val,
            (i == log_ptr-1? "": ", "));
        free(log[i]);
    }
    fputs("}\n", stderr);
    free(log);
}

void print_ptr(const void *ptr, const char *_asm)
{
    fprintf(stderr, "%s: &mem[0] = %p\n", _asm, ptr);
}
void print_ptr(std::nullptr_t ptr, const char *_asm)
{
    fprintf(stderr, "%s: &mem[0] = <undefined>\n", _asm);
}

