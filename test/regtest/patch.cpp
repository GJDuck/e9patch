/*
 * Patching.
 */

#include "stdlib.c"

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
void print(const char *_asm, const void *ptr)
{
    fprintf(stderr, "%s: %p\n", _asm, ptr);
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

struct LOG_ENTRY
{
    const void *addr;
    intptr_t val;
};

void log(const void *addr, intptr_t val)
{
    static struct LOG_ENTRY **log = nullptr;
    static size_t log_size = 0;
    static size_t log_ptr  = 0;

    struct LOG_ENTRY *entry =
        (struct LOG_ENTRY *)malloc(sizeof(struct LOG_ENTRY));
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
        log = (struct LOG_ENTRY **)realloc(log,
            log_size * sizeof(struct LOG_ENTRY *));
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

const void *repair_fib(uint64_t n, intptr_t *rax, intptr_t *rsp)
{
    uint64_t a = 0, b = 1;
    for (size_t i = 2; i <= n; i++)
    {
        uint64_t c = a + b;
        a = b;
        b = c;
    }
    *rax = (n == 0? 0: b);
    if (rsp == nullptr)
        return nullptr;
    intptr_t RSP = *rsp;
    intptr_t retaddr = *(intptr_t *)RSP;
    RSP += sizeof(void *);
    *rsp = RSP;
    return (const void *)retaddr;
}

void zero_rax(uint64_t *rax)
{
    *rax = 0x0;
}

void ABORT(void)
{
    abort();
}

void cast(int8_t x, const char *_asm)
{
    fprintf(stderr, "x = 0x%.2X; // %s\n", (uint8_t)x, _asm);
}
void cast(int16_t x, const char *_asm)
{
    fprintf(stderr, "x = 0x%.4X; // %s\n", (uint16_t)x, _asm);
}
void cast(int32_t x, const char *_asm)
{
    fprintf(stderr, "x = 0x%.8X; // %s\n", x, _asm);
}
void cast(int64_t x, const char *_asm)
{
    fprintf(stderr, "x = 0x%.16lX; // %s\n", x, _asm);
}
void cast(int8_t *x, const char *_asm)
{
    fprintf(stderr, "x = (int8_t *)%p; // %s\n", x, _asm);
}
void cast(int16_t *x, const char *_asm)
{
    fprintf(stderr, "x = (int16_t *)%p; // %s\n", x, _asm);
}
void cast(int32_t *x, const char *_asm)
{
    fprintf(stderr, "x = (int32_t *)%p; // %s\n", x, _asm);
}
void cast(int64_t *x, const char *_asm)
{
    fprintf(stderr, "x = (int64 *)%p; // %s\n", x, _asm);
}
void cast(void *x, const char *_asm)
{
    fprintf(stderr, "x = (void *)%p; // %s\n", x, _asm);
}
void cast(char *x, const char *_asm)
{
    fprintf(stderr, "x = (char *)%p; // %s\n", x, _asm);
}
void cast(const int8_t *x, const char *_asm)
{
    fprintf(stderr, "x = (const int8_t *)%p; // %s\n", x, _asm);
}
void cast(const int16_t *x, const char *_asm)
{
    fprintf(stderr, "x = (const int16_t *)%p; // %s\n", x, _asm);
}
void cast(const int32_t *x, const char *_asm)
{
    fprintf(stderr, "x = (const int32_t *)%p; // %s\n", x, _asm);
}
void cast(const int64_t *x, const char *_asm)
{
    fprintf(stderr, "x = (const int64 *)%p; // %s\n", x, _asm);
}
void cast(const void *x, const char *_asm)
{
    fprintf(stderr, "x = (const void *)%p; // %s\n", x, _asm);
}
void cast(const char *x, const char *_asm)
{
    fprintf(stderr, "x = (const char *)%p; // %s\n", x, _asm);
}
void cast(std::nullptr_t x, const char *_asm)
{
    fprintf(stderr, "x = nullptr; // %s\n", _asm);
}

void test_memset(intptr_t *ptr)
{
    memset(ptr, 0xe9, sizeof(*ptr));
    fprintf(stderr, "*ptr = %.16lx\n", *ptr);
    fprintf(stderr, "%s\n", (*ptr == (intptr_t)0xe9e9e9e9e9e9e9e9?
        "PASSED": "FAILED"));
    exit(0);
}
void test_memcpy(intptr_t *ptr)
{
    intptr_t val = -1;
    memcpy(&val, ptr, sizeof(val));
    fprintf(stderr, "*ptr = %.16lx\n", *ptr);
    fprintf(stderr, "val  = %.16lx\n", val);
    fprintf(stderr, "%s\n", (val == *ptr? "PASSED": "FAILED"));
    exit(0);
}

struct TMP
{
    char x[6];
    char y[6];
};
void test_memset_2(void)
{
    struct TMP tmp;
    memset((void *)tmp.x, 'A', 6);
    memset((void *)tmp.y, 'B', 6);
    fwrite(&tmp, sizeof(tmp), 1, stderr);
}
void test_memcpy_2(void)
{
    const char *aaa = "AAAAAA", *bbb = "BBBBBB";
    struct TMP tmp;
    memcpy((void *)tmp.x, bbb, 6);
    memcpy((void *)tmp.y, aaa, 6);
    fwrite(&tmp, sizeof(tmp), 1, stderr);
}

struct TMP2
{
    char x[6];
    char c;
    char y[6];
};
void test_memcpy_3(void)
{
    const char *xxx = "XXXXXX";
    struct TMP2 tmp;
    memcpy((void *)tmp.x, xxx, 6);
    tmp.c = 'Y';
    memcpy((void *)tmp.y, xxx, 6);
    fwrite(&tmp, sizeof(tmp), 1, stderr);
}

void test_fread(void)
{
    size_t size = 2 * BUFSIZ;
    FILE *stream = fopen("test.tmp", "w");
    for (size_t i = 0; i < size; i++)
        fputc(0xFF, stream);
    fclose(stream);
    stream = fopen("test.tmp", "r");
    uint8_t *buf = (uint8_t *)malloc(size);
    memset(buf, 0xAA, size);
    for (size_t i = 0; i < size; )
    {
        size_t r = fread(buf+i, 1, size-i, stream);
        if (r == 0)
        {
            fprintf(stderr, "fread() failed\n");
            abort();
        }
        i += r;
    }
    fclose(stream);
    unlink("test.tmp");
    for (size_t i = 0; i < size; i++)
    {
        if (buf[i] != 0xFF)
        {
            fprintf(stderr, "buf[%zu] = 0x%.2X?\n", i, buf[i]);
            break;
        }
    }
}

void test_stdio(intptr_t arg)
{
    fprintf(stderr, "arg = 0x%llx\n", arg);
    
    fprintf(stderr, "[0]\n");
    FILE *stream = fopen("test.tmp", "w");
    if (stream == NULL)
        fprintf(stderr, "stream is NULL\n");
    int n = fprintf(stream, "%s %10d %zd -%#lx %p\n%u\t%4hu\t \t%c 0%o\n",
        "aaa", 101, arg, arg, (void *)arg, (unsigned)arg, (uint16_t)arg,
        (char)arg, 0644);
    fprintf(stderr, "pos = %zd vs %d\n", ftell(stream), n);
    const char HELLO[] = "Hello World!";
    int r = fwrite(HELLO, sizeof(char), sizeof(HELLO)-1, stream);
    fprintf(stderr, "write = %d\n", r);
    fseek(stream, 1, SEEK_SET);
    fprintf(stderr, "getc() = %d\n", getc(stream));
    fputs("bbb", stream);
    fclose(stream);

    fprintf(stderr, "[1]\n");
    stream = fopen("test.tmp", "r");
    if (stream == NULL)
        fprintf(stderr, "stream is NULL\n");
    fseek(stream, 4, SEEK_CUR);
    fprintf(stderr, "pos = %zd\n", ftell(stream));
    int i, j;
    fscanf(stream, "%d", &i);
    fprintf(stderr, "i = %d\n", i);
    fseek(stream, 0, SEEK_SET);
    getc(stream);
    fprintf(stderr, "pos = %zd\n", ftell(stream));
    ungetc('X', stream);
    fprintf(stderr, "pos = %zd\n", ftell(stream));
    char s[5];
    fscanf(stream, " %5s", s);
    fprintf(stderr, "s = \"%s\"\n", s);
    char c1, c2, c3, c4;
    s[2] = toupper(s[2]);
    sscanf(s, "%c%c%c%c", &c1, &c2, &c3, &c4);
    fprintf(stderr, "s = \"%c%c%c%c\"\n", c1, c2, c3, c4);
    fclose(stream);

    fprintf(stderr, "[2]\n");
    stream = fopen("test.tmp", "r+");
    if (stream == NULL)
        fprintf(stderr, "stream is NULL\n");
    char buf[5];
    if (setvbuf(stream, buf, _IOLBF, sizeof(buf)) < 0)
        fprintf(stderr, "setvbuf failed (%s)\n", strerror(errno));
    fputs("cccc  ", stream);
    fprintf(stderr, "c = '%c'\n", getc(stream));
    ungetc('7', stream);
    intptr_t x, y;
    void *p;
    unsigned u;
    uint16_t h;
    char c;
    unsigned o;
    errno = 0;
    r = fscanf(stream, "%d %d\t\r\n%zd   %li %p %u %hu %c %o", &i, &j, &x, &y,
        &p, &u, &h, &c, &o);
    fprintf(stderr, "errno = %d (%s)\n", errno, strerror(errno));
    fprintf(stderr, "r = %d\n", r);
    fprintf(stderr, "i = %d\n", i);
    fprintf(stderr, "j = %d\n", j);
    fprintf(stderr, "x = 0x%lx\n", x);
    fprintf(stderr, "y = 0x%lx\n", y);
    fprintf(stderr, "p = %p\n", p);
    fprintf(stderr, "u = %u\n", u);
    fprintf(stderr, "h = %hu\n", h);
    fprintf(stderr, "c = '%c'\n", c);
    fprintf(stderr, "o = %#o\n", o);
    getc(stream);
    char buf1[20] = {0};
    r = fread(buf1, sizeof(char), sizeof(buf1), stream);
    fprintf(stderr, "read = \"%s\" (%d)\n", buf1, r);
    fprintf(stderr, "feof() = %d\n", feof(stream));
    clearerr(stream);
    fprintf(stderr, "feof() = %d\n", feof(stream));
    fseek(stream, 0, SEEK_SET);
    fscanf(stream, "%s", s);
    fprintf(stderr, "s = \"%s\"\n", s);
    fseek(stream, 0, SEEK_SET);
    fscanf(stream, "%4c", s);
    fprintf(stderr, "s = \"%s\"\n", s);
    fscanf(stream, "%4c", s);
    fseek(stream, 1, SEEK_SET);
    c = getc(stream);
    fprintf(stderr, "c = '%c'\n", c);
    ungetc('d', stream);
    c = getc(stream);
    fprintf(stderr, "c = '%c'\n", c);
    fseek(stream, 0, SEEK_SET);
    fprintf(stream, "Hello World %i\n\n", 7);
    fclose(stream);

    fprintf(stderr, "[3]\n");
    int fd = open("test.tmp", O_RDONLY);
    stream = fdopen(fd, "r");
    if (stream == NULL)
        fprintf(stderr, "stream is NULL\n");
    if (setvbuf(stream, NULL, _IONBF, 0) < 0)
        fprintf(stderr, "setvbuf failed (%s)\n", strerror(errno));
    char hello[10], world[10];
    fseek(stream, 1, SEEK_CUR);
    fprintf(stderr, "pos = %zd\n", ftell(stream));
    fprintf(stderr, "pos = %zd\n", lseek(fileno(stream), SEEK_CUR, 0));
    ungetc('X', stream);
    r = fscanf(stream, "Xel%2s %4sd %i ", hello, world, &i);
    fprintf(stderr, "r = %d\n", r);
    fprintf(stderr, "hello = \"%s\"\n", hello);
    fprintf(stderr, "world = \"%s\"\n", world);
    fprintf(stderr, "i = %d\n", i);
    fclose(stream);

    unlink("test.tmp");
}

void test_string(void)
{
    char *s1 = strdup("AAAAAAAAAABAAAAAAAAAA");
    char *s2 = strdup("AAAAAAAAAAAAAAAAAAAAA");
    size_t n = strlen(s1);
    fprintf(stderr, "strlen(\"%s\") = %zu\n", s1, n);
    fprintf(stderr, "strnlen(\"\", 5) = %zu\n", strnlen("", 5));
    fprintf(stderr, "strnlen(\"%s\", 5) = %zu\n", s1, strnlen(s1, 5));
    fprintf(stderr, "strnlen(\"%s\", 25) = %zu\n", s1, strnlen(s1, 25));
    fprintf(stderr, "strchr(\"%s\", 'B') = \"%s\"\n", s1, strchr(s1, 'B'));
    fprintf(stderr, "strchr(\"%s\", 'B') = \"%s\"\n", s2, strchr(s2, 'B'));
    fprintf(stderr, "memcmp(\"%s\", \"%s\") = %d\n",
        s1, s1, memcmp(s1, s1, n));
    fprintf(stderr, "memcmp(\"%s\", \"%s\") = %d\n",
        s1, s2, memcmp(s1, s2, n));
    fprintf(stderr, "memcmp(\"%s\", \"%s\") = %d\n",
        s2, s2, memcmp(s2, s2, n));
    fprintf(stderr, "memcmp(\"%s\", \"%s\") = %d\n",
        s2, s1, memcmp(s2, s1, n));
    fprintf(stderr, "strcmp(\"%s\", \"%s\") = %d\n",
        s1, s1, strcmp(s1, s1));
    fprintf(stderr, "strcmp(\"%s\", \"%s\") = %d\n",
        s1, s2, strcmp(s1, s2));
    fprintf(stderr, "strcmp(\"%s\", \"%s\") = %d\n",
        s2, s2, strcmp(s2, s2));
    fprintf(stderr, "strcmp(\"%s\", \"%s\") = %d\n",
        s2, s1, strcmp(s2, s1));
    fprintf(stderr, "strncmp(\"%s\", \"%s\", 10) = %d\n",
        s1, s1, strncmp(s1, s1, 10));
    fprintf(stderr, "strncmp(\"%s\", \"%s\", 10) = %d\n",
        s1, s2, strncmp(s1, s2, 10));
    fprintf(stderr, "strncmp(\"%s\", \"%s\", 10) = %d\n",
        s2, s2, strncmp(s2, s2, 10));
    fprintf(stderr, "strncmp(\"%s\", \"%s\", 10) = %d\n",
        s2, s1, strncmp(s2, s1, 10));
    char hello[13] = "Hello ", world[] = "World!";
    fprintf(stderr, "strncat(\"%s\", \"%s\", 3) = ", hello, world);
    strncat(hello, world, 3);
    fprintf(stderr, "\"%s\"\n", hello);
    hello[6] = '\0';
    fprintf(stderr, "strcat(\"%s\", \"%s\") = ", hello, world);
    strcat(hello, world);
    fprintf(stderr, "\"%s\"\n", hello);
    char buf[10] = "buffer...";
    char *data = "data";
    fprintf(stderr, "strcpy(\"%s\", \"%s\") = ", buf, data);
    strcpy(buf, data);
    for (size_t i = 0; i < 10; i++)
        fprintf(stderr, "%c'%c'", (i == 0? '{': ','), (buf[i]? buf[i]: '0'));
    fputs("}\n", stderr);
    char buf1[10] = "buffer...";
    fprintf(stderr, "strncpy(\"%s\", \"%s\", 10) = ", buf1, data);
    strncpy(buf1, data, 10);
    for (size_t i = 0; i < 10; i++)
        fprintf(stderr, "%c'%c'", (i == 0? '{': ','), (buf1[i]? buf1[i]: '0'));
    fputs("}\n", stderr);
    for (size_t i = 0; i < sizeof(hello); i++)
    {
        char *str = strdup(hello + sizeof(hello) - 1 - i);
        fprintf(stderr, "strlen(\"%s\") = %zu\n", str, strlen(str));
        free(str);
    }
    for (size_t i = 0; i < sizeof(hello); i++)
    {
        char *str = strdup(hello + sizeof(hello) - 1 - i);
        fprintf(stderr, "strnlen(\"%s\", 5) = %zu\n", str, strnlen(str, 5));
        free(str);
    }
    int bs[] = {0, 8, 10, 16, 36, -1};
    const char *Xs[] = {"0", " - 1", " \t-1234567890zzz", "0644", "0x123456789abc", NULL};
    for (size_t i = 0; bs[i] >= 0; i++)
    {
        int b = bs[i];
        for (size_t i = 0; Xs[i] != NULL; i++)
        {
            const char *X = Xs[i];
            errno = 0;
            char *end = NULL;
            int64_t x = strtoll(X, &end, b);
            fprintf(stderr, "strtoll(\"%s\", %d) = %zd (%s) [\"%s\"]\n",
                X, b, x, strerror(errno), end);
        }
    }
    free(s1);
    free(s2);
}

void test_stat(const char *filename)
{
    struct stat buf;
    if (stat(filename, &buf) < 0)
        perror("stat()");
    fprintf(stderr, "mode = %o\n", buf.st_mode);
    fprintf(stderr, "size = %zu\n", buf.st_size);
}

static int tree_compare(const void *a, const void *b)
{
    return (int)*(size_t *)a - (int)*(size_t *)b;
}
static void tree_print(const void *node, const VISIT which, const int depth)
{
    switch (which)
    {
        case leaf: case postorder:
            fprintf(stderr, "%zu ", **(size_t **)node);
            break;
        default:
            break;
    }
}
void test_tree(void)
{
    const uint8_t sbox[256] =
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16
    };
    void *root = NULL;
    for (size_t i = 0; i < 256; i++)
    {
        size_t *ptr = (size_t *)malloc(sizeof(size_t));
        *ptr = (size_t)sbox[i];
        void *r = tsearch(ptr, &root, tree_compare);
        if (r == NULL)
            abort();
        if (*(size_t **)r != ptr)
            fprintf(stderr, "insert %zu failed\n", *ptr);
    }
    const uint8_t xs[] = {101, 0, 103, 255, 107, 1, 101, 109};
    for (size_t i = 0; i < sizeof(xs); i++)
    {
        size_t key = (size_t)xs[i];
        void *r = tdelete(&key, &root, tree_compare);
        if (r == NULL)
            fprintf(stderr, "failed to delete %zu\n", key);
    }
    twalk(root, tree_print);
    tdestroy(root, free);
}

extern "C"
{
void format(const char *msg, intptr_t a1, intptr_t a2, intptr_t a3,
    intptr_t a4, intptr_t a5, intptr_t a6, intptr_t a7)
{
    fprintf(stderr, msg, a1, a2, a3, a4, a5, a6, a7);
}
}   // extern "C"

void skip(void *state_0, size_t size)
{
    STATE *state = (STATE *)state_0;
    state->rip += size;
    jump(state);
}

static int int_compare(const void *A, const void *B)
{
    int a = *(int *)A, b = *(int *)B;
    if (a == b)
        return 0;
    return (a < b? -1: 1);
}
void test_qsort(void)
{
    int M = 50;
    int a[M];
    for (int i = 0; i < M; i++)
        a[i] = i;
    srand(1234);
    for (int X = 0; X < 50; X++, M--)
    {
        printf("\n---- test #%d\n", X+1);
        for (int i = 0; i < M; i++)
        {
            int j = rand() % M, k = rand() % M;
            int t = a[j]; a[j] = a[k]; a[k] = t;
        }
        for (int i = 0; i < M; i++)
            printf("%s%d", (i == 0? "": ","), a[i]);
        putchar('\n');
        qsort(a, M, sizeof(a[0]), int_compare);
        for (int i = 0; i < M; i++)
        {
            if (i > 0 && a[i] <= a[i-1]) abort();
            printf("%s%d", (i == 0? "": ","), a[i]);
        }
        putchar('\n');
        for (int Y = 0; Y < 10; Y++)
        {
            int k = rand() % M + 10;
            void *r = bsearch(&k, a, M, sizeof(a[0]), int_compare);
            if (r == NULL)
            {
                if (k < M) abort();
                printf("%s%d=_", (Y == 0? "": " "), k);
            }
            else
            {
                if (*(int *)r != k) abort();
                printf("%s%d=X", (Y == 0? "": " "), k);
            }
        }
        putchar('\n');
    }
}

