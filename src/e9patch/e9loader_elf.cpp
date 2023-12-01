/*
 * e9loader_elf.cpp
 * Copyright (C) 2023 National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * NOTE: As a special exception, this file is under the MIT license.  The
 *       rest of the E9Patch/E9Tool source code is under the GPLv3 license.
 */

#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <fcntl.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <syscall.h>
#include <unistd.h>

#include "e9loader.cpp"

struct ksigaction
{
    void *sa_handler_2;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};
#define SA_RESTORER 0x04000000
#define E9_BACKDOOR 0xe9e9e9e9

typedef void (*e9handler_t)(int, siginfo_t *, void *);
struct e9scratch_s
{
    e9handler_t next;
    uint8_t tls[PAGE_SIZE / 2];
};

extern "C"
{
    void *e9init(int argc, char **argv, char **envp,
        const struct e9_config_s *config);
    void *e9fini(const struct e9_config_s *config);
    void e9handler(int sig, siginfo_t *info, ucontext_t *ctx,
        const e9_config_s *config);
    intptr_t e9syscall(long number, ...);
}

/*
 * E9Patch loader entry point.
 */
asm (
    ".section .text.entry,\"x\",@progbits\n"

    "_init:\n"          // _init() offset = +0
    "\tcallq e9init\n"
    "\tpop %rdx\n"
    "\tpop %rsi\n"
    "\tpop %rdi\n"
    "\tjmpq *%rax\n"

    ".align 16\n"       // _fini() offset = +16
    "_fini:\n"
    "\tcallq e9fini\n"
    "\tjmpq *%rax\n"

    ".align 8\n"        // _handler() offset = +24
    "_handler:\n"
    "\tjmp e9handler\n"

    ".section .text\n"
);

asm (
    ".globl e9syscall\n"
    ".type e9syscall,@function\n"
    "e9syscall:\n"
    "\tmov %edi, %eax\n"
    "\tmov %rsi, %rdi\n"
    "\tmov %rdx, %rsi\n"
    "\tmov %rcx, %rdx\n"
    "\tmov %r8, %r10\n"
    "\tmov %r9, %r8\n"
    "\tmov 0x8(%rsp), %r9\n"
    "\tsyscall\n"
    "\tretq\n"
);

/*
 * Something went wrong, print an error and abort.
 */
static NO_INLINE NO_RETURN void e9panic(const char *msg, ...)
{
    char buf[BUFSIZ], *str = buf;
    str = e9write_str(str, "e9patch loader error: ");
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    str = e9write_char(str, '\n');

    size_t len = str - buf;
    e9syscall(SYS_write, STDERR_FILENO, buf, len);
    e9syscall(SYS_kill, /*pid=*/0, SIGABRT);
    while (true)
        asm volatile ("ud2");
}

/*
 * Write a debug message.
 */
static NO_INLINE void e9debug(const char *msg, ...)
{
    char buf[BUFSIZ], *str = buf;
    str = e9write_str(str, "e9patch loader debug: ");
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    str = e9write_char(str, '\n');

    size_t len = str - buf;
    e9syscall(SYS_write, STDERR_FILENO, buf, len);
}

/*
 * Default mmap() routine.
 */
static intptr_t e9mmap(void *ptr, size_t len, int prot, int flags, int fd,
    off_t offset)
{
    return e9syscall(SYS_mmap, ptr, len, prot, flags, fd, offset);
}

/*
 * Allocate or get scratch.
 */
static NO_INLINE struct e9scratch_s *e9scratch(const e9_config_s *config,
    bool alloc)
{
    uint8_t *loader_base = (uint8_t *)config;
    uint8_t *scratch = loader_base - PAGE_SIZE;
    if (!alloc)
        return (struct e9scratch_s *)scratch;
    intptr_t r = e9mmap(scratch, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    r = (r >= 0 && r != (intptr_t)scratch? -EAGAIN: r);
    if (r < 0)
        e9panic("mmap() scratch failed (errno=%u)", (unsigned)-r);
    return (struct e9scratch_s *)scratch;
}

typedef intptr_t (*mmap_t)(void *, size_t, int, int, int, off_t);
typedef void (*init_t)(int, char **, char **, const void *, const void *);
typedef void (*fini_t)(const void *);

/*
 * Load a set of maps.
 */
static NO_INLINE void e9load_maps(const e9_map_s *maps, uint32_t num_maps,
    const uint8_t *elf_base, int fd, mmap_t mmap)
{
    for (uint32_t i = 0; i < num_maps; i++)
    {
        const uint8_t *addr = (maps[i].abs? (const uint8_t *)NULL: elf_base);
        addr += (intptr_t)maps[i].addr * PAGE_SIZE;
        size_t len = (size_t)maps[i].size * PAGE_SIZE;
        off_t offset = (off_t)maps[i].offset * PAGE_SIZE;
        int prot = (maps[i].r? PROT_READ: 0x0) |
                   (maps[i].w? PROT_WRITE: 0x0) |
                   (maps[i].x? PROT_EXEC: 0x0);
        int flags = MAP_FIXED | MAP_PRIVATE;
#if 0
        e9debug("mmap(addr=%p,size=%U,offset=+%U,prot=%c%c%c)",
            addr, len, offset,
            (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
            (maps[i].x? 'x': '-'));
#endif
        intptr_t result = mmap((void *)addr, len, prot, flags, fd, offset);
        if (result < 0)
            e9panic("mmap(addr=%p,size=%U,offset=+%U,prot=%c%c%c) failed "
                "(errno=%u)%s", addr, len, offset,
                (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
                (maps[i].x? 'x': '-'), -(int)result,
                (-(int)result == ENOMEM?
                    "\nhint: see the e9patch manpage for more information.":
                    ""));
    }
}

/*
 * Signal handler.
 */
void e9handler(int sig, siginfo_t *info, ucontext_t *ctx,
    const e9_config_s *config)
{
    mcontext_t *mctx = &ctx->uc_mcontext;
    const uint8_t *loader_base = (const uint8_t *)config;
    const uint8_t *elf_base    = loader_base - config->base;
    const struct e9_trap_s *traps =
        (const struct e9_trap_s *)(loader_base + config->traps);
    const uint8_t *rip = (const uint8_t *)mctx->gregs[REG_RIP];
    int64_t idx = -1;
    if (rip >= elf_base && rip <= loader_base)
    {
        int64_t lo = 0, hi = config->num_traps;
        intptr_t key = rip - elf_base;
        while (lo <= hi)
        {
            int64_t mid = (lo + hi) / 2;
            if (key < traps[mid].rip)
                hi = mid - 1;
            else if (key > traps[mid].rip)
                lo = mid + 1;
            else
            {
                idx = mid;
                break;
            }
        }
    }
    const uint8_t *trampoline = elf_base + traps[idx].trampoline;
    if (idx < 0)
    {
        // No trampoline found:
        struct e9scratch_s *scratch = e9scratch(config, /*alloc=*/false);
        if (scratch->next != NULL)
            scratch->next(sig, info, ctx);      // Try the next binary
        struct ksigaction action =
        {
            (void *)SIG_DFL, SA_NODEFER | SA_RESTORER, NULL, 0
        };
        e9syscall(SYS_rt_sigaction, SIGILL, &action, NULL, 8, E9_BACKDOOR);
        trampoline = (uint8_t *)mctx->gregs[REG_RIP];
    }
    void *xstate = (void *)mctx->fpregs;
    asm volatile (
        "mov %%rcx,%%fs:0x40\n"                 // trampoline
        "xor %%edx,%%edx\n"
        "mov $-1,%%rax\n"
        "xrstor  (%%rsi)\n"                     // restore xsave state
        "mov     (%%rbx),%%r8\n"
        "mov 0x08(%%rbx),%%r9\n"
        "mov 0x10(%%rbx),%%r10\n"
        "mov 0x18(%%rbx),%%r11\n"
        "mov 0x20(%%rbx),%%r12\n"
        "mov 0x28(%%rbx),%%r13\n"
        "mov 0x30(%%rbx),%%r14\n"
        "mov 0x38(%%rbx),%%r15\n"
        "mov 0x40(%%rbx),%%rdi\n"
        "mov 0x48(%%rbx),%%rsi\n"
        "mov 0x50(%%rbx),%%rbp\n"
        "mov 0x60(%%rbx),%%rdx\n"
        "mov 0x68(%%rbx),%%rax\n"
        "mov 0x88(%%rbx),%%rcx\n"               // %rflags
        "push %%rcx\n"
        "popfq\n"
        "mov 0x78(%%rbx),%%rsp\n"
        "mov 0x70(%%rbx),%%rcx\n"
        "mov 0x58(%%rbx),%%rbx\n"
        "jmpq *%%fs:0x40\n"                     // Jump to trampoline
            : : "b"(mctx), "c"(trampoline), "S"(xstate));
    __builtin_unreachable();
}

/*
 * Prevent future SIGILL handlers.
 */
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
static void e9filter(struct e9scratch_s *scratch)
{
    intptr_t r = e9syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (r < 0)
        e9panic("prctl() failed (errno=%u)", -r);
    struct sock_filter filter[] =
    {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, args[4])),
        // Backdoor: TODO: think of a better solution
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, E9_BACKDOOR, 3, 0),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGILL, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    }; 
    struct sock_fprog fprog =
    {
        (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        filter
    };
    r = e9syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, /*flags=*/0x0,
        &fprog);
    if (r < 0)
        e9panic("seccomp() failed (errno=%u)", -r);
}

/*
 * Get an address.
 */
static NO_INLINE const void *e9addr(intptr_t addr, const uint8_t *elf_base)
{
    if ((addr & E9_ABS_ADDR) != 0x0)
        return (const void *)(addr & ~E9_ABS_ADDR);
    else
        return (const void *)(elf_base + addr);
}

/*
 * Loader initialization code.
 */
void *e9init(int argc, char **argv, char **envp, const e9_config_s *config)
{
    // Step (0): Sanity checks & initialization:
    if (config->magic[0] != 'E' || config->magic[1] != '9' ||
            config->magic[2] != 'P' || config->magic[3] != 'A' ||
            config->magic[4] != 'T' || config->magic[5] != 'C' ||
            config->magic[6] != 'H' || config->magic[7] != '\0')
        e9panic("missing \"E9PATCH\" magic number");
    const uint8_t *loader_base = (const uint8_t *)config;
    const uint8_t *loader_end  = loader_base + config->size;
    const uint8_t *elf_base    = loader_base - config->base;

    // Step (1): Find & open the binary:
    char buf[BUFSIZ];
    const char *path = "/proc/self/exe";
    if ((config->flags & E9_FLAG_EXE) == 0)
    {
        // This is a shared object, so use the /proc/self/map_files/
        // method to find the binary.
        char *str = buf;
        str = e9write_format(str, "/proc/self/map_files/%X-%X", loader_base,
            loader_end);
        str = e9write_char(str, '\0');
        path = buf;
    }
    ssize_t len = (ssize_t)e9syscall(SYS_readlink, path, buf, sizeof(buf));
    if (len < 0)
        e9panic("readlink(path=\"%s\") failed (errno=%u)", buf, -len);
    buf[len] = '\0';
    int fd = (int)e9syscall(SYS_open, buf, O_RDONLY, 0);
    if (fd < 0)
        e9panic("open(path=\"%s\") failed (errno=%u)", buf, -fd);

    // Step (2): Setup dummy TLS (if necessary):
    struct e9scratch_s *scratch = NULL;
    uintptr_t tls = 0x0;
    intptr_t r = e9syscall(SYS_arch_prctl, ARCH_GET_FS, &tls);
    if (r < 0)
        e9panic("arch_prctl() failed (errno=%u)", -r);
    if (tls == 0x0)
    {
        // No libc == no tls:
        scratch = e9scratch(config, /*alloc=*/true);
        tls = (uintptr_t)&scratch->tls;
        r = e9syscall(SYS_arch_prctl, ARCH_SET_FS, tls);
        if (r < 0)
            e9panic("arch_prctl() failed (errno=%u)", -r);
        asm volatile ("mov %0,%%fs:0x00" : : "r"(tls));
    }

    // Step (3): Map in the trampoline code:
    mmap_t mmap = e9mmap;
    const struct e9_map_s *maps =
        (const struct e9_map_s *)(loader_base + config->maps[0]);
    e9load_maps(maps, config->num_maps[0], elf_base, fd, mmap);
    if (config->mmap != 0x0)
        mmap = (mmap_t)e9addr(config->mmap, elf_base);
    maps = (const struct e9_map_s *)(loader_base + config->maps[1]);
    e9load_maps(maps, config->num_maps[1], elf_base, fd, mmap);
    e9syscall(SYS_close, fd);

    // Step (4): Call the initialization routines:
    const struct e9_config_elf_s *config_elf =
        (const struct e9_config_elf_s *)(config + 1);
    const void *dynamic = NULL;
    if (config_elf->dynamic != 0x0)
        dynamic = (const void *)(elf_base + config_elf->dynamic);
    const intptr_t *inits = (const intptr_t *)(loader_base + config->inits);
    for (uint32_t i = 0; i < config->num_inits; i++)
    {
        init_t init = (init_t)e9addr(inits[i], elf_base);
        init(argc, argv, envp, dynamic, config);
    }

    // Step (5): Setup SIGILL handler (if necessary):
    if (config->num_traps > 0)
    {
        const uint8_t *handler = loader_base + config->handler;
        struct ksigaction old, action =
        {
            (void *)handler, SA_NODEFER | SA_SIGINFO | SA_RESTORER,
            NULL, 0x0
        };
        intptr_t r = e9syscall(SYS_rt_sigaction, SIGILL, &action, &old, 8,
            E9_BACKDOOR);
        if (r < 0)
            e9panic("sigaction() failed (errno=%u)", -r);
        scratch =
            (scratch == NULL? e9scratch(config, /*alloc=*/true): scratch);
        scratch->next = (e9handler_t)old.sa_handler_2;
        e9filter(scratch);
    }

    // Step (6): Return the entry point:
    void *entry = (void *)e9addr(config->entry, elf_base);
    return entry;
}

/*
 * Loader finalization code.
 */
void *e9fini(const e9_config_s *config)
{
    const uint8_t *loader_base = (const uint8_t *)config;
    const uint8_t *elf_base    = loader_base - config->base;

    const intptr_t *finis = (const intptr_t *)(loader_base + config->finis);
    for (uint32_t i = 0; i < config->num_finis; i++)
    {
        fini_t fini = (fini_t)e9addr(finis[i], elf_base);
        fini(config);
    }

    void *fini = (void *)e9addr(config->fini, elf_base);
    return fini;
}

