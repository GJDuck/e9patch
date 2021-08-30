/*
 * e9loader_elf.cpp
 * Copyright (C) 2021 National University of Singapore
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
#include <cstdint>
#include <cstdlib>

#include <fcntl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include "e9loader.h"

#define NO_INLINE    __attribute__((__noinline__))
#define NO_RETURN   __attribute__((__noreturn__))

#define BUFSIZ      8192
#define PAGE_SIZE   4096

extern "C"
{
    void *e9loader(int argc, char **argv, const struct e9_config_s *config);
    intptr_t e9syscall(long number, ...);
}

asm (
    /*
     * E9Patch loader entry point.
     */
    ".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"
    "\tcallq e9loader\n"
    "\tjmpq *%rax\n"

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
 * Low-level string formatting routines.
 */
static char *e9write_str(char *str, const char *s)
{
    while (*s != '\0')
        *str++ = *s++;
    return str;
}
static char *e9write_char(char *str, char c)
{
    *str++ = c;
    return str;
}
static NO_INLINE char *e9write_hex(char *str, uint64_t x)
{
    if (x == 0)
    {
        *str++ = '0';
        return str;
    }
    bool zero = false;
    int n = 15;
    do
    {
        unsigned digit = (unsigned)((x >> (n * 4)) & 0xF);
        n--;
        if (digit == 0 && !zero)
            continue;
        zero = true;
        if (digit <= 9)
            *str++ = '0' + digit;
        else
            *str++ = 'a' + (digit - 10);
    }
    while (n >= 0);
    return str;
}
static NO_INLINE char *e9write_num(char *str, uint64_t x)
{
    if (x == 0)
    {
        *str++ = '0';
        return str;
    }
    bool zero = false;
    uint64_t r = 10000000000000000000ull;
    do
    {
        unsigned digit = (unsigned)(x / r);
        x %= r;
        r /= 10;
        if (digit == 0 && !zero)
            continue;
        zero = true;
        *str++ = '0' + digit;
    }
    while (r > 0);
    return str;
}
static NO_INLINE char *e9write_format(char *str, const char *msg, va_list ap)
{
    char c;
    while ((c = *msg++) != '\0')
    {
        if (c == '%')
        {
            c = *msg++;
            const char *s;
            uint64_t x;
            int64_t i;
            switch (c)
            {
                case '%':
                    str = e9write_char(str, '%');
                    break;
                case 'c':
                    c = (char)va_arg(ap, int);
                    str = e9write_char(str, c);
                    break;
                case 's':
                    s = va_arg(ap, const char *);
                    str = e9write_str(str, s);
                    break;
                case 'p':
                    str = e9write_str(str, "0x");
                    // Fallthrough
                case 'x': case 'X':
                    x = (c == 'x'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    str = e9write_hex(str, x);
                    break;
                case 'u': case 'U':
                    x = (c == 'u'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    str = e9write_num(str, x);
                    break;
                case 'd': case 'D':
                    i = (c == 'd'? va_arg(ap, unsigned): va_arg(ap, uint64_t));
                    if (i < 0)
                        str = e9write_char(str, '-');
                    str = e9write_num(str, (uint64_t)(i < 0? -i: i));
                    break;
            }
            continue;
        }
        str = e9write_char(str, c);
    }
    return str;
}
static char *e9write_format(char *str, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    str = e9write_format(str, msg, ap);
    va_end(ap);
    return str;
}

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
    __builtin_unreachable();
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

typedef intptr_t (*mmap_t)(void *, size_t, int, int, int, off_t);
typedef void (*init_t)(int, char **, char **, void *);

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
#if 0
        e9debug("mmap(addr=%p,size=%U,offset=+%U,prot=%c%c%c)",
            addr, len, offset,
            (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
            (maps[i].x? 'x': '-'));
#endif
        intptr_t result = mmap((void *)addr, len, prot, MAP_FIXED | MAP_PRIVATE,
            fd, offset);
        if (result < 0)
            e9panic("mmap(addr=%p,size=%U,offset=+%U,prot=%c%c%c) failed "
                "(errno=%u)", addr, len, offset,
                (maps[i].r? 'r': '-'), (maps[i].w? 'w': '-'),
                (maps[i].x? 'x': '-'), -(int)result);
    }
}

/*
 * Main loader code.
 */
void *e9loader(int argc, char **argv, const e9_config_s *config)
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

    // Step (2): Map in the trampoline code:
    mmap_t mmap = e9mmap;
    const struct e9_map_s *maps =
        (const struct e9_map_s *)(loader_base + config->maps[0]);
    e9load_maps(maps, config->num_maps[0], elf_base, fd, mmap);
    if (config->mmap != 0x0)
        mmap = (mmap_t)(elf_base + config->mmap);
    maps = (const struct e9_map_s *)(loader_base + config->maps[1]);
    e9load_maps(maps, config->num_maps[1], elf_base, fd, mmap);
    e9syscall(SYS_close, fd);

    // Step (3): Call the initialization routines:
    void *dynamic = NULL;
    char **envp = NULL;
    if ((config->flags & E9_FLAG_EXE) != 0)
    {
        if (config->dynamic != 0x0)
            dynamic = (void *)(elf_base + config->dynamic);
        envp = argv + argc;
    }
    const intptr_t *inits = (const intptr_t *)(loader_base + config->inits);
    for (uint16_t i = 0; i < config->num_inits; i++)
    {
        init_t init = (init_t)(elf_base + inits[i]);
        init(argc, argv, envp, dynamic);
    }

    // Step (4): Return the entry point:
    void *entry = (void *)(elf_base + config->entry);
    return entry;
}

