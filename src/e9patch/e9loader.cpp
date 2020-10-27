/*
 * e9loader.cpp
 * Copyright (C) 2020 National University of Singapore
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
#include <cstdint>
#include <cstdlib>

#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "e9loader.h"

#define NO_INLINE    __attribute__((__noinline__))
#define NO_RETURN   __attribute__((__noreturn__))

#define STRING(x)   STRING_2(x)
#define STRING_2(x) #x

#define BUFSIZ      8192

static NO_INLINE int e9binary(char *path_buf);

extern const char mapsname[];
extern const char maps_err_str[];
extern const char open_err_str[];
extern const char mmap_err_str[];
extern const char common_err_str[];

extern "C"
{
    int e9entry(void);
    NO_INLINE NO_RETURN void e9error(const char *err_str, int err);
}

/*
 * Directory entry structure.
 */
struct linux_dirent64
{
    ino64_t        d_ino;
    off64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

asm (
    /*
     * Entry into stage #1.  We:
     *  (1) save the state.
     *  (2) call e9entry()
     *  (3) setup stage #2 parameters
     *  (4) jump to stage #2
     */
    ".globl _entry\n"
    ".type _entry,@function\n"
    "_entry:\n"
    
    // (1) save the state
    "\tpushq %r15\n"
    "\tpushq %r14\n"
    "\tpushq %r13\n"
    "\tpushq %r12\n"
    "\tpushq %r11\n"
    "\tpushq %r10\n"
    "\tpushq %r9\n"
    "\tpushq %r8\n"
    "\tpushq %rcx\n"
    "\tpushq %rdx\n"
    "\tpushq %rsi\n"
    "\tpushq %rdi\n"

    // (2) call e9entry()
    "\tcallq e9entry\n"                     // Call main entry routine

    // (3) setup stage #2 parameters
    // Stage #2 expects certain parameters to be in specific registers:
    "\tmov %eax, %r8d\n"                    // fd into %r8
    "\tleaq _entry(%rip), %r12\n"           // base into %r12
    "\tmovabs $" STRING(LOADER_ADDRESS) ",%rdx\n"
    "\tsubq %rdx,%r12\n"
    "\tmov $9, %r13d\n"                     // SYS_MMAP into %r13
    "\tleaq .LMMAP_ERROR(%rip), %r14\n"     // mmap error handler into %r14

    // (4) jump to stage #2
    // Stage #2 will be placed at the end of the (.text) section.
    "\tjmp __etext\n"
    
    /*
     * The following defines the read-only data used by the loader.
     * Note that we define the data as executable code to keep everything
     * in the (.text) section.
     */
    ".global mapsname\n"
    ".type mapsname,@function\n"
    "mapsname:\n"
    ".ascii \"/proc/self/map_files/\"\n"
    ".byte 0x00\n"

    ".globl maps_err_str\n"
    ".type maps_err_str,@function\n"
    "maps_err_str:\n"
    ".ascii \"find shared object path (errno=%d)\\n\"\n"
    ".byte 0x00\n"

    ".globl open_err_str\n"
    ".type open_err_str,@function\n"
    "open_err_str:\n"
    ".ascii \"open file \\\"%s\\\" for reading (errno=%d)\\n\"\n"
    ".byte 0x00\n"

    ".globl mmap_err_str\n"
    ".type mmap_err_str,@function\n" 
    "mmap_err_str:\n"
    ".ascii \"map file \\\"%s\\\" (errno=%d)\\n\"\n"
    ".byte 0x00\n"

    ".globl common_err_str\n"
    ".type common_err_str,@function\n" 
    "common_err_str:\n"
    ".ascii \"e9loader error: failed to \"\n"
    ".byte 0x00\n"

    /*
     * mmap() error handling code goes here.
     */
    ".LMMAP_ERROR:\n"
    "\tleaq mmap_err_str(%rip), %rdi\n"
    "\tmov %rax, %rsi\n"
    "\tneg %rsi\n"
    "\tjmp e9error\n"

);

static int e9open(const char *filename_0, int flags_0, int mode_0)
{
    register uintptr_t filename asm("rdi") = (uintptr_t)filename_0;
    register uintptr_t flags asm("rsi")    = (uintptr_t)flags_0;
    register uintptr_t mode asm("rdx")     = (uintptr_t)mode_0;
    register intptr_t fd asm("rax");

    asm volatile (
        "mov $2, %%eax\n\t"             // SYS_OPEN
        "syscall"
        : "=rax"(fd) : "r"(filename), "r"(flags), "r"(mode) : "rcx", "r11");

    return (int)fd;
}

static int e9write(int fd_0, const char *buf_0, size_t len_0)
{
    register uintptr_t fd asm("rdi")  = (uintptr_t)fd_0;
    register uintptr_t buf asm("rsi") = (uintptr_t)buf_0;
    register uintptr_t len asm("rdx") = (uintptr_t)len_0;
    register intptr_t err asm("rax");

    asm volatile (
        "mov $1, %%eax\n\t"              // SYS_WRITE
        "syscall"
        : "=rax"(err) : "r"(fd), "r"(buf), "r"(len) : "rcx", "r11");

    return (int)err;
}

static int e9kill(pid_t pid_0, int sig_0)
{
    register uintptr_t pid asm("rdi") = (uintptr_t)pid_0;
    register uintptr_t sig asm("rsi") = (uintptr_t)sig_0;
    register intptr_t err asm("rax");

    asm volatile (
        "mov $62, %%eax\n\t"             // SYS_KILL
        "syscall"
        : "=rax"(err) : "r"(pid), "r"(sig): "rcx", "r11");

    return (int)err;
}

static int e9readlink(const char *path_0, char *buf_0, size_t len_0)
{
    register uintptr_t path asm("rdi") = (uintptr_t)path_0;
    register uintptr_t buf asm("rsi")  = (uintptr_t)buf_0;
    register uintptr_t len asm("rdx")  = (uintptr_t)len_0;
    register intptr_t err asm("rax");

    asm volatile (
        "mov $89, %%eax\n\t"             // SYS_READLINK
        "syscall"
        : "=rax"(err) : "r"(path), "r"(buf), "r"(len) : "rcx", "r11");

    return (int)err;
}

static int e9getdents64(int fd_0, struct linux_dirent64 *dirp_0,
    unsigned count_0)
{
    register uintptr_t fd asm("rdi")    = (uintptr_t)fd_0;
    register uintptr_t dirp asm("rsi")  = (uintptr_t)dirp_0;
    register uintptr_t count asm("rdx") = (uintptr_t)count_0;
    register intptr_t len asm("rax");

    asm volatile (
        "mov $217, %%eax\n\t"           // SYS_GETDENTS64
        "syscall"
        : "=rax"(len) : "r"(fd), "r"(dirp), "r"(count) : "rcx", "r11");

    return (int)len;
}

static int e9close(int fd_0)
{
    register uintptr_t fd asm("rdi") = (uintptr_t)fd_0;
    register intptr_t err asm("rax");

    asm volatile (
        "mov $3, %%eax\n\t"             // SYS_CLOSE
        "syscall"
        : "=rax"(err) : "r"(fd) : "rcx", "r11");

    return (int)err;
}

/*
 * Convert a number into a string.
 */
static char *e9num2str(char *str, int x)
{
    int r = 1000000000;
    bool seen = false;
    while (r != 0)
    {
        char c = '0' + x / r;
        x %= r;
        r /= 10;
        if (!seen && c == '0')
            continue;
        seen = true;
        *str++ = c;
    }
    if (!seen)
        *str++ = '0';
    return str;
}

/*
 * Print an error message to stderr and abort.
 */
NO_INLINE NO_RETURN void e9error(const char *err_str, int err)
{
    char path_buf[BUFSIZ];
    int result = e9binary(path_buf);
    if (result != 0)
    {
        path_buf[0] = path_buf[1] = path_buf[2] = '?';
        path_buf[3] = '\0';
    }
    const char *path = path_buf;

    char str_buf[BUFSIZ];
    char *str = str_buf;

    const char *err_str_0 = common_err_str;
    while (*err_str_0 != '\0')
        *str++ = *err_str_0++;
    while (*err_str != '\0')
    {
        if (*err_str == '%')
        {
            err_str++;
            switch (*err_str++)
            {
                case 'd':
                    str = e9num2str(str, err);
                    break;
                case 's':
                    while (*path != '\0')
                        *str++ = *path++;
                    break;
            }
        }
        else
            *str++ = *err_str++;
    }
    (void)e9write(STDERR_FILENO, str_buf, str - str_buf);
    (void)e9kill(/*pid=*/0, SIGABRT);
    asm volatile ("ud2");
    __builtin_unreachable();
}

/*
 * Convert a hex string into a number.
 */
static intptr_t e9hexstr2num(const char **str_ptr)
{
    const char *str = *str_ptr;
    intptr_t x = 0;
    while (true)
    {
        char c = *str++;
        if (c >= '0' && c <= '9')
        {
            x <<= 4;
            x |= (intptr_t)(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            x <<= 4;
            x |= (intptr_t)(10 + c - 'a');
        }
        else
        {
            *str_ptr = str;
            return x;
        }
    }
}

/*
 * Place the pathname of enclosing binary into `path_buf'.
 */
static NO_INLINE int e9binary(char *path_buf)
{
    // Step (1): Read contents of /proc/self/map_files/
    int fd = e9open(mapsname, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return fd;
    uint8_t buf[BUFSIZ];

    // Step (2): Search for an entry corresponding to the enclosing function.
    intptr_t code = (intptr_t)&e9binary;
    bool found = false;
    while (!found)
    {
        int len = e9getdents64(fd, (struct linux_dirent64 *)buf, sizeof(buf));
        if (len < 0)
        {
            e9close(fd);
            return len;
        }

        for (int i = 0; !found && i < len; )
        {
            struct linux_dirent64 *entry = (struct linux_dirent64 *)(buf + i);
            i += entry->d_reclen;
            if (entry->d_type != DT_LNK)
                continue;

            const char *name = entry->d_name;
            intptr_t lo = e9hexstr2num(&name);
            if (code < lo)
                continue;
            intptr_t hi = e9hexstr2num(&name);
            if (code <= hi)
            {
                int j;
                for (j = 0; mapsname[j] != '\0'; j++)
                    path_buf[j] = mapsname[j];
                name = entry->d_name;
                for (int k = 0; name[k] != '\0'; k++)
                    path_buf[j++] = name[k];
                path_buf[j] = '\0';
                found = true;
            }
        }
    }
    e9close(fd);

    // Step (3): Read the link.
    // Note: this is necessary since Linux does not allow the path to be
    //       opened directly.
    int len = e9readlink(path_buf, path_buf, BUFSIZ);
    if (len < 0)
        return len;
    path_buf[len] = '\0';
    return 0;
}

int e9entry(void)
{
    char path_buf[BUFSIZ];
    int err = e9binary(path_buf);
    if (err != 0)
        e9error(maps_err_str, -err);

    int fd = e9open(path_buf, O_RDONLY, 0);
    if (fd < 0)
        e9error(open_err_str, -fd);
    return fd;
}

