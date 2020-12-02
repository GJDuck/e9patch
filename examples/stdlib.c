/*      _      _ _ _ _ 
 *  ___| |_ __| | (_) |__
 * / __| __/ _` | | | '_ \
 * \__ \ || (_| | | | |_) |
 * |___/\__\__,_|_|_|_.__/
 *
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

#ifndef __STDLIB_C
#define __STDLIB_C

/*
 * This is a single-file WYSIWYG static libc replacement.  To use, simply
 * #include the entire file as follows:
 *
 *    #include "stdlib.c"
 *
 * Since the functions are defined as "static", the compiler should remove
 * any unused functions from the final binary.
 *
 * NOTES:
 *
 * It is tempting to use the "real" libc.  However, this will break
 * transparency: the real libc has internal state (e.g., errno) that will be
 * changed via standard library calls, which can subtly change the behaviour
 * of the main program.  This libc has an internal state that is completely
 * disjoint from the program's libc.
 *
 * Furthermore, standard library calls assume the SYSV ABI, which assumes the
 * stack is aligned and the floating point register state has been saved.
 * These are not preversed under the clean ABI, and transitioning between ABIs
 * is an expensive operation.  This libc is designed to be compatible with the
 * clean ABI.
 *
 * Finally, call instrumentation is a hostile environment where we cannot
 * control when or where the instrumentation is invoked.  This can easily
 * lead to deadlocks and other problems (e.g., a signal occurs while a lock
 * is held, causing the instrumentation to be invoked again, and another
 * attempt to acquire the lock).  This libc is designed to handle such cases
 * more gracefully.
 *
 * DESIGN:
 *
 * Generally, the code has been optimized for size and compilation time
 * rather than performance.  Dependencies between library functions has also
 * been minimized to keep the resulting binary small.  For example, fopen()
 * calls mmap() rather than malloc() to allocate memory.  This avoids pulling
 * in the malloc() implementation for a program that only uses stream I/O.
 * Generally, this file can be compiled in a second or less, depending on how
 * many functions are used.  
 *
 * This file also assumes no initialization, or failing that, manual
 * initialization (e.g., setting `environ' for getenv()).
 *
 * WARNING:
 *
 * This file maintains a separate state to the rewritten binary libc.  The
 * two libcs cannot be mixed.  For example, you cannot allocate an object
 * using this file's malloc() and pass it to the main program to be free'ed
 * using libc's free(), and expected everything to work.  Furthermore, the
 * errno is different from the main program's errno, etc.
 *
 * Note however that kernel objects such as file descriptors may be shared.
 * Although disjoint, the stdin/stdout/stderr streams operate on the same
 * underlying files meaning that they must be used with care.
 */

/*
 * Note: We need to redefine libc functions from "extern" to "static".
 *       There does not seem to be an elegant way of doing this, so we
 *       rename the functions in the #include'd files.
 *       Even this method can fail, e.g., if the header #undef's it.
 */
#define __errno_location    __hide____errno_location
#define read                __hide__read
#define write               __hide__write
#define open                __hide__open
#define close               __hide__close
#define stat                __hide__stat
#define fstat               __hide__fstat
#define lstat               __hide__lstat
#define poll                __hide__poll
#define lseek               __hide__lseek
#define mmap                __hide__mmap
#define mprotect            __hide__mprotect
#define msync               __hide__msync
#define munmap              __hide__munmap
#define sigaction(a, b, c)  __hide__sigaction(a, b, c)
#define ioctl               __hide__ioctl
#define pipe                __hide__pipe
#define select              __hide__select
#define mremap              __hide__mremap
#define madvise             __hide__madvise
#define shmget              __hide__shmget
#define shmat               __hide__shmat
#define shmctl              __hide__shmctl
#define dup                 __hide__dup
#define dup2                __hide__dup2
#define getpid              __hide__getpid
#define fork                __hide__fork
#define execve              __hide__execve
#define exit                __hide__exit
#define waitpid             __hide__waitpid
#define kill                __hide__kill
#define fcntl               __hide__fcntl
#define flock               __hide__flock
#define fsync               __hide__fsync
#define truncate            __hide__truncate
#define ftruncate           __hide__ftruncate
#define getcwd              __hide__getcwd
#define chdir               __hide__chdir
#define rename              __hide__rename
#define mkdir               __hide__mkdir
#define rmdir               __hide__rmdir
#define link                __hide__link
#define unlink              __hide__unlink
#define gettimeofday        __hide__gettimeofday
#define getrlimit           __hide__getrlimit
#define getrusage           __hide__getrusage
#define getuid              __hide__getuid
#define geteuid             __hide__geteuid
#define pipe2               __hide__pipe2
#define dup3                __hide__dup3
#define isatty              __hide__isatty

#define malloc              __hide__malloc
#define realloc             __hide__realloc
#define free                __hide__free
#define getenv              __hide__getenv
#define strtol              __hide__strtol
#define strtoll             __hide__strtoll
#define strtoul             __hide__strtoul
#define strtoull            __hide__strtoull
#define atoi                __hide__atoi
#define atol                __hide__atol
#define atoll               __hide__atoll
#define abort               __hide__abort
#define abs                 __hide__abs
#define labs                __hide__labs
#define environ             __hide__environ

#define FILE                __hide__FILE
#define fopen               __hide__fopen
#define fdopen              __hide__fdopen
#define freopen             __hide__freopen
#define clearerr            __hide__clearerr
#define ferror              __hide__ferror
#define feof                __hide__feof
#define fileno              __hide__fileno
#define setvbuf             __hide__setvbuf
#define fflush              __hide__fflush
#define fclose              __hide__fclose
#define fputc               __hide__fputc
#define fputs               __hide__fputs
#define putc                __hide__putc
#define putchar             __hide__putchar
#define puts                __hide__puts
#define fwrite              __hide__fwrite
#define fgetc               __hide__fgetc
#define fgets               __hide__fgets
#define getc                __hide__getc
#define getchar             __hide__getchar
#define ungetc              __hide__ungetc
#define fread               __hide__fread
#define fseek               __hide__fseek
#define ftell               __hide__ftell
#define clearerr_unlocked   __hide__clearerr_unlocked
#define feof_unlocked       __hide__feof_unlocked
#define ferror_unlocked     __hide__ferror_unlocked
#define fileno_unlocked     __hide__fileno_unlocked
#define fflush_unlocked     __hide__fflush_unlocked
#define fputc_unlocked      __hide__fputc_unlocked
#define fputs_unlocked      __hide__fputs_unlocked
#define putc_unlocked       __hide__putc_unlocked
#define putchar_unlocked    __hide__putchar_unlocked
#define puts_unlocked       __hide__puts_unlocked
#define fwrite_unlocked     __hide__fwrite_unlocked
#define fgetc_unlocked      __hide__fgetc_unlocked
#define fgets_unlocked      __hide__fgets_unlocked
#define getc_unlocked       __hide__getc_unlocked
#define getchar_unlocked    __hide__getchar_unlocked
#define fread_unlocked      __hide__fread_unlocked
#define vsnprintf           __hide__vsnprintf
#define snprintf            __hide__snprintf
#define vfprintf            __hide__vfprintf
#define fprintf             __hide__fprintf
#define printf              __hide__printf

#define isalnum             __hide__isalnum
#define isalpha             __hide__isalpha
#define isdigit             __hide__isdigit
#define islower             __hide__islower
#define isprint             __hide__isprint
#define isspace             __hide__isspace
#define isxdigit            __hide__isxdigit
#define toupper             __hide__toupper
#define tolower             __hide__tolower

#define memcmp              __hide__memcmp
#define memcpy              __hide__memcpy
#define memset              __hide__memset
#define strlen              __hide__strlen
#define strnlen             __hide__strnlen
#define strcmp              __hide__strcmp
#define strncmp             __hide__strncmp
#define strcat              __hide__strcat
#define strncat             __hide__strncat
#define strcpy              __hide__strcpy
#define strncpy             __hide__strncpy
#define strerror            __hide__strerror

#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/syscall.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#undef __errno_location
#undef read
#undef write
#undef open
#undef close
#undef stat
#undef fstat
#undef lstat
#undef poll
#undef lseek
#undef mmap
#undef mprotect
#undef msync
#undef munmap
#undef sigaction
#undef ioctl
#undef pipe
#undef select
#undef mremap
#undef madvise
#undef shmget
#undef shmat
#undef shmctl
#undef dup
#undef dup2
#undef getpid
#undef fork
#undef execve
#undef exit
#undef waitpid
#undef kill
#undef fcntl
#undef flock
#undef fsync
#undef truncate
#undef ftruncate
#undef getcwd
#undef chdir
#undef rename
#undef mkdir
#undef rmdir
#undef link
#undef unlink
#undef gettimeofday
#undef getrlimit
#undef getrusage
#undef getuid
#undef geteuid
#undef pipe2
#undef dup3
#undef isatty

#undef malloc
#undef realloc
#undef free
#undef getenv
#undef strtol
#undef strtoll
#undef strtoul
#undef strtoull
#undef atoi
#undef atol
#undef atoll
#undef abort
#undef abs
#undef labs
#undef environ

#undef FILE
#undef fopen
#undef fdopen
#undef freopen
#undef fflush
#undef fclose
#undef clearerr
#undef ferror
#undef feof
#undef fileno
#undef setvbuf
#undef fputc
#undef fputs
#undef putc
#undef putchar
#undef puts
#undef fwrite
#undef fgetc
#undef fgets
#undef getc
#undef getchar
#undef ungetc
#undef fread
#undef fseek
#undef ftell
#undef clearerr_unlocked
#undef feof_unlocked
#undef ferror_unlocked
#undef fileno_unlocked
#undef fflush_unlocked
#undef fputc_unlocked
#undef fputs_unlocked
#undef putc_unlocked
#undef putchar_unlocked
#undef puts_unlocked
#undef fwrite_unlocked
#undef fgetc_unlocked
#undef fgets_unlocked
#undef getc_unlocked
#undef getchar_unlocked
#undef fread_unlocked
#undef vsnprintf
#undef snprintf
#undef vfprintf
#undef fprintf
#undef printf

#undef isalnum
#undef isalpha
#undef isdigit
#undef islower
#undef isprint
#undef isspace
#undef isxdigit
#undef toupper
#undef tolower

#undef memcmp
#undef memset
#undef memcpy
#undef strlen
#undef strnlen
#undef strcmp
#undef strncmp
#undef strcat
#undef strncat
#undef strcpy
#undef strncpy
#undef strerror

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************/
/* CONFIG                                                                   */
/****************************************************************************/

/*
 * If NO_GLIBC is defined, enable a configuration that works if glibc is NOT
 * used by the main program.
 */
#ifdef NO_GLIBC
#define ERRNO_REG       1
#define MUTEX_SAFE      1
#endif

/****************************************************************************/
/* DEBUG                                                                    */
/****************************************************************************/

#define STRING(x)           STRING_2(x)
#define STRING_2(x)         #x

static ssize_t write(int fd, const void *buf, size_t count);
static int vsnprintf(char *str, size_t size, const char *format, va_list ap);

static __attribute__((__noinline__)) void debug_impl(const char *format, ...)
{
    va_list ap, ap2;
    va_start(ap, format);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, format, ap);
    if (n >= 0)
    {
        char buf[n+1];
        int r = vsnprintf(buf, sizeof(buf), format, ap2);
        if (r == n)
            write(STDERR_FILENO, buf, n);
    }
    va_end(ap);
}

#define debug(format, ...)                                                  \
    debug_impl("\33[35mdebug\33[0m: " __FILE__ ": " STRING(__LINE__) ": "   \
        format "\n", ## __VA_ARGS__)

/****************************************************************************/
/* ERRNO                                                                    */
/****************************************************************************/

#if !defined(ERRNO_TLS) && !defined(ERRNO_REG)
#define ERRNO_TLS       // Use TLS by default 
#endif

#ifdef ERRNO_TLS
/*
 * Errno is stored in thread-local address %fs:ERRNO_TLS_OFFSET, which is
 * hopefully unused by the program (it should be unused by default).  If it
 * is used, then define ERRNO_TLS_OFFSET to be something else.  This assumes
 * the program uses libc.
 */
#ifndef ERRNO_TLS_OFFSET
#define ERRNO_TLS_OFFSET          0x40
#endif
static __attribute__((__noinline__)) int *__errno_location(void)
{
    register int *loc asm ("rax");
    asm volatile (
        "mov %%fs:0x0,%0\n"
        "lea " STRING(ERRNO_TLS_OFFSET) "(%0),%0\n" : "=r"(loc)
    );
    return loc;
}
#endif

#ifdef ERRNO_REG
/*
 * Errno is stored in %r11.
 *
 * This generates a warning message "call-clobbered register used for global
 * register variable" and an error message in clang.  It should be safe for
 * our purposes where we never call external libraries.  Note however that
 * errno value will be clobbered by the main progam.
 */ 
#undef errno
register int errno asm ("r11");
#endif

/****************************************************************************/
/* SYSCALL                                                                  */
/****************************************************************************/

#ifdef ERRNO_TLS
asm (
    ".globl syscall\n"
    "syscall:\n"

    "mov %edi,%eax\n"
    "mov %rsi,%rdi\n"
    "mov %rdx,%rsi\n"
    "mov %rcx,%rdx\n"
    "mov %r8,%r10\n"
    "mov %r9,%r8\n"
    "mov 0x8(%rsp),%r9\n"

    "syscall\n"

    "test %rax,%rax\n"
    "jge .Lsyscall_ok\n"

    "neg %rax\n"
    "mov %rax,%fs:" STRING(ERRNO_TLS_OFFSET) "\n"
    "mov $-1,%rax\n"
    ".Lsyscall_ok:\n"
    "retq\n"
);
#endif

#ifdef ERRNO_REG
asm (
    ".globl syscall\n"
    "syscall:\n"

    "push %r11\n"
    "mov %edi,%eax\n"
    "mov %rsi,%rdi\n"
    "mov %rdx,%rsi\n"
    "mov %rcx,%rdx\n"
    "mov %r8,%r10\n"
    "mov %r9,%r8\n"
    "mov 0x10(%rsp),%r9\n"

    "syscall\n"

    "pop %r11\n" 
    "test %rax,%rax\n"
    "jge .Lsyscall_ok\n"

    "neg %rax\n"
    "mov %rax,%r11\n"         // Store into errno
    "mov $-1,%rax\n"

    ".Lsyscall_ok:\n"
    "retq\n"
);
#endif

static ssize_t read(int fd, void *buf, size_t count)
{
    return (ssize_t)syscall(SYS_read, fd, buf, count);
}

static ssize_t write(int fd, const void *buf, size_t count)
{
    return (ssize_t)syscall(SYS_write, fd, buf, count);
}

static int open(const char *pathname, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    int result = (int)syscall(SYS_open, pathname, flags, mode);
    va_end(ap);
    return result;
}

static int close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

struct stat;
static int stat(const char *pathname, struct stat *buf)
{
    return (int)syscall(SYS_stat, pathname, buf);
}

static int fstat(int fd, struct stat *buf)
{
    return (int)syscall(SYS_fstat, fd, buf);
}

static int lstat(const char *pathname, struct stat *buf)
{
    return (int)syscall(SYS_lstat, pathname, buf);
}

static int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return (int)syscall(SYS_poll, fds, nfds, timeout);
}

static off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)syscall(SYS_lseek, fd, offset, whence);
}

static void *mmap(void *addr, size_t length, int prot, int flags, int fd,
    off_t offset)
{
    return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
}

static int mprotect(void *addr, size_t len, int prot)
{
    return (int)syscall(SYS_mprotect, addr, len, prot);
}

static int msync(void *addr, size_t length, int flags)
{
    return (int)syscall(SYS_msync, addr, length, flags);
}

static int munmap(void *addr, size_t length)
{
    return (int)syscall(SYS_munmap, addr, length);
}

static int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    unsigned long arg = va_arg(ap, unsigned long);
    int result = (int)syscall(SYS_ioctl, fd, request, arg);
    va_end(ap);
    return result;
}

static int pipe(int pipefd[2])
{
    return (int)syscall(SYS_pipe, pipefd);
}

static int select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    return (int)syscall(SYS_select, nfds, readfds, writefds, exceptfds,
        timeout);
}

static void *mremap(void *old_address, size_t old_size, size_t new_size,
    int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    void *new_address = va_arg(ap, void *);
    void *ptr = (void *)syscall(SYS_mremap, old_address, old_size, new_size,
        flags, new_address);
    va_end(ap);
    return ptr;
}

static int madvise(void *addr, size_t length, int advice)
{
    return (int)syscall(SYS_madvise, addr, length, advice);
}

static int shmget(key_t key, size_t size, int shmflg)
{
    return (int)syscall(SYS_shmget, key, size, shmflg);
}

static void *shmat(int shmid, const void *shmaddr, int shmflg)
{
    return (void *)syscall(SYS_shmat, shmid, shmaddr, shmflg);
}

struct shmid_ds;
static int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
    return (int)syscall(SYS_shmctl, shmid, cmd, buf);
}

static int dup(int oldfd)
{
    return (int)syscall(SYS_dup, oldfd);
}

static int dup2(int oldfd, int newfd)
{
    return (int)syscall(SYS_dup2, oldfd, newfd);
}

static pid_t getpid(void)
{
    return (pid_t)syscall(SYS_getpid);
}

static pid_t fork(void)
{
    return (pid_t)syscall(SYS_fork);
}

static int execve(const char *filename, char *const argv[],
    char *const envp[])
{
    return (int)syscall(SYS_execve, filename, argv, envp);
}

static void exit(int status)
{
    (void)syscall(SYS_exit, status);
    __builtin_unreachable();
}

static pid_t waitpid(pid_t pid, int *status, int options)
{
    return (pid_t)syscall(SYS_wait4, pid, status, options, NULL);
}

static int kill(pid_t pid, int sig)
{
    return (int)syscall(SYS_kill, pid, sig);
}

static int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    int arg = va_arg(ap, int);
    int result = (int)syscall(SYS_fcntl, fd, cmd, arg);
    va_end(ap);
    return result;
}

static int flock(int fd, int operation)
{
    return (int)syscall(SYS_flock, fd, operation);
}

static int fsync(int fd)
{
    return (int)syscall(SYS_fsync, fd);
}

static int truncate(const char *path, off_t length)
{
    return (int)syscall(SYS_truncate, path, length);
}

static int ftruncate(int fd, off_t length)
{
    return (int)syscall(SYS_ftruncate, fd, length);
}

static char *getcwd(char *buf, size_t size)
{
    long result = syscall(SYS_getcwd, buf, size);
    return (result < 0? NULL: buf);
}

static int chdir(const char *path)
{
    return (int)syscall(SYS_chdir, path);
}

static int rename(const char *oldpath, const char *newpath)
{
    return (int)syscall(SYS_rename, oldpath, newpath);
}

static int mkdir(const char *pathname, mode_t mode)
{
    return (int)syscall(SYS_mkdir, pathname, mode);
}

static int rmdir(const char *pathname)
{
    return (int)syscall(SYS_rmdir, pathname);
}

static int link(const char *oldpath, const char *newpath)
{
    return (int)syscall(SYS_link, oldpath, newpath);
}

static int unlink(const char *pathname)
{
    return (int)syscall(SYS_unlink, pathname);
}

static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return (int)syscall(SYS_gettimeofday, tv, tz);
}

static int getrlimit(int resource, struct rlimit *rlim)
{
    return (int)syscall(SYS_getrlimit, resource, rlim);
}

static int getrusage(int who, struct rusage *usage)
{
    return (int)syscall(SYS_getrusage, who, usage);
}

static uid_t getuid(void)
{
    return (uid_t)syscall(SYS_getuid);
}

static uid_t geteuid(void)
{
    return (uid_t)syscall(SYS_geteuid);
}

static int dup3(int oldfd, int newfd, int flags)
{
    return (int)syscall(SYS_dup3, oldfd, newfd, flags);
}

static int pipe2(int pipefd[2], int flags)
{
    return (int)syscall(SYS_pipe2, pipefd, flags);
}

static int getrandom(void *buf, size_t buflen, unsigned int flags)
{
    return (int)syscall(SYS_getrandom, buf, buflen, flags);
}

static int isatty(int fd)
{
    struct termios buf;
    if (ioctl(fd, TCGETS, &buf) < 0)
    {
        if (errno == EINVAL)
            errno = ENOTTY;
        return 0;
    }
    return 1;
}

/****************************************************************************/
/* PANIC                                                                    */
/****************************************************************************/

#define panic(msg_str)                                                      \
    do                                                                      \
    {                                                                       \
        const char msg[] = __FILE__ ": " STRING(__LINE__) ": "  msg_str     \
            "\n";                                                           \
        write(STDERR_FILENO, msg, sizeof(msg)-1);                           \
        kill(getpid(), SIGABRT);                                            \
        asm volatile ("ud2");                                               \
        __builtin_unreachable();                                            \
    }                                                                       \
    while (false)

/****************************************************************************/
/* MUTEX                                                                    */
/****************************************************************************/

/*
 * These are not part of libc, but are essential functionality.
 *
 * The mutex implementation has to survive a much more hostile environment
 * than normal pthread/glibc code.  For example:
 *
 *  (1) a signal may occur while holding the lock, causing another
 *      instrumentation call, leading to a deadlock.
 *  (2) a thread holding a lock can be killed anytime by the program.
 *
 * The first is common in practice, and the second can occur if the program
 * does not use a standard/sane implementations of threads.
 *
 * We implement two kinds of mutexes:
 *
 *  - MUTEX_FAST (default): assumes libc and that (2) does not hold; and
 *  - MUTEX_SAFE: no assumptions but slow (!).
 *
 * The MUTEX_SAFE variant resorts to a syscall for every lock/unlock
 * operation.
 */

#include <linux/futex.h>

#ifndef MUTEX_SAFE

static pid_t mutex_gettid(void)
{
    register pid_t tid asm ("eax");
    // Warning: this assumes the thread ID is stored at %fs:0x2d0.
    asm volatile (
        "mov %%fs:0x2d0,%0\n" : "=r"(tid)
    );
    return tid;
}

static bool mutex_fast_lock(pid_t *x)
{
    pid_t self  = mutex_gettid();
    pid_t owner = __sync_val_compare_and_swap(x, 0, self);
    return (owner == 0);
}

static bool mutex_fast_unlock(pid_t *x)
{
    pid_t self = mutex_gettid();
    return __sync_bool_compare_and_swap(x, self, 0);
}

#else

#define mutex_fast_lock(x)      false
#define mutex_fast_unlock(x)    false

#endif

struct mutex_s
{
    // The stack may be unaligned, so we do manual alignment.
    uint8_t val[2 * sizeof(int)];
};
typedef struct mutex_s mutex_t;

#define MUTEX_INITIALIZER       {{0}}

static pid_t *mutex_get_ptr(const mutex_t *m)
{
    uintptr_t ptr = (uintptr_t)m->val + sizeof(int);
    return (pid_t *)(ptr & ~0x3ull);
}

/*
 * NOTE: mutex_lock() is marked with the __warn_unused_result__ attribute.
 *       This is because this function can fail with EDEADLOCK in normal use
 *       cases, so the return value should always be checked.
 */
static __attribute__((__noinline__, __warn_unused_result__)) int mutex_lock(mutex_t *m)
{
    pid_t *x = mutex_get_ptr(m);
    if (mutex_fast_lock(x))
        return 0;
    if (syscall(SYS_futex, x, FUTEX_LOCK_PI, 0, NULL, NULL, 0) < 0)
        return -1;
    if (*x & FUTEX_OWNER_DIED)
    {
        // This can occur if a thread dies while holding a lock.
        errno = EOWNERDEAD;
        return -1;
    }
    return 0;                       // acquired
}

static __attribute__((__noinline__)) int mutex_unlock(mutex_t *m)
{
    pid_t *x = mutex_get_ptr(m);
    if (mutex_fast_unlock(x))
        return 0;
    if (syscall(SYS_futex, x, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) < 0)
        return -1;
    return 0;                       // released
}

/****************************************************************************/
/* MALLOC                                                                   */
/****************************************************************************/

/*
 * We use a variant of the LowFat allocator (https://github.com/GJDuck/LowFat).
 * This is mainly due its small size and simple design.
 */

#define MALLOC_PAGE_SIZE        4096
#define MALLOC_POOL_SIZE        (1ull << 30)        // 1GB
#define MALLOC_POOL_MAX         61

struct malloc_header_s
{
    size_t size:32;                                 // malloc size
    size_t idx:32;                                  // region index
    struct malloc_header_s *next;                   // freelist next
};

struct malloc_pool_s
{
    mutex_t mutex;                                  // region mutex
    uint8_t *base;                                  // region base
    uint8_t *next;                                  // next free
    uint8_t *access;                                // next accessible
    uint8_t *end;                                   // region end
    struct malloc_header_s *free;                   // freelist
};

static struct malloc_pool_s malloc_pools[MALLOC_POOL_MAX];

static const size_t malloc_sizes[] =
{
    16, /* idx=0 */
    32, /* idx=1 */
    48, /* idx=2 */
    64, /* idx=3 */
    80, /* idx=4 */
    96, /* idx=5 */
    112, /* idx=6 */
    128, /* idx=7 */
    144, /* idx=8 */
    160, /* idx=9 */
    192, /* idx=10 */
    224, /* idx=11 */
    256, /* idx=12 */
    272, /* idx=13 */
    320, /* idx=14 */
    384, /* idx=15 */
    448, /* idx=16 */
    512, /* idx=17 */
    528, /* idx=18 */
    640, /* idx=19 */
    768, /* idx=20 */
    896, /* idx=21 */
    1024, /* idx=22 */
    1040, /* idx=23 */
    1280, /* idx=24 */
    1536, /* idx=25 */
    1792, /* idx=26 */
    2048, /* idx=27 */
    2064, /* idx=28 */
    2560, /* idx=29 */
    3072, /* idx=30 */
    3584, /* idx=31 */
    4096, /* idx=32 */
    4112, /* idx=33 */
    5120, /* idx=34 */
    6144, /* idx=35 */
    7168, /* idx=36 */
    8192, /* idx=37 */
    8208, /* idx=38 */
    10240, /* idx=39 */
    12288, /* idx=40 */
    16384, /* idx=41 */
    32768, /* idx=42 */
    65536, /* idx=43 */
    131072, /* idx=44 */
    262144, /* idx=45 */
    524288, /* idx=46 */
    1048576, /* idx=47 */
    2097152, /* idx=48 */
    4194304, /* idx=49 */
    8388608, /* idx=50 */
    16777216, /* idx=51 */
    33554432, /* idx=52 */
    67108864, /* idx=53 */
    134217728, /* idx=54 */
    268435456, /* idx=55 */
    536870912, /* idx=56 */
    1073741824, /* idx=57 */
    2147483648, /* idx=58 */
    4294967296, /* idx=59 */
    8589934592, /* idx=60 */
};

static size_t malloc_index(size_t size)
{
    size += sizeof(struct malloc_header_s);
    switch (__builtin_clzll(size))
    {
        case 64: case 63: case 62: case 61: case 60: case 59:
            if (size <= 16)
                return 0;
        case 58:
            if (size <= 32)
                return 1;
            if (size <= 48)
                return 2;
        case 57:
            if (size <= 64)
                return 3;
            if (size <= 80)
                return 4;
            if (size <= 96)
                return 5;
            if (size <= 112)
                return 6;
        case 56:
            if (size <= 128)
                return 7;
            if (size <= 144)
                return 8;
            if (size <= 160)
                return 9;
            if (size <= 192)
                return 10;
            if (size <= 224)
                return 11;
        case 55:
            if (size <= 256)
                return 12;
            if (size <= 272)
                return 13;
            if (size <= 320)
                return 14;
            if (size <= 384)
                return 15;
            if (size <= 448)
                return 16;
        case 54:
            if (size <= 512)
                return 17;
            if (size <= 528)
                return 18;
            if (size <= 640)
                return 19;
            if (size <= 768)
                return 20;
            if (size <= 896)
                return 21;
        case 53:
            if (size <= 1024)
                return 22;
            if (size <= 1040)
                return 23;
            if (size <= 1280)
                return 24;
            if (size <= 1536)
                return 25;
            if (size <= 1792)
                return 26;
        case 52:
            if (size <= 2048)
                return 27;
            if (size <= 2064)
                return 28;
            if (size <= 2560)
                return 29;
            if (size <= 3072)
                return 30;
            if (size <= 3584)
                return 31;
        case 51:
            if (size <= 4096)
                return 32;
            if (size <= 4112)
                return 33;
            if (size <= 5120)
                return 34;
            if (size <= 6144)
                return 35;
            if (size <= 7168)
                return 36;
        case 50:
            if (size <= 8192)
                return 37;
            if (size <= 8208)
                return 38;
            if (size <= 10240)
                return 39;
            if (size <= 12288)
                return 40;
        case 49:
            if (size <= 16384)
                return 41;
        case 48:
            if (size <= 32768)
                return 42;
        case 47:
            if (size <= 65536)
                return 43;
        case 46:
            if (size <= 131072)
                return 44;
        case 45:
            if (size <= 262144)
                return 45;
        case 44:
            if (size <= 524288)
                return 46;
        case 43:
            if (size <= 1048576)
                return 47;
        case 42:
            if (size <= 2097152)
                return 48;
        case 41:
            if (size <= 4194304)
                return 49;
        case 40:
            if (size <= 8388608)
                return 50;
        case 39:
            if (size <= 16777216)
                return 51;
        case 38:
            if (size <= 33554432)
                return 52;
        case 37:
            if (size <= 67108864)
                return 53;
        case 36:
            if (size <= 134217728)
                return 54;
        case 35:
            if (size <= 268435456)
                return 55;
        case 34:
            if (size <= 536870912)
                return 56;
        case 33:
            if (size <= 1073741824)
                return 57;
        case 32:
            if (size <= 2147483648)
                return 58;
        case 31:
            if (size <= 4294967296)
                return 59;
        case 30:
            if (size <= 8589934592)
                return 60;
        default:
            return SIZE_MAX;
    }
}

static bool malloc_recover(struct malloc_pool_s *pool)
{
    if (errno != EOWNERDEAD)
        return false;
    // Recovery from EOWNERDEAD may leak memory (or entire mappings).
    if (pool->base != NULL && pool->end == NULL)
    {
        // Complete partial initialization
        pool->next   = pool->base;
        pool->access = pool->base;
        pool->end    = pool->base + MALLOC_POOL_SIZE;
    }
    mutex_unlock(&pool->mutex);
    return false;
}

static __attribute__((__noinline__)) void *malloc_allocate(size_t size,
    size_t idx, bool lock)
{
    if (idx > MALLOC_POOL_MAX)
    {
        errno = EINVAL;
        return NULL;
    }
    struct malloc_pool_s *pool = malloc_pools + idx;
    size_t alloc_size = malloc_sizes[idx];

    struct malloc_header_s *node = pool->free;
    while (node != NULL)
    {
        struct malloc_header_s *next = node->next;
        struct malloc_header_s *curr =
            __sync_val_compare_and_swap(&pool->free, node, next);
        if (node == curr)
        {
            node->size = size;
            node->idx  = idx;
            node->next = NULL;
            return (void *)(node+1);
        }
        node = curr;
    }

    if (lock && mutex_lock(&pool->mutex) < 0 && !malloc_recover(pool))
        return NULL;

    if (pool->base == NULL)
    {
        void *addr = mmap(NULL, MALLOC_POOL_SIZE, PROT_NONE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
        if (addr == MAP_FAILED)
        {
            if (lock)
                mutex_unlock(&pool->mutex);
            return NULL;
        }
        pool->base   = (uint8_t *)addr;
        pool->next   = pool->base;
        pool->access = pool->base;
        pool->end    = pool->base + MALLOC_POOL_SIZE;
        pool->free   = NULL;
    }

    if (pool->next + alloc_size > pool->end)
    {
        if (lock)
            mutex_unlock(&pool->mutex);
        errno = ENOMEM;
        return NULL;
    }

    uint8_t *next = pool->next;
    node = (struct malloc_header_s *)next;
    next += alloc_size;
    if (next > pool->access)
    {
        size_t access_size =
          ((next - pool->access) / MALLOC_PAGE_SIZE) + MALLOC_PAGE_SIZE;
        if (mprotect(pool->access, access_size, PROT_READ | PROT_WRITE) < 0)
        {
            if (lock)
                mutex_unlock(&pool->mutex);
            return NULL;
        }
        pool->access += access_size;
    }
    pool->next = next;
    if (lock)
        mutex_unlock(&pool->mutex);

    node->size = size;
    node->idx  = idx;
    
    return (void *)(node+1);
}

static void *malloc(size_t size)
{
    size_t idx = malloc_index(size);
    return malloc_allocate(size, idx, /*lock=*/true);
}

static void *malloc_unlocked(size_t size)
{
    size_t idx = malloc_index(size);
    return malloc_allocate(size, idx, /*lock=*/false);
}

static void free(void *ptr)
{
    if (ptr == NULL)
        return;
 
    struct malloc_header_s *node = (struct malloc_header_s *)ptr;
    node--;
    if (node->next != NULL || node->idx == 0 || node->idx >= MALLOC_POOL_MAX)
        panic("bad-free() detected");

    struct malloc_pool_s *pool = malloc_pools + node->idx;
    if ((uint8_t *)node < pool->base || (uint8_t *)node >= pool->end)
        panic("bad free() detected");

    size_t alloc_size = malloc_sizes[node->idx]; 
    if (node->size > MALLOC_PAGE_SIZE)
    {
        uintptr_t start = (uintptr_t)ptr;
        uintptr_t end   = start + alloc_size;
        start += (start % MALLOC_PAGE_SIZE != 0? MALLOC_PAGE_SIZE: 0);
        start -= (start % MALLOC_PAGE_SIZE);
        end   -= (end % MALLOC_PAGE_SIZE);
        if (end > start)
            (void)madvise((void *)start, end - start, MADV_DONTNEED);
    }

    struct malloc_header_s *next = pool->free;
    while (true)
    {
        node->next = next;
        struct malloc_header_s *curr =
            __sync_val_compare_and_swap(&pool->free, next, node);
        if (curr == next)
            return;
        next = curr;
    }
}

static void free_unlocked(void *ptr) __attribute__((__alias__("free")));

static void *memcpy(void *dst, const void *src, size_t n);
static void *malloc_reallocate(void *ptr, size_t size, bool lock)
{
    if (ptr == NULL)
        return (lock? malloc(size): malloc_unlocked(size));

    struct malloc_header_s *node = (struct malloc_header_s *)ptr;
    node--;
    if (node->idx == malloc_index(size))
    {
        node->size = size;
        return ptr;
    }

    void *new_ptr = (lock? malloc(size): malloc_unlocked(size));
    if (new_ptr == NULL)
        return new_ptr;

    size_t copy_size = (size < node->size? size: node->size);
    memcpy(new_ptr, ptr, copy_size);
    if (lock)
        free(ptr);
    else
        free_unlocked(ptr);
    return new_ptr;
}

static void *realloc(void *ptr, size_t size)
{
    return malloc_reallocate(ptr, size, /*lock=*/true);
}

static void *realloc_unlocked(void *ptr, size_t size)
{
    return malloc_reallocate(ptr, size, /*lock=*/false);
}

/****************************************************************************/
/* SIGNAL                                                                   */
/****************************************************************************/

struct ksigaction
{
    void *sa_handler_2;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    sigset_t sa_mask;
};
#define SA_RESTORER 0x04000000

static void signal_restorer(void)
{
    (void)syscall(SYS_rt_sigreturn);
}

static int sigaction(int signum, const struct sigaction *act,
    struct sigaction *oldact)
{
    struct ksigaction kact, koldact;
    if (act != NULL)
    {
        kact.sa_handler_2 = act->sa_handler;
        memcpy(&kact.sa_mask, &act->sa_mask, sizeof(kact.sa_mask));
        kact.sa_flags = act->sa_flags | SA_RESTORER;
        kact.sa_restorer = signal_restorer;
    }
    int result = (int)syscall(SYS_rt_sigaction, signum, &kact, &koldact,
        _NSIG / 8);
    if (result < 0)
        return result;
    if (oldact != NULL)
    {
        oldact->sa_handler = koldact.sa_handler_2;
        memcpy(&oldact->sa_mask, &koldact.sa_mask, sizeof(oldact->sa_mask));
        oldact->sa_flags = (koldact.sa_flags & ~SA_RESTORER);
        oldact->sa_restorer = NULL;
    }
    return result;
}

/****************************************************************************/
/* CTYPE                                                                    */
/****************************************************************************/

static int isalnum(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9');
}

static int isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int isdigit(int c)
{
    return (c >= '0' && c <= '9');
}

static int islower(int c)
{
    return (c >= 'a' && c <= 'z');
}

static int isprint(int c)
{
    return (c >= ' ' && c <= UINT8_MAX);
}

static int isspace(int c)
{
    switch (c)
    {
        case ' ': case '\n': case '\r': case '\t': case '\v': case '\f':
            return true;
        default:
            return false;
    }
}

static int isxdigit(int c)
{
    return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
        (c >= '0' && c <= '9');
}

static int toupper(int c)
{
    if (c >= 'a' && c <= 'z')
        c = 'A' + (c - 'a');
    return c;
}

static int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        c = 'a' + (c - 'A');
    return c;
}

/****************************************************************************/
/* STRING                                                                   */
/****************************************************************************/

static void *memset(void *s, int c, size_t n)
{
    int8_t *s1 = (int8_t *)s;
    for (size_t i = 0; i < n; i++)
        s1[i] = (int8_t)c;
    return s;
}

static void *memcpy(void *dst, const void *src, size_t n)
{
    int8_t *dst1 = (int8_t *)dst1;
    const int8_t *src1 = (const int8_t *)src;
    for (size_t i = 0; i < n; i++)
        dst1[i] = src1[i];
    return dst;
}

static size_t strlen(const char *s)
{
    size_t len = 0;
    while (*s++ != '\0')
        len++;
    return len;
}

static int memcmp(const void *s1, const void *s2, size_t n)
{
    const int8_t *a1 = (int8_t *)s1, *a2 = (int8_t *)s2;
    for (size_t i = 0; i < n; i++)
    {
        int cmp = (int)a2[i] - (int)a1[i];
        if (cmp != 0)
            return cmp;
    }
    return 0;
}

static int strncmp(const char *s1, const char *s2, size_t n)
{
    for (; n > 0; n--)
    {
        int cmp = (int)*s2 - (int)*s1;
        if (cmp != 0)
            return cmp;
        if (*s1 == '\0')
            return 0;
        s1++; s2++;
    }
    return 0;
}

static size_t strnlen(const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n && s[i] != '\0'; i++)
        ;
    return i;
}

static int strcmp(const char *s1, const char *s2)
{
    return strncmp(s1, s2, SIZE_MAX);
}

static char *strncat(char *dst, const char *src, size_t n)
{
    size_t dlen = strlen(dst), i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dst[dlen + i] = src[i];
    dst[dlen + i] = '\0';
    return dst;
}

static char *strcat(char *dst, const char *src)
{
    return strncat(dst, src, SIZE_MAX);
}

static char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++)
        dst[i] = src[i];
    for (; i < n; i++)
        dst[i] = '\0';
    return dst;
}

static char *strcpy(char *dst, const char *src)
{
    while (*src != '\0')
        *dst++ = *src++;
    *dst = '\0';
    return dst;
}

static const char *strerror(int errnum)
{
    switch (errno)
    {
        case E2BIG:
            return "Argument list too long";
        case EACCES:
            return "Permission denied";
        case EAGAIN:
            return "Resource temporarily unavailable";
        case EBADF:
            return "Bad file descriptor";
        case EBADMSG:
            return "Bad message";
        case EBUSY:
            return "Device or resource busy";
        case ECANCELED:
            return "Operation canceled";
        case ECHILD:
            return "No child processes";
        case EDEADLK:
            return "Resource deadlock avoided";
        case EDOM:
            return "Mathematics argument out of domain of function";
        case EEXIST:
            return "File exists";
        case EFAULT:
            return "Bad address";
        case EFBIG:
            return "File too large";
        case EINPROGRESS:
            return "Operation in progress";
        case EINTR:
            return "Interrupted function call";
        case EINVAL:
            return "Invalid argument";
        case EIO:
            return "Input/output error";
        case EISDIR:
            return "Is a directory";
        case EMFILE:
            return "Too many open files";
        case EMLINK:
            return "Too many links";
        case EMSGSIZE:
            return "Message too long";
        case ENAMETOOLONG:
            return "Filename too long";
        case ENFILE:
            return "Too many open files in system";
        case ENODEV:
            return "No such device";
        case ENOENT:
            return "No such file or directory";
        case ENOEXEC:
            return "Exec format error";
        case ENOLCK:
            return "No locks available";
        case ENOMEM:
            return "Not enough space";
        case ENOSPC:
            return "No space left on device";
        case ENOSYS:
            return "Function not implemented";
        case ENOTDIR:
            return "Not a directory";
        case ENOTEMPTY:
            return "Directory not empty";
        case ENOTSUP:
            return "Operation not supported";
        case ENOTTY:
            return "Inappropriate I/O control operation";
        case ENXIO:
            return "No such device or address";
        case EPERM:
            return "Operation not permitted";
        case EPIPE:
            return "Broken pipe";
        case ERANGE:
            return "Result too large";
        case EROFS:
            return "Read-only filesystem";
        case ESPIPE:
            return "Invalid seek";
        case ESRCH:
            return "No such process";
        case ETIMEDOUT:
            return "Connection timed out";
        case EXDEV:
            return "Improper link";
        case EOWNERDEAD:
            return "Owner died";
        default:
            return "Unknown error code";
    }
}

/****************************************************************************/
/* ATOI                                                                     */
/****************************************************************************/

static int atoi_digit(char c, int base)
{
    int d = -1;
    if (c >= '0' && c <= '9')
        d = c - '0';
    else if (c >= 'a' && c <= 'z')
        d = 10 + (c - 'a');
    else if (c >= 'A' && c <= 'Z')
        d = 10 + (c - 'Z');
    if (d < 0)
        return d;
    if (d >= base)
        return -1;
    return d;
}

static __int128 atoi_convert(const char * __restrict__ nptr,
    char ** __restrict__ endptr, int base, __int128 min, __int128 max)
{
    char *dummy_endptr;
    if (endptr == NULL)
        endptr = &dummy_endptr;
    if (base != 0 && (base < 2 || base > 36))
    {
        *endptr = (char *)nptr;
        errno = EINVAL;
        return 0;
    }
    while (isspace(*nptr))
        nptr++;
    bool neg = false;
    switch (*nptr)
    {
        case '-':
            neg = true;
            // Fallthrough:
        case '+':
            nptr++;
            break;
        default:
            break;
    }
    switch (*nptr)
    {
        case '0':
            if (base == 0)
            {
                nptr++;
                if (*nptr == 'x' || *nptr == 'X')
                {
                    base = 16;
                    nptr++;
                }
                else
                    base = 8;
            }
            break;
        case '\0':
            *endptr = (char *)nptr;
            errno = EINVAL;
            return 0;
    }
        
    __int128 x = 0;
    unsigned i;
    int d;
    for (i = 0; (d = atoi_digit(*nptr, base)) >= 0; i++)
    {
        x *= base;
        if (!neg)
        {
            x += (__int128)d;
            if (x > max)
            {
                *endptr = (char *)nptr;
                errno = ERANGE;
                return max;
            }
        }
        else
        {
            x -= (__int128)d;
            if (x < min)
            {
                *endptr = (char *)nptr;
                errno = ERANGE;
                return min;
            }
        }
        nptr++;
    }
    if (i == 0)
    {
        errno = EINVAL;
        return 0;
    }
    *endptr = (char *)nptr;
    return x;
}

static unsigned long long int strtoull(const char * __restrict__ nptr,
    char ** __restrict__ endptr, int base)
{
    return (unsigned long long int)atoi_convert(nptr, endptr, base, 0,
        ULLONG_MAX);
}

static unsigned long int strtoul(const char * __restrict__ nptr,
    char ** __restrict__ endptr, int base)
{
    return (unsigned long int)atoi_convert(nptr, endptr, base, 0, ULONG_MAX);
}

static long long int strtoll(const char * __restrict__ nptr,
    char ** __restrict__ endptr, int base)
{
    return (long long int)atoi_convert(nptr, endptr, base, LLONG_MIN,
        LLONG_MAX);
}

static long int strtol(const char * __restrict__ nptr,
    char ** __restrict__ endptr, int base)
{
    return (long int)atoi_convert(nptr, endptr, base, LONG_MIN, LONG_MAX);
}

static int atoi(const char *nptr)
{
    int saved_errno = errno;
    int x = (int)atoi_convert(nptr, NULL, 10, INT_MIN, INT_MAX);
    errno = saved_errno;
    return x;
}

static long int atol(const char *nptr)
{
    int saved_errno = errno;
    long int x = (long int)atoi_convert(nptr, NULL, 10, LONG_MIN, LONG_MAX);
    errno = saved_errno;
    return x;
}

static long long int atoll(const char *nptr)
{
    int saved_errno = errno;
    long long int x = (long long int)atoi_convert(nptr, NULL, 10, LLONG_MIN,
        LLONG_MAX);
    errno = saved_errno;
    return x;
}

/****************************************************************************/
/* STDIO                                                                    */
/****************************************************************************/

#define STDIO_FLAG_INITED        0x0001
#define STDIO_FLAG_READ          0x0002
#define STDIO_FLAG_WRITE         0x0004
#define STDIO_FLAG_READING       0x0008
#define STDIO_FLAG_WRITING       0x0010
#define STDIO_FLAG_NO_BUF        0x0020
#define STDIO_FLAG_OWN_BUF       0x0040
#define STDIO_FLAG_EOF           0x0080
#define STDIO_FLAG_ERROR         0x0100

struct stdio_stream_s
{
    mutex_t mutex;
    unsigned flags;
    int fd;
    int eol;
    char *write_ptr;
    char *write_end;
    char *read_ptr;
    char *read_end;
    char *buf;
    size_t bufsiz;
};
typedef struct stdio_stream_s FILE;

#define stdio_lock(stream, errval)                                      \
    do                                                                  \
    {                                                                   \
        if (mutex_lock(&(stream)->mutex) < 0 &&                         \
                !stdio_stream_recover(stream))                          \
            return errval;                                              \
    }                                                                   \
    while (false)
#define stdio_unlock(m)                                                 \
    mutex_unlock(&(stream)->mutex)

static __attribute__((__noinline__)) bool stdio_stream_recover(FILE *stream)
{
    if (errno == EOWNERDEAD)
    {
        stream->flags |= STDIO_FLAG_ERROR;
        return true;    // lock held
    }
    return false;
}

static FILE *stdio_stream_alloc(int fd, bool r, bool w, int mode)
{
    // Use mmap() rather than malloc() to avoid dependencies.
    size_t size = sizeof(struct stdio_stream_s);
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED)
        return NULL;
    FILE *stream = (FILE *)ptr;
    stream->flags  = (r? STDIO_FLAG_READ: 0) |
                     (w? STDIO_FLAG_WRITE: 0) |
                     (mode == _IONBF? STDIO_FLAG_NO_BUF: 0);
    stream->eol    = (mode == _IOLBF? '\n': EOF);
    stream->bufsiz = BUFSIZ;
    stream->fd     = fd;
    return stream;
}

static int stdio_stream_buf_init(FILE *stream)
{
    if (stream->flags & STDIO_FLAG_NO_BUF)
    {
        stream->buf    = NULL;
        stream->bufsiz = 0;
    }
    else if (stream->buf == NULL)
    {
        void *ptr = mmap(NULL, stream->bufsiz, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (ptr == MAP_FAILED)
            return EOF;
        stream->buf = (char *)ptr;
        stream->flags |= STDIO_FLAG_OWN_BUF;
    }
    stream->flags |= STDIO_FLAG_INITED;
    return 0;
}

static ssize_t stdio_stream_read_buf(FILE *stream, char *start, char *end)
{
    ssize_t size = read(stream->fd, start, end - start);
    if (size == 0)
    {
        stream->flags |= STDIO_FLAG_EOF;
        return EOF;
    }
    if (size < 0)
    {
        stream->flags |= STDIO_FLAG_ERROR;
        return EOF;
    }
    return size;
}

static int stdio_stream_read(FILE *stream)
{
    if (stream->buf == 0)
        return 0;
    stream->read_ptr = stream->buf;
    stream->read_end = stream->buf;
    ssize_t size = stdio_stream_read_buf(stream, stream->buf,
            stream->buf + stream->bufsiz);
    if (size < 0)
        return EOF;
    stream->read_end += size;
    return 0;
}

static int stdio_write_buf(int fd, const char *start, const char *end)
{
    while (start < end)
    {
        ssize_t size = write(fd, start, end - start);
        if (size < 0)
            return EOF;
        start += size;
    }
    return 0;
}

static int stdio_stream_write_buf(FILE *stream, const char *start,
    const char *end)
{
    if (stdio_write_buf(stream->fd, start, end) < 0)
    {
        stream->flags |= STDIO_FLAG_ERROR;
        return EOF;
    }
    return 0;
}

static int stdio_stream_write(FILE *stream)
{
    if (stream->buf == NULL)
        return 0;
    if (stream->write_ptr == NULL)
    {
        stream->write_ptr = stream->buf;
        stream->write_end = stream->buf + stream->bufsiz;
        return 0;
    }
    if (stdio_stream_write_buf(stream, stream->buf, stream->write_ptr) < 0)
    {
        stream->flags |= STDIO_FLAG_ERROR;
        return EOF;
    }
    stream->write_ptr = stream->buf;
    return 0;
}

static int fflush_unlocked(FILE *stream)
{
    if (stream->flags & STDIO_FLAG_ERROR)
    {
        errno = EINVAL;
        return EOF;
    }
    if (stream->flags & STDIO_FLAG_WRITING)
        return stdio_stream_write(stream);
    if (stream->flags & STDIO_FLAG_READING)
    {
        off_t offset = stream->read_ptr - stream->read_end;
        stream->read_ptr = stream->buf;
        stream->read_end = stream->buf;
        if (offset < 0 && lseek(stream->fd, offset, SEEK_CUR) < 0)
        {
            stream->flags |= STDIO_FLAG_ERROR;
            return EOF;
        }
    }
    return 0;
}

static int fflush(FILE *stream)
{
    if (stream == NULL)
        panic("fflush(NULL) not supported");
    stdio_lock(stream, EOF);
    int result = fflush_unlocked(stream);
    stdio_unlock(stream);
    return result;
}

static int stdio_stream_read_init(FILE *stream)
{
    if (!(stream->flags & STDIO_FLAG_READ) ||
         (stream->flags & STDIO_FLAG_ERROR) ||
         (stream->flags & STDIO_FLAG_EOF))
    {
        errno = EINVAL;
        return EOF;
    }
    if (stream->flags & STDIO_FLAG_WRITING)
    {
        stream->flags &= ~STDIO_FLAG_WRITING;
        fflush_unlocked(stream);
    }
    stream->flags |= STDIO_FLAG_READING;
    if (!(stream->flags & STDIO_FLAG_INITED) &&
            stdio_stream_buf_init(stream) < 0)
        return EOF;
    if (stream->read_ptr >= stream->read_end &&
            stdio_stream_read(stream) < 0)
        return EOF;
    return 0;
}

static int stdio_stream_write_init(FILE *stream)
{
    if (!(stream->flags & STDIO_FLAG_WRITE) ||
         (stream->flags & STDIO_FLAG_ERROR))
    {
        errno = EINVAL;
        return EOF;
    }
    if (stream->flags & STDIO_FLAG_READING)
    {
        stream->flags &= ~STDIO_FLAG_READING;
        fflush_unlocked(stream);
    }
    stream->flags |= STDIO_FLAG_WRITING;
    if (!(stream->flags & STDIO_FLAG_INITED) &&
            stdio_stream_buf_init(stream) < 0)
        return EOF;
    if (stream->write_ptr >= stream->write_end &&
            stdio_stream_write(stream) < 0)
        return EOF;
    return 0;
}

static int stdio_stream_free(FILE *stream)
{
    int result1 = 0, result2 = 0;
    if (stream->buf != NULL && (stream->flags & STDIO_FLAG_OWN_BUF))
        result1 = munmap(stream->buf, stream->bufsiz);
    result2 = munmap(stream, sizeof(*stream));
    return (result1 == 0? result2: result1);
}

static int stdio_parse_mode(const char *mode)
{
    int flags = 0;
    char plus = mode[1];
    if ((plus == '+' && mode[2] != '\0') || (plus != '+' && plus != '\0'))
        return -1;
    switch (*mode)
    {
        case 'r':
            flags = (plus != '+'? O_RDONLY: O_RDWR);
            break;
        case 'w':
            flags = (plus != '+'? O_WRONLY | O_CREAT: O_RDWR | O_CREAT);
            break;
        case 'a':
            flags = (plus != '+'? O_WRONLY | O_CREAT | O_APPEND:
                                  O_RDWR | O_CREAT | O_APPEND);
            break;
        default:
            return -1;
    }
    return flags;
}

static FILE *fdopen(int fd, const char *mode)
{
    int flags = stdio_parse_mode(mode);
    if (flags < 0)
    {
        errno = EINVAL;
        return NULL;
    }
    bool r = ((flags & O_ACCMODE) != O_WRONLY? true: false);
    bool w = ((flags & O_ACCMODE) != O_RDONLY? true: false);
    FILE *stream = stdio_stream_alloc(fd, r, w, _IOFBF);
    if (stream == NULL)
    {
        close(fd);
        return NULL;
    }
    return stream;
}

static FILE *fopen(const char *path, const char *mode)
{
    int flags = stdio_parse_mode(mode);
    if (flags < 0)
    {
        errno = EINVAL;
        return NULL;
    }
    int fd = open(path, flags,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd < 0)
        return NULL;
    bool r = ((flags & O_ACCMODE) != O_WRONLY? true: false);
    bool w = ((flags & O_ACCMODE) != O_RDONLY? true: false);
    FILE *stream = stdio_stream_alloc(fd, r, w, _IOFBF);
    if (stream == NULL)
    {
        close(fd);
        return NULL;
    }
    return stream;
}

static int fclose(FILE *stream)
{
    int result1 = fflush(stream);
    int result2 = close(stream->fd);
    int result3 = stdio_stream_free(stream);
    return (result1 == 0? (result2 == 0? result3: result2): result1);
}

static FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    int flags = stdio_parse_mode(mode);
    if (flags < 0)
    {
        fclose(stream);
        errno = EINVAL;
        return NULL;
    }
    int fd = open(path, flags,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
    if (fd < 0)
    {
        fclose(stream);
        return NULL;
    }
    int old_fd = -1;
    bool r = ((flags & O_ACCMODE) != O_WRONLY? true: false);
    bool w = ((flags & O_ACCMODE) != O_RDONLY? true: false);
    flags = (r? STDIO_FLAG_READ: 0) | (w? STDIO_FLAG_WRITE: 0);
    if (mutex_lock(&stream->mutex) < 0)
    {
        close(fd);
        return NULL;
    }
    (void)fflush_unlocked(stream);    // Ignore errors
    old_fd         = stream->fd;
    stream->fd     = fd;
    stream->flags &= ~(STDIO_FLAG_READ | STDIO_FLAG_WRITE |
                       STDIO_FLAG_READING | STDIO_FLAG_WRITING |
                       STDIO_FLAG_EOF | STDIO_FLAG_ERROR);
    stream->flags |= flags;
    stream->read_ptr = stream->read_end = NULL;
    stream->write_ptr = stream->write_end = NULL;
    mutex_unlock(&stream->mutex);
    (void)close(old_fd);                    // Ignore errors
    return stream;
}

static void clearerr_unlocked(FILE *stream)
{
    stream->flags &= ~(STDIO_FLAG_EOF | STDIO_FLAG_ERROR |
        STDIO_FLAG_READING | STDIO_FLAG_WRITING);
    stream->read_ptr = stream->read_end = NULL;
    stream->write_ptr = stream->write_end = NULL;
}

static void clearerr(FILE *stream)
{
    stdio_lock(stream, /*void*/);
    clearerr_unlocked(stream);
    stdio_unlock(stream);
}

static int ferror_unlocked(FILE *stream)
{
    return (stream->flags & STDIO_FLAG_ERROR? 1: 0);
}

static int ferror(FILE *stream)
{
    stdio_lock(stream, -1);
    int result = ferror_unlocked(stream);
    stdio_unlock(stream);
    return result;
}

static int feof_unlocked(FILE *stream)
{
    return (stream->flags & STDIO_FLAG_EOF? 1: 0);
}

static int feof(FILE *stream)
{
    stdio_lock(stream, -1);
    int result = feof_unlocked(stream);
    stdio_unlock(stream);
    return result;
}

static int fileno_unlocked(FILE *stream)
{
    return stream->fd;
}

static int fileno(FILE *stream)
{
    stdio_lock(stream, -1);
    int result = fileno_unlocked(stream);
    stdio_unlock(stream);
    return result;
}

static int setvbuf(FILE *stream, char *buf, int mode, size_t size)
{
    stdio_lock(stream, -1);
    if (stream->flags & STDIO_FLAG_INITED)
    {
        stdio_unlock(stream);
        errno = EINVAL;
        return EOF;
    }
    if (buf != NULL && size > 0)
    {
        stream->buf    = buf;
        stream->bufsiz = size;
    }
    int result = 0;
    switch (mode)
    {
        case _IOFBF:
            stream->flags &= ~STDIO_FLAG_NO_BUF;
            stream->eol = EOF;
            break;
        case _IOLBF:
            stream->flags &= ~STDIO_FLAG_NO_BUF;
            stream->eol = '\n';
            break;
        case _IONBF:
            stream->flags |= STDIO_FLAG_NO_BUF;
            stream->eol = EOF;
            break;
        default:
            errno = EINVAL;
            result = -1;
            break;
    }
    stdio_unlock(stream);
    return result;
}

static mutex_t stdio_mutex;
static FILE *stdio_stream[3] = {NULL};

#undef  stdin
#define stdin   stdio_get_stream(STDIN_FILENO)

#undef  stdout
#define stdout  stdio_get_stream(STDOUT_FILENO)

#undef  stderr
#define stderr  stdio_get_stream(STDERR_FILENO)

static __attribute__((__noinline__, __const__)) FILE *stdio_get_stream(int fd)
{
    if (stdio_stream[fd] != NULL)
        return stdio_stream[fd];

    bool r = (fd == STDIN_FILENO);
    bool w = (fd == STDOUT_FILENO || fd == STDERR_FILENO);
    int mode = (fd == STDERR_FILENO? _IONBF: _IOLBF);
    if (mutex_lock(&stdio_mutex) < 0)
        panic("failed to lock stdio stream");
    if (stdio_stream[fd] == NULL)
    {
        FILE *stream = stdio_stream_alloc(fd, r, w, mode);
        if (stream == NULL)
            panic("failed to allocate stdio stream");
        stdio_stream[fd] = stream;
    }
    mutex_unlock(&stdio_mutex);
    
    return stdio_stream[fd];
}

static int fputc_unlocked(int c, FILE *stream)
{
    if (stdio_stream_write_init(stream) < 0)
        return EOF;
    char d = (char)c;
    if (stream->write_ptr == NULL)
    {
        if (stdio_stream_write_buf(stream, &d, &d + sizeof(d)) < 0)
            return EOF;
        return (int)d;
    }
    *stream->write_ptr++ = d;
    if ((int)(unsigned char)d == stream->eol && stdio_stream_write(stream) < 0)
        return EOF;
    return (int)d;
}

static int fputc(int c, FILE *stream)
{
    stdio_lock(stream, EOF);
    int result = fputc_unlocked(c, stream);
    stdio_unlock(stream);
    return result;
}

static int fputs_unlocked(const char *s, FILE *stream)
{
    if (stdio_stream_write_init(stream) < 0)
        return EOF;
    if (stream->write_ptr == NULL)
    {
        size_t len = strlen(s);
        if (stdio_stream_write_buf(stream, s, s + len) < 0)
            return EOF;
        return 0;
    }
    bool flush = false;
    for (; *s != 0; s++)
    {
        *stream->write_ptr++ = *s;
        if (stream->write_ptr >= stream->write_end)
        {
            if (stdio_stream_write(stream) < 0)
                return EOF;
            flush = false;
        }
        else if ((int)(unsigned char)*s == stream->eol)
            flush = true;
    }
    if (flush && stdio_stream_write(stream) < 0)
        return EOF;
    return 0;
}

static int fputs(const char *s, FILE *stream)
{
    stdio_lock(stream, EOF);
    int result = fputs_unlocked(s, stream);
    stdio_unlock(stream);
    return result;
}

static int putc(int c, FILE *stream)
{
    return fputc(c, stream);
}

static int putc_unlocked(int c, FILE *stream)
{
    return fputc_unlocked(c, stream);
}

static int putchar(int c)
{
    return fputc(c, stdout);
}

static int putchar_unlocked(int c)
{
    return fputc_unlocked(c, stdout);
}

static int puts(const char *s)
{
    if (fputs(s, stdout) < 0)
        return EOF;
    return fputc('\n', stdout);
}

static int puts_unlocked(const char *s)
{
    if (fputs_unlocked(s, stdout) < 0)
        return EOF;
    return fputc_unlocked('\n', stdout);
}

static size_t fwrite_unlocked(const void *ptr, size_t size, size_t nmemb,
    FILE *stream)
{
    if (stdio_stream_write_init(stream) < 0)
        return 0;
    size *= nmemb;
    if (size == 0)
        return 0;
    const char *ptr8 = (const char *)ptr;
    if (stream->write_ptr == NULL)
    {
        if (stdio_stream_write_buf(stream, ptr8, ptr8 + size) < 0)
            return 0;
        return nmemb;
    }
    bool flush = false;
    for (size_t i = 0; i < size; i++)
    {
        *stream->write_ptr++ = ptr8[i];
        if (stream->write_ptr >= stream->write_end)
        {
            if (stdio_stream_write(stream) < 0)
                return 0;
            flush = false;
        }
        else if ((int)(unsigned char)ptr8[i] == stream->eol)
            flush = true;
    }
    if (flush && stdio_stream_write(stream) < 0)
        return 0;
    return nmemb;
}

static size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    stdio_lock(stream, 0);
    size_t result = fwrite_unlocked(ptr, size, nmemb, stream);
    stdio_unlock(stream);
    return result;
}

static int fgetc_unlocked(FILE *stream)
{
    if (stdio_stream_read_init(stream) < 0)
        return EOF;
    if (stream->read_ptr == NULL)
    {
        char buf[1];
        if (stdio_stream_read_buf(stream, buf, buf+1) < 0)
            return EOF;
        return (int)buf[0];
    }
    char c = *stream->read_ptr++;
    return (int)c;
}

static int fgetc(FILE *stream)
{
    stdio_lock(stream, EOF);
    int result = fgetc_unlocked(stream);
    stdio_unlock(stream);
    return result;
}

static int fgets_unlocked(char *s, int size, FILE *stream)
{
    if (stdio_stream_read_init(stream) < 0)
        return EOF;
    int i;
    for (i = 0; i < size-1; i++)
    {
        int c;
        if (stream->read_ptr < stream->read_end)
            c = (int)*stream->read_ptr++;
        else
        {
            c = fgetc_unlocked(stream);
            if (c == EOF)
            {
                if (ferror(stream))
                    return EOF;
                break;
            }
        }
        s[i] = c;
        if (c == '\n')
        {
            i++;
            break;
        }
    }
    s[i] = '\0';
    return 0;
}

static int fgets(char *s, int size, FILE *stream)
{
    stdio_lock(stream, EOF);
    int result = fgets_unlocked(s, size, stream);
    stdio_unlock(stream);
    return result;
}

static int getc(FILE *stream)
{
    return fgetc(stream);
}

static int getc_unlocked(FILE *stream)
{
    return fgetc_unlocked(stream);
}

static int getchar(void)
{
    return fgetc(stdin);
}

static int getchar_unlocked(void)
{
    return fgetc_unlocked(stdin);
}

static int ungetc(int c, FILE *stream)
{
    stdio_lock(stream, EOF);
    if (!(stream->flags & STDIO_FLAG_READING))
    {
        stdio_unlock(stream);
        errno = EINVAL;
        return EOF;
    }
    if (stream->read_ptr == NULL)
        panic("ungetc and _IONBF is not supported");
    if (stream->read_ptr <= stream->buf)
    {
        stdio_unlock(stream);
        errno = EINVAL;
        return EOF;
    }
    stream->read_ptr--;
    *stream->read_ptr = (char)c;
    stdio_unlock(stream);
    return c;
}

// The define/undef trick does not work for fread_unlocked()...
#undef fread_unlocked
#define fread_unlocked(ptr, size, nmemb, stream)                        \
    stdio_fread_unlocked((ptr), (size), (nmemb), (stream))

static size_t stdio_fread_unlocked(void *ptr, size_t size, size_t nmemb,
        FILE *stream)
{
    if (stdio_stream_read_init(stream) < 0)
        return 0;
    size_t total = size * nmemb;
    if (total == 0)
        return 0;
    char *ptr8 = (char *)ptr;
    if (stream->read_ptr == NULL)
    {
        ssize_t result = stdio_stream_read_buf(stream, ptr8, ptr8 + total);
        if (result < 0)
            return 0;
        return ((size_t)result == total? nmemb: (size_t)result / size);
    }
    size_t i;
    for (i = 0; i < total; i++)
    {
        int c;
        if (stream->read_ptr < stream->read_end)
            c = (int)*stream->read_ptr++;
        else
        {
            c = fgetc_unlocked(stream);
            if (c == EOF)
                break;
        }
        ptr8[i] = c;
    }
    return (i == total? nmemb: i / size);
}

static size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    stdio_lock(stream, 0);
    size_t result = fread_unlocked(ptr, size, nmemb, stream);
    stdio_unlock(stream);
    return result;
}

static int fseek(FILE *stream, long offset, int whence)
{
    switch (whence)
    {
        case SEEK_SET: case SEEK_CUR: case SEEK_END:
            break;
        default:
            errno = EINVAL;
            return -1;
    }
    stdio_lock(stream, -1);
    if (fflush_unlocked(stream) < 0)
    {
        stdio_unlock(stream);
        return -1;
    }
    if (lseek(stream->fd, offset, whence) < 0)
    {
        stdio_unlock(stream);
        return -1;
    }
    stream->flags &= ~STDIO_FLAG_EOF;
    stdio_unlock(stream);
    return 0;
}

static long ftell(FILE *stream)
{
    long result = -1, offset = 0;
    stdio_lock(stream, -1);
    if (stream->flags & STDIO_FLAG_READING)
        offset = -(stream->read_end - stream->read_ptr);
    else if (stream->flags & STDIO_FLAG_WRITING)
        offset = stream->write_end - stream->write_ptr;
    result = lseek(stream->fd, 0, SEEK_CUR);
    if (result >= 0)
        result += offset;
    stdio_unlock(stream);
    return result;
}

/****************************************************************************/
/* PRINTF                                                                   */
/****************************************************************************/

#define PRINTF_FLAG_NEG        0x0001
#define PRINTF_FLAG_UPPER      0x0002
#define PRINTF_FLAG_HEX        0x0004
#define PRINTF_FLAG_PLUS       0x0008
#define PRINTF_FLAG_HASH       0x0010
#define PRINTF_FLAG_SPACE      0x0020
#define PRINTF_FLAG_RIGHT      0x0040
#define PRINTF_FLAG_ZERO       0x0080
#define PRINTF_FLAG_PRECISION  0x0100
#define PRINTF_FLAG_8          0x0200
#define PRINTF_FLAG_16         0x0400
#define PRINTF_FLAG_64         0x0800

static __attribute__((__noinline__)) size_t printf_put_char(char *str,
    size_t size, size_t idx, char c)
{
    if (str == NULL || idx >= size)
        return idx+1;
    str[idx++] = c;
    return idx;
}

static __attribute__((__noinline__)) size_t printf_put_num(char *str,
    size_t size, size_t idx, unsigned flags, size_t width, size_t precision,
    unsigned long long x)
{
    char prefix[2] = {'\0', '\0'};
    char buf[32];
    size_t i = 0;
    if (flags & PRINTF_FLAG_HEX)
    {
        if (flags & PRINTF_FLAG_HASH)
        {
            prefix[0] = '0';
            prefix[1] = (flags & PRINTF_FLAG_UPPER? 'X': 'x');
        }
        const char digs[] = "0123456789abcdef";
        const char DIGS[] = "0123456789ABCDEF";
        const char *ds = (flags & PRINTF_FLAG_UPPER? DIGS: digs);
        int shift = (15 * 4);
        bool seen = false;
        while (shift >= 0)
        {
            char c = ds[(x >> shift) & 0xF];
            shift -= 4;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    else
    {
        if (flags & PRINTF_FLAG_NEG)
            prefix[0] = '-';
        else if (flags & PRINTF_FLAG_PLUS)
            prefix[0] = '+';
        else if (flags & PRINTF_FLAG_SPACE)
            prefix[0] = ' ';
        unsigned long long r = 10000000000000000000ull;
        bool seen = false;
        while (r != 0)
        {
            char c = '0' + x / r;
            x %= r;
            r /= 10;
            if (!seen && c == '0')
                continue;
            seen = true;
            buf[i++] = c;
        }
        if (!seen)
            buf[i++] = '0';
    }
    if ((flags & PRINTF_FLAG_ZERO) && !(flags & PRINTF_FLAG_PRECISION))
    {
        precision = width;
        width = 0;
    }
    size_t len_0 = i;
    size_t len_1 = (len_0 < precision? precision: len_0);
    size_t len   =
        len_1 + (prefix[0] != '\0'? 1 + (prefix[1] != '\0'? 1: 0): 0);
    if (!(flags & PRINTF_FLAG_RIGHT))
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    if (prefix[0] != '\0')
    {
        idx = printf_put_char(str, size, idx, prefix[0]);
        if (prefix[1] != '\0')
            idx = printf_put_char(str, size, idx, prefix[1]);
    }
    for (size_t i = 0; precision > len_0 && i < precision - len_0; i++)
        idx = printf_put_char(str, size, idx, '0');
    for (size_t i = 0; i < len_0; i++)
        idx = printf_put_char(str, size, idx, buf[i]);
    if (flags & PRINTF_FLAG_RIGHT)
    {
        for (size_t i = 0; width > len && i < width - len; i++)
            idx = printf_put_char(str, size, idx, ' ');
    }
    return idx;
}

static int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    size_t idx = 0;
    for (; *format != '\0'; format++)
    {
        if (*format != '%')
        {
            idx = printf_put_char(str, size, idx, *format);
            continue;
        }
        format++;
        unsigned flags = 0x0;
        for (; true; format++)
        {
            switch (*format)
            {
                case ' ':
                    flags |= PRINTF_FLAG_SPACE;
                    continue;
                case '+':
                    flags |= PRINTF_FLAG_PLUS;
                    continue;
                case '-':
                    if (!(flags & PRINTF_FLAG_ZERO))
                        flags |= PRINTF_FLAG_RIGHT;
                    continue;
                case '#':
                    flags |= PRINTF_FLAG_HASH;
                    continue;
                case '0':
                    flags &= ~PRINTF_FLAG_RIGHT;
                    flags |= PRINTF_FLAG_ZERO;
                    continue;
                default:
                    break;
            }
            break;
        }

        size_t width = 0;
        if (*format == '*')
        {
            format++;
            int tmp = va_arg(ap, int);
            if (tmp < 0)
            {
                flags |= (!(flags & PRINTF_FLAG_ZERO)? PRINTF_FLAG_RIGHT: 0);
                width = (size_t)-tmp;
            }
            else
                width = (size_t)tmp;
        }
        else
        {
            for (; isdigit(*format); format++)
            {
                width *= 10;
                width += (unsigned)(*format - '0');
                width = (width > INT32_MAX? INT32_MAX: width);
            }
        }
        width = (width > INT16_MAX? INT16_MAX: width);

        size_t precision = 0;
        if (*format == '.')
        {
            flags |= PRINTF_FLAG_PRECISION;
            format++;
            if (*format == '*')
            {
                format++; 
                int tmp = va_arg(ap, int);
                tmp = (tmp < 0? 0: tmp);
                precision = (size_t)tmp;
            }
            else
            {
                for (; isdigit(*format); format++)
                {
                    precision *= 10;
                    precision += (unsigned)(*format - '0');
                    precision = (precision > INT32_MAX? INT32_MAX: precision);
                }
            }
        }

        switch (*format)
        {
            case 'l':
                flags |= PRINTF_FLAG_64;
                format++;
                if (*format == 'l')
                    format++;
                break;
            case 'h':
                format++;
                if (*format == 'h')
                {
                    format++;
                    flags |= PRINTF_FLAG_8;
                }
                else
                    flags |= PRINTF_FLAG_16;
                break;
            case 'z': case 'j': case 't':
                format++;
                flags |= PRINTF_FLAG_64;
                break;
        }

        int64_t x;
        uint64_t y;
        const char *s;
        size_t len;
        bool end = false;
        switch (*format)
        {
            case '\0':
                end = true;
                break;
            case 'c':
                x = (int64_t)(char)va_arg(ap, int);
                idx = printf_put_char(str, size, idx, (char)x);
                break;
            case 'd': case 'i':
                if (flags & PRINTF_FLAG_8)
                    x = (int64_t)(int8_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_16)
                    x = (int64_t)(int16_t)va_arg(ap, int);
                else if (flags & PRINTF_FLAG_64)
                    x = va_arg(ap, int64_t);
                else
                    x = (int64_t)va_arg(ap, int);
                if (x < 0)
                {
                    flags |= PRINTF_FLAG_NEG;
                    x = -x;
                }
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, (uint64_t)x);
                break;
            case 'X':
                flags |= PRINTF_FLAG_UPPER;
                // Fallthrough
            case 'x':
                flags |= PRINTF_FLAG_HEX;
                // Fallthrough
            case 'u':
                if (flags & PRINTF_FLAG_8)
                    y = (uint64_t)(uint8_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_16)
                    y = (uint64_t)(uint16_t)va_arg(ap, unsigned);
                else if (flags & PRINTF_FLAG_64)
                    y = va_arg(ap, uint64_t);
                else
                    y = (uint64_t)va_arg(ap, unsigned);
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 'p':
                y = (uint64_t)va_arg(ap, const void *);
                flags |= PRINTF_FLAG_HASH | PRINTF_FLAG_HEX;
                idx = printf_put_num(str, size, idx, flags, width,
                    precision, y);
                break;
            case 's':
                s = va_arg(ap, const char *);
                s = (s == NULL? "(null)": s);
                len = strlen(s);
                len = ((flags & PRINTF_FLAG_PRECISION) && precision < len?
                    precision: len);
                if (!(flags & PRINTF_FLAG_RIGHT))
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                for (size_t i = 0; i < len; i++)
                    idx = printf_put_char(str, size, idx, s[i]);
                if (flags & PRINTF_FLAG_RIGHT)
                {
                    for (size_t i = 0; width > len && i < width - len; i++)
                        idx = printf_put_char(str, size, idx, ' ');
                }
                break;
            default:
                idx = printf_put_char(str, size, idx, *format);
                break;
        }
        if (end)
            break;
    }
    (void)printf_put_char(str, size, idx, '\0');
    if (idx > INT32_MAX)
    {
        errno = ERANGE;
        return -1;
    }
    return (int)idx;
}

static int snprintf(char *str, size_t len, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vsnprintf(str, len, format, ap);
    va_end(ap);
    return result;
}

static int vfprintf(FILE *stream, const char *format, va_list ap)
{
    va_list ap1;
    va_copy(ap1, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result < 0)
        return result;
    char buf[result+1];
    result = vsnprintf(buf, result+1, format, ap1);
    if (result < 0)
        return result;
    if (fputs(buf, stream))
        return -1;
    return result;
}

static int vfprintf_unlocked(FILE *stream, const char *format, va_list ap)
{
    va_list ap1;
    va_copy(ap1, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result < 0)
        return result;
    char buf[result+1];
    result = vsnprintf(buf, result+1, format, ap1);
    if (result < 0)
        return result;
    if (fputs_unlocked(buf, stream))
        return -1;
    return result;
}

static int fprintf(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfprintf(stream, format, ap);
    va_end(ap);
    return result;
}

static int fprintf_unlocked(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfprintf_unlocked(stream, format, ap);
    va_end(ap);
    return result;
}

static int printf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfprintf(stdout, format, ap);
    va_end(ap);
    return result;
}

static int printf_unlocked(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfprintf_unlocked(stdout, format, ap);
    va_end(ap);
    return result;
}

/****************************************************************************/
/* MISC                                                                     */
/****************************************************************************/

/*
 * Note: To use getenv() it is necessary to initialize `environ' in
 *       the init() function.
 */
static char **environ = NULL;

static char *getenv(const char *name)
{
    if (environ == NULL)
        panic("environ not initialized");
    for (char **p = environ; *p != NULL; p++)
    {
        char *def = *p;
        size_t i;
        for (i = 0; def[i] != '=' && def[i] != '\0' &&
                def[i] == name[i]; i++)
            ;
        if (def[i] == '=' && name[i] == '\0')
            return def+i+1;
    }
    return NULL;
}

static __attribute__((__noreturn__)) void abort(void)
{
    kill(getpid(), SIGABRT);
    while (true)
        asm volatile ("ud2");
}

static int abs(int x)
{
    return (x < 0? -x: x);
}

static long int labs(long int x)
{
    return (x < 0? -x: x);
}

#ifdef __cplusplus
}       // extern "C"
#endif

#endif
