/*      _      _ _ _ _ 
 *  ___| |_ __| | (_) |__
 * / __| __/ _` | | | '_ \
 * \__ \ || (_| | | | |_) |
 * |___/\__\__,_|_|_|_.__/
 *
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
 * been minimized to keep the resulting binary small.  Generally, this file can
 * be compiled in a second or less, depending on how many functions are used.  
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
 * Only compiler-provided headers should be included.
 * GLibc headers should NOT be included.
 */
#ifdef __cplusplus
#include <cstdarg>
#include <cstdbool>
#include <cstddef>
#include <cstdint>
#else
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#define STDIN_FILENO                    0
#define STDOUT_FILENO                   1
#define STDERR_FILENO                   2

#define SYS_read                        0
#define SYS_write                       1
#define SYS_open                        2
#define SYS_close                       3
#define SYS_stat                        4
#define SYS_fstat                       5
#define SYS_lstat                       6
#define SYS_poll                        7
#define SYS_lseek                       8
#define SYS_mmap                        9
#define SYS_mprotect                    10
#define SYS_munmap                      11
#define SYS_brk                         12
#define SYS_rt_sigaction                13
#define SYS_rt_sigprocmask              14
#define SYS_rt_sigreturn                15
#define SYS_ioctl                       16
#define SYS_pread64                     17
#define SYS_pwrite64                    18
#define SYS_readv                       19
#define SYS_writev                      20
#define SYS_access                      21
#define SYS_pipe                        22
#define SYS_select                      23
#define SYS_sched_yield                 24
#define SYS_mremap                      25
#define SYS_msync                       26
#define SYS_mincore                     27
#define SYS_madvise                     28
#define SYS_shmget                      29
#define SYS_shmat                       30
#define SYS_shmctl                      31
#define SYS_dup                         32
#define SYS_dup2                        33
#define SYS_pause                       34
#define SYS_nanosleep                   35
#define SYS_getitimer                   36
#define SYS_alarm                       37
#define SYS_setitimer                   38
#define SYS_getpid                      39
#define SYS_sendfile                    40
#define SYS_socket                      41
#define SYS_connect                     42
#define SYS_accept                      43
#define SYS_sendto                      44
#define SYS_recvfrom                    45
#define SYS_sendmsg                     46
#define SYS_recvmsg                     47
#define SYS_shutdown                    48
#define SYS_bind                        49
#define SYS_listen                      50
#define SYS_getsockname                 51
#define SYS_getpeername                 52
#define SYS_socketpair                  53
#define SYS_setsockopt                  54
#define SYS_getsockopt                  55
#define SYS_clone                       56
#define SYS_fork                        57
#define SYS_vfork                       58
#define SYS_execve                      59
#define SYS_exit                        60
#define SYS_wait4                       61
#define SYS_kill                        62
#define SYS_uname                       63
#define SYS_semget                      64
#define SYS_semop                       65
#define SYS_semctl                      66
#define SYS_shmdt                       67
#define SYS_msgget                      68
#define SYS_msgsnd                      69
#define SYS_msgrcv                      70
#define SYS_msgctl                      71
#define SYS_fcntl                       72
#define SYS_flock                       73
#define SYS_fsync                       74
#define SYS_fdatasync                   75
#define SYS_truncate                    76
#define SYS_ftruncate                   77
#define SYS_getdents                    78
#define SYS_getcwd                      79
#define SYS_chdir                       80
#define SYS_fchdir                      81
#define SYS_rename                      82
#define SYS_mkdir                       83
#define SYS_rmdir                       84
#define SYS_creat                       85
#define SYS_link                        86
#define SYS_unlink                      87
#define SYS_symlink                     88
#define SYS_readlink                    89
#define SYS_chmod                       90
#define SYS_fchmod                      91
#define SYS_chown                       92
#define SYS_fchown                      93
#define SYS_lchown                      94
#define SYS_umask                       95
#define SYS_gettimeofday                96
#define SYS_getrlimit                   97
#define SYS_getrusage                   98
#define SYS_sysinfo                     99
#define SYS_times                       100
#define SYS_ptrace                      101
#define SYS_getuid                      102
#define SYS_syslog                      103
#define SYS_getgid                      104
#define SYS_setuid                      105
#define SYS_setgid                      106
#define SYS_geteuid                     107
#define SYS_getegid                     108
#define SYS_setpgid                     109
#define SYS_getppid                     110
#define SYS_getpgrp                     111
#define SYS_setsid                      112
#define SYS_setreuid                    113
#define SYS_setregid                    114
#define SYS_getgroups                   115
#define SYS_setgroups                   116
#define SYS_setresuid                   117
#define SYS_getresuid                   118
#define SYS_setresgid                   119
#define SYS_getresgid                   120
#define SYS_getpgid                     121
#define SYS_setfsuid                    122
#define SYS_setfsgid                    123
#define SYS_getsid                      124
#define SYS_capget                      125
#define SYS_capset                      126
#define SYS_rt_sigpending               127
#define SYS_rt_sigtimedwait             128
#define SYS_rt_sigqueueinfo             129
#define SYS_rt_sigsuspend               130
#define SYS_sigaltstack                 131
#define SYS_utime                       132
#define SYS_mknod                       133
#define SYS_uselib                      134
#define SYS_personality                 135
#define SYS_ustat                       136
#define SYS_statfs                      137
#define SYS_fstatfs                     138
#define SYS_sysfs                       139
#define SYS_getpriority                 140
#define SYS_setpriority                 141
#define SYS_sched_setparam              142
#define SYS_sched_getparam              143
#define SYS_sched_setscheduler          144
#define SYS_sched_getscheduler          145
#define SYS_sched_get_priority_max      146
#define SYS_sched_get_priority_min      147
#define SYS_sched_rr_get_interval       148
#define SYS_mlock                       149
#define SYS_munlock                     150
#define SYS_mlockall                    151
#define SYS_munlockall                  152
#define SYS_vhangup                     153
#define SYS_modify_ldt                  154
#define SYS_pivot_root                  155
#define SYS__sysctl                     156
#define SYS_prctl                       157
#define SYS_arch_prctl                  158
#define SYS_adjtimex                    159
#define SYS_setrlimit                   160
#define SYS_chroot                      161
#define SYS_sync                        162
#define SYS_acct                        163
#define SYS_settimeofday                164
#define SYS_mount                       165
#define SYS_umount2                     166
#define SYS_swapon                      167
#define SYS_swapoff                     168
#define SYS_reboot                      169
#define SYS_sethostname                 170
#define SYS_setdomainname               171
#define SYS_iopl                        172
#define SYS_ioperm                      173
#define SYS_create_module               174
#define SYS_init_module                 175
#define SYS_delete_module               176
#define SYS_get_kernel_syms             177
#define SYS_query_module                178
#define SYS_quotactl                    179
#define SYS_nfsservctl                  180
#define SYS_getpmsg                     181
#define SYS_putpmsg                     182
#define SYS_afs_syscall                 183
#define SYS_tuxcall                     184
#define SYS_security                    185
#define SYS_gettid                      186
#define SYS_readahead                   187
#define SYS_setxattr                    188
#define SYS_lsetxattr                   189
#define SYS_fsetxattr                   190
#define SYS_getxattr                    191
#define SYS_lgetxattr                   192
#define SYS_fgetxattr                   193
#define SYS_listxattr                   194
#define SYS_llistxattr                  195
#define SYS_flistxattr                  196
#define SYS_removexattr                 197
#define SYS_lremovexattr                198
#define SYS_fremovexattr                199
#define SYS_tkill                       200
#define SYS_time                        201
#define SYS_futex                       202
#define SYS_sched_setaffinity           203
#define SYS_sched_getaffinity           204
#define SYS_set_thread_area             205
#define SYS_io_setup                    206
#define SYS_io_destroy                  207
#define SYS_io_getevents                208
#define SYS_io_submit                   209
#define SYS_io_cancel                   210
#define SYS_get_thread_area             211
#define SYS_lookup_dcookie              212
#define SYS_epoll_create                213
#define SYS_epoll_ctl_old               214
#define SYS_epoll_wait_old              215
#define SYS_remap_file_pages            216
#define SYS_getdents64                  217
#define SYS_set_tid_address             218
#define SYS_restart_syscall             219
#define SYS_semtimedop                  220
#define SYS_fadvise64                   221
#define SYS_timer_create                222
#define SYS_timer_settime               223
#define SYS_timer_gettime               224
#define SYS_timer_getoverrun            225
#define SYS_timer_delete                226
#define SYS_clock_settime               227
#define SYS_clock_gettime               228
#define SYS_clock_getres                229
#define SYS_clock_nanosleep             230
#define SYS_exit_group                  231
#define SYS_epoll_wait                  232
#define SYS_epoll_ctl                   233
#define SYS_tgkill                      234
#define SYS_utimes                      235
#define SYS_vserver                     236
#define SYS_mbind                       237
#define SYS_set_mempolicy               238
#define SYS_get_mempolicy               239
#define SYS_mq_open                     240
#define SYS_mq_unlink                   241
#define SYS_mq_timedsend                242
#define SYS_mq_timedreceive             243
#define SYS_mq_notify                   244
#define SYS_mq_getsetattr               245
#define SYS_kexec_load                  246
#define SYS_waitid                      247
#define SYS_add_key                     248
#define SYS_request_key                 249
#define SYS_keyctl                      250
#define SYS_ioprio_set                  251
#define SYS_ioprio_get                  252
#define SYS_inotify_init                253
#define SYS_inotify_add_watch           254
#define SYS_inotify_rm_watch            255
#define SYS_migrate_pages               256
#define SYS_openat                      257
#define SYS_mkdirat                     258
#define SYS_mknodat                     259
#define SYS_fchownat                    260
#define SYS_futimesat                   261
#define SYS_newfstatat                  262
#define SYS_unlinkat                    263
#define SYS_renameat                    264
#define SYS_linkat                      265
#define SYS_symlinkat                   266
#define SYS_readlinkat                  267
#define SYS_fchmodat                    268
#define SYS_faccessat                   269
#define SYS_pselect6                    270
#define SYS_ppoll                       271
#define SYS_unshare                     272
#define SYS_set_robust_list             273
#define SYS_get_robust_list             274
#define SYS_splice                      275
#define SYS_tee                         276
#define SYS_sync_file_range             277
#define SYS_vmsplice                    278
#define SYS_move_pages                  279
#define SYS_utimensat                   280
#define SYS_epoll_pwait                 281
#define SYS_signalfd                    282
#define SYS_timerfd_create              283
#define SYS_eventfd                     284
#define SYS_fallocate                   285
#define SYS_timerfd_settime             286
#define SYS_timerfd_gettime             287
#define SYS_accept4                     288
#define SYS_signalfd4                   289
#define SYS_eventfd2                    290
#define SYS_epoll_create1               291
#define SYS_dup3                        292
#define SYS_pipe2                       293
#define SYS_inotify_init1               294
#define SYS_preadv                      295
#define SYS_pwritev                     296
#define SYS_rt_tgsigqueueinfo           297
#define SYS_perf_event_open             298
#define SYS_recvmmsg                    299
#define SYS_fanotify_init               300
#define SYS_fanotify_mark               301
#define SYS_prlimit64                   302
#define SYS_name_to_handle_at           303
#define SYS_open_by_handle_at           304
#define SYS_clock_adjtime               305
#define SYS_syncfs                      306
#define SYS_sendmmsg                    307
#define SYS_setns                       308
#define SYS_getcpu                      309
#define SYS_process_vm_readv            310
#define SYS_process_vm_writev           311
#define SYS_kcmp                        312
#define SYS_finit_module                313
#define SYS_sched_setattr               314
#define SYS_sched_getattr               315
#define SYS_renameat2                   316
#define SYS_seccomp                     317
#define SYS_getrandom                   318
#define SYS_memfd_create                319
#define SYS_kexec_file_load             320
#define SYS_bpf                         321
#define SYS_execveat                    322
#define SYS_userfaultfd                 323
#define SYS_membarrier                  324
#define SYS_mlock2                      325

#define EPERM                           1
#define ENOENT                          2
#define ESRCH                           3
#define EINTR                           4
#define EIO                             5
#define ENXIO                           6
#define E2BIG                           7
#define ENOEXEC                         8
#define EBADF                           9
#define ECHILD                          10
#define EAGAIN                          11
#define ENOMEM                          12
#define EACCES                          13
#define EFAULT                          14
#define ENOTBLK                         15
#define EBUSY                           16
#define EEXIST                          17
#define EXDEV                           18
#define ENODEV                          19
#define ENOTDIR                         20
#define EISDIR                          21
#define EINVAL                          22
#define ENFILE                          23
#define EMFILE                          24
#define ENOTTY                          25
#define ETXTBSY                         26
#define EFBIG                           27
#define ENOSPC                          28
#define ESPIPE                          29
#define EROFS                           30
#define EMLINK                          31
#define EPIPE                           32
#define EDOM                            33
#define ERANGE                          34
#define EDEADLK                         35
#define ENAMETOOLONG                    36
#define ENOLCK                          37
#define ENOSYS                          38
#define ENOTEMPTY                       39
#define ELOOP                           40
#define EWOULDBLOCK                     11
#define ENOMSG                          42
#define EIDRM                           43
#define ECHRNG                          44
#define EL2NSYNC                        45
#define EL3HLT                          46
#define EL3RST                          47
#define ELNRNG                          48
#define EUNATCH                         49
#define ENOCSI                          50
#define EL2HLT                          51
#define EBADE                           52
#define EBADR                           53
#define EXFULL                          54
#define ENOANO                          55
#define EBADRQC                         56
#define EBADSLT                         57
#define EDEADLOCK                       35
#define EBFONT                          59
#define ENOSTR                          60
#define ENODATA                         61
#define ETIME                           62
#define ENOSR                           63
#define ENONET                          64
#define ENOPKG                          65
#define EREMOTE                         66
#define ENOLINK                         67
#define EADV                            68
#define ESRMNT                          69
#define ECOMM                           70
#define EPROTO                          71
#define EMULTIHOP                       72
#define EDOTDOT                         73
#define EBADMSG                         74
#define EOVERFLOW                       75
#define ENOTUNIQ                        76
#define EBADFD                          77
#define EREMCHG                         78
#define ELIBACC                         79
#define ELIBBAD                         80
#define ELIBSCN                         81
#define ELIBMAX                         82
#define ELIBEXEC                        83
#define EILSEQ                          84
#define ERESTART                        85
#define ESTRPIPE                        86
#define EUSERS                          87
#define ENOTSOCK                        88
#define EDESTADDRREQ                    89
#define EMSGSIZE                        90
#define EPROTOTYPE                      91
#define ENOPROTOOPT                     92
#define EPROTONOSUPPORT                 93
#define ESOCKTNOSUPPORT                 94
#define EOPNOTSUPP                      95
#define EPFNOSUPPORT                    96
#define EAFNOSUPPORT                    97
#define EADDRINUSE                      98
#define EADDRNOTAVAIL                   99
#define ENETDOWN                        100
#define ENETUNREACH                     101
#define ENETRESET                       102
#define ECONNABORTED                    103
#define ECONNRESET                      104
#define ENOBUFS                         105
#define EISCONN                         106
#define ENOTCONN                        107
#define ESHUTDOWN                       108
#define ETOOMANYREFS                    109
#define ETIMEDOUT                       110
#define ECONNREFUSED                    111
#define EHOSTDOWN                       112
#define EHOSTUNREACH                    113
#define EALREADY                        114
#define EINPROGRESS                     115
#define ESTALE                          116
#define EUCLEAN                         117
#define ENOTNAM                         118
#define ENAVAIL                         119
#define EISNAM                          120
#define EREMOTEIO                       121
#define EDQUOT                          122
#define ENOMEDIUM                       123
#define EMEDIUMTYPE                     124
#define ECANCELED                       125
#define ENOKEY                          126
#define EKEYEXPIRED                     127
#define EKEYREVOKED                     128
#define EKEYREJECTED                    129
#define EOWNERDEAD                      130
#define ENOTRECOVERABLE                 131
#define ERFKILL                         132
#define EHWPOISON                       133
#define ENOTSUP                         95

#define SIGHUP                          1
#define SIGINT                          2
#define SIGQUIT                         3
#define SIGILL                          4
#define SIGTRAP                         5
#define SIGABRT                         6
#define SIGIOT                          6
#define SIGBUS                          7
#define SIGFPE                          8
#define SIGKILL                         9
#define SIGUSR1                         10
#define SIGSEGV                         11
#define SIGUSR2                         12
#define SIGPIPE                         13
#define SIGALRM                         14
#define SIGTERM                         15
#define SIGSTKFLT                       16
#define SIGCLD                          SIGCHLD
#define SIGCHLD                         17
#define SIGCONT                         18
#define SIGSTOP                         19
#define SIGTSTP                         20
#define SIGTTIN                         21
#define SIGTTOU                         22
#define SIGURG                          23
#define SIGXCPU                         24
#define SIGXFSZ                         25
#define SIGVTALRM                       26
#define SIGPROF                         27
#define SIGWINCH                        28
#define SIGPOLL                         SIGIO
#define SIGIO                           29
#define SIGPWR                          30
#define SIGSYS                          31
#define SIGUNUSED                       31
#define _NSIG                           65

typedef unsigned short mode_t;
typedef long ssize_t;
typedef long off_t;
typedef long ptrdiff_t;
typedef int pid_t;
typedef int uid_t;
typedef int gid_t;
typedef long time_t;
typedef long clock_t;
typedef int key_t;

#define CHAR_BIT                        8
#define SCHAR_MIN                       INT8_MIN
#define SCHAR_MAX                       INT8_MAX
#define CHAR_MIN                        SCHAR_MIN
#define CHAR_MAX                        SCHAR_MAX
#define UCHAR_MAX                       UINT8_MAX
#define SHRT_MIN                        INT16_MIN
#define SHRT_MAX                        INT16_MAX
#define USHRT_MAX                       UINT16_MAX
#define INT_MIN                         INT32_MIN
#define INT_MAX                         INT32_MAX
#define UINT_MAX                        UINT32_MAX
#define LONG_MIN                        ((long)INT64_MIN)
#define LONG_MAX                        ((long)INT64_MAX)
#define ULONG_MAX                       ((unsigned long)UINT64_MAX)
#define LLONG_MIN                       ((long long)INT64_MIN)
#define LLONG_MAX                       ((long long)INT64_MAX)
#define ULLONG_MAX                      ((unsigned long long)UINT64_MAX)

#define S_IRUSR                         0400
#define S_IWUSR                         0200
#define S_IXUSR                         0100
#define S_IRWXU                         (S_IRUSR|S_IWUSR|S_IXUSR)
#define S_IRGRP                         (S_IRUSR >> 3)
#define S_IWGRP                         (S_IWUSR >> 3)
#define S_IXGRP                         (S_IXUSR >> 3)
#define S_IRWXG                         (S_IRWXU >> 3)
#define S_IROTH                         (S_IRGRP >> 3)
#define S_IWOTH                         (S_IWGRP >> 3)
#define S_IXOTH                         (S_IXGRP >> 3)
#define S_IRWXO                         (S_IRWXG >> 3)
#define S_ISUID                         04000
#define S_ISGID                         02000
#define S_ISVTX                         01000

#define O_ACCMODE                       00000003
#define O_RDONLY                        00000000
#define O_WRONLY                        00000001
#define O_RDWR                          00000002
#define O_CREAT                         00000100
#define O_EXCL                          00000200
#define O_NOCTTY                        00000400
#define O_TRUNC                         00001000
#define O_APPEND                        00002000
#define O_NONBLOCK                      00004000
#define O_DSYNC                         00010000
#define O_DIRECT                        00040000
#define O_LARGEFILE                     00100000
#define O_DIRECTORY                     00200000
#define O_NOFOLLOW                      00400000
#define O_NOATIME                       01000000
#define O_CLOEXEC                       02000000
#define O_ASYNC                         00020000
#define O_SYNC                          04010000

#define LOCK_SH                         1
#define LOCK_EX                         2
#define LOCK_UN                         8

#define FD_SETSIZE  512
#define FD_NBITS    (8 * sizeof(unsigned long))
typedef struct
{
    unsigned long fds_bits[FD_SETSIZE / FD_NBITS];
} fd_set;
#define FD_ZERO(fds)                    memset((fds), 0x0, sizeof(fd_set))
#define FD_SET(fd, fds)                 \
    ((fds)->fds_bits[(fd)/FD_NBITS] |= (0x1ul<<((fd)%FD_NBITS)))
#define FD_CLR(fd, fds)                 \
    ((fds)->fds_bits[(fd)/FD_NBITS] &= ~(0x1ul<<((fd)%FD_NBITS)))
#define FD_ISSET(fd, fds)               \
    (((fds)->fds_bits[(fd)/FD_NBITS] & (0x1ul<<((fd)%FD_NBITS))) != 0)

typedef unsigned long int nfds_t;
struct pollfd
{
    int fd;
    short events;
    short revents;
};
#define POLLIN                          0x0001
#define POLLPRI                         0x0002
#define POLLOUT                         0x0004
#define POLLERR                         0x0008
#define POLLHUP                         0x0010
#define POLLNVAL                        0x0020

struct timeval
{
    time_t tv_sec;
    long   tv_usec;
};
struct timespec
{
    time_t tv_sec;
    long   tv_nsec;
};
struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

struct stat
{
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned st_mode;
    uid_t st_uid;
    gid_t st_gid;
    unsigned __pad;
    unsigned long st_rdev;
    off_t st_size;
    long st_blksize;
    long st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    unsigned long __unused[3];
};

struct rusage
{
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};
#define RUSAGE_SELF                     0
#define RUSAGE_CHILDREN                 (-1)
#define RUSAGE_THREAD                   1

struct rlimit
{
    unsigned long rlim_cur;
    unsigned long rlim_max;
};
#define RLIMIT_CPU                      0
#define RLIMIT_FSIZE                    1
#define RLIMIT_DATA                     2
#define RLIMIT_STACK                    3
#define RLIMIT_CORE                     4
#define RLIMIT_RSS                      5
#define RLIMIT_NPROC                    6
#define RLIMIT_NOFILE                   7
#define RLIMIT_MEMLOCK                  8
#define RLIMIT_AS                       9
#define RLIMIT_LOCKS                    10

struct termios
{
    unsigned c_iflag;
    unsigned c_oflag;
    unsigned c_cflag;
    unsigned c_lflag;
    unsigned char c_line;
    unsigned char c_cc[19];
};
#define TCGETS                          0x5401

#define PROT_READ                       0x1
#define PROT_WRITE                      0x2
#define PROT_EXEC                       0x4
#define PROT_NONE                       0x0

#define MAP_SHARED                      0x0001
#define MAP_PRIVATE                     0x0002
#define MAP_FIXED                       0x0010
#define MAP_ANONYMOUS                   0x0020
#define MAP_NORESERVE                   0x4000
#define MAP_POPULATE                    0x8000
#define MAP_FAILED                      ((void *)-1)

#define MREMAP_MAYMOVE                  1
#define MREMAP_FIXED                    2

#define MS_ASYNC                        1
#define MS_INVALIDATE                   2
#define MS_SYNC                         4

#define MADV_NORMAL                     0
#define MADV_RANDOM                     1
#define MADV_SEQUENTIAL                 2
#define MADV_WILLNEED                   3
#define MADV_DONTNEED                   4

typedef unsigned long sigset_t;
typedef void (*sighandler_t)(int);
#define SIG_ERR     ((sighandler_t)-1)
#define SIG_DFL     ((sighandler_t)0)
#define SIG_IGN     ((sighandler_t)1)
typedef union
{
    int sival_int;
    void *sival_ptr;
} sigval_t;
#define SI_MAX_SIZE     128
#define SI_PAD_SIZE     ((SI_MAX_SIZE / sizeof(int)) - 4)
typedef struct
{
    int si_signo;
    int si_errno;
    int si_code;
    union
    {
        int _pad[SI_PAD_SIZE];
        struct
        {
            pid_t si_pid;
            uid_t si_uid;
        } _kill;
        struct
        {
            int si_tid;
            int si_overrun;
            sigval_t si_sigval;
        } _timer;
        struct
        {
            pid_t si_pid;
            uid_t si_uid;
            sigval_t si_sigval;
        } _rt;
        struct
        {
            pid_t si_pid;
            uid_t si_uid;
            int si_status;
            clock_t si_utime;
            clock_t si_stime;
        } _sigchld;
        struct
        {
            void *si_addr;
            short int si_addr_lsb;
            struct
            {
                void *_lower;
                void *_upper;
            } si_addr_bnd;
        } _sigfault;
        struct
        {
            long si_band;
            int si_fd;
        } _sigpoll;
        struct
        {
            void *_call_addr;
            int _syscall;
            unsigned _arch;
        } _sigsys;
      } _sifields;
} siginfo_t;
struct sigaction
{
    union
    {
        sighandler_t sa_handler;
        void (*sa_sigaction)(int, siginfo_t *, void *);
    };
    sigset_t sa_mask;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
};
#define SA_NOCLDSTOP            0x00000001u
#define SA_NOCLDWAIT            0x00000002u
#define SA_SIGINFO              0x00000004u
#define SA_ONSTACK              0x08000000u
#define SA_RESTART              0x10000000u
#define SA_NODEFER              0x40000000u
#define SA_RESETHAND            0x80000000u
#define SA_NOMASK               SA_NODEFER
#define SA_ONESHOT              SA_RESETHAND
#define SA_RESTORER             0x04000000

struct iovec
{
    void *iov_base;
    size_t iov_len;
};

#define WNOHANG                 1
#define WEXITSTATUS(status)     (((status) >> 8) & 0xFF)
#define WTERMSIG(status)        ((status) & 0x7F)
#define WIFSIGNALED(status)     (WTERMSIG(status) != 0)
#define WIFEXITED(status)       (WTERMSIG(status) == 0)
#define EXIT_SUCCESS            0
#define EXIT_FAILURE            1

typedef int32_t socklen_t;
#define AF_UNSPEC               0
#define AF_UNIX                 1
#define AF_INET                 2
#define AF_INET6                10
#define SOCK_STREAM             1
#define SOCK_DGRAM              2
#define SOCK_RAW                3
#define SOCK_SEQPACKET          5
#define SOCK_PACKET             10
#define IPPROTO_ICMP            1
#define IPPROTO_TCP             6
#define IPPROTO_UDP             17
struct in_addr
{
    uint32_t s_addr;
};
struct in6_addr
{
    union
    {
        uint8_t  s6_addr[16];
        uint16_t s6_addr16[8];
        uint32_t s6_addr32[4];
    };
};
typedef unsigned short sa_family_t;
struct sockaddr
{
    sa_family_t sa_family;
    char sa_data[14];
};
struct sockaddr_in
{
    sa_family_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[
        sizeof(struct sockaddr) -
        sizeof(sa_family_t) -
        sizeof(uint16_t) -
        sizeof(struct in_addr)];
};
struct sockaddr_in6
{
    sa_family_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};
struct sockaddr_un
{
    sa_family_t sun_family;
    char sun_path[108];
};
struct msghdr
{
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

#ifdef __cplusplus
extern "C"
{
#endif

long syscall(int callno, ...);
static void *memset(void *s, int c, size_t n);
static void *memcpy(void *dest, const void *src, size_t n);

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
    int *loc;
    asm volatile (
        "mov %%fs:0x0,%0\n"
        "lea " STRING(ERRNO_TLS_OFFSET) "(%0),%0\n" : "=a"(loc)
    );
    return loc;
}
#define errno                   (*__errno_location())
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
    mode_t mode = va_arg(ap, int);
    int result = (int)syscall(SYS_open, pathname, flags, mode);
    va_end(ap);
    return result;
}

static int close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

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

static int execve(const char *filename, char *const argv[],
    char *const envp[])
{
    return (int)syscall(SYS_execve, filename, argv, envp);
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

static int symlink(const char *oldname, const char *newname)
{
    return (int)syscall(SYS_symlink, oldname, newname);
}

static ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return (ssize_t)syscall(SYS_readlink, pathname, buf, bufsiz);
}

static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return (int)syscall(SYS_gettimeofday, tv, tz);
}

static int getrlimit(int resource, struct rlimit *rlim)
{
    return (int)syscall(SYS_getrlimit, resource, rlim);
}

static int setrlimit(int resource, const struct rlimit *rlim)
{
    return (int)syscall(SYS_setrlimit, resource, rlim);
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

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    return syscall(SYS_nanosleep, req, rem);
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
    // Warning: this assumes the thread ID is stored at %fs:0x2d0.
    pid_t tid;
    asm volatile (
        "mov %%fs:0x2d0,%0\n" : "=a"(tid)
    );
    return tid;
}

static void mutex_settid(pid_t tid)
{
    asm volatile (
        "mov %0,%%fs:0x2d0\n" : : "r"(tid)
    );
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

static pid_t gettid(void)
{
    return mutex_gettid();
}

#else       /* MUTEX_SAFE */

#define mutex_settid(tid)       /* NOP */
#define mutex_fast_lock(x)      false
#define mutex_fast_unlock(x)    false

static pid_t gettid(void)
{
    return syscall(SYS_gettid);
}

#endif      /* MUTEX_SAFE */

struct mutex_s
{
    // The stack may be unaligned, so we do manual alignment.
    uint8_t val[2 * sizeof(int)];
};
typedef struct mutex_s mutex_t;

#define MUTEX_INITIALIZER       {{0}}

static void mutex_init(mutex_t *m)
{
    mutex_t m0 = MUTEX_INITIALIZER;
    memcpy(m, &m0, sizeof(struct mutex_s));
}

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
static __attribute__((__noinline__, __warn_unused_result__))
    int mutex_lock(mutex_t *m)
{
    pid_t *x = mutex_get_ptr(m);
    if (mutex_fast_lock(x))
        return 0;
    if (syscall(SYS_futex, x, FUTEX_LOCK_PI, 0, NULL, NULL, 0) < 0)
        return -1;
    if (*x & FUTEX_OWNER_DIED)
    {
        // This can occur if a thread dies while holding a lock.
        *x &= ~FUTEX_OWNER_DIED;
        errno = EOWNERDEAD;
        return -1;
    }
    return 0;                       // acquired
}

static __attribute__((__noinline__)) int mutex_trylock(mutex_t *m)
{
    pid_t *x = mutex_get_ptr(m);
    if (mutex_fast_lock(x))
        return 0;
    else
    {
        errno = EBUSY;
        return -1;
    }
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

static pid_t fork(void)
{
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0)
        mutex_settid((pid_t)syscall(SYS_gettid));
    return child;
}

/****************************************************************************/
/* CONFIGURATION                                                            */
/****************************************************************************/

/*
 * Save stdlib configuration as a symbol.
 */
#ifndef ERRNO_TLS
#define CONFIG_ERRNO        0x1
#else
#define CONFIG_ERRNO        0
#endif

#ifdef MUTEX_SAFE
#define CONFIG_MUTEX        0x2
#else
#define CONFIG_MUTEX        0
#endif

asm (
    ".globl _stdlib_config\n"
    ".set _stdlib_config,"
        STRING(CONFIG_ERRNO) "|"
        STRING(CONFIG_MUTEX) "\n"
);

/****************************************************************************/
/* MALLOC                                                                   */
/****************************************************************************/

/*
 * This is a malloc() implementation based on interval-trees.  This algorithm
 * is chosen because (1) it is relatively simple, and (2) the worst-case time
 * and memory performance should be reasonable.
 *
 * The implementation uses code that is derived from Niels Provos' red-black
 * tree implementation.  See the copyright and license (BSD) below.
 */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Malloc metadata node.
 */
struct malloc_node_s
{
    uint32_t color:1;       // RB-tree color
    uint32_t magic:31;      // Magic number
    uint32_t parent;        // RB-tree parent
    uint32_t left;          // RB-tree left
    uint32_t right;         // RB-tree right
    uint32_t size;          // allocation SIZE
    uint32_t lb;            // sub-tree LB
    uint32_t ub;            // sub-tree UB
    uint32_t gap;           // sub-tree max GAP
};

/*
 * Malloc pool.
 */
struct malloc_pool_s
{
    mutex_t mutex;          // Mutex
    uint8_t *base;          // Pool base address
    uint32_t mmap;          // Pool mmap limit
    uint32_t end;           // Pool end address
    uint32_t root;          // Pool root node
    int flags;              // Pool mmap flags
};

static struct malloc_pool_s malloc_pool = {MUTEX_INITIALIZER, 0};

#define MA_MAGIC_NUMBER             0x4945F7C2
#define MA_UNIT                     16
#define MA_MAX_SIZE                 (MA_UNIT * UINT32_MAX)
#define MA_NIL                      0x0
#define MA_ZERO                     ((void *)-((intptr_t)UINT32_MAX + 1))
#define MA_PAGE_SIZE                4096ull
#define MA_BLACK                    0
#define MA_RED                      1
#define MA_NODE(pool, N)            \
    ((struct malloc_node_s *)(pool->base+(N)*MA_UNIT))
#define MA_PARENT(pool, N)          (MA_NODE(pool, N)->parent)
#define MA_LEFT(pool, N)            (MA_NODE(pool, N)->left)
#define MA_RIGHT(pool, N)           (MA_NODE(pool, N)->right)
#define MA_COLOR(pool, N)           (MA_NODE(pool, N)->color)
#define MA_SIZE(pool, N)            (MA_NODE(pool, N)->size)
#define MA_LB(pool, N)              (MA_NODE(pool, N)->lb)
#define MA_UB(pool, N)              (MA_NODE(pool, N)->ub)
#define MA_GAP(pool, N)             (MA_NODE(pool, N)->gap)
#define MA_MAGIC(pool, N)           (MA_NODE(pool, N)->magic)
#define MA_POOL_LB(pool)            \
    (sizeof(*pool) / MA_UNIT + (sizeof(*pool) % MA_UNIT? 1: 0))
#define MA_POOL_UB(pool)            (pool->end)

#define MA_MAX(n, m)                ((n) > (m)? (n): (m))
#define MA_MIN(n, m)                ((n) < (m)? (n): (m))

#define MA_PAGES(n)                 \
    ((n) / MA_PAGE_SIZE + ((n) % MA_PAGE_SIZE? 1: 0))

/*
 * Create a malloc() pool.  Here, flags are mmap() flags.
 */
static struct malloc_pool_s *pool_create(int flags, size_t lb, size_t ub)
{
    if (ub < lb)
    {
        errno = EINVAL;
        return NULL;
    }
    lb += sizeof(struct malloc_pool_s);
    ub += sizeof(struct malloc_pool_s);
    void *ptr = mmap(NULL, ub, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr == MAP_FAILED)
        return NULL;
    flags |= MAP_ANONYMOUS;
    struct malloc_pool_s *pool = (struct malloc_pool_s *)ptr;
    ptr = mmap(ptr, lb, PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0);
    if (ptr != (void *)pool)
    {
        (void)munmap(ptr, ub);
        errno = EINVAL;
        return NULL;
    }
    mutex_init(&pool->mutex);
    pool->base   = (uint8_t *)pool;
    pool->mmap   = (MA_PAGE_SIZE * MA_PAGES(lb)) / MA_UNIT;
    pool->end    = (MA_PAGE_SIZE * MA_PAGES(ub)) / MA_UNIT;
    pool->root   = MA_NIL;
    pool->flags  = flags;
    return pool;
}

/*
 * Destroy a malloc() pool.
 */
static int pool_destroy(struct malloc_pool_s *pool)
{
    if (pool == &malloc_pool)
    {
        errno = EINVAL;
        return -1;
    }
    return munmap(pool, (size_t)pool->end * MA_UNIT);
}

/*
 * Pool init.
 */
static struct malloc_pool_s *pool_init(struct malloc_pool_s *pool)
{
    pool = (pool == NULL? &malloc_pool: pool);
    if (pool->base != NULL)
        return pool;
    if (mutex_lock(&pool->mutex) < 0)
        return pool;
    if (pool->base != NULL)
    {
        mutex_unlock(&pool->mutex);
        return pool;
    }
    uintptr_t hint = 0xaaa00000000ull;
    (void)getrandom(&hint, sizeof(uint32_t), 0);
    hint &= ~(MA_PAGE_SIZE-1);
    void *ptr = mmap((void *)hint, MA_MAX_SIZE, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (ptr == MAP_FAILED)
        panic("mmap() failed");
    pool->base   = (uint8_t *)ptr;
    pool->mmap   = 0;
    pool->end    = UINT32_MAX;
    pool->root   = MA_NIL;
    pool->flags  = MAP_PRIVATE | MAP_ANONYMOUS;
    mutex_unlock(&pool->mutex);
    return pool;
}

/*
 * Fix the interval-tree invariant (RB-tree augmentation).
 */
static void malloc_fix_invariant(struct malloc_pool_s *pool, uint32_t n)
{
    if (n == MA_NIL)
        return;
    uint32_t l = MA_LEFT(pool, n), r = MA_RIGHT(pool, n);
    uint32_t llb = (l != MA_NIL? MA_LB(pool, l): MA_POOL_UB(pool));
    intptr_t rub = (r != MA_NIL? MA_UB(pool, r): MA_POOL_LB(pool));
    MA_LB(pool, n) = MA_MIN(llb, n);
    MA_UB(pool, n) = MA_MAX(rub, n + MA_SIZE(pool, n));
    uint32_t lgap = (l != MA_NIL? MA_GAP(pool, l): 0);
    uint32_t rgap = (r != MA_NIL? MA_GAP(pool, r): 0);
    uint32_t gap  = MA_MAX(lgap, rgap);
    gap = MA_MAX(gap, (uint32_t)(l != MA_NIL?  n - MA_UB(pool, l): 0));
    gap = MA_MAX(gap, (uint32_t)(r != MA_NIL?
        MA_LB(pool, r) - (n + MA_SIZE(pool, n)): 0));
    MA_GAP(pool, n) = gap;
}

static void malloc_rotate_left(struct malloc_pool_s *pool, uint32_t n)
{
    uint32_t tmp = MA_RIGHT(pool, n);
    if ((MA_RIGHT(pool, n) = MA_LEFT(pool, tmp)) != MA_NIL)
        MA_PARENT(pool, MA_LEFT(pool, tmp)) = n;
    malloc_fix_invariant(pool, n);
    if ((MA_PARENT(pool, tmp) = MA_PARENT(pool, n)) != MA_NIL)
    {
        if (n == MA_LEFT(pool, MA_PARENT(pool, n)))
            MA_LEFT(pool, MA_PARENT(pool, n)) = tmp;
        else
            MA_RIGHT(pool, MA_PARENT(pool, n)) = tmp;
    }
    else
        pool->root = tmp;
    MA_LEFT(pool, tmp) = n;
    MA_PARENT(pool, n) = tmp;
    malloc_fix_invariant(pool, tmp);
    if (MA_PARENT(pool, tmp) != MA_NIL)
        malloc_fix_invariant(pool, MA_PARENT(pool, tmp));
}

static void malloc_rotate_right(struct malloc_pool_s *pool, uint32_t n)
{
    uint32_t tmp = MA_LEFT(pool, n);
    if ((MA_LEFT(pool, n) = MA_RIGHT(pool, tmp)) != MA_NIL)
        MA_PARENT(pool, MA_RIGHT(pool, tmp)) = n;
    malloc_fix_invariant(pool, n);
    if ((MA_PARENT(pool, tmp) = MA_PARENT(pool, n)) != MA_NIL)
    {
        if (n == MA_LEFT(pool, MA_PARENT(pool, n)))
            MA_LEFT(pool, MA_PARENT(pool, n)) = tmp;
        else
            MA_RIGHT(pool, MA_PARENT(pool, n)) = tmp;
    } else
        pool->root = tmp;
    MA_RIGHT(pool, tmp) = n;
    MA_PARENT(pool, n) = tmp;
    malloc_fix_invariant(pool, tmp);
    if (MA_PARENT(pool, tmp) != MA_NIL)
        malloc_fix_invariant(pool, MA_PARENT(pool, tmp));
}

static void malloc_rebalance_insert(struct malloc_pool_s *pool, uint32_t n)
{
    uint32_t parent, gparent, tmp;
    for (uint32_t m = n; m != MA_NIL; m = MA_PARENT(pool, m))
        malloc_fix_invariant(pool, m);
    while ((parent = MA_PARENT(pool, n)) != MA_NIL &&
                MA_COLOR(pool, parent) == MA_RED)
    {
        gparent = MA_PARENT(pool, parent);
        if (parent == MA_LEFT(pool, gparent))
        {
            tmp = MA_RIGHT(pool, gparent);
            if (tmp != MA_NIL && MA_COLOR(pool, tmp) == MA_RED)
            {
                MA_COLOR(pool, tmp)     = MA_BLACK;
                MA_COLOR(pool, parent)  = MA_BLACK;
                MA_COLOR(pool, gparent) = MA_RED;
                n = gparent;
                continue;
            }
            if (MA_RIGHT(pool, parent) == n)
            {
                malloc_rotate_left(pool, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            MA_COLOR(pool, parent)  = MA_BLACK;
            MA_COLOR(pool, gparent) = MA_RED;
            malloc_rotate_right(pool, gparent);
        }
        else
        {
            tmp = MA_LEFT(pool, gparent);
            if (tmp != MA_NIL && MA_COLOR(pool, tmp) == MA_RED)
            {
                MA_COLOR(pool, tmp)     = MA_BLACK;
                MA_COLOR(pool, parent)  = MA_BLACK;
                MA_COLOR(pool, gparent) = MA_RED;
                n = gparent;
                continue;
            }
            if (MA_LEFT(pool, parent) == n)
            {
                malloc_rotate_right(pool, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            MA_COLOR(pool, parent)  = MA_BLACK;
            MA_COLOR(pool, gparent) = MA_RED;
            malloc_rotate_left(pool, gparent);
        }
    }
    MA_COLOR(pool, pool->root) = MA_BLACK;
}

static void malloc_rebalance_remove(struct malloc_pool_s *pool,
    uint32_t parent, uint32_t n)
{
    uint32_t tmp;
    while ((n == MA_NIL || MA_COLOR(pool, n) == MA_BLACK) && n != pool->root)
    {
        if (MA_LEFT(pool, parent) == n)
        {
            tmp = MA_RIGHT(pool, parent);
            if (MA_COLOR(pool, tmp) == MA_RED)
            {
                MA_COLOR(pool, tmp) = MA_BLACK;
                MA_COLOR(pool, parent) = MA_RED;
                malloc_rotate_left(pool, parent);
                tmp = MA_RIGHT(pool, parent);
            }
            if ((MA_LEFT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_LEFT(pool, tmp)) == MA_BLACK) &&
                (MA_RIGHT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_RIGHT(pool, tmp)) == MA_BLACK))
            {
                MA_COLOR(pool, tmp) = MA_RED;
                n = parent;
                parent = MA_PARENT(pool, n);
            }
            else
            {
                if (MA_RIGHT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_RIGHT(pool, tmp)) == MA_BLACK)
                {
                    uint32_t oleft;
                    if ((oleft = MA_LEFT(pool, tmp)) != MA_NIL)
                        MA_COLOR(pool, oleft) = MA_BLACK;
                    MA_COLOR(pool, tmp) = MA_RED;
                    malloc_rotate_right(pool, tmp);
                    tmp = MA_RIGHT(pool, parent);
                }
                MA_COLOR(pool, tmp) = MA_COLOR(pool, parent);
                MA_COLOR(pool, parent) = MA_BLACK;
                if (MA_RIGHT(pool, tmp))
                    MA_COLOR(pool, MA_RIGHT(pool, tmp)) = MA_BLACK;
                malloc_rotate_left(pool, parent);
                n = pool->root;
                break;
            }
        }
        else
        {
            tmp = MA_LEFT(pool, parent);
            if (MA_COLOR(pool, tmp) == MA_RED)
            {
                MA_COLOR(pool, tmp) = MA_BLACK;
                MA_COLOR(pool, parent) = MA_RED;
                malloc_rotate_right(pool, parent);
                tmp = MA_LEFT(pool, parent);
            }
            if ((MA_LEFT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_LEFT(pool, tmp)) == MA_BLACK) &&
                (MA_RIGHT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_RIGHT(pool, tmp)) == MA_BLACK))
            {
                MA_COLOR(pool, tmp) = MA_RED;
                n = parent;
                parent = MA_PARENT(pool, n);
            }
            else
            {
                if (MA_LEFT(pool, tmp) == MA_NIL ||
                    MA_COLOR(pool, MA_LEFT(pool, tmp)) == MA_BLACK)
                {
                    uint32_t oright;
                    if ((oright = MA_RIGHT(pool, tmp)) != MA_NIL)
                        MA_COLOR(pool, oright) = MA_BLACK;
                    MA_COLOR(pool, tmp) = MA_RED;
                    malloc_rotate_left(pool, tmp);
                    tmp = MA_LEFT(pool, parent);
                }
                MA_COLOR(pool, tmp) = MA_COLOR(pool, parent);
                MA_COLOR(pool, parent) = MA_BLACK;
                if (MA_LEFT(pool, tmp))
                    MA_COLOR(pool, MA_LEFT(pool, tmp)) = MA_BLACK;
                malloc_rotate_right(pool, parent);
                n = pool->root;
                break;
            }
        }
    }
    if (n != MA_NIL)
        MA_COLOR(pool, n) = MA_BLACK;
}

static uint32_t malloc_remove(struct malloc_pool_s *pool, uint32_t n)
{
    uint32_t child, parent, old = n, color;
    if (MA_LEFT(pool, n) == MA_NIL)
        child = MA_RIGHT(pool, n);
    else if (MA_RIGHT(pool, n) == MA_NIL)
        child = MA_LEFT(pool, n);
    else
    {
        uint32_t left;
        n = MA_RIGHT(pool, n);
        while ((left = MA_LEFT(pool, n)) != MA_NIL)
            n = left;
        child = MA_RIGHT(pool, n);
        parent = MA_PARENT(pool, n);
        color = MA_COLOR(pool, n);
        if (child != MA_NIL)
            MA_PARENT(pool, child) = parent;
        if (parent != MA_NIL)
        {
            if (MA_LEFT(pool, parent) == n)
                MA_LEFT(pool, parent) = child;
            else 
                MA_RIGHT(pool, parent) = child;
            malloc_fix_invariant(pool, parent);
        }
        else
            pool->root = child;
        if (MA_PARENT(pool, n) == old)
            parent = n;
        MA_PARENT(pool, n) = MA_PARENT(pool, old);
        MA_LEFT(pool, n)   = MA_LEFT(pool, old);
        MA_RIGHT(pool, n)  = MA_RIGHT(pool, old);
        MA_COLOR(pool, n)  = MA_COLOR(pool, old);
        if (MA_PARENT(pool, old) != MA_NIL)
        {
            if (MA_LEFT(pool, MA_PARENT(pool, old)) == old)
                MA_LEFT(pool, MA_PARENT(pool, old)) = n;
            else
                MA_RIGHT(pool, MA_PARENT(pool, old)) = n;
            malloc_fix_invariant(pool, MA_PARENT(pool, old));
        }
        else
            pool->root = n;
        MA_PARENT(pool, MA_LEFT(pool, old)) = n;
        if (MA_RIGHT(pool, old) != MA_NIL)
            MA_PARENT(pool, MA_RIGHT(pool, old)) = n;
        if (parent)
        {
            left = parent;
            do
            {
                malloc_fix_invariant(pool, left);
            }
            while ((left = MA_PARENT(pool, left)) != MA_NIL);
        }
        goto color;
    }
    parent = MA_PARENT(pool, n);
    color = MA_COLOR(pool, n);
    if (child != MA_NIL)
        MA_PARENT(pool, child) = parent;
    if (parent)
    {
        if (MA_LEFT(pool, parent) == n)
            MA_LEFT(pool, parent) = child;
        else
            MA_RIGHT(pool, parent) = child;
        n = parent;
        do
        {
            malloc_fix_invariant(pool, n);
        }
        while ((n = MA_PARENT(pool, n)) != MA_NIL);
    }
    else
        pool->root = child;
color:
    if (color == MA_BLACK)
        malloc_rebalance_remove(pool, parent, child);
    return old;
}

static bool malloc_mem_grow(struct malloc_pool_s *pool, uint32_t hi)
{
    if (hi <= pool->mmap)
        return true;
    uint8_t *base = pool->base + (size_t)pool->mmap * MA_UNIT;
    size_t extension = (size_t)(hi - pool->mmap) * MA_UNIT;
    extension -= extension % MA_PAGE_SIZE;
    extension += 4 * MA_PAGE_SIZE;          // Extra padding
    uint8_t *ptr = (uint8_t *)mmap(base, extension, PROT_READ | PROT_WRITE,
        pool->flags | MAP_FIXED, -1, 0);
    if (ptr != base)
    {
        (void)munmap(ptr, extension);
        errno = ENOMEM;
        return false;
    }
    pool->mmap += extension / MA_UNIT;
    return true;
}

static uint32_t malloc_mem_alloc(struct malloc_pool_s *pool, uint32_t size,
    uint32_t lb, uint32_t ub)
{
    if (ub - lb < size)
    {
        errno = ENOMEM;
        return MA_NIL;
    }
    uint32_t lo = lb;
    uint32_t hi = lo + size;
    if (!malloc_mem_grow(pool, hi))
        return MA_NIL;
    return lo;
}

static bool malloc_mem_realloc(struct malloc_pool_s *pool, uint32_t base,
    uint32_t size)
{
    uint32_t hi = base + size;
    return malloc_mem_grow(pool, hi);
}

static void *malloc_impl(struct malloc_pool_s *pool, size_t size, bool lock)
{
    if (size == 0)
        return MA_ZERO;
    size += sizeof(struct malloc_node_s);
    size_t size128 = size / MA_UNIT + (size % MA_UNIT? 1: 0);
    if (size128 > UINT32_MAX)
    {
        errno = ENOMEM;
        return NULL;
    }

    pool = pool_init(pool);
    if (lock && mutex_lock(&pool->mutex) < 0)
        return NULL;

    uint32_t n = pool->root, parent = MA_NIL;
    uint32_t lb = MA_POOL_LB(pool), ub = MA_POOL_UB(pool);
    bool left = false;
    while (true)
    {
        if (n == MA_NIL)
            break;
        uint32_t l = MA_LEFT(pool, n), r = MA_RIGHT(pool, n);
        if (size128 <= MA_GAP(pool, n))
        {
            // Inner
            uint32_t lgap = (l != MA_NIL?
                MA_MAX(MA_GAP(pool, l), n - MA_UB(pool, l)): 0);
            if (size128 <= lgap)
            {
                ub = n;
                parent = n;
                n = l;
                left = true;
            }
            else
            {
                lb = n + MA_SIZE(pool, n);
                parent = n;
                n = r;
                left = false;
            }
            continue;
        }
        else
        {
            // Outer
            if (size128 <= MA_MAX(lb, MA_LB(pool, n)) - lb)
            {
                ub = MA_LB(pool, n);
                parent = n;
                n = l;
                left = true;
                continue;
            }
            if (size128 <= ub - MA_MIN(ub, MA_UB(pool, n)))
            {
                lb = MA_UB(pool, n);
                parent = n;
                n = r;
                left = false;
                continue;
            }
            if (lock) mutex_unlock(&pool->mutex);
            errno = ENOMEM;
            return NULL;
        }
    }

    uint32_t i = malloc_mem_alloc(pool, (uint32_t)size128, lb, ub);
    if (i == MA_NIL)
    {
        if (lock) mutex_unlock(&pool->mutex);
        return NULL;
    }
    struct malloc_node_s *node = MA_NODE(pool, i);
    node->parent = parent;
    node->size   = size128;
    node->lb     = i;
    node->ub     = i + size128;
    node->left   = node->right = MA_NIL;
    node->gap    = 0;
    node->magic  = MA_MAGIC_NUMBER;
    if (parent == MA_NIL)
    {
        node->color = MA_BLACK;
        pool->root = i;
    }
    else
    {
        node->color = MA_RED;
        if (left)
            MA_LEFT(pool, parent) = i;
        else
            MA_RIGHT(pool, parent) = i;
        malloc_rebalance_insert(pool, i);
    }
    if (lock) mutex_unlock(&pool->mutex);
    void *ptr = (void *)(pool->base + (size_t)i * MA_UNIT +
        sizeof(struct malloc_node_s));
    return ptr;
}

static void free_impl(struct malloc_pool_s *pool, void *ptr, bool lock)
{
    if (ptr == NULL || ptr == MA_ZERO)
        return;

    pool = pool_init(pool);
    if ((uint8_t *)ptr < pool->base ||
            (uint8_t *)ptr >= pool->base + MA_UNIT * (size_t)pool->end)
        panic("bad free() detected");
    if ((uintptr_t)ptr % MA_UNIT != 0)
        panic("bad free() detected");
    off_t diff = (uint8_t *)ptr - pool->base - sizeof(struct malloc_node_s);
    uint32_t i = (uint32_t)(diff / MA_UNIT);

    if (lock && mutex_lock(&pool->mutex) < 0)
        panic("failed to acquire malloc() lock");

    uint32_t n = pool->root;
    while (true)
    {
        if (n == MA_NIL)
            panic("bad free() detected");
        if (n == i)
        {
            if (MA_MAGIC(pool, n) != MA_MAGIC_NUMBER)
                panic("bad free() detected");
            malloc_remove(pool, n);
            if (lock) mutex_unlock(&pool->mutex);
            return;
        }
        n = (i < n? MA_LEFT(pool, n): MA_RIGHT(pool, n));
    }
}

static void *calloc_impl(struct malloc_pool_s *pool, size_t nmemb,
    size_t size, bool lock)
{
    void *ptr = malloc_impl(pool, nmemb * size, lock);
    if (ptr == NULL || ptr == MA_ZERO)
        return ptr;
    memset(ptr, 0, nmemb * size);
    return ptr;
}

static void *realloc_impl(struct malloc_pool_s *pool, void *ptr, size_t size,
    bool lock)
{
    if (ptr == NULL || ptr == MA_ZERO)
        return malloc_impl(pool, size, lock);

    pool = pool_init(pool);
    if ((uint8_t *)ptr < pool->base ||
            (uint8_t *)ptr >= pool->base + MA_UNIT * (size_t)pool->end)
        panic("bad realloc() detected");
    if ((uintptr_t)ptr % MA_UNIT != 0)
        panic("bad realloc() detected");
    if (size == 0)
    {
        free_impl(pool, ptr, lock);
        return MA_ZERO;
    }
    off_t diff = (uint8_t *)ptr - pool->base - sizeof(struct malloc_node_s);
    uint32_t i = (uint32_t)(diff / MA_UNIT);
 
    size += sizeof(struct malloc_node_s);
    size_t size128 = size / MA_UNIT + (size % MA_UNIT? 1: 0);
    if (size128 > UINT32_MAX)
    {
        errno = ENOMEM;
        return NULL;
    }

    if (lock && mutex_lock(&pool->mutex) < 0)
        return NULL;
    uint32_t n = pool->root, ub = UINT32_MAX;
    bool left = false;
    while (true)
    {
        if (n == MA_NIL)
            panic("bad realloc() detected");
        if (n == i)
            break;
        left = (i < n);
        if (left)
            ub = n;
        n = (left? MA_LEFT(pool, n): MA_RIGHT(pool, n));
    }
    if (MA_MAGIC(pool, n) != MA_MAGIC_NUMBER)
        panic("bad realloc() detected");
    uint32_t r = MA_RIGHT(pool, n);
    ub = (r != MA_NIL? MA_LB(pool, r): ub);

    if (n + size128 <= ub)
    {
        // In-place realloc:
        if (MA_SIZE(pool, n) == size128)
        {
            if (lock) mutex_unlock(&pool->mutex);
            return ptr;
        }
        if (!malloc_mem_realloc(pool, n, size128))
        {
            if (lock) mutex_unlock(&pool->mutex);
            return NULL;
        }
        MA_SIZE(pool, n) = size128;
        for (; n != MA_NIL; n = MA_PARENT(pool, n))
            malloc_fix_invariant(pool, n);
        if (lock) mutex_unlock(&pool->mutex);
        return ptr;
    }
    size_t copy_size = MA_SIZE(pool, n) * MA_UNIT;
    if (lock) mutex_unlock(&pool->mutex);

    void *new_ptr = malloc_impl(pool, size, lock);
    if (new_ptr == NULL)
        return new_ptr;
    memcpy(new_ptr, ptr, copy_size);
    
    if (lock && mutex_lock(&pool->mutex) < 0)
        return NULL;
    malloc_remove(pool, n);
    if (lock) mutex_unlock(&pool->mutex);
    return new_ptr;
}

static void *malloc(size_t size)
{
    return malloc_impl(NULL, size, /*lock=*/true);
}
static void *calloc(size_t nmemb, size_t size)
{
    return calloc_impl(NULL, nmemb, size, /*lock=*/true);
}
static void *realloc(void *ptr, size_t size)
{
    return realloc_impl(NULL, ptr, size, /*lock=*/true);
}
static void free(void *ptr)
{
    free_impl(NULL, ptr, /*lock=*/true);
}

static void *malloc_unlocked(size_t size)
{
    return malloc_impl(NULL, size, /*lock=*/false);
}
static void *calloc_unlocked(size_t nmemb, size_t size)
{
    return calloc_impl(NULL, nmemb, size, /*lock=*/false);
}
static void *realloc_unlocked(void *ptr, size_t size)
{
    return realloc_impl(NULL, ptr, size, /*lock=*/false);
}
static void free_unlocked(void *ptr)
{
    free_impl(NULL, ptr, /*lock=*/false);
}

static void *pool_malloc(struct malloc_pool_s *pool, size_t size)
{
    return malloc_impl(pool, size, /*lock=*/true);
}
static void *pool_calloc(struct malloc_pool_s *pool, size_t nmemb, size_t size)
{
    return calloc_impl(pool, nmemb, size, /*lock=*/true);
}
static void *pool_realloc(struct malloc_pool_s *pool, void *ptr, size_t size)
{
    return realloc_impl(pool, ptr, size, /*lock=*/true);
}
static void pool_free(struct malloc_pool_s *pool, void *ptr)
{
    free_impl(pool, ptr, /*lock=*/true);
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
        kact.sa_handler_2 = (void *)act->sa_handler;
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
        oldact->sa_handler = (void (*)(int))koldact.sa_handler_2;
        memcpy(&oldact->sa_mask, &koldact.sa_mask, sizeof(oldact->sa_mask));
        oldact->sa_flags = (koldact.sa_flags & ~SA_RESTORER);
        oldact->sa_restorer = NULL;
    }
    return result;
}

static void (*signal(int signum, void (*handler)(int)))(int)
{
    struct sigaction action, old_action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    action.sa_flags |= SA_RESTART;
    if (sigaction(signum, &action, &old_action) < 0)
        return SIG_ERR;
    return old_action.sa_handler;
}

static int raise(int sig)
{
    return kill(gettid(), sig);
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

static int isupper(int c)
{
    return (c >= 'A' && c <= 'Z');
}

static int isprint(int c)
{
    return (c >= ' ' && c < INT8_MAX);
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

static int isodigit(int c)
{
    return (c >= '0' && c <= '7');
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

static void *memset(void *dst, int c, size_t n)
{
    uint8_t *dst8 = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++)
        dst8[i] = (uint8_t)c;
    return dst;
}

static void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *dst8 = (uint8_t *)dst;
    const uint8_t *src8 = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++)
        dst8[i] = src8[i];
    return dst;
}

static void *memmove(void *dst, const void *src, size_t n)
{
    uint8_t *dst8 = (uint8_t *)dst;
    const uint8_t *src8 = (const uint8_t *)src;
    if (dst8 < src8)
        memcpy(dst, src, n);
    else
    {
        for (ssize_t i = (ssize_t)n-1; i >= 0; i--)
            dst8[i] = src8[i];
    }
    return dst;
}

static int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *a8 = (const uint8_t *)a;
    const uint8_t *b8 = (const uint8_t *)b;
    for (size_t i = 0; i < n; i++)
    {
        int cmp = (int)a8[i] - (int)b8[i];
        if (cmp != 0)
            return cmp;
    }
    return 0;
}


static void *memchr(const void *a, int c, size_t n)
{
    const uint8_t *a8 = (const uint8_t *)a;
    for (size_t i = 0; i < n; i++)
    {
        if ((int)a8[i] == c)
            return (void *)(a8 + i);
    }
    return NULL;
}

static size_t strlen(const char *s)
{
    size_t n = 0;
    for (size_t i = 0; s[i] != '\0'; i++)
        n++;
    return n;
}

static size_t strnlen(const char *s, size_t n)
{
    size_t m = 0;
    for (size_t i = 0; m < n && s[i] != '\0'; i++)
        m++;
    return m;
}

static int strncmp(const char *s1, const char *s2, size_t n)
{
    for (; n > 0; n--)
    {
        int cmp = (int)*s1 - (int)*s2;
        if (cmp != 0)
            return cmp;
        if (*s1 == '\0')
            return 0;
        s1++; s2++;
    }
    return 0;
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

static char *strchr(const char *src, int c0)
{
    char c = (char)c0;
    for (size_t i = 0; src[i] != '\0'; i++)
        if (src[i] == c)
            return (char *)(src + i);
    return NULL;
}

static char *strdup(const char *src)
{
    if (src == NULL)
        return NULL;
    size_t len = strlen(src);
    char *dst = (char *)malloc(len+1);
    if (dst == NULL)
        return NULL;
    memcpy(dst, src, len+1);
    return dst;
}

static const char *strerror(int errnum)
{
    switch (errnum)
    {
        case 0: return "Success";
        case E2BIG: return "Argument list too long";
        case EACCES: return "Permission denied";
        case EAGAIN: return "Resource temporarily unavailable";
        case EBADF: return "Bad file descriptor";
        case EBADMSG: return "Bad message";
        case EBUSY: return "Device or resource busy";
        case ECANCELED: return "Operation canceled";
        case ECHILD: return "No child processes";
        case EDEADLK: return "Resource deadlock avoided";
        case EDOM: return "Mathematics argument out of domain of function";
        case EEXIST: return "File exists";
        case EFAULT: return "Bad address";
        case EFBIG: return "File too large";
        case EINPROGRESS: return "Operation in progress";
        case EINTR: return "Interrupted function call";
        case EINVAL: return "Invalid argument";
        case EIO: return "Input/output error";
        case EISDIR: return "Is a directory";
        case EMFILE: return "Too many open files";
        case EMLINK: return "Too many links";
        case EMSGSIZE: return "Message too long";
        case ENAMETOOLONG: return "Filename too long";
        case ENFILE: return "Too many open files in system";
        case ENODEV: return "No such device";
        case ENOENT: return "No such file or directory";
        case ENOEXEC: return "Exec format error";
        case ENOLCK: return "No locks available";
        case ENOMEM: return "Not enough space";
        case ENOSPC: return "No space left on device";
        case ENOSYS: return "Function not implemented";
        case ENOTDIR: return "Not a directory";
        case ENOTEMPTY: return "Directory not empty";
        case ENOTSUP: return "Operation not supported";
        case ENOTTY: return "Inappropriate I/O control operation";
        case ENXIO: return "No such device or address";
        case EPERM: return "Operation not permitted";
        case EPIPE: return "Broken pipe";
        case ERANGE: return "Numerical result out of range";
        case EROFS: return "Read-only filesystem";
        case ESPIPE: return "Invalid seek";
        case ESRCH: return "No such process";
        case ETIMEDOUT: return "Connection timed out";
        case EXDEV: return "Improper link";
        case EOWNERDEAD: return "Owner died";
        default: return "Unknown error code";
    }
}

static const char *strsignal(int sig)
{
    switch (sig)
    {
        case SIGHUP: return "Hangup";
        case SIGINT: return "Interrupt";
        case SIGQUIT: return "Quit";
        case SIGILL: return "Illegal instruction";
        case SIGABRT: return "Aborted";
        case SIGFPE: return "Floating point exception";
        case SIGKILL: return "Killed";
        case SIGSEGV: return "Segmentation fault";
        case SIGPIPE: return "Broken pipe";
        case SIGALRM: return "Alarm clock";
        case SIGTERM: return "Terminated";
        case SIGUSR1: return "User defined signal 1";
        case SIGUSR2: return "User defined signal 2";
        case SIGCHLD: return "Child exited";
        case SIGCONT: return "Continued";
        case SIGSTOP: return "Stopped (signal)";
        case SIGBUS: return "Bus error";
        case SIGPOLL: return "I/O possible";
        case SIGSYS: return "Bad system call";
        case SIGTRAP: return "Trace/breakpoint trap";
        case SIGURG: return "Urgent I/O condition";
        default: return "Unknown signal";
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
        d = 10 + (c - 'A');
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
    char *startptr = (char *)nptr;
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
            switch (base)
            {
                case 16:
                    nptr++;
                    if (*nptr == 'x' || *nptr == 'X')
                        nptr++;
                    break;
                case 8:
                    nptr++;
                    break;
                case 0:
                    nptr++;
                    if (*nptr == 'x' || *nptr == 'X')
                    {
                        nptr++;
                        base = 16;
                    }
                    else if (atoi_digit(*nptr, 8) >= 0)
                        base = 8;
                    else
                    {
                        *endptr = (char *)nptr;
                        return 0;
                    }
                    break;
            }
            break;
        case '\0':
            *endptr = startptr;
            return 0;
        default:
            base = (base == 0? 10: base);
            if (atoi_digit(*nptr, base) < 0)
            {
                *endptr = (char *)startptr;
                return 0;
            }
            break;
    }
        
    __int128 x = 0;
    unsigned i;
    int d;
    for (i = 0; (d = atoi_digit(*nptr, base)) >= 0; i++)
    {
        nptr++;
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

#define EOF                         (-1)

#define _IOFBF                      0
#define _IOLBF                      1
#define _IONBF                      2

#define BUFSIZ                      8192

#define SEEK_SET                    0
#define SEEK_CUR                    1
#define SEEK_END                    2

#define STDIO_FLAG_INITED           0x0001
#define STDIO_FLAG_READ             0x0002
#define STDIO_FLAG_WRITE            0x0004
#define STDIO_FLAG_READING          0x0008
#define STDIO_FLAG_WRITING          0x0010
#define STDIO_FLAG_NO_BUF           0x0020
#define STDIO_FLAG_OWN_BUF          0x0040
#define STDIO_FLAG_EOF              0x0080
#define STDIO_FLAG_ERROR            0x0100

struct stdio_stream_s
{
    mutex_t mutex;
    unsigned flags;
    int fd;
    int eol;
    int unget;
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
    FILE *stream = (FILE *)malloc(sizeof(struct stdio_stream_s));
    if (stream == NULL)
        return NULL;
    memset(stream, 0, sizeof(*stream));
    stream->flags  = (r? STDIO_FLAG_READ: 0) |
                     (w? STDIO_FLAG_WRITE: 0) |
                     (mode == _IONBF? STDIO_FLAG_NO_BUF: 0);
    stream->eol    = (mode == _IOLBF? '\n': EOF);
    stream->unget  = EOF;
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
        stream->buf = (char *)malloc(stream->bufsiz);
        if (stream->buf == NULL)
            return EOF;
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
        return -1;
    }
    if (size < 0)
    {
        stream->flags |= STDIO_FLAG_ERROR;
        return -1;
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
    {
        if (stdio_stream_write(stream) != 0)
            return EOF;
    }
    else if (stream->flags & STDIO_FLAG_READING)
    {
        stream->unget = EOF;
        off_t offset = stream->read_ptr - stream->read_end;
        stream->read_ptr = stream->buf;
        stream->read_end = stream->buf;
        if (offset < 0 && lseek(stream->fd, offset, SEEK_CUR) < 0)
        {
            stream->flags |= STDIO_FLAG_ERROR;
            return EOF;
        }
    }
    stream->flags &= ~(STDIO_FLAG_READING | STDIO_FLAG_WRITING);
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
        fflush_unlocked(stream);
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
        fflush_unlocked(stream);
    stream->flags |= STDIO_FLAG_WRITING;
    if (!(stream->flags & STDIO_FLAG_INITED) &&
            stdio_stream_buf_init(stream) < 0)
        return EOF;
    if (stream->write_ptr >= stream->write_end &&
            stdio_stream_write(stream) < 0)
        return EOF;
    return 0;
}

static void stdio_stream_free(FILE *stream)
{
    if (stream->buf != NULL && (stream->flags & STDIO_FLAG_OWN_BUF))
        free(stream->buf);
    free(stream);
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
            flags = (plus != '+'? O_WRONLY | O_CREAT | O_TRUNC:
                                  O_RDWR | O_CREAT | O_TRUNC);
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
    stdio_stream_free(stream);
    return (result1 == 0? result2: result1);
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
    stream->flags &= ~(STDIO_FLAG_EOF | STDIO_FLAG_ERROR);
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
    switch (mode)
    {
        case _IONBF:
            if (buf != NULL)
                goto invalid;
            break;
        case _IOFBF: case _IOLBF:
            break;
        default: invalid:
            errno = EINVAL;
            return -1;
    }

    void *oldbuf = NULL;
    stdio_lock(stream, -1);
    fflush_unlocked(stream);

    if (stream->buf != NULL && (stream->flags & STDIO_FLAG_OWN_BUF))
        oldbuf = stream->buf;
    stream->flags &=
        ~(STDIO_FLAG_INITED | STDIO_FLAG_OWN_BUF | STDIO_FLAG_NO_BUF);
    stream->buf    = buf;
    stream->bufsiz = (buf == NULL? BUFSIZ: size);
    stream->eol    = (mode == _IOLBF? '\n': EOF);
    stream->flags |= (mode == _IONBF? STDIO_FLAG_NO_BUF: 0x0);

    stdio_unlock(stream);
    free(oldbuf);
    return 0;
}

static mutex_t stdio_mutex = MUTEX_INITIALIZER;
static FILE *stdio_stream[3] = {NULL};
#define stdin   stdio_get_stream(STDIN_FILENO)
#define stdout  stdio_get_stream(STDOUT_FILENO)
#define stderr  stdio_get_stream(STDERR_FILENO)

static __attribute__((__noinline__, __const__)) FILE *stdio_get_stream(int fd)
{
    if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
        return NULL;

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
    if (stream->unget != EOF)
    {
        int c = stream->unget;
        stream->unget = EOF;
        return c;
    }
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
            if (feof_unlocked(stream))
                break;
            if (ferror_unlocked(stream))
                return EOF;
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

static int ungetc_unlocked(int c, FILE *stream)
{
    if (stream->unget != EOF ||
        stdio_stream_read_init(stream) < 0)
    {
        errno = EINVAL;
        return EOF;
    }
    stream->unget = c;
    stream->flags &= ~STDIO_FLAG_EOF;
    return c;
}

static int ungetc(int c, FILE *stream)
{
    stdio_lock(stream, EOF);
    c = ungetc_unlocked(c, stream);
    stdio_unlock(stream);
    return c;
}

static size_t fread_unlocked(void *ptr, size_t size, size_t nmemb,
        FILE *stream)
{
    if (stdio_stream_read_init(stream) < 0)
        return 0;
    size_t total = size * nmemb;
    if (total == 0)
        return 0;
    char *ptr8 = (char *)ptr;
    bool unget = (stream->unget != EOF);
    if (unget)
    {
        ptr8[0] = (char)stream->unget;
        stream->unget = EOF;
    }
    if (stream->read_ptr == NULL)
    {
        ssize_t result = stdio_stream_read_buf(stream, ptr8 + unget,
            ptr8 + total - unget);
        result = (result < 0? (ssize_t)unget: result);
        return ((size_t)result == total? nmemb: (size_t)result / size);
    }
    size_t i;
    for (i = unget; i < total; i++)
    {
        int c;
        if (stream->read_ptr < stream->read_end)
            c = (int)*stream->read_ptr++;
        else
        {
            c = fgetc_unlocked(stream);
            if (feof_unlocked(stream) || ferror_unlocked(stream))
                break;
        }
        ptr8[i] = (char)c;
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
    {
        offset = -(stream->read_end - stream->read_ptr);
        offset -= (stream->unget != EOF? 1: 0);
    }
    else if (stream->flags & STDIO_FLAG_WRITING)
        offset = stream->write_ptr - stream->buf;
    result = lseek(stream->fd, 0, SEEK_CUR);
    if (result >= 0)
        result += offset;
    stdio_unlock(stream);
    return result;
}

/****************************************************************************/
/* PRINTF                                                                   */
/****************************************************************************/

#define PRINTF_FLAG_NEG         0x0001
#define PRINTF_FLAG_UPPER       0x0002
#define PRINTF_FLAG_OCTAL       0x0004
#define PRINTF_FLAG_HEX         0x0008
#define PRINTF_FLAG_PLUS        0x0010
#define PRINTF_FLAG_HASH        0x0020
#define PRINTF_FLAG_SPACE       0x0040
#define PRINTF_FLAG_RIGHT       0x0080
#define PRINTF_FLAG_ZERO        0x0100
#define PRINTF_FLAG_PRECISION   0x0200
#define PRINTF_FLAG_8           0x0400
#define PRINTF_FLAG_16          0x0800
#define PRINTF_FLAG_64          0x1000

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
    bool seen = false;
    if (flags & (PRINTF_FLAG_HEX | PRINTF_FLAG_OCTAL))
    {
        if (flags & PRINTF_FLAG_HASH)
        {
            prefix[0] = '0';
            if (flags & PRINTF_FLAG_HEX)
                prefix[1] = (flags & PRINTF_FLAG_UPPER? 'X': 'x');
        }
        const char digs[] = "0123456789abcdef";
        const char DIGS[] = "0123456789ABCDEF";
        const char *ds = (flags & PRINTF_FLAG_UPPER? DIGS: digs);
        int shift = (flags & PRINTF_FLAG_HEX? 60: 63),
              dec = (flags & PRINTF_FLAG_HEX? 4: 3),
             mask = (flags & PRINTF_FLAG_HEX? 0xF: 0x7);
        while (shift >= 0)
        {
            char c = ds[(x >> shift) & mask];
            shift -= dec;
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
            case 'o':
                flags |= PRINTF_FLAG_OCTAL;
                goto uint;
            case 'X':
                flags |= PRINTF_FLAG_UPPER;
                // Fallthrough
            case 'x':
                flags |= PRINTF_FLAG_HEX;
                // Fallthrough
            case 'u': uint:
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

static int vasprintf(char **strp, const char *format, va_list ap)
{
    *strp = NULL;
    va_list aq;
    va_copy(aq, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result >= 0)
    {
        char *buf = (char *)malloc(result+1);
        result = (buf == NULL? -1: result);
        if (result >= 0)
            result = vsnprintf(buf, result+1, format, aq);
        else
            free(buf);
        *strp = (result >= 0? buf: NULL);
    }
    va_end(aq);
    return result;
}

static int snprintf(char *str, size_t len, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vsnprintf(str, len, format, ap);
    va_end(ap);
    return result;
}

static int asprintf(char **strp, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vasprintf(strp, format, ap);
    va_end(ap);
    return result;
}

static int vfprintf(FILE *stream, const char *format, va_list ap)
{
    va_list aq;
    va_copy(aq, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result >= 0)
    {
        char buf[result+1];
        result = vsnprintf(buf, result+1, format, aq);
        if (result >= 0)
        {
            if (fputs(buf, stream))
                result = -1;
        }
    }
    va_end(aq);
    return result;
}

static int vfprintf_unlocked(FILE *stream, const char *format, va_list ap)
{
    va_list aq;
    va_copy(aq, ap);
    int result = vsnprintf(NULL, SIZE_MAX, format, ap);
    if (result >= 0)
    {
        char buf[result+1];
        result = vsnprintf(buf, result+1, format, aq);
        if (result >= 0)
        {
            if (fputs_unlocked(buf, stream))
                result = -1;
        }
    }
    va_end(aq);
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

static void perror(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
}

/****************************************************************************/
/* SCANF                                                                    */
/****************************************************************************/

#define SCANF_FLAG_NEG      0x0001
#define SCANF_FLAG_DEC      0x0002
#define SCANF_FLAG_OCT      0x0004
#define SCANF_FLAG_HEX      0x0008
#define SCANF_FLAG_8        0x0010
#define SCANF_FLAG_16       0x0020
#define SCANF_FLAG_64       0x0040
#define SCANF_FLAG_SIGNED   0x0080

struct scanf_stream_s
{
    FILE *stream;
    const char *str;
    ssize_t pos;
};

static __attribute__((__noinline__)) char scanf_get_char(
    struct scanf_stream_s *in)
{
    char c = EOF;
    if (in->stream != NULL)
        c = fgetc_unlocked(in->stream);
    else
    {
        if (in->pos < 0 || in->str[in->pos] == '\0')
            in->pos = -1;
        else
            c = in->str[in->pos++];
    }
    return c;
}

static __attribute__((__noinline__)) void scanf_unget_char(char c,
    struct scanf_stream_s *in)
{
    if (c == EOF)
        return;
    if (in->stream != NULL)
        ungetc_unlocked(c, in->stream);
    else
    {
        if (in->pos <= 0)
            in->pos = -1;
        else
            in->pos--;
    }
}

static __attribute__((__noinline__)) char scanf_get_char_n(
    struct scanf_stream_s *in, size_t *width)
{
    if (*width == 0)
        return EOF;
    *width -= 1;
    return scanf_get_char(in);
}

static __attribute__((__noinline__)) void scanf_unget_char_n(char c,
    struct scanf_stream_s *in, size_t *width)
{
    if (c == EOF)
        return;
    *width += 1;
    scanf_unget_char(c, in);
}

static __attribute__((__noinline__)) bool scanf_get_dec(
    struct scanf_stream_s *in, size_t *width, uint64_t *p, bool *r)
{
    char c = scanf_get_char_n(in, width);
    if (!isdigit(c))
    {
        scanf_unget_char_n(c, in, width);
        return false;
    }
    uint64_t i = 0;
    do
    {
        i *= 10;
        uint64_t d = (c - '0');
        if (UINT64_MAX - i < d)
            *r = true;
        i = (UINT64_MAX - i < d? UINT64_MAX: i + d);
    }
    while (isdigit(c = scanf_get_char_n(in, width)));
    scanf_unget_char_n(c, in, width);
    *p = i;
    return true;
}

static __attribute__((__noinline__)) bool scanf_get_oct(
    struct scanf_stream_s *in, size_t *width, uint64_t *p, bool *r)
{
    char c = scanf_get_char_n(in, width);
    if (!isodigit(c))
    {
        scanf_unget_char_n(c, in, width);
        return false;
    }
    uint64_t i = 0;
    do
    {
        i *= 8;
        uint64_t d = (c - '0');
        if (UINT64_MAX - i < d)
            *r = true;
        i = (UINT64_MAX - i < d? UINT64_MAX: i + d);
    }
    while (isodigit(c = scanf_get_char_n(in, width)));
    scanf_unget_char_n(c, in, width);
    *p = i;
    return true;
}

static __attribute__((__noinline__)) bool scanf_get_hex(
    struct scanf_stream_s *in, size_t *width, uint64_t *p, bool *r)
{
    char c = scanf_get_char_n(in, width);
    if (!isxdigit(c))
    {
        scanf_unget_char_n(c, in, width);
        return false;
    }
    uint64_t i = 0;
    do
    {
        i *= 16;
        uint64_t d = (c >= '0' && c <= '9'? c - '0':
                      c >= 'a' && c <= 'f'? 10 + c - 'a':
                      c >= 'A' && c <= 'F'? 10 + c - 'A': 0);
        if (UINT64_MAX - i < d)
            *r = true;
        i = (UINT64_MAX - i < d? UINT64_MAX: i + d);
    }
    while (isxdigit(c = scanf_get_char_n(in, width)));
    scanf_unget_char_n(c, in, width);
    *p = i;
    return true;
}

static __attribute__((__noinline__)) bool scanf_get_num(
    struct scanf_stream_s *in, size_t width, unsigned flags, void *ptr)
{
    size_t size = (flags & SCANF_FLAG_8?  sizeof(uint8_t):
                   flags & SCANF_FLAG_16? sizeof(uint16_t):
                   flags & SCANF_FLAG_64? sizeof(uint64_t): sizeof(uint32_t));
    memset(ptr, 0, size);
    char c;
    while (isspace(c = scanf_get_char(in)))
        ;
    width--;
    bool neg = (c == '-');
    if (neg || c == '+')
        c = scanf_get_char_n(in, &width);
    uint64_t i = 0;
    bool overflow = false;
    if (c == '0' && (flags & (SCANF_FLAG_OCT | SCANF_FLAG_HEX)))
    {
        c = scanf_get_char_n(in, &width);
        if ((flags & SCANF_FLAG_HEX) && (c == 'x' || c == 'X'))
        {
            if (!scanf_get_hex(in, &width, &i, &overflow))
                return false;
        }
        else if (flags & SCANF_FLAG_OCT)
        {
            scanf_unget_char_n(c, in, &width);
            if (!scanf_get_oct(in, &width, &i, &overflow))
                return false;
        }
        else
            scanf_unget_char_n(c, in, &width);
    }
    else if (flags & SCANF_FLAG_DEC)
    {
        scanf_unget_char_n(c, in, &width);
        if (!scanf_get_dec(in, &width, &i, &overflow))
            return false;
    }
    else
    {
        scanf_unget_char_n(c, in, &width);
        return false;
    }
    if (neg)
    {
        if (i > (uint64_t)INT64_MAX+1)
        {
            overflow = true;
            i = (uint64_t)INT64_MIN;
        }
        else
            i = -i;
    }
    if (flags & SCANF_FLAG_SIGNED)
    {
        int64_t j = (int64_t)i;
        int64_t lb = (flags & SCANF_FLAG_8?  INT8_MIN:
                      flags & SCANF_FLAG_16? INT16_MIN:
                      flags & SCANF_FLAG_64? INT64_MIN: INT32_MIN);
        if (j < lb)
        {
            overflow = true;
            j = lb;
        }
        int64_t ub = (flags & SCANF_FLAG_8?  INT8_MAX:
                      flags & SCANF_FLAG_16? INT16_MAX:
                      flags & SCANF_FLAG_64? INT64_MAX: INT32_MAX);
        if (j > ub)
        {
            overflow = true;
            j = ub;
        }
        i = (uint64_t)j;
    }
    else
    {
        uint64_t ub = (flags & SCANF_FLAG_8?  UINT8_MAX:
                       flags & SCANF_FLAG_16? UINT16_MAX:
                       flags & SCANF_FLAG_64? UINT64_MAX: UINT32_MAX);
        if (i > ub)
        {
            overflow = true;
            i = ub;
        }
    }
    memcpy(ptr, &i, size);
    if (overflow)
        errno = ERANGE;
    return true;
}

static int scanf_impl(struct scanf_stream_s *in, const char *format, va_list ap)
{
    int num = 0;
    char c;
    for (; *format != '\0'; format++)
    {
        if (isspace(*format))
        {
            while (isspace(c = scanf_get_char(in)))
                ;
            scanf_unget_char(c, in);
            while (isspace(format[1]))
                format++;
            continue;
        }
        switch (*format)
        {
            case '%':
                format++;
                if (*format != '%')
                    break;
                // Fallthrough:
            default:
                c = scanf_get_char(in);
                if (c != *format)
                {
                    scanf_unget_char(c, in);
                    return num;
                }
                continue;
        }
        
        size_t width = 0;
        for (; isdigit(*format); format++)
        {
            width *= 10;
            width += (unsigned)(*format - '0');
            width = (width > INT32_MAX? INT32_MAX: width);
        }
        width = (width == 0? INT32_MAX: width);

        unsigned flags = 0x0;
        switch (*format)
        {
            case 'l':
                flags |= SCANF_FLAG_64;
                format++;
                if (*format == 'l')
                    format++;
                break;
            case 'h':
                format++;
                if (*format == 'h')
                {
                    format++;
                    flags |= SCANF_FLAG_8;
                }
                else
                    flags |= SCANF_FLAG_16;
                break;
            case 'z': case 'j': case 't':
                format++;
                flags |= SCANF_FLAG_64;
                break;
        }

        void *ptr = (void *)va_arg(ap, void *);
        char *ptr8 = (char *)ptr;
        switch (*format)
        {
            case 'c':
                width = (width == INT32_MAX? 1: 0);
                while ((c = scanf_get_char_n(in, &width)) != EOF)
                    *ptr8++ = c;
                if (width != 0)
                    return num;
                break;
            case 's':
                while (isspace(c = scanf_get_char_n(in, &width)))
                    ;
                *ptr8++ = c;
                while ((c = scanf_get_char_n(in, &width)) != EOF &&
                        !isspace(c))
                    *ptr8++ = c;
                scanf_unget_char_n(c, in, &width);
                *ptr8++ = '\0';
                break;
            case 'd':
                flags |= SCANF_FLAG_DEC | SCANF_FLAG_SIGNED;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            case 'u':
                flags |= SCANF_FLAG_DEC;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            case 'o':
                flags |= SCANF_FLAG_OCT;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            case 'x': case 'X':
                flags |= SCANF_FLAG_HEX;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            case 'i':
                flags |= SCANF_FLAG_DEC | SCANF_FLAG_OCT | SCANF_FLAG_HEX |
                    SCANF_FLAG_SIGNED;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            case 'p':
                flags |= SCANF_FLAG_HEX | SCANF_FLAG_64;
                if (!scanf_get_num(in, width, flags, ptr))
                    return num;
                break;
            default:
                return num;
        }
        num++;
    }
    return num;
}

static int vsscanf(const char *str, const char *format, va_list ap)
{
    if (str == NULL)
    {
        errno = EINVAL;
        return EOF;
    }
    struct scanf_stream_s in = {0};
    in.stream = NULL;
    in.str = str;
    in.pos = 0;
    return scanf_impl(&in, format, ap);
}

static int vfscanf_unlocked(FILE *stream, const char *format, va_list ap)
{
    if (stream == NULL)
    {
        errno = EINVAL;
        return EOF;
    }
    struct scanf_stream_s in;
    in.stream = stream;
    int result = scanf_impl(&in, format, ap);
    if (result == 0 && ferror(stream))
        result = EOF;
    return result;
}

static int vfscanf(FILE *stream, const char *format, va_list ap)
{
    stdio_lock(stream, -1);
    int result = vfscanf_unlocked(stream, format, ap);
    stdio_unlock(stream);
    return result;
}

static int vscanf_unlocked(const char *format, va_list ap)
{
    return vfscanf_unlocked(stdin, format, ap);
}

static int vscanf(const char *format, va_list ap)
{
    return vfscanf(stdin, format, ap);
}

static int sscanf(const char *str, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vsscanf(str, format, ap);
    va_end(ap);
    return result;
}

static int fscanf(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfscanf(stream, format, ap);
    va_end(ap);
    return result;
}

static int fscanf_unlocked(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vfscanf_unlocked(stream, format, ap);
    va_end(ap);
    return result;
}

static int scanf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vscanf(format, ap);
    va_end(ap);
    return result;
}

static int scanf_unlocked(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vscanf_unlocked(format, ap);
    va_end(ap);
    return result;
}

/****************************************************************************/
/* LIBDL                                                                    */
/****************************************************************************/

#ifdef LIBDL

/*
 * This is an implementation of libdl functionality (dlopen, etc.).
 *
 * NOTEs:
 *  - This module must be initialized by calling dlinit(dynamic), where
 *    `dynamic' is the pointer to the dynamic information passed as the
 *    fourth argument to init(...).
 *  - These functions are not the libdl versions, but the GLibc private
 *    versions (__libc_dlopen, etc.), which do not officially exist.  Thus,
 *    there is a chance this code will fail if glibc is updated.
 *  - For this to work, the binary must link against libc (most do).
 *  - The glibc versions are slightly different, e.g., no RTLD_NEXT.
 *  - In principle, one could get the "real" libdl versions using
 *    dlopen("libdl.so").
 *  - BE AWARE OF ABI ISSUES.  External library code probably uses the SYSV
 *    ABI meaning that the program may crash if you try and call it from a
 *    clean call.  To avoid this, the dlcall() helper function may be used
 *    to safely switch to the SYSV ABI.
 *
 */

#include <elf.h>

struct link_map
{
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next, *l_prev;
};
struct r_debug
{
    int r_version;
    struct link_map *r_map;
    Elf64_Addr r_brk;
    enum
    {
        RT_CONSISTENT,
        RT_ADD,
        RT_DELETE
    } r_state;
    Elf64_Addr r_ldbase;
};

#define RTLD_DEFAULT    ((void *) 0)

#define RTLD_LAZY       0x0001
#define RTLD_NOW        0x0002
#define RTLD_NOLOAD     0x0004
#define RTLD_DEEPBIND   0x0008
#define RTLD_GLOBAL     0x0100
#define RTLD_LOCAL      0x0000
#define RTLD_NODELETE   0x1000

typedef intptr_t (*dlopen_t)(const char *, int);
typedef intptr_t (*dlclose_t)(void *);
typedef intptr_t (*dlsym_t)(void *, const char *);
typedef intptr_t (*dlvsym_t)(void *, const char *, const char *);
struct hshtab_s
{
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloomsz;
    uint32_t bloomshft;
    uint8_t data[];
};

static struct link_map *dldefault = NULL;
static dlopen_t  dlopen_impl      = NULL;
static dlsym_t   dlsym_impl       = NULL;
static dlvsym_t  dlvsym_impl      = NULL;
static dlclose_t dlclose_impl     = NULL;
void            *dlerrno_impl     = NULL;

intptr_t dlcall(void *f, ...);

static const Elf64_Sym *dl_gnu_hash_lookup(const void *hshtab_0,
    const Elf64_Sym *symtab, const char *strtab, const char *name)
{
    uint32_t h = 5381;
    for (int i = 0; name[i]; i++)
        h = (h << 5) + h + name[i];

    const struct hshtab_s *hshtab =
        (const struct hshtab_s *)hshtab_0;

    const uint32_t *buckets =
        (const uint32_t *)(hshtab->data + hshtab->bloomsz * sizeof(uint64_t));
    const uint32_t *chain = buckets + hshtab->nbuckets;

    uint32_t idx = buckets[h % hshtab->nbuckets];
    if (idx < hshtab->symoffset)
        return NULL;
    for (; ; idx++)
    {
        const char* entry = strtab + symtab[idx].st_name;
        const uint32_t hh = chain[idx - hshtab->symoffset];
        if ((hh | 0x1) == (h | 0x1) && strcmp(name, entry) == 0)
            return symtab + idx;
        if ((hh & 0x1) != 0)
            return NULL;
    }
}

/*
 * Initialize dynamic linker routines.
 */
static int dlinit(const void *dynamic_0)
{
    const Elf64_Dyn *dynamic = (const Elf64_Dyn *)dynamic_0;
    if (dynamic == NULL)
    {
        errno = ENOEXEC;
        return -1;
    }

    // Get the linkmap from DT_DEBUG
    struct r_debug *debug = NULL;
    for (size_t i = 0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_DEBUG)
            debug = (struct r_debug *)dynamic[i].d_un.d_ptr;
    }
    if (debug == NULL)
    {
        errno = ENOEXEC;
        return -1;
    }
    struct link_map *link_map = debug->r_map;
    dldefault = link_map;

    // Scan all objects to find the __libc_dl*() functions.
    for (struct link_map *l = link_map; l != NULL; l = l->l_next)
    {
        const Elf64_Dyn *dynamic = l->l_ld;
        if (dynamic == NULL)
            continue;
        const void *hshtab      = NULL;
        const Elf64_Sym *symtab = NULL;
        const char *strtab      = NULL;
        for (size_t i = 0; dynamic[i].d_tag != DT_NULL; i++)
        {
            switch (dynamic[i].d_tag)
            {
                case DT_STRTAB:
                    strtab = (const char *)dynamic[i].d_un.d_ptr;
                    break;
                case DT_SYMTAB:
                    symtab = (const Elf64_Sym *)dynamic[i].d_un.d_ptr;
                    break;
                case DT_GNU_HASH:
                    hshtab = (const void *)dynamic[i].d_un.d_ptr;
                    break;
                default:
                    continue;
            }
        }
        if (hshtab == NULL || symtab == NULL || strtab == NULL)
            continue;
        if ((intptr_t)hshtab <= UINT32_MAX || (intptr_t)symtab <= UINT32_MAX ||
                (intptr_t)strtab <= UINT32_MAX)
            continue;
        const Elf64_Sym *dlopen_sym = dl_gnu_hash_lookup(hshtab, symtab,
            strtab, "__libc_dlopen_mode");
        if (dlopen_sym == NULL)
            dlopen_sym = dl_gnu_hash_lookup(hshtab, symtab, strtab, "dlopen");
        const Elf64_Sym *dlsym_sym = dl_gnu_hash_lookup(hshtab, symtab,
            strtab, "__libc_dlsym");
        if (dlsym_sym == NULL)
            dlsym_sym = dl_gnu_hash_lookup(hshtab, symtab, strtab, "dlsym");
        const Elf64_Sym *dlvsym_sym = dl_gnu_hash_lookup(hshtab, symtab,
            strtab, "__libc_dlvsym");
        if (dlvsym_sym == NULL)
            dlvsym_sym = dl_gnu_hash_lookup(hshtab, symtab, strtab, "dlvsym");
        const Elf64_Sym *dlclose_sym = dl_gnu_hash_lookup(hshtab, symtab,
            strtab, "__libc_dlclose");
        if (dlclose_sym == NULL)
            dlclose_sym = dl_gnu_hash_lookup(hshtab, symtab, strtab, "dlclose");
        const Elf64_Sym *dlerrno_sym = dl_gnu_hash_lookup(hshtab, symtab,
            strtab, "__errno_location");
        if (dlopen_sym != NULL && dlsym_sym != NULL && dlclose_sym != NULL &&
                dlerrno_sym != NULL)
        {
            dlopen_impl  = (dlopen_t)(l->l_addr + dlopen_sym->st_value);
            dlsym_impl   = (dlsym_t)(l->l_addr + dlsym_sym->st_value);
            dlvsym_impl  = (dlvsym_t)(l->l_addr + dlvsym_sym->st_value);
            dlclose_impl = (dlclose_t)(l->l_addr + dlclose_sym->st_value);
            dlerrno_impl = (void *)(l->l_addr + dlerrno_sym->st_value);
            return 0;
        }
    }

    errno = EINVAL;
    return -1;
}

static void *dlopen(const char *filename, int flags)
{
    if (dlopen_impl == NULL)
        panic("dl not initialized");
    return (void *)dlcall((void *)dlopen_impl, filename, flags);
}

static void *dlsym(void *handle, const char *name)
{
    if (dlsym_impl == NULL)
        panic("dl not initialized");
    if (handle == NULL)
        handle = dldefault;
    return (void *)dlcall((void *)dlsym_impl, handle, name);
}

static void *dlvsym(void *handle, const char *name, const char *version)
{
    if (dlvsym_impl == NULL)
        panic("dl not initialized or unsupported");
    if (handle == NULL)
        handle = dldefault;
    return (void *)dlcall((void *)dlvsym_impl, handle, name, version);
}

static int dlclose(void *handle)
{
    if (dlclose_impl == NULL)
        panic("dl not initialized");
    return (int)dlcall((void *)dlclose_impl, handle);
}

/*
 * dlcall(f, ...) --- call SYSV ABI function f(...)
 *
 * This function should be used to call external library code or to switch to
 * using the SYSV ABI.  It works by saving errno, the extended register state,
 * as well as aligning the stack, as per the SYSV ABI specification.  The
 * dlcall(...) operation is relatively slow, so should be used sparingly.
 *
 * WARNING:
 *  - A maximum of SIXTEEN function parameters are supported by dlcall(f, ...).
 */
asm (
    ".globl dlcall\n"
    "dlcall:\n"

    // Align the stack:
    "mov %rsp,%r11\n"
    "and $-64,%rsp\n"
    "push %r11\n"

    // Save errno:
    "mov dlerrno_impl(%rip),%rax\n"
    "push %rdi\n"
    "push %rsi\n"
    "push %rdx\n"
    "push %rcx\n"
    "push %r8\n"
    "push %r9\n"
    "push %r11\n"
    "callq *%rax\n"             // __errno_location()
    "pop %r11\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rcx\n"
    "pop %rdx\n"
    "pop %rsi\n"
    "pop %rdi\n"
    "push %rax\n"
    "mov (%rax),%eax\n"
    "push %rax\n"

    // Save extended state:
    "lea -(0x1000+64-3*8)(%rsp),%rsp\n"
    "mov %rdx,%r10\n"
    "xor %edx,%edx\n"
    "mov $0xe7,%eax\n"          // x87,SSE,AVX,AVX512
    "mov %rdx,512(%rsp)\n"      // Zero XSAVE header
    "mov %rdx,512+8(%rsp)\n"
    "mov %rdx,512+16(%rsp)\n"
    "mov %rdx,512+24(%rsp)\n"
    "xsave (%rsp)\n"

    // Call the function:
    "mov %r10,%rdx\n"
    "mov %rdi,%r10\n"
    "mov %rsi,%rdi\n"
    "mov %rdx,%rsi\n"
    "mov %rcx,%rdx\n"
    "mov %r8,%rcx\n"
    "mov %r9,%r8\n"
    "mov 0x08(%r11),%r9\n"
    "mov 0x58(%r11),%rax\n"
    "push %rax\n"
    "mov 0x50(%r11),%rax\n"
    "push %rax\n"
    "mov 0x48(%r11),%rax\n"
    "push %rax\n"
    "mov 0x40(%r11),%rax\n"
    "push %rax\n"
    "mov 0x38(%r11),%rax\n"
    "push %rax\n"
    "mov 0x30(%r11),%rax\n"
    "push %rax\n"
    "mov 0x28(%r11),%rax\n"
    "push %rax\n"
    "mov 0x20(%r11),%rax\n"
    "push %rax\n"
    "mov 0x18(%r11),%rax\n"
    "push %rax\n"
    "mov 0x10(%r11),%rax\n"
    "push %rax\n"
    "callq *%r10\n"             // f(...)

    // Restore extended state:
    "mov %rax,%rdi\n"
    "xor %edx,%edx\n"
    "mov $0xe7,%eax\n"
    "xrstor 0x50(%rsp)\n"
    "mov %rdi,%rax\n"

    // Restore errno:
    "lea 0x1000+64-3*8+0x50(%rsp),%rsp\n"
    "pop %rdx\n"
    "pop %rcx\n"
    "mov %edx,(%rcx)\n"

    // Unalign the stack:
    "pop %rsp\n"

    "retq\n"
);

#endif      /* defined(LIBDL) */

/****************************************************************************/
/* SEARCH                                                                   */
/****************************************************************************/

/*
 * This is an implementation of the POSIX tree-search (tsearch) family of
 * functions, see (man tsearch) for more information.  Unlike the POSIX
 * specification, this version additionally guarantees that the tree is
 * balanced, for O(log N) worst-case behaviour.
 *
 * The implementation uses code that is derived from Niels Provos' red-black
 * tree implementation.  See the copyright and license (BSD) below.
 */

/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

typedef enum
{
    preorder,
    postorder,
    endorder,
    leaf
} VISIT;
struct node_s
{
    void *key;
    struct node_s *parent;
    struct node_s *left;
    struct node_s *right;
    int color;
};
struct tree_s
{
    struct node_s *root;
};

#define TREE_BLACK                  0
#define TREE_RED                    1
#define TREE_PARENT(N)              ((N)->parent)
#define TREE_LEFT(N)                ((N)->left)
#define TREE_RIGHT(N)               ((N)->right)
#define TREE_COLOR(N)               ((N)->color)

static void tree_rotate_left(struct tree_s *t, struct node_s *n)
{
    struct node_s *tmp = TREE_RIGHT(n);
    if ((TREE_RIGHT(n) = TREE_LEFT(tmp)) != NULL)
        TREE_PARENT(TREE_LEFT(tmp)) = n;
    if ((TREE_PARENT(tmp) = TREE_PARENT(n)) != NULL)
    {
        if (n == TREE_LEFT(TREE_PARENT(n)))
            TREE_LEFT(TREE_PARENT(n)) = tmp;
        else
            TREE_RIGHT(TREE_PARENT(n)) = tmp;
    }
    else
        t->root = tmp;
    TREE_LEFT(tmp) = n;
    TREE_PARENT(n) = tmp;
}

static void tree_rotate_right(struct tree_s *t, struct node_s *n)
{
    struct node_s *tmp = TREE_LEFT(n);
    if ((TREE_LEFT(n) = TREE_RIGHT(tmp)) != NULL)
        TREE_PARENT(TREE_RIGHT(tmp)) = n;
    if ((TREE_PARENT(tmp) = TREE_PARENT(n)) != NULL)
    {
        if (n == TREE_LEFT(TREE_PARENT(n)))
            TREE_LEFT(TREE_PARENT(n)) = tmp;
        else
            TREE_RIGHT(TREE_PARENT(n)) = tmp;
    } else
        t->root = tmp;
    TREE_RIGHT(tmp) = n;
    TREE_PARENT(n) = tmp;
}

static void tree_rebalance_insert(struct tree_s *t, struct node_s *n)
{
    struct node_s *parent, *gparent, *tmp;
    while ((parent = TREE_PARENT(n)) != NULL &&
                TREE_COLOR(parent) == TREE_RED)
    {
        gparent = TREE_PARENT(parent);
        if (parent == TREE_LEFT(gparent))
        {
            tmp = TREE_RIGHT(gparent);
            if (tmp != NULL && TREE_COLOR(tmp) == TREE_RED)
            {
                TREE_COLOR(tmp)     = TREE_BLACK;
                TREE_COLOR(parent)  = TREE_BLACK;
                TREE_COLOR(gparent) = TREE_RED;
                n = gparent;
                continue;
            }
            if (TREE_RIGHT(parent) == n)
            {
                tree_rotate_left(t, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            TREE_COLOR(parent)  = TREE_BLACK;
            TREE_COLOR(gparent) = TREE_RED;
            tree_rotate_right(t, gparent);
        }
        else
        {
            tmp = TREE_LEFT(gparent);
            if (tmp != NULL && TREE_COLOR(tmp) == TREE_RED)
            {
                TREE_COLOR(tmp)     = TREE_BLACK;
                TREE_COLOR(parent)  = TREE_BLACK;
                TREE_COLOR(gparent) = TREE_RED;
                n = gparent;
                continue;
            }
            if (TREE_LEFT(parent) == n)
            {
                tree_rotate_right(t, parent);
                tmp = parent;
                parent = n;
                n = tmp;
            }
            TREE_COLOR(parent)  = TREE_BLACK;
            TREE_COLOR(gparent) = TREE_RED;
            tree_rotate_left(t, gparent);
        }
    }
    TREE_COLOR(t->root) = TREE_BLACK;
}

static void tree_rebalance_remove(struct tree_s *t, struct node_s *parent,
    struct node_s *n)
{
    struct node_s *tmp;
    while ((n == NULL || TREE_COLOR(n) == TREE_BLACK) && n != t->root)
    {
        if (TREE_LEFT(parent) == n)
        {
            tmp = TREE_RIGHT(parent);
            if (TREE_COLOR(tmp) == TREE_RED)
            {
                TREE_COLOR(tmp) = TREE_BLACK;
                TREE_COLOR(parent) = TREE_RED;
                tree_rotate_left(t, parent);
                tmp = TREE_RIGHT(parent);
            }
            if ((TREE_LEFT(tmp) == NULL ||
                    TREE_COLOR(TREE_LEFT(tmp)) == TREE_BLACK) &&
                (TREE_RIGHT(tmp) == NULL ||
                    TREE_COLOR(TREE_RIGHT(tmp)) == TREE_BLACK))
            {
                TREE_COLOR(tmp) = TREE_RED;
                n = parent;
                parent = TREE_PARENT(n);
            }
            else
            {
                if (TREE_RIGHT(tmp) == NULL ||
                    TREE_COLOR(TREE_RIGHT(tmp)) == TREE_BLACK)
                {
                    struct node_s *oleft;
                    if ((oleft = TREE_LEFT(tmp)) != NULL)
                        TREE_COLOR(oleft) = TREE_BLACK;
                    TREE_COLOR(tmp) = TREE_RED;
                    tree_rotate_right(t, tmp);
                    tmp = TREE_RIGHT(parent);
                }
                TREE_COLOR(tmp) = TREE_COLOR(parent);
                TREE_COLOR(parent) = TREE_BLACK;
                if (TREE_RIGHT(tmp))
                    TREE_COLOR(TREE_RIGHT(tmp)) = TREE_BLACK;
                tree_rotate_left(t, parent);
                n = t->root;
                break;
            }
        }
        else
        {
            tmp = TREE_LEFT(parent);
            if (TREE_COLOR(tmp) == TREE_RED)
            {
                TREE_COLOR(tmp) = TREE_BLACK;
                TREE_COLOR(parent) = TREE_RED;
                tree_rotate_right(t, parent);
                tmp = TREE_LEFT(parent);
            }
            if ((TREE_LEFT(tmp) == NULL ||
                    TREE_COLOR(TREE_LEFT(tmp)) == TREE_BLACK) &&
                (TREE_RIGHT(tmp) == NULL ||
                    TREE_COLOR(TREE_RIGHT(tmp)) == TREE_BLACK))
            {
                TREE_COLOR(tmp) = TREE_RED;
                n = parent;
                parent = TREE_PARENT(n);
            }
            else
            {
                if (TREE_LEFT(tmp) == NULL ||
                    TREE_COLOR(TREE_LEFT(tmp)) == TREE_BLACK)
                {
                    struct node_s *oright;
                    if ((oright = TREE_RIGHT(tmp)) != NULL)
                        TREE_COLOR(oright) = TREE_BLACK;
                    TREE_COLOR(tmp) = TREE_RED;
                    tree_rotate_left(t, tmp);
                    tmp = TREE_LEFT(parent);
                }
                TREE_COLOR(tmp) = TREE_COLOR(parent);
                TREE_COLOR(parent) = TREE_BLACK;
                if (TREE_LEFT(tmp))
                    TREE_COLOR(TREE_LEFT(tmp)) = TREE_BLACK;
                tree_rotate_right(t, parent);
                n = t->root;
                break;
            }
        }
    }
    if (n != NULL)
        TREE_COLOR(n) = TREE_BLACK;
}

static struct node_s *tree_remove(struct tree_s *t, struct node_s *n)
{
    struct node_s *child, *parent, *old = n;
    int color;
    if (TREE_LEFT(n) == NULL)
        child = TREE_RIGHT(n);
    else if (TREE_RIGHT(n) == NULL)
        child = TREE_LEFT(n);
    else
    {
        struct node_s *left;
        n = TREE_RIGHT(n);
        while ((left = TREE_LEFT(n)) != NULL)
            n = left;
        child = TREE_RIGHT(n);
        parent = TREE_PARENT(n);
        color = TREE_COLOR(n);
        if (child != NULL)
            TREE_PARENT(child) = parent;
        if (parent != NULL)
        {
            if (TREE_LEFT(parent) == n)
                TREE_LEFT(parent) = child;
            else 
                TREE_RIGHT(parent) = child;
        }
        else
            t->root = child;
        if (TREE_PARENT(n) == old)
            parent = n;
        TREE_PARENT(n) = TREE_PARENT(old);
        TREE_LEFT(n)   = TREE_LEFT(old);
        TREE_RIGHT(n)  = TREE_RIGHT(old);
        TREE_COLOR(n)  = TREE_COLOR(old);
        if (TREE_PARENT(old) != NULL)
        {
            if (TREE_LEFT(TREE_PARENT(old)) == old)
                TREE_LEFT(TREE_PARENT(old)) = n;
            else
                TREE_RIGHT(TREE_PARENT(old)) = n;
        }
        else
            t->root = n;
        TREE_PARENT(TREE_LEFT(old)) = n;
        if (TREE_RIGHT(old) != NULL)
            TREE_PARENT(TREE_RIGHT(old)) = n;
        goto color;
    }
    parent = TREE_PARENT(n);
    color = TREE_COLOR(n);
    if (child != NULL)
        TREE_PARENT(child) = parent;
    if (parent)
    {
        if (TREE_LEFT(parent) == n)
            TREE_LEFT(parent) = child;
        else
            TREE_RIGHT(parent) = child;
    }
    else
        t->root = child;
color:
    if (color == TREE_BLACK)
        tree_rebalance_remove(t, parent, child);
    return old;
}

static void *pool_tsearch(struct malloc_pool_s *pool, const void *key,
    void **root, int (*compare)(const void *, const void *))
{
    if (root == NULL)
        return NULL;
    struct tree_s *t = (struct tree_s *)root;
    struct node_s *n = t->root, *parent = NULL;
    int cmp = 0;
    while (n != NULL)
    {
        parent = n;
        cmp = compare(key, n->key);
        if (cmp < 0)
            n = TREE_LEFT(n);
        else if (cmp > 0)
            n = TREE_RIGHT(n);
        else
            return (void *)n;
    }
    n = (struct node_s *)pool_malloc(pool, sizeof(struct node_s));
    if (n == NULL)
        return NULL;
    n->key = (void *)key;
    TREE_PARENT(n) = parent;
    TREE_LEFT(n)   = TREE_RIGHT(n) = NULL;
    TREE_COLOR(n)  = TREE_RED;
    if (parent != NULL)
    {
        if (cmp < 0)
            TREE_LEFT(parent) = n;
        else
            TREE_RIGHT(parent) = n;
    }
    else
        t->root = n;
    tree_rebalance_insert(t, n);
    return n;
}
static void *tsearch(const void *key, void **root,
    int (*compare)(const void *, const void *))
{
    return pool_tsearch(NULL, key, root, compare);
}

static void *tfind(const void *key, void **root,
    int (*compare)(const void *, const void *))
{
    if (root == NULL)
        return NULL;
    struct tree_s *t = (struct tree_s *)root;
    struct node_s *n = t->root;
    int cmp = 0;
    while (n != NULL)
    {
        cmp = compare(key, n->key);
        if (cmp < 0)
            n = TREE_LEFT(n);
        else if (cmp > 0)
            n = TREE_RIGHT(n);
        else
            return (void *)n;
    }
    return NULL;
}
static void *pool_tfind(struct malloc_pool_s *pool, const void *key,
    void **root, int (*compare)(const void *, const void *))
{
    return tfind(key, root, compare);
}

static void *pool_tdelete(struct malloc_pool_s *pool, const void *key,
    void **root, int (*compare)(const void *, const void *))
{
    if (root == NULL)
        return NULL;
    struct tree_s *t = (struct tree_s *)root;
    struct node_s *n = t->root;
    int cmp = 0;
    while (n != NULL)
    {
        cmp = compare(key, n->key);
        if (cmp < 0)
            n = TREE_LEFT(n);
        else if (cmp > 0)
            n = TREE_RIGHT(n);
        else
        {
            struct node_s *parent = TREE_PARENT(n);
            n = tree_remove(t, n);
            pool_free(pool, n);
            return (parent == NULL? (void *)root: parent);
        }
    }
    return NULL;
}
static void *tdelete(const void *key, void **root,
    int (*compare)(const void *, const void *))
{
    return pool_tdelete(NULL, key, root, compare);
}

static void tree_walk(const struct node_s *n, int depth,
    void (*action)(const void *, const VISIT, const int))
{
    if (TREE_LEFT(n) == NULL && TREE_RIGHT(n) == NULL)
        action(n, leaf, depth);
    else
    {
        action(n, preorder, depth);
        if (TREE_LEFT(n) != NULL)
            tree_walk(TREE_LEFT(n), depth+1, action);
        action(n, postorder, depth);
        if (TREE_RIGHT(n) != NULL)
            tree_walk(TREE_RIGHT(n), depth+1, action);
        action(n, endorder, depth);
    }
}
static void twalk(const void *root,
    void (*action)(const void *, const VISIT, const int))
{
    if (root == NULL || action == NULL)
        return;
    struct node_s *n = (struct node_s *)root;
    tree_walk(n, 0, action);
}

static void tree_destroy(struct malloc_pool_s *pool, const struct node_s *n,
    void (*free_node)(void *))
{
    if (n == NULL)
        return;
    if (free_node != NULL)
        free_node(n->key);
    tree_destroy(pool, TREE_LEFT(n), free_node);
    tree_destroy(pool, TREE_RIGHT(n), free_node);
    pool_free(pool, (void *)n);
}
static void tdestroy(const void *root, void (*free_node)(void *))
{
    struct node_s *n = (struct node_s *)root;
    tree_destroy(NULL, n, free_node);
}
static void pool_tdestroy(struct malloc_pool_s *pool, const void *root,
    void (*free_node)(void *))
{
    struct node_s *n = (struct node_s *)root;
    tree_destroy(pool, n, free_node);
}

/****************************************************************************/
/* RANDOM                                                                   */
/****************************************************************************/

#define RAND_MAX        0x7FFF
static volatile uint32_t rand_state = 0;

static void srand(unsigned seed)
{
    rand_state = (seed - 1);
}

static int rand(void)
{
    uint32_t x, y;
    do
    {
        x = rand_state;
        y = (1103515245 * x + 12345) & 0x7FFFFFFF;
    }
    while (!__sync_bool_compare_and_swap(&rand_state, x, y));
    return (y >> 16);
}

/****************************************************************************/
/* SOCKET                                                                   */
/****************************************************************************/

#define _BSWAP_U16(x)                                   \
    ((((x) & 0x00FF) << 8) |                            \
     (((x) & 0xFF00) >> 8))
#define _BSWAP_U32(x)                                   \
    ((((x) & 0x000000FF) << 24) |                       \
     (((x) & 0x0000FF00) << 8) |                        \
     (((x) & 0x00FF0000) >> 8) |                        \
     (((x) & 0xFF000000) >> 24))
#define _BSWAP_U64(x)                                   \
    ((((x) & 0x00000000000000FFull) << 56) |            \
     (((x) & 0x000000000000FF00ull) << 40) |            \
     (((x) & 0x0000000000FF0000ull) << 24) |            \
     (((x) & 0x00000000FF000000ull) << 8)  |            \
     (((x) & 0x000000FF00000000ull) >> 8)  |            \
     (((x) & 0x0000FF0000000000ull) >> 24) |            \
     (((x) & 0x00FF000000000000ull) >> 40) |            \
     (((x) & 0xFF00000000000000ull) >> 56))

static uint16_t ntohs(uint16_t x)
{
    return _BSWAP_U16(x);
}
static uint32_t ntohl(uint32_t x)
{
    return _BSWAP_U32(x);
}
static uint64_t ntohll(uint64_t x)
{
    return _BSWAP_U64(x);
}
static uint16_t htons(uint16_t) __attribute__((__alias__("ntohs")));
static uint32_t htonl(uint32_t) __attribute__((__alias__("ntohl")));
static uint64_t htonll(uint64_t) __attribute__((__alias__("ntohll")));

/****************************************************************************/
/* STATE                                                                    */
/****************************************************************************/

/*
 * The "state" data structure.
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
    union
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
 * Jump to state (also restores %rip and %rip)
 */
static __attribute__((noreturn)) void jump(const struct STATE *state)
{
    asm volatile
    (
     /* "mov 0x00(%0),%%rflags\n" */
        "mov 0x08(%0),%%r15\n"
        "mov 0x10(%0),%%r14\n"
        "mov 0x18(%0),%%r13\n"
        "mov 0x20(%0),%%r12\n"
        "mov 0x28(%0),%%r11\n"
        "mov 0x30(%0),%%r10\n"
        "mov 0x38(%0),%%r9\n"
        "mov 0x40(%0),%%r8\n"
        "mov 0x48(%0),%%rdi\n"
        "mov 0x50(%0),%%rsi\n"
        "mov 0x58(%0),%%rbp\n"
        "mov 0x60(%0),%%rbx\n"
        "mov 0x68(%0),%%rdx\n"
     /* "mov 0x70(%0),%%rcx\n" */
     /* "mov 0x78(%0),%%rax\n" */
        "mov 0x80(%0),%%rsp\n"
     /* "mov 0x88(%0),%%rip\n" */

        "mov 0x88(%0),%%rax\n"
        "mov %%rax,%%fs:" STRING(ERRNO_TLS_OFFSET) "\n"

        "mov 0x00(%0),%%rax\n"
        "add $0x7f,%%al\n"
        "sahf\n"

        "mov 0x78(%0),%%rax\n"
        "mov 0x70(%0),%%rcx\n"

        "jmpq *%%fs:" STRING(ERRNO_TLS_OFFSET) "\n"

        : "+c"(state)
    );
    while (true)
        asm volatile ("ud2");
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

static __attribute__((__noreturn__)) void exit(int status)
{
    if (mutex_lock(&stdio_mutex) < 0)
        panic("failed to lock stdio stream");
    for (int i = 0; i < 3; i++)
    {
        FILE *stream = stdio_stream[i];
        if (stream != NULL)
            fclose(stream);
    }
    (void)syscall(SYS_exit_group, status);
    while (true)
        asm volatile ("ud2");
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

static int ttyname_r(int fd, char *buf, size_t buflen)
{
    char path[32];
    ssize_t r = snprintf(path, sizeof(path)-1, "/proc/self/fd/%d", fd);
    if (r < 0 || r >= (ssize_t)sizeof(path)-1)
        return errno;
    r = readlink(path, buf, buflen-1);
    if (r < 0)
        return (errno == ENAMETOOLONG? ERANGE: errno);
    return 0;
}

static unsigned sleep(unsigned sec)
{
    struct timespec ts = {sec, 0}, tr;
    if (nanosleep(&ts, &tr) < 0)
    {
        if (errno == EINTR)
            return (unsigned)tr.tv_sec;
        return sec;
    }
    return 0;
}

static int usleep(unsigned us)
{
    size_t ns = us * 1000;
    struct timespec ts =
        {(time_t)(ns / 1000000000ul), (long)(ns % 1000000000ul)};
    return nanosleep(&ts, NULL);
}

#ifdef __cplusplus
}       // extern "C"
#endif

#endif
