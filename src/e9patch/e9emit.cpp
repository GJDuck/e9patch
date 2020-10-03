/*
 * e9emit.cpp
 * Copyright (C) 2020 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "e9emit.h"
#include "e9patch.h"

/*
 * Emit the complete patched executable binary file.
 */
void emitBinary(const char *filename, const uint8_t *bin, size_t len)
{
    FILE *out = fopen(filename, "w");
    if (out == nullptr)
        error("failed to open output file \"%s\" for writing: %s", filename,
            strerror(errno));
    if (fwrite(bin, sizeof(uint8_t), len, out) != len)
        error("failed to write output to file \"%s\": %s", filename,
            strerror(errno));
    if (fchmod(fileno(out), S_IRUSR | S_IWUSR | S_IXUSR |
                            S_IRGRP | S_IWGRP | S_IXGRP |
                            S_IROTH | S_IWOTH | S_IXOTH))
    {
        // This is a warning since the output might be /dev/null
        warning("failed to set execute permission for output file \"%s\": %s",
            filename, strerror(errno));
    }
    if (fclose(out) < 0)
        error("failed to close output file \"%s\": %s", filename,
            strerror(errno));
}

/*
 * Emit a binary patch.  Implements (an approximation of) the pipeline:
 *      cat bin1 | xxd > tmp.1
 *      cat bin2 | xxd > tmp.2
 *      diff tmp.1 tmp.2 | gzip > filename
 *      rm tmp.1 tmp.2
 */
void emitPatch(const char *filename, const char *compress, int fd1,
    const uint8_t *bin2, size_t len2)
{
    char fifo_name1[64], fifo_name2[64], *fifo_name = nullptr;
    int fd, fds2[2], fds3[2];
    static unsigned CHILD_MAX = 4;
    pid_t pids[CHILD_MAX];
    const char *progs[CHILD_MAX];
    unsigned pc = 0;
    uint64_t rand64[2];

    // Create named pipes:
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        error("failed to open \"/dev/urandom\": %s", strerror(errno));
    if (read(fd, (void *)rand64, sizeof(rand64)) != sizeof(rand64))
        error("failed to read from \"/dev/urandom\": %s", strerror(errno));
    close(fd);
    pid_t pid = getpid();
    int r = snprintf(fifo_name1, sizeof(fifo_name1)-1,
        "/tmp/bin1_%d_%.16lX.hex", pid, rand64[0]);
    if (r < 0 || r >= (int)sizeof(fifo_name1))
    {
name_error:
        error("failed to generate named pipe name: %s", strerror(errno));
    }
    r = snprintf(fifo_name2, sizeof(fifo_name2)-1, "/tmp/bin2_%d_%.16lX.hex",
        pid, rand64[1]);
    if (r < 0 || r >= (int)sizeof(fifo_name1))
        goto name_error;
    if (mkfifo(fifo_name1, S_IRUSR | S_IWUSR) != 0 ||
            mkfifo(fifo_name2, S_IRUSR | S_IWUSR) != 0)
        error("failed to create named pipe: %s", strerror(errno));

    // Execute xxd #1 
    progs[pc] = "xxd";
    pids[pc]  = fork();
    if (pids[pc] == 0)
    {
        if (dup2(fd1, STDIN_FILENO) < 0)
        {
dup2_error:
            error("failed to dup file descriptor: %s", strerror(errno));
        }
        close(fd1);
        fifo_name = fifo_name1;
        fd = open(fifo_name, O_WRONLY);
        if (fd < 0)
        {
open_error:
            error("failed to open named pipe: %s", strerror(errno));
        }
        if (dup2(fd, STDOUT_FILENO) < 0)
            goto dup2_error;
        close(fd);
        if (execlp(progs[pc], progs[pc], "-p", nullptr) != 0)
        {
execlp_error:
            error("failed to execute \"%s\" command: %s", progs[pc],
                strerror(errno));
        }
    }
    else if (pids[pc] < 0)
    {
fork_error:
        error("failed to fork process: %s", strerror(errno));
    }
    pc++;

    // Execute xxd #2
    if (pipe(fds2) != 0)
    {
pipe_error:
            error("failed to open pipe: %s", strerror(errno));
    }
    progs[pc] = "xxd";
    pids[pc]  = fork();
    if (pids[pc] == 0)
    {
        close(fds2[1]);
        if (dup2(fds2[0], STDIN_FILENO) < 0)
            goto dup2_error;
        close(fds2[0]);
        fifo_name = fifo_name2;
        fd = open(fifo_name, O_WRONLY);
        if (fd < 0)
            goto open_error;
        if (dup2(fd, STDOUT_FILENO) < 0)
            goto dup2_error;
        close(fd);
        if (execlp(progs[pc], progs[pc], "-p", nullptr) != 0)
            goto execlp_error;
    }
    else if (pids[pc] < 0)
        goto fork_error;
    close(fds2[0]);
    pc++;

    // Execute diff
    int fd3 = STDOUT_FILENO;
    if (strcmp(filename, "-") != 0)
    {
        fd3 = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IRGRP | S_IROTH |
            S_IWUSR | S_IWGRP | S_IWOTH);
        if (fd3 < 0)
            error("failed to open file \"%s\" for writing: %s", filename,
                strerror(errno));
    }
    fd = fd3;
    if (compress != nullptr)
    {
        if (pipe(fds3) != 0)
            goto pipe_error;
        fd = fds3[1];
    }
    progs[pc] = "diff";
    pids[pc]  = fork();
    if (pids[pc] == 0)
    {
        close(fds2[1]);
        if (fd != STDOUT_FILENO)
        {
            if (compress != nullptr)
                close(fds3[0]);
            if (dup2(fd, STDOUT_FILENO) < 0)
                goto dup2_error;
            close(fd);
        }
        if (execlp(progs[pc], progs[pc], fifo_name1, fifo_name2, nullptr) != 0)
            goto execlp_error;
    }
    else if (pids[pc] < 0)
        goto fork_error;
    pc++;

    // Execute compress
    if (compress != nullptr)
    {
        progs[pc] = compress;
        pids[pc]  = fork();
        if (pids[pc] == 0)
        {
            close(fds2[1]);
            close(fds3[1]);
            if (dup2(fds3[0], STDIN_FILENO) < 0)
                goto dup2_error;
            close(fds3[0]);
            if (fd3 != STDOUT_FILENO)
            {
                if (dup2(fd3, STDOUT_FILENO) < 0)
                    goto dup2_error;
                close(fd3);
            }
            if (execlp(progs[pc], progs[pc], nullptr) != 0)
                goto execlp_error;
        }
        else if (pids[pc] < 0)
            goto fork_error;
        close(fds3[0]);
        close(fds3[1]);
    }

    // Copy the data into the pipe:
    int fd2 = fds2[1];
    for (size_t i = 0; i < len2; i += BUFSIZ)
    {
        size_t count2 = std::min((size_t)BUFSIZ, len2 - i);
        if (write(fd2, bin2+i, count2) != (int)count2)
            error("failed to write to pipe: %s", strerror(errno));
    }
    close(fd2);

    // Wait for the child processes to finish:
    for (unsigned i = 0; i < pc; i++)
    {
        int status;
        while (true)
        {
            if (waitpid(pids[i], &status, 0) < 0)
                error("failed to wait for child process \"%s\" (%d): %s",
                    progs[i], pids[i], strerror(errno));
            if (WIFEXITED(status))
            {
                status = WEXITSTATUS(status);
                if (status == EXIT_SUCCESS)
                    break;
                if (status == 1 && strcmp(progs[i], "diff") == 0)
                    break;
                error("child process \"%s\" (%d) exitted with status %d",
                    progs[i], pids[i], status);
            }
            else if (WIFSIGNALED(status))
            {
                int sig = WTERMSIG(status);
                error("child process \"%s\" (%d) killed by signal %d (%s)",
                    progs[i], pids[i], sig, strsignal(sig));
            }
        }
    }

    // Cleanup:
    if (unlink(fifo_name1) < 0 || unlink(fifo_name2) < 0)
        error("failed to unlink named pipe: %s", strerror(errno));
}

