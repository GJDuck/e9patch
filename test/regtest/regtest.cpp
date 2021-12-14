/*
 * Copyright (C) 2021 National University of Singapore
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

#include <string>
#include <vector>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

static bool option_tty = false;

#define RED     "\33[31m"
#define GREEN   "\33[32m"
#define YELLOW  "\33[33m"
#define WHITE "\33[0m"

#define error(msg, ...)                                                 \
    do                                                                  \
    {                                                                   \
        fprintf(stderr, "%serror%s: " msg "\n",                         \
            (option_tty? RED: ""), (option_tty? WHITE: ""),           \
            ##__VA_ARGS__);                                             \
        exit(EXIT_FAILURE);                                             \
    }                                                                   \
    while (false)

/*
 * Run a single test case.
 */
static bool runTest(const struct dirent *test, const std::string &options)
{
    std::string in(test->d_name);
    std::string basename(in, 0, in.size()-3);
    std::string out(basename);
    out += ".out";
    std::string exp(basename);
    exp += ".exp";
    std::string exe(basename);
    exe += ".exe";
    std::string log(basename);
    log += ".log";
    std::string cmd(basename);
    cmd += ".cmd";

    // Step (0): reset
    unlink(out.c_str());
    unlink(exe.c_str());
    unlink(log.c_str());

    // Step (1): generate the EXE
    std::string command("../../e9tool ");
    if (options != "")
    {
        command += options;
        command += ' ';
    }
    command += "-M 'addr >= &\"entry\"' ";
    FILE *IN = fopen(in.c_str(), "r");
    if (IN == nullptr)
        error("failed to open file \"%s\": %s", in.c_str(), strerror(errno));
    char c;
    for (int i = 0; (c = getc(IN)) != '\n' && isprint(c) && i < 1024; i++)
        command += c;
    fclose(IN);
    command += " -E data..data_END -E data2...text -E .text..begin -o ";
    command += exe;
    command += " >";
    command += log;
    command += " 2>&1";

    printf("\n\t%s\n", command.c_str());
    int r = system(command.c_str());
    if (r != 0)
    {
        printf("%s%s%s: %sFAILED%s (patching failed with status %d, see %s)\n",
            (option_tty? YELLOW: ""), basename.c_str(), (option_tty? WHITE: ""),
            (option_tty? RED: ""), (option_tty? WHITE: ""),
            r, log.c_str());
        return false;
    }

    // Step (2): execute the EXE
    FILE *CMD = fopen(cmd.c_str(), "r");
    command.clear();
    if (CMD != NULL)
    {
        for (int i = 0; (c = getc(CMD)) != '\n' && isprint(c) && i < 1024; i++)
            command += c;
        fclose(CMD);
    }
    else
    {
        command += "./";
        command += exe;
    }
    command += " >";
    command += out;
    command += " 2>&1";
    printf("\t%s\n", command.c_str());
    r = system(command.c_str());
    if (r != 0 && /*Ignore signals=*/
        !(WIFEXITED(r) && WEXITSTATUS(r) >= 128 && WEXITSTATUS(r) <= 128+32))
    {
        printf("%s%s%s: %sFAILED%s (execution failed with status %d, see %s)\n",
            (option_tty? YELLOW: ""), basename.c_str(), (option_tty? WHITE: ""),
            (option_tty? RED: ""), (option_tty? WHITE: ""),
            r, out.c_str());
        return false;
    }
    command.clear();
    command = "sed -i 's/ (core dumped)//g' ";
    command += out;
    system(command.c_str());

    // Step (3): compare the output
    FILE *OUT = fopen(out.c_str(), "r");
    if (OUT == nullptr)
        error("failed to open file \"%s\" for reading: %s", out.c_str(),
            strerror(errno));
    FILE *EXP = fopen(exp.c_str(), "r");
    if (EXP == nullptr)
    {
        if (errno == ENOENT)
            EXP = fopen("/dev/null", "r");	// Missing = empty file
        if (EXP == nullptr)
            error("failed to open file \"%s\" for reading: %s", exp.c_str(),
                strerror(errno));
    }
    const int LIMIT = 100000;   
    for (int i = 0; i < LIMIT; i++)
    {
        char c = getc(OUT), d = getc(EXP);
        if (c != d)
        {
            fclose(OUT); fclose(EXP);
            printf("%s%s%s: %sFAILED%s (miscompare, see the diff between %s and "
                    "%s)\n",
                (option_tty? YELLOW: ""), basename.c_str(),
                (option_tty? WHITE: ""), (option_tty? RED: ""),
                (option_tty? WHITE: ""), out.c_str(), exp.c_str());
            return false;
        }
        if (c == EOF)
            break;
    }
    fclose(OUT); fclose(EXP);

    // Success!
    printf("%s%s%s: %spassed%s\n",
        (option_tty? YELLOW: ""), basename.c_str(), (option_tty? WHITE: ""),
        (option_tty? GREEN: ""), (option_tty? WHITE: ""));
    return true;
}

/*
 * Test if directory entry is a test case (i.e., ends with ".in").
 */
static int isTest(const struct dirent *entry)
{
    size_t len = strlen(entry->d_name);
    if (len <= 3)
        return false;
    if (entry->d_name[len-1] != 'n' || entry->d_name[len-2] != 'i' ||
            entry->d_name[len-3] != '.')
        return false;
    return true;
}

/*
 * Entry.
 */
int main(int argc, char **argv)
{
    std::string options;
    for (int i = 1; i < argc; i++)
    {
        if (i > 1)
            options += ' ';
        options += argv[i];
    }

    option_tty = (isatty(STDOUT_FILENO) && isatty(STDERR_FILENO));
    struct dirent **tests = nullptr;
    int n = scandir(".", &tests, isTest, alphasort);
    if (n < 0)
        error("failed to scan current directory: %s", strerror(errno));
    size_t passed = 0, failed = 0, total = 0;
    std::vector<std::string> fails;
    for (int i = 0; i < n; i++)
    {
        total++;
        if (runTest(tests[i], options))
            passed++;
        else
        {
            fails.push_back(tests[i]->d_name);
            failed++;
        }
    }

    const char *highlight = "", *off = "";
    if (option_tty)
    {
        if (passed == total)
            highlight = GREEN, off = WHITE;
        else if (passed == 0)
            highlight = RED, off = WHITE;
        else
            highlight = YELLOW, off = WHITE;
    }
    putchar('\n');
    printf("PASSED = %s%.2f%%%s (%zu/%zu); FAILED = %s%.2f%%%s (%zu/%zu)\n\n",
        highlight, (double)passed / (double)total * 100.0, off, passed, total,
        highlight, (double)failed / (double)total * 100.0, off, failed, total);
    if (fails.size() > 0)
    {
        printf("FAILED = {");
        bool prev = false;
        for (const auto &fail: fails)
        {
            if (prev)
                putchar(',');
            prev = true;
            printf("%s", fail.c_str());
        }
        printf("}\n\n");
    }

    return 0;
}

