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

#include <cstring>
#include <cstdlib>

#include <dlfcn.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "e9misc.h"
#include "e9tool.h"

using namespace e9tool;

/*
 * Options.
 */
bool option_is_tty       = false;
bool option_no_warnings  = false;
bool option_debug        = false;
bool option_intel_syntax = false;
bool option_targets      = false;
bool option_bbs          = false;
bool option_fs           = false;
bool option_trap_all     = false;

/*
 * Duplicate a string.
 */
char *strDup(const char *old_str, size_t n)
{
    char *new_str = strndup(old_str, n);
    if (new_str == nullptr)
        error("failed to duplicate string \"%s\": %s", old_str,
            strerror(ENOMEM));
    return new_str;
}

/*
 * Check for suffix.
 */
bool hasSuffix(const std::string &str, const char *suffix)
{
    size_t len = strlen(suffix);
    return (str.size() < len? false: str.compare(str.size()-len,
        len, suffix, len) == 0);
}

/*
 * Get executable path.
 */
void getExePath(std::string &path)
{
    char buf[BUFSIZ];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len < 0 || (size_t)len > sizeof(buf)-1)
        error("failed to read executable path: %s", strerror(errno));
    buf[len] = '\0';
    char *dir = dirname(buf);
    path += dir;
    if (path.size() > 0 && path[path.size()-1] != '/')
        path += '/';
}

/*
 * Attempt to guess if the filename is a library or not.
 */
bool isLibraryFilename(const char *filename)
{
    const char *str;
    while ((str = strchr(filename, '/')) != nullptr)
        filename = str+1;
    str = strstr(filename, "lib");
    if (str == nullptr)
        return false;
    str = strstr(str, ".so");
    if (str == nullptr)
        return false;
    str += 3;
    while (*str != '\0')
    {
        if (*str != '.')
            return false;
        str++;
        if (!isdigit(*str++))
            return false;
        while (isdigit(*str))
            str++;
    }
    return true;
}

/*
 * Get path information.
 */
static void getPath(bool exe, std::vector<std::string> &paths)
{
    if (exe)
    {
        char *path = getenv("PATH"), *save, *dir;
        if (path == nullptr)
            return;
        path = strDup(path);
        strtok_r(path, ":", &save);
        while ((dir = strtok_r(nullptr, ":", &save)) != nullptr)
            paths.push_back(dir);
        free(path);
    }
    else
    {
        void *handle = dlopen(nullptr, RTLD_LAZY);
        if (handle == nullptr)
            return;
        Dl_serinfo serinfo_0, *serinfo = nullptr;
        if (dlinfo(handle, RTLD_DI_SERINFOSIZE, &serinfo_0) != 0)
        {
            dlinfo_error:
            free(serinfo);
            dlclose(handle);
            return;
        }
        serinfo = (Dl_serinfo *)malloc(serinfo_0.dls_size);
        if (serinfo == nullptr)
            goto dlinfo_error;
        if (dlinfo(handle, RTLD_DI_SERINFOSIZE, serinfo) != 0)
            goto dlinfo_error;
        if (dlinfo(handle, RTLD_DI_SERINFO, serinfo) != 0)
            goto dlinfo_error;
        for (unsigned i = 0; i < serinfo->dls_cnt; i++)
            paths.push_back(serinfo->dls_serpath[i].dls_name);
        free(serinfo);
        dlclose(handle);
        return;
    }
}

/*
 * Find an exe file in PATH.
 */
const char *findBinary(const char *filename, bool exe, bool dot)
{
    if (filename[0] == '/' || filename[0] == '.')
        return filename;
    std::vector<std::string> path;
    getPath(exe, path);
    if (dot)
        path.push_back(".");
    for (const auto &dirname: path)
    {
        std::string pathname_0(dirname);
        pathname_0 += '/';
        pathname_0 += filename;

        char *pathname = realpath(pathname_0.c_str(), nullptr);
        if (pathname == nullptr)
            continue;
        struct stat buf;
        if (stat(pathname, &buf) == 0 && (buf.st_mode & S_IXOTH) != 0)
            return pathname;
        free(pathname);
    }

    error("failed to find %s file \"%s\" in %s",
        (exe? "executable": "library"), filename, (exe? "PATH": "RPATH"));
}

/*
 * Usage.
 */
void usage(FILE *stream, const char *progname)
{
    fprintf(stream,
        "        ___  _              _\n"
        "   ___ / _ \\| |_ ___   ___ | |\n"
        "  / _ \\ (_) | __/ _ \\ / _ \\| |\n"
        " |  __/\\__, | || (_) | (_) | |\n"
        "  \\___|  /_/ \\__\\___/ \\___/|_|\n"
        "\n"
        "usage: %s [OPTIONS] --match MATCH --patch PATCH ... input-file\n"
        "\n"
        "MATCH\n"
        "=====\n"
        "\n"
        "Matchings determine which instructions should be rewritten.  "
            "Matchings are\n"
        "specified using the `--match'/`-M' option:\n"
        "\n"
        "\t--match MATCH, -M MATCH\n"
        "\t\tSpecifies an instruction matching MATCH.\n"
        "\n"
        "Please see the e9tool-user-guide for more information.\n"
        "\n"
        "PATCH\n"
        "=====\n"
        "\n"
        "Patches determine how matching instructions should be rewritten.  "
            "Patches are\n"
        "specified using the `--patch'/`-P' option:\n"
        "\n"
        "\t--patch PATCH, -P patch\n"
        "\t\tThe PATCH specifies how instructions matching the preceding\n"
        "\t\t`--match'/`-M' options are to be rewritten.\n"
        "\n"
        "Please see the e9tool-user-guide for more information.\n"
        "\n"
        "OTHER OPTIONS\n"
        "=============\n"
        "\n"
        "\t--backend PROG\n"
        "\t\tUse PROG as the backend.  The default is \"e9patch\".\n"
        "\n"
        "\t--compression N, -c N\n"
        "\t\tSet the compression level to be N, where N is a number within\n"
        "\t\tthe range 0..9.  The default is 9 for maximum compression.\n"
        "\t\tHigher compression makes the output binary smaller, but also\n"
        "\t\tincreases the number of mappings (mmap() calls) required.\n"
        "\n"
        "\t--Dsync N\n"
        "\t\tIf the disassembler desyncs (e.g., data in the code section),\n"
        "\t\tthen automatically exclude N surrounding instructions.\n"
        "\t\tThe default is 64.\n"
        "\n"
        "\t--Dthreshold N\n"
        "\t\tTreat suspicious instructions as data.  Lower numbers means\n"
        "\t\tless tolerance.  The default is 2.\n"
        "\n"
        "\t--debug\n"
        "\t\tEnable debug output.\n"
        "\n"
        "\t--exclude RANGE, -E RANGE\n"
        "\t\tExclude the address RANGE from disassembly and rewriting.\n"
        "\t\tHere, RANGE has the format `LB .. UB', where LB/UB are\n"
        "\t\tinteger addresses, section names or symbols.  The address\n"
        "\t\trange [LB..UB) will be excluded, and UB must point to the\n"
        "\t\tfirst instruction where disassembly should resume.\n"
        "\n"
        "\t--executable\n"
        "\t\tTreat the input file as an executable, even if it appears to\n"
        "\t\tbe a shared library.  See the `--shared' option for more\n"
        "\t\tinformation.\n"
        "\n"
        "\t--format FORMAT\n"
        "\t\tSet the output format to FORMAT which is one of {binary,\n"
        "\t\tjson, patch, patch.gz, patch,bz2, patch.xz}.  Here:\n"
        "\n"
        "\t\t\t- \"binary\" is a modified ELF executable file;\n"
        "\t\t\t- \"json\" is the raw JSON RPC stream for the e9patch\n"
        "\t\t\t  backend; or\n"
        "\t\t\t- \"patch\" \"patch.gz\" \"patch.bz2\" and \"patch.xz\"\n"
        "\t\t\t  are (compressed) binary diffs in xxd format.\n"
        "\n"
        "\t\tThe default format is \"binary\".\n"
        "\n"
        "\t--help, -h\n"
        "\t\tPrint this message and exit.\n"
        "\n"
        "\t--no-warnings\n"
        "\t\tDo not print warning messages.\n"
        "\n"
        "\t--plt\n"
        "\t\tEnable the disassembly/rewriting of the .plt/.plt.got sections.\n"
        "\t\tThese sections are excluded by default.\n"
        "\n"
        "\t--plugin=NAME:OPTION\n"
        "\t\tPass OPTION to the plugin with NAME.  Here NAME must identify a\n"
        "\t\tplugin used by a matching or patching operation.\n"
        "\n"
        "\t-O0, -O1, -O2, -O3, -Os\n"
        "\t\tSet the optimization level.  Here:\n"
        "\n"
        "\t\t\t-O0 disables all optimization,\n"
        "\t\t\t-O1 conservatively optimizes for performance,\n"
        "\t\t\t-O2 optimizes for performance,\n"
        "\t\t\t-O3 aggressively optimizes for performance, and \n"
        "\t\t\t-Os optimizes for space.\n"
        "\n"
        "\t\tThe default is -O2.\n"
        "\n"
        "\t--option OPTION\n"
        "\t\tPass OPTION to the e9patch backend.\n"
        "\n"
        "\t--output FILE, -o FILE\n"
        "\t\tSpecifies the path to the output file.  The default filename is\n"
        "\t\tone of {\"a.out\", \"a.so\", \"a.exe\", \"a.dll\"}, depending on\n"
        "\t\tthe input binary type.\n"
        "\n"
        "\t--seed=SEED\n"
        "\t\tSet SEED to be the random number seed.\n"
        "\n"
        "\t--shared\n"
        "\t\tTreat the input file as a shared library, even if it appears to\n"
        "\t\tbe an executable.  By default, the input file will only be\n"
        "\t\ttreated as a shared library if (1) it is a dynamic executable\n"
        "\t\t(ET_DYN) and (2) has a filename of the form:\n"
        "\n"
        "\t\t\t[PATH/]lib*.so[.VERSION]\n"
        "\n"
        "\t--static-loader, -s\n"
        "\t\tReplace patched pages statically.  By default, patched pages\n"
        "\t\tare loaded during program initialization as this is more\n"
        "\t\treliable for large/complex binaries.  However, this may bloat\n"
        "\t\tthe size of the output patched binary.\n"
        "\n"
        "\t--syntax SYNTAX\n"
        "\t\tSelects the assembly syntax to be SYNTAX.  Possible values are:\n"
        "\n"
        "\t\t\t- \"ATT\"  : X86_64 ATT asm syntax; or\n"
        "\t\t\t- \"intel\": X86_64 Intel asm syntax.\n"
        "\n"
        "\t\tThe default syntax is \"ATT\".\n"
        "\n"
        "\t--trap=ADDR, --trap-all\n"
        "\t\tInsert a trap (int3) instruction at the corresponding\n"
        "\t\ttrampoline entry.  This can be used for debugging with gdb.\n"
        "\n", progname);
}

