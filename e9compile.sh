#!/bin/sh
#
# Copyright (C) 2022 National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

if [ $# -lt 1 ]
then
    echo "${YELLOW}usage${OFF}: $0 file.c EXTRA_ARGS" >&2
    exit 1
fi

case "$1" in
    *.s)
        CC=gcc
        EXTENSION=s
        ;;
    *.c)
        CC=gcc
        EXTENSION=c
        ;;
    *.cpp)
        CC=g++
        EXTENSION=cpp
        ;;
    *)
        echo >&2
        echo "${RED}error${OFF}: file $1 must have a .c/.cpp/.s extension" >&2
        echo >&2
        exit 1
        ;;
esac
BASENAME=`basename $1 .$EXTENSION`
DIRNAME=`dirname $1`

shift

CFLAGS="-fno-stack-protector \
    -fpie -O2 -Wno-unused-function \
    -mno-mmx -mno-sse -mno-avx -mno-avx2 -mno-avx512f -msoft-float \
    -fno-tree-vectorize -fomit-frame-pointer \
    -I examples/"
COMPILE="$CC $CFLAGS -c -Wall $@ \"$DIRNAME/$BASENAME.$EXTENSION\""

echo "$COMPILE" | xargs
if ! eval "$COMPILE"
then
    echo >&2
    echo "${RED}error${OFF}: compilation of (${YELLOW}$BASENAME${OFF}) failed" >&2
    echo >&2
    exit 1
fi

CFLAGS="-pie -nostdlib \
    -Wl,-z -Wl,max-page-size=4096 \
    -Wl,-z -Wl,norelro \
    -Wl,-z -Wl,stack-size=0 \
    -Wl,--export-dynamic \
    -Wl,--entry=0x0 \
    -Wl,--strip-all"
COMPILE="$CC \"$BASENAME.o\" -o \"$BASENAME\" $CFLAGS"

echo "$COMPILE" | xargs
if ! eval "$COMPILE"
then
    echo >&2
    echo "${RED}error${OFF}: linking (${YELLOW}$BASENAME${OFF}) failed" >&2
    echo >&2
    exit 1
fi

RELOCS=`readelf -r "$BASENAME" | head -n 10 | grep 'R_X86_64_'`
if [ ! -z "$RELOCS" ]
then
    echo >&2
    echo "${RED}error${OFF}: the generated file (${YELLOW}$BASENAME${OFF}) contains relocations" >&2
    echo >&2
    echo "EXPLANATION:" >&2
    echo >&2
    echo "    E9Tool's call instrumentation does not support relocations.  These are" >&2
    echo "    usually caused by global variables that contain pointers, e.g.:" >&2
    echo >&2
    echo "      ${YELLOW}const char *days[] = {\"mon\", \"tue\", \"wed\", \"thu\", \"fri\", \"sat\", \"sun\"};${OFF}" >&2
    echo >&2
    echo "    Here, the global variable days[] is an array-of-pointers which usually" >&2
    echo "    results in relocations in the instrumentation binary.  Currently, E9Tool's" >&2
    echo "    call instrumentation does not apply relocations, meaning that the final" >&2
    echo "    patched binary using the instrumentation may crash." >&2
    echo >&2
    echo "    It may be possible to rewrite code to avoid relocations in exchange for" >&2
    echo "    extra padding, e.g.:" >&2
    echo >&2
    echo "      ${YELLOW}const char days[][4] = {\"mon\", \"tue\", \"wed\", \"thu\", \"fri\", \"sat\", \"sun\"};${OFF}" >&2
    echo >&2
    exit 1
fi

exit 0

