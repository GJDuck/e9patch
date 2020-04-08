#!/bin/sh

if [ $# -lt 1 ]
then
    echo "usage: $0 file.c EXTRA_ARGS" >&2
    exit 1
fi

CC=gcc
DIRNAME=`dirname $1`
BASENAME=`basename $1 .c`

shift

set -e
set -x

$CC -fno-stack-protector -fpie -O2 -c -Wall $@ "$DIRNAME/$BASENAME.c"
$CC "$BASENAME.o" -o $BASENAME -pie -nostdlib -Wl,-z -Wl,max-page-size=4096 \
    -Wl,--export-dynamic -Wl,--entry=0x0 -Wl,--strip-all

