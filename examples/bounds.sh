#!/bin/bash

if [ $# != 1 ]
then
    echo "usage: $0 EXE" >&2
    exit 1
fi

EXE=`which "$1"`
if [ "$EXE" = "" ]
then
    echo "error: \"$1\" not found" >&2
    exit 1
fi

EXTRA=
TYPE=`file "$EXE" | grep executable`
if [ ! "$TYPE" = "" ]
then
    EXTRA="--option --mem-lb=0x400000 "
fi

echo $PIE

if [ ! -x bounds ]
then
    ./e9compile.sh examples/bounds.c
fi

echo "e9tool -M 'defined(mem[0]) and mem[0].access in {r,w,rw} and mem[0].seg == nil and mem[0].base != nil and mem[0].base != %rsp and mem[0].base != %rip' -P 'check((static)addr, mem[0].base, &mem[0], mem[0].size, asm)@bounds' $EXTRA\"$EXE\""

./e9tool -M 'defined(mem[0]) and
             mem[0].access in {r,w,rw} and
             mem[0].seg == nil and
             mem[0].base != nil and
             mem[0].base != %rsp and
             mem[0].base != %rip' \
         -P 'check((static)addr,
                   mem[0].base,
                   &mem[0],
                   mem[0].size,
                   asm)@bounds' \
         $EXTRA$EXE

echo
echo "usage: LD_PRELOAD=/usr/share/redfat/libredfat.so ./a.out ..."
echo

