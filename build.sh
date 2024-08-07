#!/bin/bash

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

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
(cd contrib/libdw; make clean; make -j `nproc`)
(cd contrib/zydis; make clean; make -j `nproc`)
make clean
make -j `nproc` tool release

echo -e "${GREEN}$0${OFF}: done...!"

