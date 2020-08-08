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

set -e
mkdir -p tmp
./e9compile.sh examples/nop.c >/dev/null 2>&1 

for ACTION in \
    '=.*:passthru' \
    '=.*:call entry@nop' \
    '=.*:call[naked,after] entry@nop' \
    '=.*:call entry(asmStr,instr,rflags,rdi,rip,addr)@nop' \
    '=.*:print'
do
    # Step (1): duplicate the tools
    ./e9tool ./e9tool  "--action=$ACTION" -o tmp/e9tool.patched  -c 6 -s \
        >/dev/null 2>&1
    ./e9tool ./e9patch "--action=$ACTION" -o tmp/e9patch.patched -c 6 -s \
        >/dev/null 2>&1
    
    # Step (2): duplicate the tools with the duplicated tools
    tmp/e9tool.patched --backend "$PWD/tmp/e9patch.patched" \
        ./e9tool  "--action=$ACTION" -o tmp/e9tool.2.patched  -c 6 -s \
        >/dev/null 2>&1
    tmp/e9tool.patched --backend "$PWD/tmp/e9patch.patched" \
        ./e9patch "--action=$ACTION" -o tmp/e9patch.2.patched  -c 6 -s \
        >/dev/null 2>&1
    
    # Step (3): Everything should be the same:
    if diff tmp/e9tool.patched tmp/e9tool.2.patched > /dev/null
    then
        echo -e "${GREEN}PASSED${OFF}: e9tool  ${YELLOW}$ACTION${OFF}"
    else
        echo -e "${RED}FAILED${OFF}: e9tool  ${YELLOW}$ACTION${OFF}"
    fi
    if diff tmp/e9patch.patched tmp/e9patch.2.patched > /dev/null
    then
        echo -e "${GREEN}PASSED${OFF}: e9patch ${YELLOW}$ACTION${OFF}"
    else
        echo -e "${RED}FAILED${OFF}: e9patch ${YELLOW}$ACTION${OFF}"
    fi
done

