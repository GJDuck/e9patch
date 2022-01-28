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
../../e9compile.sh ../../examples/nop.c >/dev/null 2>&1 

# Setup the example.so plugin
g++ -std=c++11 -fPIC -shared -o example.so -O2 \
    ../../examples/plugins/example.cpp -I ../../src/e9tool/ 

runtest()
{
    MATCH=$1
    PATCH=$2
    EXTRA=$3

    # Step (1): duplicate the tools
    if ! ../../e9tool ../../e9tool "--match=$MATCH" "--patch=$PATCH" $EXTRA \
            -o tmp/e9tool.patched  -c 6 -s >/dev/null 2>&1
    then
       echo -e "${RED}FAILED${OFF}: e9tool  ${YELLOW}-M $MATCH -P $PATCH${OFF} [step (1)]"
       continue
    fi
    if ! ../../e9tool ../../e9patch "--match=$MATCH" "--patch=$PATCH" $EXTRA \
            -o tmp/e9patch.patched -c 6 -s >/dev/null 2>&1
    then
        echo -e "${RED}FAILED${OFF}: e9patch ${YELLOW}-M $MATCH -P $PATCH${OFF} [step (1)]"
        continue
    fi
 
    # Step (2): duplicate the tools with the duplicated tools
    if ! tmp/e9tool.patched --backend "$PWD/tmp/e9patch.patched" \
            ../../e9tool  "--match=$MATCH" "--patch=$PATCH" $EXTRA \
            -o tmp/e9tool.2.patched -c 6 -s >/dev/null 2>&1
    then
        echo -e "${RED}FAILED${OFF}: e9tool  ${YELLOW}-M $MATCH -P $PATCH${OFF} [step (2)]"
        continue;
    fi
    if !  tmp/e9tool.patched --backend "$PWD/tmp/e9patch.patched" \
            ../../e9patch "--match=$MATCH" "--patch=$PATCH" $EXTRA \
            -o tmp/e9patch.2.patched -c 6 -s >/dev/null 2>&1
    then
        echo -e "${RED}FAILED${OFF}: e9patch ${YELLOW}-M $MATCH -P $PATCH${OFF} [step (2)]"
        continue
    fi
    
    # Step (3): Everything should be the same:
    if diff tmp/e9tool.patched tmp/e9tool.2.patched > /dev/null
    then
        echo -e "${GREEN}PASSED${OFF}: e9tool  ${YELLOW}-M $MATCH -P $PATCH${OFF}"
    else
        echo -e "${RED}FAILED${OFF}: e9tool  ${YELLOW}-M $MATCH -P $PATCH${OFF}"
    fi
    if diff tmp/e9patch.patched tmp/e9patch.2.patched > /dev/null
    then
        echo -e "${GREEN}PASSED${OFF}: e9patch ${YELLOW}-M $MATCH -P $PATCH${OFF}"
    else
        echo -e "${RED}FAILED${OFF}: e9patch ${YELLOW}-M $MATCH -P $PATCH${OFF}"
    fi
}

runtest true empty
runtest true 'entry<naked>()@nop'
runtest true 'entry(asm,instr,rflags,rdi,rip,addr,target,next)@nop'
runtest true 'entry(&rsp,&rax,&rsi,&rdi,&r8,&r15,static addr,0x1234)@nop'
runtest true 'entry(BB,F,BB.size,F.size,BB.offset,F.offset,BB.len,F.name)@nop'
runtest true 'entry(&op[0],&src[0],&dst[0],&op[1],&src[1],&dst[1],&dst[7],&src[7])@nop'
runtest true 'entry(reg[0],&reg[0],imm[0],&imm[0],&mem[0],reg[1],&reg[1],imm[1])@nop'
runtest 'plugin(example).match()' 'plugin(example).patch()' '--plugin=example:-limit=99999999999'
runtest true print

