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

while [ $# -ge 1 ]
do
    case "$1" in
        --help|-h)
            echo "usage: $0 [OPTIONS]"
            echo
            echo "OPTIONS:"
            echo
            echo "    --help, -h"
            echo "        Print this message"
            echo
            exit 0
            ;;
        *)
            echo "unknown argument \"$1\"; try \`$0 --help' for more information"
            exit 1
            ;;
    esac
    shift
done

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make tool.clean clean
make -j `nproc` tool release

echo -e "${GREEN}$0${OFF}: done...!"

