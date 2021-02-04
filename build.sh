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

VERSION=e3f106739a6ae78d47772dff31062d644ea21078

while [ $# -ge 1 ]
do
    case "$1" in
        --capstone)
            VERSION="$2"
            shift
            ;;
        --help|-h)
            echo "usage: $0 [OPTIONS]"
            echo
            echo "OPTIONS:"
            echo
            echo "    --capstone VERSION"
            echo "        Build using Capstone VERSION"
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

TARGET=`readlink capstone`
if [ "$TARGET" != "capstone-$VERSION" ]
then
    if [ ! -f capstone-$VERSION.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading capstone.zip..."
        wget -O capstone-$VERSION.zip \
            https://github.com/aquynh/capstone/archive/$VERSION.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting capstone-$VERSION.zip..."
    unzip capstone-$VERSION.zip
    rm -rf capstone
    ln -s capstone-$VERSION capstone

    echo -e "${GREEN}$0${OFF}: building capstone-$VERSION..."
    cd capstone
    CAPSTONE_ARCHS="x86" ./make.sh
    cd ..
fi

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make clean
make -j `nproc` tool release

echo -e "${GREEN}$0${OFF}: done...!"

