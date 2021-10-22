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

TARGET=`readlink zydis`
if [ ! -d zydis ]
then
    ZYDIS_VERSION=6a17c48576e1b016ce098c4bdbd001a1403b6a0a
    ZYCORE_VERSION=4f3746faa1d19a14857ea7d1495c2ab006103698

    echo -e "${GREEN}$0${OFF}: downloading zydis-$ZYDIS_VERSION.zip..."
    wget -O zydis-$ZYDIS_VERSION.zip https://github.com/zyantific/zydis/archive/$ZYDIS_VERSION.zip

    echo -e "${GREEN}$0${OFF}: downloading zycore-$ZYCORE_VERSION.zip..."
    wget -O zycore-$ZYCORE_VERSION.zip https://github.com/zyantific/zycore-c/archive/$ZYCORE_VERSION.zip

    echo -e "${GREEN}$0${OFF}: extracting zydis-$ZYDIS_VERSION.zip..."
    unzip zydis-$ZYDIS_VERSION.zip
    rm -f zydis-$ZYDIS_VERSION.zip

    echo -e "${GREEN}$0${OFF}: extracting zycore-$ZYCORE_VERSION.zip..."
    unzip zycore-$ZYCORE_VERSION.zip
    rm -f zycore-$ZYCORE_VERSION.zip

    echo -e "${GREEN}$0${OFF}: building Zydis..."
    mv zydis-$ZYDIS_VERSION zydis/
    rm -rf zydis/dependencies/zycore/
    mv zycore-c-$ZYCORE_VERSION zydis/dependencies/zycore/
    rm -rf zycore-c-$ZYCORE_VERSION
	cat << EOF > zydis/include/ZydisExportConfig.h
#ifndef ZYDIS_EXPORT_H
#define ZYDIS_EXPORT_H
#define ZYDIS_EXPORT
#define ZYDIS_NO_EXPORT
#define ZYDIS_DEPRECATED __attribute__ ((__deprecated__))
#define ZYDIS_DEPRECATED_EXPORT ZYDIS_EXPORT ZYDIS_DEPRECATED
#define ZYDIS_DEPRECATED_NO_EXPORT ZYDIS_NO_EXPORT ZYDIS_DEPRECATED
#define ZYDIS_NO_DEPRECATED
#endif
EOF
	cat << EOF > zydis/include/ZycoreExportConfig.h
#ifndef ZYCORE_EXPORT_H
#define ZYCORE_EXPORT_H
#define ZYCORE_EXPORT
#define ZYCORE_NO_EXPORT
#define ZYCORE_DEPRECATED __attribute__ ((__deprecated__))
#define ZYCORE_DEPRECATED_EXPORT ZYCORE_EXPORT ZYCORE_DEPRECATED
#define ZYCORE_DEPRECATED_NO_EXPORT ZYCORE_NO_EXPORT ZYCORE_DEPRECATED
#define ZYCORE_NO_DEPRECATED
#endif
EOF
    make -f Makefile.zydis -j `nproc`
fi

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make clean
make -j `nproc` tool release

echo -e "${GREEN}$0${OFF}: done...!"

