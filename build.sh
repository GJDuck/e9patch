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

if [ ! -d capstone ]
then
    if [ ! -f capstone.zip ]
    then
        echo -e "${GREEN}$0${OFF}: downloading capstone.zip..."
        wget -O capstone.zip \
            https://github.com/aquynh/capstone/archive/4.0.2.zip
    fi

    echo -e "${GREEN}$0${OFF}: extracting capstone.zip..."
    unzip capstone.zip
    mv capstone-4.0.2 capstone

    echo -e "${GREEN}$0${OFF}: building capstone.zip..."
    cd capstone
    CAPSTONE_ARCHS="x86" ./make.sh
    cd ..
fi

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make clean
make -j `nproc` tool release

echo -e "${GREEN}$0${OFF}: done...!"

