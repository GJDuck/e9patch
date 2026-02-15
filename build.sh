#!/bin/bash
#
# Copyright (C) National University of Singapore
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
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BOLD='\033[1m'
    OFF='\033[0m'
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

check_cmd()
{
    if which $1 >/dev/null 2>&1
    then
        return
    fi
    echo -e "${RED}error${OFF}: building E9Tool/E9Patch requires \"${YELLOW}$1${OFF}\"" >&2
    echo -e "       (hint: try installing \"${YELLOW}$1${OFF}\" with \"${YELLOW}sudo apt install $2${OFF}\")" >&2
    exit 1
}

check_hdr()
{
    if echo "#include <$1>" | gcc -E - >/dev/null 2>&1
    then
        return
    fi
    echo -e "${RED}error${OFF}: building E9Tool/E9Patch requires \"${YELLOW}$1${OFF}\"" >&2
    echo -e "       (hint: try installing \"${YELLOW}$1${OFF}\" with \"${YELLOW}sudo apt install $2${OFF}\"" >&2
    exit 1
}

check_cmd gcc      build-essential
check_cmd g++      build-essential
check_cmd make     build-essential
check_cmd ar       build-essential
check_cmd ld       build-essential
check_cmd strip    build-essential
check_cmd xxd      xxd
check_cmd markdown markdown
check_hdr zlib.h   zlib1g-dev

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make clean
make -j$(nproc) release

echo -e "${GREEN}$0${OFF}: done...!"
