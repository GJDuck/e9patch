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

echo -e "${GREEN}$0${OFF}: building e9patch and e9tool..."
make clean
make -j$(nproc) release

echo -e "${GREEN}$0${OFF}: done...!"
