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

NAME=e9patch
VERSION=`cat VERSION`

set -e

./build.sh
rm -rf install/
mkdir -p install
mkdir -p install/data
mkdir -p install/control

DESTDIR=install/data make install

cd install/data
tar cz --owner root --group root -f ../data.tar.gz .
md5sum `find ../data/ -type f -printf "%P "` > ../control/md5sums

cd ../control/
cat << EOF > control
Package: ${NAME}
Version: ${VERSION}
Maintainer: Gregory J. Duck <gregory@comp.nus.edu.sg>
Section: universe/devel
Priority: optional
Homepage: https://github.com/GJDuck/e9patch
Architecture: amd64
Depends: libc6 (>= 2.14), zlib1g (>= 1:1.2.2.3)
Description: The E9Patch static binary rewriting system
 E9Patch is a powerful static rewriting system for stripped x86_64 Linux ELF
 and Windows PE binaries.  E9Patch is primarily designed for robustness, and
 can scale to very large/complex binaries without introducing rewriting
 errors.
 .
 This package also includes the E9Tool frontend for E9Patch.
EOF
tar cz --owner root --group root -f ../control.tar.gz control md5sums
cd ..
echo "2.0" > debian-binary
PACKAGE="${NAME}_${VERSION}_amd64.deb"
fakeroot ar cr "../${PACKAGE}" debian-binary control.tar.gz \
    data.tar.gz

echo -e "${GREEN}$0${OFF}: Successfully built ${YELLOW}${PACKAGE}${OFF}..."

