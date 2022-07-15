#!/bin/bash
#
# Copyright (C) 2022 National University of Singapore
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

NAME=e9patch
VERSION=`cat VERSION`

if [ ! -x e9patch ]
then
    echo -e "${RED}$0${OFF}: run ./build.sh first" 1>&2
    exit 1
fi

set -e

rm -rf install/
mkdir -p install
cd install/
mkdir -p data
mkdir -p control

cd data/
mkdir -p "./usr/bin/"
cp "../../e9patch"      "./usr/bin/"
cp "../../e9tool"       "./usr/bin/"
cat "../../e9compile.sh" | \
    sed 's/-I examples/-I \/usr\/share\/e9compile\/include/g' > \
    "./usr/bin/e9compile"
chmod a+x "./usr/bin/e9compile"
mkdir -p "./usr/share/doc/e9patch/"
cat "../../doc/e9patch-programming-guide.md" | \
    sed 's/https:\/\/github.com\/GJDuck\/e9patch\/blob\/master\/doc\/e9tool-user-guide.md/file:\/\/\/usr\/share\/doc\/e9tool\/e9tool-user-guide.html/g' | \
    sed 's/https:\/\/github.com\/GJDuck\/e9patch\/tree\/master\/examples/file:\/\/\/usr\/share\/e9tool\/examples/g' | \
    markdown > "./usr/share/doc/e9patch/e9patch-programming-guide.html"
cp "../../LICENSE" "./usr/share/doc/e9patch/"
mkdir -p "./usr/share/doc/e9tool/"
cat "../../doc/e9tool-user-guide.md" | \
    sed 's/https:\/\/github.com\/GJDuck\/e9patch\/blob\/master\/doc\/e9patch-programming-guide.md/file:\/\/\/usr\/share\/doc\/e9patch\/e9patch-programming-guide.html/g' | \
    markdown > "./usr/share/doc/e9tool/e9tool-user-guide.html"
cp "../../LICENSE" "./usr/share/doc/e9tool/"
mkdir -p "./usr/share/e9tool/include/"
cp "../../src/e9tool/e9tool.h" "./usr/share/e9tool/include/"
cp "../../src/e9tool/e9plugin.h" "./usr/share/e9tool/include/"
mkdir -p "./usr/share/e9tool/examples/"
cp "../../examples/args.c" "./usr/share/e9tool/examples/"
cp "../../examples/counter.c" "./usr/share/e9tool/examples/"
cp "../../examples/delay.c" "./usr/share/e9tool/examples/"
cp "../../examples/hello.c" "./usr/share/e9tool/examples/"
cp "../../examples/io.c" "./usr/share/e9tool/examples/"
cp "../../examples/limit.c" "./usr/share/e9tool/examples/"
cp "../../examples/nop.c" "./usr/share/e9tool/examples/"
cp "../../examples/print.c" "./usr/share/e9tool/examples/"
cp "../../examples/state.c" "./usr/share/e9tool/examples/"
cp "../../examples/trap.c" "./usr/share/e9tool/examples/"
cp "../../examples/win64_demo.c" "./usr/share/e9tool/examples/"
mkdir -p "./usr/share/e9tool/examples/plugins/"
cp "../../examples/plugins/example.cpp" "./usr/share/e9tool/examples/plugins/"
mkdir -p "./usr/share/e9compile/include/"
cp "../../examples/stdlib.c" "./usr/share/e9compile/include/"
cp "../../examples/rbtree.c" "./usr/share/e9compile/include/"
cp "../../src/e9patch/e9loader.h" "./usr/share/e9compile/include/"
mkdir -p "./usr/share/man/man1/"
gzip --stdout ../../doc/e9patch.1   > ./usr/share/man/man1/e9patch.1.gz
gzip --stdout ../../doc/e9tool.1    > ./usr/share/man/man1/e9tool.1.gz
gzip --stdout ../../doc/e9compile.1 > ./usr/share/man/man1/e9compile.1.gz
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
Depends: libc6 (>= 2.14)
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

