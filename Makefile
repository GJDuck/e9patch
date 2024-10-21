#########################################################################
# BUILD COMMON
#########################################################################

PREFIX ?= /usr
CXXFLAGS = -std=c++11 -Wall -Wno-reorder -fPIC -pie -march=native \
    -DVERSION=$(shell cat VERSION) -Wl,-rpath=$(PREFIX)/share/e9tool/lib/

E9PATCH_OBJS=\
    src/e9patch/e9CFR.o \
    src/e9patch/e9alloc.o \
    src/e9patch/e9api.o \
    src/e9patch/e9elf.o \
    src/e9patch/e9emit.o \
    src/e9patch/e9json.o \
    src/e9patch/e9mapping.o \
    src/e9patch/e9misc.o \
    src/e9patch/e9optimize.o \
    src/e9patch/e9patch.o \
    src/e9patch/e9pe.o \
    src/e9patch/e9tactics.o \
    src/e9patch/e9trampoline.o \
    src/e9patch/e9x86_64.o

E9TOOL_OBJS=\
    src/e9tool/e9action.o \
    src/e9tool/e9cfg.o \
    src/e9tool/e9codegen.o \
    src/e9tool/e9csv.o \
    src/e9tool/e9dwarf.o \
    src/e9tool/e9frontend.o \
    src/e9tool/e9metadata.o \
    src/e9tool/e9misc.o \
    src/e9tool/e9parser.o \
    src/e9tool/e9tool.o \
    src/e9tool/e9types.o \
    src/e9tool/e9x86_64.o
E9TOOL_LIBS=\
    contrib/zydis/libZydis.a \
    contrib/libdw/libdw.a
E9TOOL_CXXFLAGS=\
    -I src/e9tool/ -Wno-unused-function \
    -I contrib/zydis/include/ \
    -I contrib/zydis/dependencies/zycore/include/
E9TOOL_LDFLAGS=\
    -Wl,--dynamic-list=src/e9tool/e9tool.syms \
    -ldl -lz

#########################################################################
# CONVENTIONAL BUILD
#########################################################################

all: e9tool e9patch

e9tool: CXXFLAGS += -O2 -DSYSTEM_LIBDW $(E9TOOL_CXXFLAGS)
e9tool: contrib/zydis/libZydis.a $(E9TOOL_OBJS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) contrib/zydis/libZydis.a -o e9tool \
	    $(E9TOOL_LDFLAGS) -ldw
	strip e9tool

e9patch: CXXFLAGS += -O2 
e9patch: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch
	strip e9patch

clean:
	rm -rf $(E9PATCH_OBJS) $(E9TOOL_OBJS) e9patch e9tool \
        src/e9patch/e9loader.c e9loader.out e9loader.o e9loader.bin

loader_elf:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -Wno-unused-function -fPIC \
        -Os -c src/e9patch/e9loader_elf.cpp
	$(CXX) -pie -nostdlib -o e9loader_elf.bin e9loader_elf.o -T e9loader.ld
	xxd -i e9loader_elf.bin > src/e9patch/e9loader_elf.c

loader_pe:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -fno-zero-initialized-in-bss \
        -Wno-unused-function -fPIC -mabi=ms -fshort-wchar \
        -Os -c src/e9patch/e9loader_pe.cpp
	$(CXX) -pie -nostdlib -o e9loader_pe.bin e9loader_pe.o -T e9loader.ld
	xxd -i e9loader_pe.bin > src/e9patch/e9loader_pe.c

src/e9patch/e9elf.o: loader_elf
src/e9patch/e9pe.o: loader_pe

contrib/zydis/libZydis.a:
	(cd contrib/zydis/; make)

contrib/libdw/libdw.a:
	(cd contrib/libdw/; make)

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 e9patch "$(DESTDIR)$(PREFIX)/bin/e9patch"
	install -m 755 e9tool "$(DESTDIR)$(PREFIX)/bin/e9tool"
	install -m 755 e9compile.sh "$(DESTDIR)$(PREFIX)/bin/e9compile"
	sed \
	    -e 's/-I examples/-I \$(PREFIX)\/share\/e9compile\/include/g' e9compile.sh > \
	    "$(DESTDIR)$(PREFIX)/bin/e9compile"
	chmod 555 "$(DESTDIR)$(PREFIX)/bin/e9compile"
	install -d "$(DESTDIR)$(PREFIX)/share/doc/e9patch/"
	sed \
	    -e 's/https:\/\/github.com\/GJDuck\/e9patch\/blob\/master\/doc\/e9tool-user-guide.md/file:\/\/\$(PREFIX)\/share\/doc\/e9tool\/e9tool-user-guide.html/g' \
	    -e 's/https:\/\/github.com\/GJDuck\/e9patch\/tree\/master\/examples/file:\/\/\$(PREFIX)\/share\/e9tool\/examples/g' \
		doc/e9patch-programming-guide.md | markdown > \
	    "$(DESTDIR)$(PREFIX)/share/doc/e9patch/e9patch-programming-guide.html"
	install -m 444 LICENSE "$(DESTDIR)$(PREFIX)/share/doc/e9patch/LICENSE"
	install -d "$(DESTDIR)$(PREFIX)/share/doc/e9tool/"
	sed \
        -e 's/https:\/\/github.com\/GJDuck\/e9patch\/blob\/master\/doc\/e9patch-programming-guide.md/file:\/\/\$(PREFIX)\/share\/doc\/e9patch\/e9patch-programming-guide.html/g' \
        doc/e9tool-user-guide.md | markdown > \
        "$(DESTDIR)$(PREFIX)/share/doc/e9tool/e9tool-user-guide.html"
	install -m 444 LICENSE "$(DESTDIR)$(PREFIX)/share/doc/e9tool/LICENSE"
	install -d "$(DESTDIR)$(PREFIX)/share/e9tool/include/"
	install -m 444 src/e9tool/e9tool.h "$(DESTDIR)$(PREFIX)/share/e9tool/include/e9tool.h"
	install -m 444 src/e9tool/e9plugin.h "$(DESTDIR)$(PREFIX)/share/e9tool/include/e9plugin.h"
	install -d "$(DESTDIR)$(PREFIX)/share/e9tool/examples/"
	install -m 444 examples/bounds.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/bounds.c"
	sed \
	    -e 's/.\/e9compile.sh examples\/bounds.c/e9compile \$(PREFIX)\/share\/e9tool\/examples\/bounds.c/' \
	    -e 's/\.\/e9tool/e9tool/' \
        examples/bounds.sh > \
	    "$(DESTDIR)$(PREFIX)/share/e9tool/examples/bounds.sh"
	chmod 555 "$(DESTDIR)$(PREFIX)/share/e9tool/examples/bounds.sh"
	install -m 444 examples/cfi.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/cfi.c"
	install -m 444 examples/count.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/count.c"
	install -m 444 examples/cov.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/cov.c"
	install -m 444 examples/delay.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/delay.c"
	install -m 444 examples/hello.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/hello.c"
	install -m 444 examples/limit.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/limit.c"
	install -m 444 examples/nop.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/nop.c"
	install -m 444 examples/print.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/print.c"
	install -m 444 examples/printf.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/printf.c"
	install -m 444 examples/skip.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/skip.c"
	install -m 444 examples/state.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/state.c"
	install -m 444 examples/trap.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/trap.c"
	install -m 444 examples/win64_demo.c "$(DESTDIR)$(PREFIX)/share/e9tool/examples/win64_demo.c"
	install -d "$(DESTDIR)$(PREFIX)/share/e9tool/examples/plugins/"
	install -m 444 examples/plugins/example.cpp "$(DESTDIR)$(PREFIX)/share/e9tool/examples/plugins/example.cpp"
	install -d "$(DESTDIR)$(PREFIX)/share/e9compile/include/"
	install -m 444 examples/stdlib.c "$(DESTDIR)$(PREFIX)/share/e9compile/include/stdlib.c"
	install -m 444 src/e9patch/e9loader.h "$(DESTDIR)$(PREFIX)/share/e9compile/include/e9loader.h"
	install -d "$(DESTDIR)$(PREFIX)/share/man/man1/"
	gzip --stdout doc/e9patch.1 > "$(DESTDIR)$(PREFIX)/share/man/man1/e9patch.1.gz"
	chmod 444 "$(DESTDIR)$(PREFIX)/share/man/man1/e9patch.1.gz"
	gzip --stdout doc/e9tool.1 > "$(DESTDIR)$(PREFIX)/share/man/man1/e9tool.1.gz"
	chmod 444 "$(DESTDIR)$(PREFIX)/share/man/man1/e9tool.1.gz"
	gzip --stdout doc/e9compile.1 > "$(DESTDIR)$(PREFIX)/share/man/man1/e9compile.1.gz"
	chmod 444 "$(DESTDIR)$(PREFIX)/share/man/man1/e9compile.1.gz"

#########################################################################
# SPECIAL BUILD
#########################################################################

release: CXXFLAGS += -O2 -D NDEBUG
release: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch
	strip e9patch

debug: CXXFLAGS += -O0 -g
debug: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch

sanitize: CXXFLAGS += -O0 -g -fsanitize=address
sanitize: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch

tool: CXXFLAGS += -O2 $(E9TOOL_CXXFLAGS) -I contrib/libdw/
tool: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS)
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g $(E9TOOL_CXXFLAGS) -I contrib/libdw/
tool.debug: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS)

tool.sanitize: CXXFLAGS += -O0 -g -fsanitize=address $(E9TOOL_CXXFLAGS) \
	-I contrib/libdw/
tool.sanitize: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS)

