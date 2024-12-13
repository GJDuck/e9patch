.PHONY: all clean install dev release debug sanitize
.SECONDEXPANSION:

#########################################################################
# BUILD COMMON
#########################################################################

PREFIX ?= /usr
CXXFLAGS ?= -march=native
CXXFLAGS += -std=c++11 -Wall -Wno-reorder -fPIC -pie \
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

E9TOOL_LIBS ::=
E9TOOL_CXXFLAGS ::= -Isrc/e9tool -Wno-unused-function
E9TOOL_LDFLAGS ::= -Wl,--dynamic-list=src/e9tool/e9tool.syms
E9TOOL_LDLIBS ::= -ldl -lz

BIN ::= e9tool e9patch e9compile
INCLUDE ::= src/e9tool/e9tool.h src/e9tool/e9plugin.h
MAN1 ::= $(wildcard doc/*.1)
DOC ::= $(wildcard doc/e9*.md)
EXAMPLE ::= $(wildcard examples/*.sh examples/*.c examples/*.cpp \
	examples/plugins/*.cpp)
INSTALL = $(DESTDIR)$(PREFIX)/share/doc/e9patch/LICENSE \
	$(BIN:%=$(DESTDIR)$(PREFIX)/bin/%) \
	$(DESTDIR)$(PREFIX)/share/e9compile/include/e9loader.h \
	$(INCLUDE:src/%.h=$(DESTDIR)$(PREFIX)/include/%.h) \
	$(MAN1:%.1=$(DESTDIR)$(PREFIX)/share/man/man1/%.1) \
	$(DOC:doc/%.md=$(DESTDIR)$(PREFIX)/share/doc/e9patch/%.html) \
	$(EXAMPLE:%=$(DESTDIR)$(PREFIX)/share/e9tool/%)

#########################################################################
# CONVENTIONAL BUILD
#########################################################################

all: CXXFLAGS += -DSYSTEM_LIBDW
all: E9TOOL_LDLIBS += -ldw -lZydis
all: e9tool e9patch

e9tool: CXXFLAGS += $(E9TOOL_CXXFLAGS)
e9tool: LDFLAGS += $(E9TOOL_LDFLAGS)
e9tool: LDLIBS += $(E9TOOL_LIBS) $(E9TOOL_LDLIBS)
e9tool: $(E9TOOL_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

e9patch: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(MAKE) -C contrib/libdw clean
	$(MAKE) -C contrib/zydis clean
	rm -rf $(E9PATCH_OBJS) $(E9TOOL_OBJS) e9patch e9tool \
        src/e9patch/e9loader_*.c e9loader_*.o e9loader_*.bin

src/e9patch/e9loader_elf.c: src/e9patch/e9loader_elf.cpp
	$(CXX) -std=c++11 -Wall -fno-stack-protector -Wno-unused-function -fPIC \
        -Os -c $<
	$(CXX) -pie -nostdlib -o e9loader_elf.bin e9loader_elf.o -T e9loader.ld
	xxd -i e9loader_elf.bin > $@

src/e9patch/e9loader_pe.c: src/e9patch/e9loader_pe.cpp
	$(CXX) -std=c++11 -Wall -fno-stack-protector -fno-zero-initialized-in-bss \
        -Wno-unused-function -fPIC -mabi=ms -fshort-wchar -Os -c $<
	$(CXX) -pie -nostdlib -o e9loader_pe.bin e9loader_pe.o -T e9loader.ld
	xxd -i e9loader_pe.bin > $@

src/e9patch/e9elf.o: src/e9patch/e9loader_elf.c
src/e9patch/e9pe.o: src/e9patch/e9loader_pe.c

install: $(INSTALL)

$(DESTDIR)$(PREFIX)/share/doc/e9patch/LICENSE: LICENSE
	install -Dm 644 $< "$@"

e9compile: e9compile.sh
	sed 's#-I examples#-I $(PREFIX)/share/e9compile/include#g' $< > $@

$(DESTDIR)$(PREFIX)/bin/%: %
	install -Dm 755 $< "$@"

$(DESTDIR)$(PREFIX)/share/e9compile/include/e9loader.h: src/e9patch/e9loader.h
	install -Dm 644 $< "$@"

$(DESTDIR)$(PREFIX)/include/%.h: src/%.h
	install -Dm 644 $< "$@"

$(DESTDIR)$(PREFIX)/share/man/man1/%.1: %.1
	install -Dm 644 $< "$@"

$(DESTDIR)$(PREFIX)/share/doc/e9patch/%.html: doc/%.md
	install -d $(DESTDIR)$(PREFIX)/share/doc/e9patch
	sed \
		-e 's#https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md#file://$(PREFIX)/share/doc/e9patch/e9patch-programming-guide.html#g' \
		-e 's#https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md#file://$(PREFIX)/share/doc/e9tool/e9tool-user-guide.html#g' \
		-e 's#https://github.com/GJDuck/e9patch/tree/master/examples#file://$(PREFIX)/share/e9tool/examples#g' \
		$< | markdown > $@

$(DESTDIR)$(PREFIX)/share/e9tool/examples/%.c: examples/%.c
	install -Dm 644 $< "$@"

$(DESTDIR)$(PREFIX)/share/e9tool/examples/%.cpp: examples/%.cpp
	install -Dm 644 $< "$@"

$(DESTDIR)$(PREFIX)/share/e9tool/examples/bounds.sh: examples/bounds.sh
	install -Dm 755 $< "$@"
	sed \
		-e 's#\./e9compile.sh examples/bounds.c#e9compile $(PREFIX)/share/e9tool/examples/bounds.c#' \
		-e 's#\./e9tool#e9tool#' \
		-i "$@"

uninstall:
	rm -fr $(INSTALL)

#########################################################################
# SPECIAL BUILD
#########################################################################

contrib/zydis/libZydis.a:
	$(MAKE) -C contrib/zydis

contrib/libdw/libdw.a:
	$(MAKE) -C contrib/libdw

dev: E9TOOL_CXXFLAGS += -Icontrib/libdw \
	-Icontrib/zydis/include -Icontrib/zydis/dependencies/zycore/include
dev: E9TOOL_LIBS += contrib/zydis/libZydis.a contrib/libdw/libdw.a
dev: contrib/zydis/libZydis.a contrib/libdw/libdw.a e9patch e9tool

release: CXXFLAGS += -O2 -DNDEBUG
release: dev
	strip e9patch e9tool

debug: CXXFLAGS += -O0 -g
debug: dev

sanitize: CXXFLAGS += -O0 -g -fsanitize=address
sanitize: dev
