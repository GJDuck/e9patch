#CC=clang
#CXX=clang++

CXXFLAGS = -std=c++11 -Wall -Wno-reorder -fPIC -pie -march=native \
    -DVERSION=$(shell cat VERSION) -Wl,-rpath=/usr/share/e9tool/lib/

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
    -I contrib/libdw/ \
    -I contrib/zydis/include/ \
    -I contrib/zydis/dependencies/zycore/include/
E9TOOL_LDFLAGS=\
    -Wl,--dynamic-list=src/e9tool/e9tool.syms \
    -lpthread -ldl -lz

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

tool: CXXFLAGS += -O2 $(E9TOOL_CXXFLAGS)
tool: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS) -Wl,-Map=output.map
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g $(E9TOOL_CXXFLAGS)
tool.debug: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS)

tool.sanitize: CXXFLAGS += -O0 -g -fsanitize=address $(E9TOOL_CXXFLAGS)
tool.sanitize: $(E9TOOL_OBJS) $(E9TOOL_LIBS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) $(E9TOOL_LIBS) -o e9tool \
        $(E9TOOL_LDFLAGS)

tool.clean:
	rm -rf $(E9TOOL_OBJS) e9tool

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

clean:
	rm -rf $(E9PATCH_OBJS) e9patch \
        src/e9patch/e9loader.c e9loader.out e9loader.o e9loader.bin

