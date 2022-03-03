#CC=clang
#CXX=clang++

CXXFLAGS = -std=c++11 -Wall -Wno-reorder -fPIC -pie -march=native

E9PATCH_OBJS=\
    src/e9patch/e9alloc.o \
    src/e9patch/e9api.o \
    src/e9patch/e9elf.o \
    src/e9patch/e9emit.o \
    src/e9patch/e9json.o \
    src/e9patch/e9mapping.o \
    src/e9patch/e9patch.o \
    src/e9patch/e9optimize.o \
    src/e9patch/e9pe.o \
    src/e9patch/e9tactics.o \
    src/e9patch/e9trampoline.o \
    src/e9patch/e9x86_64.o

E9TOOL_OBJS=\
    src/e9tool/e9action.o \
    src/e9tool/e9cfg.o \
    src/e9tool/e9codegen.o \
    src/e9tool/e9csv.o \
    src/e9tool/e9frontend.o \
    src/e9tool/e9metadata.o \
    src/e9tool/e9misc.o \
    src/e9tool/e9parser.o \
    src/e9tool/e9tool.o \
    src/e9tool/e9types.o \
    src/e9tool/e9x86_64.o

release: CXXFLAGS += -O2 -D NDEBUG
release: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch $(LDFLAGS)
	strip e9patch

debug: CXXFLAGS += -O0 -g -fsanitize=address
debug: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch

tool: CXXFLAGS += -O2 -I src/e9tool/ -I zydis/include/ \
    -I zydis/dependencies/zycore/include/ -Wno-unused-function
tool: $(E9TOOL_OBJS) 
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) -o e9tool libZydis.a \
        -Wl,--dynamic-list=src/e9tool/e9tool.syms -ldl $(LDFLAGS)
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g -I src/e9tool/ -I zydis/include/ \
    -I zydis/dependencies/zycore/include/ -Wno-unused-function \
    -fsanitize=address
tool.debug: $(E9TOOL_OBJS)
	$(CXX) $(CXXFLAGS) $(E9TOOL_OBJS) -o e9tool libZydis.a \
        -Wl,--dynamic-list=src/e9tool/e9tool.syms -ldl

loader_elf:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -Wno-unused-function -fPIC \
        -Os -c src/e9patch/e9loader_elf.cpp
	$(CXX) -pie -nostdlib -o e9loader_elf.bin e9loader_elf.o -T e9loader.ld
	xxd -i e9loader_elf.bin > src/e9patch/e9loader_elf.c

loader_pe:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -Wno-unused-function -fPIC \
        -mabi=ms -fshort-wchar \
        -Os -c src/e9patch/e9loader_pe.cpp
	$(CXX) -pie -nostdlib -o e9loader_pe.bin e9loader_pe.o -T e9loader.ld
	xxd -i e9loader_pe.bin > src/e9patch/e9loader_pe.c

src/e9patch/e9elf.o: loader_elf
src/e9patch/e9pe.o: loader_pe

clean:
	rm -rf $(E9PATCH_OBJS) $(E9TOOL_OBJS) e9tool.o e9patch e9tool a.out \
        src/e9patch/e9loader.c e9loader.out e9loader.o e9loader.bin

