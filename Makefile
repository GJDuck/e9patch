#CC=clang
#CXX=clang++

CXXFLAGS = -std=c++11 -Wall -Wno-reorder -fPIC -pie -march=haswell

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

E9TOOL_SRC=\
    src/e9tool/e9cfg.cpp \
    src/e9tool/e9csv.cpp \
    src/e9tool/e9frontend.cpp \
    src/e9tool/e9metadata.cpp \
    src/e9tool/e9parser.cpp \
    src/e9tool/e9tool.cpp \
    src/e9tool/e9types.cpp \
    src/e9tool/e9x86_64.cpp 

release: CXXFLAGS += -O2 -D NDEBUG
release: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch
	strip e9patch

debug: CXXFLAGS += -O0 -g -fsanitize=address
debug: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch

e9tool.o: $(E9TOOL_SRC)
	$(CXX) $(CXXFLAGS) -c src/e9tool/e9tool.cpp

tool: CXXFLAGS += -O2 -I src/e9tool/ -I zydis/include/ \
    -I zydis/dependencies/zycore/include/ -Wno-unused-function
tool: e9tool.o
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool libZydis.a \
        -Wl,--export-dynamic -ldl
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g -I src/e9tool/ -I zydis/include/ \
    -I zydis/dependencies/zycore/include/ -Wno-unused-function \
    -fsanitize=address
tool.debug: e9tool.o
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool libZydis.a \
        -Wl,--export-dynamic -ldl

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

src/e9patch/e9alloc.o: CXXFLAGS += -Wno-unused-function

src/e9patch/e9elf.o: loader_elf
src/e9patch/e9pe.o: loader_pe

clean:
	rm -rf $(E9PATCH_OBJS) e9tool.o e9patch e9tool a.out \
        src/e9patch/e9loader.c e9loader.out e9loader.o e9loader.bin

