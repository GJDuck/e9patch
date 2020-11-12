#CC=clang
#CXX=clang++

CXXFLAGS = -std=c++14 -Wall -Wno-reorder -fPIC -pie

E9PATCH_OBJS=\
    src/e9patch/e9alloc.o \
    src/e9patch/e9api.o \
    src/e9patch/e9elf.o \
    src/e9patch/e9emit.o \
    src/e9patch/e9json.o \
    src/e9patch/e9mapping.o \
    src/e9patch/e9patch.o \
    src/e9patch/e9tactics.o \
    src/e9patch/e9trampoline.o \
    src/e9patch/e9x86_64.o

E9TOOL_SRC=\
    src/e9tool/e9csv.cpp \
    src/e9tool/e9frontend.cpp \
    src/e9tool/e9metadata.cpp \
    src/e9tool/e9parser.cpp \
    src/e9tool/e9tool.cpp \
    src/e9tool/e9types.cpp

release: CXXFLAGS += -O2 -D NDEBUG
release: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch
	strip e9patch

debug: CXXFLAGS += -O0 -g
debug: $(E9PATCH_OBJS)
	$(CXX) $(CXXFLAGS) $(E9PATCH_OBJS) -o e9patch

e9tool.o: $(E9TOOL_SRC)
	$(CXX) $(CXXFLAGS) -c src/e9tool/e9tool.cpp

tool: CXXFLAGS += -O2 -I src/e9tool/ -I capstone/include/ -Wno-unused-function
tool: e9tool.o
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool capstone/libcapstone.a \
        -Wl,--export-dynamic -ldl
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g -I src/e9tool/ -I capstone/include/ \
    -Wno-unused-function
tool.debug: e9tool.o
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool capstone/libcapstone.a \
        -Wl,--export-dynamic -ldl

loader:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -fpie -Os -c \
        src/e9patch/e9loader.cpp
	$(CXX) -nostdlib -o e9loader.out e9loader.o -Wl,--entry=_entry
	objcopy --dump-section .text=e9loader.bin e9loader.out
	xxd -i e9loader.bin > src/e9patch/e9loader.c

src/e9patch/e9alloc.o: CXXFLAGS += -Wno-unused-function

src/e9patch/e9elf.o: loader

clean:
	rm -rf $(E9PATCH_OBJS) e9tool.o e9patch e9tool a.out \
        src/e9patch/e9loader.c e9loader.out e9loader.o e9loader.bin

