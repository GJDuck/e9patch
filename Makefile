#CC=clang
#CXX=clang++

CXXFLAGS = -std=c++11 -Wall -Wno-reorder -fPIC -pie

OBJS=\
    e9alloc.o \
    e9api.o \
    e9elf.o \
    e9emit.o \
    e9json.o \
    e9mapping.o \
    e9patch.o \
    e9tactics.o \
    e9trampoline.o \
    e9x86_64.o

release: CXXFLAGS += -O2 -D NDEBUG
release: $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o e9patch
	strip e9patch

debug: CXXFLAGS += -O0 -g
debug: $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o e9patch

tool: CXXFLAGS += -O2 -I capstone/include/ -Wno-unused-function
tool: e9tool.o e9frontend.cpp
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool capstone/libcapstone.a
	strip e9tool

tool.debug: CXXFLAGS += -O0 -g -I capstone/include/ -Wno-unused-function
tool.debug: e9tool.o e9frontend.cpp
	$(CXX) $(CXXFLAGS) e9tool.o -o e9tool capstone/libcapstone.a

loader:
	$(CXX) -std=c++11 -Wall -fno-stack-protector -fpie -Os -c e9loader.cpp
	$(CXX) -nostdlib -o e9loader.out e9loader.o -Wl,--entry=_entry
	objcopy --dump-section .text=e9loader.bin e9loader.out
	xxd -i e9loader.bin > e9loader.c

e9alloc.o: CXXFLAGS += -Wno-unused-function

e9elf.o: loader

clean:
	rm -rf $(OBJS) e9tool.o e9patch e9tool a.out e9loader.o e9loader.out \
        e9loader.c e9loader.bin

