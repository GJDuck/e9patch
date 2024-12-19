.POSIX:
.PHONY: all clean check

E9TOOL ?= ../../e9tool
E9COMPILE ?= ../../e9compile.sh

FCF_NONE := $(shell \
    if gcc -fcf-protection=none --version 2>&1 | grep -q 'unrecognized'; \
        then true; \
        else echo -fcf-protection=none; fi)

BASE ::= test test.pie bugs test.libc libtest.so test_c test_c.debug example.so
TRAMPOLINE ::= inst patch dl init fini
IN ::= $(wildcard *.in)
EXE ::= $(IN:.in=.exe)

all: regtest $(BASE) $(TRAMPOLINE)

clean:
	rm -f regtest
	rm -f $(BASE) $(TRAMPOLINE) $(EXE)
	rm -f *.out *.log *.diff

regtest: regtest.cpp
	$(CXX) -std=c++11 -O2 -g -fPIC -pie $< -o $@

%.exe: in=$(shell head -1 $<)
%.exe: %.in $(BASE) $(TRAMPOLINE) $(E9TOOL)
	$(E9TOOL) $(E9TOOL_OPTIONS) -M 'addr >= &"entry"' $(in)\
		-E data..data_END -E data2...text -E .text..begin -o $@

test: test.s
	$(CC) -x assembler-with-cpp -o $@ $< -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0

test.pie: test.s
	$(CC) -x assembler-with-cpp -o $@ $< -pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=1 \
		-Wl,--export-dynamic

bugs: bugs.s
	$(CC) -x assembler-with-cpp -o $@ $< -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0

test.libc: test_libc.s
	$(CC) -x assembler-with-cpp -pie $< -Wl,--export-dynamic -o $@

libtest.so: libtest.s
	$(CC) -x assembler-with-cpp $< -shared -o $@

test_c: test_c.c
	$(CC) -O2 -fPIC $(FCF_NONE) -pie -o $@ $< \
		-Wl,--export-dynamic -U_FORTIFY_SOURCE
	strip test_c

test_c.debug: test_c.c
	$(CC) -O0 -g -fPIC -pie $< -o $@

inst: inst.c ../../examples/stdlib.c $(E9COMPILE)
	$(E9COMPILE) $< -I../../examples

patch: patch.cpp ../../examples/stdlib.c $(E9COMPILE)
	$(E9COMPILE) $< -std=c++11 -I../../examples

dl: dl.c ../../examples/stdlib.c $(E9COMPILE)
	NO_SIMD_CHECK=1 $(E9COMPILE) $< -I../../examples

init: init.c ../../examples/stdlib.c $(E9COMPILE)
	$(E9COMPILE) $< -I../../examples

fini: fini.c ../../examples/stdlib.c $(E9COMPILE)
	$(E9COMPILE) $< -I../../examples

example.so: ../../examples/plugins/example.cpp ../../src/e9tool/e9plugin.h
	$(CXX) -std=c++11 -O2 -fPIC -I../../src/e9tool $< -shared -o $@

check: run-tests $(EXE)
	./$^
