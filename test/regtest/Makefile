.POSIX:
.PHONY: all clean check

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
%.exe: %.in $(BASE) $(TRAMPOLINE)
	../../e9tool $(E9TOOL_OPTIONS) -M 'addr >= &"entry"' $(in)\
		-E data..data_END -E data2...text -E .text..begin -o $@

test:
	gcc -x assembler-with-cpp -o test test.s -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0

test.pie:
	gcc -x assembler-with-cpp -o test.pie test.s -pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=1 \
		-Wl,--export-dynamic

bugs:
	gcc -x assembler-with-cpp -o bugs bugs.s -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0

test.libc:
	gcc -x assembler-with-cpp -o test.libc test_libc.s -pie -Wl,--export-dynamic

libtest.so:
	gcc -x assembler-with-cpp -shared -o libtest.so libtest.s 

test_c:
	gcc -O2 -fPIC $(FCF_NONE) -pie -o test_c test_c.c \
		-Wl,--export-dynamic -U_FORTIFY_SOURCE
	strip test_c

test_c.debug:
	gcc -O0 -g -fPIC -pie -o test_c.debug test_c.c

inst:
	../../e9compile.sh inst.c -I ../../examples/ 

patch:
	../../e9compile.sh patch.cpp -std=c++11 -I ../../examples/ 

dl:
	NO_SIMD_CHECK=1 ../../e9compile.sh dl.c -I ../../examples/

init:
	../../e9compile.sh init.c -I ../../examples/ 

fini:
	../../e9compile.sh fini.c -I ../../examples/

example.so:
	g++ -std=c++11 -fPIC -shared -o example.so -O2 \
        ../../examples/plugins/example.cpp -I ../../src/e9tool/

check: run-tests $(EXE)
	./$^
