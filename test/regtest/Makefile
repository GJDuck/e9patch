all:
	gcc -x assembler-with-cpp -o test test.s -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0
	gcc -x assembler-with-cpp -o test.pie test.s -pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=1 \
		-Wl,--export-dynamic
	gcc -x assembler-with-cpp -o bugs bugs.s -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0
	gcc -x assembler-with-cpp -o test.libc test_libc.s -pie -Wl,--export-dynamic
	gcc -x assembler-with-cpp -shared -o libtest.so libtest.s 
	../../e9compile.sh inst.c -I ../../examples/ -D NO_GLIBC
	../../e9compile.sh patch.cpp -std=c++11 -I ../../examples/ -D NO_GLIBC
	../../e9compile.sh dl.c -I ../../examples/
	../../e9compile.sh init.c -I ../../examples/ -D NO_GLIBC
	../../e9compile.sh fini.c -I ../../examples/ -D NO_GLIBC
	g++ -std=c++11 -fPIC -shared -o example.so -O2 \
        ../../examples/plugins/example.cpp -I ../../src/e9tool/
	g++ -std=c++11 -pie -fPIC -o regtest regtest.cpp -O2

clean:
	rm -f *.log *.out *.exe test test.pie test.libc libtest.so inst inst.o \
        patch patch.o init init.o regtest
