all:
	gcc -x assembler-with-cpp -o test test.s -no-pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
        -Wl,-z -Wl,max-page-size=4096 -DPIE=0
	gcc -x assembler-with-cpp -o test.pie test.s -pie -nostdlib \
        -Wl,--section-start=.text=0xa000000 -Wl,--section-start=.bss=0xc000000 \
         -Wl,-z -Wl,max-page-size=4096 -DPIE=1
	../../e9compile.sh inst.c -I ../../examples/ -D NO_GLIBC
	../../e9compile.sh patch.cpp -I ../../examples/ -D NO_GLIBC
	g++ -std=c++11 -pie -fPIC -o regtest regtest.cpp -O2

clean:
	rm -f *.log *.out *.exe test test.pie inst inst.o patch patch.o regtest
