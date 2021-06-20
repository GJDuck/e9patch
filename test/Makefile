all:
	gcc -o test test.s -no-pie -nostdlib -Wl,--section-start=.text=0xa00000 \
        -Wl,--section-start=.bss=0xc00000 -Wl,-z -Wl,max-page-size=4096
	../e9compile.sh inst.c -I ../examples/ -D NO_GLIBC
	../e9compile.sh patch.cpp -I ../examples/ -D NO_GLIBC
	g++ -std=c++11 -pie -fPIC -o regtest regtest.cpp -O2

clean:
	rm -f *.log *.out *.exe test inst inst.o patch patch.o regtest
