E9Patch - A Powerful Static Binary Rewriter
===========================================

E9Patch is a scalable static binary rewriting tool for `x86_64` Linux ELF
binaries.

Building
--------

To build E9Patch, simply run the `build.sh` script.

This should build two tools:

1. `e9patch`: the binary rewriter backend; and
2. `e9tool`: a basic frontend for `e9patch`.

Usage
-----

The `e9patch` tool is usable via the `e9tool` front-end.

For example, to add instruction printing instrumentation to all `xor`
instructions in `xterm`, we can use the following command:

        $ ./e9tool --action='asm=xor.*:print' `which xterm`

This will write out a modified `xterm` into the file `a.out`.

The modified `xterm` can be run as per normal, but will print the assembly
string of each executed `xor` instruction to `stderr`:

        $ ./a.out
        xorl %ebp, %ebp
        xorl %ebx, %ebx
        xorl %eax, %eax
        xorl %edx, %edx
        xorl %edi, %edi
        ...

For a full list of supported options and modes, see:

        $ ./e9tool --help

More Examples
-------------

Patch all jump instructions with "empty" (a.k.a. "passthru")
instrumentation:

        $ ./e9tool --action='asm=j.*:passthru' `which xterm`
        $ ./a.out

Print all jump instructions with "print" instrumentation:

        $ ./e9tool --action='asm=j.*:print' `which xterm`
        $ ./a.out

Same as above, but use "Intel" syntax:

        $ ./e9tool --action='asm=j.*:print' `which xterm` --syntax=intel
        $ ./a.out

Patch all jump instructions with a call to an empty function:

        $ ./e9compile.sh examples/nop.c
        $ ./e9tool --action='asm=j.*:call[naked] entry@nop' `which xterm`
        $ ./a.out

Patch all jump instructions with instruction count instrumentation:

        $ ./e9compile.sh examples/counter.c
        $ ./e9tool --action='asm=j.*:call entry@counter' `which xterm`
        $ FREQ=10000 ./a.out

Patch all jump instructions with pretty print instrumentation:

        $ ./e9compile.sh examples/print.c
        $ ./e9tool --action='asm=j.*:call entry(instrAddr,instrAsmStr,instrBytes,instrBytesLen)@print' `which xterm`
        $ ./a.out

Patch all jump instructions with "delay" instrumentation to slow the
program down:

        $ ./e9compile.sh examples/delay.c
        $ ./e9tool --action='asm=j.*:call entry@delay' `which xterm`
        $ DELAY=100000 ./a.out

Patch all jump instructions in Google Chrome with empty instrumentation:

        $ mkdir -p chrome
        $ for FILE in /opt/google/chrome/*; do ln -sf $FILE chrome/; done
        $ rm chrome/chrome
        $ ./e9tool --action='asm=j.*:passthru' /opt/google/chrome/chrome -o chrome/chrome -c 5 --start=ChromeMain
        $ cd chrome
        $ ./chrome

Patch all jump instructions in Google Chrome with instruction count
instrumentation:

        $ ./e9compile.sh examples/counter.c
        $ mkdir -p chrome
        $ for FILE in /opt/google/chrome/*; do ln -sf $FILE chrome/; done
        $ rm chrome/chrome
        $ ./e9tool --action='asm=j.*:call entry@counter' /opt/google/chrome/chrome -o chrome/chrome -c 5 --start=ChromeMain
        $ cd chrome
        $ FREQ=10000000 ./chrome

*Notes*:

* Tested for `XTerm(322)`
* Tested for Google Chrome version `80.0.3987.132 (Official Build) (64-bit)`.

Documentation
-------------

TODO

* Try the examples.
* Try (`e9tool --help`) for a full list of options.

How it Works
------------

TODO

* See the paper (below).

Bugs
----

E9Patch should be considered alpha-quality software.  Bugs can be reported
here:
[https://github.com/GJDuck/e9patch/issues](https://github.com/GJDuck/e9patch/issues)

Versions
--------

TODO

The released version is an improved version of the original prototype
evaluated in the paper.

License
-------

GPLv3

Further Reading
---------------

* Gregory J. Duck, Xiang Gao, Abhik Roychoudhury, [Binary Rewriting without Control Flow Recovery](https://comp.nus.edu.sg/~gregory/papers/e9patch.pdf),
  Programming Language Design and Implementation (PLDI), 2020.

Acknowledgements
----------------

This work was partially supported by the National Satellite of Excellence in
Trustworthy Software Systems, funded by National Research Foundation (NRF)
Singapore under National Cybersecurity R&D (NCR) programme.

