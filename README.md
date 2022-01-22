# E9Patch - A Powerful Static Binary Rewriter

E9Patch is a powerful static binary rewriting tool for `x86_64` Linux ELF
binaries.
E9Patch is:

* *Scalable*: E9Patch can reliably rewrite large/complex binaries
  including web browsers (>100MB in size).
* *Compatible*: The rewritten binary is a drop-in replacement of the
  original, with no additional dependencies.
* *Fast*: E9Patch can rewrite most binaries in a few seconds.
* *Low Overheads*: Both performance and memory.
* *Programmable*: E9Patch is designed so that it can be easily integrated
  into other projects.
  See the [E9Tool User's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md) and the [E9Patch Programmer's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md)
  for more information.

**NEW (9th Sep 2021)**: Experimental support for Windows PE binaries has been
                        added.

## Background

*Static binary rewriting* takes as input a binary file
(ELF executable or shared object, e.g. `a.out`) and outputs a new binary
file (e.g., `b.out`) with some patch/modification applied to it.
The patched `b.out` can then be used as a drop-in replacement of
the original `a.out`.
Typical binary rewriting applications include
instrumentation (the addition of new instructions)
or patching (replacing binary code with a new version).

Static binary rewriting is notoriously difficult.
One problem is that space for the new instructions must be allocated,
and this typically means that existing instructions will need to be moved
in order to make room.
However, some of these existing instructions may also be *jump targets*,
meaning that the all jump/call instructions in the original binary
will also need to be adjusted in the rewritten binary.
Unfortunately, things get complicated very quickly:

* The complete set of targets cannot be determined statically
  (it is an undecidable problem in the general case of indirect
   calls or jumps).
* Cross-binary calls/jumps are not uncommon, for example the `compare`
  function pointer argument to libc's `qsort()`.
  Since code pointers cannot be reliably distinguished from other data
  in the general case,
  this can mean that the entire shared library dependency tree also needs
  to be rewritten.

Unless all jumps and calls are perfectly adjusted, the rewritten binary
will likely crash or otherwise misbehave.
This is why existing static binary rewriting tools tend to scale poorly.

### How E9Patch is Different

E9Patch is different to other tools in that it can statically
rewrite `x86_64` Linux ELF binaries
***without modifying the set of jump targets***.
To do so, E9Patch uses a set of novel low-level binary rewriting
techniques, such as *instruction punning, padding and eviction* that can
insert or replace binary code without the need to move existing
instructions.
Since existing instructions are not moved, the set of jump targets
remains unchanged, meaning that calls/jumps do not need to be corrected
(including cross binary calls/jumps).

E9Patch is therefore highly scalable by design, and can reliably rewrite very
large binaries such as Google Chrome and FireFox (>100MB in size).

To find out more on how E9Patch works, please see our PLDI'2020 paper:

* Gregory J. Duck, Xiang Gao, Abhik Roychoudhury, [Binary Rewriting without Control Flow Recovery](https://comp.nus.edu.sg/~gregory/papers/e9patch.pdf),
  Programming Language Design and Implementation (PLDI), 2020.
  [PLDI'2020 Presentation](https://www.youtube.com/watch?v=qK2ZCEStoG0)

### Additional Notes

The key to E9Patch's scalability is that it makes minimal assumptions
about the input binary.
However, E9Patch is not 100% assumption-free, and does assume:

* The binary can be *disassembled* and does not use *overlapping
  instructions*.
  The default E9Tool frontend uses the
  [Zydis disassembler](https://github.com/zyantific/zydis).
* The binary does not read from, or write, to the patched executable
  segments.
  For example, *self-modifying code* is not supported.

Most off-the-self `x86_64` Linux binaries will satisfy these assumptions.

The instruction patching methodology that E9Patch uses is not
guaranteed to work for every instruction.
As such, the *coverage* of the patching may not be 100%.
E9Patch will print coverage information after the rewriting process,
e.g.:

        num_patched = 2766 / 2766 (100.00%)

Most applications can expect at or near 100% coverage.
However, coverage can be diminished by several factors, including:

* Patching single-byte instructions such as `ret`s, `push`es and `pop`s.
  These are difficult to patch, affecting coverage.
* Patching too many instructions.
* Binaries with large static code or data segments that limit the space
  available for trampolines.

A patched binary with less than 100% coverage will still run
correctly, albeit with some instructions remaining unpatched.
Whether or not this is an issue depends largely on the application.

## Building

Building E9Patch is very easy: simply run the `build.sh` script.

This should automatically build two tools:

1. `e9patch`: the binary rewriter backend; and
2. `e9tool`: a basic linear disassembly frontend for E9Patch.

*Note*: E9Tool and E9Patch are considered to be different tools.
Limitations of E9Tool do not necessarily extend to E9Patch itself.
Other frontends for E9Patch (e.g., based on more advanced disassembly
techniques) can be built, although this is currently future work.

## Examples

E9Patch is usable via the E9Tool frontend.

For example, to add instruction printing instrumentation to all `xor`
instructions in `xterm`, we can use the following command:

        $ ./e9tool -M 'asm=/xor.*/' -P print xterm

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

### More Examples

Patch all jump instructions with "empty" instrumentation:

        $ ./e9tool -M 'asm=/j.*/' -P empty xterm
        $ ./a.out

Print all jump instructions with "print" instrumentation:

        $ ./e9tool -M 'asm=/j.*/' -P print xterm
        $ ./a.out

Same as above, but use "Intel" syntax:

        $ ./e9tool -M 'asm=/j.*/' -P print xterm --syntax=intel
        $ ./a.out

Patch all jump instructions with a call to an empty function:

        $ ./e9compile.sh examples/nop.c
        $ ./e9tool -M 'asm=/j.*/' -P 'entry()@nop' xterm
        $ ./a.out

Patch all jump instructions with instruction count instrumentation:

        $ ./e9compile.sh examples/counter.c
        $ ./e9tool -M 'asm=/j.*/' -P 'entry()@counter' xterm
        $ FREQ=10000 ./a.out

Patch all jump instructions with pretty print instrumentation:

        $ ./e9compile.sh examples/print.c
        $ ./e9tool -M 'asm=/j.*/' -P 'entry(addr,instr,size,asm)@print' xterm
        $ ./a.out

Patch all jump instructions with "delay" instrumentation to slow the
program down:

        $ ./e9compile.sh examples/delay.c
        $ ./e9tool -M 'asm=/j.*/' -P 'entry()@delay' xterm
        $ DELAY=100000 ./a.out

Patch all jump instructions in Google Chrome with empty instrumentation:

        $ mkdir -p chrome
        $ for FILE in /opt/google/chrome/*; do ln -sf $FILE chrome/; done
        $ rm chrome/chrome
        $ ./e9tool -M 'asm=/j.*/' -P empty /opt/google/chrome/chrome -c 4 -o chrome/chrome
        $ cd chrome
        $ ./chrome

Patch all jump instructions in Google Chrome with instruction count
instrumentation:

        $ ./e9compile.sh examples/counter.c
        $ mkdir -p chrome
        $ for FILE in /opt/google/chrome/*; do ln -sf $FILE chrome/; done
        $ rm chrome/chrome
        $ ./e9tool -M 'asm=/j.*/' -P 'entry()@counter' /opt/google/chrome/chrome -c 4 -o chrome/chrome
        $ cd chrome
        $ FREQ=10000000 ./chrome

*Notes*:

* Tested for `XTerm(322)`
* Tested for Google Chrome version `80.0.3987.132 (Official Build) (64-bit)`.

## Projects

Some other projects that use E9Patch include:

* [E9AFL](https://github.com/GJDuck/e9afl): Automatically insert
  [AFL](https://github.com/google/AFL) instrumentation into binaries.
* [E9Syscall](https://github.com/GJDuck/e9syscall): System call
  interception using static binary rewriting of `libc.so`.

## Documentation

If you just want to test E9Patch out, then please try the above examples.

E9Patch is a low-level tool that is designed to be integrable into other
projects.
To find out more, please see the following documentation:

* [E9Patch Programmer's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md)
* [E9Tool User's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md) (incomplete)

## Bugs

E9Patch should be considered alpha-quality software.
Bugs can be reported here:

* [https://github.com/GJDuck/e9patch/issues](https://github.com/GJDuck/e9patch/issues)

## Versions

The current version of E9Patch is significantly improved compared to
the original prototype evaluated in the PLDI'2020 paper.
Specifically:

* The current version implements several new optimizations and can generate
  significantly faster binaries, sometimes by a factor of 2x.
  To enable the new optimizations, pass the `-O2` option to E9Tool.
* The implementation of the *Physical Page Grouping* space optimization
  has also been improved.
* The patching coverage has also been slightly improved.
* Many new features have been implemented (see the documentation).

## License

This software has been released under the GNU Public License (GPL) Version 3.

Some specific files are released under the MIT license (check the file
preamble).

## Acknowledgements

This work was partially supported by the National Satellite of Excellence in
Trustworthy Software Systems, funded by National Research Foundation (NRF)
Singapore under the National Cybersecurity R&D (NCR) programme.

