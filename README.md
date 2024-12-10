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

*Static binary rewriting* takes an input binary 
(ELF executable or shared object) and generates an output binary
with some patch/modification applied to it.
The patched binary can be used as a drop-in replacement of the original.

For more information, please see our PLDI'2020 paper:

* Gregory J. Duck, Xiang Gao, Abhik Roychoudhury, [Binary Rewriting without Control Flow Recovery](https://comp.nus.edu.sg/~gregory/papers/e9patch.pdf),
  Programming Language Design and Implementation (PLDI), 2020.
  [PLDI'2020 Presentation](https://www.youtube.com/watch?v=qK2ZCEStoG0)

## Release

Pre-built E9Patch binaries can be downloaded here:

* [https://github.com/GJDuck/e9patch/releases](https://github.com/GJDuck/e9patch/releases)

## Build

Building E9Patch is very easy: simply run the `build.sh` script.

This will automatically build two tools:

1. `e9patch`: the binary rewriter backend; and
2. `e9tool`: a linear disassembly frontend for E9Patch.

## Example Usage

E9Patch is usable via the E9Tool frontend.

For example, to add instruction printing instrumentation to all `xor`
instructions in `xterm`, we can use the following command:

        $ ./e9tool -M 'asm=/xor.*/' -P print xterm

This will generate a modified version of `xterm` written to the `a.out` file.

The modified `xterm` can be run as normal, but will print the assembly
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

*Notes*:

* Tested for `XTerm(322)`

## Projects

Some other projects that use E9Patch include:

* [RedFat](https://github.com/GJDuck/RedFat): A binary hardening system based
  on [low-fat pointers](https://github.com/GJDuck/LowFat).
* [E9AFL](https://github.com/GJDuck/e9afl): Automatically insert
  [AFL](https://github.com/google/AFL) instrumentation into binaries.
* [E9Syscall](https://github.com/GJDuck/e9syscall): System call
  interception using static binary rewriting of `libc.so`.
* [Hopper](https://github.com/FuzzAnything/hopper): Automatic fuzzing test
  cases generation for libraries.
* [EnvFuzz](https://github.com/GJDuck/EnvFuzz): Program environment fuzzing.
* [RFF](https://github.com/dylanjwolff/RFF): Greybox fuzzing for
  concurrency testing.
* [AutoTrace](https://github.com/GJDuck/AutoTrace): Simple source line-based
  tracing.

## Documentation

E9Patch is a low-level tool that is designed to be integrable into other
projects.
To find out more, please see the following documentation:

* [E9Patch Programmer's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md)
* [E9Tool User's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md)

## Bugs

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

