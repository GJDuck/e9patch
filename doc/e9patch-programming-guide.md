# E9Patch Programming Guide

E9Patch is a low-level static binary rewriting tool for x86-64 Linux ELF
executables and shared objects.
This document is intended for tool/frontend developers.
If you are a user and merely wish to use E9Patch to rewrite
binaries, we recommend you read the documentation for E9Tool instead.

There are three main ways to integrate E9Patch into your project:

* [1. E9Tool Call Instrumentation](#e9tool-call)
  [simple, high-level, rigid, **recommended method**]
* [2. E9Patch JSON-RPC Interface](#json-rpc-interface)
  [advanced, low-level, flexible]
* [3. E9Tool Plugin API](#e9tool-plugin)
  [advanced, low-level, flexible]

If performance is not an issue,
then we recommend using [E9Tool call instrumentation](e9tool-call).
For serious/optimized applications, we recommend using
an [E9Tool plugin](#e9tool-plugin) or
the [E9Patch JSON-RPC interface](#json-rpc-interface).

---
## 1. E9Tool Call Instrumentation

E9Tool supports a generic instruction patching capability in the form of
*call instrumentation*.
This is by far the simplest way to build a new application using E9Patch,
and is also the recommended method unless you are specifically trying
to generate optimized code, or if your application requires maximum
flexibility.

To use call instrumentation, you simply implement the desired instrumentation
as a function using a suitable programming language (e.g., `C`).
For example, the following code defines a function that increments a
counter.
Once the counter exceeds some predefined maximum value, the function
will execute the `int3` instruction, causing `SIGTRAP` to be sent to
the program.

        static unsigned long counter = 0;
        static unsigned long max = 100000;
        void entry(void)
        {
            counter++;
            if (counter >= max)
                asm volatile ("int3");
        }

Once defined, the instrumentation will need to be compiled accordingly.
For this, the `e9compile.sh` script has been included which invokes
`gcc` with the correct options.
The main limitation is that the instrumentation code cannot use dynamically
linked libraries, including `libc.so`.

        ./e9compile.sh counter.c

This will build an ELF executable file `counter`.
(Although the generated `counter` file is an ELF executable, it is not
intended to be runnable, and it will crash if you attempt to execute it
directly).

Next, a binary can be instrumented using the `counter` executable.
To do so, you simply use the `--action` option and select *call
instrumentation*.
For example, to instrument all jump instructions in `xterm` the command-line
syntax is as follows:

        ./e9tool --match 'asm=j.*' --action 'call entry@counter' xterm

The syntax is as follows:

* `--match`: Selects the E9Tool "match" command-line option.
   This is to specify which instructions to instrument/patch.
* `asm=j.*`: Specifies that we want to patch/instrument all instructions
  whose assembly syntax matches the regular expression `j.*`.
  For the `x86_64`, only jump instructions begin with `j`, so this
  syntax selects all jump instructions, e.g.
  `jmp`, `jnz`, `jg`, etc.
* `--action`: Selects the E9Tool "action" command-line option.
  This tells E9Tool what patching/instrumentation action to perform on
  matching instructions.
* `call entry@counter`: Specifies that the trampoline should call
  the function `entry()` in the `counter` executable.

By default, *call instrumentation* will handle all low-level details, such as
saving and restoring the CPU state, and
embedding the `counter` executable inside the patched binary.
This makes *call instrumentation* relatively simple to use.

By default the modified binary will be wrtten to `a.out`.
The instrumented `a.out` file will call the `counter` function each
time a jump instruction is executed.
After 100000 jumps, the program will terminate with `SIGTRAP`.

Additional examples of *call instrumentation* are also
[available here](https://github.com/GJDuck/e9patch/tree/master/examples).

---
### 1.1 Libc Support

A parallel implementation of common libc functions is provided in the
`examples/stdlib.c` file.
To use, simply include this file into your project:

        #include "stdlib.c"

This version of libc is designed to be compatible with call instrumentation.
However, only a subset of libc is implemented, so it is WYSIWYG.
That said, many common libc functions, including file I/O and memory
allocation, have been implemented.

It is not advisable to call the "real" `glibc` functions from call
instrumentation, namely:

* `glibc` functions use the System V ABI which is not compatible with
  the clean call ABI.
  Specifically, the clean ABI does not align the stack nor save/restore
  floating point registers for performance reasons.
* Many `glibc` functions are not reentrant and access/modify global state
  such as `errno`.
  Thus, calling `glibc` functions directly can break transparency and/or cause
  problems such as deadlocks.

Unlike `glibc`,
the parallel libc is designed to be compatible with the clean ABI and
handle problems such as deadlocks gracefully.

---
### 1.2 Initialization

It is also possible to define an initialization function.
For example:

        #include "stdlib.c"

        static int max = 1000;

        void init(int argc, char **argv, char **envp)
        {
            environ = envp;     // Init getenv()

            const char *MAX = getenv("MAX");
            if (MAX != NULL)
                max = atoi(MAX);
        }

The initialization function must be named `init`, and will be called
once during the patched program's initialization.
For patched executables, the command line arguments (`argc` and `argv`) and
the environment pointer (`envp`) will be passed as arguments to the function.
Note that, for technical reasons, the `argc`/`argv`/`envp`
arguments are only available for patched executables.
These arguments will be zero/`NULL` for patched shared objects.

In the example above, the initialization function searches for an
environment variable `MAX`, and sets the `max` counter accordingly.

---
### 1.3 Advanced Options

*Call instrumentation* supports advanced options that
are specified in square brackets after the `call` token
in the `--action` option.
For example:

        ./e9tool --match 'asm=j.*' --action 'call[after] entry@counter' xterm

This specifies the `after` option, which means the `entry()`
function should be called after the patched instruction
(the default is before).

The options are:

* `clean`/`naked` for clean/naked calls.
* `before`/`after`/`replace`/`conditional` for inserting the
  call before/after the instruction, or (conditionally) replacing
  the instruction by the call.

Here the `naked` option indicates that the called function will be
responsible for preserving the CPU state, and not E9Tool.
This usually means the function must be implemented in assembly.
For some applications, this can enable more optimized code.
The default is `clean`, which means E9Tool will automatically
generate code for saving/restoring the CPU state.
Note that, for efficiency reasons, the `clean` call ABI differs from
the standard System V ABI in the following way:

* The x87/MMX/SSE/AVX/AVX2/AVX512 registers are *not* saved.
* The stack pointer `%rsp` is *not* guaranteed to be aligned to a 16-byte
  boundary.

These differences are generally safe provided the instrumentation code
exclusively uses general-purpose registers
(as is enforced by `e9compile.sh`).
Otherwise, it will be necessary to save the registers and align the
stack manually inside the instrumentation code.

The `before`/`after`/`replace` option specifies where the
instrumented call should be placed.
For `replace`, the original instruction is essentially deleted
from the patched binary, and it is up to the called function to
execute/emulate a replacement.
For `conditional`, the return value of the called function will
be examined.
If zero is returned, the behavior will be same as `replace` and the original
instruction will not be executed.
Otherwise if non-zero, the behavior will be same as `before` and the
original instruction will be executed in its original context.

---
### 1.4 Arguments

E9Tool also supports passing arguments to the called function.
The syntax uses the `C`-style round brackets.
For example:

        ./e9tool --match 'asm=j.*' --action 'call entry(rip)@counter' xterm

This specifies that the current value of the instruction pointer
(`%rip`) should be passed as the first argument to the function
`entry()`.
The called function can use this argument, e.g.:


        void entry(void *rip)
        {
            counter++;
            if (counter >= max || (unsigned long)rip < 0x10000000)
                asm volatile ("int3");
        }

The modified function will now immediately trap for any instruction
that is less than the address `0x10000000` (e.g., to enforce PIC code).

Several arguments are supported:

* `asm` is a pointer to a string representation of the instruction.
* `asm.size` is the number of bytes in `asm`.
* `asm.len` is the length of `asm`.
* `addr` is the address of the instruction.
* `base` is the PIC base address.
* `instr` is the bytes of the instruction.
* `next` is the address of the next instruction.
* `offset` is the file offset of the instruction.
* `target` is the jump/call/return target address, else -1.
* `trampoline` is the address of the trampoline.
* `random` is a random value [0..2147483647].
* `staticAddr` is the (static) address of the instruction.
* `size` is the number of bytes in `instr`.
* `ah`...`dh`, `al`...`r15b`,
  `ax`...`r15w`, `eax`...`r15d`,
  `rax`...`r15`, `rip`, `rflags` is the corresponding register value.
* `&ah`...`&dh`, `&al`...`&r15b`,
  `&ax`...`&r15w`, `&eax`...`&r15d`,
  `&rax`...`&r15`, `&rflags` is the corresponding register value but
   passed-by-pointer.
* `op[i]`, `src[i]`, `dst[i]`, `imm[i]`, `reg[i]`, `mem[i]` is the ith
  operand, source operand, destination operand, immediate operand, register
  operand, memory operand respectively.
* `&op[i]`, `&src[i]`, `&dst[i]`, `&imm[i]`, `&reg[i]`, `&mem[i]` is the
   same as above but passed-by-pointer.
* An integer constant.
* A file lookup of the form `basename[index]` where
  `basename` is the basename of a CSV file used in
  the matching, and `index` is a column index.
  Note that the matching must select a unique row.

Note that the current E9Tool supports a maximum of 8 arguments.

---
## <a id="json-rpc-interface">2. E9Patch JSON-RPC API</a>

The E9Patch tool uses the [JSON-RPC](https://en.wikipedia.org/wiki/JSON-RPC)
(version 2.0) as its API.
Basically, the E9Patch tool expects a stream of JSON-RPC messages which
describe which binary to rewrite, and how to rewrite it.
These JSON-RPC messages are fed from a frontend tool, such as E9Tool,
but this design means that multiple different frontends can be supported.
The choice of JSON-RPC as the API also means that the frontend can be
implemented in any programming language, including C++, python or Rust.

By design, E9Patch tool will do very little parsing or analysis of the input
binary file.
Instead, the analysis/parsing is left to the frontend, and E9Patch relies on
the frontend to supply all necessary information in order to rewrite the
binary.
Specifically, the frontend must specify:

* The file offsets, virtual addresses and size of instructions in the input
  binary.
* The file offsets of the patch location.
* The templates for the trampolines to be used by the rewritten binary.
* Any additional data/code to be inserted into the rewritten binary.

The main JSON-RPC messages are:

* [2.1 Binary Message](#binary-message)
* [2.2 Trampoline Message](#trampoline-message)
* [2.3 Reserve Message](#reserve-message)
* [2.4 Instruction Message](#instruction-message)
* [2.5 Patch Message](#patch-message)
* [2.6 Emit Message](#emit-message)

The E9Patch JSON-RPC parser does not yet support the full JSON syntax, but
implements a reasonable subset.
The parser also implements an extension in the form of support for
hexadecimal numbers in a string format.
For example, the following are equivalent:

        "address": 4245300
        "address": "0x40c734"

The string format can also be used to represent numbers larger than
those representable in 32bits.

Note that implementing a new frontend from scratch may require a lot of
boilerplate code.
An alternative is to implement an *E9Tool* plugin which is documented
[here](e9tool-plugin).

---
### <a id="binary-message">2.1 Binary Message</a>

The `"binary"` message begins the patching process.
It must be the first message sent to E9Patch.

#### Parameters:

* `"filename"`: the path to the binary file that is to be patched.
* `"mode"`: the type of the binary file.
    Valid values include `"exe"` for executables and `"shared"` for
    shared objects.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "binary",
            "params":
            {
                "filename": "/usr/bin/xterm",
                "mode": "exe"
            },
            "id": 0
        }

---
### <a id="trampoline-message">2.2 Trampoline Message</a>

The `"trampoline"` message sends a trampoline template specification
to E9Patch that can be used to patch instructions.

#### Parameters:

* `"name"`: the name of the trampoline.
* `"template"`: the template of the trampoline.

#### Notes:

The template essentially specifies what bytes should be placed in
memory when the trampoline is used by a patched instruction.
The template can consist of both instructions and data, depending
on the application.

The template specification language is low-level, and is essentially a sequence
of bytes, but can also include other data types (integers, strings),
macros and labels.
Any desired instruction sequence should therefore be specified in machine code.

The template is specified as a list of *elements*, where each element can be
any of the following:

* A byte: represented by an integer *0..255*
* A macro: represented by a string beginning with a dollar character,
  e.g. `"$asmStr`.
  Macros are expanded with values provided by the `"patch"` message
  (see below).
  There are also some builtin macros (see below).
* A label: represented by a string beginning with the string `".L"`,
  e.g. `".Llabel"`.
  There are also some builtin labels (see below).
* An integer: represented by a type/value tuple, e.g. `{"int32": 1000}`, 
  where valid types are:
    * `"int8"`: a single byte signed integer
    * `"int16"`: a 16bit little-endian signed integer
    * `"int32"`: a 32bit little-endian signed integer
    * `"int64"`: a 64bit little-endian signed integer
* A string: represented by a type/value where the type is `"string"`, e.g.
    `{"string": "hello\n"}`
* A relative offset: represented by a type/value tuple, e.g.
  `{"rel8": ".Llabel"}`. where valid types are:
    * `"rel8"`: an 8bit relative offset 
    * `"rel32"`: a 32bit relative offset

Several builtin macros are implicitly defined, including:

* `"$bytes"`: The original byte sequence of the instruction that was patched
* `"$instruction"`: A byte sequence of instructions that emulates the
  patched instruction.
  Note that this is usually equivalent to `"$bytes"` except for
  instructions that are position-dependent.
* `"$continue"`: A byte sequence of instructions that will return
  control-flow to the next instruction after the patched instruction.
  This can be used to return from trampolines.
* `"$taken"`: Similar to `"$continue"`, but for the branch-taken case of
  conditional jumps.

Several builtin labels are also implicitly defined, including:

* `".Lcontinue"`: The address corresponding to `"$continue"`
* `".Ltaken"`: The address corresponding to `$taken"`
* `".Linstruction"`: The address of the patched instruction.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "trampoline",
            "params":
            {
                "name":"print",
                "template": [
                    72, 141, 164, 36, 0, 192, 255, 255,
                    87,
                    86,
                    80,
                    81,
                    82,
                    65, 83,
                    72, 141, 53, {"rel32": ".Lstring"},
                    186, "$asmStrLen",
                    191, 2, 0, 0, 0,
                    184, 1, 0, 0, 0,
                    15, 5,
                    65, 91,
                    90,
                    89,
                    88,
                    94,
                    95,
                    72, 141, 164, 36, 0, 64, 0, 0,
                    "$instruction",
                    "$continue",
                    ".Lstring",
                    "$asmStr"
                ]
            },
            "id":1
        }

This is a representation of the following trampoline in assembly syntax:

            # Save registers:
            lea -0x4000(%rsp),%rsp
            push %rdi
            push %rsi
            push %rax
            push %rcx
            push %rdx
            push %r11
    
            # Setup and execute a SYS_write system call:
            leaq .Lstring(%rip),%rsi
            mov $asmStrlen,%edx
            mov $0x2,%edi           # stderr
            mov $0x1,%eax           # SYS_write
            syscall
    
            # Restore registers:
            pop %r11
            pop %rdx
            pop %rcx
            pop %rax
            pop %rsi
            pop %rdi
            lea 0x4000(%rsp),%rsp
    
            # Execute the displaced instruction:
            $instruction
    
            # Return from the trampoline
            $continue
    
            # Store the asm String here:
        .Lstring:
            $asmStr

Note that the interface is very low-level.
E9Patch does not have a builtin assembler so instructions must be specified
in machine code.
Furthermore, it is up to the trampoline template specification to
save/restore the CPU state as necessary.
In the example above, the trampoline saves several registers to the
stack before restoring them before returning.
Note that under the System V ABI, up to 128bytes below the stack
pointer may be used (the stack red zone), hence a pair of
`lea` instructions must adjust the stack pointer to skip this
region, else the patched program may crash or misbehave.
In general, the saving/restoring of the CPU state is solely the responsibility
of the frontend, and E9Patch will simply execute the template "as-is".

---
### <a id="reserve-message">2.3 Reserve Message</a>

The `"reserve"` message is useful for reserving sections of the
patched program's virtual address space and (optionally) initializing
it with data.
Reserved addresses will not be used to host trampolines.

#### Parameters:

* `"absolute"`: [optional] if `true` then the address is interpreted as an
  absolute address.
* `"address"`: the base address of the virtual address space region.
  For PIC, this is a relative address unless `"absolute"` is set to
  `true`.
* `"bytes"`: [optional] bytes to initialize the memory with, using the
  trampoline template syntax.
  This is mandatory if `"length"` is unspecified.
* `"length"`: [optional] the length of the reservation.
  This is mandatory if `"bytes"` is unspecified.
* `"init"`: [optional] an address of an initialization routine that will
  be called when the patched program is loaded into memory.
* `"mmap"`: [optional] an address of a replacement implementation of
  `mmap()` that will be used during the patched program's initialization.
  This is for advanced applications only.
* `"protection"`: [optional] the page permissions represented as a
  string, e.g., `"rwx"`, `"r-x"`, `"r--"`, etc.
  The default is `"r-x"`.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "reserve",
            "params":
            {
                "address": 2097152,
                "length": 65536
            },
            "id": 1
        }

        {
            "jsonrpc": "2.0",
            "method": "reserve",
            "params":
            {
                "address": 23687168,
                "protection": "r-x",
                "bytes": [127, 69, 76, 70, 2, 1, 1, ..., 0]
            },
            "id": 1
        }

---
### <a id="instruction-message">2.4 Instruction Message</a>

The `"instruction"` message sends information about a single instruction
in the binary file.

#### Parameters:

* `"address"`: the virtual address of the instruction.  This can be a
    relative address for *Position Independent Code* (PIC) binaries, or an
    absolute address for non-PIC binaries.
* `"length"`: the length of the instruction in bytes.
* `"offset"`: the file offset of instruction in the input binary.

#### Notes:

Note that it is not necessary to send an "instruction" message for every
instruction in the input binary.
Instead, only send an "instruction" message for patch locations, and
instructions within the x86-64 *short jump distance* of a patch location.
This is all instructions within the range of [-128..127] bytes of a patch
location instruction.

The E9Patch tool does not validate the information and simply trusts
the information to be correct.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "instruction",
            "params":
            {
                "address":4533271,
                "length":3,
                "offset":338967
            },
            "id": 10
        }

---
### <a id="patch-messge">2.5 Patch Message</a>

The `"patch"` message tells E9Patch to patch a given instruction.

#### Parameters:

* `"offset"`: the file-offset that identifies an instruction previously
    sent via an "instruction" message.
* `"trampoline"`: the name of a trampoline template sent by a previous
    "trampoline" message.
* `"metadata"`: a set of key-value pairs mapping macro names to data
    represented in the trampoline template format.
    This metadata will be used to instantiate the trampoline before
    it is emitted in the rewritten binary.

#### Notes:

Note that patch messages should be sent in ***reverse order*** as they appear
in the binary file.
That is, the patch location with the highest file offset should be sent
first, then the second highest should be sent second, and so forth.
This is to implement the *reverse execution order* strategy which is
necessary to manage the complex dependencies between patch locations.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "patch",
            "params":
            {
                "trampoline": "print",
                "metadata":
                {
                    "$asmStr": "jmp 0x406ac0\n",
                    "$asmStrLen": {"int32":13}
                },
                "offset":338996
            },
            "id": 43
        }

---
### <a id="emit-message">2.6 Emit Message</a>

The `"emit"` message instructs E9Patch to emit the patched binary file.

#### Parameters:

* `"filename"`: the path where the patched binary file is to be written to.
* `"format"`: the format of the patched binary.
    Supported values include `"binary"` (an ELF binary)
    `"patch"` (a binary diff) and
    `"patch.gz"`/`"patch.bz2"`/`"patch.xz"` (a compressed binary diff).
* `"mapping_size"`: Determines how big each file mapping should be.
    This controls the aggressiveness of the *Physical Page Grouping*
    optimization.
    Valid values must be a power-of-two times the page size (4096),
    where smaller values corresponding to more aggressive space optimization.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "emit",
            "params":
            {
                "filename": "a.out",
                "format": "binary",
                "mapping_size": 4096
            },
            "id": 82535
        }

---
## <a id="e9tool-plugin">3. E9Tool Plugin API</a>

E9Tool is the default frontend for E9Patch.  Although it is possible to
create new frontends for E9Patch, for some applications this can be quite
complicated and require a lot of boilerplate code.  To help address this,
we added a plugin mechanism for E9Tool, as documented below.

A plugin is a shared object that exports specific functions, as outlined
below.  These functions will be invoked by E9Tool at different stages of
the patching process.  Mundane tasks, such as disassembly, will be handled
by the E9Tool frontend.

The E9Tool plugin API is very simple and consists of just four functions:

1. `e9_plugin_init_v1(FILE *out, const ELF *in, ...)`:
    Called once before the binary is disassembled.
2. `e9_plugin_instr_v1(FILE *out, const ELF *in, ...)`:
    Called once for each disassembled instruction.
3. `e9_plugin_match_v1(FILE *out, const ELF *in, ...)`:
    Called once for each matching.
4. `e9_plugin_patch_v1(FILE *out, const ELF *in, ...)`:
    Called for each patch location.
5. `e9_plugin_fini_v1(FILE *out, const ELF *in, ...)`:
    Called once after all instructions have been patched.

Note that each function is optional, and the plugin can choose not to
define it.  However, The plugin must define at least one of these functions
to be considered valid.

Each function takes at least two arguments, namely:

* `out`: is the JSON-RPC output stream that is sent to the E9Patch
  backend; and
* `in`: a representation of the input ELF file, see e9frontend.h for
  more information.

Some functions take additional arguments, including:

* `handle`: Capstone handle.
* `offset`: File offset of instruction (if applicable).
* `I`: Instruction (if applicable).
* `context`: An optional plugin-defined context returned by the
  `e9_plugin_init_v1()` function.

Some API function return a value, including:

* `e9_plugin_init_v1()` returns an optional `context` that will be
  passed to all other API calls.
* `e9_plugin_match_v1()` returns an integer value of the plugin's
   choosing.  This integer value can be matched using by the `--match`
   E9Tool command-line option, else the value will be ignored.

The API is meant to be highly flexible.  Basically, the plugin API
functions are expected to send JSON-RPC messages directly to the E9Patch
backend by writing to the `out` output stream.
See the [E9Patch JSON-RPC interface](#json-rpc-interface) for more
information.

For typical usage,
the `e9_plugin_init_v1()` function will do the following tasks
(as required):

1. Initialize the plugin (if necessary)
2. Setup trampolines
3. Reserve parts of the virtual address space
4. Load ELF binaries into the virtual address space
5. Create and return the context (if necessary)

The `e9_plugin_instr_v1()` function will do the following:

1. Analyze or remember the instruction (if necessary)
2. Setup additional trampolines (if necessary)

The `e9_plugin_match_v1()` function will do the following:

1. Return a value to be used in a matching.

The `e9_plugin_patch_v1()` function will do the following:

1. Setup additional trampolines (if necessary)
2. Send a "patch" JSON-RPC message with appropriate metadata.

The `e9_plugin_fini_v1()` function will do any cleanup if necessary.

See the `e9frontend.h` file for useful functions that can assist with these
tasks.  Otherwise, there are no limitations on what these functions can do,
just provided the E9Patch backend can parse the JSON-RPC messages sent by
the plugin.  This makes the plugin API very powerful.

---
### 3.1 Using Plugins

Plugins can be used by E9Tool and the `--action` option.
For example:

        g++ -std=c++11 -fPIC -shared -o myPlugin.so myPlugin.cpp -I . -I capstone/include/
        ./e9tool --match 'asm=j.*' --action 'plugin(myPlugin).patch()' xterm

The syntax is as follows:

* `--action`: Selects the E9Tool "action" command-line option.
  This tells E9Tool what patching/instrumentation action to do.
* `plugin(myPlugin).patchh()`: Specifies that instrument the program using the
  `myPlugin.so` plugin.

If `myPlugin.so` exports the `e9_plugin_match_v1()` function, it is also
possible to match against the return value.
For example:

        ./e9tool --match 'plugin(myPlugin).match() > 0x333' --action 'plugin(myPlugin).patch()' xterm

This command will only patch instructions where the `e9_plugin_match_v1()`
function returns a value greater than `0x333`.

