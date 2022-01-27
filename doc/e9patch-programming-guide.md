# E9Patch Programming Guide

E9Patch is a low-level static binary rewriting tool for x86-64 Linux ELF
executables and shared objects.
This document is intended for tool/frontend developers.
If you are a user and merely wish to use E9Patch to rewrite
binaries, we recommend you read the documentation for E9Tool instead.

There are three main ways to integrate E9Patch into your project:

* [1. E9Tool Call Trampolines](#e9tool-call)
  [simple, high-level, rigid, **recommended method**]
* [2. E9Patch JSON-RPC Interface](#json-rpc-interface)
  [advanced, low-level, flexible]
* [3. E9Tool Plugin API](#e9tool-plugin)
  [advanced, low-level, flexible]

If performance is not an issue,
then we recommend using [E9Tool call instrumentation](#e9tool-call).
For serious/optimized applications, we recommend using
an [E9Tool plugin](#e9tool-plugin) or
the [E9Patch JSON-RPC interface](#json-rpc-interface).

---
## <a id="e9tool-call">1. E9Tool Call Trampolines</a>

E9Tool supports a generic instruction patching capability in the form of
*call trampolines*.
This is by far the simplest way to build a new application using E9Patch,
and is also the recommended method unless you are specifically trying
to generate optimized code, or if your application requires maximum
flexibility.

Call trampolines allow *patch code* to be implemented as ordinary functions
using a supported programming language, such as `C`, `C++` or assembly.
The patch code can then be compiled into a *patch binary* will be injected
into the rewritten binary.
The patch functions can then be called from the desired locations.

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

Once defined, the patch code can then be compiled using the special
`e9compile.sh` script.
This script invokes `gcc` with the correct options necessary to be
compatible with E9Tool:

        ./e9compile.sh counter.c

This command will build a special ELF executable file named `counter`.

To rewrite a binary using `counter`, we use E9Tool and the `--patch`/`-P`
options.
For example, to instrument all jump instructions in the `xterm` binary
with a call to the `entry()` function, we can use the following
command-line syntax:

        ./e9tool -M 'asm=j.*' -P 'entry()@counter' xterm

The syntax is as follows:

* `-M`: Selects the E9Tool "match" command-line option.
   This specifies which instructions should be instrumented.
* `asm=j.*`: Specifies that we want to patch/instrument all instructions
  whose assembly syntax matches the regular expression `j.*`.
  For the `x86_64`, only jump instructions begin with `j`, so this
  syntax selects all jump instructions, e.g.
  `jmp`, `jnz`, `jg`, etc.
* `-P`: Selects the E9Tool "patch" command-line option.
  This tells E9Tool how to patch the matching instruction(s).
* `entry()@counter`: Specifies that the trampoline should call
  the function `entry()` in the `counter` binary.

By default, *call trampolines* will handle all low-level details, such as
saving and restoring the CPU state, and
injecting the `counter` executable into the rewritten binary.

By default the modified binary will be written to `a.out`.
The instrumented `a.out` file will call the `counter` function each
time a jump instruction is executed.
After 100000 jumps, the program will terminate with `SIGTRAP`.

Call trampolines support many features, such as function arguments,
selectable ABIs, and conditional control-flow redirection.
More information about *call trampolines* can be found in the
[E9Tool User's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9tool-user-guide.md).

Additional examples of *call trampolines* are also
[available here](https://github.com/GJDuck/e9patch/tree/master/examples).

---
## <a id="json-rpc-interface">2. E9Patch JSON-RPC API</a>

The E9Patch tool uses the [JSON-RPC](https://en.wikipedia.org/wiki/JSON-RPC)
(version 2.0) as its API.
Basically, the E9Patch tool expects a stream of JSON-RPC messages which
describe which binary to rewrite and how to rewrite it.
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
* [2.6 Options Message](#options-message)
* [2.7 Emit Message](#emit-message)

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
    Valid values include `"elf.exe"` for ELF executables and `"elf.so"` for
    ELF shared objects.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "binary",
            "params":
            {
                "filename": "/usr/bin/xterm",
                "mode": "elf.exe"
            },
            "id": 0
        }

---
### <a id="trampoline-message">2.2 Trampoline Message</a>

The `"trampoline"` message sends a trampoline template specification
to E9Patch that can be used to patch instructions.

#### Parameters:

* `"name"`: the name of the trampoline.
  Valid names must start with the dollar character.
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
  Macros are expanded with meta data values provided by the `"patch"` message
  (see below) or a template from another "trampoline" message.
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
* An empty value: represented by the `null` token.

Several builtin macros are implicitly defined, including:

* `"$bytes"`: The original byte sequence of the instruction that was patched
* `"$instr"`: A byte sequence of instructions that emulates the
  patched instruction.
  Note that this is usually equivalent to `"$bytes"` except for
  instructions that are position-dependent.
* `"$break"` (thin break): A byte sequence of instructions that will return
  control-flow to the next instruction after the matching instruction.
  The `"$break"` builtin macro is guaranteed to be implemented as a single
  `jmpq rel32` instruction.
* `"$BREAK"` (fat break): Semantically equivalent to `"$break"`, but the
  implementation is not limited to a single jump instruction.
  This allows for a more aggressive optimization that is possible using a
  thin `"$break"`, but at the cost of more space usage.
  For optimal results, each trampoline should use exactly one fat `"$BREAK"`,
  with thin `"$break"` used for the rest (if applicable).
* `"$take"`: Similar to `"$break"`, but for the branch-taken case of
  conditional jumps.

Several builtin labels are also implicitly defined, including:

* `".Lbreak"`: The address corresponding to `"$break"`
* `".Ltake"`: The address corresponding to `$take"`
* `".Linstr"`: The address of the matching instruction.
* `".Lconfig"`: The address of the internal E9Patch configuration structure.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "trampoline",
            "params":
            {
                "name": "$print",
                "template": [
                    72, 141, 164, 36, 0, 192, 255, 255,
                    87,
                    86,
                    80,
                    81,
                    82,
                    65, 83,
                    72, 141, 53, {"rel32": ".LasmStr"},
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
                    "$instr",
                    "$BREAK",
                    ".LasmStr",
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
            leaq .LasmStr(%rip),%rsi
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
            $instr
    
            # Return from the trampoline
            $BREAK
    
            # Store the asm String here:
        .LasmStr:
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

The above code uses two user-defined macros, namely `"$asmStr"` and
`"$asmStrLen"`.
The values of these macros depend on the matching instruction, so will be
instantiated by meta data defined by the "patch" message (see below).

---
### <a id="reserve-message">2.3 Reserve Message</a>

The `"reserve"` message is useful for reserving sections of the
patched program's virtual address space and (optionally) initializing
it with data.
The reserved address range will not be used to host trampolines.

Note that the reserved address range will be implicitly rounded to the
nearest page boundary.
This means that trampoline and reserved memory will be disjoint at the
page level.

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
* `"init"`: [optional] the address of an initialization routine that will
  be called when the patched program is loaded into memory.
* `"fini"`: [optional] the address of a finalization routine that will be
  called when the patched program exits normally.
* `"mmap"`: [optional] the address of a replacement implementation of
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
* `"trampoline"`: a trampoline name (sent by a previous "trampoline"
    message) or a trampoline template.
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
                "trampoline": "$print",
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
### <a id="options-message">2.6 Options Message</a>

The `"options"` message allows E9Patch command-line options to be passed using
the JSON-RPC interface.
The new options will be applied to subsequent messages.
For the complete list of command-line options, see:

        ./e9patch --help

#### Parameters:

* `"argv"`: a list of command-line options.

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "options",
            "params":
            {
                "argv": ["--tactic-T3=false", "--mem-mapping-size=4096"]
            },
            "id": 777
        }

---
### <a id="emit-message">2.7 Emit Message</a>

The `"emit"` message instructs E9Patch to emit the patched binary file.

#### Parameters:

* `"filename"`: the path where the patched binary file is to be written to.
* `"format"`: the format of the patched binary.
    Supported values include `"binary"` (an ELF binary)
    `"patch"` (a binary diff) and
    `"patch.gz"`/`"patch.bz2"`/`"patch.xz"` (a compressed binary diff).

#### Example:

        {
            "jsonrpc": "2.0",
            "method": "emit",
            "params":
            {
                "filename": "a.out",
                "format": "binary"
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

The E9Tool plugin API is very simple and consists of the following functions:

1. `e9_plugin_init_v1(const Context *cxt)`:
    Called once before the binary is disassembled.
2. `e9_plugin_match_v1(const Context *cxt)`:
    Called once for each match location.
3. `e9_plugin_patch_v1(const Context *cxt, Phase phase)`:
    Called for each patch location (see the `Phase` enum).
4. `e9_plugin_fini_v1(const Context *cxt)`:
    Called once after all instructions have been patched.
5. `e9_plugin_event_v1(const Context *cxt, void *arg)`:
    Called once for each event (see the `Event` enum).

Note that each function is optional, and the plugin can choose not to
define it.  However, The plugin must define at least one of these functions
to be considered valid.

Each function takes at least one argument, namely the "context" of type
`Context` defined in `e9plugin.h`.
The `Context` structure contains several fields, including:

* `out`: is the JSON-RPC output stream that is sent to the E9Patch
   backend.
   The plugin can directly emit messages to this stream.
* `argv`: is a vector of all command-line options passed in using
   E9Tool's `--plugin` option.
* `context`: is the plugin-defined context, which is the return value of
   the `e9_plugin_init_v1()` function.
* `elf`: is the input ELF file.
* `Is`: is a vector containing all disassembled instructions, sorted by
   address.
* `idx`: is the index (into `Is`) of the instruction being matched/patched.
* `I`: is detailed information about the instruction being matched/patched.
* `id`: is the current patch ID.

Notes:

* Not all `Context` fields will be defined for each operation.
  For example, the `Is` field will be undefined before the input binary has
  been disassembled.
  Undefined fields will have the value `NULL`/`-1`, depending on the type.
* The `I` structure (if defined) is *temporary*, and will be immediately
  destroyed once the plugin function returns.
  Plugins must ***not*** store references to this object.
* The `Is` array (if defined) is persistent, and the plugin may safely store
  references to this object until `e9_plugin_fini_v1()` returns.

Some API functions take an additional enumeration value:

* `e9_plugin_event_v1()` takes an `Event` enum value which indicates
  one of the following:
  - `EVENT_DISASSEMBLY_COMPLETE`: Disassembly completed.
  - `EVENT_MATCHING_COMPLETE`: Matching completed.
  - `EVENT_PATCHING_COMPLETE`: Patching completed.
* `e9_plugin_patch_v1()` take a `Phase` enum value that represents what
  part of the patch should be emitted:
  - `PHASE_CODE`: Emit the executable code in trampoline template format.
  - `PHASE_DATA`: Emit any data referenced by the code in trampoline template
    format.
  - `PHASE_METADATA`: Emit instruction-specific metadata as comma-separated
    `key:value` pairs, where `key` is a macro name, and `value` is a value
    specified in trampoline template format.

Some API function return a value, including:

* `e9_plugin_init_v1()` returns an optional `context` that will be
   passed to all other API calls through the `cxt->context` field.
* `e9_plugin_match_v1()` returns an integer value of the plugin's
   choosing.  This integer value can be matched using by the `--match`/`-M`
   E9Tool command-line options, else the value will be ignored.

The API is designed to be highly flexible.  Basically, the plugin API
functions are expected to send JSON-RPC messages (or parts of messages)
directly to the E9Patch backend by writing to the `out` output stream.
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

The `e9_plugin_match_v1()` function will do the following:

1. Return a value to be used in a matching.

The `e9_plugin_patch_v1()` function will do the following:

1. Send the code, data and metadata for each patch operation.

The `e9_plugin_fini_v1()` function will do any cleanup if necessary.

Note that the `e9_plugin_patch_v1()` sends *parts* of a JSON-RPC "patch"
message, and not a whole message.
This design is necessary to make trampolines composable with each other.

See the `e9frontend.h` file for useful functions that can assist with these
tasks.  Otherwise, there are no limitations on what these functions can do,
just provided the E9Patch backend can parse the JSON-RPC messages sent by
the plugin.  This makes the plugin API very powerful.

---
### 3.1 Using Plugins

Plugins can be used by E9Tool and the `--patch`/`-P` option.
For example:

        g++ -std=c++11 -fPIC -shared -o myPlugin.so myPlugin.cpp -I src/e9tool/
        ./e9tool -M 'plugin(myPlugin).match() > 0x333' -P 'plugin(myPlugin).patch()' xterm

The syntax is as follows:

* `-M`: Selects the E9Tool "match" command-line option.
* `-P`: Selects the E9Tool "patch" command-line option.
  This tells E9Tool what patching/instrumentation to do.
* `plugin(myPlugin).match() > 0x333`: Specifies that we should only rewrite
  instructions for which the `e9_plugin_match_v1()`
  function returns a value greater than `0x333`.
* `plugin(myPlugin).patch()`: Specifies that instrument the program using the
  `e9_plugin_patch_v1()` function.

For this example to work, the `myPlugin.so` plugin must export both the
`e9_plugin_match_v1()` and `e9_plugin_patch_v1()` functions.

For an example plugin, see `examples/plugin/example.cpp`.

