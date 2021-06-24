# E9Tool User's Guide

**NOTE**: This guide is a work-in-progress and still incomplete.

E9Tool is a frontend for E9Patch.
Basically, E9Tool translates high-level patching commands
(i.e., *what* instructions to patch, and *how* to patch them)
into low-level commands for E9Patch.
E9Patch is very low-level tool and not designed
to be used directly.

---
## Contents

* [1. Matching Language](#s1)
    - [1.1 Attributes](#s11)
    - [1.2 Definedness](#s12)
    - [1.3 Examples](#s13)
    - [1.4 Exclusions](#s14)
* [2. Action Language](#s2)
    - [2.1 Builtin Actions](#s21)
    - [2.2 Call Actions](#s22)
        * [2.2.1 Call Action Arguments](#s221)
            - [2.2.1.1 Pass-by-pointer](#s2211)
            - [2.2.1.2 Polymorphic Arguments](#s2212)
            - [2.2.1.4 Explicit Memory Operand Arguments](#s2213)
            - [2.2.1.4 Undefined Arguments](#s2214)
        * [2.2.2 Call Action Options](#s222)
        * [2.2.3 Call Action Standard Library](#s223)
        * [2.2.4 Call Action Initialization](#s224)
    - [2.3 Plugin Actions](#s23)

---
## <a id="s1">1. Matching Language</a>

The *matching language* specifies what instructions should be patched by
the corresponding *action* (see below).
Matchings are specified using the (`--match MATCH`) or
(`-M MATCH)` command-line option.
The basic form of a matching (`MATCH`) is a Boolean expression of
`TEST`s using the following high-level grammar:

<pre>
    MATCH ::=   TEST
              | <b>(</b> MATCH <b>)</b>
              | <b>not</b> MATCH
              | MATCH <b>and</b> MATCH
              | MATCH <b>or</b> MATCH
</pre>


Alternatively, C-style Boolean operations (`!`, `&&`, and `||`) can be used
instead of (`not`, `and`, and `or`).

Each `TEST` queries some specific property/attribute of the underlying
instruction, defined using the following grammar:

<pre>
    TEST ::=   <b>defined</b> <b>(</b> ATTRIBUTE <b>)</b>
             | VALUES <b>in</b> ATTRIBUTE
             | ATTRIBUTE [ CMP VALUES ]

    VALUES ::=   REGULAR-EXPRESSION
               | VALUE [ <b>,</b> VALUE ] *
               | BASENAME <b>[</b> INTEGER <b>]</b>

    CMP ::=   <b>=</b> | <b>==</b> | <b>!=</b> | <b>&gt;</b> | <b>&gt;=</b> | <b>&lt;</b> | <b>&lt;=</b>
</pre>

A `TEST` tests some underlying instruction `ATTRIBUTE` using an
integer, string or set comparison operator `CMP`.
The following comparison operators are supported:

<table border="1">
<tr><th>Comparison</th><th>Type</th><th>Description</th></tr>
<tr><td><b><tt>=</tt> or <tt>==</tt></b></td><td><tt>Integer</tt> or <tt>String</tt></td>
    <td>Equality</td></tr>
<tr><td><b><tt>!=</tt></b></td><td><tt>Integer</tt> or <tt>String</tt></td>
    <td>Disequality</td></tr>
<tr><td><b><tt>&gt;</tt></b></td><td><tt>Integer</tt></td>
    <td>Greater-than</td></tr>
<tr><td><b><tt>&gt;=</tt></b></td><td><tt>Integer</tt></td>
    <td>Greater-than-or-equal-to</td></tr>
<tr><td><b><tt>&lt;</tt></b></td><td><tt>Integer</tt></td>
    <td>Less-than</td></tr>
<tr><td><b><tt>&lt;=</tt></b></td><td><tt>Integer</tt></td>
    <td>Less-than-or-equal-to</td></tr>
<tr><td><b><tt>in</tt></b></td><td><tt>Set</tt></td>
    <td>Set membership</td></tr>
</table>

If the comparison operator and value are omitted, then the test is
equivalent to (`ATTRIBUTE != 0`).

A `VALUE` can be either:

* An *integer constant*, e.g., `123`, `0x123`, etc.
* A *string constant*, e.g., `"abc"`, etc.
* An *enumeration value* such as register names (`rax`, `eax`, etc.), operand types
  (`imm`, `reg`, `mem`), etc.
* A *symbolic address* of the form `NAME`, where `NAME` is any section
  or symbol name from the input ELF file.
  A symbolic address has type `Integer`.

For string attributes, the value can be a regular expression.
This means that the corresponding attribute value must either
match (for `==`) or not match (for `!=`) the regular expression,
depending on the comparison operator.

---
### <a id="s11">1.1 Attributes</a>

The following `ATTRIBUTE`s (with corresponding types) are
supported:

<table border="1">
<tr><th>Attribute</th><th>Type</th><th>Description</th></tr>
<tr><td><b><tt>true</tt></b></td><td><tt>Boolean</tt></td><td>True</td></tr>
<tr><td><b><tt>false</tt></b></td><td><tt>Boolean</tt></td><td>False</td></tr>
<tr><td><b><tt>jump<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for jump instructions, false otherwise</tt></td>
<tr><td><b><tt>call<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for call instructions, false otherwise</tt></td>
<tr><td><b><tt>return<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for return instructions, false otherwise</tt></td>
<tr><td><b><tt>asm</tt></b></td><td><tt>String</tt></td>
    <td>The assembly string representation</td></tr>
<tr><td><b><tt>mnemonic</tt></b></td><td><tt>String</tt></td>
    <td>The mnemonic</td></tr>
<tr><td><b><tt>section</tt></b></td><td><tt>String</tt></td>
    <td>The section name</td></tr>
<tr><td><b><tt>addr</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF virtual address</td></tr>
<tr><td><b><tt>offset</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF file offset</td></tr>
<tr><td><b><tt>size</tt></b></td><td><tt>Integer</tt></td>
    <td>The size of the instruction in bytes</td></tr>
<tr><td><b><tt>random</tt></b></td><td><tt>Integer</tt></td>
    <td>A random value [0..<tt>RAND_MAX</tt>]</td></tr>
<tr><td><b><tt>target</tt></b></td><td><tt>Intger</tt></td>
    <td>The jump/call target (if statically known).</td></tr>
<tr><td><b><tt>op.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of operands</td></tr>
<tr><td><b><tt>src.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of source operands</td></tr>
<tr><td><b><tt>dst.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of destination operands</td></tr>
<tr><td><b><tt>imm.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of immediate operands</td></tr>
<tr><td><b><tt>reg.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of register operands</td></tr>
<tr><td><b><tt>mem.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of memory operands</td></tr>
<tr><td><b><tt>op[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> operand</td></tr>
<tr><td><b><tt>src[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand</td></tr>
<tr><td><b><tt>dst[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand</td></tr>
<tr><td><b><tt>imm[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> immediate operand</td></tr>
<tr><td><b><tt>reg[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> register operand</td></tr>
<tr><td><b><tt>mem[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand</td></tr>
<tr><td><b><tt>op[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <i>i</i><sup>th</sup> operand type</td></tr>
<tr><td><b><tt>src[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand type</td></tr>
<tr><td><b><tt>dst[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand type</td></tr>
<tr><td><b><tt>op[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <i>i</i><sup>th</sup> operand access</td></tr>
<tr><td><b><tt>src[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand access</td></tr>
<tr><td><b><tt>dst[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand access</td></tr>
<tr><td><b><tt>reg[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <i>i</i><sup>th</sup> register operand access</td></tr>
<tr><td><b><tt>mem[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand access</td></tr>
<tr><td><b><tt>op[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> operand segment register</td></tr>
<tr><td><b><tt>src[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand segment register</td></tr>
<tr><td><b><tt>dst[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand segment register</td></tr>
<tr><td><b><tt>mem[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand segment register</td></tr>
<tr><td><b><tt>op[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> operand displacement</td></tr>
<tr><td><b><tt>src[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand displacement</td></tr>
<tr><td><b><tt>dst[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand displacement</td></tr>
<tr><td><b><tt>mem[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand displacement</td></tr>
<tr><td><b><tt>op[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> operand base register</td></tr>
<tr><td><b><tt>src[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand base register</td></tr>
<tr><td><b><tt>dst[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand base register</td></tr>
<tr><td><b><tt>mem[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand base register</td></tr>
<tr><td><b><tt>op[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> operand index register</td></tr>
<tr><td><b><tt>src[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand index register</td></tr>
<tr><td><b><tt>dst[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand index register</td></tr>
<tr><td><b><tt>mem[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand index register</td></tr>
<tr><td><b><tt>op[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> operand scale</td></tr>
<tr><td><b><tt>src[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> source operand scale</td></tr>
<tr><td><b><tt>dst[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> destination operand scale</td></tr>
<tr><td><b><tt>mem[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <i>i</i><sup>th</sup> memory operand scale</td></tr>
<tr><td><b><tt>regs</tt></b></td><td><tt>Set&lt;Register&gt;</tt></td>
    <td>The set of all accessed registers</td></tr>
<tr><td><b><tt>reads</tt></b></td><td><tt>Set&lt;Register&gt;</tt></td>
    <td>The set of all read-from registers</td></tr>
<tr><td><b><tt>writes</tt></b></td><td><tt>Set&lt;Register&gt;</tt></td>
    <td>The set of all written-to registers</td></tr>
<tr><td><b><tt>plugin(NAME).match()</tt></b></td><td><tt>Integer</tt></td>
    <td>Value from <tt>NAME.so</tt> plugin</td></tr>
</table>

Here `Register` is the set of all `x86_64` register names defined as
follows:

        Register = {
            rip, rflags,
            es, cs, ss, ds, fs, gs,
            ah, ch, dh, bh,
            al, cl, dl, bl, spl, bpl, sil, dil, r8b, ..., r15b,
            ax, cx, dx, bx, sp, bp, si, di, r8w, ..., r15w,
            eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, ..., r15d,
            rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, ..., r15,
            xmm0, ..., xmm31,
            ymm0, ..., ymm31,
            zmm0, ..., zmm31, ...}

An `Operand` can be one of three values:

* An immediate value represented by an `Integer`
* A register represented by a `Register`
* A memory operand (not representable)

Thus the `Operand` type is the union of the `Integer` and `Register` types:

        Operand = Integer | Register

---
### <a id="s12">1.2 Definedness</a>

Not all attributes are defined for all instructions.
For example, if the instruction has 3 operands, then only `op[0]`, `op[1]`,
and `op[2]` will be *defined*, and `op[3]` and beyond will be
*undefined*.
Similarly, `op[0].base` will be *undefined* if the first operand of the
instruction is not a memory operand.

Any test that uses an undefined value will fail.
For example, both of the tests (`op[3] == 0x1`) and (`op[3] != 0x1`) will
fail, despite each test being the negation of the other.
The explicit Boolean operators (`not`, `and`, and `or`) treat failure
due to undefinedness the same as `false`, thus the tests
(`op[3] != 0x1`) and (`not op[3] == 0x1`) are not equivalent
for undefined values.

The special `defined(ATTRIBUTE)` test can be used to determine if
an attribute is defined or not.

---
### <a id="s13">1.3 Examples</a>

* (`true`):
  match every instruction.
* (`false`):
  do not match any instruction.
* (`asm == jmp.*%r.*`):
  match all instructions whose assembly representation matches
  the regular expression `jmp.*%r.*`
  (will match jump instructions that access a register).
* (`mnemonic == jmp`):
  match all instructions whose mnemonic is `jmp`.
* (`addr == 0x4234a7`):
  match the instruction at the virtual address `0x4234a7`.
* (`addr == 0x4234a7,0x44bd6e,0x4514b4`):
  match the instructions at the virtual addresses
  `0x4234a7`, `0x44bd6e`, and `0x4514b4`.
* (`addr >= 0x4234a7 and addr <= 0x4514b4`):
  match all instructions in the virtual address range
  `0x4234a7..0x4514b4`
* (`op.size > 1`):
  match all instructions with more than one operand.
* (`reg.size == 2`):
  match all instructions with exactly two register operands.
* (`op[0] == 0x1234`):
  match all instructions where the first operand is the immediate
  value `0x1234`.
* (`op[0] == rax`):
  match all instructions where the first operand is the `%rax` register.
* (`op[0].type == mem`):
  match all instructions where the first operand is a memory operand.
* (`reg[0] == rax and reg[1] == rbx`):
  match all instructions where the first and second register operands
  are `%rax` and `%rbx` respectively.
* (`mem[0].base == rax and mem[0].index == rbx`):
  match all instructions with a memory operand with `%rax` as the
  base and `%rbx` as the index.
* (`mem[0].base == nil`):
  match all instructions with a memory operand that does not use a base
  register.
* (`rflags in reads`):
  match all instructions that read the flags register.
* (`rflags in writes`):
  match all instructions that modify the flags register.
* (`not rflags in regs`):
  match all instructions that do not access the flags register.
* `defined(mem[0])`:
  match all instructions that have at least one memory operand.
* (`call and target == &malloc`):
  match all direct calls to `malloc()`.

---
### <a id="s14">1.4 Exclusions</a>

*Exclusions* are an additional method for controlling which instructions are
patched.
An exclusion is specified by the (`--exclude RANGE`) or (or `-E RANGE`)
command line option, where `RANGE` specifies a range of addresses that
should not be disassembled or rewritten.
Exclusions are more low-level than the matching language since the `RANGE`
will not even be disassembled.
This can help solve some problems, such as the binary storing data
inside the `.text` section.

The general syntax for `RANGE` is:
<pre>
    RANGE ::=   ADDR [ <b>..</b> ADDR ]
    ADDR  ::=   VALUE [ <b>+</b> INTEGER ]
    VALUE ::=   INTEGER
              | SYMBOL
              | SECTION [ <b>.</b> ( <b>start</b> | <b>end</b> ) ]
</pre>
For example:

* `0x12345...0x45689`: exclude a specific address range
* `.text..ChromeMain`: exclude the `.text` section up to the symbol `ChromeMain`
* `.plt .. .text`: exclude a range of sections
* `.plt.start .. .text.end`: equivalent to the above
* `.plt .. .text.start`: exclude all sections between `.plt` and the starting
  address of `.text`.  The `.text` section itself will not be excluded.
* `malloc .. malloc+16`: exclude the 16-byte PLT entry for malloc.
* `.text`: exclude the entire `.text` section.

Note that a `RANGE` may include a lower and upper bound, i.e., `LB .. UB`.
If the `UB` is omitted, then `UB=LB` is implied.
The instruction at the address `UB` is *not* excluded, and disassembly will
resume from this address.
In other words, the syntax `LB .. UB` represents the address range `[LB..UB)`,
and E9Tool assumes that `UB` points to a valid instruction from which
disassembly can resume.

---
## <a id="s2">2. Action Language</a>

The *action language* specifies how to patch matching instructions
from the input binary.
Actions are specified using the (`--action ACTION`) or
(`-A ACTION)` command-line option, and must be paired with one
or more matchings.
The basic form of an action (`ACTION`) uses
the following high-level grammar:

<pre>
    ACTION ::=   <b>passthru</b>
               | <b>trap</b>
               | <b>exit(</b>CODE<b>)</b>
               | <b>print</b>
               | CALL
               | <b>plugin(</b>NAME<b>).patch()</b>
</pre>

An action is either *builtin*, a *call*, or defined by a *plugin*.

---
### <a id="s21">2.1 Builtin Actions</a>

The builtin actions include:

<table border="1">
<tr><th>Action</th><th>Description</th></tr>
<tr><td><b><tt>passthru</tt></b></td>
    <td>Empty instrumentation</td></tr>
<tr><td><b><tt>trap</tt></b></td>
    <td>Trap (<tt>int3</tt>) instrumentation</td></tr>
<tr><td><b><tt>exit(CODE)</tt></b></td>
    <td>Exit with <tt>CODE</tt> instrumentation</td></tr>
<tr><td><b><tt>print</tt></b></td>
    <td>Instruction printing instrumentation</td></tr>
</table>

Here:

* The `passthru` instrumentation uses empty trampolines that do nothing
  other than return control flow back to the main program.
  This can be used to establish a baseline for benchmarking.
* The `trap` instrumentation executes a single trap (`int3`) instruction.
* The `exit(CODE)` instrumentation immediately exits the program
  with status `CODE`.
* The `print` instrumentation inserts a trampoline that prints the
  assembly representation of the instrumented instruction to `stderr`.
  This can be used for testing and debugging.

---
### <a id="s22">2.2 Call Actions</a>

A *call* action calls a user-defined function that can be implemented
in a high-level programming language such as C or C++.
Call actions are the main way of implementing custom patches using
E9Tool.
The syntax for a call action is as follows:

<pre>
    CALL ::=  <b>call</b> [ OPTIONS ] FUNCTION [ ARGS ] <b>@</b> BINARY

    OPTIONS ::=   <b>[</b> OPTION <b>,</b> ... <b>]</b>
    OPTION  ::=   <b>clean</b> | <b>naked</b>
                | <b>before</b> | <b>after</b> | <b>replace</b> | <b>conditional</b> [ <b>.</b> <b>jump</b> ]

    ARGS ::=   <b>(</b> ARG <b>,</b> ... <b>)</b>
</pre>

The call action specifies that the trampoline should call function
`FUNCTION` from the instrumentation binary `BINARY` with the arguments
`ARGS`.

To use a call action, simply implement the desired instrumentation
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
`gcc` with the necessary options in order to generate an E9Tool
compatible binary:

        ./e9compile.sh counter.c

---
#### <a id="s221">2.2.1 Call Action Arguments</a>

Call actions also support passing arguments to the called function.
The syntax uses the `C`-style round brackets.
For example:

        ./e9tool -M ... -A 'call func(rip)@example' xterm

This specifies that the current value of the instruction pointer
`%rip` should be passed as the first argument to the function
`func()`.
The called function can use this argument, e.g.:

        void func(const void *rip)
        {
            ...
        }

Call actions support up to eight *arguments*.
The following arguments are supported:

<table border="1">
<tr><th>Argument</th><th>Type</th><th>Description</th></tr>
<tr><td><i>Integer</i></td><td><tt>intptr_t</tt></td>
    <td>An integer constant</td></tr>
<tr><td><tt>&amp;</tt><i>Name</i></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the named section/symbol/PLT/GOT entry</td></tr>
<tr><td><tt>static &amp;</tt><i>Name</i></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the named section/symbol/PLT/GOT entry</td></tr>
<tr><td><b><tt>asm</tt></b></td><td><tt>const char &#42;</tt></td>
    <td>Assembly representation of the matching instruction</td></tr>
<tr><td><b><tt>asm.size</tt></b></td><td><tt>size_t</tt></td>
    <td>The number of bytes in <tt>asm</tt> (including the nul character)</td></tr>
<tr><td><b><tt>asm.len</tt></b></td><td><tt>size_t</tt></td>
    <td>The string length of <tt>asm</tt> (excluding the nul character)</td></tr>
<tr><td><b><tt>base</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime base address of the binary</td></tr>
<tr><td><b><tt>addr</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the matching instruction</td></tr>
<tr><td><b><tt>static addr</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the matching instruction</td></tr>
<tr><td><b><tt>id</tt></b></td><td><tt>intptr_t</tt></td>
    <td>A unique identifier (one per patch)</td></tr>
<tr><td><b><tt>instr</tt></b></td><td><tt>const uint8_t &#42;</tt></td>
    <td>The machine-code bytes of the matching instruction</td></tr>
<tr><td><b><tt>next</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the next executed instruction</td></tr>
<tr><td><b><tt>static next</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the next executed instruction</td></tr>
<tr><td><b><tt>offset</tt></b></td><td><tt>off_t</tt></td>
    <td>The ELF file offset of the matching instruction</td></tr>
<tr><td><b><tt>target</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the jump/call/return target, else <tt>NULL</tt></td></tr>
<tr><td><b><tt>static target</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the jump/call/return target, else <tt>NULL</tt></td></tr>
<tr><td><b><tt>trampoline</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the trampoline</td></tr>
<tr><td><b><tt>random</tt></b></td><td><tt>intptr_t</tt></td>
    <td>A (statically generated) random integer [0..<tt>RAND_MAX</tt>]</td></tr>
<tr><td><b><tt>size</tt></b></td><td><tt>size_t</tt></td>
    <td>The size of <tt>instr</tt> in bytes</td></tr>
<tr><td><b><tt>state</tt></b></td><td><tt>void &#42;</tt></td>
    <td>A pointer to a structure containing all general purpose registers</td></tr>
<tr><td><b><tt>ah</tt></b>,...,<b><tt>dh</tt></b>, <b><tt>al</tt></b>,...,<b><tt>r15b</tt></b></td><td><tt>int8_t</tt></td>
    <td>The corresponding 8bit register</td></tr>
<tr><td><b><tt>ax</tt></b>,...,<b><tt>r15w</tt></b></td><td><tt>int16_t</tt></td>
    <td>The corresponding 16bit register</td></tr>
<tr><td><b><tt>eax</tt></b>,...,<b><tt>r15d</tt></b></td><td><tt>int32_t</tt></td>
    <td>The corresponding 32bit register</td></tr>
<tr><td><b><tt>rax</tt></b>,...,<b><tt>r15</tt></b></td><td><tt>int64_t</tt></td>
    <td>The corresponding 64bit register</td></tr>
<tr><td><b><tt>rflags</tt></b></td><td><tt>int16_t</tt></td>
    <td>The <tt>%rflags</tt> register with format
    <tt>SF:ZF:0:AF:0:PF:1:CF:0:0:0:0:0:0:0:OF</tt></td></tr>
<tr><td><b><tt>rip</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The <tt>%rip</tt> register</td></tr>
<tr><td><b><tt>&amp;ah</tt></b>,...,<b><tt>&amp;dh</tt></b>, <b><tt>&amp;al</tt></b>,...,<b><tt>&amp;r15b</tt></b></td><td><tt>int8_t &#42;</tt></td>
    <td>The corresponding 8bit register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;ax</tt></b>,...,<b><tt>&amp;r15w</tt></b></td><td><tt>int16_t &#42;</tt></td>
    <td>The corresponding 16bit register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;eax</tt></b>,...,<b><tt>&amp;r15d</tt></b></td><td><tt>int32_t &#42;</tt></td>
    <td>The corresponding 32bit register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;rax</tt></b>,...,<b><tt>&amp;r15</tt></b></td><td><tt>int64_t &#42;</tt></td>
    <td>The corresponding 64bit register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;rflags</tt></b></td><td><tt>int16_t &#42;</tt></td>
    <td>The <tt>%rflags</tt> register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand</td></tr>
<tr><td><b><tt>src[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand</td></tr>
<tr><td><b><tt>dst[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination operand</td></tr>
<tr><td><b><tt>imm[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> immediate operand</td></tr>
<tr><td><b><tt>reg[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> register operand</td></tr>
<tr><td><b><tt>mem[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand</td></tr>
<tr><td><b><tt>&amp;op[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i]</tt></b></td><td><tt>int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;imm[i]</tt></b></td><td><tt>const int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> immediate operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;reg[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> register operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i]</tt></b></td><td><tt>int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand size</td></tr>
<tr><td><b><tt>src[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    size</td></tr>
<tr><td><b><tt>dst[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand size</td></tr>
<tr><td><b><tt>imm[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> immediate operand
    size</td></tr>
<tr><td><b><tt>reg[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> register operand
    size</td></tr>
<tr><td><b><tt>mem[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    size</td></tr>
<tr><td><b><tt>op[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand type
    (1=immediate, 2=register, 3=memory operand)</td></tr>
<tr><td><b><tt>src[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    type</td></tr>
<tr><td><b><tt>dst[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand type</td></tr>
<tr><td><b><tt>imm[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> immediate operand
    type</td></tr>
<tr><td><b><tt>reg[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> register operand
    type</td></tr>
<tr><td><b><tt>mem[i].type</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    type</td></tr>
<tr><td><b><tt>op[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand access
    (<tt>0x80 | PROT_READ | PROT_WRITE</tt>)
<tr><td><b><tt>src[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    access</td></tr>
<tr><td><b><tt>dst[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand access</td></tr>
<tr><td><b><tt>imm[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> immediate operand
    access</td></tr>
<tr><td><b><tt>reg[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> register operand
    access</td></tr>
<tr><td><b><tt>mem[i].access</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    access</td></tr>
<tr><td><b><tt>op[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand 
    displacement</td></tr>
<tr><td><b><tt>src[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    displacement</td></tr>
<tr><td><b><tt>dst[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand displacement</td></tr>
<tr><td><b><tt>mem[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    displacement</td></tr>
<tr><td><b><tt>op[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand base
    register</td></tr>
<tr><td><b><tt>src[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    base register</td></tr>
<tr><td><b><tt>dst[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand base register</td></tr>
<tr><td><b><tt>mem[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    base register</td></tr>
<tr><td><b><tt>&amp;op[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand base
    register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand index
    register</td></tr>
<tr><td><b><tt>src[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    index register</td></tr>
<tr><td><b><tt>dst[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand index register</td></tr>
<tr><td><b><tt>mem[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    index register</td></tr>
<tr><td><b><tt>&amp;op[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand index
    register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> operand 
    scale</td></tr>
<tr><td><b><tt>src[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> source operand
    scale</td></tr>
<tr><td><b><tt>dst[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> destination
    operand scale</td></tr>
<tr><td><b><tt>mem[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <i>i</i><sup>th</sup> memory operand
    scale</td></tr>
<tr><td><b><tt>mem8&lt;MEMOP&gt;</tt></b></td><td><tt>int8_t</tt></td>
    <td>An explicit 8-bit <tt>MEMOP</tt></td></tr>
<tr><td><b><tt>mem16&lt;MEMOP&gt;</tt></b></td><td><tt>int16_t</tt></td>
    <td>An explicit 16-bit <tt>MEMOP</tt></td></tr>
<tr><td><b><tt>mem32&lt;MEMOP&gt;</tt></b></td><td><tt>int32_t</tt></td>
    <td>An explicit 32-bit <tt>MEMOP</tt></td></tr>
<tr><td><b><tt>mem64&lt;MEMOP&gt;</tt></b></td><td><tt>int64_t</tt></td>
    <td>An explicit 64-bit <tt>MEMOP</tt></td></tr>
<tr><td><b><tt>&amp;mem8&lt;MEMOP&gt;</tt></b></td><td><tt>int8_t &#42;</tt></td>
    <td>An explicit 8-bit <tt>MEMOP</tt> (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem16&lt;MEMOP&gt;</tt></b></td><td><tt>int16_t &#42;</tt></td>
    <td>An explicit 16-bit <tt>MEMOP</tt> (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem32&lt;MEMOP&gt;</tt></b></td><td><tt>int32_t &#42;</tt></td>
    <td>An explicit 32-bit <tt>MEMOP</tt> (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem64&lt;MEMOP&gt;</tt></b></td><td><tt>int64_t &#42;</tt></td>
    <td>An explicit 64-bit <tt>MEMOP</tt> (passed-by-pointer)</td></tr>
</table>

Notes:

* The `rflags` argument differs from the native
  `x86_64` layout in terms of the number of flags as well as the flag ordering.
  The modified layout is used for efficiency reasons since preserving the
  native layout is a relatively slow operation.
* For technical reasons, the `%rip` register is considered constant and cannot
  be modified.
* The `state` argument is a pointer to a structure containing all
  general-purpose and flag registers.
  See the `examples/state.c` example for the structure layout.
  The values in the structure can be modified, in which case the corresponding
  register will be updated accordingly.
  The structure does not include the stack register (`%rsp`) which must be
  passed separately.
* The `static` version of some arguments gives the address relative to the ELF
  base, given by the formula: *runtime address = ELF address + ELF base*.
  This corresponds to the value used by the matching.

---
##### <a id="s2211">2.2.1.1 Pass-by-pointer</a>

Some arguments can be passed by pointer.
This allows the corresponding value to be modified (provided the
corresponding type is not `const`),
making it possible to manipulate the state of the program at
runtime.

For example, the consider the following simple function defined in
`example.c`:

        void inc(int64_t *ptr)
        {
            *ptr += 1;
        }

And the following action:

        $ e9compile.sh example.c
        $ e9tool -M ... -A 'call inc(&rax)@example' xterm

This action will increment the `%rax` register when the `inc()` function
is called for each matching instruction.

Attempting to write to a `const` pointer is undefined behavior.
Typically, this will result in a crash or the written value will be
silently ignored.

The passed pointer depends on the operand type:

* For immediate operands (e.g., `&imm[i]`), the pointer will
  point to a constant value stored in read-only memory.
* For register operands (e.g., `&reg[i]`), the pointer will
  point to a temporary location that holds the register value.
* For memory operands (e.g., `&mem[i]`), the pointer will be exactly
  the runtime pointer value calculated by the operand itself.
  For example, consider the instruction (`mov 0x33(%rax,%rbx,2),%rcx`),
  then the value for `&mem[0]` will be (`0x33+%rax+2*%rbx`).

Generally, it is recommended to pass memory operands by pointer rather
than by value.
If passed by value, the memory operand pointer will be dereferenced, which
may result in a crash for instructions such as (`nop`) and (`lea`) that
do not access the operand.

---
##### <a id="s2212">2.2.1.2 Polymorphic Arguments</a>

Some arguments can have different types, depending on the instruction.
For example, with:

        mov %rax,%rbx
        mov %eax,%ebx
        mov %ax,%bx
        mov %al,%bl

The corresponding types for `&op[0]` will be (`int64_t *`), (`int32_t *`),
(`int16_t *`) and (`int8_t *`) respectively.
If the function is defined in `C`, there is no way to know the type of
the passed argument.

One solution is to implement the functions in `C++` rather than `C`,
and to use function overloading.
For example, using `C++`, one can define:

        void func(int64_t *x) { ... }
        void func(int32_t *x) { ... }
        void func(int16_t *x) { ... }
        void func(int8_t *x)  { ... }

Next, the program can be rewritten as follows:

        $ e9compile.sh example.cpp
        $ e9tool -M ... -A 'call func(&op[0])@example' xterm

E9Tool will automatically select the function instance that best
matches the argument types, or generate an error if no appropriate
match can be found.

---
##### <a id="s2213">2.2.1.3 Explicit Memory Operand Arguments</a>

It is possible to pass explicit memory operands as arguments.
This is useful for reading/writing to known memory locations, such as
stack memory.
The syntax is:
<pre>
    ( <b>mem8</b> | <b>mem16</b> | <b>mem32</b> | <b>mem64</b> ) <b>&lt;</b> MEMOP <b>&gt;</b>
</pre>
Here, the <tt>mem8</tt>...<tt>mem64</tt> token specifies the size of
the memory operand, and <tt>MEMOP</tt> is the memory operand itself
specified in AT&amp;T syntax.
For example, the following explcit memory operands access stack memory:

        mem64<(%rsp)>
        mem64<0x100(%rsp)>
        mem64<0x200(%rsp,%rax,8)>
        ...

---
##### <a id="s2214">2.2.1.4 Undefined Arguments</a>

Some arguments may be undefined, e.g., `op[3]` for a 2-operand instruction.
In this case, the `NULL` pointer will be passed and the type will
be `std::nullptr_t`.
This can also be used for function overloading:

        void func(std::nullptr_t x) { ... }

---
#### <a id="s222">2.2.2 Call Action Options</a>

Call actions support different *options*.

The `before`/`after`/`replace`/`conditional`/`conditional.jump` options
specify where the instrumentation should be placed in relation to the
matching instruction.
Here:

* `before` specifies that the function should be called *before* the
   matching instruction (the default);
* `after` specifies that the function should be called *after* the
   matching instruction;
* `replace` specifies that the function should *replace* the matching
   instruction (which will not be executed); and
* `conditional` inspects the return value of the function.
   If the returned value is non-zero, the matching instruction will *not*
   be executed (like `replace`).
   Otherwise if zero, the matching instruction will be executed as normal
   (like `before`).
   Essentially, `conditional` implements the following pseudocode:
<pre>
       result = func(...);
       if (result) { nop } else { instruction }
</pre>
* `conditional.jump` inspects the return value of the function.
   If the returned value is non-zero, then control-flow will jump to the
   returned value interpreted as an address, and without executing the
   matching instruction.
   Otherwise if zero, the matching instruction will be executed as normal
   (like `before`).
   Essentially, `conditional.jump` implements the following pseudocode:
<pre>
        result = func(...);
        if (result) { goto result } else { instruction }
</pre>

Only one of these options is valid at the same time.
Note that for the `after` option, the function will **not** be called
if the matching instruction transfers control flow, e.g., for
jumps (taken), calls or returns.

The `naked` option specifies that the function should be called
directly and to minimize the saving/restoring any state.
By default, the `clean` call option will save/restore all scratch
registers that are potentially clobbered by `C`/`C++` code.
In contrast, `naked` calls will not save any register unless it is
explicitly used to pass an argument, and it is up to the function to
save/restore any state as necessary.
Naked calls allow for a more fine grained control and this can be used to
improve performance.
However, naked calls are generally incompatible with `C`/`C++`, and
the function will usually need to be implemented directly in assembly.
As such, the `naked` option is not recommended 
unless you know what you are doing.

The default is `clean`, which means E9Tool will automatically
generate code for saving/restoring the CPU state,
including all caller-saved registers
`%rax`, `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`, `%r10`, and `%r11`.
Note that, for performance reasons, the `clean` call ABI differs from
the standard System V ABI in the following way:

* The x87/MMX/SSE/AVX/AVX2/AVX512 registers are *not* saved.
* The stack pointer `%rsp` is *not* guaranteed to be aligned to a 16-byte
  boundary.

These differences are generally safe provided the instrumentation code
exclusively uses general-purpose registers
(as is enforced by `e9compile.sh`).
Otherwise, it will be necessary to save the registers and align the
stack manually inside the instrumentation code.

---
#### <a id="s223">2.2.3 Call Action Standard Library</a>

The main limitation of call actions is that the instrumentation
cannot use dynamically linked libraries, including `glibc`.
This is because the instrumentation binary is directly injected
into the rewritten binary rather than dynamically/statically linked.

A parallel implementation of common libc functions is provided by the
`examples/stdlib.c` file.
To use, simply include this file into the instrumentation code:

        #include "stdlib.c"

This version of libc is designed to be compatible with call instrumentation.
However, only a subset of libc is implemented, so it is WYSIWYG.
Many common libc functions, including file I/O and memory
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
#### <a id="s224">2.2.4 Call Action Initialization</a>

It is also possible to define an initialization function in the
instrumentation code.
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
arguments are only available for patched executables, and will be
zero/`NULL` for patched shared objects.

In the example above, the initialization function searches for an
environment variable `MAX`, and sets the `max` counter accordingly.

---
### <a id="s23">2.3 Plugin Actions</a>

Call action trampolines call the instrumentation binary from the
trampoline.
This adds an extra layer of indirection, namely, from the main
program, to the trampoline, and to the call instrumentation.
For highly optimized applications, it is better to inline the instrumentation
directly inside the trampoline.
However, this requires a very fine-grained control over the
generated trampolines.
This is possible using *plugin actions*, which allow a very fine-grained
control over the contents of the generated trampolines.
For more information, please see the [E9Patch Programmer's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md).

