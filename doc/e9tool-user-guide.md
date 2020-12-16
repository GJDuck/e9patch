# E9Tool User's Guide

**NOTE**: This guide is a work-in-progress and still incomplete.

## Matching Language

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

A `VALUE` can be either an integer, string, or a special symbol
such as a register name, etc.
For string attributes, the value can be a regular expression.
This means that the corresponding attribute value must either
match (for `==`) or not match (for `!=`) the regular expression,
depending on the comparison operator.

### Attributes

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
<tr><td><b><tt>addr</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF virtual address</td></tr>
<tr><td><b><tt>offset</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF file offset</td></tr>
<tr><td><b><tt>size</tt></b></td><td><tt>Integer</tt></td>
    <td>The size of the instruction in bytes</td></tr>
<tr><td><b><tt>random</tt></b></td><td><tt>Integer</tt></td>
    <td>A random value [0..<tt>RAND_MAX</tt>]</td></tr>
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
    <td>The <tt>i</tt><sup>th</sup> operand</td></tr>
<tr><td><b><tt>src[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand</td></tr>
<tr><td><b><tt>dst[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand</td></tr>
<tr><td><b><tt>imm[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <tt>i</tt><sup>th</sup> immediate operand</td></tr>
<tr><td><b><tt>reg[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <tt>i</tt><sup>th</sup> register operand</td></tr>
<tr><td><b><tt>mem[i]</tt></b></td><td><tt>Operand</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand</td></tr>
<tr><td><b><tt>op[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand type</td></tr>
<tr><td><b><tt>src[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand type</td></tr>
<tr><td><b><tt>dst[i].type</tt></b></td><td><tt>{imm,reg,mem}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand type</td></tr>
<tr><td><b><tt>op[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand access</td></tr>
<tr><td><b><tt>src[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand access</td></tr>
<tr><td><b><tt>dst[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand access</td></tr>
<tr><td><b><tt>reg[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> register operand access</td></tr>
<tr><td><b><tt>mem[i].access</tt></b></td><td><tt>{-,r,w,rw}</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand access</td></tr>
<tr><td><b><tt>op[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand segment register</td></tr>
<tr><td><b><tt>src[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand segment register</td></tr>
<tr><td><b><tt>dst[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand segment register</td></tr>
<tr><td><b><tt>mem[i].seg</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand segment register</td></tr>
<tr><td><b><tt>op[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand displacement</td></tr>
<tr><td><b><tt>src[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand displacement</td></tr>
<tr><td><b><tt>dst[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand displacement</td></tr>
<tr><td><b><tt>mem[i].disp</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand displacement</td></tr>
<tr><td><b><tt>op[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand base register</td></tr>
<tr><td><b><tt>src[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand base register</td></tr>
<tr><td><b><tt>dst[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand base register</td></tr>
<tr><td><b><tt>mem[i].base</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand base register</td></tr>
<tr><td><b><tt>op[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand index register</td></tr>
<tr><td><b><tt>src[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand index register</td></tr>
<tr><td><b><tt>dst[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand index register</td></tr>
<tr><td><b><tt>mem[i].index</tt></b></td><td><tt>Register</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand index register</td></tr>
<tr><td><b><tt>op[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> operand scale</td></tr>
<tr><td><b><tt>src[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> source operand scale</td></tr>
<tr><td><b><tt>dst[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> destination operand scale</td></tr>
<tr><td><b><tt>mem[i].scale</tt></b></td><td><tt>Integer</tt></td>
    <td>The <tt>i</tt><sup>th</sup> memory operand scale</td></tr>
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

### Definedness

Not all attributes are defined for all instructions.
For example, if the instruction has 3 operands, then only `op[0]`, `op[1]`,
and `op[2]` will be *defined*, and `op[3]` and beyond will be
be *undefined*.
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

### Examples

* (`true`):
  match every instruction.
* (`false`):
  do not match any instruction.
* (`asm == jmp.*%r.*`):
  match all instructions whose assembly representation matches
  the regular expression `jmp.*%r.*`
  (will match jump instructions that access a register).
* (`mnemonic == jmpq`):
  match all instructions whose mnemonic is `jmpq`.
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

## Action Language

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

An action is either *builtin*, a *call*, or a defined by a *plugin*.

### Builtin Actions

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

### Call Actions

A *call* action calls a user-defined function that can be implemented
in a high-level programming language such as C or C++.
Call actions are the main way of implementing custom patches using
E9Tool.
The syntax for a call action is as follows:

<pre>
    CALL ::=  <b>call</b> [ OPTIONS ] FUNCTION [ ARGS ] <b>@</b> BINARY

    OPTIONS ::=   <b>[</b> OPTION <b>,</b> ... <b>]</b>
    OPTION  ::=   <b>clean</b> | <b>naked</b>
                | <b>before</b> | <b>after</b> | <b>replace</b> | <b>conditional</b>

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


#### Call Action Arguments

Call actions support up to eight *arguments*.
The following arguments are supported:

<table border="1">
<tr><th>Argument</th><th>Type</th><th>Description</th></tr>
<tr><td><i>Integer</i></td><td><tt>intptr_t</tt></td>
    <td>An integer constant</td></tr>
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
<tr><td><b><tt>instr</tt></b></td><td><tt>const uint8_t &#42;</tt></td>
    <td>The machine-code bytes of the matching instruction</td></tr>
<tr><td><b><tt>next</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the next executed instruction</td></tr>
<tr><td><b><tt>offset</tt></b></td><td><tt>off_t</tt></td>
    <td>The ELF file offset of the matching instruction</td></tr>
<tr><td><b><tt>target</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the jump/call/return target, else <tt>NULL</tt></td></tr>
<tr><td><b><tt>trampoline</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the trampoline</td></tr>
<tr><td><b><tt>random</tt></b></td><td><tt>intptr_t</tt></td>
    <td>A (statically generated) random integer [0..<tt>RAND_MAX</tt>]</td></tr>
<tr><td><b><tt>size</tt></b></td><td><tt>size_t</tt></td>
    <td>The size of <tt>instr</tt> in bytes</td></tr>
<tr><td><b><tt>staticAddr</tt></b></td><td><tt>size_t</tt></td>
    <td>The ELF virtual address of the matching instruction</td></tr>
<tr><td><b><tt>ah</tt></b>,...,<b><tt>dh</tt></b>, <b><tt>al</tt></b>,...,<b><tt>r15b</tt></b></td><td><tt>int8_t</tt></td>
    <td>The corresponding 8bit register</td></tr>
<tr><td><b><tt>ax</tt></b>,...,<b><tt>r15w</tt></b></td><td><tt>int16_t</tt></td>
    <td>The corresponding 16bit register</td></tr>
<tr><td><b><tt>eax</tt></b>,...,<b><tt>r15d</tt></b></td><td><tt>int32_t</tt></td>
    <td>The corresponding 32bit register</td></tr>
<tr><td><b><tt>rax</tt></b>,...,<b><tt>r15</tt></b></td><td><tt>int64_t</tt></td>
    <td>The corresponding 64bit register</td></tr>
<tr><td><b><tt>rflags</tt></b></td><td><tt>int16_t</tt></td>
    <td>The <tt>%rflags</tt> register</td></tr>
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
    <td>The <tt>rflags</tt> register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand</td></tr>
<tr><td><b><tt>src[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand</td></tr>
<tr><td><b><tt>dst[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination operand</td></tr>
<tr><td><b><tt>imm[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> immediate operand</td></tr>
<tr><td><b><tt>reg[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> register operand</td></tr>
<tr><td><b><tt>mem[i]</tt></b></td><td><tt>int8/16/32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand</td></tr>
<tr><td><b><tt>&amp;op[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i]</tt></b></td><td><tt>const int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i]</tt></b></td><td><tt>int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;imm[i]</tt></b></td><td><tt>const int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> immediate operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;reg[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> register operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i]</tt></b></td><td><tt>(const) int8/16/32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand size</td></tr>
<tr><td><b><tt>src[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    size</td></tr>
<tr><td><b><tt>dst[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand size</td></tr>
<tr><td><b><tt>imm[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> immediate operand
    size</td></tr>
<tr><td><b><tt>reg[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> register operand
    size</td></tr>
<tr><td><b><tt>mem[i].size</tt></b></td><td><tt>size_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    size</td></tr>
<tr><td><b><tt>op[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand 
    displacement</td></tr>
<tr><td><b><tt>src[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    displacement</td></tr>
<tr><td><b><tt>dst[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand displacement</td></tr>
<tr><td><b><tt>mem[i].disp</tt></b></td><td><tt>int32_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    displacement</td></tr>
<tr><td><b><tt>op[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand base
    register</td></tr>
<tr><td><b><tt>src[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    base register</td></tr>
<tr><td><b><tt>dst[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand base register</td></tr>
<tr><td><b><tt>mem[i].base</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    base register</td></tr>
<tr><td><b><tt>&amp;op[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand base
    register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i].base</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    base register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand index
    register</td></tr>
<tr><td><b><tt>src[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    index register</td></tr>
<tr><td><b><tt>dst[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand index register</td></tr>
<tr><td><b><tt>mem[i].index</tt></b></td><td><tt>int32/64_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    index register</td></tr>
<tr><td><b><tt>&amp;op[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand index
    register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;src[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;dst[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>&amp;mem[i].index</tt></b></td><td><tt>int32/64_t &#42;</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    index register (passed-by-pointer)</td></tr>
<tr><td><b><tt>op[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> operand 
    scale</td></tr>
<tr><td><b><tt>src[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> source operand
    scale</td></tr>
<tr><td><b><tt>dst[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> destination
    operand scale</td></tr>
<tr><td><b><tt>mem[i].scale</tt></b></td><td><tt>int8_t</tt></td>
    <td>The matching instruction's <tt>i</tt><sup>th</sup> memory operand
    scale</td></tr>
</table>

##### Pass-by-pointer

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

For memory operands, e.g. `&mem[i]`, the passed pointer will be exactly
the runtime pointer value calculated by the operand itself.
For example, consider the instruction (`mov 0x33(%rax,%rbx,2),%rcx`),
then the value for `&mem[0]` will be (`0x33+%rax+2*%rbx`).
Generally, it is recommended to pass memory operands by pointer rather
than by value.
If passed by value, the memory operand pointer will be dereferenced, which
may result in a crash for instructions such as (`nop`) and (`lea`) that
do not access the operand.

##### Polymorphic Arguments

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

##### Undefined Arguments

Some arguments may be undefined, e.g., `op[3]` for a 2-operand instruction.
In this case, the `NULL` pointer will be passed and the type will
be `std::nullptr_t`.
This can also be used for function overloading:

        void func(std::nullptr_t x) { ... }

#### Call Action Options

Call actions support different *options*.

The `before`/`after`/`replace`/`conditional` options specify where
the instrumentation should be placed in relation to the matching
instruction.
Here:

* `before` specifies that the function should be called *before* the
   matching instruction (the default);
* `after` specifies that the function should be called *after* the
   matching instruction;
* `replace` specifies that the function should *replace* the matching
   instruction (which will not be executed); and
* `conditional` inspects the return value of the function.
   If the return value is zero, the matching instruction is not executed
   (like `replace`), else if non-zero, the matching instruction
   is executed (like `before`).

Only one of these options is valid at the same time.
Note that for the `after` option, the function will **not** be called
if the matching instruction transfers control flow, e.g., for
jumps (taken), calls or returns.

The `naked` option specifies that the function should be called
directly and to minimize the saving/restoring any state.
By default, the `clean` call option will save/restore all scratch
registers that are potentially clobbered by `C`/`C++` code,
including
`%rax`, `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`, `%r10`, and `%r11`.
In contrast, `naked` calls will not save any register unless it is
explicitly used to pass an argument, and it is up to the function to
save/restore any state as necessary.
Naked calls allow for a more fine grained control and this can be used to
improve performance.
However, naked calls are generally incompatible with `C`/`C++`, and
the function will usually need to be implemented directly in assembly.
As such, the `naked` option is not recommended 
unless you know what you are doing.

#### Call Action Standard Library

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

### Plugin Actions

Call action trampolines call the instrumentation binary from the
trampoline.
This adds an extra layer of indirection, namely, from the main
program, to the trampoline, and to the call instrumentation.
For highly optimized, it is better to inline the instrumentation
directly inside the trampoline.
However, this requires a very fine-grained control over the
generated trampolines.
This is possible using *plugin actions*, which allow a very fine-grained
control over the contents of the generated trampolines.
For more information, please see the *E9Patch Programmer's Guide*.

