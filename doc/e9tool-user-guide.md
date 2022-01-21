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

* [1. Matching Language](#matching)
    - [1.1 Attributes](#attributes)
    - [1.2 Definedness](#definedness)
    - [1.3 Control-flow](#control-flow)
    - [1.4 Instruction Specifiers](#specifiers)
    - [1.5 Comma-Separated Values](#csv)
    - [1.6 Examples](#match-examples)
    - [1.7 Exclusions](#exclusions)
* [2. Patch Language](#patching)
    - [2.1 Builtin Trampolines](#builtins)
    - [2.2 Call Trampolines](#calls)
        * [2.2.1 Call Trampoline Arguments](#call-args)
           - [2.2.1.1 Pass-by-pointer](#pass-by-pointer)
            - [2.2.1.2 Polymorphic Arguments](#polymorphism)
            - [2.2.1.3 Explicit Memory Operand Arguments](#memop-args)
            - [2.2.1.4 Undefined Arguments](#undefined-args)
        * [2.2.2 Call Trampoline ABI](#call-abi)
        * [2.2.3 Conditional Call Trampoline](#conditional-calls)
        * [2.2.4 Call Trampoline Standard Library](#standard-library)
        * [2.2.5 Call Trampoline Initialization and Finalization](#init-fini)
        * [2.2.6 Call Trampoline Dynamic Loading](#dynamic-loading)
    - [2.3 Plugin Trampolines](#plugins)
    - [2.4 Composing Trampolines](#composition)

---
## <a id="matching">1. Matching Language</a>

The *matching language* specifies what instructions should be patched by
the corresponding *patch* (see below).
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
    TEST ::=   <b>defined</b> <b>(</b> EXPR <b>)</b>
             | EXPR [ CMP EXPR ]

    EXPR ::=   VALUE 
             | [ SPECIFIER <b>.</b> ] ATTRIBUTE

    CMP ::=   <b>=</b> | <b>==</b> | <b>!=</b> | <b>&gt;</b> | <b>&gt;=</b> | <b>&lt;</b> | <b>&lt;=</b> | <b>in</b>
</pre>

A `TEST` tests some underlying instruction `EXPR` expressions using a
comparison operator `CMP`.
The following comparison operators are supported:

<table border="1">
<tr><th>Comparison</th><th>Description</th></tr>
<tr><td><b><tt>=</tt> or <tt>==</tt></b></td>
    <td>Equality</td></tr>
<tr><td><b><tt>!=</tt></b></td>
    <td>Disequality</td></tr>
<tr><td><b><tt>&gt;</tt></b></td>
    <td>Greater-than</td></tr>
<tr><td><b><tt>&gt;=</tt></b></td>
    <td>Greater-than-or-equal-to</td></tr>
<tr><td><b><tt>&lt;</tt></b></td>
    <td>Less-than</td></tr>
<tr><td><b><tt>&lt;=</tt></b></td>
    <td>Less-than-or-equal-to</td></tr>
<tr><td><b><tt>in</tt></b></td>
    <td>Set membership or subset</td></tr>
</table>

If the comparison operator and value are omitted, then the test is
equivalent to (`EXPR != 0`).

A `VALUE` can be one of:

* An *integer constant*, e.g., `123`, `0x123`, etc.
* A *string constant*, e.g., `"abc"`, etc.
* An *enumeration value*, including:
  - register names (`rax`, `eax`, etc.)
  - operand types (`imm`, `reg`, `mem`)
  - access types (`-`, `r`, `w`, `rw`)
* A *memory operand* (see below).
* A *symbolic address* of the form `NAME`, where `NAME` is any section
  or symbol name from the input ELF file.
  A symbolic address has type `Integer`.
* A *set* of `VALUE`s, e.g., `{rax,rbx,rcx}`.
* A *regular expression* delimited by slashes (`/`), e.g., `/xor.*/`,
  `/mov.+\(%rax.*/`, etc.

String values can be matched (or not matched) against regular expressions
using the equality `==` (or disequality `!=`) comparison operators.
For example, the test (`"mov (%rax,%rbx,8),%rcx" == /mov.+\(%rax.*/`)
will evaluate to *true*.

Memory operands can be represented using the following syntax:
<pre>
    ( <b>mem8</b> | <b>mem16</b> | <b>mem32</b> | <b>mem64</b> ) <b>&lt;</b> MEMOP <b>&gt;</b>
</pre>
Here, the <tt>mem8</tt>...<tt>mem64</tt> token specifies the size of
the memory operand, and <tt>MEMOP</tt> is the memory operand itself
specified in AT&amp;T syntax.
For example, the following explicit memory operands access stack memory:

        mem32<(%rax)>
        mem64<0x100(%rsp)>
        mem64<0x200(%rsp,%rax,8)>
        ...

---
### <a id="attributes">1.1 Attributes</a>

The following `ATTRIBUTE`s (with corresponding types) are supported:

<table border="1">
<tr><th>Attribute</th><th>Type</th><th>Description</th></tr>
<tr><td><b><tt>true</tt></b></td><td><tt>Boolean</tt></td><td>True</td></tr>
<tr><td><b><tt>false</tt></b></td><td><tt>Boolean</tt></td><td>False</td></tr>
<tr><td><b><tt>jump<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for jump instructions, false otherwise</td></tr>
<tr><td><b><tt>condjump<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for conditional jump instructions, false otherwise</td></tr>
<tr><td><b><tt>call<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for call instructions, false otherwise</td></tr>
<tr><td><b><tt>return<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for return instructions, false otherwise</td></tr>
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
<tr><td><b><tt>target</tt></b></td><td><tt>Integer</tt></td>
    <td>The jump/call target (if statically known).</td></tr>
<tr><td><b><tt>x87<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for x87 instructions, false otherwise</td></tr>
<tr><td><b><tt>mmx<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for MMX instructions, false otherwise</td></tr>
<tr><td><b><tt>sse<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for SSE instructions, false otherwise</td></tr>
<tr><td><b><tt>avx<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for AVX instructions, false otherwise</td></tr>
<tr><td><b><tt>avx2<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for AVX2 instructions, false otherwise</td></tr>
<tr><td><b><tt>avx512<tt></b></td><td><tt>Boolean</tt></td>
    <td>True for AVX512 instructions, false otherwise</td></tr>
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
<tr><td><b><tt>BB</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF virtual address of the current basic-block</td></tr>
<tr><td><b><tt>BB.addr</tt></b></td><td><tt>Integer</tt></td>
    <td>Alias for <tt>BB</tt></td></tr>
<tr><td><b><tt>BB.offset</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF file offset of the current basic-block</td></tr>
<tr><td><b><tt>BB.entry</tt></b></td><td><tt>Boolean</tt></td>
    <td>True for the first instruction in the current basic-block,
        false otherwise.</td></tr>
<tr><td><b><tt>BB.exit</tt></b></td><td><tt>Boolean</tt></td>
    <td>True for the last instruction in the current basic-block,
        false otherwise.</td></tr>
<tr><td><b><tt>BB.best</tt></b></td><td><tt>Boolean</tt></td>
    <td>True for the "best" instruction in the current basic-block,
        false otherwise.</td></tr>
<tr><td><b><tt>BB.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The size of the current basic-block in bytes</td></tr>
<tr><td><b><tt>BB.len</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of instructions in the current basic-block</td></tr>
<tr><td><b><tt>F</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF virtual address of the current function</td></tr>
<tr><td><b><tt>F.addr</tt></b></td><td><tt>Integer</tt></td>
    <td>Alias for <tt>F</tt></td></tr>
<tr><td><b><tt>F.offset</tt></b></td><td><tt>Integer</tt></td>
    <td>The ELF file offset of the current function</td></tr>
<tr><td><b><tt>F.entry</tt></b></td><td><tt>Boolean</tt></td>
    <td>True for the first instruction in the current function,
        false otherwise.</td></tr>
<tr><td><b><tt>F.best</tt></b></td><td><tt>Boolean</tt></td>
    <td>True for the "best" instruction in the current function,
        false otherwise.</td></tr>
<tr><td><b><tt>F.size</tt></b></td><td><tt>Integer</tt></td>
    <td>The size of the current function in bytes</td></tr>
<tr><td><b><tt>F.len</tt></b></td><td><tt>Integer</tt></td>
    <td>The number of instructions in the current function</td></tr>
<tr><td><b><tt>F.name</tt></b></td><td><tt>String</tt></td>
    <td>The name of the function (if available)</td></tr>
<tr><td><b><tt>NAME[i]<tt></b></td><td><tt>Integer | String</tt></td>
    <td>The corresponding value from the <tt>NAME.csv</tt> file</td></tr>
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
* A memory operand represented by a `MemOp`

Thus the `Operand` type is the union of the `Integer`, `Register`, and
`MemOp` types:

        Operand = Integer | Register | MemOp

---
### <a id="definedness">1.2 Definedness</a>

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
### <a id="control-flow">1.3 Control-flow</a>

The `BB.*` attributes represent properties over the current *basic-block*
which contains the instruction being matched.
Here, a basic-block is a straight-line instruction sequence a single entry
point and a single exit (excluding function calls).
The set of basic-blocks are recovered from the input binary using a
simple built-in static analysis.
That said, basic-block recovery is well-known to be an undeciable
problem in the general case, meaning that the built-in analysis must rely
on several heuristics that may not be perfectly accurate.
As such, the `BB.*` attributes should should only be used for applications
(e.g., optimization) where some inaccuracy can be tolerated.
Finally, we note that the recovered basic-block information is only made
available to the the application layer.
The recovered information is not passed to (or used by) the
underlying E9Patch binary rewriter.

The `BB.best` attribute selects the "best" instruction in a basic-block to
instrument in order to maximum coverage and speed.
This is useful for applications that need to instrument at the basic-block
level (rather than the instruction level).

Similarly, the `F.*` attributes represent properties over the current
*function* which contains the instruction being matched.
As with basic-blocks, E9Tool uses a very simple (heuristic-based) function
recovery analysis that is not guaranteed to be accurate, so function
matching should only be used for applications where some 
inaccuracy can be tolerated.
The `F.name` attribute is the name of the current function if known
(i.e., there exists an entry in an ELF symbol table), else
the result is *undefined*.

---
### <a id="specifiers">1.4 Instruction Specifiers</a>

The attribute expression may be annotated by an explicit instruction
`SPECIFIER` of the following form:

<pre>
        SPECIFIER ::= INSTR-SET <b>[</b> INDEX <b>]</b>
        INSTR-SET ::= ( <b>I</b> | <b>BB</b> | <b>F</b>)
</pre>

Here `INSTR-SET` is one of the following instruction sets:

* `I`: The set of all disassembled instructions.
* `BB`: The set of all instructions in the current basic-block.
* `F`: The set of all instructions in the current function.

The `INDEX` is a signed integer which represents of offset relative to the
current instruction.
For example, `I[0]` is the current instruction, `I[1]` is the next
instruction, `I[-1]` is the previous instruction, etc.
Similarly, `BB[1]` is the next instruction in the current basic-block,
`F[-1]` is the previous instruction in the current function, etc.
Note that previous/next instructions may not exist, in which case the result
will be *undefined*.

If unspecified, the instruction specifier is implicitly `I[0]`
(i.e., the *current* instruction).
Note that `BB[0]` and `F[0]` may be undefined if the current instruction
does not belong to any basic block or function.
For example, padding NOPs that inserted by the compiler for alignment
purposes are not considered part of a basic block.

Instruction specifiers are useful for matching some context around
the current instruction.
For example, the following matches all conditional jump instructions that are
immediately preceded by a comparison in the same basic block:

        condjump and BB[-1].mnemonic == "cmp"

---
### <a id="csv">1.5 Comma-Separated Values</a>

It is possible to match against user-defined data stored in one or more
*comma-separated values* (CSV) files using the `NAME[i]` attribute.
This makes it possible to match against data generated by other binary
analysis tools, e.g., control-flow information, etc.

Here, the `NAME[i]` attribute will parse the `NAME.csv` file and resolve to the
following value:

* The *row* is selected by the address of the matching instruction, which is
  matched against the *first* column stored in the `NAME.csv` file.
* The *column* is selected by the index *i*.

If neither the row nor column exist the result is *undefined*.

For example, suppose the `file.csv` file contains the following contents:

        0x400100,1,"Monday",0xaaa
        0x400105,2,"Tuesday",0xbbb
        0x40010a,3,"Wednesday",0xccc

When matching the instruction at address `0x400105`, we have that
(`file[0] == 0x400105`), (`file[1] == 2`), (`file[2] == "Tuesday"`), etc.
As seen by this example, CSV files can be used to store both integer and
string values.

---
### <a id="match-examples">1.6 Examples</a>

* (`true`):
  match every instruction.
* (`false`):
  do not match any instruction.
* (`asm == /jmp.*%r.*/`):
  match all instructions whose assembly representation matches
  the regular expression `jmp.*%r.*`
  (will match jump instructions that access a register).
* (`mnemonic == "jmp"`):
  match all instructions whose mnemonic is `jmp`.
* (`addr == 0x4234a7`):
  match the instruction at the virtual address `0x4234a7`.
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
* (`op[0] == op[1]`):
  match all instructions where the first two operands are the same.
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
* (`{rax, rdx} in writes`):
  match all instructions what write to registers `%rax` and `%rdx`.
* (`op[0] == mem64<0x200(%rsp,%rax,8)>`):
  match all instructions with the corresponding memory operand.

---
### <a id="exclusions">1.7 Exclusions</a>

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
## <a id="patching">2. Patch Language</a>

The *patch language* specifies how to patch matching instructions
from the input binary.
Patches are specified using the (`--patch PATCH`) or
(`-P PATCH`) command-line option, and must be paired with one
or more matchings.
The basic form of a patch (`PATCH`) uses
the following high-level grammar:

<pre>
    PATCH      ::= [ POSITION ] TRAMPOLINE
    POSITION   ::=   <b>before</b>
                   | <b>replace</b>
                   | <b>after</b>
    TRAMPOLINE ::=   <b>empty</b>
                   | <b>break</b>
                   | <b>trap</b>
                   | <b>exit(</b>CODE<b>)</b>
                   | <b>print</b>
                   | CALL
                   | <b>if</b> CALL <b>break</b>
                   | <b>if</b> CALL <b>goto</b>
                   | <b>plugin(</b>NAME<b>).patch()</b>
</pre>

A patch is an optional *position* followed by a *trampoline*.
The trampoline represents code that will be executed when
control-flow reaches the matching instruction.
The trampoline can be either a *builtin* trampoline, a *call* trampoline,
or a trampoline defined by a *plugin*.

---
### <a id="builtins">2.1 Builtin Trampolines</a>

The builtin trampolines include:

<table border="1">
<tr><th>Patch</th><th>Description</th></tr>
<tr><td><b><tt>empty</tt></b></td>
    <td>The empty trampoline</td></tr>
<tr><td><b><tt>break</tt></b></td>
    <td>Immediately return from trampoline</td></tr>
<tr><td><b><tt>trap</tt></b></td>
    <td>Execute a TRAP (<tt>int3</tt>) instruction</td></tr>
<tr><td><b><tt>exit(CODE)</tt></b></td>
    <td>Exit with <tt>CODE</tt></td></tr>
<tr><td><b><tt>print</tt></b></td>
    <td>Printing the matching instruction</td></tr>
</table>

Here:

* `empty` is the empty trampoline with no instructions.
  Control-flow is still redirected to/from empty trampolines, and
  this can be used to establish a baseline for benchmarking.
* `break` immediately returns from the trampoline back to the main
  program.
* `trap` executes a single TRAP (`int3`) instruction.
* `exit(CODE)` will immediately exit from the program with status `CODE`.
* `print` will print the assembly representation of the matching
  instruction to `stderr`.
  This can be used for testing and debugging.

---
### <a id="calls">2.2 Call Trampolines</a>

A *call* trampoline calls a user-defined function that can be implemented
in a high-level programming language such as C or C++.
Call trampolines are the main way of implementing custom patches using
E9Tool.
The syntax for a call trampoline is as follows:

<pre>
    CALL ::= FUNCTION [ ABI ] ARGS <b>@</b> BINARY
    ABI  ::= <b>&lt;</b> <b>clean</b> | <b>naked</b> <b>&gt;</b>
    ARGS ::= <b>(</b> ARG <b>,</b> ... <b>)</b>
</pre>

The call trampoline specifies that the trampoline should call function
`FUNCTION` from the binary `BINARY` with the arguments `ARGS`.

To use a call trampoline:

1. Implement the desired patch as a function using the `C` or `C++`
   programming language.
2. Compile the patch program using the special `e9compile.sh` script
   to generate a patch binary.
3. Use an E9Tool to call the patch function from the patch binary
   at the desired locations.

E9Tool will handle all of the low-level details, such as loading the
patch binary into memory, passing the arguments to the function, and 
saving/restoring the CPU state.

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

Once defined, the program can be compiled using the `e9compile.sh`
script.

        ./e9compile.sh counter.c

The `e9compile.sh` script is a `gcc` wrapper that ensures the
generated binary is compatible with E9Tool.
In this case, the script will generate a `counter` binary if
compilation is successful.

Finally, the `counter` binary can be used as a call trampoline.
For example, to generate a `SIGTRAP` after the 10000th `xor`
instruction:

        ./e9tool -M 'mnemonic=="xor"' -P 'entry()@counter' ...

Call trampolines are primarily designed for ease-of-use and
**not** for speed.
For applications where speed is essential, it is recommended
to design a custom trampoline using a plugin.

---
#### <a id="call-args">2.2.1 Call Trampoline Arguments</a>

Call trampolines also support passing arguments to the called function.
The syntax uses the `C`-style round brackets.
For example:

        ./e9tool -M ... -P 'func(rip)@example' xterm

This specifies that the current value of the instruction pointer
`%rip` should be passed as the first argument to the function
`func()`.
The called function can use this argument, e.g.:

        void func(const void *rip)
        {
            ...
        }

Call trampolines support up to eight *arguments*.
The following arguments are supported:

<table border="1">
<tr><th>Argument</th><th>Type</th><th>Description</th></tr>
<tr><td><i>Integer</i></td><td><tt>intptr_t</tt></td>
    <td>An integer constant</td></tr>
<tr><td><i>String</i></td><td><tt>const char &#42;</tt></td>
    <td>A string constant</td></tr>
<tr><td><b><tt>&amp;</tt></b><i>Name</i></td><td><tt>const void &#42;</tt></td>
    <td>The runtime address of the named section/symbol/PLT/GOT entry</td></tr>
<tr><td><b><tt>static &amp;</tt></b><i>Name</i></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the named section/symbol/PLT/GOT entry</td></tr>
<tr><td><b><tt>asm</tt></b></td><td><tt>const char &#42;</tt></td>
    <td>Assembly representation of the matching instruction</td></tr>
<tr><td><b><tt>asm.size</tt></b></td><td><tt>size_t</tt></td>
    <td>The number of bytes in <tt>asm</tt> (including the nul character)</td></tr>
<tr><td><b><tt>asm.len</tt></b></td><td><tt>size_t</tt></td>
    <td>The string length of <tt>asm</tt> (excluding the nul character)</td></tr>
<tr><td><b><tt>base</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The runtime base address of the binary</td></tr>
<tr><td><b><tt>config</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>A pointer to the E9Patch configuration (see <tt>e9loader.h</tt>)</td></tr>
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
<tr><td><b><tt>BB</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The address of the matching instruction's basic block</td></tr>
<tr><td><b><tt>static BB</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>The ELF address of the matching instruction's basic block</td></tr>
<tr><td><b><tt>BB.addr</tt></b></td><td><tt>const void &#42;</tt></td>
    <td>Alias for <tt>BB</tt></td></tr>
<tr><td><b><tt>BB.offset</tt></b></td><td><tt>off_t</tt></td>
    <td>The ELF file offset of the matching instruction's basic block</td></tr>
<tr><td><b><tt>BB.size</tt></b></td><td><tt>size_t</tt></td>
    <td>The size of the matching instruction's basic block in bytes</td></tr>
<tr><td><b><tt>BB.len</tt></b></td><td><tt>size_t</tt></td>
    <td>The number of instructions in the matching instruction's basic
    block</td></tr>
<tr><td><b><tt>F</tt></b></td><td><tt>const void &#42;</tt></td>
     <td>The address of the matching instruction's function</td></tr> 
<tr><td><b><tt>static F</tt></b></td><td><tt>const void &#42;</tt></td>
     <td>The ELF address of the matching instruction's function</td></tr> 
<tr><td><b><tt>F.addr</tt></b></td><td><tt>const void &#42;</tt></td>
     <td>Alias for <tt>F</tt></td></tr> 
<tr><td><b><tt>F.offset</tt></b></td><td><tt>off_t</tt></td>
    <td>The ELF file offset of the matching instruction's function</td></tr>
<tr><td><b><tt>F.size</tt></b></td><td><tt>size_t</tt></td>
    <td>The size of the matching instruction's function in bytes</td></tr>
<tr><td><b><tt>F.len</tt></b></td><td><tt>size_t</tt></td>
    <td>The number of instructions in the matching instruction's 
    function</td></tr>
<tr><td><b><tt>F.name</tt></b></td><td><tt>const char &#42;</tt></td>
    <td>The matching instruction's function name</td></tr>
</table>

Notes:

* The `rflags` argument differs from the native
  `x86_64` layout in terms of the number of flags as well as the flag ordering.
  The modified layout is used for efficiency reasons since preserving the
  native layout is a relatively slow operation.
* For technical reasons, the `%rip` register is considered constant and cannot
  be modified.
  To implement jumps, use [conditional call trampolines](#conditional-calls) instead.
* The `state` argument is a pointer to a structure containing all
  general-purpose registers, the flag register (`%rflags`), the stack register
  (`%rsp`) and the instruction pointer register (`%rip`).
  See the `examples/state.c` example for the structure layout.
  Except for `%rip`, the values in the structure can be modified, in which
  case the corresponding register will be updated accordingly.
* The `static` version of some arguments gives the address relative to the ELF
  base, given by the formula: *runtime address = ELF address + ELF base*.
  This corresponds to the value used by the matching.

---
##### <a id="pass-by-pointer">2.2.1.1 Pass-by-pointer Arguments</a>

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

And the following patch:

        $ e9compile.sh example.c
        $ e9tool -M ... -P 'inc(&rax)@example' xterm

This patch will increment the `%rax` register when the `inc()` function
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
##### <a id="polymorphism">2.2.1.2 Polymorphic Arguments</a>

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
        $ e9tool -M ... -P 'func(&op[0])@example' xterm

E9Tool will automatically select the function instance that best
matches the argument types, or generate an error if no appropriate
match can be found.

---
##### <a id="memop-args">2.2.1.3 Explicit Memory Operand Arguments</a>

It is possible to pass explicit memory operands as arguments.
This is useful for reading/writing to known memory locations, such as
stack memory.
The syntax is the same as the matching language, e.g.,
`mem32<(%rax)>`, `mem64<0x200(%rsp,%rax,8)>`, etc.

---
##### <a id="undefined-args">2.2.1.4 Undefined Arguments</a>

Some arguments may be undefined, e.g., `op[3]` for a 2-operand instruction.
In this case, the `NULL` pointer will be passed and the type will
be `std::nullptr_t`.
This can also be used for function overloading:

        void func(std::nullptr_t x) { ... }

---
#### <a id="call-abi">2.2.2 Call Trampoline ABI</a>

Call trampolines support two *Application Binary Interfaces* (ABIs).

* `clean` saves/restores the CPU state and is compatible with `C`/`C++`
* `naked` saves/restores registers corresponding to arguments only

The ABI can be specified inside angled brackets (`<...>`) after the function
name, e.g.:

        $ e9tool -M ... -P 'func<naked>(&op[0])@example' xterm

This will call `func` using the `naked` ABI.

The `clean` ABI is the default, which means E9Tool will automatically
generate code for saving/restoring most of the CPU state,
including all caller-saved registers
`%rax`, `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9`, `%r10`, and `%r11`.
Note however that the `clean` ABI is different from the standard
System V ABI in the following ways:

* The x87/MMX/SSE/AVX/AVX2/AVX512 registers are *not* saved.
* The stack pointer `%rsp` is *not* guaranteed to be aligned to a 16-byte
  boundary.

These differences exist for performance reasons, since saving/restoring
the extended register state is an expensive operation.
The differences are generally safe provided the patch code exclusively
uses general-purpose registers.
Patch binaries generated by the `e9compile.sh` script are guaranteed to
be compatible with the `clean` ABI.

The `naked` ABI specifies that the function should be called
directly and to limit the saving/restoring to registers used to
pass arguments.
Naked calls allow for a more fine grained control and this can be used to
improve performance.
However, naked calls are generally incompatible with `C`/`C++`, and
the function will usually need to be implemented directly in assembly.
As such, the `naked` ABI is not recommended unless you know what you are doing.

---
#### <a id="conditional-calls">2.2.3 Conditional Call Trampolines</a>

*Conditional* call trampolines examine the return value of the called
function, and change the control flow accordingly.
There are two basic forms of conditional call trampolines:

* `if func(...) break`: if the function returns a non-zero value, then
  immediately return from the trampoline back to the main program.
* `if func(...) goto`: if the function returns a non-zero value interpreted
  as an *address*, then immediately jump to that *address*.

The first form allows for the conditional execution of the remainder
of the trampoline, possibly including the matching instruction itself.
For example, consider:

        $ e9tool -M 'mnemonic=="syscall"' -P 'if filter(...)@example break' ...

The patch is placed in the default `before` position, i.e., will be executed
as instrumentation *before* the matching instruction.
If the `filter(...)` function returns a non-zero value, the trampoline will
immediately return, without executing the matching instruction.

The second form allows for arbitrary jumps to be implemented.
The (`if func(...) goto`) syntax can be thought of as shorthand for:

        if (addr = func(...)) { goto addr; }

The `goto` is only executed if the return value of the `func` is non-`NULL`.

---
#### <a id="standard-library">2.2.4 Call Trampoline Standard Library</a>

The main limitation of call trampolines is that the patch code
cannot use standard libraries directly, including `glibc`.
This is because the instrumentation binary is directly injected
into the rewritten binary rather than dynamically/statically linked.

A parallel implementation of common libc functions is provided by the
`examples/stdlib.c` file.
To use, simply include this file into the instrumentation code:

        #include "stdlib.c"

This version of libc is designed to be compatible with patch code.
However, only a subset of libc is implemented, so it is WYSIWYG.
That said, many common libc functions, including file I/O and memory
allocation, have been implemented.

Unlike `glibc` the parallel libc is designed to be compatible with the clean
ABI and handle problems, such as deadlocks, more gracefully.

---
#### <a id="init-fini">2.2.5 Call Trampoline Initialization and Finalization</a>

It is possible to define an initialization function in the
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

In the example above, the initialization function searches for an
environment variable `MAX`, and sets the `max` counter accordingly.

For dynamically linked binaries, it is also possible to define a finalization
function that will be called during normal program exit.
For example:

        #include "stdlib.h"

        void fini(void)
        {
            fflush(stdout);
        }

The finalization funtion must be named `fini` and takes no arguments.
Note that the finalization function will not be called if the program exits
abnormally, such as a signal (`SIGSEGV`) or if the program calls "fast" exit
(`_exit()`).

---
#### <a id="dynamic-loading">2.2.6 Call Trampoline Dynamic Loading</a>

The parallel libc also provides an optional implementation of the
standard dynamic linker functions `dlopen()`, `dlsym()`, and `dlclose()`.
These can be used to dynamically load shared objects at runtime, or access
existing shared libraries that are already dynamically linked into the original
program.
To enable, define the `LIBDL` macro before including `stdlib.c`.

        #define LIBDL
        #include "stdlib.c"

The `dlinit(dynamic)` function must also be called in the `init()` routine,
where `dynamic` is a secret fourth argument to the `init()` function:

        void init(int argc, char **argv, char **envp, void *dynamic)
        {
            int result = dlinit(dynamic);
            ...
        }

Once initialized, the `dlopen()`, `dlsym()`, and `dlclose()` functions can be
used similarly to the standard `libdl` counterparts.

Note that function pointers returned by `dlsym()` **should not be called
directly** unless you know what you are doing.
This is because most libraries are compiled with the System V ABI, which is
incompatible with the clean call ABI used by the instrumentation.
To avoid ABI incompatibility, the external library code should be called using
a special wrapper function `dlcall()`:

        intptr_t dlcall(void *func, arg1, arg2, ...);

The `dlcall()` function will:

* Align/restore the stack pointer to 16bytes, as required by the System V ABI.
* Save/restore the extended register state, including `%xmm0`, etc.
* Save/restore the glibc version of `errno`.

Be aware that the dynamic loading API has several caveats:

* The `dlopen()`, `dlsym()`, and `dlclose()` are wrappers for the glibc
  versions of these functions (`__libc_dlopen`, etc.).
  The glibc versions do not officially exist, so this functionality may change
  at any time.
  Also the glibc versions lack some features, such as `RTLD_NEXT`, that are
  available with the standard libdl versions.
* Since glibc is required, the original binary must be dynamically linked.
* Many external library functions are not designed to be reentrant, and this
  may cause deadlocks if a signal occurs when the signal handler is also
  instrumented.
* The `dlcall()` function supports a maximum of 16 arguments.
* The `dlcall()` function is relatively slow, so ought to be used sparingly.

---
### <a id="plugins">2.3 Plugin Trampolines</a>

By design, call trampolines are very simple to use, but this also comes at
the cost of efficiency.
The problem is that call trampolines add an extra layer of indirection,
namely, the control-flow will transfer from the main program, to the trampoline,
and then to the called function.
For optimal results, it is sometimes better to inline the functionality
directly into the trampoline and avoid the extra level of indirection.

A very fine-grained control over the generated trampolines is possible
using *plugin trampolines*, which allows for the precise content of
trampolines to be specified directly.
The downside is that low-level details, such as the saving/restoring of
CPU state, must be handled manually by the trampoline code, so this method
is generally only recommended for expert users only.

For more information, please see the
[E9Patch Programmer's Guide](https://github.com/GJDuck/e9patch/blob/master/doc/e9patch-programming-guide.md).

---
### <a id="composition">2.4 Composing Trampolines</a>

Depending on the `--match`/`-M` and `--patch`/`-P` options, more than
one patch may match a given instruction.
If this occurs, then *all* matching trampolines will be executed in an order
determined by:

* The explicit (or implicit) *patch position* annotation, then
* The command-line order for tie-breaking.

The possible values for the *patch position* annotation are:

* `before`: The trampoline will be executed *before* the matching instruction.
  That is, the trampoline is *instrumentation*.
* `replace`: The trampoline *replaces* the matching instruction.
* `after`: The trampoline is executed *after* the matching instruction.

If unspecified, the default patch position is assumed to be "`before`", meaning
that the trampoline will be executed before the matching instruction
(i.e., instrumentation).

Conceptually, the individual trampolines will be arranged into a "meta"
trampoline that will be executed in place of the original matching
instruction.
The meta trampoline has the following basic form:
<pre>
        BEFORE (<b>instruction</b> | REPLACE) AFTER <b>break</b>
</pre>
Here `BEFORE` are all *before* trampolines in command-line order,
`instruction` is the original matching instruction,
`REPLACE` is the *replace*ment trampoline,
`AFTER` are all *after* trampolines in command-line order, and
`break` returns control-flow back to the main program.

Notes:

* There can be at most one *replace*ment trampoline.
  If no replacement trampoline is specified, E9Tool will execute the original
  matching instruction.
* For the `after` position, the trampoline will **not** be executed
  if the matching instruction transfers control flow
  (i.e., for jumps taken, calls or returns).
* Similarly, if any component trampoline transfers control flow
  (via a `break` or `goto`), the
  rest of the "meta" trampoline will not be executed.

For example, consider the command:

        e9tool -M 'asm=/xor.*/' -P 'after trap' -P 'replace f(...)@bin' -P print -P 'before if g(...)@bin goto' ...

Then the following "meta" trampoline will be executed in place of each `xor`
instruction:

        print; if g(...) goto; f(...)@bin; trap; break;

The `print` trampoline is implicitly in the *before* position, so is executed
first.
Next, the conditional call (`if g(...) goto`), also in the *before* position,
will be executed.
This conditional call will transfer control-flow if the `g(...)` function
returns a non-`NULL` value, in which case the rest of the meta trampoline
will not be executed.
Otherwise, the call `f(...)@bin` trampoline will be executed next,
which *replace*s the original matching `xor` instruction.
Finally, the `trap` trampoline, in the *after* position, will be executed last.

This design makes it possible to compose instrumentation schemas.
For example, one could compose AFL fuzzing instrumentation with another
instrumentation for detecting memory errors.

