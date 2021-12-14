# Copyright (C) 2021 National University of Singapore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This program executes a bunch of instructions, before printing
# "PASSED" to stderr and exitting.  It is used for testing E9Patch.

.globl _start
.type  _start, @function
_start:
    # These setup some predicable state & are not to be instrumented:
    #
    # Note: the first 2 words are read by the program, so do not change.
    #
    lea .Lstack+32768(%rip),%rsp
    xor %eax,%eax           # for %rflags
    mov $0x0b0b0b0b,%eax
    mov $0x1c1c1c1c,%edx
    mov $0x2d2d2d2d,%ecx
    mov $0x3e3e3e3e,%ebx
    mov $0x4f4f4f4f,%ebp
    mov $0x50505050,%esi
    mov $0x61616161,%edi
    mov $0x72727272,%r8d
    mov $0x83838383,%r9d
    mov $0x94949494,%r10d
    mov $0xa5a5a5a5,%r11d
    mov $0xb6b6b6b6,%r12d
    mov $0xc7c7c7c7,%r13d
    mov $0xd8d8d8d8,%r14d
    mov $0xe9e9e9e9,%r15d

    push %rax
    push %rdi
    push %rsi 
    push %rcx
    push %r11
    mov $158,%eax           # SYS_arch_prctl
    mov $0x1002,%edi        # ARCH_SET_FS
    lea .Lstack(%rip),%rsi
    syscall
    pop %r11
    pop %rcx
    pop %rsi
    pop %rdi
    pop %rax

    .byte 0xe9, 0x80, 0x00, 0x00, 0x00  # jmp entry

    # The instrumented code starts here:
.globl begin
.type begin, @object
begin:

    .byte 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00    # NOP
    movabs $0x1111111111111111, %r11
    movabs $0x1111111111111111, %r12
    movabs $0x1111111111111111, %r13
    movabs $0x1111111111111111, %r14
    movabs $0x1111111111111111, %r15
    movabs $0x1111111111111111, %r11
    movabs $0x1111111111111111, %r12
    movabs $0x1111111111111111, %r13
    movabs $0x1111111111111111, %r14
    movabs $0x1111111111111111, %r15
    movabs $0x1111111111111111, %r15
    movabs $0x1111111111111111, %r15

    # Execution starts here:
.globl entry
.type entry, @object
entry:

    jnz .Lunreachable
.Lloop:
    push %r15
    js  .Lloop

    mov data(%rip), %rax
    movabs $0x8877665544332211, %rbx
    cmp %rax, %rbx
    jz .Lpass_1
    ud2
.Lpass_1:
    .byte 0x66, 0x90                # 2-byte NOP
    jns .Lpass_2
    ud2
.Lpass_2:
    .byte 0x0f, 0x1f, 0x00          # 3-byte NOP
    jnl .Lpass_3
    ud2
.Lpass_3:
    jng .Lpass_4
    ud2
.Lpass_4:
    cmpl $0x33, %ebx
    jg .Lpass_5
    ud2
.Lpass_5:
    jng .Lunreachable
    mov data(%rip), %r8
    mov data2(%rip), %rcx
    cmp %r8, %rcx
    .byte 0x0f, 0x1f, 0x40, 0x00    # 4-byte NOP
    jnz .Lpass_a
    ud2
.Lpass_a:
    jg .Lpass_b
    ud2
.Lpass_b:
    jrcxz .Lrcxz
    jmp .Lpass_c
.Lrcxz:
    ud2
.Lpass_c:
    .byte 0xe8, 0x00, 0x00, 0x00, 0x00
    .byte 0xe9, 0x00, 0x00, 0x00, 0x00
    jmp .Ljump_target
.global data
.type data, @object
data:
    .byte 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
.global data_END
.type data_END, @object
data_END:
.Ljump_target:
    lea .Ljump_target_2(%rip),%r10
    push %r10
    push %r11
    mov $-0x7777,%rcx
    jmp *0x7777+0x8(%rsp,%rcx,1)
    ud2

.Ljump_target_2:
    call .Lcall_target
    
    movabs $0x1111111111111111, %r8
    movabs $0x1111111111111111, %r9
    movabs $0x1111111111111111, %r10

.Lcall_target:
    add $8,%rsp
    lea .Lcall_target_2(%rip), %rdx
    call *%rdx
.Lcall_target_2:
    pop %r14

.Linstrs:
    add $6,%r9
    add %r9,%r10
    sub $8,%r8
    sub %r8,%r10
    imul %r10
    imul %r11,%r10
    imul $0x77,%r11,%r10
    and $0xfe,%rax
    and %rax,%rbx
    or $0x13,%rbx
    or %rcx,%rbx
    not %rcx
    neg %rcx
    shl $7,%rdi
    sar $3,%rdi

.Lmath:
    push %r13
    mov $133*133,%rax
    pxor %xmm0,%xmm0
    cvtsi2ss %rax,%xmm0
    sqrtss %xmm0,%xmm1
    comiss %xmm0,%xmm1
    je .Lmath
    cvttss2si %xmm1,%rax
    cmp $133,%rax
    jne .Lmath

.Lmemory:
    mov -0x100(%rsp),%rax
    test %rax,%rax
    jz .Lpass_x
    ud2
.Lpass_x:
    xor %esi,%esi
    mov -0x100(%rsp,%rsi,8),%rax
    test %rax,%rax
    jz .Lpass_y
    ud2
.Lpass_y:
    mov %cs:-0x100(%rsp,%rsi,8),%rax
    mov %ds:-0x100(%rsp,%rsi,8),%rcx
    cmp %rax,%rcx
    je .Lpass_z
    ud2
.Lpass_z:

.if PIE
.global func
.type func, @function
func:
    lea _start(%rip),%rax
    lea -0xa000000(%rax),%rax
    mov 0xa000000(%rax),%rcx
    jecxz .Lunreachable
    inc %esi
    mov 0xa000000(%rax,%rsi,8),%rcx
    jrcxz .Lunreachable
    mov 0xa000008(%rax),%rdx
    cmp %rcx,%rdx
    jne .Lunreachable
.else
    mov 0xa000000,%ecx
    jecxz .Lunreachable
    inc %esi
    mov 0xa000000(%rax,%rsi,8),%rcx
    jrcxz .Lunreachable
    mov 0xa000000(,%rsi,8),%rdx
    cmp %rcx,%rdx
    jne .Lunreachable
    mov 0xa000008,%rdx
    cmp %rcx,%rdx
    jne .Lunreachable
.endif

.Lprint:
    xor %eax,%eax   # SYS_write
    inc %eax
    mov %eax,%edi
    inc %rdi
    lea .Lstring(%rip),%rsi
    mov $7, %rdx
    syscall
    # Note: %r11 is undefined after syscall

    mov $60,%eax    # SYS_exit
    xor %edi,%edi
    syscall

.Lunreachable:
    mov 0x12345, %rax

    # Reservoir of big instructions to help T3
.Lreservoir:
    movabs $0x1111111111111111, %r11
    movabs $0x1111111111111111, %r12
    movabs $0x1111111111111111, %r13
    movabs $0x1111111111111111, %r14
    movabs $0x1111111111111111, %r15

.global data2
.type data2, @object
data2:
    .byte 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
.Lstring:
    .ascii "PASSED\n"

.section .bss
.align 16
.Lstack:
.fill 32768

