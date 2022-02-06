# Copyright (C) 2022 National University of Singapore
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

# Unlike "test", this program can be extended to test bugs that are triggered 
# by specific instructions.

.globl _start
.type  _start, @function
_start:

    lea .Lstack+32768-0x100(%rip),%rsp
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

    # The instrumented code starts here:
.align 512
.globl begin
.type begin, @object
begin:

.globl entry
.type entry, @object
entry:

bug_scratch:
    mov %rsp, %rdi
    xor %esi, %esi
    mov (%rdi,%rsi,8), %rax

bug_vsib:
    mov %rsp, %r8
    and $-32, %r8
    vpxor %xmm0,%xmm0,%xmm0
    vpxor %ymm0,%ymm1,%ymm1
    mov $-1,%rax
    vpgatherqd %xmm0,(%r8,%ymm1,1),%xmm2

# Additional bugs can be added here:

.Lprint:
    xor %eax,%eax   # SYS_write
    inc %eax
    mov %eax,%edi
    inc %rdi
    lea .Lstring(%rip),%rsi
    mov $7, %rdx
    syscall

.Lexit:
    mov $60,%eax    # SYS_exit
    xor %edi,%edi
    syscall
    ud2
    jmp .Lexit

.global data2
.type data2, @object
data2:
.Lstring:
    .ascii "PASSED\n"

.section .bss
.align 16
.Lstack:
.fill 32768

