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

.globl begin
.type  begin, @function
begin:
.globl entry
.type  entry, @function
    ud2
entry:
.globl main
.type  main, @function
    .byte 0x66, 0x90
main:
    subq $8, %rsp
    movsd .Lpi(%rip), %xmm0
    movq stderr@GOTPCREL(%rip), %rax
    leaq .Lformat(%rip), %rsi
    movq (%rax), %rdi
    movl $1, %eax
    call fprintf@PLT

    xor %edi,%edi
    call exit@PLT

    movabs $0x1111111111111111, %r15
    movabs $0x1111111111111111, %r15
    movabs $0x1111111111111111, %r15

.globl data
.type  data, @function
data:
.globl data_END
.type  data_END, @function
data_END:
.globl data2
.type  data2, @function
data2:
    ud2

.globl func
.type func, @function
func:
    movsd .Le(%rip), %xmm0
    retq

.section .rodata
.align 16
.Lpi:
    .long   4028335726
    .long   1074340345
.Le:
    .long   2511009680
    .long   1074118409
.Lformat:
    .string "xmm0 = %g\n"

