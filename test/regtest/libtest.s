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

.globl entry
.type entry, @function
entry:

.globl add
.type add, @function
add:
    mov %rdi, %rax
    add %rsi, %rax
    retq

.globl sub
.type sub, @function
sub:
    mov %rdi, %rax
    sub %rsi, %rax
    retq

.globl mul
.type mul, @function
mul:
    mov %rdi, %rax
    imul %rsi, %rax
    retq

