#!/usr/bin/rz-asm -a x86 -b 64 -f
# SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
# SPDX-License-Identifier: LGPL-3.0-only
# - pancake xor encoder egg engine  #
# rz-asm -a x86.nasm -f xorencoder.asm

.equ CODESIZE,22
.equ BASE,0x29
.equ KEY,33

# This is a way to get EIP without 0s
.hex E8 FF FF FF FF C1
# get EIP in EBX
	pop rsi
	# rsi += base
	sub rsi, -BASE
	mov rdi, rsi
	# rcx = CODESIZE
	xor rcx, rcx
	sub rcx, -CODESIZE
	# rbx = KEY
	xor rbx, rbx
	sub rbx, -KEY
food:
	# xor [rsi], rbx
	.hex 31 1e
	add rsi, 4
	dec rcx
	test rcx, rcx
	# jnz food
	.hex 75 f2
	jmp rdi
int3
int3
int3
int3
int3
