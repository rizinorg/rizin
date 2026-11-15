// SPDX-FileCopyrightText: 2024-2026 mostafa <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

return rz_str_dup(
	"=PC	pc\n"
	"=LR	x1\n"
	"=SP	x2\n"
	"=BP	x8\n" // s0/fp (frame pointer)
	"=R0	x10\n" // a0
	"=R1	x11\n" // a1
	"=A0	x10\n"
	"=A1	x11\n"
	"=A2	x12\n"
	"=A3	x13\n"
	"=A4	x14\n"
	"=A5	x15\n"
	"=A6	x16\n"
	"=A7	x17\n"
	"gpr	pc	.32	0	0\n"
	"gpr	x1	.32	4	0\n" // ra
	"gpr	x2	.32	8	0\n" // sp
	"gpr	x3	.32	12	0\n" // gp
	"gpr	x4	.32	16	0\n" // tp
	"gpr	x5	.32	20	0\n" // t0
	"gpr	x6	.32	24	0\n" // t1
	"gpr	x7	.32	28	0\n" // t2
	"gpr	x8	.32	32	0\n" // s0 / fp
	"gpr	x9	.32	36	0\n" // s1
	"gpr	x10	.32	40	0\n" // a0
	"gpr	x11	.32	44	0\n" // a1
	"gpr	x12	.32	48	0\n" // a2
	"gpr	x13	.32	52	0\n" // a3
	"gpr	x14	.32	56	0\n" // a4
	"gpr	x15	.32	60	0\n" // a5
	"gpr	x16	.32	64	0\n" // a6
	"gpr	x17	.32	68	0\n" // a7
	"gpr	x18	.32	72	0\n" // s2
	"gpr	x19	.32	76	0\n" // s3
	"gpr	x20	.32	80	0\n" // s4
	"gpr	x21	.32	84	0\n" // s5
	"gpr	x22	.32	88	0\n" // s6
	"gpr	x23 .32 92	0\n" // s7
	"gpr	x24 .32 96	0\n" // s8
	"gpr	x25 .32 100	0\n" // s9
	"gpr	x26 .32 104	0\n" // s10
	"gpr	x27 .32 108	0\n" // s11
	"gpr	x28 .32 112	0\n" // t3
	"gpr	x29 .32 116	0\n" // t4
	"gpr	x30 .32 120	0\n" // t5
	"gpr	x31 .32 124	0\n" // t6
);
