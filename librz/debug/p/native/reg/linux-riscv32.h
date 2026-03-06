// SPDX-FileCopyrightText: 2024 mostafa <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Matches the kernel's struct user_regs_struct for RISC-V 32-bit (asm/ptrace.h):
 *
 *   struct user_regs_struct {
 *       unsigned long pc;           // offset 0
 *       unsigned long ra;           // offset 4   (x1)
 *       unsigned long sp;           // offset 8   (x2)
 *       unsigned long gp;           // offset 12  (x3)
 *       unsigned long tp;           // offset 16  (x4)
 *       unsigned long t0;           // offset 20  (x5)
 *       unsigned long t1;           // offset 24  (x6)
 *       unsigned long t2;           // offset 28  (x7)
 *       unsigned long s0;           // offset 32  (x8 / fp)
 *       unsigned long s1;           // offset 36  (x9)
 *       unsigned long a0 .. a7;     // offset 40..68 (x10..x17)
 *       unsigned long s2 .. s11;    // offset 72..108 (x18..x27)
 *       unsigned long t3 .. t6;     // offset 112..124 (x28..x31)
 *   };  // total: 32 × 4 = 128 bytes
 *
 * x0 is hardwired zero — not stored by the kernel, mapped as virtual (?).
 */

return rz_str_dup(
	"=PC\tpc\n"
	"=SP\tx2\n"
	"=BP\tx8\n" // s0/fp (frame pointer)
	"=R0\tx10\n" // a0
	"=R1\tx11\n" // a1
	"=A0\tx10\n"
	"=A1\tx11\n"
	"=A2\tx12\n"
	"=A3\tx13\n"
	"=A4\tx14\n"
	"=A5\tx15\n"
	/* pc is the first field in the ptrace buffer */
	"gpr\tpc\t.32\t0\t0\n"
	/* x0 is hardwired zero, not stored in the ptrace buffer */
	"gpr\tx0\t.32\t?\t0\n"
	/* x1..x31 follow pc in ABI order (ra, sp, gp, tp, t0..t6, s0..s11, a0..a7) */
	"gpr\tx1\t.32\t4\t0\n" // ra
	"gpr\tx2\t.32\t8\t0\n" // sp
	"gpr\tx3\t.32\t12\t0\n" // gp
	"gpr\tx4\t.32\t16\t0\n" // tp
	"gpr\tx5\t.32\t20\t0\n" // t0
	"gpr\tx6\t.32\t24\t0\n" // t1
	"gpr\tx7\t.32\t28\t0\n" // t2
	"gpr\tx8\t.32\t32\t0\n" // s0 / fp
	"gpr\tx9\t.32\t36\t0\n" // s1
	"gpr\tx10\t.32\t40\t0\n" // a0
	"gpr\tx11\t.32\t44\t0\n" // a1
	"gpr\tx12\t.32\t48\t0\n" // a2
	"gpr\tx13\t.32\t52\t0\n" // a3
	"gpr\tx14\t.32\t56\t0\n" // a4
	"gpr\tx15\t.32\t60\t0\n" // a5
	"gpr\tx16\t.32\t64\t0\n" // a6
	"gpr\tx17\t.32\t68\t0\n" // a7
	"gpr\tx18\t.32\t72\t0\n" // s2
	"gpr\tx19\t.32\t76\t0\n" // s3
	"gpr\tx20\t.32\t80\t0\n" // s4
	"gpr\tx21\t.32\t84\t0\n" // s5
	"gpr\tx22\t.32\t88\t0\n" // s6
	"gpr\tx23\t.32\t92\t0\n" // s7
	"gpr\tx24\t.32\t96\t0\n" // s8
	"gpr\tx25\t.32\t100\t0\n" // s9
	"gpr\tx26\t.32\t104\t0\n" // s10
	"gpr\tx27\t.32\t108\t0\n" // s11
	"gpr\tx28\t.32\t112\t0\n" // t3
	"gpr\tx29\t.32\t116\t0\n" // t4
	"gpr\tx30\t.32\t120\t0\n" // t5
	"gpr\tx31\t.32\t124\t0\n" // t6
);
