// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/* Register layout of NetBSD/vax `struct reg`, kept in sync with the kernel:
 *   sys/arch/vax/include/reg.h (reg.h,v 1.7) declares the struct, and
 *   sys/arch/vax/vax/machdep.c:process_read_regs() (the PT_GETREGS handler)
 *   fills all 17 ints in order: r0-r11, ap, fp, sp, pc, psl.
 * With 4-byte ints these land at byte offsets 0,4,..,64 (68 bytes total).
 * The PSL condition codes are bits 0-3 of psl (absolute bits 512-515),
 * matching PSL_C/PSL_V/PSL_Z/PSL_N in sys/arch/vax/include/psl.h. */

return rz_str_dup(
	"=PC	pc\n"
	"=SP	sp\n"
	"=BP	fp\n"
	"=A0	r0\n"
	"=A1	r1\n"
	"=A2	r2\n"
	"=A3	r3\n"
	"gpr	r0	.32	0	0\n"
	"gpr	r1	.32	4	0\n"
	"gpr	r2	.32	8	0\n"
	"gpr	r3	.32	12	0\n"
	"gpr	r4	.32	16	0\n"
	"gpr	r5	.32	20	0\n"
	"gpr	r6	.32	24	0\n"
	"gpr	r7	.32	28	0\n"
	"gpr	r8	.32	32	0\n"
	"gpr	r9	.32	36	0\n"
	"gpr	r10	.32	40	0\n"
	"gpr	r11	.32	44	0\n"
	"gpr	ap	.32	48	0\n"
	"gpr	fp	.32	52	0\n"
	"gpr	sp	.32	56	0\n"
	"gpr	pc	.32	60	0\n"
	"gpr	psl	.32	64	0\n"
	"gpr	c	.1	.512	0	carry\n"
	"gpr	v	.1	.513	0	overflow\n"
	"gpr	z	.1	.514	0	zero\n"
	"gpr	n	.1	.515	0	negative\n");
