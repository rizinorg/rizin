// SPDX-FileCopyrightText: 2025 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// found in binutils-gdb source code
// gdb/alpha-tdep.{c, h}/alpha_register_name
static const char *map_dwarf_reg_to_alpha_reg(ut32 regnum) {
	switch (regnum) {
		KASE(0, r0); // v0
		KASE(1, r1); // t0
		KASE(2, r2); // t1
		KASE(3, r3); // t2
		KASE(4, r4); // t3
		KASE(5, r5); // t4
		KASE(6, r6); // t5
		KASE(7, r7); // t6
		KASE(8, r8); // t7
		KASE(9, r9); // s0
		KASE(10, r10); // s1
		KASE(11, r11); // s2
		KASE(12, r12); // s3
		KASE(13, r13); // s4
		KASE(14, r14); // s5
		KASE(15, r15); // fp
		KASE(16, r16); // a0
		KASE(17, r17); // a1
		KASE(18, r18); // a2
		KASE(19, r19); // a3
		KASE(20, r20); // a4
		KASE(21, r21); // a5
		KASE(22, r22); // t8
		KASE(23, r23); // t9
		KASE(24, r24); // t10
		KASE(25, r25); // t11
		KASE(26, r26); // ra
		KASE(27, r27); // t12
		KASE(28, r28); // at
		KASE(29, r29); // gp
		KASE(30, r30); // sp
		KASE(31, r31); // zero
		KASE(32, f0);
		KASE(33, f1);
		KASE(34, f2);
		KASE(35, f3);
		KASE(36, f4);
		KASE(37, f5);
		KASE(38, f6);
		KASE(39, f7);
		KASE(40, f8);
		KASE(41, f9);
		KASE(42, f10);
		KASE(43, f11);
		KASE(44, f12);
		KASE(45, f13);
		KASE(46, f14);
		KASE(47, f15);
		KASE(48, f16);
		KASE(49, f17);
		KASE(50, f18);
		KASE(51, f19);
		KASE(52, f20);
		KASE(53, f21);
		KASE(54, f22);
		KASE(55, f23);
		KASE(56, f24);
		KASE(57, f25);
		KASE(58, f26);
		KASE(59, f27);
		KASE(60, f28);
		KASE(61, f29);
		KASE(62, f30);
		KASE(63, fpcr);
		KASE(64, pc);

	default:
		rz_warn_if_reached();
		return "Undefined DWARF2 register mapping for Alpha";
	}
}
