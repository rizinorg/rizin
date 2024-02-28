// SPDX-FileCopyrightText: 2024 Heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// found in rx toolchain gdb source code
// gdb/rx-tdep.c/rx_dwarf_reg_to_regnum
static const char *map_dwarf_reg_to_rx_reg(ut32 regnum) {
	switch (regnum) {
		KASE(0, r0);
		KASE(1, r1);
		KASE(2, r2);
		KASE(3, r3);
		KASE(4, r4);
		KASE(5, r5);
		KASE(6, r6);
		KASE(7, r7);
		KASE(8, r8);
		KASE(9, r9);
		KASE(10, r10);
		KASE(11, r11);
		KASE(12, r12);
		KASE(13, r13);
		KASE(14, r14);
		KASE(15, r15);
		KASE(16, psw);
		KASE(17, pc);
		// rxv3
		KASE(32, dr0);
		KASE(33, dr1);
		KASE(34, dr2);
		KASE(35, dr3);
		KASE(36, dr4);
		KASE(37, dr5);
		KASE(38, dr6);
		KASE(39, dr7);
		KASE(40, dr8);
		KASE(41, dr9);
		KASE(42, dr10);
		KASE(43, dr11);
		KASE(44, dr12);
		KASE(45, dr13);
		KASE(46, dr14);
		KASE(47, dr15);
	default:
		rz_warn_if_reached();
		return "Undefined DWARF2 register mapping for RX";
	}
}
