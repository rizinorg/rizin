/**
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-dwarf.adoc
 */
#include "rz_util/rz_assert.h"
static const char *map_dwarf_reg_to_riscv_reg(ut32 reg_num) {
	switch (reg_num) {
		// Integer Registers
		KASE(0, x0)
		KASE(1, x1)
		KASE(2, x2)
		KASE(3, x3)
		KASE(4, x4)
		KASE(5, x5)
		KASE(6, x6)
		KASE(7, x7)
		KASE(8, x8)
		KASE(9, x9)
		KASE(10, x10)
		KASE(11, x11)
		KASE(12, x12)
		KASE(13, x13)
		KASE(14, x14)
		KASE(15, x15)
		KASE(16, x16)
		KASE(17, x17)
		KASE(18, x18)
		KASE(19, x19)
		KASE(20, x20)
		KASE(21, x21)
		KASE(22, x22)
		KASE(23, x23)
		KASE(24, x24)
		KASE(25, x25)
		KASE(26, x26)
		KASE(27, x27)
		KASE(28, x28)
		KASE(29, x29)
		KASE(30, x30)
		KASE(31, x31)
		// Floating-point Registers
		KASE(32, f0)
		KASE(33, f1)
		KASE(34, f2)
		KASE(35, f3)
		KASE(36, f4)
		KASE(37, f5)
		KASE(38, f6)
		KASE(39, f7)
		KASE(40, f8)
		KASE(41, f9)
		KASE(42, f10)
		KASE(43, f11)
		KASE(44, f12)
		KASE(45, f13)
		KASE(46, f14)
		KASE(47, f15)
		KASE(48, f16)
		KASE(49, f17)
		KASE(50, f18)
		KASE(51, f19)
		KASE(52, f20)
		KASE(53, f21)
		KASE(54, f22)
		KASE(55, f23)
		KASE(56, f24)
		KASE(57, f25)
		KASE(58, f26)
		KASE(59, f27)
		KASE(60, f28)
		KASE(61, f29)
		KASE(62, f30)
		KASE(63, f31)
		// 64 Alternate Frame Return Column
		// 65 - 95 Reserved for future standard extensions
		// 96 - 127 Vector Registers
		KASE(96, v0)
		KASE(97, v1)
		KASE(98, v2)
		KASE(99, v3)
		KASE(100, v4)
		KASE(101, v5)
		KASE(102, v6)
		KASE(103, v7)
		KASE(104, v8)
		KASE(105, v9)
		KASE(106, v10)
		KASE(107, v11)
		KASE(108, v12)
		KASE(109, v13)
		KASE(110, v14)
		KASE(111, v15)
		KASE(112, v16)
		KASE(113, v17)
		KASE(114, v18)
		KASE(115, v19)
		KASE(116, v20)
		KASE(117, v21)
		KASE(118, v22)
		KASE(119, v23)
		KASE(120, v24)
		KASE(121, v25)
		KASE(122, v26)
		KASE(123, v27)
		KASE(124, v28)
		KASE(125, v29)
		KASE(126, v30)
		KASE(127, v31)
		// 128 - 3071 Reserved for future standard extensions
		// 3072 - 4095 Reserved for custom extensions
		// 4096 - 8191 CSRs
	default:
		if (regnum >= 4096 && regnum < 8192) {
			const char *name = CSR_NAMES[regnum];
			if (name != NULL) {
				return name;
			}
			rz_warn_if_reached();
			return "unsupported_csr";
		}
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}