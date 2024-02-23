// SPDX-FileCopyrightText: 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_RL78_DWARF_REG_H
#define RZ_RL78_DWARF_REG_H

static const char *
rl78_register_name(ut32 index) {
	static const char *const reg_names[] = {
		"", /* bank0_r0 */
		"", /* bank0_r1 */
		"", /* bank0_r2 */
		"", /* bank0_r3 */
		"", /* bank0_r4 */
		"", /* bank0_r5 */
		"", /* bank0_r6 */
		"", /* bank0_r7 */

		"", /* bank1_r0 */
		"", /* bank1_r1 */
		"", /* bank1_r2 */
		"", /* bank1_r3 */
		"", /* bank1_r4 */
		"", /* bank1_r5 */
		"", /* bank1_r6 */
		"", /* bank1_r7 */

		"", /* bank2_r0 */
		"", /* bank2_r1 */
		"", /* bank2_r2 */
		"", /* bank2_r3 */
		"", /* bank2_r4 */
		"", /* bank2_r5 */
		"", /* bank2_r6 */
		"", /* bank2_r7 */

		"", /* bank3_r0 */
		"", /* bank3_r1 */
		"", /* bank3_r2 */
		"", /* bank3_r3 */
		"", /* bank3_r4 */
		"", /* bank3_r5 */
		"", /* bank3_r6 */
		"", /* bank3_r7 */

		"psw",
		"es",
		"cs",
		"",

		"", /* spl */
		"", /* sph */
		"pmc",
		"mem",

		"pc",
		"sp",

		"x",
		"a",
		"c",
		"b",
		"e",
		"d",
		"l",
		"h",

		"ax",
		"bc",
		"de",
		"hl",

		"bank0_r0",
		"bank0_r1",
		"bank0_r2",
		"bank0_r3",
		"bank0_r4",
		"bank0_r5",
		"bank0_r6",
		"bank0_r7",

		"bank1_r0",
		"bank1_r1",
		"bank1_r2",
		"bank1_r3",
		"bank1_r4",
		"bank1_r5",
		"bank1_r6",
		"bank1_r7",

		"bank2_r0",
		"bank2_r1",
		"bank2_r2",
		"bank2_r3",
		"bank2_r4",
		"bank2_r5",
		"bank2_r6",
		"bank2_r7",

		"bank3_r0",
		"bank3_r1",
		"bank3_r2",
		"bank3_r3",
		"bank3_r4",
		"bank3_r5",
		"bank3_r6",
		"bank3_r7",

		"bank0_rp0",
		"bank0_rp1",
		"bank0_rp2",
		"bank0_rp3",

		"bank1_rp0",
		"bank1_rp1",
		"bank1_rp2",
		"bank1_rp3",

		"bank2_rp0",
		"bank2_rp1",
		"bank2_rp2",
		"bank2_rp3",

		"bank3_rp0",
		"bank3_rp1",
		"bank3_rp2",
		"bank3_rp3",

		"bank0_rp0_ptr_r0", "bank0_rp0_ptr_r1", "bank0_rp0_ptr_r2", "bank0_rp0_ptr_r3",
		"bank0_rp0_ptr_r4", "bank0_rp0_ptr_r5", "bank0_rp0_ptr_r6", "bank0_rp0_ptr_r7",
		"bank0_rp0_ptr_r8", "bank0_rp0_ptr_r9", "bank0_rp0_ptr_r10", "bank0_rp0_ptr_r11",
		"bank0_rp0_ptr_r12", "bank0_rp0_ptr_r13", "bank0_rp0_ptr_r14", "bank0_rp0_ptr_r15"
	};

	if (index >= RZ_ARRAY_SIZE(reg_names)) {
		return NULL;
	}
	return reg_names[index];
}

#endif // RZ_RL78_DWARF_REG_H
