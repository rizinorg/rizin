// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "c166/c166_common.h"

// clang-format off
const char *const c166_rw[] = {
	"r0", "r1", "r2", "r3",
	"r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15",
};

const char *const c166_rb[] = {
	"rl0", "rh0",
	"rl1", "rh1",
	"rl2", "rh2",
	"rl3", "rh3",
	"rl4", "rh4",
	"rl5", "rh5",
	"rl6", "rh6",
	"rl7", "rh7",
};

/**
 * Maps hexcodes to condition codes for JMPR instructions
 * Used to determine the condition code for conditional jump instructions
 */
// C166 condition code names
const char *const conds_names[] = {
	[C166_CC_UC]    = "cc_UC",      ///< Unconditional
	[C166_CC_V]     = "cc_V",       ///< Overflow
	[C166_CC_NV]    = "cc_NV",      ///< No Overflow
	[C166_CC_N]     = "cc_N",       ///< Negative
	[C166_CC_NN]    = "cc_NN",      ///< Not Negative
	[C166_CC_C]     = "cc_C/ULT",   ///< Carry
	[C166_CC_NC]    = "cc_NC/UGE",  ///< No Carry
	[C166_CC_EQ]    = "cc_Z/EQ",    ///< Equal
	[C166_CC_NE]    = "cc_NZ/NE",   ///< Not Equal
	[C166_CC_ULE]   = "cc_ULE",     ///< Unsigned Less Than or Equal
	[C166_CC_UGT]   = "cc_UGT",     ///< Unsigned Greater Than
	[C166_CC_SLE]   = "cc_SLE",     ///< Signed Less Than or Equal
	[C166_CC_SGE]   = "cc_SGE",     ///< Signed Greater Than or Equal
	[C166_CC_SGT]   = "cc_SGT",     ///< Signed Greater Than
	[C166_CC_NET]   = "cc_NET",     ///< Not Equal and Not End-of-Table

	[C166_CC_SLT]   = "cc_SLT",     ///< Signed Less Than

	[C166_CC_NUSR0] = "cc_NUSR0",   ///< USR-bit 0 is cleared (*)
	[C166_CC_NUSR1] = "cc_NUSR1",   ///< USR-bit 1 is cleared (*)
	[C166_CC_USR0]  = "cc_USR0",    ///< USR-bit 0 is set 1
	[C166_CC_USR1]  = "cc_USR1"     ///< USR-bit 1 is set 1
};
// clang-format on

const char *conds(ut8 cc) {
	return conds_names[cc << 1];
}

const char *conds_extended(ut8 cc) {
	return conds_names[cc];
}

const char *const c166_extx_names[] = {
	"exts",
	"extp",
	"extsr",
	"extpr"
};

const char *c166_get_word_reg_name(const ut8 rb_index) {
	if (rb_index < 0 || rb_index >= 16) {
		return NULL;
	}
	const ut16 rw_index = rb_index >> 1;
	return c166_rw[rw_index];
}

ut8 c166_get_byte_offset(const ut8 rb_index) {
	return (rb_index & 1) << 3;
}
