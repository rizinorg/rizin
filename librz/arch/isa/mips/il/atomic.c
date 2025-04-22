// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file atomic.c
 * RzIL implementation of MIPS atomic operations.
 **/

static RzILOpEffect *mips_il_ll(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Linked Word (atomic)
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_lld(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Load Linked Doubleword (atomic)
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_sc(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Conditional Word (atomic)
	NOT_IMPLEMENTED;
}

static RzILOpEffect *mips_il_scd(const csh *handle, const cs_insn *insn, const ut32 gprlen) {
	// Store Conditional Doubleword (atomic)
	NOT_IMPLEMENTED;
}
