// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_PRIVATE_H
#define RZ_ASM_PRIVATE_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>

struct rz_asm_t {
	void *core; /// should not be used.
	ut8 ptr_alignment_I;
	void *plugin_data;
	ut8 ptr_alignment_II;
	// NOTE: Do not change the order of fields above!
	// They are used in pointer passing hacks in rz_types.h.
	char *cpu;
	int bits;
	int big_endian;
	int syntax;
	ut64 pc;
	RzAsmPlugin *cur;
	RzAsmPlugin *acur;
	HtSP /*<RzAsmPlugin *>*/ *plugins;
	RzBinBind binb;
	RzParse *ifilter;
	RzParse *ofilter;
	Sdb *pair;
	RzSyscall *syscall;
	RzPath *sdb_opcodes_path; ///< pointer to RzPath, contains path prefix of the system
	char *features;
	char *platforms;
	int invhex; // invalid instructions displayed in hex
	int pcalign;
	int bitshift;
	bool immsign; // Print signed immediates as negative values, not their unsigned representation.
	bool immdisp; // Display immediates with # symbol (for arm architectures). false = show hashs
	bool utf8; // Flag for plugins: Use utf-8 characters.
	HtSS *flags;
	int seggrn;
	bool pseudo;
};

#endif // RZ_ASM_PRIVATE_H
