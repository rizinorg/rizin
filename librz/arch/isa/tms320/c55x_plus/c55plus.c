// SPDX-FileCopyrightText: 2013 th0rpe <josediazfer@yahoo.es>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c55plus.c
 *
 * TMS320C55x+ disassembler glue layer.
 *
 * This is the entry point called from tms320_dasm() when asm.cpu is
 * "c55x+". It hands the input bytes to the th0rpe c55plus_decode()
 * walker, lower-cases the resulting mnemonic to match rizin's house
 * style, and writes it into the caller's tms320_dasm_t.
 *
 * The decode walker is a global-state machine using extern ins_buff /
 * ins_buff_len pointers -- keep this glue thin so the global setup
 * stays in one place.
 */

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_util/rz_str.h>

#define USE_DECODE
#include "decode.h"

#include "../tms320_dasm.h"

extern ut8 *ins_buff;
extern ut32 ins_buff_len;
extern char *c55plus_decode(ut32 ins_pos, ut32 *next_ins_pos);

int c55x_plus_disassemble(tms320_dasm_t *dasm, const ut8 *buf, int len) {
	ut32 next_ins_pos = 0;

	ins_buff = (ut8 *)buf;
	ins_buff_len = (ut32)len;

	char *ins_decoded = c55plus_decode(0, &next_ins_pos);
	dasm->length = next_ins_pos;
	if (!ins_decoded) {
		return 0;
	}

	/* Walker emits mixed-case mnemonics (e.g. "MOV", "AC0"); rizin
	 * convention is all-lowercase. */
	rz_str_case(ins_decoded, false);
	snprintf(dasm->syntax, sizeof(dasm->syntax), "%s", ins_decoded);
	free(ins_decoded);

	return next_ins_pos;
}
