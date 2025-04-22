// SPDX-FileCopyrightText: 2002-2009 Bas Wijnen <wijnen@debian.org>
// SPDX-FileCopyrightText: 2005 Jan Wilmans <jw@dds.nl>
// SPDX-FileCopyrightText: 2012 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: GPL-3.0-or-later

/* Z80 assembler by shevek

   Copyright (C) 2002-2009 Bas Wijnen <wijnen@debian.org>
   Copyright (C) 2005 Jan Wilmans <jw@dds.nl>

   This file is part of z80asm.

   Z80asm is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Z80asm is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RZ_API_I
#define RZ_API_I
#endif
#include "z80asm.h"
#include <rz_util.h>
/* hack */
#include "expressions.c"

#define wrtb(state, x) state.obuf[state.obuflen++] = x

/* global variables */
/* mnemonics, used as argument to indx() in assemble */
static const char *mnemonics[] = {
	"call", "cpdr", "cpir", "djnz", "halt", "indr", "inir", "lddr", "ldir",
	"otdr", "otir", "outd", "outi", "push", "reti", "retn", "rlca", "rrca",
	"defb", "defw", "defs", "defm",
	"adc", "add", "and", "bit", "ccf", "cpd", "cpi", "cpl", "daa", "dec", "equ",
	"exx", "inc", "ind", "ini", "ldd", "ldi", "neg", "nop", "out", "pop",
	"res", "ret", "rla", "rlc", "rld", "rra", "rrc", "rrd", "rst", "sbc",
	"scf", "set", "sla", "sll", "sli", "sra", "srl", "sub", "xor", "org",
	"cp", "di", "ei", "ex", "im", "in", "jp", "jr", "ld", "or", "rl", "rr",
	"db", "dw", "ds", "dm",
	"include", "incbin", "if", "else", "endif", "end", "macro", "endm",
	"seek", NULL
};

/* skip over spaces in string */
static const char *delspc(const char *ptr) {
	while (*ptr && isspace ((const unsigned char) *ptr))
		ptr++;
	if (*ptr == ';') {
		ptr = "";
	}
	return ptr;
}

/* read away a comma, error if there is none */
static void rd_comma(const char **p) {
	*p = delspc (*p);
	if (**p != ',') {
		RZ_LOG_ERROR("assembler: z80: `,' expected. Remainder of line: %s\n", *p);
		return;
	}
	*p = delspc ((*p) + 1);
}

/* look ahead for a comma, no error if not found */
static int has_argument(const char **p) {
	const char *q = delspc (*p);
	return *q == ',';
}

/* During assembly, many literals are not parsed.  Instead, they are saved
 * until all labels are read.  After that, they are parsed.  This function
 * is used during assembly, to find the place where the command continues. */
static void skipword(Z80AssemblerState *state, const char **pos, char delimiter, int sp) {
	/* rd_expr will happily read the expression, and possibly return
	 * an invalid result.  It will update pos, which is what we need.  */
	/* Pass valid to allow using undefined labels without errors.  */
	int valid;
	rd_expr(state, pos, delimiter, &valid, sp, 0);
}

/* find any of the list[] entries as the start of ptr and return index */
static int indx(Z80AssemblerState *state, const char **ptr, const char **list, int error, const char **expr) {
	int i;
	*ptr = delspc (*ptr);
	if (!**ptr) {
		if (error) {
			RZ_LOG_ERROR("assembler: z80: unexpected end of line\n");
			return 0;
		} else {
			return 0;
		}
	}
	if (state->comma > 1) {
		rd_comma (ptr);
	}
	for (i = 0; list[i]; i++) {
		const char *input = *ptr;
		const char *check = list[i];
		int had_expr = 0;
		if (!list[i][0]) {
			continue;
		}
		while (*check) {
			if (*check == ' ') {
				input = delspc (input);
			} else if (*check == '*') {
				*expr = input;
				state->mem_delimiter = check[1];
				rd_expr(state, &input, state->mem_delimiter, NULL, state->sp, 0);
				had_expr = 1;
			} else if (*check == '+') {
				if (*input == '+' || *input == '-') {
					*expr = input;
					state->mem_delimiter = check[1];
					rd_expr(state, &input, state->mem_delimiter, NULL, state->sp, 0);
				}
			} else if (*check == *input || (*check >= 'a' && *check <= 'z'
							&& *check - 'a' + 'A' == *input)) {
				++input;
			} else {
				break;
			}

			++check;
		}
		if (*check || (isalnum ((const unsigned char) check[-1]) && isalnum ((const unsigned char) input[0]))) {
			continue;
		}
		if (had_expr) {
			input = delspc (input);
			if (*input && *input != ',') {
				continue;
			}
		}
		*ptr = input;
		state->comma++;
		return i + 1;
	}
	// if (error) RZ_LOG_ERROR("assembler: z80: parse error. Remainder of line=%s\n", *ptr);
	return 0;
}

/* read a mnemonic */
static int readcommand(Z80AssemblerState *state, const char **p) {
	return indx(state, p, mnemonics, 0, NULL);
}

/* try to read a label and optionally store it in the list */
static void readlabel(Z80AssemblerState *state, const char **p, int store, int sp) {
	const char *c, *d, *pos, *dummy;
	int i, j;
	struct label *previous;
	for (d = *p; *d && *d != ';'; d++) {
		;
	}
	for (c = *p; !strchr (" \r\n\t", *c) && c < d; c++) {
		;
	}
	pos = strchr (*p, ':');
	if (!pos || pos >= c) {
		return;
	}
	if (pos == *p) {
		RZ_LOG_ERROR("assembler: z80: `:' found without a label\n");
		return;
	}
	if (!store) {
		*p = pos + 1;
		return;
	}
	c = pos + 1;
	dummy = *p;
	j = rd_label(state, &dummy, &i, &previous, sp, 0);
	if (i || j) {
		RZ_LOG_ERROR("assembler: z80: duplicate definition of label %s\n", *p);
		*p = c;
		return;
	}

	*p = c;
}

static int compute_ref(Z80AssemblerState *state, struct reference *ref, int allow_invalid) {
	const char *ptr;
	int valid = 0;
	int backup_addr = state->addr;
	int backup_baseaddr = state->baseaddr;
	int backup_comma = state->comma;
	int backup_file = state->file;
	int backup_sp = state->sp;

	state->sp = ref->level;
	state->addr = ref->addr;
	state->baseaddr = ref->baseaddr;
	state->comma = ref->comma;
	state->file = ref->infile;
	ptr = ref->input;
	if (!ref->done) {
		ref->computed_value = rd_expr(state, &ptr, ref->delimiter,
			allow_invalid ? &valid : NULL,
			ref->level, 1);
		if (valid) {
			ref->done = 1;
		}
	}

	state->sp = backup_sp;
	state->addr = backup_addr;
	state->baseaddr = backup_baseaddr;
	state->comma = backup_comma;
	state->file = backup_file;
	return ref->computed_value;
}

/* read a word from input and store it in readword. return 1 on success */
static int rd_word(Z80AssemblerState *state, const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	state->readword = *p;
	state->mem_delimiter = delimiter;
	skipword(state, p, delimiter, state->sp);
	return 1;
}

/* read a byte from input and store it in readbyte. return 1 on success */
static int rd_byte(Z80AssemblerState *state, const char **p, char delimiter) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	state->readbyte = *p;
	state->writebyte = 1;
	state->mem_delimiter = delimiter;
	skipword(state, p, delimiter, state->sp);
	return 1;
}

/* read (SP), DE, or AF */
static int rd_ex1(Z80AssemblerState *state, const char **p) {
#define DE 2
#define AF 3
	const char *list[] = {
		"( sp )", "de", "af", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read first argument of IN */
static int rd_in(Z80AssemblerState *state, const char **p) {
#define A 8
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "f", "a", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read second argument of out (c),x */
static int rd_out(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "0", "a", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read (c) or (nn) */
static int rd_nnc(Z80AssemblerState *state, const char **p) {
#define C 1
	int i;
	const char *list[] = {
		"( c )", "(*)", "a , (*)", NULL
	};
	i = indx(state, p, list, 1, &(state->readbyte));
	if (i < 2) {
		return i;
	}
	return 2;
}

/* read (C) */
static int rd_c(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"( c )", "( bc )", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read a or hl */
static int rd_a_hl(Z80AssemblerState *state, const char **p) {
#define HL 2
	const char *list[] = {
		"a", "hl", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read first argument of ld */
static int rd_ld(Z80AssemblerState *state, const char **p) {
#define ldBC    1
#define ldDE    2
#define ldHL    3
#define ldSP    4
#define ldIX    5
#define ldIY    6
#define ldB     7
#define ldC     8
#define ldD     9
#define ldE     10
#define ldH     11
#define ldL     12
#define ld_HL   13
#define ldA     14
#define ldI     15
#define ldR     16
#define ld_BC   17
#define ld_DE   18
#define ld_IX   19
#define ld_IY   20
#define ld_NN   21
	int i;
	const char *list[] = {
		"ixh", "ixl", "iyh", "iyl", "bc", "de", "hl", "sp", "ix",
		"iy", "b", "c", "d", "e", "h", "l", "( hl )", "a", "i",
		"r", "( bc )", "( de )", "( ix +)", "(iy +)", "(*)", NULL
	};
	const char *nn;
	i = indx(state, p, list, 1, &nn);
	if (!i) {
		return 0;
	}
	if (i <= 2) {
		state->indexed = 0xdd;
		return ldH + (i == 2);
	}
	if (i <= 4) {
		state->indexed = 0xfd;
		return ldH + (i == 4);
	}
	i -= 4;
	if (i == ldIX || i == ldIY) {
		state->indexed = i == ldIX ? 0xDD : 0xFD;
		return ldHL;
	}
	if (i == ld_IX || i == ld_IY) {
		state->indexjmp = nn;
		state->indexed = i == ld_IX ? 0xDD : 0xFD;
		return ld_HL;
	}
	if (i == ld_NN) {
		state->readword = nn;
	}
	return i;
}

/* read first argument of JP */
static int rd_jp(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"nz", "z", "nc", "c", "po", "pe", "p", "m", "( ix )", "( iy )",
		"(hl)", NULL
	};
	i = indx(state, p, list, 0, NULL);
	if (i < 9) {
		return i;
	}
	if (i == 11) {
		return -1;
	}
	state->indexed = 0xDD + 0x20 * (i - 9);
	return -1;
}

/* read first argument of JR */
static int rd_jr(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"nz", "z", "nc", "c", NULL
	};
	return indx(state, p, list, 0, NULL);
}

/* read A */
static int rd_a(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"a", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read bc,de,hl,af */
static int rd_stack(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"bc", "de", "hl", "af", "ix", "iy", NULL
	};
	i = indx(state, p, list, 1, NULL);
	if (i < 5) {
		return i;
	}
	state->indexed = 0xDD + 0x20 * (i - 5);
	return 3;
}

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn
 * but now with extra hl or i[xy](15) for add-instruction
 * and set variables accordingly */
static int rd_r_add(Z80AssemblerState *state, const char **p) {
#define addHL   15
	int i;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l",
		"( hl )", "a", "( ix +)", "( iy +)", "hl", "ix", "iy", "*", NULL
	};
	const char *nn;
	i = indx(state, p, list, 0, &nn);
	if (i == 18) {	/* expression */
		state->readbyte = nn;
		state->writebyte = 1;
		return 7;
	}
	if (i > 14) {	/* hl, ix, iy */
		if (i > 15) {
			state->indexed = 0xDD + 0x20 * (i - 16);
		}
		return addHL;
	}
	if (i <= 4) {	/* i[xy][hl]  */
		state->indexed = 0xdd + 0x20 * (i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9) {
		return i;
	}
	state->indexed = 0xDD + 0x20 * (i - 9); /* (i[xy] +) */
	state->indexjmp = nn;
	return 7;
}

/* read bc,de,hl, or sp */
static int rd_rr_(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"bc", "de", "hl", "sp", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read bc,de,hl|ix|iy,sp. hl|ix|iy only if it is already indexed the same. */
static int rd_rrxx(Z80AssemblerState *state, const char **p) {
	const char *listx[] = {
		"bc", "de", "ix", "sp", NULL
	};
	const char *listy[] = {
		"bc", "de", "iy", "sp", NULL
	};
	const char *list[] = {
		"bc", "de", "hl", "sp", NULL
	};
	if (state->indexed == 0xdd) {
		return indx(state, p, listx, 1, NULL);
	}
	if (state->indexed == 0xfd) {
		return indx(state, p, listy, 1, NULL);
	}
	return indx(state, p, list, 1, NULL);
}

/* read b,c,d,e,h,l,(hl),a,(ix+nn),(iy+nn),nn
 * and set variables accordingly */
static int rd_r(Z80AssemblerState *state, const char **p) {
	int i;
	const char *nn;
	const char *list[] = {
		"ixl", "ixh", "iyl", "iyh", "b", "c", "d", "e", "h", "l", "( hl )",
		"a", "( ix +)", "( iy +)", "*", NULL
	};
	i = indx(state, p, list, 0, &nn);
	if (i == 15) {	/* expression */
		state->readbyte = nn;
		state->writebyte = 1;
		return 7;
	}
	if (i <= 4) {
		state->indexed = 0xdd + 0x20 * (i > 2);
		return 6 - (i & 1);
	}
	i -= 4;
	if (i < 9) {
		return i;
	}
	state->indexed = 0xDD + 0x20 * (i - 9);
	state->indexjmp = nn;
	return 7;
}

/* like rd_r(), but without nn */
static int rd_r_(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx(state, p, list, 1, &(state->indexjmp));
	if (i < 9) {
		return i;
	}
	state->indexed = 0xDD + 0x20 * (i - 9);
	return 7;
}

/* read a number from 0 to 7, for bit, set or res */
static int rd_0_7(Z80AssemblerState *state, const char **p) {
	*p = delspc (*p);
	if (**p == 0) {
		return 0;
	}
	state->bitsetres = *p;
	skipword(state, p, ',', state->sp);
	return 1;
}

/* read long condition. do not error if not found. */
static int rd_cc(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"nz", "z", "nc", "c", "po", "pe", "p", "m", NULL
	};
	return indx(state, p, list, 0, NULL);
}

/* read long or short register,  */
static int rd_r_rr(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"iy", "ix", "sp", "hl", "de", "bc", "", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "( ix +)", "( iy +)", NULL
	};
	i = indx(state, p, list, 1, &(state->indexjmp));
	if (!i) {
		return 0;
	}
	if (i < 16 && i > 2) {
		return 7 - i;
	}
	if (i > 15) {
		state->indexed = 0xDD + (i - 16) * 0x20;
		return -7;
	}
	state->indexed = 0xDD + (2 - i) * 0x20;
	return 3;
}

/* read hl */
static int rd_hl(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"hl", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read hl, ix, or iy */
static int rd_hlx(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"hl", "ix", "iy", NULL
	};
	i = indx(state, p, list, 1, NULL);
	if (i < 2) {
		return i;
	}
	state->indexed = 0xDD + 0x20 * (i - 2);
	return 1;
}

/* read af' */
static int rd_af_(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"af'", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read 0(1), 1(3), or 2(4) */
static int rd_0_2(Z80AssemblerState *state, const char **p) {
	const char *list[] = {
		"0", "", "1", "2", NULL
	};
	return indx(state, p, list, 1, NULL);
}

/* read argument of ld (hl), */
static int rd_ld_hl(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "", "a", "*", NULL
	};
	i = indx(state, p, list, 0, &(state->readbyte));
	if (i < 9) {
		return i;
	}
	state->writebyte = 1;
	return 7;
}

/* read argument of ld (nnnn), */
static int rd_ld_nn(Z80AssemblerState *state, const char **p) {
#define ld_nnHL 5
#define ld_nnA 6
	int i;
	const char *list[] = {
		"bc", "de", "", "sp", "hl", "a", "ix", "iy", NULL
	};
	i = indx(state, p, list, 1, NULL);
	if (i < 7) {
		return i;
	}
	state->indexed = 0xdd + 0x20 * (i == 8);
	return ld_nnHL;
}

/* read argument of ld a, */
static int rd_lda(Z80AssemblerState *state, const char **p) {
#define A_N 7
#define A_I 9
#define A_R 10
#define A_NN 11
	int i;
	const char *list[] = {
		"( sp )", "( iy +)", "( de )", "( bc )", "( ix +)", "b", "c", "d", "e", "h",
		"l", "( hl )", "a", "i", "r", "(*)", "*", NULL
	};
	const char *nn;
	i = indx(state, p, list, 0, &nn);
	if (i == 2 || i == 5) {
		state->indexed = (i == 2) ? 0xFD : 0xDD;
		state->indexjmp = nn;
		return 7;
	}
	if (i == 17) {
		state->readbyte = nn;
		state->writebyte = 1;
		return 7;
	}
	if (i == 16) {
		state->readword = nn;
	}
	return i - 5;
}

/* read argument of ld b|c|d|e|h|l */
static int rd_ldbcdehla(Z80AssemblerState *state, const char **p) {
	int i;
	const char *list[] = {
		"b", "c", "d", "e", "h", "l", "( hl )", "a", "( ix +)", "( iy +)", "ixh",
		"ixl", "iyh", "iyl", "*", NULL
	};
	const char *nn;
	i = indx(state, p, list, 0, &nn);
	if (i == 15) {
		state->readbyte = nn;
		state->writebyte = 1;
		return 7;
	}
	if (i > 10) {
		int x;
		x = 0xdd + 0x20 * (i > 12);
		if (state->indexed && state->indexed != x) {
			RZ_LOG_ERROR("assembler: z80: illegal use of index registers\n");
			return 0;
		}
		state->indexed = x;
		return 6 - (i & 1);
	}
	if (i > 8) {
		if (state->indexed) {
			RZ_LOG_ERROR("assembler: z80: illegal use of index registers\n");
			return 0;
		}
		state->indexed = 0xDD + 0x20 * (i == 10);
		state->indexjmp = nn;
		return 7;
	}
	return i;
}

/* read nnnn, or (nnnn) */
static int rd_nn_nn(Z80AssemblerState *state, const char **p) {
#define _NN 1
	const char *list[] = {
		"(*)", "*", NULL
	};
	return 2 - indx(state, p, list, 0, &(state->readword));
}

/* read {HL|IX|IY},nnnn, or (nnnn) */
static int rd_sp(Z80AssemblerState *state, const char **p) {
#define SPNN 0
#define SPHL 1
	int i;
	const char *list[] = {
		"hl", "ix", "iy", "(*)", "*", NULL
	};
	const char *nn;
	i = indx(state, p, list, 0, &nn);
	if (i > 3) {
		state->readword = nn;
		return i == 4? 2: 0;
	}
	if (i != 1) {
		state->indexed = 0xDD + 0x20 * (i - 2);
	}
	return 1;
}

/* do the actual work */
static int assemble(const char *str, unsigned char *_obuf) {
	Z80AssemblerState state = {
		.addr = 0,
		.z80buffer = strdup(str),
		.comma = 0,
		.indexed = 0,
		.indexjmp = 0,
		.writebyte = 0,
		.readbyte = 0,
		.readword = 0,
		.define_macro = 0,
		.verbose = 0,

		.obuflen = 0,
		.obuf = _obuf,
	};

	const char *ptr;
	char *bufptr;
	int r, s; /* registers */
	int cmd;

	for (bufptr = state.z80buffer; (bufptr = strchr(bufptr, '\n'));) {
		*bufptr = ' ';
	}
	for (bufptr = state.z80buffer; (bufptr = strchr(bufptr, '\r'));) {
		*bufptr = ' ';
	}
	ptr = state.z80buffer;
	state.baseaddr = state.addr;
	++state.stack[state.sp].line;

	ptr = delspc (ptr);
	if (!*ptr) {
		return state.obuflen;
	}

	readlabel(&state, &ptr, 1, state.sp);

	ptr = delspc (ptr);
	if (!*ptr) {
		return state.obuflen;
	}

	cmd = readcommand(&state, &ptr) - 1;
	int i, have_quote;
	switch (cmd) {
		case Z80_ADC:
			if (!(r = rd_a_hl(&state, &ptr))) {
				break;
			}
			if (r == HL) {
				if (!(r = rd_rr_(&state, &ptr))) {
					break;
				}
				wrtb(state, 0xED);
				r--;
				wrtb(state, 0x4A + 0x10 * r);
				break;
			}
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0x88 + r);
			break;
		case Z80_ADD:
			if (!(r = rd_r_add(&state, &ptr))) {
				break;
			}
			if (r == addHL) {
				if (!(r = rd_rrxx(&state, &ptr))) {
					break;
				}
				r--;
				wrtb(state, 0x09 + 0x10 * r); /* ADD HL/IX/IY, qq  */
				break;
			}
			if (has_argument (&ptr)) {
				if (r != A) {
					RZ_LOG_ERROR("assembler: z80: parse error before: %s\n", ptr);
					break;
				}
				if (!(r = rd_r(&state, &ptr))) {
					break;
				}
				r--;
				wrtb(state, 0x80 + r); /* ADD A,r  */
				break;
			}
			r--;
			wrtb(state, 0x80 + r); /* ADD r  */
			break;
		case Z80_AND:
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xA0 + r);
			break;
		case Z80_BIT:
			if (!rd_0_7(&state, &ptr)) {
				break;
			}
			rd_comma (&ptr);
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			wrtb(state, 0x40 + (r - 1));
			break;
		case Z80_CALL:
			if ((r = rd_cc(&state, &ptr))) {
				r--;
				wrtb(state, 0xC4 + 8 * r);
				rd_comma (&ptr);
			} else {
				wrtb(state, 0xCD);
			}
			break;
		case Z80_CCF:
			wrtb(state, 0x3F);
			break;
		case Z80_CP:
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xB8 + r);
			break;
		case Z80_CPD:
			wrtb(state, 0xED);
			wrtb(state, 0xA9);
			break;
		case Z80_CPDR:
			wrtb(state, 0xED);
			wrtb(state, 0xB9);
			break;
		case Z80_CPI:
			wrtb(state, 0xED);
			wrtb(state, 0xA1);
			break;
		case Z80_CPIR:
			wrtb(state, 0xED);
			wrtb(state, 0xB1);
			break;
		case Z80_CPL:
			wrtb(state, 0x2F);
			break;
		case Z80_DAA:
			wrtb(state, 0x27);
			break;
		case Z80_DEC:
			if (!(r = rd_r_rr(&state, &ptr))) {
				break;
			}
			if (r < 0) {
				r--;
				wrtb(state, 0x05 - 8 * r);
				break;
			}
			r--;
			wrtb(state, 0x0B + 0x10 * r);
			break;
		case Z80_DI:
			wrtb(state, 0xF3);
			break;
		case Z80_DJNZ:
			wrtb(state, 0x10);
			// rd_wrt_jr (&ptr, '\0');
			break;
		case Z80_EI:
			wrtb(state, 0xFB);
			break;
		case Z80_EX:
			if (!(r = rd_ex1(&state, &ptr))) {
				break;
			}
			switch (r) {
				case DE:
					if (!rd_hl(&state, &ptr)) {
						break;
					}
					wrtb(state, 0xEB);
					break;
				case AF:
					if (!rd_af_(&state, &ptr)) {
						break;
					}
					wrtb(state, 0x08);
					break;
				default:
					if (!rd_hlx(&state, &ptr)) {
						break;
					}
					wrtb(state, 0xE3);
			}
			break;
		case Z80_EXX:
			wrtb(state, 0xD9);
			break;
		case Z80_HALT:
			wrtb(state, 0x76);
			break;
		case Z80_IM:
			if (!(r = rd_0_2(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xED);
			r--;
			wrtb(state, 0x46 + 8 * r);
			break;
		case Z80_IN:
			if (!(r = rd_in(&state, &ptr))) {
				break;
			}
			if (r == A) {
				if (!(r = rd_nnc(&state, &ptr))) {
					break;
				}
				if (r == C) {
					wrtb(state, 0xED);
					wrtb(state, 0x40 + 8 * (A - 1));
					break;
				}
				wrtb(state, 0xDB);
				break;
			}
			if (!rd_c(&state, &ptr)) {
				break;
			}
			wrtb(state, 0xED);
			r--;
			wrtb(state, 0x40 + 8 * r);
			break;
		case Z80_INC:
			if (!(r = rd_r_rr(&state, &ptr))) {
				break;
			}
			if (r < 0) {
				r++;
				wrtb(state, 0x04 - 8 * r);
				break;
			}
			r--;
			wrtb(state, 0x03 + 0x10 * r);
			break;
		case Z80_IND:
			wrtb(state, 0xED);
			wrtb(state, 0xAA);
			break;
		case Z80_INDR:
			wrtb(state, 0xED);
			wrtb(state, 0xBA);
			break;
		case Z80_INI:
			wrtb(state, 0xED);
			wrtb(state, 0xA2);
			break;
		case Z80_INIR:
			wrtb(state, 0xED);
			wrtb(state, 0xB2);
			break;
		case Z80_JP:
			r = rd_jp(&state, &ptr);
			if (r < 0) {
				wrtb(state, 0xE9);
				break;
			}
			if (r) {
				r--;
				wrtb(state, 0xC2 + 8 * r);
				rd_comma (&ptr);
			} else {
				wrtb(state, 0xC3);
			}
			break;
		case Z80_JR:
			r = rd_jr(&state, &ptr);
			if (r) {
				rd_comma (&ptr);
			}
			wrtb(state, 0x18 + 8 * r);
			break;
		case Z80_LD:
			if (!(r = rd_ld(&state, &ptr))) {
				break;
			}
			switch (r) {
				case ld_BC:
				case ld_DE:
					if (!rd_a(&state, &ptr)) {
						break;
					}
					wrtb(state, 0x02 + 0x10 * (r == ld_DE ? 1 : 0));
					break;
				case ld_HL:
					r = rd_ld_hl(&state, &ptr) - 1;
					wrtb(state, 0x70 + r);
					break;
				case ld_NN:
					if (!(r = rd_ld_nn(&state, &ptr))) {
						break;
					}
					if (r == ld_nnA || r == ld_nnHL) {
						wrtb(state, 0x22 + 0x10 * (r == ld_nnA ? 1 : 0));
						break;
					}
					wrtb(state, 0xED);
					wrtb(state, 0x43 + 0x10 * --r);
					break;
				case ldA:
					if (!(r = rd_lda(&state, &ptr))) {
						break;
					}
					if (r == A_NN) {
						wrtb(state, 0x3A);
						break;
					}
					if (r == A_I || r == A_R) {
						wrtb(state, 0xED);
						wrtb(state, 0x57 + 8 * (r == A_R ? 1 : 0));
						break;
					}
					if (r == A_N) {
						char n = rz_num_math(NULL, state.readbyte);
						wrtb(state, 0x3E);
						wrtb(state, n);
						break;
					}
					if (r < 0) {
						r++;
						wrtb(state, 0x0A - 0x10 * r);
						break;
					}
					wrtb(state, 0x78 + --r);
					break;
				case ldB:
				case ldC:
				case ldD:
				case ldE:
				case ldH:
				case ldL:
					if (!(s = rd_ldbcdehla(&state, &ptr))) {
						break;
					}
					if (s == 7) {
						char n = rz_num_math(NULL, state.readbyte);
						wrtb(state, 0x08 * (r - 7) + 0x6);
						wrtb(state, n);
					} else {
						wrtb(state, 0x40 + 0x08 * (r - 7) + (s - 1));
					}
					break;
				case ldBC:
				case ldDE:
					s = rd_nn_nn(&state, &ptr);
					if (s == _NN) {
						wrtb(state, 0xED);
						wrtb(state, 0x4B + 0x10 * (r == ldDE ? 1 : 0));
						break;
					}
					wrtb(state, 0x01 + (r == ldDE ? 1 : 0) * 0x10);
					break;
				case ldHL:
					r = rd_nn_nn(&state, &ptr);
					wrtb(state, 0x21 + (r == _NN ? 1 : 0) * 9);
					break;
				case ldI:
				case ldR:
					if (!rd_a(&state, &ptr)) {
						break;
					}
					wrtb(state, 0xED);
					wrtb(state, 0x47 + 0x08 * (r == ldR ? 1 : 0));
					break;
				case ldSP:
					r = rd_sp(&state, &ptr);
					if (r == SPHL) {
						wrtb(state, 0xF9);
						break;
					}
					if (r == SPNN) {
						wrtb(state, 0x31);
						break;
					}
					wrtb(state, 0xED);
					wrtb(state, 0x7B);
					break;
			}
			break;
		case Z80_LDD:
			wrtb(state, 0xED);
			wrtb(state, 0xA8);
			break;
		case Z80_LDDR:
			wrtb(state, 0xED);
			wrtb(state, 0xB8);
			break;
		case Z80_LDI:
			wrtb(state, 0xED);
			wrtb(state, 0xA0);
			break;
		case Z80_LDIR:
			wrtb(state, 0xED);
			wrtb(state, 0xB0);
			break;
		case Z80_NEG:
			wrtb(state, 0xED);
			wrtb(state, 0x44);
			break;
		case Z80_NOP:
			wrtb(state, 0x00);
			break;
		case Z80_OR:
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xB0 + r);
			break;
		case Z80_OTDR:
			wrtb(state, 0xED);
			wrtb(state, 0xBB);
			break;
		case Z80_OTIR:
			wrtb(state, 0xED);
			wrtb(state, 0xB3);
			break;
		case Z80_OUT:
			if (!(r = rd_nnc(&state, &ptr))) {
				break;
			}
			if (r == C) {
				if (!(r = rd_out(&state, &ptr))) {
					break;
				}
				wrtb(state, 0xED);
				r--;
				wrtb(state, 0x41 + 8 * r);
				break;
			}
			if (!rd_a(&state, &ptr)) {
				break;
			}
			wrtb(state, 0xD3);
			break;
		case Z80_OUTD:
			wrtb(state, 0xED);
			wrtb(state, 0xAB);
			break;
		case Z80_OUTI:
			wrtb(state, 0xED);
			wrtb(state, 0xA3);
			break;
		case Z80_POP:
			if (!(r = rd_stack(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xC1 + 0x10 * r);
			break;
		case Z80_PUSH:
			if (!(r = rd_stack(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xC5 + 0x10 * r);
			break;
		case Z80_RES:
			if (!rd_0_7(&state, &ptr)) {
				break;
			}
			rd_comma (&ptr);
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x80 + r);
			break;
		case Z80_RET:
			if (!(r = rd_cc(&state, &ptr))) {
				wrtb(state, 0xC9);
				break;
			}
			r--;
			wrtb(state, 0xC0 + 8 * r);
			break;
		case Z80_RETI:
			wrtb(state, 0xED);
			wrtb(state, 0x4D);
			break;
		case Z80_RETN:
			wrtb(state, 0xED);
			wrtb(state, 0x45);
			break;
		case Z80_RL:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x10 + r);
			break;
		case Z80_RLA:
			wrtb(state, 0x17);
			break;
		case Z80_RLC:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x00 + r);
			break;
		case Z80_RLCA:
			wrtb(state, 0x07);
			break;
		case Z80_RLD:
			wrtb(state, 0xED);
			wrtb(state, 0x6F);
			break;
		case Z80_RR:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x18 + r);
			break;
		case Z80_RRA:
			wrtb(state, 0x1F);
			break;
		case Z80_RRC:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x08 + r);
			break;
		case Z80_RRCA:
			wrtb(state, 0x0F);
			break;
		case Z80_RRD:
			wrtb(state, 0xED);
			wrtb(state, 0x67);
			break;
		case Z80_RST:
			ptr = "";
			break;
		case Z80_SBC:
			if (!(r = rd_a_hl(&state, &ptr))) {
				break;
			}
			if (r == HL) {
				if (!(r = rd_rr_(&state, &ptr))) {
					break;
				}
				wrtb(state, 0xED);
				r--;
				wrtb(state, 0x42 + 0x10 * r);
				break;
			}
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0x98 + r);
			break;
		case Z80_SCF:
			wrtb(state, 0x37);
			break;
		case Z80_SET:
			if (!rd_0_7(&state, &ptr)) {
				break;
			}
			rd_comma (&ptr);
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0xC0 + r);
			break;
		case Z80_SLA:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x20 + r);
			break;
		case Z80_SLI:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x30 + r);
			break;
		case Z80_SRA:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x28 + r);
			break;
		case Z80_SRL:
			if (!(r = rd_r_(&state, &ptr))) {
				break;
			}
			wrtb(state, 0xCB);
			r--;
			wrtb(state, 0x38 + r);
			break;
		case Z80_SUB:
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			if (has_argument (&ptr)) {		/* SUB A,r ?  */
				if (r != A) {
					RZ_LOG_ERROR("assembler: z80: parse error before: %s\n", ptr);
					break;
				}
				if (!(r = rd_r(&state, &ptr))) {
					break;
				}
			}
			r--;
			wrtb(state, 0x90 + r);
			break;
		case Z80_XOR:
			if (!(r = rd_r(&state, &ptr))) {
				break;
			}
			r--;
			wrtb(state, 0xA8 + r);
			break;
		case Z80_DEFB:
		case Z80_DB:
		case Z80_DEFM:
		case Z80_DM:
			ptr = delspc (ptr);
			while (1) {
				have_quote = (*ptr == '"' || *ptr == '\'');
				if (have_quote) {
					/* Read string.  */
					int quote = *ptr;
					++ptr;
					while (*ptr != quote) {
						wrtb(state, rd_character(&state, &ptr, NULL, 1));
						if (*ptr == 0) {
							RZ_LOG_ERROR("assembler: z80: end of line in quoted string\n");
							break;
						}
					}
					++ptr;
				} else {
					/* Read expression.  */
					skipword(&state, &ptr, ',', state.sp);
				}
				ptr = delspc (ptr);
				if (*ptr == ',') {
					++ptr;
					continue;
				}
				if (*ptr != 0) {
					RZ_LOG_ERROR("assembler: z80: junk in byte definition: %s\n", ptr);
				}
				break;
			}
			break;
		case Z80_DEFW:
		case Z80_DW:
			if (!rd_word(&state, &ptr, ',')) {
				RZ_LOG_ERROR("assembler: z80: No data for word definition\n");
				break;
			}
			while (1) {
				ptr = delspc (ptr);
				if (*ptr != ',') {
					break;
				}
				++ptr;
				if (!rd_word(&state, &ptr, ',')) {
					RZ_LOG_ERROR("assembler: z80: Missing expression in defw\n");
				}
			}
			break;
		case Z80_DEFS:
		case Z80_DS:
			r = rd_expr(&state, &ptr, ',', NULL, state.sp, 1);
			if (r < 0) {
				RZ_LOG_ERROR("assembler: z80: ds should have its first argument >=0"
						" (not -0x%x)\n", -r);
				break;
			}
			ptr = delspc (ptr);
			if (*ptr) {
				rd_comma (&ptr);
				state.readbyte = 0;
				rd_byte(&state, &ptr, '\0');
				state.writebyte = 0;
				break;
			}
			for (i = 0; i < r; i++) {
				wrtb(state, 0);
			}
			break;
		case Z80_END:
			break;
		case Z80_ORG:
			state.addr = rd_expr(&state, &ptr, '\0', NULL, state.sp, 1) & 0xffff;
			break;
		case Z80_IF:
			break;
		case Z80_ELSE:
			RZ_LOG_ERROR("assembler: z80: else without if\n");
			break;
		case Z80_ENDIF:
			RZ_LOG_ERROR("assembler: z80: endif without if\n");
			break;
		case Z80_ENDM:
			if (state.stack[state.sp].file) {
				RZ_LOG_ERROR("assembler: z80: endm outside macro definition\n");
			}
			break;
		case Z80_SEEK:
			RZ_LOG_ERROR("assembler: z80: seek error\n");
			break;
		default:
			// RZ_LOG_ERROR("assembler: z80: command or comment expected (was %s)\n", ptr);
			return 0;
	}

	return state.obuflen;
}

// XXX
RZ_API_I int z80asm(unsigned char *outbuf, const char *s) {
	return assemble (s, outbuf);
}

#ifdef MAIN_ASM
int main(int argc, char **argv) {
	int len;
	unsigned char buf[4];

	buf[0] = buf[1] = buf[2] = 0;
	len = z80asm (buf, "nop");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "cp b");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "call 0x123");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	len = z80asm (buf, "call bla");
	printf ("%d   %02x%02x%02x\n", len, buf[0], buf[1], buf[2]);

	return 0;
}
#endif
