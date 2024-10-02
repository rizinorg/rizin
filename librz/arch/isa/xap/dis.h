// SPDX-FileCopyrightText: 2007 sorbo
// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _INCLUDE_XAP_DIS_H_
#define _INCLUDE_XAP_DIS_H_

#include <rz_types.h>
#include <rz_util.h>

typedef struct instruction {
	ut16 in_mode; // : 2,
	ut16 in_reg; // : 2,
	ut16 in_opcode; // : 4,
	ut16 in_operand; // : 8;
} xap_instruction_t;

#if 0
struct instruction {
	ut16 in_mode : 2,
		in_reg : 2,
		in_opcode : 4,
		in_operand : 8;
#if __sun || defined(_MSC_VER)
#ifndef _MSC_VER
#warning XXX related to sunstudio :O
#endif
};
#else
} __packed;
#endif
#endif

typedef struct directive {
	ut16 opcode;
	struct instruction d_inst;
	int d_operand;
	int d_prefix;
	unsigned int d_off;
	RzStrBuf *d_asm;
	struct directive *d_next;
} xap_directive_t;

typedef struct label {
	char l_name[128];
	unsigned int l_off;
	struct directive *l_refs[666];
	int l_refc;
	struct label *l_next;
} xap_label_t;

typedef struct state {
	int s_prefix;
	unsigned int s_prefix_val;
	unsigned int s_off;
	char *s_fname;
	int s_u;
	unsigned int s_labelno;
	const unsigned char *s_buf;
	xap_directive_t s_dirs;
	xap_label_t s_labels;
	int s_format;
	int s_nop;
	xap_directive_t *s_nopd;
	int s_ff_quirk;
} xap_state_t;

#define MODE_MASK     3
#define REG_SHIFT     2
#define REG_MASK      3
#define OPCODE_SHIFT  4
#define OPCODE_MASK   0xF
#define OPERAND_SHIFT 8

#define INST_NOP   0x0000
#define INST_BRK   0x0004
#define INST_SLEEP 0x0008
#define INST_U     0x0009
#define INST_SIF   0x000C
#define INST_RTS   0x00E2
#define INST_BRXL  0xfe09
#define INST_BC    0xff09

#define REG_AH 0
#define REG_AL 1
#define REG_X  2
#define REG_Y  3

#define DATA_MODE_IMMEDIATE 0
#define DATA_MODE_DIRECT    1
#define DATA_MODE_INDEXED_X 2
#define DATA_MODE_INDEXED_Y 3

#define ADDR_MODE_RELATIVE   0
#define ADDR_MODE_X_RELATIVE 2

static void xap_decode(xap_state_t *s, xap_directive_t *d);
static int xap_read_instruction(xap_state_t *s, xap_directive_t *d);

#endif
