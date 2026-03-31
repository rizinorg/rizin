// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "amd29k.h"
#include "amd29k_internal.h"
#include <stdio.h>
#include <string.h>
#include <rz_analysis.h>

#define N_AMD29K_INSTRUCTIONS 207

#define AMD29K_GET_TYPE(x, i)  ((x)->type[(i)])
#define AMD29K_GET_VALUE(x, i) ((x)->operands[(i)])
#define AMD29K_SET_VALUE(x, i, v, t) \
	((x)->operands[(i)] = (v)); \
	((x)->type[(i)] = (t))
#define AMD29K_SET_INVALID(x, i) ((x)->type[(i)] = AMD29K_TYPE_UNK)
#define AMD29K_HAS_BIT(x)        (((x)[0] & 1))

#define AMD29K_REG_LR0 128

// clang-format off
static const char *amd29k_reg_names[] = {
// global registers
	  "gr0",   "rsp",   "gr2",   "gr3",   "gr4",   "gr5",   "gr6",   "gr7",
	  "gr8",   "gr9",  "gr10",  "gr11",  "gr12",  "gr13",  "gr14",  "gr15",
	 "gr16",  "gr17",  "gr18",  "gr19",  "gr20",  "gr21",  "gr22",  "gr23",
	 "gr24",  "gr25",  "gr26",  "gr27",  "gr28",  "gr29",  "gr30",  "gr31",
	 "gr32",  "gr33",  "gr34",  "gr35",  "gr36",  "gr37",  "gr38",  "gr39",
	 "gr40",  "gr41",  "gr42",  "gr43",  "gr44",  "gr45",  "gr46",  "gr47",
	 "gr48",  "gr49",  "gr50",  "gr51",  "gr52",  "gr53",  "gr54",  "gr55",
	 "gr56",  "gr57",  "gr58",  "gr59",  "gr60",  "gr61",  "gr62",  "gr63",
	  "it0",   "it1",   "it2",   "it3",   "kt0",   "kt1",   "kt2",   "kt3",
	  "kt4",   "kt5",   "kt6",   "kt7",   "kt8",   "kt9",  "kt10",  "kt11",
	  "ks0",   "ks1",   "ks2",   "ks3",   "ks4",   "ks5",   "ks6",   "ks7",
	  "ks8",   "ks9",  "ks10",  "ks11",  "ks12",  "ks13",  "ks14",  "ks15",
	   "v0",    "v1",    "v2",    "v3",    "v4",    "v5",    "v6",    "v7",
	   "v8",    "v9",   "v10",   "v11",   "v12",   "v13",   "v14",   "v15",
	   "r1",    "r2",    "r3",    "r4",    "x0",    "x1",    "x2",    "x3",
   	   "x4",   "tav",   "tpc",   "lrp",   "slp",   "msp",   "rab",   "rfb",
// local registers
	  "lr0",   "lr1",    "p0",    "p1",    "p2",    "p3",    "p4",    "p5",
	   "p6",    "p7",    "p8",    "p9",   "p10",   "p11",   "p12",   "p13",
	  "p14",   "p15",  "lr18",  "lr19",  "lr20",  "lr21",  "lr22",  "lr23",
	 "lr24",  "lr25",  "lr26",  "lr27",  "lr28",  "lr29",  "lr30",  "lr31",
	 "lr32",  "lr33",  "lr34",  "lr35",  "lr36",  "lr37",  "lr38",  "lr39",
	 "lr40",  "lr41",  "lr42",  "lr43",  "lr44",  "lr45",  "lr46",  "lr47",
	 "lr48",  "lr49",  "lr50",  "lr51",  "lr52",  "lr53",  "lr54",  "lr55",
	 "lr56",  "lr57",  "lr58",  "lr59",  "lr60",  "lr61",  "lr62",  "lr63",
	 "lr64",  "lr65",  "lr66",  "lr67",  "lr68",  "lr69",  "lr70",  "lr71",
	 "lr72",  "lr73",  "lr74",  "lr75",  "lr76",  "lr77",  "lr78",  "lr79",
	 "lr80",  "lr81",  "lr82",  "lr83",  "lr84",  "lr85",  "lr86",  "lr87",
	 "lr88",  "lr89",  "lr90",  "lr91",  "lr92",  "lr93",  "lr94",  "lr95",
	 "lr96",  "lr97",  "lr98",  "lr99", "lr100", "lr101", "lr102", "lr103",
	"lr104", "lr105", "lr106", "lr107", "lr108", "lr109", "lr110", "lr111",
	"lr112", "lr113", "lr114", "lr115", "lr116", "lr117", "lr118", "lr119",
	"lr120", "lr121", "lr122", "lr123", "lr124", "lr125", "lr126", "lr127"
};
// clang-format on

static void decode_ra_rb_rci(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	if (AMD29K_HAS_BIT(buffer)) {
		AMD29K_SET_VALUE(instruction, 2, buffer[3], AMD29K_TYPE_IMM);
	} else {
		AMD29K_SET_VALUE(instruction, 2, buffer[3], AMD29K_TYPE_REG);
	}
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_imm_rb_rci(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	if (AMD29K_HAS_BIT(buffer)) {
		AMD29K_SET_VALUE(instruction, 2, buffer[3], AMD29K_TYPE_IMM);
	} else {
		AMD29K_SET_VALUE(instruction, 2, buffer[3], AMD29K_TYPE_REG);
	}
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_ra_rb_rc(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 2, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_ra_imm16(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 8) + buffer[3];
	AMD29K_SET_VALUE(instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, word, AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_ra_i16_sh2(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int)(0xfffc0000 | word);
	}
	AMD29K_SET_VALUE(instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, (ut32)word, AMD29K_TYPE_JMP);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_imm16_sh2(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int)(0xfffc0000 | word);
	}
	AMD29K_SET_VALUE(instruction, 0, word, AMD29K_TYPE_JMP);
	AMD29K_SET_INVALID(instruction, 1);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_load_store(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, ((buffer[1] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 1, (buffer[1] & 0x7F), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 2, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 3, buffer[3], AMD29K_HAS_BIT(buffer) ? AMD29K_TYPE_IMM : AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_calli(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_rc_ra_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 2, (buffer[3] & 3), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_clz(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[3], AMD29K_HAS_BIT(buffer) ? AMD29K_TYPE_IMM : AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_convert(amd29k_instr_t *instruction, const ut8 *buffer) {
	// lambda w,ea: (w >> 24,[decode_byte1(w), decode_byte2(w), ('imm',False,(w&0x80)>>7), ('imm',False,(w&0x70)>>4), ('imm',False,(w&0xC)>>2), ('imm',False, w&3)])
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 2, ((buffer[3] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 3, ((buffer[3] & 0x70) >> 4), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 4, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 5, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
}

static void decode_rc_ra(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_dmac_fmac(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, ((buffer[1] & 0x3c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 1, (buffer[1] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 2, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 3, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_ra_rb(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_rb(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 1);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_rc_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_ra_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE(instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_mfsr(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_mtsr(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE(instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE(instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

static void decode_none(amd29k_instr_t *instruction, const ut8 *buffer) {
	// lambda w,ea: (w >> 24, None)
	AMD29K_SET_INVALID(instruction, 0);
	AMD29K_SET_INVALID(instruction, 1);
	AMD29K_SET_INVALID(instruction, 2);
	AMD29K_SET_INVALID(instruction, 3);
	AMD29K_SET_INVALID(instruction, 4);
	AMD29K_SET_INVALID(instruction, 5);
}

const amd29k_instruction_t amd29k_instructions[N_AMD29K_INSTRUCTIONS] = {
	{ AMD29K_29000, "illegal", RZ_ANALYSIS_OP_TYPE_NULL, 0x00, decode_none, NULL },
	{ AMD29K_29000, "add", RZ_ANALYSIS_OP_TYPE_ADD, 0x14, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "add", RZ_ANALYSIS_OP_TYPE_ADD, 0x15, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addc", RZ_ANALYSIS_OP_TYPE_ADD, 0x1C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addc", RZ_ANALYSIS_OP_TYPE_ADD, 0x1D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addcs", RZ_ANALYSIS_OP_TYPE_ADD, 0x18, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addcs", RZ_ANALYSIS_OP_TYPE_ADD, 0x19, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addcu", RZ_ANALYSIS_OP_TYPE_ADD, 0x1A, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "addcu", RZ_ANALYSIS_OP_TYPE_ADD, 0x1B, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "adds", RZ_ANALYSIS_OP_TYPE_ADD, 0x10, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "adds", RZ_ANALYSIS_OP_TYPE_ADD, 0x11, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "addu", RZ_ANALYSIS_OP_TYPE_ADD, 0x12, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "addu", RZ_ANALYSIS_OP_TYPE_ADD, 0x13, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "and", RZ_ANALYSIS_OP_TYPE_AND, 0x90, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "and", RZ_ANALYSIS_OP_TYPE_AND, 0x91, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "andn", RZ_ANALYSIS_OP_TYPE_AND, 0x9C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "andn", RZ_ANALYSIS_OP_TYPE_AND, 0x9D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "aseq", RZ_ANALYSIS_OP_TYPE_CMP, 0x70, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asge", RZ_ANALYSIS_OP_TYPE_CMP, 0x5C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asge", RZ_ANALYSIS_OP_TYPE_CMP, 0x5D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asgeu", RZ_ANALYSIS_OP_TYPE_CMP, 0x5E, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asgeu", RZ_ANALYSIS_OP_TYPE_CMP, 0x5F, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asgt", RZ_ANALYSIS_OP_TYPE_CMP, 0x58, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asgt", RZ_ANALYSIS_OP_TYPE_CMP, 0x59, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asgtu", RZ_ANALYSIS_OP_TYPE_CMP, 0x5A, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asgtu", RZ_ANALYSIS_OP_TYPE_CMP, 0x5B, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asle", RZ_ANALYSIS_OP_TYPE_CMP, 0x54, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asle", RZ_ANALYSIS_OP_TYPE_CMP, 0x55, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asleu", RZ_ANALYSIS_OP_TYPE_CMP, 0x56, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asleu", RZ_ANALYSIS_OP_TYPE_CMP, 0x57, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "aslt", RZ_ANALYSIS_OP_TYPE_CMP, 0x50, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "aslt", RZ_ANALYSIS_OP_TYPE_CMP, 0x51, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asltu", RZ_ANALYSIS_OP_TYPE_CMP, 0x52, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asltu", RZ_ANALYSIS_OP_TYPE_CMP, 0x53, decode_imm_rb_rci, NULL },
	{ AMD29K_29000, "asneq", RZ_ANALYSIS_OP_TYPE_CMP, 0x72, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "asneq", RZ_ANALYSIS_OP_TYPE_CMP, 0x73, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "call", RZ_ANALYSIS_OP_TYPE_CALL, 0xA8, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "call", RZ_ANALYSIS_OP_TYPE_CALL, 0xA9, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "calli", RZ_ANALYSIS_OP_TYPE_ICALL, 0xC8, decode_calli, NULL },
	{ AMD29K_29050, "class", RZ_ANALYSIS_OP_TYPE_NULL, 0xE6, decode_rc_ra_imm, NULL },
	{ AMD29K_29000, "clz", RZ_ANALYSIS_OP_TYPE_NULL, 0x08, decode_clz, NULL },
	{ AMD29K_29000, "clz", RZ_ANALYSIS_OP_TYPE_NULL, 0x09, decode_clz, NULL },
	{ AMD29K_29000, "const", RZ_ANALYSIS_OP_TYPE_MOV, 0x03, decode_ra_imm16, NULL },
	{ AMD29K_29000, "consth", RZ_ANALYSIS_OP_TYPE_MOV, 0x02, decode_ra_imm16, NULL },
	{ AMD29K_29000, "consthz", RZ_ANALYSIS_OP_TYPE_MOV, 0x05, decode_ra_imm16, NULL },
	{ AMD29K_29000, "constn", RZ_ANALYSIS_OP_TYPE_MOV, 0x01, decode_ra_imm16, NULL },
	{ AMD29K_29050, "convert", RZ_ANALYSIS_OP_TYPE_NULL, 0xE4, decode_convert, NULL },
	{ AMD29K_29000, "cpbyte", RZ_ANALYSIS_OP_TYPE_CMP, 0x2E, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpbyte", RZ_ANALYSIS_OP_TYPE_CMP, 0x2F, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpeq", RZ_ANALYSIS_OP_TYPE_CMP, 0x60, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpeq", RZ_ANALYSIS_OP_TYPE_CMP, 0x61, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpge", RZ_ANALYSIS_OP_TYPE_CMP, 0x4C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpge", RZ_ANALYSIS_OP_TYPE_CMP, 0x4D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgeu", RZ_ANALYSIS_OP_TYPE_CMP, 0x4E, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgeu", RZ_ANALYSIS_OP_TYPE_CMP, 0x4F, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgt", RZ_ANALYSIS_OP_TYPE_CMP, 0x48, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgt", RZ_ANALYSIS_OP_TYPE_CMP, 0x49, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgtu", RZ_ANALYSIS_OP_TYPE_CMP, 0x4A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpgtu", RZ_ANALYSIS_OP_TYPE_CMP, 0x4B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cple", RZ_ANALYSIS_OP_TYPE_CMP, 0x44, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cple", RZ_ANALYSIS_OP_TYPE_CMP, 0x45, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpleu", RZ_ANALYSIS_OP_TYPE_CMP, 0x46, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpleu", RZ_ANALYSIS_OP_TYPE_CMP, 0x47, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cplt", RZ_ANALYSIS_OP_TYPE_CMP, 0x40, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cplt", RZ_ANALYSIS_OP_TYPE_CMP, 0x41, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpltu", RZ_ANALYSIS_OP_TYPE_CMP, 0x42, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpltu", RZ_ANALYSIS_OP_TYPE_CMP, 0x43, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpneq", RZ_ANALYSIS_OP_TYPE_CMP, 0x62, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cpneq", RZ_ANALYSIS_OP_TYPE_CMP, 0x63, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "cvdf", RZ_ANALYSIS_OP_TYPE_NULL, 0xE9, decode_rc_ra, NULL },
	{ AMD29K_29000, "cvdint", RZ_ANALYSIS_OP_TYPE_NULL, 0xE7, decode_rc_ra, NULL },
	{ AMD29K_29000, "cvfd", RZ_ANALYSIS_OP_TYPE_NULL, 0xE8, decode_rc_ra, NULL },
	{ AMD29K_29000, "cvfint", RZ_ANALYSIS_OP_TYPE_NULL, 0xE6, decode_rc_ra, NULL },
	{ AMD29K_29000, "cvintd", RZ_ANALYSIS_OP_TYPE_NULL, 0xE5, decode_rc_ra, NULL },
	{ AMD29K_29000, "cvintf", RZ_ANALYSIS_OP_TYPE_NULL, 0xE4, decode_rc_ra, NULL },
	{ AMD29K_29000, "dadd", RZ_ANALYSIS_OP_TYPE_NULL, 0xF1, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "ddiv", RZ_ANALYSIS_OP_TYPE_DIV, 0xF7, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "deq", RZ_ANALYSIS_OP_TYPE_CMP, 0xEB, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "dge", RZ_ANALYSIS_OP_TYPE_CMP, 0xEF, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "dgt", RZ_ANALYSIS_OP_TYPE_CMP, 0xED, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "div", RZ_ANALYSIS_OP_TYPE_DIV, 0x6A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "div", RZ_ANALYSIS_OP_TYPE_DIV, 0x6B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "div0", RZ_ANALYSIS_OP_TYPE_DIV, 0x68, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "div0", RZ_ANALYSIS_OP_TYPE_DIV, 0x69, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "divide", RZ_ANALYSIS_OP_TYPE_DIV, 0xE1, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "dividu", RZ_ANALYSIS_OP_TYPE_DIV, 0xE3, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "divl", RZ_ANALYSIS_OP_TYPE_DIV, 0x6C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "divl", RZ_ANALYSIS_OP_TYPE_DIV, 0x6D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "divrem", RZ_ANALYSIS_OP_TYPE_DIV, 0x6E, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "divrem", RZ_ANALYSIS_OP_TYPE_DIV, 0x6F, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "dlt", RZ_ANALYSIS_OP_TYPE_CMP, 0xEF, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "dmac", RZ_ANALYSIS_OP_TYPE_NULL, 0xD9, decode_dmac_fmac, NULL },
	{ AMD29K_29050, "dmsm", RZ_ANALYSIS_OP_TYPE_NULL, 0xDB, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "dmul", RZ_ANALYSIS_OP_TYPE_MUL, 0xF5, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "dsub", RZ_ANALYSIS_OP_TYPE_SUB, 0xF3, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "emulate", RZ_ANALYSIS_OP_TYPE_NULL, 0xF8, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "exbyte", RZ_ANALYSIS_OP_TYPE_NULL, 0x0A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "exbyte", RZ_ANALYSIS_OP_TYPE_NULL, 0x0B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "exhw", RZ_ANALYSIS_OP_TYPE_NULL, 0x7C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "exhw", RZ_ANALYSIS_OP_TYPE_NULL, 0x7D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "exhws", RZ_ANALYSIS_OP_TYPE_NULL, 0x7E, decode_rc_ra, NULL },
	{ AMD29K_29000, "extract", RZ_ANALYSIS_OP_TYPE_NULL, 0x7A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "extract", RZ_ANALYSIS_OP_TYPE_NULL, 0x7B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "fadd", RZ_ANALYSIS_OP_TYPE_ADD, 0xF0, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "fdiv", RZ_ANALYSIS_OP_TYPE_DIV, 0xF6, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "fdmul", RZ_ANALYSIS_OP_TYPE_MUL, 0xF9, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "feq", RZ_ANALYSIS_OP_TYPE_CMP, 0xEA, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "fge", RZ_ANALYSIS_OP_TYPE_CMP, 0xEE, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "fgt", RZ_ANALYSIS_OP_TYPE_CMP, 0xEC, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "flt", RZ_ANALYSIS_OP_TYPE_CMP, 0xEE, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "fmac", RZ_ANALYSIS_OP_TYPE_NULL, 0xD8, decode_dmac_fmac, NULL },
	{ AMD29K_29050, "fmsm", RZ_ANALYSIS_OP_TYPE_NULL, 0xDA, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "fmul", RZ_ANALYSIS_OP_TYPE_MUL, 0xF4, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "fsub", RZ_ANALYSIS_OP_TYPE_SUB, 0xF2, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "halt", RZ_ANALYSIS_OP_TYPE_RET, 0x89, decode_none, NULL },
	{ AMD29K_29000, "inbyte", RZ_ANALYSIS_OP_TYPE_NULL, 0x0C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "inbyte", RZ_ANALYSIS_OP_TYPE_NULL, 0x0D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "inhw", RZ_ANALYSIS_OP_TYPE_NULL, 0x78, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "inhw", RZ_ANALYSIS_OP_TYPE_NULL, 0x79, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "inv", RZ_ANALYSIS_OP_TYPE_NULL, 0x9F, decode_none, NULL },
	{ AMD29K_29000, "iret", RZ_ANALYSIS_OP_TYPE_RET, 0x88, decode_none, NULL },
	{ AMD29K_29000, "iretinv", RZ_ANALYSIS_OP_TYPE_RET, 0x8C, decode_none, NULL },
	{ AMD29K_29000, "jmp", RZ_ANALYSIS_OP_TYPE_JMP, 0xA0, decode_imm16_sh2, NULL },
	{ AMD29K_29000, "jmp", RZ_ANALYSIS_OP_TYPE_JMP, 0xA1, decode_imm16_sh2, NULL },
	{ AMD29K_29000, "jmpf", RZ_ANALYSIS_OP_TYPE_CJMP, 0xA4, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "jmpf", RZ_ANALYSIS_OP_TYPE_CJMP, 0xA5, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "jmpfdec", RZ_ANALYSIS_OP_TYPE_CJMP, 0xB4, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "jmpfdec", RZ_ANALYSIS_OP_TYPE_CJMP, 0xB5, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "jmpfi", RZ_ANALYSIS_OP_TYPE_RCJMP, 0xC4, decode_ra_rb, NULL },
	{ AMD29K_29000, "jmpi", RZ_ANALYSIS_OP_TYPE_RJMP, 0xC0, decode_rb, NULL },
	{ AMD29K_29000, "jmpt", RZ_ANALYSIS_OP_TYPE_CJMP, 0xAC, decode_ra_i16_sh2, NULL },
	{ AMD29K_29000, "jmpti", RZ_ANALYSIS_OP_TYPE_RCJMP, 0xCC, decode_ra_rb, NULL },
	{ AMD29K_29050, "mfacc", RZ_ANALYSIS_OP_TYPE_NULL, 0xE9, decode_rc_imm, NULL },
	{ AMD29K_29050, "mtacc", RZ_ANALYSIS_OP_TYPE_NULL, 0xE8, decode_ra_imm, NULL },
	{ AMD29K_29000, "mfsr", RZ_ANALYSIS_OP_TYPE_NULL, 0xC6, decode_mfsr, NULL },
	{ AMD29K_29000, "mftlb", RZ_ANALYSIS_OP_TYPE_NULL, 0xB6, decode_rc_ra, NULL },
	{ AMD29K_29000, "mtsr", RZ_ANALYSIS_OP_TYPE_NULL, 0xCE, decode_mtsr, NULL },
	{ AMD29K_29000, "mtsrim", RZ_ANALYSIS_OP_TYPE_NULL, 0x04, decode_ra_imm16, NULL },
	{ AMD29K_29000, "mttlb", RZ_ANALYSIS_OP_TYPE_NULL, 0xBE, decode_ra_rb, NULL },
	{ AMD29K_29000, "mul", RZ_ANALYSIS_OP_TYPE_MUL, 0x64, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "mul", RZ_ANALYSIS_OP_TYPE_MUL, 0x65, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "mull", RZ_ANALYSIS_OP_TYPE_MUL, 0x66, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "mull", RZ_ANALYSIS_OP_TYPE_MUL, 0x67, decode_ra_rb_rci, NULL },
	{ AMD29K_29050, "multiplu", RZ_ANALYSIS_OP_TYPE_MUL, 0xE2, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "multiply", RZ_ANALYSIS_OP_TYPE_MUL, 0xE0, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "multm", RZ_ANALYSIS_OP_TYPE_MUL, 0xDE, decode_ra_rb_rc, NULL },
	{ AMD29K_29050, "multmu", RZ_ANALYSIS_OP_TYPE_MUL, 0xDF, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "mulu", RZ_ANALYSIS_OP_TYPE_MUL, 0x74, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "mulu", RZ_ANALYSIS_OP_TYPE_MUL, 0x75, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "nand", RZ_ANALYSIS_OP_TYPE_AND, 0x9A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "nand", RZ_ANALYSIS_OP_TYPE_AND, 0x9B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "nor", RZ_ANALYSIS_OP_TYPE_NOR, 0x98, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "nor", RZ_ANALYSIS_OP_TYPE_NOR, 0x99, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "or", RZ_ANALYSIS_OP_TYPE_OR, 0x92, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "or", RZ_ANALYSIS_OP_TYPE_OR, 0x93, decode_ra_rb_rci, NULL },
	{ AMD29K_29050, "orn", RZ_ANALYSIS_OP_TYPE_OR, 0xAA, decode_ra_rb_rci, NULL },
	{ AMD29K_29050, "orn", RZ_ANALYSIS_OP_TYPE_OR, 0xAB, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "setip", RZ_ANALYSIS_OP_TYPE_NULL, 0x9E, decode_ra_rb_rc, NULL },
	{ AMD29K_29000, "sll", RZ_ANALYSIS_OP_TYPE_SHL, 0x80, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "sll", RZ_ANALYSIS_OP_TYPE_SHL, 0x81, decode_ra_rb_rci, NULL },
	{ AMD29K_29050, "sqrt", RZ_ANALYSIS_OP_TYPE_NULL, 0xE5, decode_rc_ra_imm, NULL },
	{ AMD29K_29000, "sra", RZ_ANALYSIS_OP_TYPE_SHR, 0x86, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "sra", RZ_ANALYSIS_OP_TYPE_SHR, 0x87, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "srl", RZ_ANALYSIS_OP_TYPE_SAL, 0x82, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "srl", RZ_ANALYSIS_OP_TYPE_SAL, 0x83, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "load", RZ_ANALYSIS_OP_TYPE_LOAD, 0x16, decode_load_store, NULL },
	{ AMD29K_29000, "load", RZ_ANALYSIS_OP_TYPE_LOAD, 0x17, decode_load_store, NULL },
	{ AMD29K_29000, "loadl", RZ_ANALYSIS_OP_TYPE_LOAD, 0x06, decode_load_store, NULL },
	{ AMD29K_29000, "loadl", RZ_ANALYSIS_OP_TYPE_LOAD, 0x07, decode_load_store, NULL },
	{ AMD29K_29000, "loadm", RZ_ANALYSIS_OP_TYPE_LOAD, 0x36, decode_load_store, NULL },
	{ AMD29K_29000, "loadm", RZ_ANALYSIS_OP_TYPE_LOAD, 0x37, decode_load_store, NULL },
	{ AMD29K_29000, "loadset", RZ_ANALYSIS_OP_TYPE_LOAD, 0x26, decode_load_store, NULL },
	{ AMD29K_29000, "loadset", RZ_ANALYSIS_OP_TYPE_LOAD, 0x27, decode_load_store, NULL },
	{ AMD29K_29000, "store", RZ_ANALYSIS_OP_TYPE_STORE, 0x1E, decode_load_store, NULL },
	{ AMD29K_29000, "store", RZ_ANALYSIS_OP_TYPE_STORE, 0x1F, decode_load_store, NULL },
	{ AMD29K_29000, "storel", RZ_ANALYSIS_OP_TYPE_STORE, 0x0E, decode_load_store, NULL },
	{ AMD29K_29000, "storel", RZ_ANALYSIS_OP_TYPE_STORE, 0x0F, decode_load_store, NULL },
	{ AMD29K_29000, "storem", RZ_ANALYSIS_OP_TYPE_STORE, 0x3E, decode_load_store, NULL },
	{ AMD29K_29000, "storem", RZ_ANALYSIS_OP_TYPE_STORE, 0x3F, decode_load_store, NULL },
	{ AMD29K_29000, "sub", RZ_ANALYSIS_OP_TYPE_SUB, 0x24, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "sub", RZ_ANALYSIS_OP_TYPE_SUB, 0x25, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subc", RZ_ANALYSIS_OP_TYPE_SUB, 0x2C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subc", RZ_ANALYSIS_OP_TYPE_SUB, 0x2D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subcs", RZ_ANALYSIS_OP_TYPE_SUB, 0x28, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subcs", RZ_ANALYSIS_OP_TYPE_SUB, 0x29, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subcu", RZ_ANALYSIS_OP_TYPE_SUB, 0x2A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subcu", RZ_ANALYSIS_OP_TYPE_SUB, 0x2B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subr", RZ_ANALYSIS_OP_TYPE_SUB, 0x34, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subr", RZ_ANALYSIS_OP_TYPE_SUB, 0x35, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrc", RZ_ANALYSIS_OP_TYPE_SUB, 0x3C, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrc", RZ_ANALYSIS_OP_TYPE_SUB, 0x3D, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrcs", RZ_ANALYSIS_OP_TYPE_SUB, 0x38, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrcs", RZ_ANALYSIS_OP_TYPE_SUB, 0x39, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrcu", RZ_ANALYSIS_OP_TYPE_SUB, 0x3A, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrcu", RZ_ANALYSIS_OP_TYPE_SUB, 0x3B, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrs", RZ_ANALYSIS_OP_TYPE_SUB, 0x30, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subrs", RZ_ANALYSIS_OP_TYPE_SUB, 0x31, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subru", RZ_ANALYSIS_OP_TYPE_SUB, 0x32, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subru", RZ_ANALYSIS_OP_TYPE_SUB, 0x33, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subs", RZ_ANALYSIS_OP_TYPE_SUB, 0x20, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subs", RZ_ANALYSIS_OP_TYPE_SUB, 0x21, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subu", RZ_ANALYSIS_OP_TYPE_SUB, 0x22, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "subu", RZ_ANALYSIS_OP_TYPE_SUB, 0x23, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "xnor", RZ_ANALYSIS_OP_TYPE_XOR, 0x96, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "xnor", RZ_ANALYSIS_OP_TYPE_XOR, 0x97, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "xor", RZ_ANALYSIS_OP_TYPE_XOR, 0x94, decode_ra_rb_rci, NULL },
	{ AMD29K_29000, "xor", RZ_ANALYSIS_OP_TYPE_XOR, 0x95, decode_ra_rb_rci, NULL },
};

bool amd29k_instr_decode(const ut8 *buffer, const ut32 buffer_size, amd29k_instr_t *instruction, const ut32 cpu_id) {
	if (!buffer || buffer_size < 4 || !instruction) {
		return false;
	}

	if (buffer[0] == 0x70 && buffer[1] == 0x40 && buffer[2] == 0x01 && buffer[3] == 0x01) {
		decode_none(instruction, buffer);
		instruction->mnemonic = "nop";
		instruction->op_type = RZ_ANALYSIS_OP_TYPE_NOP;
		return true;
	}

	for (size_t i = 0; i < N_AMD29K_INSTRUCTIONS; i++) {
		const amd29k_instruction_t *in = &amd29k_instructions[i];
		if (in->cpu > cpu_id || in->mask != buffer[0]) {
			continue;
		}

		in->decode(instruction, buffer);
		instruction->mnemonic = in->mnemonic;
		instruction->op_type = in->op_type;
		return true;
	}

	return false;
}

static const char *amd29k_get_regname(int reg) {
	if (reg < 0 || reg >= RZ_ARRAY_SIZE(amd29k_reg_names)) {
		return "?";
	}
	return amd29k_reg_names[reg];
}

bool amd29k_instr_is_ret(amd29k_instr_t *instruction) {
	if (!instruction) {
		return false;
	} else if (!strcmp(instruction->mnemonic, "calli")) {
		return AMD29K_GET_VALUE(instruction, 0) == AMD29K_REG_LR0;
	} else if (!strcmp(instruction->mnemonic, "jmpi")) {
		return AMD29K_GET_VALUE(instruction, 0) == AMD29K_REG_LR0;
	}
	return false;
}

ut64 amd29k_instr_jump(amd29k_instr_t *instruction, ut64 address) {
	if (!instruction) {
		return UT64_MAX;
	}

	int type = AMD29K_GET_TYPE(instruction, 0);
	if (type == AMD29K_TYPE_JMP) {
		return address + AMD29K_GET_VALUE(instruction, 0);
	}

	type = AMD29K_GET_TYPE(instruction, 1);
	if (type == AMD29K_TYPE_JMP) {
		return address + AMD29K_GET_VALUE(instruction, 1);
	}

	return UT64_MAX;
}

static void amd29k_opex_add_reg(RzStructuredData *operands, int reg) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "reg");
	rz_structured_data_map_add_string(operand, "value", amd29k_get_regname(reg));
}

static void amd29k_opex_add_signed(RzStructuredData *operands, st64 imm) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "imm");
	rz_structured_data_map_add_signed(operand, "value", imm);
}

static void amd29k_opex_add_unsigned(RzStructuredData *operands, ut64 imm) {
	RzStructuredData *operand = rz_structured_data_array_add_map(operands);
	rz_structured_data_map_add_string(operand, "type", "imm");
	rz_structured_data_map_add_unsigned(operand, "value", imm, false);
}

RzStructuredData *amd29k_instr_opex(amd29k_instr_t *instruction, ut64 address) {
	if (!instruction) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	for (size_t i = 0; i < AMD29K_MAX_OPERANDS; ++i) {
		int type = AMD29K_GET_TYPE(instruction, i);
		int value = AMD29K_GET_VALUE(instruction, i);

		switch (type) {
		case AMD29K_TYPE_REG:
			amd29k_opex_add_reg(operands, value);
			break;
		case AMD29K_TYPE_IMM:
			amd29k_opex_add_signed(operands, value);
			break;
		case AMD29K_TYPE_JMP:
			amd29k_opex_add_unsigned(operands, address + value);
			break;
		default:
			return root;
		}
	}

	return root;
}

void amd29k_instr_print(amd29k_instr_t *instruction, ut64 address, RzStrBuf *sb) {
	if (!instruction || !sb) {
		return;
	}

	rz_strbuf_set(sb, instruction->mnemonic);
	for (size_t i = 0; i < AMD29K_MAX_OPERANDS; ++i) {
		int type = AMD29K_GET_TYPE(instruction, i);
		int value = AMD29K_GET_VALUE(instruction, i);

		switch (type) {
		case AMD29K_TYPE_REG: {
			const char *reg0 = amd29k_get_regname(value);
			rz_strbuf_appendf(sb, " %s", reg0);
			break;
		}
		case AMD29K_TYPE_IMM: {
			if (value >= 0) {
				rz_strbuf_appendf(sb, " 0x%x", value);
			} else {
				value = 0 - value;
				rz_strbuf_appendf(sb, " -0x%x", value);
			}
			break;
		}
		case AMD29K_TYPE_JMP: {
			ut64 jump = address + value;
			rz_strbuf_appendf(sb, " 0x%" PFMT64x, jump);
			break;
		}
		default:
			return;
		}
	}
}
