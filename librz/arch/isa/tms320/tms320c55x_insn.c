// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_analysis.h>

#include "tms320c55x_insn.h"

/* Mnemonic strings indexed by TMS320C55InsID. Keep in sync with the enum
 * in tms320c55x_insn.h. */
static const char *const tms320c55x_insn_names[] = {
	[TMS320C55_INS_INVALID] = "invalid",
	[TMS320C55_INS_AADD] = "aadd",
	[TMS320C55_INS_ABDST] = "abdst",
	[TMS320C55_INS_ABS] = "abs",
	[TMS320C55_INS_ADD] = "add",
	[TMS320C55_INS_ADDV] = "addv",
	[TMS320C55_INS_ADDRV] = "addrv",
	[TMS320C55_INS_ADDSUB] = "addsub",
	[TMS320C55_INS_ADDSUB2CC] = "addsub2cc",
	[TMS320C55_INS_ADDSUBCC] = "addsubcc",
	[TMS320C55_INS_AMAR] = "amar",
	[TMS320C55_INS_AMOV] = "amov",
	[TMS320C55_INS_AND] = "and",
	[TMS320C55_INS_ASUB] = "asub",
	[TMS320C55_INS_B] = "b",
	[TMS320C55_INS_BAND] = "band",
	[TMS320C55_INS_BCC] = "bcc",
	[TMS320C55_INS_BCLR] = "bclr",
	[TMS320C55_INS_BCNT] = "bcnt",
	[TMS320C55_INS_BFXPA] = "bfxpa",
	[TMS320C55_INS_BFXTR] = "bfxtr",
	[TMS320C55_INS_BNOT] = "bnot",
	[TMS320C55_INS_BSET] = "bset",
	[TMS320C55_INS_BTST] = "btst",
	[TMS320C55_INS_BTSTCLR] = "btstclr",
	[TMS320C55_INS_BTSTNOT] = "btstnot",
	[TMS320C55_INS_BTSTP] = "btstp",
	[TMS320C55_INS_BTSTSET] = "btstset",
	[TMS320C55_INS_CALL] = "call",
	[TMS320C55_INS_CALLCC] = "callcc",
	[TMS320C55_INS_CIRC] = "circ",
	[TMS320C55_INS_CMP] = "cmp",
	[TMS320C55_INS_CMPAND] = "cmpand",
	[TMS320C55_INS_CMPOR] = "cmpor",
	[TMS320C55_INS_COPY] = "copy",
	[TMS320C55_INS_SWAPP] = "swapp",
	[TMS320C55_INS_SWAP4] = "swap4",
	[TMS320C55_INS_DELAY] = "delay",
	[TMS320C55_INS_DMAXDIFF] = "dmaxdiff",
	[TMS320C55_INS_DMINDIFF] = "dmindiff",
	[TMS320C55_INS_EXP] = "exp",
	[TMS320C55_INS_FIRSADD] = "firsadd",
	[TMS320C55_INS_FIRSSUB] = "firssub",
	[TMS320C55_INS_IDLE] = "idle",
	[TMS320C55_INS_INTR] = "intr",
	[TMS320C55_INS_LMS] = "lms",
	[TMS320C55_INS_LMSF] = "lmsf",
	[TMS320C55_INS_MAC] = "mac",
	[TMS320C55_INS_MACK] = "mack",
	[TMS320C55_INS_MACM] = "macm",
	[TMS320C55_INS_MACMK] = "macmk",
	[TMS320C55_INS_MANT] = "mant",
	[TMS320C55_INS_MAS] = "mas",
	[TMS320C55_INS_MASM] = "masm",
	[TMS320C55_INS_MAX] = "max",
	[TMS320C55_INS_MAXDIFF] = "maxdiff",
	[TMS320C55_INS_MIN] = "min",
	[TMS320C55_INS_MINDIFF] = "mindiff",
	[TMS320C55_INS_MOV] = "mov",
	[TMS320C55_INS_MPY] = "mpy",
	[TMS320C55_INS_MPYK] = "mpyk",
	[TMS320C55_INS_MPYM] = "mpym",
	[TMS320C55_INS_MPYMK] = "mpymk",
	[TMS320C55_INS_NEG] = "neg",
	[TMS320C55_INS_NOP] = "nop",
	[TMS320C55_INS_NOP_16] = "nop_16",
	[TMS320C55_INS_ESTOP] = "estop",
	[TMS320C55_INS_ECOPR] = "ecopr",
	[TMS320C55_INS_NOT] = "not",
	[TMS320C55_INS_OR] = "or",
	[TMS320C55_INS_POP] = "pop",
	[TMS320C55_INS_POPBOTH] = "popboth",
	[TMS320C55_INS_PSH] = "psh",
	[TMS320C55_INS_PSHBOTH] = "pshboth",
	[TMS320C55_INS_RESET] = "reset",
	[TMS320C55_INS_RET] = "ret",
	[TMS320C55_INS_RETCC] = "retcc",
	[TMS320C55_INS_RETI] = "reti",
	[TMS320C55_INS_ROL] = "rol",
	[TMS320C55_INS_ROR] = "ror",
	[TMS320C55_INS_ROUND] = "round",
	[TMS320C55_INS_RPT] = "rpt",
	[TMS320C55_INS_RPTADD] = "rptadd",
	[TMS320C55_INS_RPTB] = "rptb",
	[TMS320C55_INS_RPTBLOCAL] = "rptblocal",
	[TMS320C55_INS_RPTCC] = "rptcc",
	[TMS320C55_INS_RPTSUB] = "rptsub",
	[TMS320C55_INS_SAT] = "sat",
	[TMS320C55_INS_SFTCC] = "sftcc",
	[TMS320C55_INS_SFTL] = "sftl",
	[TMS320C55_INS_SFTS] = "sfts",
	[TMS320C55_INS_SFTSC] = "sftsc",
	[TMS320C55_INS_SIM_TRIG] = "sim_trig",
	[TMS320C55_INS_SQA] = "sqa",
	[TMS320C55_INS_SQAM] = "sqam",
	[TMS320C55_INS_SQDST] = "sqdst",
	[TMS320C55_INS_SQR] = "sqr",
	[TMS320C55_INS_SQRM] = "sqrm",
	[TMS320C55_INS_SQS] = "sqs",
	[TMS320C55_INS_SQSM] = "sqsm",
	[TMS320C55_INS_SUB] = "sub",
	[TMS320C55_INS_SUBADD] = "subadd",
	[TMS320C55_INS_SUBC] = "subc",
	[TMS320C55_INS_SWAP] = "swap",
	[TMS320C55_INS_TRAP] = "trap",
	[TMS320C55_INS_XCC] = "xcc",
	[TMS320C55_INS_XCCPART] = "xccpart",
	[TMS320C55_INS_XOR] = "xor",
};

RZ_API const char *tms320c55x_insn_name(TMS320C55InsID id) {
	if ((size_t)id < (sizeof(tms320c55x_insn_names) / sizeof(tms320c55x_insn_names[0])) && tms320c55x_insn_names[id]) {
		return tms320c55x_insn_names[id];
	}
	return "invalid";
}

RZ_API TMS320C55InsID tms320c55x_insn_id_from_syntax(const char *syntax) {
	if (!syntax) {
		return TMS320C55_INS_INVALID;
	}
	/* Skip leading spaces and an optional C55x+ parallel marker. */
	const char *p = syntax;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	if (p[0] == '|' && p[1] == '|') {
		p += 2;
		while (*p == ' ' || *p == '\t') {
			p++;
		}
	}
	/* Extract the leading mnemonic token (lowercase letters, digits, _). */
	char tok[32];
	size_t n = 0;
	while (n < sizeof(tok) - 1 && ((p[n] >= 'a' && p[n] <= 'z') || (p[n] >= '0' && p[n] <= '9') || p[n] == '_')) {
		tok[n] = p[n];
		n++;
	}
	tok[n] = '\0';
	if (n == 0) {
		return TMS320C55_INS_INVALID;
	}
	for (size_t i = 1; i < (sizeof(tms320c55x_insn_names) / sizeof(tms320c55x_insn_names[0])); i++) {
		if (tms320c55x_insn_names[i] && !strcmp(tms320c55x_insn_names[i], tok)) {
			return (TMS320C55InsID)i;
		}
	}
	return TMS320C55_INS_INVALID;
}

RZ_API int tms320c55x_insn_optype(TMS320C55InsID id) {
	switch (id) {
	case TMS320C55_INS_ADD:
	case TMS320C55_INS_AADD:
	case TMS320C55_INS_ADDSUB:
	case TMS320C55_INS_ADDSUBCC:
	case TMS320C55_INS_ADDSUB2CC:
	case TMS320C55_INS_SUBADD:
		return RZ_ANALYSIS_OP_TYPE_ADD;
	case TMS320C55_INS_SUB:
	case TMS320C55_INS_SUBC:
	case TMS320C55_INS_NEG:
		return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_AND:
	case TMS320C55_INS_BAND:
	case TMS320C55_INS_BTST:
	case TMS320C55_INS_BTSTCLR:
	case TMS320C55_INS_BTSTNOT:
	case TMS320C55_INS_BTSTP:
	case TMS320C55_INS_BTSTSET:
		return RZ_ANALYSIS_OP_TYPE_AND;
	case TMS320C55_INS_OR:
	case TMS320C55_INS_CMPOR:
		return RZ_ANALYSIS_OP_TYPE_OR;
	case TMS320C55_INS_XOR:
		return RZ_ANALYSIS_OP_TYPE_XOR;
	case TMS320C55_INS_NOT:
	case TMS320C55_INS_BNOT:
		return RZ_ANALYSIS_OP_TYPE_NOT;
	case TMS320C55_INS_MOV:
	case TMS320C55_INS_DELAY:
	case TMS320C55_INS_BFXTR:
	case TMS320C55_INS_BFXPA:
	case TMS320C55_INS_BSET:
	case TMS320C55_INS_BCLR:
	case TMS320C55_INS_ROUND:
	case TMS320C55_INS_EXP:
	case TMS320C55_INS_MANT:
	case TMS320C55_INS_BCNT:
	case TMS320C55_INS_CIRC:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_MPY:
	case TMS320C55_INS_MPYK:
	case TMS320C55_INS_MPYM:
	case TMS320C55_INS_MPYMK:
	case TMS320C55_INS_MAC:
	case TMS320C55_INS_MACK:
	case TMS320C55_INS_MACM:
	case TMS320C55_INS_MACMK:
	case TMS320C55_INS_MAS:
	case TMS320C55_INS_MASM:
	case TMS320C55_INS_SQA:
	case TMS320C55_INS_SQAM:
	case TMS320C55_INS_SQR:
	case TMS320C55_INS_SQRM:
	case TMS320C55_INS_SQS:
	case TMS320C55_INS_SQSM:
	case TMS320C55_INS_SQDST:
	case TMS320C55_INS_LMS:
	case TMS320C55_INS_LMSF:
	case TMS320C55_INS_FIRSADD:
	case TMS320C55_INS_FIRSSUB:
		return RZ_ANALYSIS_OP_TYPE_MUL;
	case TMS320C55_INS_SFTL:
	case TMS320C55_INS_SFTS:
	case TMS320C55_INS_SFTSC:
	case TMS320C55_INS_SFTCC:
		return RZ_ANALYSIS_OP_TYPE_SHL;
	case TMS320C55_INS_ROL:
		return RZ_ANALYSIS_OP_TYPE_ROL;
	case TMS320C55_INS_ROR:
		return RZ_ANALYSIS_OP_TYPE_ROR;
	case TMS320C55_INS_CMP:
	case TMS320C55_INS_CMPAND:
	case TMS320C55_INS_MAX:
	case TMS320C55_INS_MIN:
	case TMS320C55_INS_MAXDIFF:
	case TMS320C55_INS_MINDIFF:
	case TMS320C55_INS_DMAXDIFF:
	case TMS320C55_INS_DMINDIFF:
		return RZ_ANALYSIS_OP_TYPE_CMP;
	case TMS320C55_INS_AMOV:
	case TMS320C55_INS_AMAR:
	case TMS320C55_INS_ASUB:
		return RZ_ANALYSIS_OP_TYPE_LEA;
	case TMS320C55_INS_SWAP:
		return RZ_ANALYSIS_OP_TYPE_XCHG;
	/* ABS is intentionally NOT mapped: although RZ_ANALYSIS_OP_TYPE_ABS
	 * exists as an enum value, rizin renders it as "undefined", which is
	 * worse than leaving the op at NULL. Keep it NULL. */
	case TMS320C55_INS_ABDST:
		/* Absolute distance |a-b| (accumulate): difference-based. */
		return RZ_ANALYSIS_OP_TYPE_SUB;
	case TMS320C55_INS_SAT:
		/* Saturate: clamp a value into range — a (conditional) move. */
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case TMS320C55_INS_NOP:
	case TMS320C55_INS_IDLE:
		return RZ_ANALYSIS_OP_TYPE_NOP;
	case TMS320C55_INS_PSH:
		return RZ_ANALYSIS_OP_TYPE_PUSH;
	case TMS320C55_INS_POP:
		return RZ_ANALYSIS_OP_TYPE_POP;
	/* PSHBOTH / POPBOTH push or pop a register *pair* in one op; the
	 * byte-level classifier types them UPUSH / UPOP (multi-register
	 * stack ops), which is more specific than PUSH / POP. Returning NULL
	 * here preserves that. */
	case TMS320C55_INS_RET:
	case TMS320C55_INS_RETI:
		return RZ_ANALYSIS_OP_TYPE_RET;
	case TMS320C55_INS_RETCC:
		return RZ_ANALYSIS_OP_TYPE_CRET;
	case TMS320C55_INS_INTR:
		return RZ_ANALYSIS_OP_TYPE_SWI;
	case TMS320C55_INS_TRAP:
	case TMS320C55_INS_RESET:
		return RZ_ANALYSIS_OP_TYPE_TRAP;
	default:
		/* Control flow (B/BCC/CALL/CALLCC/...), repeats (RPT*), XCC,
		 * ABS (renders as "undefined" — see above), SIM_TRIG and anything
		 * else: leave to the byte-level classifier, which sets jump/call
		 * targets, stack deltas and operand fields. */
		return RZ_ANALYSIS_OP_TYPE_NULL;
	}
}
