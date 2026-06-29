// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * TMS320C5x architecture descriptor, analysis entry and RzIL VM configuration.
 *
 * The C5x has its own decode front-end (c5x_decode, the real C5x object
 * encoding) and reuses the shared C55 consumers (c55_format, c55_fill_analysis,
 * c55_lift) through the descriptor below. Shared-semantics instructions carry
 * the C2x ids and route through the C2x mnemonic/op-type/lifter; the C5x-only
 * ids are handled by c5x_mnemonic/c5x_op_type/c5x_lift.
 */

#include "c5x.h"
#include "../c2x/c2x.h"

/**
 * \brief Map an instruction id to its C5x mnemonic.
 * \param id C5X_INS_* id, or a shared C2X_INS_* id
 * \return Static mnemonic string, never NULL
 *
 * Only the C5x-only ids and the shared ids whose canonical C5x spelling
 * differs from the C2x one are handled here; the rest delegate to
 * \ref c2x_mnemonic.
 */
RZ_IPI const char *c5x_mnemonic(ut16 id) {
	switch (id) {
	// shared ids whose canonical C5x spelling differs from the C2x mnemonic
	case C2X_INS_ADDK: return "add";
	case C2X_INS_SUBK: return "sub";
	case C2X_INS_LARK: return "lar";
	// 16-bit immediate ALU forms (decoded as the C2x long-immediate ops)
	case C2X_INS_LALK: return "lacc";
	case C2X_INS_ADLK: return "add";
	case C2X_INS_SBLK: return "sub";
	case C2X_INS_ANDK: return "and";
	case C2X_INS_ORK: return "or";
	case C2X_INS_XORK: return "xor";
	case C2X_INS_RPTK: return "rpt";
	case C2X_INS_LDPK: return "ldp";
	// C5x-only mnemonics
	case C5X_INS_LACC: return "lacc";
	case C5X_INS_LACL: return "lacl";
	case C5X_INS_LACB: return "lacb";
	case C5X_INS_SACB: return "sacb";
	case C5X_INS_EXAR: return "exar";
	case C5X_INS_ADDB: return "addb";
	case C5X_INS_SBB: return "sbb";
	case C5X_INS_ADCB: return "adcb";
	case C5X_INS_SBBB: return "sbbb";
	case C5X_INS_CRGT: return "crgt";
	case C5X_INS_CRLT: return "crlt";
	case C5X_INS_ANDB: return "andb";
	case C5X_INS_ORB: return "orb";
	case C5X_INS_XORB: return "xorb";
	case C5X_INS_ROLB: return "rolb";
	case C5X_INS_RORB: return "rorb";
	case C5X_INS_SFLB: return "sflb";
	case C5X_INS_SFRB: return "sfrb";
	case C5X_INS_SAMM: return "samm";
	case C5X_INS_LAMM: return "lamm";
	case C5X_INS_LMMR: return "lmmr";
	case C5X_INS_SMMR: return "smmr";
	case C5X_INS_BLDD: return "bldd";
	case C5X_INS_BLPD: return "blpd";
	case C5X_INS_BLDP: return "bldp";
	case C5X_INS_MADS: return "mads";
	case C5X_INS_MADD: return "madd";
	case C5X_INS_SPLK: return "splk";
	case C5X_INS_BCND: return "bcnd";
	case C5X_INS_BCNDD: return "bcndd";
	case C5X_INS_CC: return "cc";
	case C5X_INS_CCD: return "ccd";
	case C5X_INS_RETC: return "retc";
	case C5X_INS_RETCD: return "retcd";
	case C5X_INS_RETD: return "retd";
	case C5X_INS_XC: return "xc";
	case C5X_INS_BSAR: return "bsar";
	case C5X_INS_ZAP: return "zap";
	case C5X_INS_ZPR: return "zpr";
	case C5X_INS_SATH: return "sath";
	case C5X_INS_SATL: return "satl";
	case C5X_INS_BACCD: return "baccd";
	case C5X_INS_CALAD: return "calad";
	case C5X_INS_APL: return "apl";
	case C5X_INS_OPL: return "opl";
	case C5X_INS_XPL: return "xpl";
	case C5X_INS_CPL: return "cpl";
	case C5X_INS_RPTB: return "rptb";
	case C5X_INS_RPTZ: return "rptz";
	case C5X_INS_SETC: return "setc";
	case C5X_INS_CLRC: return "clrc";
	case C5X_INS_IDLE2: return "idle2";
	case C5X_INS_NMI: return "nmi";
	case C5X_INS_RETE: return "rete";
	case C5X_INS_RETI: return "reti";
	case C5X_INS_INTR: return "intr";
	case C5X_INS_BD: return "bd";
	case C5X_INS_CALLD: return "calld";
	case C5X_INS_BANZD: return "banzd";
	case C5X_INS_LST: return "lst";
	case C5X_INS_SST: return "sst";
	default: return c2x_mnemonic(id);
	}
}

/**
 * \brief Map an instruction id to its RzAnalysisOp type.
 * \param id C5X_INS_* id, or a shared C2X_INS_* id
 * \return RZ_ANALYSIS_OP_TYPE_* value for \p id
 *
 * Shared ids delegate to \ref c2x_op_type.
 */
RZ_IPI ut32 c5x_op_type(ut16 id) {
	switch (id) {
	case C5X_INS_LACC:
	case C5X_INS_LACL:
	case C5X_INS_LACB:
	case C5X_INS_SACB:
	case C5X_INS_EXAR:
	case C5X_INS_SAMM:
	case C5X_INS_LAMM:
	case C5X_INS_LMMR:
	case C5X_INS_SMMR:
	case C5X_INS_BLDD:
	case C5X_INS_BLPD:
	case C5X_INS_BLDP:
	case C5X_INS_SPLK:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C5X_INS_ADDB:
	case C5X_INS_ADCB:
		return RZ_ANALYSIS_OP_TYPE_ADD;
	case C5X_INS_SBB:
	case C5X_INS_SBBB:
		return RZ_ANALYSIS_OP_TYPE_SUB;
	case C5X_INS_ANDB:
		return RZ_ANALYSIS_OP_TYPE_AND;
	case C5X_INS_ORB:
		return RZ_ANALYSIS_OP_TYPE_OR;
	case C5X_INS_XORB:
		return RZ_ANALYSIS_OP_TYPE_XOR;
	case C5X_INS_CRGT:
	case C5X_INS_CRLT:
	case C5X_INS_SATH:
	case C5X_INS_SATL:
	case C5X_INS_APL:
	case C5X_INS_OPL:
	case C5X_INS_XPL:
	case C5X_INS_CPL:
	case C5X_INS_MADS:
	case C5X_INS_MADD:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C5X_INS_ROLB:
	case C5X_INS_SFLB:
	case C5X_INS_BSAR:
		return RZ_ANALYSIS_OP_TYPE_SHL;
	case C5X_INS_RORB:
	case C5X_INS_SFRB:
		return RZ_ANALYSIS_OP_TYPE_SHR;
	case C5X_INS_ZAP:
	case C5X_INS_ZPR:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C5X_INS_SETC:
	case C5X_INS_CLRC:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C5X_INS_LST:
	case C5X_INS_SST:
		return RZ_ANALYSIS_OP_TYPE_MOV;
	case C5X_INS_BCND:
	case C5X_INS_BCNDD:
	case C5X_INS_XC:
	case C5X_INS_BANZD:
		return RZ_ANALYSIS_OP_TYPE_CJMP;
	case C5X_INS_BD:
		return RZ_ANALYSIS_OP_TYPE_JMP;
	case C5X_INS_CC:
	case C5X_INS_CCD:
		return RZ_ANALYSIS_OP_TYPE_CCALL;
	case C5X_INS_CALLD:
		return RZ_ANALYSIS_OP_TYPE_CALL;
	case C5X_INS_BACCD:
		return RZ_ANALYSIS_OP_TYPE_UJMP;
	case C5X_INS_CALAD:
		return RZ_ANALYSIS_OP_TYPE_UCALL;
	case C5X_INS_RETC:
	case C5X_INS_RETCD:
		return RZ_ANALYSIS_OP_TYPE_CRET;
	case C5X_INS_RETD:
		return RZ_ANALYSIS_OP_TYPE_RET;
	case C5X_INS_RPTB:
	case C5X_INS_RPTZ:
		return RZ_ANALYSIS_OP_TYPE_NOP;
	case C5X_INS_IDLE2:
	case C5X_INS_NMI:
	case C5X_INS_INTR:
		return RZ_ANALYSIS_OP_TYPE_NULL;
	case C5X_INS_RETE:
	case C5X_INS_RETI:
		return RZ_ANALYSIS_OP_TYPE_RET;
	default:
		return c2x_op_type(id);
	}
}

/**
 * \brief C5x architecture descriptor for the shared C55 engine.
 *
 * Carries the C5x's own decoder and the consumers that fall back to the C2x
 * implementations for the shared instruction ids.
 */
const C55ArchDesc c5x_arch_desc = {
	.arch = C55_ARCH_C5X,
	.cpu_name = "c5x",
	.table = NULL, // decoded by c5x_decode(), not the shared table engine
	.table_len = 0,
	.insn_len = NULL,
	.reg_info = c2x_reg_info, // operands reference only C2x reg classes (ARn)
	.mnemonic = c5x_mnemonic,
	.op_type = c5x_op_type,
	.lift = NULL,
	.mem = { .addr_unit_log2 = 0, .ptr_width = 16, .big_endian = true, .page_reg = "dp" },
	.ea = NULL,
	.fill_dual = NULL,
	.words_le = false,
	.cond_exec_prefix = false,
	.parallel_prefix = false,
};

/**
 * \brief Analysis entry point for the "c5x" CPU.
 * \param analysis Current analysis session
 * \param op Operation to fill in
 * \param addr Address \p buf was read from
 * \param buf Instruction bytes
 * \param len Number of readable bytes in \p buf
 * \param mask Which parts of \p op the caller wants filled
 * \return Instruction length in bytes, or -1 on an undecodable word
 */
RZ_IPI int tms320_c5x_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op || !buf || len < 1) {
		return 0;
	}
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;
	C55Insn ci;
	int n = c5x_decode(buf, len, &ci);
	if (n > 0) {
		c55_fill_analysis(&c5x_arch_desc, &ci, op);
		c2x_fill_op_access(analysis, &c5x_arch_desc, &ci, op);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = c55_lift(&c5x_arch_desc, &ci, op->addr);
		}
	} else {
		// Undecodable word: flag it and give a one-word fallback size, but
		// report the failure to the caller with -1 (the common plugin convention).
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 1;
		return -1;
	}
	return op->size;
}
