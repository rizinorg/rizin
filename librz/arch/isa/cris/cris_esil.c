// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cris_esil.c
 * \brief ESIL emulation for CRIS instructions.
 */

#include "cris.h"

static const char *esil_gpr(ut8 reg, CrisIsaVersion ver) {
	return (ver == CRIS_ISA_V32) ? cris_gpr_names_v32[reg & 0xF]
				     : cris_gpr_names[reg & 0xF];
}

/**
 * Append ESIL for updating NZVC flags after an arithmetic operation.
 */
static void esil_update_flags_nzvc(RzStrBuf *out) {
	rz_strbuf_append(out, ",$z,Z,:=,31,$s,N,:=,31,$o,V,:=,$c,C,:=");
}

/**
 * Append ESIL for updating NZ flags only (logic operations).
 */
static void esil_update_flags_nz(RzStrBuf *out) {
	rz_strbuf_append(out, ",$z,Z,:=,31,$s,N,:=,0,V,:=,0,C,:=");
}

void cris_esil(const CrisInsn *insn, RzStrBuf *out, ut64 addr, CrisIsaVersion ver) {
	const char *r1 = esil_gpr(insn->reg1, ver);
	const char *r2 = esil_gpr(insn->reg2, ver);

	switch (insn->type) {
	// Quick immediate
	case CRIS_INSN_ADDQ:
		rz_strbuf_setf(out, "%d,%s,+=", insn->immediate, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_SUBQ:
		rz_strbuf_setf(out, "%d,%s,-=", insn->immediate, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_MOVEQ:
		rz_strbuf_setf(out, "%d,%s,=", insn->immediate, r2);
		break;
	case CRIS_INSN_CMPQ:
		rz_strbuf_setf(out, "%d,%s,==", insn->immediate, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_ANDQ:
		rz_strbuf_setf(out, "%d,%s,&=", insn->immediate, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_ORQ:
		rz_strbuf_setf(out, "%d,%s,|=", insn->immediate, r2);
		esil_update_flags_nz(out);
		break;

	// Quick shifts
	case CRIS_INSN_ASRQ:
		rz_strbuf_setf(out, "%d,%s,>>=", insn->immediate, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_LSLQ:
		rz_strbuf_setf(out, "%d,%s,<<=", insn->immediate, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_LSRQ:
		rz_strbuf_setf(out, "%d,%s,>>=", insn->immediate, r2);
		esil_update_flags_nz(out);
		break;

	// Register-register arithmetic
	case CRIS_INSN_ADD:
		rz_strbuf_setf(out, "%s,%s,+=", r1, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_SUB:
		rz_strbuf_setf(out, "%s,%s,-=", r1, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_CMP:
		rz_strbuf_setf(out, "%s,%s,==", r1, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_AND:
		rz_strbuf_setf(out, "%s,%s,&=", r1, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_OR:
		rz_strbuf_setf(out, "%s,%s,|=", r1, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_XOR:
		rz_strbuf_setf(out, "%s,%s,^=", r1, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_MOVE_R:
		rz_strbuf_setf(out, "%s,%s,=", r1, r2);
		break;
	case CRIS_INSN_NEG:
		rz_strbuf_setf(out, "%s,0,-,%s,=", r1, r2);
		esil_update_flags_nzvc(out);
		break;
	case CRIS_INSN_NOT:
		rz_strbuf_setf(out, "%s,0xffffffff,^,%s,=", r1, r1);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_ABS:
		rz_strbuf_setf(out, "%s,0x80000000,&,?{,%s,0,-,%s,=,}", r1, r1, r2);
		break;

	// Shifts
	case CRIS_INSN_ASR:
		rz_strbuf_setf(out, "%s,%s,>>=", r1, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_LSL:
		rz_strbuf_setf(out, "%s,%s,<<=", r1, r2);
		esil_update_flags_nz(out);
		break;
	case CRIS_INSN_LSR:
		rz_strbuf_setf(out, "%s,%s,>>=", r1, r2);
		esil_update_flags_nz(out);
		break;

	// Branch
	case CRIS_INSN_BCC_8:
	case CRIS_INSN_BCC_16: {
		ut64 target = addr + insn->immediate;
		if (insn->cond == CRIS_CC_A) {
			rz_strbuf_setf(out, "0x%" PFMT64x ",pc,=", target);
		} else {
			// Conditional branch — simplified ESIL condition check
			switch (insn->cond) {
			case CRIS_CC_EQ:
				rz_strbuf_setf(out, "Z,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_NE:
				rz_strbuf_setf(out, "Z,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_CC:
				rz_strbuf_setf(out, "C,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_CS:
				rz_strbuf_setf(out, "C,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_PL:
				rz_strbuf_setf(out, "N,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_MI:
				rz_strbuf_setf(out, "N,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_VC:
				rz_strbuf_setf(out, "V,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_VS:
				rz_strbuf_setf(out, "V,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_HI:
				rz_strbuf_setf(out, "C,Z,|,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_LS:
				rz_strbuf_setf(out, "C,Z,|,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_GE:
				rz_strbuf_setf(out, "N,V,^,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_LT:
				rz_strbuf_setf(out, "N,V,^,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_GT:
				rz_strbuf_setf(out, "N,V,^,Z,|,!,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			case CRIS_CC_LE:
				rz_strbuf_setf(out, "N,V,^,Z,|,?{,0x%" PFMT64x ",pc,=,}", target);
				break;
			default:
				break;
			}
		}
		break;
	}
	case CRIS_INSN_BA_DWORD:
		rz_strbuf_setf(out, "0x%" PFMT64x ",pc,=", addr + insn->immediate);
		break;
	case CRIS_INSN_BSR:
		rz_strbuf_setf(out, "pc,srp,=,0x%" PFMT64x ",pc,=", addr + insn->immediate);
		break;

	// Jump
	case CRIS_INSN_JUMP_R:
		rz_strbuf_setf(out, "%s,pc,=", esil_gpr(insn->reg1, ver));
		break;
	case CRIS_INSN_JSR_R:
		rz_strbuf_setf(out, "pc,srp,=,%s,pc,=", esil_gpr(insn->reg1, ver));
		break;
	case CRIS_INSN_JUMP_N:
		rz_strbuf_setf(out, "0x%x,pc,=", (ut32)insn->immediate);
		break;
	case CRIS_INSN_JSR_N:
		rz_strbuf_setf(out, "pc,srp,=,0x%x,pc,=", (ut32)insn->immediate);
		break;

	// Return
	case CRIS_INSN_RET:
		rz_strbuf_set(out, "srp,pc,=");
		break;

	// Special
	case CRIS_INSN_NOP:
		rz_strbuf_set(out, ",");
		break;

	// Memory operations — basic ESIL
	case CRIS_INSN_MOVE_MR:
		if (insn->autoincr && insn->reg1 == 0xF) {
			rz_strbuf_setf(out, "0x%x,%s,=", (ut32)insn->immediate, r2);
		} else {
			int sz_bytes = (insn->sz == CRIS_SIZE_BYTE) ? 1
				: (insn->sz == CRIS_SIZE_WORD)	    ? 2
								    : 4;
			rz_strbuf_setf(out, "%s,[%d],%s,=", r1, sz_bytes, r2);
			if (insn->autoincr) {
				rz_strbuf_appendf(out, ",%d,%s,+=", sz_bytes, r1);
			}
		}
		break;
	case CRIS_INSN_MOVE_RM: {
		int sz_bytes = (insn->sz == CRIS_SIZE_BYTE) ? 1
			: (insn->sz == CRIS_SIZE_WORD)	    ? 2
							    : 4;
		rz_strbuf_setf(out, "%s,%s,=[%d]", r2, r1, sz_bytes);
		if (insn->autoincr) {
			rz_strbuf_appendf(out, ",%d,%s,+=", sz_bytes, r1);
		}
		break;
	}

	default:
		// Unimplemented — leave ESIL empty
		break;
	}
}
