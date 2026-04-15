// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "gadget_internal.h"

static bool is_cond_end_gadget(const RzAnalysisOp *aop) {
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
	case RZ_ANALYSIS_OP_TYPE_CRET:
		return true;
	default:
		return false;
	}
}

RZ_IPI bool rz_gadget_rop_is_end_gadget(const RzAnalysisOp *aop, const bool allow_conditional) {
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		if (allow_conditional) {
			return is_cond_end_gadget(aop);
		}
		return true;
	default:
		return false;
	}
}

RZ_IPI bool rz_gadget_rop_is_valid_terminator(const RzAnalysisOp *aop, const bool allow_conditional) {
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_RET:
		if (allow_conditional) {
			return is_cond_end_gadget(aop);
		}
		return true;
	default:
		return false;
	}
}
