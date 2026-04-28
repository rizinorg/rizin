// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "gadget_internal.h"

RZ_IPI bool rz_gadget_rop_is_valid_terminator(const RzAnalysisOp *aop, const bool allow_conditional) {

	switch (aop->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_RET:
		return true;
	case RZ_ANALYSIS_OP_TYPE_CRET:
		return allow_conditional;
	default:
		return false;
	}
}
