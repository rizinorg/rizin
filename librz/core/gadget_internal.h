// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_GADGET_INTERNAL_H
#define RZ_GADGET_INTERNAL_H

#include <rz_analysis.h>

// ROP (Return-Oriented Programming)
RZ_IPI bool rz_gadget_rop_is_valid_terminator(const RzAnalysisOp *aop, const bool allow_conditional);

// COP (Call-Oriented Programming)
RZ_IPI bool rz_gadget_cop_is_valid_terminator(const RzAnalysisOp *aop, const bool allow_conditional);

// JOP (Jump-Oriented Programming)
RZ_IPI bool rz_gadget_jop_is_valid_terminator(const RzAnalysisOp *aop, const bool allow_conditional);

#endif
