// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_C166_H
#define RZIL_ANALYSIS_C166_H

#include "analysis_private.h"
#include <rz_types.h>

#define C166_ADDR_SIZE 32 // should be 24 bits max, but we can ignore this

#define C166_SP_SIZE  16
#define C166_CSP_SIZE 16

#define SEGMENTED_ADDR(csp, ip) \
	ADD( \
		SHIFTL0(UNSIGNED(32, csp), U32(14)), \
		UNSIGNED(32, ip))

#define SET_Ex(x, b) SETG("e", ITE(EQ(x, U##b(1 << (b - 1))), IL_TRUE, IL_FALSE))
#define SET_Nx(x, b) SETG("n", MSB(UNSIGNED(b, x)))

#define SET_E(x)          SET_Ex(x, 16)
#define SET_E8(x)         SET_Ex(x, 8)
#define SET_Z(x)          SETG("z", ITE(IS_ZERO(x), IL_TRUE, IL_FALSE))
#define SET_Z_CARRY(x, c) SETG("z", ITE(AND(IS_ZERO(x), c), IL_TRUE, IL_FALSE))
#define SET_DZ(x)         SETG("z", ITE(IS_ZERO(DUP(x)), IL_TRUE, IL_FALSE))
#define SET_N(x)          SET_Nx(x, 16)
#define SET_N8(x)         SET_Nx(x, 8)
#define SET_DN(x)         SETG("n", MSB(DUP(x)))
#define SET_C(x)          SETG("c", ITE(EQ(x, U16(0xFFFF)), IL_TRUE, IL_FALSE))
#define SET_C8(x)         SETG("c", ITE(EQ(x, U8(0xFF)), IL_TRUE, IL_FALSE))

#define E_FALSE SETG("e", IL_FALSE)
#define E_TRUE  SETG("e", IL_TRUE)
#define V_FALSE SETG("v", IL_FALSE)
#define V_TRUE  SETG("v", IL_TRUE)
#define Z_FALSE SETG("z", IL_FALSE)
#define Z_TRUE  SETG("z", IL_TRUE)
#define C_FALSE SETG("c", IL_FALSE)
#define C_TRUE  SETG("c", IL_TRUE)
#define N_FALSE SETG("n", IL_FALSE)

#define IL_UN(l, x) rz_il_value_new_bitv(rz_bv_new_from_ut64(l, x))
#define IL_U8(x)    IL_UN(8, x)
#define IL_U16(x)   IL_UN(16, x)
#define IL_U32(x)   IL_UN(32, x)

#define READ_RL8(x) LOGAND(UNSIGNED(8, x), U8(0xFF))
#define READ_RL(x)  LOGAND(x, U16(0xFF))
#define READ_RH8(x) UNSIGNED(8, SHIFTR0(x, U16(8)))
#define READ_RH(x)  SHIFTR0(VARG(x), U16(8))

#define GET_BIT16(src_varl, bit) SHIFTR0(LOGAND(src_varl, U16(1 << bit)), U16(bit))
#define GET_BIT8(src_varl, bit)  SHIFTR0(LOGAND(src_varl, U8(1 << bit)), U8(bit))
#define CLR_BIT16(src_varl, bit) LOGAND(src_varl, LOGNOT(U16(1 << bit)))
#define SET_BIT16(src_varl, bit) LOGOR(src_varl, U16(1 << bit))
#define INV_BIT16(src_varl, bit) LOGXOR(src_varl, U16(1 << bit))

#define SP_SET_VAL8  STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(32, VARL("SP")))
#define SP_SET_VAL16 STORE(UNSIGNED(32, VARL("SP")), UNSIGNED(32, VARL("SP")))

#define SP_GET_VAL8  LOADW(8, UNSIGNED(32, VARL("SP")))
#define SP_GET_VAL16 LOADW(16, UNSIGNED(32, VARL("SP")))
#define SP_DEC       SUB(VARL("SP"), U16(2))
#define SP_INC       ADD(VARL("SP"), U16(2))

#define IL_UN(l, x) rz_il_value_new_bitv(rz_bv_new_from_ut64(l, x))
#define IL_U8(x)    IL_UN(8, x)
#define IL_U16(x)   IL_UN(16, x)
#define IL_U32(x)   IL_UN(32, x)

#define SET_C_ADD(b, x, y, f) \
	SETG("c", UGT(ADD(UNSIGNED(b, x), UNSIGNED(b, y)), U##b(f)))

#define SET_C_ADD_8(x, y)  SET_C_ADD(16, x, y, 0xFF)
#define SET_C_ADD_16(x, y) SET_C_ADD(32, x, y, 0xFFFF)

#define SET_V_ADD(b, x, y, r) \
	SETG("v", AND(EQ(GET_BIT##b(x, (b - 1)), GET_BIT##b(UNSIGNED(b, y), (b - 1))), NE(GET_BIT##b(x, (b - 1)), GET_BIT##b(r, (b - 1)))))

#define SET_V_ADD_8(x, y, r)  SET_V_ADD(8, x, y, r)
#define SET_V_ADD_16(x, y, r) SET_V_ADD(16, x, y, r)

#define SET_V_SUB_16(x, y, r) SETG("v", AND(XOR(IS_ZERO(GET_BIT16(x, 15)), IS_ZERO(GET_BIT16(y, 15))), XOR(IS_ZERO(GET_BIT16(x, 15)), IS_ZERO(GET_BIT16(r, 15)))))

typedef RzILOpEffect *(*c166_il_op)(RzAnalysis *analysis, const ut8 *buf, RzAnalysisOp *op);

RZ_IPI bool rz_c166_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf);
RZ_IPI RzAnalysisILConfig *rz_c166_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // RZIL_ANALYSIS_C166_H
