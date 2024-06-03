// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_TRICORE_IL_H
#define RIZIN_TRICORE_IL_H

#include <rz_il/rz_il_opbuilder_begin.h>

#define BOOL_TO_BV32(b) BOOL_TO_BV(b, 32)
#define BOOL_TO_BV8(b)  BOOL_TO_BV(b, 8)

static inline int32_t sign_ext32(uint32_t X, unsigned B) {
	rz_warn_if_fail(B > 0 && B <= 32);
	return (int32_t)(X << (32 - B)) >> (32 - B);
}

static inline int64_t sign_ext64(uint64_t X, unsigned B) {
	rz_warn_if_fail(B > 0 && B <= 64);
	return (int64_t)(X << (64 - B)) >> (64 - B);
}

static inline RzILOpPure *sign_ext32_bv(uint32_t X, unsigned B) {
	return S32(sign_ext32(X, B));
}

static inline RzILOpPure *sign_ext64_bv(uint32_t X, unsigned B) {
	return S64(sign_ext64(X, B));
}

// static inline __attribute__((unused)) int32_t OneExt32(uint32_t X, unsigned B) {
//	rz_warn_if_fail(B > 0 && B <= 32);
//	return (int32_t)((~0U << B) | X);
// }
//
// static inline __attribute__((unused)) int64_t OneExt64(uint64_t X, unsigned B) {
//	rz_warn_if_fail(B > 0 && B <= 64);
//	return (int64_t)((~0ULL << B) | X);
// }

static inline RzILOpPure *BITS8(RzILOpBitVector *bv, ut32 i, ut32 n) {
	return LOGAND(SHIFTR0(bv, U8(i)), U8((1U << n) - 1));
}
static inline RzILOpPure *BITS16(RzILOpBitVector *bv, ut32 i, ut32 n) {
	return LOGAND(SHIFTR0(bv, U16(i)), U16((1U << n) - 1));
}
static inline RzILOpPure *BITS32(RzILOpBitVector *bv, ut32 i, ut32 n) {
	return LOGAND(SHIFTR0(bv, U32(i)), U32((1U << n) - 1));
}
static inline RzILOpPure *BITS64(RzILOpBitVector *bv, ut32 i, ut32 n) {
	return LOGAND(SHIFTR0(bv, U64(i)), U64((1ULL << n) - 1));
}
static inline RzILOpPure *BIT8(RzILOpBitVector *bv, ut32 i) {
	return NON_ZERO(BITS8(bv, i, 1));
}
static inline RzILOpPure *BIT16(RzILOpBitVector *bv, ut32 i) {
	return NON_ZERO(BITS16(bv, i, 1));
}
static inline RzILOpPure *BIT32(RzILOpBitVector *bv, ut32 i) {
	return NON_ZERO(BITS32(bv, i, 1));
}
static inline RzILOpPure *BIT64(RzILOpBitVector *bv, ut32 i) {
	return NON_ZERO(BITS64(bv, i, 1));
}

static inline RzILOpPure *BITS32_U(RzILOpPure *val, ut32 i, ut32 n, RzILOpPure *x) {
	ut32 mask = (1 << n) - 1;
	return LOGOR(LOGAND(val, U32(~(mask << i))), SHIFTL0((LOGAND(x, U32(mask))), U32(i)));
}

// ((value >> start) & (~0ULL >> (0x20 - length)))
static inline ut32 extract32(ut32 x, ut32 start, ut32 len) {
	return (x >> start) & (~0U >> (0x20 - len));
}

static inline RzILOpPure *SEXT32(RzILOpPure *value, ut32 length) {
	return LET("_sext_val", SIGNED(32, value), rz_il_sextract32(VARLP("_sext_val"), U32(0), U32(length)));
}
static inline RzILOpPure *SEXT64(RzILOpPure *value, ut32 length) {
	return LET("_sext_val", SIGNED(32, value), rz_il_sextract64(VARLP("_sext_val"), U32(0), U32(length)));
}
static inline RzILOpPure *ZEXT32(RzILOpPure *value, ut32 length) {
	return value;
}
static inline RzILOpPure *SHL0(RzILOpPure *value, ut32 length) {
	return SHIFTL0(value, U32(length));
}
static inline RzILOpPure *SHR0(RzILOpPure *value, ut32 length) {
	return SHIFTR0(value, U32(length));
}

#define REG_FIELD(regname, fieldname, i, n) \
	static inline RzILOpPure *regname##_##fieldname() { \
		return BITS32(VARG((#regname)), (i), (n)); \
	} \
	static inline RzILOpEffect *set_##regname##_##fieldname(RzILOpPure *x) { \
		return SETG((#regname), BITS32_U(VARG(#regname), (i), (n), (x))); \
	}

#define REG_FIELD_VER(v, regname, fieldname, i, n) \
	static inline RzILOpPure *regname##_##fieldname##_v##v() { \
		return BITS32(VARG((#regname)), (i), (n)); \
	} \
	static inline RzILOpEffect *set_##regname##_##fieldname##_v##v(RzILOpPure *x) { \
		return SETG((#regname), BITS32_U(VARG(#regname), (i), (n), (x))); \
	}

REG_FIELD(PSW, C, 31, 1);
REG_FIELD(PSW, V, 30, 1);
REG_FIELD(PSW, SV, 29, 1);
REG_FIELD(PSW, AV, 28, 1);
REG_FIELD(PSW, SAV, 27, 1);

REG_FIELD(PSW, FS, 31, 1);
REG_FIELD(PSW, FI, 30, 1);
REG_FIELD(PSW, FV, 29, 1);
REG_FIELD(PSW, FZ, 28, 1);
REG_FIELD(PSW, FU, 27, 1);
REG_FIELD(PSW, FX, 26, 1);

REG_FIELD(PSW, RM, 24, 2);
REG_FIELD(PSW, PRS, 12, 2);
REG_FIELD(PSW, IO, 10, 2);
REG_FIELD(PSW, IS, 9, 1);
REG_FIELD(PSW, GW, 8, 1);
REG_FIELD(PSW, CDE, 7, 1);
REG_FIELD(PSW, CDC, 0, 7);

REG_FIELD(FCX, FCXS, 16, 4);
REG_FIELD(FCX, FCXO, 0, 15);

REG_FIELD(PCXI, PCXS, 16, 4);
REG_FIELD(PCXI, PCXO, 0, 16);
// tc162
REG_FIELD_VER(162, PCXI, PCPN, 22, 8);
REG_FIELD_VER(162, PCXI, PIE, 21, 1);
REG_FIELD_VER(162, PCXI, UL, 20, 1);
// tc160
REG_FIELD_VER(160, PCXI, PCPN, 24, 8);
REG_FIELD_VER(160, PCXI, PIE, 23, 1);
REG_FIELD_VER(160, PCXI, UL, 22, 1);

#define REG_FIELD_VERS(X, Y) \
	static inline RzILOpPure *X##_##Y(cs_mode m) { \
		switch (m) { \
		case CS_MODE_TRICORE_162: \
			return X##_##Y##_v162(); \
		case CS_MODE_TRICORE_160: \
			return X##_##Y##_v160(); \
		default: rz_warn_if_reached(); return NULL; \
		} \
	} \
	static inline RzILOpEffect *set_##X##_##Y(cs_mode m, RzILOpPure *x) { \
		switch (m) { \
		case CS_MODE_TRICORE_162: \
			return set_##X##_##Y##_v162(x); \
		case CS_MODE_TRICORE_160: \
			return set_##X##_##Y##_v160(x); \
		default: rz_warn_if_reached(); return NULL; \
		} \
	}

REG_FIELD_VERS(PCXI, PCPN);
REG_FIELD_VERS(PCXI, PIE);
REG_FIELD_VERS(PCXI, UL);

REG_FIELD(ICR, CCPN, 0, 8);
REG_FIELD(ICR, IE, 8, 1);
REG_FIELD(ICR, PIPN, 16, 8);

REG_FIELD(DBGSR, DE, 0, 1);
REG_FIELD(DBGSR, HALT, 1, 2);
REG_FIELD(DBGSR, SIH, 3, 1);
REG_FIELD(DBGSR, SUSP, 4, 1);
REG_FIELD(DBGSR, PREVSUSP, 6, 1);
REG_FIELD(DBGSR, PEVT, 7, 1);
REG_FIELD(DBGSR, EVTSRC, 8, 5);

REG_FIELD(EXEVT, EVTA, 0, 3);
REG_FIELD(EXEVT, BBM, 3, 1);
REG_FIELD(EXEVT, BOD, 4, 1);
REG_FIELD(EXEVT, SUSP, 5, 1);
REG_FIELD(EXEVT, CNT, 6, 2);

REG_FIELD(CREVT, EVTA, 0, 3);
REG_FIELD(CREVT, BBM, 3, 1);
REG_FIELD(CREVT, BOD, 4, 1);
REG_FIELD(CREVT, SUSP, 5, 1);
REG_FIELD(CREVT, CNT, 6, 2);

REG_FIELD(SWEVT, EVTA, 0, 3);
REG_FIELD(SWEVT, BBM, 3, 1);
REG_FIELD(SWEVT, BOD, 4, 1);
REG_FIELD(SWEVT, SUSP, 5, 1);
REG_FIELD(SWEVT, CNT, 6, 2);

#define TRxEVT(x) \
	REG_FIELD(x, EVTA, 0, 3) \
	REG_FIELD(x, BBM, 3, 1) \
	REG_FIELD(x, BOD, 4, 1) \
	REG_FIELD(x, SUSP, 5, 1) \
	REG_FIELD(x, CNT, 6, 2) \
	REG_FIELD(x, TYP, 12, 1) \
	REG_FIELD(x, RNG, 13, 1) \
	REG_FIELD(x, ASI_EN, 15, 1) \
	REG_FIELD(x, ASI, 16, 5) \
	REG_FIELD(x, AST, 27, 5) \
	REG_FIELD(x, ALD, 28, 5)

TRxEVT(TR0EVT);
TRxEVT(TR1EVT);
TRxEVT(TR2EVT);
TRxEVT(TR3EVT);
TRxEVT(TR4EVT);
TRxEVT(TR5EVT);
TRxEVT(TR6EVT);
TRxEVT(TR7EVT);

REG_FIELD(TRIG_ACC, T0, 0, 1);
REG_FIELD(TRIG_ACC, T1, 1, 1);
REG_FIELD(TRIG_ACC, T2, 2, 1);
REG_FIELD(TRIG_ACC, T3, 3, 1);
REG_FIELD(TRIG_ACC, T4, 4, 1);
REG_FIELD(TRIG_ACC, T5, 5, 1);
REG_FIELD(TRIG_ACC, T6, 6, 1);
REG_FIELD(TRIG_ACC, T7, 7, 1);

REG_FIELD(DMS, Value, 1, 31);
REG_FIELD(DCX, Value, 6, 27);

REG_FIELD(DBGTCR, DTA, 0, 1);

REG_FIELD(TASK_ASI, ASI, 0, 5);

#undef REG_FIELD
#undef REG_FIELD_VERS
#undef REG_FIELD_VER

RZ_IPI RzAnalysisLiftedILOp tricore_il_op(RzAsmTriCoreContext *ctx, RzAnalysis *a);
RZ_IPI RzAnalysisILConfig *tricore_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // RIZIN_TRICORE_IL_H
