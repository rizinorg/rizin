#ifndef RZIL_FLOAT_H
#define RZIL_FLOAT_H

#include <rz_il/definitions/bool.h>
#include <rz_il/definitions/bitvector.h>

/**
 * Given the format
 * IEEE 754 only for now
 */
typedef enum float_format_enum {
	RZIL_FLOAT_IEEE754_32,
	RZIL_FLOAT_IEEE754_64,
	RZIL_FLOAT_IEEE754_128,
	RZIL_FLOAT_UNK
} RzILFloatFormat;

typedef enum float_round_enum {
	RZIL_FLOAT_RMODE_RNE, ///< rounding to nearest, ties to even
	RZIL_FLOAT_RMODE_RNA, ///< rounding to nearest, ties away
	RZIL_FLOAT_RMODE_RTP, ///< rounding towards positive
	RZIL_FLOAT_RMODE_RTN, ///< rounding towards negative
	RZIL_FLOAT_RMODE_RTZ, ///< rounding towards zero
	RZIL_FLOAT_RMODE_UNK ///< end
} RzILFloatRMode; ///< Rounding Mode

typedef struct float_t {
	RzILFloatFormat r; ///< An interpretation of bitvector
	RzILBitVector *s; ///< The bitvector of float
} RzILFloat;

RZ_API ut32 rzil_float_get_exp_len(RZ_NONNULL RzILFloat *f);
RZ_API ut32 rzil_float_get_frac_len(RZ_NONNULL RzILFloat *f);
RZ_API RzILBitVector *rzil_float_get_sigexp(RZ_NONNULL RzILFloat *f);
RZ_API RzILBitVector *rzil_float_get_frac(RzILFloat *f);
RZ_API bool rzil_float_get_sign(RzILFloat *f);
RZ_API RzILBitVector *rzil_float_get_bias(RzILFloat *f);

/// create float from bv (provide for theory handler)
RZ_API RzILFloat *rzil_float_new(RzILFloatFormat r, RzILBitVector *bv);
RZ_API RzILBitVector *rzil_float_fbits(RzILFloat *f);

///< Check float attribute, mode-irrelevant
RZ_API bool rzil_float_is_finite(RzILFloat *f);
RZ_API bool rzil_float_is_inf(RzILFloat *f);
RZ_API bool rzil_float_is_nan(RzILFloat *f);
RZ_API bool rzil_float_is_fzero(RzILFloat *f);
RZ_API bool rzil_float_is_fpos(RzILFloat *f);
RZ_API bool rzil_float_is_fneg(RzILFloat *f);

///< cast operations
/// TODO: split sort into an independent struct ?
/// fconvert and cast_*
/// see http://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/Theory/module-type-Float/index.html

///< Arithmetic Operations of fbasic
bool rzil_float_round(RzILFloat *f, RzILFloatRMode rmode);
bool rzil_float_requal(RzILFloatRMode r1, RzILFloatRMode r2);
RzILFloat *rzil_float_fneg(RzILFloat *f);
RzILFloat *rzil_float_fabs(RzILFloat *f);
RzILFloat *rzil_float_fadd(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fsub(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmul(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fdiv(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fsqrt(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmodulo(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmad(RzILFloatRMode r, RzILFloat *a, RzILFloat *b, RzILFloat *c);
RzILFloat *rzil_float_fround(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fsucc(RzILFloat *a);
RzILFloat *rzil_float_fpred(RzILFloat *a);
bool rzil_float_forder(RzILFloat *x, RzILFloat *y);

#endif // RZIL_FLOAT_H
