#ifndef RZIL_FLOAT_H
#define RZIL_FLOAT_H

/**
 * Given the format
 */
typedef enum float_format_enum {
	RZIL_FLOAT_BASIC,
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

/// create float from bv (provide for theory handler)
RzILFloat *rzil_float_float(RzILFloatFormat r, RzILBitVector *bv);
RzILBitVector *rzil_float_fbits(RzILFloat *f);

///< Check float attribute, mode-irrelevant
RzILBool *rzil_float_is_finite(RzILFloat *f);
RzILBool *rzil_float_is_inf(RzILFloat *f);
RzILBool *rzil_float_is_nan(RzILFloat *f);
RzILBool *rzil_float_is_fzero(RzILFloat *f);
RzILBool *rzil_float_is_fpos(RzILFloat *f);
RzILBool *rzil_float_is_fneg(RzILFloat *f);

///< cast operations
/// TODO: split sort into an independent struct ?
/// fconvert and cast_*
/// see http://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/Theory/module-type-Float/index.html

///< Arithmetic Operations of fbasic
RzILBool *rzil_float_requal(RzILFloatRMode r1, RzILFloatRMode r2);
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
RzILBool *rzil_float_forder(RzILFloat *x, RzILFloat *y);


#endif // RZIL_FLOAT_H
