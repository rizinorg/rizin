#ifndef RZ_IL_FLOAT_H
#define RZ_IL_FLOAT_H

#include <rz_util.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzFloat *rz_il_float_neg(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_il_float_succ(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzFloat *rz_il_float_pred(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN st32 rz_il_float_cmp(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y);

#endif // RZ_IL_FLOAT_H
