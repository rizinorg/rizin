#ifndef RZ_IL_FLOAT_H
#define RZ_IL_FLOAT_H

#include <rz_util.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv);

#endif // RZ_IL_FLOAT_H
