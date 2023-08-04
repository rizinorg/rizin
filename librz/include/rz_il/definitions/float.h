#ifndef RZ_IL_FLOAT_H
#define RZ_IL_FLOAT_H

#include <rz_util.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv);

// return const string for il_export
RZ_API const char *rz_il_float_stringify_rmode(RzFloatRMode mode);
RZ_API const char *rz_il_float_stringify_format(RzFloatFormat format);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_FLOAT_H
