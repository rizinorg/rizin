#ifndef RZ_base36_H
#define RZ_base36_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_base36_encode_dyn(ut64 val);
RZ_API ut64 rz_base36_decode(const char *str, const size_t len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_base36_H

