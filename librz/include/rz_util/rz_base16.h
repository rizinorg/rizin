#ifndef RZ_BASE16_H
#define RZ_BASE16_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_base16_encode(RZ_OUT RZ_NULLABLE char *bout, RZ_NULLABLE const ut8 *bin, size_t sz);
RZ_API int rz_base16_decode(RZ_OUT RZ_NULLABLE ut8 *bout, RZ_NULLABLE const char *bin);

RZ_API RZ_OWN char *rz_base16_encode_dyn(RZ_NULLABLE const ut8 *bin, size_t sz);
RZ_API RZ_OWN ut8 *rz_base16_decode_dyn(RZ_NULLABLE const char *in, st64 len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE16_H
