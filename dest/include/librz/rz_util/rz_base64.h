#ifndef RZ_BASE64_H
#define RZ_BASE64_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API size_t rz_base64_encode(RZ_OUT RZ_NULLABLE char *bout, RZ_NULLABLE const ut8 *bin, size_t sz);
RZ_API st64 rz_base64_decode(RZ_OUT RZ_NULLABLE ut8 *bout, RZ_NULLABLE const char *bin, st64 len);
RZ_API RZ_OWN ut8 *rz_base64_decode_dyn(RZ_NULLABLE const char *in, st64 len);
RZ_API RZ_OWN char *rz_base64_encode_dyn(RZ_NULLABLE const ut8 *bin, size_t sz);
#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE64_H
