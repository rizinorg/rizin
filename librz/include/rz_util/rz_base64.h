#ifndef RZ_BASE64_H
#define RZ_BASE64_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API size_t rz_base64_encode(char *bout, const ut8 *bin, size_t sz);
RZ_API st64 rz_base64_decode(ut8 *bout, const char *bin, st64 len);
RZ_API RZ_OWN ut8 *rz_base64_decode_dyn(const char *in, st64 len);
RZ_API RZ_OWN char *rz_base64_encode_dyn(const ut8 *bin, size_t sz);
#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE64_H
