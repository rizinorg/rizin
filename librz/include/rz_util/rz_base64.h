#ifndef R_BASE64_H
#define R_BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_base64_encode(char *bout, const ut8 *bin, int len);
RZ_API int rz_base64_decode(ut8 *bout, const char *bin, int len);
RZ_API ut8 *rz_base64_decode_dyn(const char *in, int len);
RZ_API char *rz_base64_encode_dyn(const char *str, int len);
#ifdef __cplusplus
}
#endif

#endif //  R_BASE64_H
