#ifndef R_BASE91_H
#define R_BASE91_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_base91_encode(char *bout, const ut8 *bin, int len);
RZ_API int rz_base91_decode(ut8 *bout, const char *bin, int len);

#ifdef __cplusplus
}
#endif

#endif //  R_BASE91_H
