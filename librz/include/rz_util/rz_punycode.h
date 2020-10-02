#ifndef RZ_PUNYCODE_H
#define RZ_PUNYCODE_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API char *rz_punycode_encode(const ut8 *src, int srclen, int *dstlen);
RZ_API char *rz_punycode_decode(const char *src, int srclen, int *dstlen);

#ifdef __cplusplus
}
#endif

#endif //  RZ_PUNYCODE_H
