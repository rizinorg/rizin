#ifndef RZ_HEX_H
#define RZ_HEX_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_hex_pair2bin(const char *arg);
RZ_API int rz_hex_str2binmask(const char *in, ut8 *out, ut8 *mask);
RZ_API int rz_hex_str2bin(const char *in, ut8 *out);
RZ_API int rz_hex_bin2str(const ut8 *in, int len, char *out);
RZ_API char *rz_hex_bin2strdup(const ut8 *in, int len);
RZ_API bool rz_hex_to_byte(ut8 *val, ut8 c);
RZ_API int rz_hex_str_is_valid(const char *s);
RZ_API st64 rz_hex_bin_truncate(ut64 in, int n);
RZ_API char *rz_hex_from_c(const char *code);
RZ_API char *rz_hex_from_py(const char *code);
RZ_API char *rz_hex_from_code(const char *code);
RZ_API char *rz_hex_no_code(const char *code);
RZ_API char *rz_hex_from_py_str(char *out, const char *code);
RZ_API char *rz_hex_from_py_array(char *out, const char *code);
RZ_API char *rz_hex_from_c_str(char *out, const char **code);
RZ_API char *rz_hex_from_c_array(char *out, const char *code);
#ifdef __cplusplus
}
#endif

#endif //  RZ_HEX_H
