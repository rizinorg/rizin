#ifndef RZ_NAME_H
#define RZ_NAME_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API bool rz_name_check(const char *name);
RZ_API bool rz_name_filter(char *name, int len);
RZ_API char *rz_name_filter2(const char *name);
RZ_API bool rz_name_validate_char(const char ch);

#ifdef __cplusplus
}
#endif

#endif //  RZ_NAME_H
