#ifndef RZ_NAME_H
#define RZ_NAME_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API bool rz_name_check(const char *name, bool strict);
RZ_API bool rz_name_filter(char *name, int len, bool strict);
RZ_API char *rz_name_filter2(const char *name, bool strict);
RZ_API bool rz_name_validate_char(const char ch, bool strict);

#ifdef __cplusplus
}
#endif

#endif //  RZ_NAME_H
