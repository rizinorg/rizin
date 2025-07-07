#ifndef RZ_BASE85_H
#define RZ_BASE85_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API void rz_base85_encode(FILE *fp, int delims, int wrap, int y_abbr);
RZ_API bool rz_base85_decode(FILE *fp, int delims, int ignore_garbage);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE85_H
