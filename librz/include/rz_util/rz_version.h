#ifndef RZ_VERSION_H
#define RZ_VERSION_H

#include "rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_version_gittip();
RZ_API RZ_OWN char *rz_version_str(const char *program);

#ifdef __cplusplus
}
#endif

#endif // RZ_VERSION_H
