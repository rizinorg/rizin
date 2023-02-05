#ifndef RZ_PROTOBUF_H
#define RZ_PROTOBUF_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_protobuf_decode(RZ_NULLABLE const ut8 *buffer, const ut64 size, bool debug);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PROTOBUF_H */
