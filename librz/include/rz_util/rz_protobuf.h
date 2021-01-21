#ifndef RZ_PROTOBUF_H
#define RZ_PROTOBUF_H

#ifdef __cplusplus
extern "C" {
#endif

RZ_API char *rz_protobuf_decode(const ut8 *buffer, const ut64 size, bool debug);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PROTOBUF_H */
