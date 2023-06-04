// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

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
