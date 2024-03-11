// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_RX_H
#define RZ_ARCH_RX_H

#include <rz_util.h>
#include "rx_inst.h"

RZ_API bool rx_dis(RZ_NONNULL RxInst RZ_OUT *inst, RZ_NONNULL st32 RZ_OUT *bytes_read, RZ_NONNULL const ut8 *buf, size_t buf_len);
bool rx_inst_stringify(RxInst *inst, RzStrBuf *buf);

#endif
