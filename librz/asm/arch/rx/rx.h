#ifndef RZ_ARCH_RX_H
#define RZ_ARCH_RX_H

#include <rz_util.h>
#include "rx_inst.h"

bool rx_dis(RxInst RZ_OUT *inst, size_t RZ_OUT *bytes_read, const ut8 *buf, size_t buf_len);

#endif
