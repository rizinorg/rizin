// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CMP_H
#define RZ_CMP_H

#include <rz_core.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	ut32 len; // max 255 bytes diff in one struct
	bool same;
	ut8 *data1;
	ut8 *data2;
	ut64 addr1;
	ut64 addr2;
} RzCompareData;

RZ_API RZ_OWN RzCompareData *rz_cmp_mem_mem(RZ_NONNULL RzCore *core, ut64 addr1, ut64 addr2, ut32 len);
RZ_API RZ_OWN RzCompareData *rz_cmp_mem_data(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL const ut8 *data, ut32 len);
RZ_API int rz_cmp_print(RZ_NONNULL RzCore *core, RZ_NONNULL const RzCompareData *cmp, RzOutputMode mode);
RZ_API RZ_OWN RzList /*<RzCompareData>*/ *rz_cmp_disasm(RZ_NONNULL RzCore *core, ut64 addr1, ut64 addr2, ut32 len);
RZ_API bool rz_cmp_disasm_print(RzCore *core, const RzList /*<RzCompareData>*/ *compare, bool unified);

#endif /* RZ_CMP_H */
