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
	ut8 *data1;
	ut8 *data2;
	ut64 addr1;
	ut64 addr2;
	bool same;
} RzCompareData;

RZ_API int rz_cmp_compare(RzCore *core, const ut8 *addr, int len, RzCompareOutputMode mode);
RZ_API RZ_OWN RzList /*<RzCompareData>*/ *rz_cmp_disasm(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input);
RZ_API bool rz_cmp_disasm_print(RzCore *core, const RzList /*<RzCompareData>*/ *compare, bool unified);

#endif /* RZ_CMP_H */
