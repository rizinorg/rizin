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

RZ_API RZ_OWN RzCompareData *rz_core_cmp_mem_mem(RzCore *core, ut64 addr1, ut64 addr2, ut32 len);
RZ_API RZ_OWN RzCompareData *rz_core_cmp_mem_data(RzCore *core, ut64 addr, RZ_NONNULL const ut8 *data, ut32 len);
RZ_API int rz_core_cmp_print(RzCore *core, RZ_NONNULL const RzCompareData *cmp, RzCmdStateOutput *state);
RZ_API RZ_OWN RzList /*<RzCompareData *>*/ *rz_core_cmp_disasm(RzCore *core, ut64 addr1, ut64 addr2, ut32 len);
RZ_API void rz_core_cmp_free(RzCompareData *cmp);
RZ_API bool rz_core_cmp_disasm_print(RzCore *core, const RzList /*<RzCompareData *>*/ *compare, bool unified);

/**
 * \struct RzCoreCmpWatcher
 * \brief Watcher which executes a command when listed
 */
typedef struct rz_core_cmpwatch_t {
	ut64 addr; ///< Address of the watcher
	int size; ///< Size of the watcher
	char cmd[32]; ///< Command to be executed by the watcher
	ut8 *odata; ///< original data at the given address
	ut8 *ndata; ///< New data at the given address
} RzCoreCmpWatcher;

/* watchers */
RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w);
RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr);
RZ_API bool rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd);
RZ_API bool rz_core_cmpwatch_del(RzCore *core, ut64 addr);
RZ_API bool rz_core_cmpwatch_update(RzCore *core, ut64 addr);
RZ_API void rz_core_cmpwatch_show(RzCore *core, ut64 addr, RzOutputMode mode);
RZ_API bool rz_core_cmpwatch_revert(RzCore *core, ut64 addr);

#ifdef __cplusplus
}
#endif

#endif /* RZ_CMP_H */
