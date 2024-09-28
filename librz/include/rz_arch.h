// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_types.h>
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_arch);

struct rz_arch_target_t;
struct rz_arch_op_t;
struct rz_arch_instance_t;

typedef struct rz_arch_plugin_t {
	RZ_DEPRECATE RzAsmPlugin *p_asm; ///< Assembly Plugin
	RZ_DEPRECATE RzAnalysisPlugin *p_analysis; ///< Analysis Plugin
	RZ_DEPRECATE RzParsePlugin *p_parse; ///< Parse Plugin

	void (*init)(void **plugin_data); // plugin-global, returns plugin-wide data
	void (*fini)(void *plugin_data); // plugin-global, gets plugin-wide data
	bool (*support_target)(void *plugin_data, const struct rz_arch_target_t *target);
	void (*init_instance)(struct rz_arch_instance_t *instance, const struct rz_arch_target_t *target); // per-instance
	void (*fini_instance)(struct rz_arch_instance_t *instance); // per-instance
	int (*xcode)(struct rz_arch_instance_t *instance, struct rz_arch_op_t *op, ut64 input_bits, ut64 output_bits);
} RzArchPlugin;

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins();
RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index);
RZ_API RzArchPlugin *rz_arch_get_plugins(size_t index);

typedef enum {
	RZ_ARCH_OP_MEMBER_BYTES = 1 << 0,
	RZ_ARCH_OP_MEMBER_DISASM = 1 << 1,
	RZ_ARCH_OP_MEMBER_JMP_TARGETS = 1 << 2,
	RZ_ARCH_OP_MEMBER_ALL = ~0,
} RzArchOpMember;

typedef struct rz_arch_op_t {
	RzStrBuf bytes;
	char *disasm;
	ut64 jmp;
	ut64 fail;
	RzAnalysisLiftedILOp il_op;
} RzArchOp;

typedef struct rz_arch_t {
	HtPP /*<RzArchTarget *, RzArchInstance *>*/ *instances;
	HtUP /*<RzArchPlugin *, void *>*/ *plugin_datas;
} RzArch;

typedef struct rz_arch_target_t {
	char *arch;
	char *cpu;
	int bits;
} RzArchTarget;

typedef struct rz_arch_instance_t {
	RzArchTarget *target;
	RzArchPlugin *plugin;
	void *plugin_data;
	void *instance_data;
} RzArchInstance;

RZ_API int rz_arch_target_cmp(const void *a, const void *b);
RZ_API RzArchTarget *rz_arch_target_new(const char *arch, const char *cpu, int bits);
RZ_API RzArchTarget *rz_arch_target_clone(const RzArchTarget *target);
RZ_API void rz_arch_target_free(RzArchTarget *target);
RZ_API void rz_arch_instance_free(RzArchInstance *instance);
RZ_API RzArchInstance *rz_arch_instantiate(RzArch *arch, const RzArchTarget *target);
RZ_API RzArch *rz_arch_new();
RZ_API void rz_arch_free(RzArch *arch);
RZ_API RzArchInstance *rz_arch_instance_pool_get(RzArch *arch, const RzArchTarget *target);
RZ_API int rz_arch_instance_xcode(RzArchInstance *instance, RzArchOp *op, int input_bits, int output_bits);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ARCH_H */
