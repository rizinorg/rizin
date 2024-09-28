// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_arch.h>

#include "rz_arch_plugins.h"

RZ_LIB_VERSION(rz_arch);

static RzArchPlugin *arch_static_plugins[] = { RZ_ARCH_STATIC_PLUGINS };

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins() {
	return RZ_ARRAY_SIZE(arch_static_plugins);
}

RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_asm;
}

RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_analysis;
}

RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index]->p_parse;
}

RZ_API RzArchPlugin *rz_arch_get_plugins(size_t index) {
	if (index >= RZ_ARRAY_SIZE(arch_static_plugins)) {
		return NULL;
	}
	return arch_static_plugins[index];
}

RZ_API int rz_arch_target_cmp(const void *a, const void *b) {
	const RzArchTarget *target_a = a;
	const RzArchTarget *target_b = b;
	int cmp = strcmp(target_a->arch, target_b->arch);
	if (cmp != 0) {
		return cmp;
	}
	cmp = strcmp(target_a->cpu, target_b->cpu);
	if (cmp != 0) {
		return cmp;
	}
	return target_a->bits - target_b->bits;
}

RZ_API RzArchTarget *rz_arch_target_new(const char *arch, const char *cpu, int bits) {
	RzArchTarget *target = RZ_NEW0(RzArchTarget);
	target->arch = strdup(arch);
	target->cpu = strdup(cpu);
	target->bits = bits;
	return target;
}

RZ_API RzArchTarget *rz_arch_target_clone(const RzArchTarget *target) {
	RzArchTarget *new_target = rz_arch_target_new(target->arch, target->cpu, target->bits);
	return new_target;
}

RZ_API void rz_arch_target_free(RzArchTarget *target) {
	free(target->arch);
	free(target->cpu);
	free(target);
}

RZ_API void rz_arch_instance_free(RzArchInstance *instance) {
	rz_arch_target_free(instance->target);
	instance->plugin->fini_instance(instance);
	free(instance);
}

RZ_API RzArchInstance *rz_arch_instantiate(RzArch *arch, const RzArchTarget *target) {
	RzArchInstance *instance = RZ_NEW0(RzArchInstance);
	instance->target = rz_arch_target_clone(target);

	for (int i = 0; i < rz_arch_get_n_plugins(); ++i) {
		RzArchPlugin *plugin = rz_arch_get_plugins(i);
		if (!plugin->support_target(plugin, target)) {
			continue;
		}

		bool found = false;
		void *plugin_data = ht_up_find(arch->plugin_datas, (ut64)target, &found);
		instance->plugin = plugin;
		instance->plugin_data = plugin_data;
		plugin->init_instance(instance, target);
		return instance;
	}

	rz_arch_instance_free(instance);
	return NULL;
}

static void finiKV_instances(HtPPKv *kv, void *user) {
	RzArchTarget *target = kv->key;
	rz_arch_target_free(target);

	RzArchInstance *instance = kv->value;
	rz_arch_instance_free(instance);
}

static void finiKV_plugin_datas(HtUPKv *kv, void *user) {
	RzArchPlugin *plugin = (RzArchPlugin *)kv->key;
	plugin->fini(kv->value);
}

RZ_API RzArch *rz_arch_new() {
	RzArch *arch = RZ_NEW0(RzArch);
	HtPPOptions instances_opt = {
		.cmp = rz_arch_target_cmp,
		.dupkey = (HtPPDupKey)rz_arch_target_clone,
		.finiKV = finiKV_instances,
	};
	arch->instances = ht_pp_new_opt(&instances_opt);

	HtUPOptions plugin_datas_opt = {
		.finiKV = finiKV_plugin_datas,
	};
	arch->plugin_datas = ht_up_new_opt(&plugin_datas_opt);

	for (int i = 0; i < rz_arch_get_n_plugins(); ++i) {
		RzArchPlugin *plugin = rz_arch_get_plugins(i);
		void *data = NULL;
		plugin->init(&data);
		ht_up_update(arch->plugin_datas, (ut64)plugin, data);
	}
	return arch;
}

RZ_API void rz_arch_free(RzArch *arch) {
	ht_pp_free(arch->instances);
	ht_up_free(arch->plugin_datas);
	free(arch);
}

RZ_API RzArchInstance *rz_arch_instance_pool_get(RzArch *arch, const RzArchTarget *target) {
	bool found = false;
	RzArchInstance *instance = ht_pp_find(arch->instances, target, &found);
	if (found && instance) {
		return instance;
	}
	instance = rz_arch_instantiate(arch, target);
	ht_pp_update(arch->instances, target, instance);
	return instance;
}

RZ_API int rz_arch_instance_xcode(RzArchInstance *instance, RzArchOp *op, int input_bits, int output_bits) {
	return instance->plugin->xcode(instance, op, input_bits, output_bits);
}