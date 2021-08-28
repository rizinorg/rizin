// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/mem.h>

static void free_bv_key_value(HtPPKv *kv) {
	rz_il_bv_free(kv->value);
	rz_il_bv_free(kv->key);
}

RZ_API RzILMem rz_il_new_mem(int min_unit_size) {
	RzILMem ret = (RzILMem)RZ_NEW0(struct rzil_mem_t);
	if (!ret) {
		return NULL;
	}

	HtPPOptions options = { 0 };
	options.cmp = (HtPPListComparator)rz_il_bv_cmp;
	options.hashfn = (HtPPHashFunction)rz_il_bv_hash;
	options.dupkey = (HtPPDupKey)rz_il_bv_dup;
	options.dupvalue = (HtPPDupValue)rz_il_bv_dup;
	options.freefn = (HtPPKvFreeFunc)free_bv_key_value;
	options.elem_size = sizeof(HtPPKv);
	HtPP *mem_map = ht_pp_new_opt(&options);

	ret->kv_map = mem_map;
	ret->min_unit_size = min_unit_size;

	return ret;
}

RZ_API void rz_il_free_mem(RzILMem mem) {
	if (!mem) {
		return;
	}

	ht_pp_free(mem->kv_map);
	free(mem);
}

RZ_API RzILMem rz_il_mem_store(RzILMem mem, RzILBitVector key, RzILBitVector value) {
	if (value->len != mem->min_unit_size) {
		printf("[Type Not Matched]\n");
		return NULL;
	}
	ht_pp_update(mem->kv_map, key, value);
	return mem;
}

RZ_API RzILBitVector rz_il_mem_load(RzILMem mem, RzILBitVector key) {
	RzILBitVector val = ht_pp_find(mem->kv_map, key, NULL);
	if (val == NULL) {
		return NULL;
	}
	RzILBitVector ret = rz_il_bv_dup(val);
	return ret;
}
