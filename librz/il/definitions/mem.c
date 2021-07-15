#include "mem.h"

static void free_bv_key_value(HtPPKv *kv) {
	bv_free(kv->value);
	bv_free(kv->key);
}

Mem rz_il_new_mem(int min_unit_size) {
	Mem ret = (Mem)RZ_NEW0(struct mem_t);

	HtPPOptions options = { 0 };
	options.cmp = (HtPPListComparator)bv_cmp;
	options.hashfn = (HtPPHashFunction)bv_hash;
	options.dupkey = (HtPPDupKey)bv_dump;
	options.dupvalue = (HtPPDupValue)bv_dump;
	options.freefn = (HtPPKvFreeFunc)free_bv_key_value;
	options.elem_size = sizeof(HtPPKv);
	HtPP *mem_map = ht_pp_new_opt(&options);

	ret->kv_map = mem_map;
	ret->min_unit_size = min_unit_size;

	return ret;
}

void rz_il_free_mem(Mem mem) {
	if (!mem) {
		return;
	}

	ht_pp_free(mem->kv_map);
	free(mem);
}

Mem rz_il_mem_store(Mem mem, BitVector key, BitVector value) {
	if (value->len != mem->min_unit_size) {
		printf("[Type Not Matched]\n");
		return NULL;
	}
	ht_pp_update(mem->kv_map, key, value);
	return mem;
}

BitVector rz_il_mem_load(Mem mem, BitVector key) {
	BitVector val = ht_pp_find(mem->kv_map, key, NULL);
	BitVector ret = bv_dump(val);
	return ret;
}
