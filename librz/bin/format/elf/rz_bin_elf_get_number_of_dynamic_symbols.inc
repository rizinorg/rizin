// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define HASH_NCHAIN_OFFSET(x) ((x) + 4)

static size_t get_number_of_symbols_from_hash(ELFOBJ *bin) {
	if (bin->dyn_info.dt_hash == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 hash_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_hash);
	if (hash_offset == UT64_MAX) {
		return 0;
	}

	ut64 nchain_offset = HASH_NCHAIN_OFFSET(hash_offset);
	ut64 result = BREAD32(bin->b, nchain_offset);

	return result == UT32_MAX ? 0 : result;
}

static ut64 get_index_from_buckets(ELFOBJ *bin, ut64 *bucket_offset, ut64 number_of_bucket) {
	ut64 index = 0;

	for (size_t i = 0; i < number_of_bucket; i++) {
		ut64 tmp = BREAD32(bin->b, *bucket_offset);
		index = RZ_MAX(index, tmp);
	}

	return index;
}

static ut64 get_index_from_chain(ELFOBJ *bin, ut64 bucket_offset, ut64 symbol_base, ut64 index) {
	ut64 chain_index = index - symbol_base;
	ut64 chain_offset = bucket_offset + chain_index * 4;

	while (1) {
		index++;
		size_t tmp = BREAD32(bin->b, chain_offset);

		if (tmp & 1) {
			break;
		}
	}

	return index;
}

static size_t get_number_of_symbols_from_gnu_hash(ELFOBJ *bin) {
	if (bin->dyn_info.dt_gnu_hash == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 hash_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_gnu_hash);
	if (hash_offset == UT64_MAX) {
		return 0;
	}

	size_t pos = hash_offset;

	ut64 number_of_bucket = BREAD32(bin->b, pos);
	ut64 symbol_base = BREAD32(bin->b, pos);
	ut64 bitmask_nwords = BREAD32(bin->b, pos);
	ut64 bucket_offset = hash_offset + 16 + bitmask_nwords * RZ_BIN_ELF_WORDSIZE;

	ut64 index = get_index_from_buckets(bin, &bucket_offset, number_of_bucket);

	if (!index) {
		return 0;
	}

	return get_index_from_chain(bin, bucket_offset, symbol_base, index);
}

static size_t get_number_of_symbols_from_heuristic(ELFOBJ *bin) {
	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX && bin->dyn_info.dt_strtab == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 symtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_symtab);
	ut64 strtab_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_strtab);
	if (symtab_offset == UT64_MAX || strtab_offset == UT64_MAX) {
		return 0;
	}

	if (symtab_offset > strtab_offset) {
		return 0;
	}

	ut64 symtab_size = strtab_offset - symtab_offset;
	return symtab_size / sizeof(Elf_(Sym));
}

RZ_IPI size_t Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	size_t result = get_number_of_symbols_from_hash(bin);
	if (result) {
		return result;
	}

	result = get_number_of_symbols_from_gnu_hash(bin);
	if (result) {
		return result;
	}

	return get_number_of_symbols_from_heuristic(bin);
}
