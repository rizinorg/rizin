// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool read_gnu_hash_table(ELFOBJ *bin, RzBinElfGnuHashTable *result) {
	ut64 offset = result->offset;

	return Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.nbuckets) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.symoffset) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.bloom_size) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.bloom_shift);
}

static bool read_hash_table(ELFOBJ *bin, RzBinElfHashTable *result) {
	ut64 offset = result->offset;

	return Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.nbuckets) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &result->data.nchains);
}

static size_t get_highest_chain_index_in_gnu_hash_table_buckets(ELFOBJ *bin, RzBinElfGnuHashTable *table, ut64 bucket_offset) {
	size_t result = 0;

	for (Elf_(Word) i = 0; i < table->data.nbuckets; i++) {
		Elf_(Word) tmp;
		if (!Elf_(rz_bin_elf_read_word)(bin, &bucket_offset, &tmp)) {
			RZ_LOG_WARN("Failed to read the GNU hash table (DT_GNU_HASH) bucket at 0x%" PFMT64x ".\n", bucket_offset);
			return 0;
		}

		result = RZ_MAX(result, tmp);
	}

	return result;
}

static size_t get_highest_symbol_index_in_gnu_hash_table_chains(ELFOBJ *bin, RzBinElfGnuHashTable *table, ut64 chain_offset, size_t index) {
	if (index < table->data.symoffset) {
		return 0;
	}

	Elf_(Word) chain_index = index - table->data.symoffset;
	chain_offset += chain_index * sizeof(Elf_(Word));

	while (1) {
		index++;

		Elf_(Word) tmp;
		if (!Elf_(rz_bin_elf_read_word)(bin, &chain_offset, &tmp)) {
			RZ_LOG_WARN("Failed to read the GNU hash table (DT_GNU_HASH) chain at 0x%" PFMT64x ".\n", chain_offset);
			return 0;
		}

		if (tmp & 1) {
			break;
		}
	}

	return index;
}

bool Elf_(rz_bin_elf_get_gnu_hash_table)(RZ_NONNULL ELFOBJ *bin, RzBinElfGnuHashTable *result) {
	rz_return_val_if_fail(bin && result, false);

	ut64 addr;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_GNU_HASH, &addr)) {
		return false;
	}

	result->offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (result->offset == UT64_MAX) {
		return false;
	}

	if (!read_gnu_hash_table(bin, result)) {
		RZ_LOG_WARN("Failed to read the GNU hash table (DT_GNU_HASH) at 0x%" PFMT64x ".\n", result->offset);
		return false;
	}

	return true;
}

bool Elf_(rz_bin_elf_get_hash_table)(RZ_NONNULL ELFOBJ *bin, RzBinElfHashTable *result) {
	rz_return_val_if_fail(bin && result, false);

	ut64 addr;
	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_HASH, &addr)) {
		return false;
	}

	result->offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (result->offset == UT64_MAX) {
		return false;
	}

	if (!read_hash_table(bin, result)) {
		RZ_LOG_WARN("Failed to read the hash table (DT_HASH) at 0x%" PFMT64x ".\n", result->offset);
		return false;
	}

	return true;
}

size_t Elf_(rz_bin_elf_get_number_of_symbols_from_gnu_hash_table)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	RzBinElfGnuHashTable table;
	if (!Elf_(rz_bin_elf_get_gnu_hash_table)(bin, &table)) {
		return 0;
	}

	ut64 bloom_offset = table.offset + sizeof(struct gnu_hash_table);
	ut64 bucket_offset = bloom_offset + table.data.bloom_size * sizeof(Elf_(Addr));
	ut64 chain_offset = bucket_offset + table.data.nbuckets * sizeof(Elf_(Word));

	size_t index = get_highest_chain_index_in_gnu_hash_table_buckets(bin, &table, bucket_offset);
	return get_highest_symbol_index_in_gnu_hash_table_chains(bin, &table, chain_offset, index);
}

size_t Elf_(rz_bin_elf_get_number_of_symbols_from_hash_table)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	RzBinElfHashTable table;
	if (!Elf_(rz_bin_elf_get_hash_table)(bin, &table)) {
		return 0;
	}

	return table.data.nchains;
}
