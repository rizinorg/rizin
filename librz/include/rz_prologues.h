// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PROLOGUES_GENERATOR_H
#define RZ_PROLOGUES_GENERATOR_H

#include <rz_core.h>

#define RZ_PROLOGUE_DEFAULT_LEN               16
#define RZ_PROLOGUE_DEFAULT_ENTROPY_THRESHOLD 0.8

typedef struct rz_prologue_t {
	RZ_OWN ut8 *bytes; ///< prologue's bytes buffer
	RZ_OWN ut8 *mask; ///< prologue's mask buffer, 0 = dont care bit
} RzPrologue;

typedef struct rz_prologues_arch_info_t {
	RZ_NULLABLE RZ_OWN char *arch; ///< target arch or NULL for autodetect from bininfo
	int bits; ///< target bitness or 0 for autodetect from bininfo
	bool big_endian; ///< target endianness
} RzProloguesArchInfo;

RZ_API void rz_prologues_arch_info_init(RZ_BORROW RZ_NONNULL RzProloguesArchInfo *arch_info,
	RZ_NULLABLE const char *arch, int bits, bool big_endian);
RZ_API void rz_prologues_arch_info_fini(RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *arch_info);

RZ_API bool rz_prologues_arch_check(RZ_BORROW RZ_NONNULL const RzBinInfo *info, RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *target_arch);

RZ_API RZ_OWN RzTrie *rz_prologues_trie_new(void);

RZ_API bool rz_prologues_trie_feed_binfile(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, RZ_BORROW RZ_NONNULL RzBinFile *binfile, ut64 prologue_len,
	RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_BORROW RZ_NULLABLE RzSetS *processed_files);
RZ_API st64 rz_prologues_trie_feed_all_binfiles(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, RZ_BORROW RZ_NONNULL RzBin *bin, ut64 prologue_len,
	RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_BORROW RZ_NULLABLE RzSetS *processed_files);
RZ_API bool rz_prologues_trie_feed_file(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, RZ_BORROW RZ_NONNULL RzBin *bin, RZ_NONNULL const char *file_path,
	ut64 prologue_len, RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_BORROW RZ_NULLABLE RzSetS *processed_files);
RZ_API st64 rz_prologues_trie_feed_directory(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, RZ_BORROW RZ_NONNULL RzBin *bin, RZ_NONNULL const char *dir_path,
	ut64 prologue_len, RZ_BORROW RZ_NULLABLE RzProloguesArchInfo *arch_info, RZ_BORROW RZ_NULLABLE RzSetS *processed_files);

RZ_API RZ_OWN RzVector /*<RzPrologue>*/ *rz_prologues_generalize_and_extract(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, ut64 prologue_len, double entropy_threshold);
RZ_API RZ_OWN RzVector /*<RzPrologue>*/ *rz_prologues_extract_raw_from_trie(RZ_BORROW RZ_NONNULL RzTrie *pg_trie, ut64 prologue_len);

RZ_API RZ_OWN RzStructuredData *rz_prologues_trie_to_structured_data(RZ_BORROW RZ_NONNULL const RzTrie *pg_trie,
	ut64 prologue_len, RZ_BORROW RZ_NULLABLE const RzProloguesArchInfo *arch_info, RZ_BORROW RZ_NULLABLE const RzSetS *files);
RZ_API RZ_OWN RzStructuredData *rz_prologues_to_structured_data(RZ_BORROW RZ_NONNULL const RzVector /*<RzPrologue>*/ *prologues,
	ut64 prologue_len, RZ_BORROW RZ_NULLABLE const RzProloguesArchInfo *arch_info);

#endif // RZ_PROLOGUES_GENERATOR_H
