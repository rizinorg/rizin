// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PROLOGUES_GENERATOR_H
#define RZ_PROLOGUES_GENERATOR_H

#include <rz_core.h>

typedef struct rz_prologue_t {
	ut8 *bytes; ///< prologue's bytes buffer
	ut8 *mask; ///< prologue's mask buffer, 0 = dont care bit
} RzPrologue;

RZ_API RZ_OWN RzTrie *rz_prologues_trie_new(void);

RZ_API bool rz_prologues_trie_feed_binfile(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBinFile *binfile, ut64 prologue_len);
RZ_API st64 rz_prologues_trie_feed_all_binfiles(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBin *bin, ut64 prologue_len,
	RZ_NULLABLE const char *arch, int bits, bool big_endian, RZ_NULLABLE RzSetS *processed_files);
RZ_API st64 rz_prologues_trie_feed_directory(RZ_NONNULL RzTrie *pg_trie, RZ_NONNULL RzBin *bin, RZ_NONNULL const char *dir_path,
	ut64 prologue_len, RZ_NULLABLE const char *arch, int bits, bool big_endian, RZ_NULLABLE RzSetS *processed_files);

RZ_API RZ_OWN RzVector /*<RzPrologue>*/ *rz_prologues_generalize(RzTrie *pg_trie, ut64 prologue_len, double entropy_threshold);

RZ_API RZ_OWN RzStructuredData *rz_prologues_trie_to_structured_data(RZ_NONNULL const RzTrie *pg_trie,
	ut64 prologue_len, RZ_NULLABLE const char *arch, int bits, bool big_endian, RZ_NULLABLE const RzSetS *files);
RZ_API RZ_OWN RzStructuredData *rz_prologues_to_structured_data(RZ_NONNULL const RzVector /*<RzPrologue>*/ *prologues,
	ut64 prologue_len, RZ_NULLABLE const char *arch, int bits, bool big_endian);

#endif // RZ_PROLOGUES_GENERATOR_H
