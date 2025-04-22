// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flirt.h>

/**
 * \brief      Frees a RzSigDBEntry structure
 *
 * \param[in]  entry The RzSigDBEntry to free
 */
RZ_API void rz_sign_sigdb_signature_free(RZ_NULLABLE RzSigDBEntry *entry) {
	if (!entry) {
		return;
	}
	// base_name points to file_path, so there is no need to call free
	// short_path points to file_path, so there is no need to call free
	free(entry->bin_name);
	free(entry->arch_name);
	free(entry->file_path);
	free(entry);
}

static int sigdb_signature_cmp(const RzSigDBEntry *a, const RzSigDBEntry *b, void *user) {
	return strcmp(a->short_path, b->short_path);
}

static bool sigdb_signature_resolve_details(RzSigDBEntry *entry, size_t path_len, bool with_details) {
	char *bin_end = NULL;
	char *arch_end = NULL;
	char *bits_end = NULL;
	char copy_path[1024] = { 0 };
	RzFlirtNode *node = NULL;
	RzFlirtInfo info = { 0 };
	RzBuffer *buffer = NULL;

#if __WINDOWS__
	rz_str_replace_char(entry->file_path, '/', '\\');
#endif
	// expected path elf/x86/64/signature.sig/.pat
	strncpy(copy_path, entry->file_path + path_len, sizeof(copy_path) - 1);
	entry->base_name = rz_file_basename(entry->file_path);
	entry->short_path = entry->file_path + path_len;

	if (!(bin_end = strstr(copy_path, RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing bin name).\n");
		return false;
	} else if (!(arch_end = strstr(bin_end + strlen(RZ_SYS_DIR), RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing arch name).\n");
		return false;
	} else if (!(bits_end = strstr(arch_end + strlen(RZ_SYS_DIR), RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing arch bits).\n");
		return false;
	}

	if (!with_details) {
		goto skip_details;
	}

	buffer = rz_buf_new_file(entry->file_path, O_RDONLY, 0);
	if (!buffer) {
		RZ_LOG_WARN("sigdb: cannot open signature file '%s'.\n", entry->file_path);
		return false;
	}

	if (rz_str_endswith(entry->base_name, ".sig")) {
		bool success = rz_sign_flirt_parse_header_compressed_pattern_from_buffer(buffer, &info);
		rz_buf_free(buffer);
		if (!success) {
			return false;
		}

		entry->details = RZ_STR_DUP(info.u.sig.name);
		entry->n_modules = info.u.sig.n_modules;
	} else {
		node = rz_sign_flirt_parse_string_pattern_from_buffer(buffer, RZ_FLIRT_NODE_OPTIMIZE_NONE, &info);
		rz_buf_free(buffer);
		if (!node) {
			return false;
		}

		entry->n_modules = info.u.pat.n_modules;
	}
	rz_sign_flirt_node_free(node);
	rz_sign_flirt_info_fini(&info);

skip_details:
	bin_end[0] = 0;
	entry->bin_name = rz_str_dup(copy_path);
	arch_end[0] = 0;
	entry->arch_name = rz_str_dup(bin_end + strlen(RZ_SYS_DIR));
	bits_end[0] = 0;
	entry->arch_bits = rz_get_input_num_value(NULL, arch_end + strlen(RZ_SYS_DIR));

	return true;
}

/**
 * \brief Returns a database of signatures loaded from the signature database path
 *
 * \param  sigdb_path    The signature database path/location
 * \param  with_details  When true, opens each signature within the db for extra details
 * \return List of entries
 */
RZ_API RZ_OWN RzSigDb *rz_sign_sigdb_load_database(RZ_NONNULL const char *sigdb_path, bool with_details) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(sigdb_path), NULL);
	char glob[1024];
	if (!rz_file_is_directory(sigdb_path)) {
		RZ_LOG_ERROR("sigdb path is unknown or invalid (path: %s)\n", sigdb_path);
		return NULL;
	}
	size_t path_len = strlen(sigdb_path) + 1; // ignoring also the filesystem separator
	RzSigDb *sigs = rz_sign_sigdb_new();
	if (!sigs) {
		RZ_LOG_ERROR("cannot allocate signature database\n");
		return NULL;
	}

	rz_strf(glob, RZ_JOIN_2_PATHS("%s", "**"), sigdb_path);
	RzList *files = rz_file_globsearch(glob, 10);
	char *file = NULL;
	RzListIter *iter = NULL;
	RzSigDBEntry *sig = NULL;

	rz_list_foreach (files, iter, file) {
		if (!rz_str_endswith(file, ".pat") && !rz_str_endswith(file, ".sig")) {
			continue;
		}

		sig = RZ_NEW0(RzSigDBEntry);
		if (!sig) {
			goto fail;
		}

		sig->file_path = rz_str_dup(file);
		if (!sig->file_path || !sigdb_signature_resolve_details(sig, path_len, with_details)) {
			rz_sign_sigdb_signature_free(sig);
			goto fail;
		}
		rz_sign_sigdb_add_entry(sigs, sig);
	}
	rz_list_free(files);
	return sigs;

fail:
	rz_list_free(files);
	rz_sign_sigdb_free(sigs);
	return NULL;
}

/**
 * \brief Add a new signature entry to a database
 *
 * \param db Database of signatures
 * \param entry Single signature entry to add to the database
 * \return true if the signature entry was correctly added to the database, false otherwise
 */
RZ_API bool rz_sign_sigdb_add_entry(RZ_NONNULL RzSigDb *db, RZ_NONNULL const RzSigDBEntry *entry) {
	rz_return_val_if_fail(db && entry, false);
	return ht_pu_insert(db->entries, entry, 1);
}

struct sigdb_move_data_t {
	RzSigDb *src;
	RzSigDb *dst;
};

static bool sigdb_move_entry(void *user, const void *k, const ut64 v) {
	struct sigdb_move_data_t *move_data = (struct sigdb_move_data_t *)user;
	rz_sign_sigdb_add_entry(move_data->dst, k);
	ht_pu_delete(move_data->src->entries, k);
	return true;
}

/**
 * \brief Merge the signatures from \p db2 into \p db
 *
 * Data within \p db2 is moved into \p db, making it empty.
 *
 * \param db Database of signatures to extend
 * \param db2 Database of signatures that need to be merged into \p db
 * \return true if the databases were correctly merged, false otherwise
 */
RZ_API bool rz_sign_sigdb_merge(RZ_NONNULL RzSigDb *db, RZ_NONNULL RzSigDb *db2) {
	rz_return_val_if_fail(db && db2, false);
	struct sigdb_move_data_t opt = {
		.src = db2,
		.dst = db,
	};
	db2->entries->opt.finiKV = NULL;
	ht_pu_foreach(db2->entries, sigdb_move_entry, &opt);
	return true;
}

static int ut32cmp(int a, int b) {
	if (a < b) {
		return -1;
	}
	if (a > b) {
		return 1;
	}
	return 0;
}

static int strcmp_null(const char *a, const char *b) {
	if (!a && !b) {
		return 0;
	}
	if (!a && b) {
		return -1;
	}
	if (a && !b) {
		return 1;
	}
	return strcmp(a, b);
}

static int sigdb_entry_cmp(const void *a, const void *b) {
#define field_cmp(fname, cmpfunction) \
	do { \
		int r = cmpfunction(sa->fname, sb->fname); \
		if (r != 0) { \
			return r; \
		} \
	} while (0)

	const RzSigDBEntry *sa = (const RzSigDBEntry *)a;
	const RzSigDBEntry *sb = (const RzSigDBEntry *)b;
	field_cmp(bin_name, strcmp_null);
	field_cmp(arch_name, strcmp_null);
	field_cmp(arch_bits, ut32cmp);
	field_cmp(base_name, strcmp_null);
	field_cmp(short_path, strcmp_null);
	field_cmp(file_path, strcmp_null);
	field_cmp(details, strcmp_null);
	field_cmp(n_modules, ut32cmp);
	return 0;
#undef field_cmp
}

static ut32 sigdb_entry_hash(const void *k) {
	const RzSigDBEntry *s = (const RzSigDBEntry *)k;
	ut32 r = sdb_hash(s->bin_name);
	r ^= sdb_hash(s->arch_name);
	r ^= s->arch_bits;
	r ^= sdb_hash(s->short_path);
	return r;
}

static void ht_pu_sigdb_finikv(HtPUKv *kv, RZ_UNUSED void *user) {
	if (!kv) {
		return;
	}
	rz_sign_sigdb_signature_free(kv->key);
}

/**
 * \brief Create a new empty \p RzSigDb instance
 */
RZ_API RZ_OWN RzSigDb *rz_sign_sigdb_new(void) {
	RzSigDb *db = RZ_NEW0(RzSigDb);
	if (!db) {
		return NULL;
	}
	HtPUOptions opt = { 0 };
	opt.cmp = sigdb_entry_cmp,
	opt.hashfn = sigdb_entry_hash,
	opt.finiKV = ht_pu_sigdb_finikv;
	db->entries = ht_pu_new_opt(&opt);
	if (!db->entries) {
		free(db);
		return NULL;
	}
	return db;
}

RZ_API void rz_sign_sigdb_free(RzSigDb *db) {
	if (!db) {
		return;
	}
	ht_pu_free(db->entries);
	free(db);
}

static bool sigdb_to_list(void *user, const void *k, const ut64 v) {
	RzList *l = (RzList *)user;
	rz_list_append(l, (void *)k);
	return true;
}

/**
 * \brief Return the signature database as a list of entries
 */
RZ_API RZ_OWN RzList /*<RzSigDBEntry *>*/ *rz_sign_sigdb_list(RZ_NONNULL const RzSigDb *db) {
	rz_return_val_if_fail(db, NULL);

	RzList *res = rz_list_newf((RzListFree)rz_sign_sigdb_signature_free);
	if (!res) {
		return NULL;
	}
	ht_pu_foreach(db->entries, sigdb_to_list, res);
	rz_list_sort(res, (RzListComparator)sigdb_signature_cmp, NULL);
	return res;
}
