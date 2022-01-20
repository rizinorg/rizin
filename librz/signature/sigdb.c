// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flirt.h>

static void sigdb_signature_free(RzSigDBEntry *entry) {
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

static int sigdb_signature_cmp(RzSigDBEntry *a, RzSigDBEntry *b) {
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

	buffer = rz_buf_new_slurp(entry->file_path);
	if (!buffer) {
		RZ_LOG_WARN("sigdb: cannot open .sig file '%s'.\n", entry->file_path);
		return false;
	}

	if (rz_str_endswith(entry->base_name, ".sig")) {
		node = rz_sign_flirt_parse_compressed_pattern_from_buffer(buffer, RZ_FLIRT_SIG_ARCH_ANY, &info);
		rz_buf_free(buffer);
		if (!node) {
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
	entry->bin_name = strdup(copy_path);
	arch_end[0] = 0;
	entry->arch_name = strdup(bin_end + strlen(RZ_SYS_DIR));
	bits_end[0] = 0;
	entry->arch_bits = rz_get_input_num_value(NULL, arch_end + strlen(RZ_SYS_DIR));

	return true;
}

/**
 * \brief Returns a list of entries within the signature database path
 *
 * \param  sigdb_path    The signature database path/location
 * \param  with_details  When true, opens each signature within the db for extra details
 * \return List of entries
 */
RZ_API RZ_OWN RzList /*<RzSigDBEntry>*/ *rz_sign_sigdb_load_database(RZ_NONNULL const char *sigdb_path, bool with_details) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(sigdb_path), NULL);
	char glob[1024];
	if (!rz_file_is_directory(sigdb_path)) {
		RZ_LOG_ERROR("sigdb path is unknown or invalid (path: %s)\n", sigdb_path);
		return NULL;
	}
	size_t path_len = strlen(sigdb_path) + 1; // ignoring also the filesystem separator
	RzList *sigs = rz_list_newf((RzListFree)sigdb_signature_free);
	if (!sigs) {
		rz_warn_if_reached();
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

		sig->file_path = strdup(file);
		if (!sig->file_path || !sigdb_signature_resolve_details(sig, path_len, with_details)) {
			sigdb_signature_free(sig);
			goto fail;
		}
		rz_list_append(sigs, sig);
	}
	rz_list_free(files);
	rz_list_sort(sigs, (RzListComparator)sigdb_signature_cmp);
	return sigs;

fail:
	rz_list_free(sigs);
	return NULL;
}
