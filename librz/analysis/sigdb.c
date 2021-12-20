#include <rz_analysis.h>

static void analysis_sigdb_signature_free(RzAnalysisSignature *sig) {
	if (!sig) {
		return;
	}
	// base_name points to file_path, so there is no need to call free
	// short_path points to file_path, so there is no need to call free
	free(sig->bin_name);
	free(sig->arch_name);
	free(sig->file_path);
	free(sig);
}

static bool analysis_sigdb_signature_resolve_details(RzAnalysisSignature *sig, size_t path_len) {
	char *bin_end = NULL;
	char *arch_end = NULL;
	char *bits_end = NULL;
	char info[1024] = { 0 };

	// expected path elf/x86/64/signature.sig/.pat
	strncpy(info, sig->file_path + path_len, sizeof(info) - 1);
	sig->base_name = rz_file_basename(sig->file_path);
	sig->short_path = sig->file_path + path_len;

	if (!(bin_end = strstr(info, RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing bin name).\n");
		return false;
	} else if (!(arch_end = strstr(bin_end + strlen(RZ_SYS_DIR), RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing arch name).\n");
		return false;
	} else if (!(bits_end = strstr(arch_end + strlen(RZ_SYS_DIR), RZ_SYS_DIR))) {
		RZ_LOG_WARN("sigdb: folder structure is invalid (missing arch bits).\n");
		return false;
	}

	bin_end[0] = 0;
	sig->bin_name = strdup(info);
	arch_end[0] = 0;
	sig->arch_name = strdup(bin_end + strlen(RZ_SYS_DIR));
	bits_end[0] = 0;
	sig->arch_bits = atoi(arch_end + strlen(RZ_SYS_DIR));
	return true;
}

RZ_API RzList /*<RzAnalysisSignature>*/ *rz_analysis_sigdb_load_database(RZ_NONNULL const char *sigdb_path) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(sigdb_path), NULL);
	char glob[1024];
	if (!rz_file_is_directory(sigdb_path)) {
		RZ_LOG_ERROR("Cannot sigdb path is unknown or invalid (path: %s)\n", sigdb_path);
		return NULL;
	}
	size_t path_len = strlen(sigdb_path) + 1; // ignoring also the filesystem separator
	RzList *sigs = rz_list_newf((RzListFree)analysis_sigdb_signature_free);
	if (!sigs) {
		rz_warn_if_reached();
		return NULL;
	}

	rz_strf(glob, RZ_JOIN_2_PATHS("%s", "**"), sigdb_path);

	RzList *files = rz_file_globsearch(glob, 10);
	char *file = NULL;
	RzListIter *iter = NULL;
	RzAnalysisSignature *sig = NULL;

	rz_list_foreach (files, iter, file) {
		if (!rz_str_endswith(file, ".pat") && !rz_str_endswith(file, ".sig")) {
			continue;
		}

		sig = RZ_NEW0(RzAnalysisSignature);
		if (!sig) {
			goto fail;
		}

		sig->file_path = strdup(file);
		if (!sig->file_path || !analysis_sigdb_signature_resolve_details(sig, path_len)) {
			analysis_sigdb_signature_free(sig);
			goto fail;
		}
		rz_list_append(sigs, sig);
	}
	rz_list_free(files);
	return sigs;

fail:
	rz_list_free(sigs);
	return NULL;
}
