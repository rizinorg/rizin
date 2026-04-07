// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_cons.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include "ar.h"

typedef struct {
	const char *outdir;
	bool list_only;
	bool quiet;
} RzArOptions;

#define RZ_AR_EXTRACT_CHUNK_SIZE 0x10000

static void rz_ar_show_help(void) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-ar [-hlqv] [-o outdir] archive [member ...]\n");
	// clang-format off
	const char *options[] = {
		"-h", "", "Show this help",
		"-l", "", "List matching members",
		"-o", "dir", "Set output directory (default .)",
		"-q", "", "Quiet mode",
		"-v", "", "Show version information",
	};
	// clang-format on
	rz_print_colored_help(options, RZ_ARRAY_SIZE(options), false);
}

static char *rz_ar_normalize_member_path(const char *name) {
	rz_return_val_if_fail(name, NULL);
	char *tmp = rz_file_path_local_to_unix(name);
	if (!tmp) {
		return NULL;
	}
	rz_str_replace_char(tmp, '\\', '/');
	RzList *parts = rz_str_split_duplist(tmp, "/", false);
	if (!parts) {
		free(tmp);
		return NULL;
	}
	RzList *stack = rz_list_newf(free);
	if (!stack) {
		rz_list_free(parts);
		free(tmp);
		return NULL;
	}
	RzListIter *it;
	char *part;
	rz_list_foreach (parts, it, part) {
		if (RZ_STR_ISEMPTY(part) || RZ_STR_EQ(part, ".")) {
			continue;
		}
		if (RZ_STR_EQ(part, "..")) {
			char *prev = rz_list_pop(stack);
			free(prev);
			continue;
		}
		char *tok = rz_str_dup(part);
		if (!tok) {
			rz_list_free(stack);
			rz_list_free(parts);
			free(tmp);
			return NULL;
		}
		for (char *p = tok; *p; p++) {
			if (*p == ':' || !IS_PRINTABLE(*p)) {
				*p = '_';
			}
		}
		if (!rz_list_append(stack, tok)) {
			free(tok);
			rz_list_free(stack);
			rz_list_free(parts);
			free(tmp);
			return NULL;
		}
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	bool first = true;
	rz_list_foreach (stack, it, part) {
		if (!first) {
			rz_strbuf_append(&sb, "/");
		}
		rz_strbuf_append(&sb, part);
		first = false;
	}
	char *out = NULL;
	if (!rz_strbuf_is_empty(&sb)) {
		out = rz_strbuf_drain_nofree(&sb);
	}
	rz_strbuf_fini(&sb);
	rz_list_free(stack);
	rz_list_free(parts);
	free(tmp);
	return out;
}

static bool rz_ar_member_matches(const char *member_name, const char *normalized_name, const char **filters, int nfilters) {
	rz_return_val_if_fail(member_name && normalized_name, false);
	if (!nfilters || !filters) {
		return true;
	}
	const char *member_base = rz_file_basename(member_name);
	const char *normalized_base = rz_file_basename(normalized_name);
	for (int i = 0; i < nfilters; i++) {
		const char *f = filters[i];
		if (RZ_STR_EQ(f, member_name) || RZ_STR_EQ(f, normalized_name) || RZ_STR_EQ(f, member_base) || RZ_STR_EQ(f, normalized_base)) {
			return true;
		}
	}
	return false;
}

static char *rz_ar_unique_output_path(const char *path) {
	rz_return_val_if_fail(path, NULL);
	if (!rz_file_exists(path) && !rz_file_is_directory(path)) {
		return rz_str_dup(path);
	}
	for (int i = 1;; i++) {
		char *candidate = rz_str_newf("%s.%d", path, i);
		if (!candidate) {
			return NULL;
		}
		if (!rz_file_exists(candidate) && !rz_file_is_directory(candidate)) {
			return candidate;
		}
		free(candidate);
	}
}

static bool rz_ar_extract_member(RzArFp *member, const char *dst_path) {
	rz_return_val_if_fail(member && dst_path, false);
	const ut64 size = member->end - member->start;
	if (size == 0) {
		return rz_file_dump(dst_path, NULL, 0, false);
	}
	ut8 *buf = malloc(RZ_AR_EXTRACT_CHUNK_SIZE);
	if (!buf) {
		return false;
	}
	ut64 off = 0;
	bool append = false;
	while (off < size) {
		const ut64 left = size - off;
		const int want = (int)RZ_MIN(left, (ut64)RZ_AR_EXTRACT_CHUNK_SIZE);
		const int got = ar_read_at(member, off, buf, want);
		if (got <= 0) {
			break;
		}
		if (!rz_file_dump(dst_path, buf, got, append)) {
			off = 0;
			break;
		}
		append = true;
		off += got;
	}
	free(buf);
	return off == size;
}

RZ_API int rz_main_rz_ar(int argc, const char **argv) {
	RzGetopt opt;
	RzArOptions options = {
		.outdir = ".",
		.list_only = false,
		.quiet = false,
	};
	int c;
	rz_getopt_init(&opt, argc, argv, "hlo:qv");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'h':
			rz_ar_show_help();
			return 0;
		case 'l':
			options.list_only = true;
			break;
		case 'o':
			options.outdir = opt.arg;
			break;
		case 'q':
			options.quiet = true;
			break;
		case 'v': {
			RzPath *sys_path = rz_path_new();
			if (!sys_path) {
				return 1;
			}
			int ret = rz_main_version_print(sys_path, "rz-ar");
			rz_path_free(sys_path);
			return ret;
		}
		default:
			RZ_LOG_ERROR("rz-ar: invalid option -%c\n", c);
			rz_ar_show_help();
			return 1;
		}
	}
	if (opt.ind >= argc) {
		RZ_LOG_ERROR("rz-ar: missing archive path\n");
		rz_ar_show_help();
		return 1;
	}
	const char *archive_path = argv[opt.ind++];
	const char **filters = argc > opt.ind ? &argv[opt.ind] : NULL;
	const int nfilters = argc - opt.ind;
	RzList *members = ar_open_all(archive_path, O_RDONLY | O_BINARY);
	if (!members) {
		RZ_LOG_ERROR("rz-ar: cannot open archive '%s'\n", archive_path);
		return 1;
	}
	if (!options.list_only && !rz_sys_mkdirp(options.outdir)) {
		RZ_LOG_ERROR("rz-ar: cannot create output directory '%s'\n", options.outdir);
		rz_list_free(members);
		return 1;
	}
	int matched = 0;
	int extracted = 0;
	int failed = 0;
	RzListIter *it;
	RzArFp *member;
	rz_list_foreach (members, it, member) {
		char *normalized_name = rz_ar_normalize_member_path(member->name);
		if (!normalized_name) {
			failed++;
			continue;
		}
		if (!rz_ar_member_matches(member->name, normalized_name, filters, nfilters)) {
			free(normalized_name);
			continue;
		}
		matched++;
		if (options.list_only) {
			printf("%s\n", normalized_name);
			free(normalized_name);
			continue;
		}
		char *dst = rz_file_path_join(options.outdir, normalized_name);
		free(normalized_name);
		if (!dst) {
			failed++;
			continue;
		}
		char *unique_dst = rz_ar_unique_output_path(dst);
		free(dst);
		if (!unique_dst) {
			failed++;
			continue;
		}
		char *dir = rz_file_dirname(unique_dst);
		if (!dir || !rz_sys_mkdirp(dir)) {
			free(dir);
			free(unique_dst);
			failed++;
			continue;
		}
		free(dir);
		if (!rz_ar_extract_member(member, unique_dst)) {
			RZ_LOG_ERROR("rz-ar: failed to extract '%s'\n", unique_dst);
			free(unique_dst);
			failed++;
			continue;
		}
		extracted++;
		if (!options.quiet) {
			printf("%s\n", unique_dst);
		}
		free(unique_dst);
	}
	rz_list_free(members);
	if (matched == 0) {
		RZ_LOG_ERROR("rz-ar: no matching members\n");
		return 1;
	}
	if (!options.list_only && !options.quiet) {
		printf("extracted %d file(s)%s\n", extracted, failed ? " with failures" : "");
	}
	return failed ? 1 : 0;
}
