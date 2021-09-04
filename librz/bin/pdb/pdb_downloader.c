// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_util.h>
#include <rz_core.h>
#include "pdb_downloader.h"

static bool checkExtract(void) {
#if __WINDOWS__
	return rz_sys_system("expand -? >nul") == 0;
#else
	return rz_sys_system("cabextract -v > /dev/null") == 0;
#endif
}

static bool download_and_write(SPDBDownloaderOpt *opt, const char *file) {
	char *dir = rz_str_newf("%s%s%s%s%s",
		opt->symbol_store_path, RZ_SYS_DIR,
		opt->dbg_file, RZ_SYS_DIR,
		opt->guid);
	if (!rz_sys_mkdirp(dir)) {
		free(dir);
		return false;
	}
	char *url = rz_str_newf("%s/%s/%s/%s", opt->symbol_server, opt->dbg_file, opt->guid, file);
	char *path = rz_str_newf("%s%s%s", dir, RZ_SYS_DIR, opt->dbg_file);
#if __WINDOWS__
	if (rz_str_startswith(url, "\\\\")) { // Network path
		wchar_t *origin = rz_utf8_to_utf16(url);
		wchar_t *dest = rz_utf8_to_utf16(path);
		BOOL ret = CopyFileW(origin, dest, FALSE);
		free(dir);
		free(path);
		free(origin);
		free(dest);
		return ret;
	}
#endif
	int len;
	char *file_buf = rz_socket_http_get(url, NULL, &len);
	free(url);
	if (!len || RZ_STR_ISEMPTY(file_buf)) {
		free(dir);
		free(file_buf);
		free(path);
		return false;
	}
	FILE *f = fopen(path, "wb");
	if (f) {
		fwrite(file_buf, sizeof(char), (size_t)len, f);
		fclose(f);
	}
	free(dir);
	free(path);
	free(file_buf);
	return true;
}

static int download(struct SPDBDownloader *pd) {
	SPDBDownloaderOpt *opt = pd->opt;
	int res = 0;
	int cmd_ret;

	if (!opt->dbg_file || !*opt->dbg_file) {
		// no pdb debug file
		return 0;
	}

	char *abspath_to_file = rz_str_newf("%s%s%s%s%s%s%s",
		opt->symbol_store_path, RZ_SYS_DIR,
		opt->dbg_file, RZ_SYS_DIR,
		opt->guid, RZ_SYS_DIR,
		opt->dbg_file);

	if (rz_file_exists(abspath_to_file)) {
		eprintf("File already downloaded.\n");
		free(abspath_to_file);
		return 1;
	}

	if (checkExtract() || opt->extract == 0) {
		char *extractor_cmd = NULL;
		char *archive_name = strdup(opt->dbg_file);
		archive_name[strlen(archive_name) - 1] = '_';
		char *abspath_to_archive = rz_str_newf("%s%s%s%s%s%s%s",
			opt->symbol_store_path, RZ_SYS_DIR,
			opt->dbg_file, RZ_SYS_DIR,
			opt->guid, RZ_SYS_DIR,
			archive_name);

		eprintf("Attempting to download compressed pdb in %s\n", abspath_to_archive);
		char *abs_arch_esc = rz_str_escape_sh(abspath_to_archive);
#if __WINDOWS__
		char *abs_file_esc = rz_str_escape_sh(abspath_to_file);
		// expand %1 %2
		// %1 - absolute path to archive
		// %2 - absolute path to file that will be dearchive
		extractor_cmd = rz_str_newf("expand \"%s\" \"%s\"", abs_arch_esc, abs_file_esc);
		free(abs_file_esc);
#else
		char *abspath_to_dir = rz_file_dirname(abspath_to_archive);
		char *abs_dir_esc = rz_str_escape_sh(abspath_to_dir);
		// cabextract -d %1 %2
		// %1 - path to directory where to extract all files from cab archive
		// %2 - absolute path to cab archive
		extractor_cmd = rz_str_newf("cabextract -d \"%s\" \"%s\"", abs_arch_esc, abs_dir_esc);
		free(abs_dir_esc);
		free(abspath_to_dir);
#endif
		free(abs_arch_esc);
		res = download_and_write(opt, archive_name);

		if (opt->extract > 0 && res) {
			eprintf("Attempting to decompress pdb\n");
			if (res && ((cmd_ret = rz_sys_system(extractor_cmd)) != 0)) {
				eprintf("cab extractor exited with error %d\n", cmd_ret);
				res = 0;
			}
			rz_file_rm(abspath_to_archive);
		}
		free(archive_name);
		free(abspath_to_archive);
		free(extractor_cmd);
	}
	if (res == 0) {
		eprintf("Falling back to uncompressed pdb\n");
		eprintf("Attempting to download uncompressed pdb in %s\n", abspath_to_file);
		res = download_and_write(opt, opt->dbg_file);
	}
	free(abspath_to_file);
	return res;
}

void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pd) {
	pd->opt = RZ_NEW0(SPDBDownloaderOpt);
	if (!pd->opt) {
		pd->download = 0;
		eprintf("Cannot allocate memory for SPDBDownloaderOpt.\n");
		return;
	}
	pd->opt->dbg_file = strdup(opt->dbg_file);
	pd->opt->guid = strdup(opt->guid);
	pd->opt->symbol_server = strdup(opt->symbol_server);
	pd->opt->user_agent = strdup(opt->user_agent);
	pd->opt->symbol_store_path = strdup(opt->symbol_store_path);
	pd->opt->extract = opt->extract;
	pd->download = download;
}

void deinit_pdb_downloader(SPDBDownloader *pd) {
	RZ_FREE(pd->opt->dbg_file);
	RZ_FREE(pd->opt->guid);
	RZ_FREE(pd->opt->symbol_server);
	RZ_FREE(pd->opt->user_agent);
	RZ_FREE(pd->opt->symbol_store_path);
	RZ_FREE(pd->opt);
	pd->download = 0;
}

static bool is_valid_guid(const char *guid) {
	if (!guid) {
		return false;
	}
	size_t i;
	for (i = 0; guid[i]; i++) {
		if (!isxdigit(guid[i])) {
			return false;
		}
	}
	return i >= 33; // len of GUID and age
}

int rz_bin_pdb_download(RzCore *core, PJ *pj, int isradjson, SPDBOptions *options) {
	int ret = 1;
	SPDBDownloaderOpt opt;
	SPDBDownloader pdb_downloader;
	RzBinInfo *info = rz_bin_get_info(core->bin);

	if (!info || !info->debug_file_name) {
		eprintf("Can't find debug filename\n");
		return 1;
	}

	if (!is_valid_guid(info->guid)) {
		eprintf("Invalid GUID for file\n");
		return 1;
	}

	if (!options || !options->symbol_server || !options->user_agent) {
		eprintf("Can't retrieve pdb configurations\n");
		return 1;
	}

	opt.dbg_file = rz_file_basename(info->debug_file_name);
	opt.guid = info->guid;
	opt.user_agent = options->user_agent;
	opt.symbol_store_path = options->symbol_store_path;
	opt.extract = options->extract;
	char *symbol_server = strdup(options->symbol_server);
	char *server = strtok(symbol_server, ";");
	while (server && ret) {
		opt.symbol_server = server;
		init_pdb_downloader(&opt, &pdb_downloader);
		ret = pdb_downloader.download ? pdb_downloader.download(&pdb_downloader) : 1;
		deinit_pdb_downloader(&pdb_downloader);
		server = strtok(NULL, ";");
	}
	free(symbol_server);

	if (isradjson) {
		pj_ko(pj, "pdb");
		pj_ks(pj, "file", opt.dbg_file);
		pj_kb(pj, "download", (bool)ret);
		pj_end(pj);
	} else {
		rz_cons_printf("PDB \"%s\" download %s\n",
			opt.dbg_file, ret ? "success" : "failed");
	}

	return !ret;
}
