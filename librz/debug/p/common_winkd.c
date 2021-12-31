// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "common_winkd.h"
#include <bin/pdb/pdb_downloader.h>

static char *download_pdb(const char *path, const char *symserver, const char *symstore) {
	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}
	RzBin *bin = NULL;
	RzIO *io = rz_io_new();
	if (!io) {
		goto end;
	}
	bin = rz_bin_new();
	if (!bin) {
		goto end;
	}
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bin->filter_rules = RZ_BIN_REQ_INFO;
	if (!rz_bin_open(bin, path, &opt)) {
		goto end;
	}
	pj_o(pj);
	SPDBOptions opts = { .extract = 1, .symbol_server = symserver, .symbol_store_path = symstore };
	rz_bin_pdb_download(bin, pj, true, &opts);
	pj_end(pj);
end:
	rz_bin_free(bin);
	rz_io_free(io);
	return pj_drain(pj);
}

bool winkd_download_module_and_pdb(WindModule *module, const char *symserver, const char *symstore, char **exepath, char **pdbpath) {
	if (exepath) {
		*exepath = NULL;
	}
	if (pdbpath) {
		*pdbpath = NULL;
	}
	char *sum = rz_str_newf("%08" PFMT32x "%" PFMT32x, module->timestamp, module->size);
	const char *file = rz_str_rchr(module->name, NULL, '\\') + 1;
	SPDBDownloaderOpt opts = {
		.dbg_file = file, .extract = true, .guid = sum, .symbol_server = symserver, .symbol_store_path = symstore
	};
	char *executable = rz_bin_symserver_download(&opts);
	free(sum);
	if (!executable) {
		return false;
	}
	char *res = download_pdb(executable, symserver, symstore);
	if (exepath) {
		*exepath = executable;
	} else {
		free(executable);
	}
	RzJson *json = rz_json_parse(res);
	if (!json) {
		return false;
	}
	const RzJson *pdb = rz_json_get(json, "pdb");
	if (!pdb) {
		return false;
	}
	const RzJson *ppath = rz_json_get(pdb, "path");
	if (!ppath) {
		return false;
	}
	if (pdbpath) {
		*pdbpath = strdup(ppath->str_value);
	}
	rz_json_free(json);
	free(res);
	return true;
}
