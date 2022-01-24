// SPDX-FileCopyrightText: 2014-2015 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_DOWNLOADER_H
#define PDB_DOWNLOADER_H

#include <rz_types.h>
#include <rz_bin.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SPDBOptions {
	const char *symbol_server;
	const char *symbol_store_path;
	ut64 extract;
} SPDBOptions;

typedef struct SPDBDownloaderOpt {
	const char *symbol_server;
	const char *dbg_file;
	const char *guid;
	const char *symbol_store_path;
	ut64 extract;
} SPDBDownloaderOpt;

typedef struct SPDBDownloader {
	SPDBDownloaderOpt *opt;

	char *(*download)(struct SPDBDownloader *pdb_downloader);
} SPDBDownloader;

RZ_API int rz_bin_pdb_download(RZ_NONNULL RzBin *bin, RZ_NULLABLE PJ *pj, int isradjson, RZ_NONNULL SPDBOptions *options);
RZ_API RZ_OWN char *rz_bin_symserver_download(RZ_NONNULL const SPDBDownloaderOpt *options);

#ifdef __cplusplus
}
#endif

#endif
