// SPDX-FileCopyrightText: 2014-2015 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_DOWNLOADER_H
#define PDB_DOWNLOADER_H

#include <rz_types.h>
#include <rz_core.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SPDBOptions {
	const char *user_agent;
	const char *symbol_server;
	const char *symbol_store_path;
	ut64 extract;
} SPDBOptions;

typedef struct SPDBDownloaderOpt {
	const char *user_agent;
	const char *symbol_server;
	const char *dbg_file;
	const char *guid;
	const char *symbol_store_path;
	ut64 extract;
} SPDBDownloaderOpt;

typedef struct SPDBDownloader {
	SPDBDownloaderOpt *opt;

	int (*download)(struct SPDBDownloader *pdb_downloader);
} SPDBDownloader;

///
/// \brief initialization of pdb downloader by SPDBDownloaderOpt
/// \param opt PDB options
/// \param pdb_downloader PDB downloader that will be init
///
void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pdb_downloader);

///
/// \brief deinitialization of PDB downloader
/// \param pdb_downloader PDB downloader that will be deinit
///
void deinit_pdb_downloader(SPDBDownloader *pdb_downloader);

///
/// \brief download PDB file
RZ_API int rz_bin_pdb_download(RzCore *core, PJ *pj, int isradjson, SPDBOptions *options);

#ifdef __cplusplus
}
#endif

#endif
