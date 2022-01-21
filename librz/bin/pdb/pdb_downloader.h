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

/**
 * \brief initialization of pdb downloader by SPDBDownloaderOpt
 *
 * \param opt PDB options
 * \param pdb_downloader PDB downloader that will be init
 */
void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pdb_downloader);
/**
 * \brief deinitialization of PDB downloader
 *
 * \param pdb_downloader PDB downloader that will be deinit
 */
void deinit_pdb_downloader(SPDBDownloader *pdb_downloader);
/**
 * \brief download PDB file
 */
RZ_API int rz_bin_pdb_download(RzBin *bin, PJ *pj, int isradjson, SPDBOptions *options);
/**
 * \brief downloads file from symbol server
 * \param options options for downloading file
 * \return char* is the path that file was downloaded to or NULL in case of failure
 */
RZ_API char *rz_bin_symserver_download(const SPDBDownloaderOpt *options);

#ifdef __cplusplus
}
#endif

#endif
