// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "common_winkd.h"
#include <bin/pdb/pdb_downloader.h>

void winkd_build_profile(WindCtx *ctx, RzTypeDB *db) {
	ctx->profile = RZ_NEW0(Profile);
	if (!ctx->profile) {
		return;
	}
#define O_(n) ctx->profile->f[n]
	O_(E_ActiveProcessLinks) = rz_type_db_struct_member_offset(db, "_EPROCESS", "ActiveProcessLinks");
	O_(E_UniqueProcessId) = rz_type_db_struct_member_offset(db, "_EPROCESS", "UniqueProcessId");
	O_(E_Peb) = rz_type_db_struct_member_offset(db, "_EPROCESS", "Peb");
	O_(E_ImageFileName) = rz_type_db_struct_member_offset(db, "_EPROCESS", "ImageFileName");
	O_(E_VadRoot) = rz_type_db_struct_member_offset(db, "_EPROCESS", "VadRoot");
	O_(E_ThreadListHead) = rz_type_db_struct_member_offset(db, "_EPROCESS", "ThreadListHead");
	O_(K_DirectoryTableBase) = rz_type_db_struct_member_offset(db, "_KPROCESS", "DirectoryTableBase");
	O_(P_ImageBaseAddress) = rz_type_db_struct_member_offset(db, "_PEB", "ImageBaseAddress");
	O_(P_ProcessParameters) = rz_type_db_struct_member_offset(db, "_PEB", "ProcessParameters");
	O_(RZ_ImagePathName) = rz_type_db_struct_member_offset(db, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName");
	O_(ET_ThreadListEntry) = rz_type_db_struct_member_offset(db, "_ETHREAD", "ThreadListEntry");
	O_(ET_Win32StartAddress) = rz_type_db_struct_member_offset(db, "_ETHREAD", "Win32StartAddress");
	O_(ET_Cid) = rz_type_db_struct_member_offset(db, "_ETHREAD", "Cid");
	O_(C_UniqueThread) = rz_type_db_struct_member_offset(db, "_CLIENT_ID", "UniqueThread");
	RZ_LOG_VERBOSE("_EPROCESS.ActiveProcessLinks: 0x%" PFMT32x "\n", O_(E_ActiveProcessLinks));
	RZ_LOG_VERBOSE("_EPROCESS.UniqueProcessId: 0x%" PFMT32x "\n", O_(E_UniqueProcessId));
	RZ_LOG_VERBOSE("_EPROCESS.Peb: 0x%" PFMT32x "\n", O_(E_Peb));
	RZ_LOG_VERBOSE("_EPROCESS.ImageFileName: 0x%" PFMT32x "\n", O_(E_ImageFileName));
	RZ_LOG_VERBOSE("_EPROCESS.VadRoot: 0x%" PFMT32x "\n", O_(E_VadRoot));
	RZ_LOG_VERBOSE("_EPROCESS.ThreadListHead: 0x%" PFMT32x "\n", O_(E_ThreadListHead));
	RZ_LOG_VERBOSE("_KPROCESS.DirectoryTableBase: 0x%" PFMT32x "\n", O_(K_DirectoryTableBase));
	RZ_LOG_VERBOSE("_PEB.ImageBaseAddress: 0x%" PFMT32x "\n", O_(P_ImageBaseAddress));
	RZ_LOG_VERBOSE("_PEB.ProcessParameters: 0x%" PFMT32x "\n", O_(P_ProcessParameters));
	RZ_LOG_VERBOSE("_RTL_USER_PROCESS_PARAMETERS.ImagePathName: 0x%" PFMT32x "\n", O_(RZ_ImagePathName));
	RZ_LOG_VERBOSE("_ETHREAD.ThreadListEntry: 0x%" PFMT32x "\n", O_(ET_ThreadListEntry));
	RZ_LOG_VERBOSE("_ETHREAD.Win32StartAddress: 0x%" PFMT32x "\n", O_(ET_Win32StartAddress));
	RZ_LOG_VERBOSE("_ETHREAD.Cid: 0x%" PFMT32x "\n", O_(ET_Cid));
	RZ_LOG_VERBOSE("_CLIENT_ID.UniqueThread: 0x%" PFMT32x "\n", O_(C_UniqueThread));
#undef O_
}

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
	RZ_LOG_INFO("Downloading module and pdb for '%s'\n", file);
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
		*pdbpath = rz_str_dup(ppath->str_value);
	}
	rz_json_free(json);
	free(res);
	return true;
}
