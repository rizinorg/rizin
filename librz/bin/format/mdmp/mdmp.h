// SPDX-FileCopyrightText: 2016 Davis
// SPDX-FileCopyrightText: 2016 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MDMP_H
#define MDMP_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "mdmp_specs.h"
#include "mdmp_pe.h"
#include "mdmp_pe64.h"

typedef struct minidump_object_t {
	MiniDmpHeader *hdr;

	/* Encountered streams */
	struct minidump_streams {
		ut8 *comments_a;
		ut8 *comments_w;

		MiniDmpExcStream *exception;
		MiniDmpFuncTableStream *function_table;
		MiniDmpHandleDataStream *handle_data;
		MiniDmpSysInfo *system_info;

		union {
			MiniDmpMiscInfo *misc_info_1;
			MiniDmpMiscInfo2 *misc_info_2;
		} misc_info;

		/* Lists */
		RzList *ex_threads;
		RzList *memories;
		RzList *memory_infos;
		RzList *modules;
		RzList *operations;
		RzList *thread_infos;
		RzList *threads;
		RzList *token_infos;
		RzList *unloaded_modules;
		struct {
			rva64_t base_rva;
			RzList *memories;
		} memories64;
	} streams;

	/* Binary memory objects */
	RzList /*<struct Pe32_rz_bin_mdmp_pe_bin *>*/ *pe32_bins;
	RzList /*<struct Pe64_rz_bin_mdmp_pe_bin *>*/ *pe64_bins;

	RzBuffer *b;
	size_t size;
	Sdb *kv;
} MiniDmpObj;

MiniDmpObj *rz_bin_mdmp_new_buf(RzBuffer *buf);
void rz_bin_mdmp_free(MiniDmpObj *obj);
ut64 rz_bin_mdmp_get_paddr(MiniDmpObj *obj, ut64 vaddr);
ut32 rz_bin_mdmp_get_perm(MiniDmpObj *obj, ut64 vaddr);
MiniDmpMemInfo *rz_bin_mdmp_get_mem_info(MiniDmpObj *obj, ut64 vaddr);

#endif /* MDMP_H */
