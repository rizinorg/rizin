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

struct rz_bin_mdmp_obj {
	struct minidump_header *hdr;

	/* Encountered streams */
	struct minidump_streams {
		ut8 *comments_a;
		ut8 *comments_w;

		struct minidump_exception_stream *exception;
		struct minidump_function_table_stream *function_table;
		struct minidump_handle_data_stream *handle_data;
		struct minidump_system_info *system_info;

		union {
			struct minidump_misc_info *misc_info_1;
			struct minidump_misc_info_2 *misc_info_2;
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
	RzList *pe32_bins;
	RzList *pe64_bins;

	RzBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
};

struct rz_bin_mdmp_obj *rz_bin_mdmp_new_buf(RzBuffer *buf);
void rz_bin_mdmp_free(struct rz_bin_mdmp_obj *obj);
ut64 rz_bin_mdmp_get_paddr(struct rz_bin_mdmp_obj *obj, ut64 vaddr);
ut32 rz_bin_mdmp_get_perm(struct rz_bin_mdmp_obj *obj, ut64 vaddr);
struct minidump_memory_info *rz_bin_mdmp_get_mem_info(struct rz_bin_mdmp_obj *obj, ut64 vaddr);

#endif /* MDMP_H */
