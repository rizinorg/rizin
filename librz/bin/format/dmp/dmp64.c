// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

#include "dmp64.h"

static int rz_bin_dmp64_init_memory_runs(struct rz_bin_dmp64_obj_t *obj) {
	int i, j;
	dmp64_p_memory_desc *mem_desc = &obj->header->PhysicalMemoryBlockBuffer;
	if (!memcmp(mem_desc, DMP_UNUSED_MAGIC, 4)) {
		eprintf("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	ut64 num_runs = mem_desc->NumberOfRuns;
	if (num_runs * sizeof(dmp_p_memory_run) >= rz_offsetof(dmp64_header, ContextRecord)) {
		eprintf("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	obj->pages = rz_list_newf(free);
	if (!obj->pages) {
		return false;
	}
	dmp_p_memory_run *runs = calloc(num_runs, sizeof(dmp_p_memory_run));
	ut64 num_runs_offset = rz_offsetof(dmp64_header, PhysicalMemoryBlockBuffer) + rz_offsetof(dmp64_p_memory_desc, NumberOfRuns);
	if (rz_buf_read_at(obj->b, num_runs_offset, (ut8 *)runs, num_runs * sizeof(dmp_p_memory_run)) < 0) {
		eprintf("Warning: read memory runs\n");
		free(runs);
		return false;
	};

	ut64 num_page = 0;
	ut64 base = sizeof(dmp64_header);
	for (i = 0; i < num_runs; i++) {
		dmp_p_memory_run *run = &(runs[i]);
		for (j = 0; j < run->PageCount; j++) {
			dmp_page_desc *page = RZ_NEW0(dmp_page_desc);
			if (!page) {
				free(runs);
				return false;
			}
			page->start = (run->BasePage + j) * DMP_PAGE_SIZE;
			page->file_offset = base + num_page * DMP_PAGE_SIZE;
			rz_list_append(obj->pages, page);
			num_page++;
		}
	}
	if (mem_desc->NumberOfPages != num_page) {
		eprintf("Warning: Number of Pages not matches\n");
	}

	free(runs);
	return true;
}

static int rz_bin_dmp64_init_header(struct rz_bin_dmp64_obj_t *obj) {
	if (!(obj->header = RZ_NEW0(dmp64_header))) {
		rz_sys_perror("RZ_NEW0 (header)");
		return false;
	}
	if (rz_buf_read_at(obj->b, 0, (ut8 *)obj->header, sizeof(dmp64_header)) < 0) {
		eprintf("Warning: read header\n");
		return false;
	}
	obj->dtb = obj->header->DirectoryTableBase;

	return true;
}

static int rz_bin_dmp64_init_bmp_pages(struct rz_bin_dmp64_obj_t *obj) {
	int i;
	if (!obj->bmp_header) {
		return false;
	}
	obj->pages = rz_list_newf(free);
	if (!obj->pages) {
		return false;
	}
	ut64 paddr_base = obj->bmp_header->FirstPage;
	ut64 num_pages = obj->bmp_header->Pages;
	RzBitmap *bitmap = rz_bitmap_new(num_pages);
	rz_bitmap_set_bytes(bitmap, obj->bitmap, num_pages / 8);

	ut64 num_bitset = 0;
	for (i = 0; i < num_pages; i++) {
		if (!rz_bitmap_test(bitmap, i)) {
			continue;
		}
		dmp_page_desc *page = RZ_NEW0(dmp_page_desc);
		if (!page) {
			return false;
		}
		page->start = i * DMP_PAGE_SIZE;
		page->file_offset = paddr_base + num_bitset * DMP_PAGE_SIZE;
		rz_list_append(obj->pages, page);
		num_bitset++;
	}
	if (obj->bmp_header->TotalPresentPages != num_bitset) {
		eprintf("Warning: TotalPresentPages not matched\n");
		return false;
	}

	rz_bitmap_free(bitmap);
	return true;
}

static int rz_bin_dmp64_init_bmp_header(struct rz_bin_dmp64_obj_t *obj) {
	if (!(obj->bmp_header = RZ_NEW0(dmp_bmp_header))) {
		rz_sys_perror("RZ_NEW0 (dmp_bmp_header)");
		return false;
	}
	if (rz_buf_read_at(obj->b, sizeof(dmp64_header), (ut8 *)obj->bmp_header, offsetof(dmp_bmp_header, Bitmap)) < 0) {
		eprintf("Warning: read bmp_header\n");
		return false;
	}
	if (!!memcmp(obj->bmp_header, DMP_BMP_MAGIC, 8)) {
		eprintf("Warning: Invalid Bitmap Magic\n");
		return false;
	}
	ut64 bitmapsize = obj->bmp_header->Pages / 8;
	obj->bitmap = calloc(1, bitmapsize);
	if (rz_buf_read_at(obj->b, sizeof(dmp64_header) + offsetof(dmp_bmp_header, Bitmap), obj->bitmap, bitmapsize) < 0) {
		eprintf("Warning: read bitmap\n");
		return false;
	}

	return true;
}

static int rz_bin_dmp64_init(struct rz_bin_dmp64_obj_t *obj) {
	if (!rz_bin_dmp64_init_header(obj)) {
		eprintf("Warning: Invalid Kernel Dump x64 Format\n");
		return false;
	}
	switch (obj->header->DumpType) {
	case DMP_DUMPTYPE_BITMAPFULL:
	case DMP_DUMPTYPE_BITMAPKERNEL:
		rz_bin_dmp64_init_bmp_header(obj);
		rz_bin_dmp64_init_bmp_pages(obj);
		break;
	case DMP_DUMPTYPE_FULL:
		rz_bin_dmp64_init_memory_runs(obj);
		break;
	default:
		break;
	}

	return true;
}

void rz_bin_dmp64_free(struct rz_bin_dmp64_obj_t *obj) {
	if (!obj) {
		return;
	}

	rz_buf_free(obj->b);
	obj->b = NULL;
	free(obj->header);
	free(obj->bmp_header);
	free(obj->runs);
	free(obj->bitmap);
	rz_list_free(obj->pages);
	free(obj);
}

struct rz_bin_dmp64_obj_t *rz_bin_dmp64_new_buf(RzBuffer *buf) {
	struct rz_bin_dmp64_obj_t *obj = RZ_NEW0(struct rz_bin_dmp64_obj_t);
	if (!obj) {
		return NULL;
	}
	obj->kv = sdb_new0();
	obj->size = (ut32)rz_buf_size(buf);
	obj->b = rz_buf_ref(buf);

	if (!rz_bin_dmp64_init(obj)) {
		rz_bin_dmp64_free(obj);
		return NULL;
	}

	return obj;
}
