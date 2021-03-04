// SPDX-FileCopyrightText: 2010-2013 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_types.h>
#include <rz_util.h>
#include "fatmach0.h"

static int rz_bin_fatmach0_init(struct rz_bin_fatmach0_obj_t *bin) {
	ut32 size;
	ut32 i;
	ut8 hdrbytes[sizeof(struct fat_header)] = { 0 };
	int len = rz_buf_read_at(bin->b, 0, &hdrbytes[0], sizeof(struct fat_header));
	if (len != sizeof(struct fat_header)) {
		perror("read (fat_header)");
		return false;
	}
	bin->hdr.magic = rz_read_be32(&hdrbytes[0]);
	bin->hdr.nfat_arch = rz_read_be32(&hdrbytes[4]);
	bin->nfat_arch = bin->hdr.nfat_arch;
	if (sizeof(struct fat_header) + bin->nfat_arch * sizeof(struct fat_arch) > bin->size) {
		return false;
	}
	if (bin->hdr.magic != FAT_MAGIC || !bin->nfat_arch || bin->nfat_arch < 1) {
		eprintf("Endian FAT_MAGIC failed (?)\n");
		return false;
	}
	size = bin->nfat_arch * sizeof(struct fat_arch);
	if (size < bin->nfat_arch) {
		return false;
	}
	if (!(bin->archs = malloc(size))) {
		perror("malloc (fat_arch)");
		return false;
	}
	for (i = 0; i < bin->nfat_arch; i++) {
		ut8 archbytes[sizeof(struct fat_arch)] = { 0 };
		len = rz_buf_read_at(bin->b, 8 + i * sizeof(struct fat_arch), &archbytes[0], sizeof(struct fat_arch));
		if (len != sizeof(struct fat_arch)) {
			perror("read (fat_arch)");
			RZ_FREE(bin->archs);
			return false;
		}
		bin->archs[i].cputype = rz_read_be32(&archbytes[0]);
		bin->archs[i].cpusubtype = rz_read_be32(&archbytes[4]);
		bin->archs[i].offset = rz_read_be32(&archbytes[8]);
		bin->archs[i].size = rz_read_be32(&archbytes[12]);
		bin->archs[i].align = rz_read_be32(&archbytes[16]);
	}
	return true;
}

struct rz_bin_fatmach0_arch_t *rz_bin_fatmach0_extract(struct rz_bin_fatmach0_obj_t *bin, int idx, int *narch) {
	if (!bin || (idx < 0) || (idx > bin->nfat_arch)) {
		return NULL;
	}
	if (bin->archs[idx].offset > bin->size ||
		bin->archs[idx].offset + bin->archs[idx].size > bin->size) {
		return NULL;
	}
	if (narch) {
		*narch = bin->nfat_arch;
	}
	struct rz_bin_fatmach0_arch_t *ret = RZ_NEW0(struct rz_bin_fatmach0_arch_t);
	if (ret) {
		ret->size = bin->archs[idx].size;
		if (!ret->size || ret->size > bin->size) {
			eprintf("Skipping corrupted sub-bin %d arch %d\n", idx, bin->archs[idx].size);
			free(ret);
			return NULL;
		}
		ret->offset = bin->archs[idx].offset;
		ret->b = rz_buf_new_slice(bin->b, ret->offset, ret->size);
	}
	return ret;
}

void *rz_bin_fatmach0_free(struct rz_bin_fatmach0_obj_t *bin) {
	if (!bin) {
		return NULL;
	}
	free(bin->archs);
	rz_buf_free(bin->b);
	RZ_FREE(bin);
	return NULL;
}

struct rz_bin_fatmach0_obj_t *rz_bin_fatmach0_new(const char *file) {
	struct rz_bin_fatmach0_obj_t *bin = RZ_NEW0(struct rz_bin_fatmach0_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->file = file;
	size_t binsz;
	ut8 *buf = (ut8 *)rz_file_slurp(file, &binsz);
	bin->size = binsz;
	if (!buf) {
		return rz_bin_fatmach0_free(bin);
	}
	bin->b = rz_buf_new();
	if (!rz_buf_set_bytes(bin->b, buf, bin->size)) {
		free(buf);
		return rz_bin_fatmach0_free(bin);
	}
	free(buf);
	if (!rz_bin_fatmach0_init(bin)) {
		return rz_bin_fatmach0_free(bin);
	}
	return bin;
}

struct rz_bin_fatmach0_obj_t *rz_bin_fatmach0_from_buffer_new(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);
	struct rz_bin_fatmach0_obj_t *bo = RZ_NEW0(struct rz_bin_fatmach0_obj_t);
	if (bo) {
		bo->b = rz_buf_ref(b);
		bo->size = rz_buf_size(bo->b); // XXX implicit in bo->b
		if (!rz_bin_fatmach0_init(bo)) {
			return rz_bin_fatmach0_free(bo);
		}
	}
	return bo;
}

struct rz_bin_fatmach0_obj_t *rz_bin_fatmach0_from_bytes_new(const ut8 *buf, ut64 size) {
	struct rz_bin_fatmach0_obj_t *bin = RZ_NEW0(struct rz_bin_fatmach0_obj_t);
	if (!bin) {
		return NULL;
	}
	if (!buf) {
		return rz_bin_fatmach0_free(bin);
	}
	bin->b = rz_buf_new();
	bin->size = size;
	if (!rz_buf_set_bytes(bin->b, buf, size)) {
		return rz_bin_fatmach0_free(bin);
	}
	if (!rz_bin_fatmach0_init(bin)) {
		return rz_bin_fatmach0_free(bin);
	}
	return bin;
}
