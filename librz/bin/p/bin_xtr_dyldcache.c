// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "mach0/dyldcache.h"
#include "mach0/mach0.h"

static RzBinXtrData *extract(RzBin *bin, int idx);
static RzList *extractall(RzBin *bin);
static RzBinXtrData *oneshot(RzBin *bin, const ut8 *buf, ut64 size, int idx);
static RzList *oneshotall(RzBin *bin, const ut8 *buf, ut64 size);

static bool check_buffer(RzBuffer *buf) {
	ut8 b[4] = { 0 };
	rz_buf_read_at(buf, 0, b, sizeof(b));
	return !memcmp(buf, "dyld", 4);
}

static void free_xtr(void *xtr_obj) {
	rz_bin_dyldcache_free((struct rz_bin_dyldcache_obj_t *)xtr_obj);
}

static void destroy(RzBin *bin) {
	free_xtr(bin->cur->xtr_obj);
}

static bool load(RzBin *bin) {
	if (!bin || !bin->cur) {
		return false;
	}
	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = rz_bin_dyldcache_new(bin->cur->file);
	}
	if (!bin->file) {
		bin->file = bin->cur->file;
	}
	return bin->cur->xtr_obj ? true : false;
}

static RzList *extractall(RzBin *bin) {
	RzList *result = NULL;
	int nlib, i = 0;
	RzBinXtrData *data = extract(bin, i);
	if (!data) {
		return result;
	}
	// XXX - how do we validate a valid nlib?
	nlib = data->file_count;
	result = rz_list_newf(rz_bin_xtrdata_free);
	if (!result) {
		rz_bin_xtrdata_free(data);
		return NULL;
	}
	rz_list_append(result, data);
	for (i = 1; data && i < nlib; i++) {
		data = extract(bin, i);
		rz_list_append(result, data);
	}
	return result;
}

static inline void fill_metadata_info_from_hdr(RzBinXtrMetadata *meta, struct MACH0_(mach_header) * hdr) {
	meta->arch = strdup(MACH0_(get_cputype_from_hdr)(hdr));
	meta->bits = MACH0_(get_bits_from_hdr)(hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr)(hdr);
	meta->type = MACH0_(get_filetype_from_hdr)(hdr);
}

static RzBinXtrData *extract(RzBin *bin, int idx) {
	int nlib = 0;
	RzBinXtrData *res = NULL;
	char *libname;
	struct MACH0_(mach_header) * hdr;
	struct rz_bin_dyldcache_lib_t *lib = rz_bin_dyldcache_extract(
		(struct rz_bin_dyldcache_obj_t *)bin->cur->xtr_obj, idx, &nlib);

	if (lib) {
		RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
		if (!metadata) {
			free(lib);
			return NULL;
		}
		hdr = MACH0_(get_hdr)(lib->b);
		if (!hdr) {
			free(lib);
			RZ_FREE(metadata);
			free(hdr);
			return NULL;
		}
		fill_metadata_info_from_hdr(metadata, hdr);
		rz_bin_dydlcache_get_libname(lib, &libname);
		metadata->libname = strdup(libname);

		res = rz_bin_xtrdata_new(lib->b, lib->offset, lib->size, nlib, metadata);
		rz_buf_free(lib->b);
		free(lib);
		free(hdr);
	}
	return res;
}

static RzBinXtrData *oneshot(RzBin *bin, const ut8 *buf, ut64 size, int idx) {
	RzBinXtrData *res = NULL;
	struct rz_bin_dyldcache_obj_t *xtr_obj;
	struct rz_bin_dyldcache_lib_t *lib;
	int nlib = 0;
	char *libname;
	struct MACH0_(mach_header) * hdr;

	if (!load(bin)) {
		return NULL;
	}

	xtr_obj = bin->cur->xtr_obj;
	lib = rz_bin_dyldcache_extract(xtr_obj, idx, &nlib);
	if (!lib) {
		free_xtr(xtr_obj);
		bin->cur->xtr_obj = NULL;
		return NULL;
	}
	RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
	if (!metadata) {
		free(lib);
		return NULL;
	}
	hdr = MACH0_(get_hdr)(lib->b);
	if (!hdr) {
		free(lib);
		free(metadata);
		return NULL;
	}
	fill_metadata_info_from_hdr(metadata, hdr);
	rz_bin_dydlcache_get_libname(lib, &libname);
	metadata->libname = strdup(libname);

	res = rz_bin_xtrdata_new(lib->b, lib->offset, rz_buf_size(lib->b), nlib, metadata);
	rz_buf_free(lib->b);
	free(hdr);
	free(lib);
	return res;
}

static RzList *oneshotall(RzBin *bin, const ut8 *buf, ut64 size) {
	RzBinXtrData *data = NULL;
	RzList *res = NULL;
	int nlib, i = 0;
	if (!bin->file) {
		if (!load(bin)) {
			return NULL;
		}
	}
	data = oneshot(bin, buf, size, i);
	if (!data) {
		return res;
	}
	// XXX - how do we validate a valid nlib?
	nlib = data->file_count;
	res = rz_list_newf(rz_bin_xtrdata_free);
	if (!res) {
		rz_bin_xtrdata_free(data);
		return NULL;
	}
	rz_list_append(res, data);
	for (i = 1; data && i < nlib; i++) {
		data = oneshot(bin, buf, size, i);
		rz_list_append(res, data);
	}
	return res;
}

RzBinXtrPlugin rz_bin_xtr_plugin_xtr_dyldcache = {
	.name = "xtr.dyldcache",
	.desc = "dyld cache bin extractor plugin",
	.license = "LGPL3",
	.load = &load,
	.extract = &extract,
	.extractall = &extractall,
	.destroy = &destroy,
	.extract_from_bytes = &oneshot,
	.extractall_from_bytes = &oneshotall,
	.free_xtr = &free_xtr,
	.check_buffer = &check_buffer,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN_XTR,
	.data = &rz_bin_xtr_plugin_dyldcache,
	.version = RZ_VERSION
};
#endif
