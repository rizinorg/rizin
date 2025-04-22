// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "mach0/fatmach0.h"
#include "mach0/mach0.h"

static RzBinXtrData *extract(RzBin *bin, int idx);

static bool checkHeader(RzBuffer *b) {
	ut8 buf[4];
	const ut64 sz = rz_buf_size(b);
	rz_buf_read_at(b, 0, buf, 4);
	if (sz >= 0x300 && !memcmp(buf, "\xca\xfe\xba\xbe", 4)) {
		ut64 addr = 4 * sizeof(32);

		ut32 off;
		if (!rz_buf_read_be32_at(b, addr, &off)) {
			return false;
		}

		if (off > 0 && off + 4 < sz) {
			ut64 h = 0;
			rz_buf_read_at(b, h + off, buf, 4);
			if (!memcmp(buf, "\xce\xfa\xed\xfe", 4) ||
				!memcmp(buf, "\xfe\xed\xfa\xce", 4) ||
				!memcmp(buf, "\xfe\xed\xfa\xcf", 4) ||
				!memcmp(buf, "\xcf\xfa\xed\xfe", 4)) {
				return true;
			}
		}
	}
	return false;
}

static bool check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);
	return checkHeader(buf);
}

static void free_xtr(void *xtr_obj) {
	rz_bin_fatmach0_free((struct rz_bin_fatmach0_obj_t *)xtr_obj);
}

static void destroy(RzBin *bin) {
	free_xtr(bin->cur->xtr_obj);
}

static bool load(RzBin *bin) {
	return ((bin->cur->xtr_obj = rz_bin_fatmach0_new(bin->file)) != NULL);
}

static int size(RzBin *bin) {
	// TODO
	return 0;
}

static inline void fill_metadata_info_from_hdr(RzBinXtrMetadata *meta, struct MACH0_(mach_header) * hdr) {
	meta->arch = rz_str_dup(MACH0_(get_cputype_from_hdr)(hdr));
	meta->bits = MACH0_(get_bits_from_hdr)(hdr);
	meta->machine = MACH0_(get_cpusubtype_from_hdr)(hdr);
	meta->type = MACH0_(get_filetype_from_hdr)(hdr);
	meta->libname = NULL;
	meta->xtr_type = "fat";
}

// XXX deprecate
static RzBinXtrData *extract(RzBin *bin, int idx) {
	int narch;
	struct rz_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct rz_bin_fatmach0_arch_t *arch = rz_bin_fatmach0_extract(fb, idx, &narch);
	if (!arch) {
		return NULL;
	}
	RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
	if (!metadata) {
		rz_buf_free(arch->b);
		free(arch);
		return NULL;
	}
	struct MACH0_(mach_header) *hdr = MACH0_(get_hdr)(arch->b);
	if (!hdr) {
		free(metadata);
		free(arch);
		free(hdr);
		return NULL;
	}
	fill_metadata_info_from_hdr(metadata, hdr);
	RzBinXtrData *res = rz_bin_xtrdata_new(arch->b, arch->offset, arch->size, narch, metadata);
	rz_buf_free(arch->b);
	free(arch);
	free(hdr);
	return res;
}

static RzBinXtrData *oneshot_buffer(RzBin *bin, RzBuffer *b, int idx) {
	rz_return_val_if_fail(bin && bin->cur, NULL);

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = rz_bin_fatmach0_from_buffer_new(b);
	}
	int narch;
	struct rz_bin_fatmach0_obj_t *fb = bin->cur->xtr_obj;
	struct rz_bin_fatmach0_arch_t *arch = rz_bin_fatmach0_extract(fb, idx, &narch);
	if (arch) {
		RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
		if (metadata) {
			struct MACH0_(mach_header) *hdr = MACH0_(get_hdr)(arch->b);
			if (hdr) {
				fill_metadata_info_from_hdr(metadata, hdr);
				RzBinXtrData *res = rz_bin_xtrdata_new(arch->b, arch->offset, arch->size, narch, metadata);
				rz_buf_free(arch->b);
				free(arch);
				free(hdr);
				return res;
			}
			free(metadata);
		}
		free(arch);
	}
	return NULL;
}

static RzList /*<RzBinXtrData *>*/ *oneshotall_buffer(RzBin *bin, RzBuffer *b) {
	RzBinXtrData *data = oneshot_buffer(bin, b, 0);
	if (data) {
		// XXX - how do we validate a valid narch?
		int narch = data->file_count;
		RzList *res = rz_list_newf(rz_bin_xtrdata_free);
		if (!res) {
			rz_bin_xtrdata_free(data);
			return NULL;
		}
		rz_list_append(res, data);
		int i = 0;
		for (i = 1; data && i < narch; i++) {
			data = oneshot_buffer(bin, b, i);
			if (data) {
				rz_list_append(res, data);
			}
		}
		return res;
	}
	return NULL;
}

RzBinXtrPlugin rz_bin_xtr_plugin_fatmach0 = {
	.name = "xtr.fatmach0",
	.desc = "fat mach0 bin extractor plugin",
	.license = "LGPL3",
	.load = &load,
	.size = &size,
	.extract = &extract,
	.destroy = &destroy,
	.extract_from_buffer = &oneshot_buffer,
	.extractall_from_buffer = &oneshotall_buffer,
	.free_xtr = &free_xtr,
	.check_buffer = check_buffer,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN_XTR,
	.data = &rz_bin_xtr_plugin_fatmach0,
	.version = RZ_VERSION
};
#endif
