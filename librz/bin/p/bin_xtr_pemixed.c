// SPDX-FileCopyrightText: 2018-2019 JohnPeng47 <johnpeng47@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "pe/pemixed.h"

static RzList *oneshotall(RzBin *bin, const ut8 *buf, ut64 size);
static RzBinXtrData *oneshot(RzBin *bin, const ut8 *buf, ut64 size, int subbin_type);

static void free_xtr(void *xtr_obj) {
	rz_bin_pemixed_free((struct rz_bin_pemixed_obj_t *)xtr_obj);
}

static void destroy(RzBin *bin) {
	free_xtr(bin->cur->xtr_obj);
}

static bool check_buffer(RzBuffer *b) {
	return false;
#if 0
	if (!bytes) {
		return false;
	}
	if (sz <= 0x3d) { //less than size of MS-DOS header which is 64bytes
		return false;
	}
	ut32 idx = (bytes[0x3c] | (bytes[0x3d]<<8));
	if (sz > idx + 0x18 + 2) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		if (!memcmp (bytes, "MZ", 2)) {
			if (!memcmp (bytes+idx, "PE", 2) &&
				!memcmp (bytes+idx+0x18, "\x0b\x01", 2)) {
				return true;
			}
			// TODO: Add one more indicator, to prevent false positives
			if (!memcmp (bytes+idx, "PL", 2)) {
				return true;
			}
		}
	}
	return false;
#endif
}

// TODO RzBufferify
static RzList *oneshotall(RzBin *bin, const ut8 *buf, ut64 size) {
	//extract dos componenent first
	RzBinXtrData *data = oneshot(bin, buf, size, SUB_BIN_DOS);

	if (!data) {
		return NULL;
	}
	// XXX - how do we validate a valid narch?
	RzList *res = rz_list_newf(rz_bin_xtrdata_free);
	rz_list_append(res, data);

	if ((data = oneshot(bin, buf, size, SUB_BIN_NATIVE))) {
		rz_list_append(res, data);
	}

	if ((data = oneshot(bin, buf, size, SUB_BIN_NET))) {
		rz_list_append(res, data);
	}

	return res;
}

//implement this later
static void fill_metadata_info_from_hdr(RzBinXtrMetadata *meta, void *foo) { // struct Pe_32_rz_bin_pemixed_obj_t* pe_bin){
	meta->arch = NULL;
	meta->bits = 0;
	meta->machine = NULL;
	meta->type = NULL;
	meta->libname = NULL;
	meta->xtr_type = "net";
	//strcpy (meta->xtr_type, "net");
}

// XXX: ut8* should be RzBuffer *
static RzBinXtrData *oneshot(RzBin *bin, const ut8 *buf, ut64 size, int sub_bin_type) {
	rz_return_val_if_fail(bin && bin->cur && buf, false);

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = rz_bin_pemixed_from_bytes_new(buf, size);
	}

	struct rz_bin_pemixed_obj_t *fb = bin->cur->xtr_obj;
	// this function is prolly not nessescary
	struct PE_(rz_bin_pe_obj_t) *pe = rz_bin_pemixed_extract(fb, sub_bin_type);
	if (!pe) {
		return NULL;
	}
	RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
	if (!metadata) {
		return NULL;
	}
	fill_metadata_info_from_hdr(metadata, pe);
	return rz_bin_xtrdata_new(pe->b, 0, pe->size, 3, metadata);
}

RzBinXtrPlugin rz_bin_xtr_plugin_xtr_pemixed = {
	.name = "xtr.pemixed",
	.desc = "Extract sub-binaries in PE files",
	.load = NULL, //not yet implemented
	.extract = NULL, //not yet implemented
	.extractall = NULL, //not yet implemented
	.destroy = &destroy,
	.extract_from_bytes = &oneshot,
	.extractall_from_bytes = &oneshotall,
	.free_xtr = &free_xtr,
	.check_buffer = &check_buffer,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN_XTR,
	.data = &rz_bin_xtr_plugin_pemixed,
	.version = RZ_VERSION
};
#endif
