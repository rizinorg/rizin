// SPDX-FileCopyrightText: 2025 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../format/cart/cart.h"

static bool check_buffer(RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);
	return rz_bin_cart_check_buffer(buf);
}

static void free_xtr(void *xtr_obj) {
	rz_bin_cart_free((CartObj *)xtr_obj);
}

static void destroy(RzBin *bin) {
	if (bin && bin->cur) {
		free_xtr(bin->cur->xtr_obj);
		bin->cur->xtr_obj = NULL;
	}
}

static bool load(RzBin *bin) {
	rz_return_val_if_fail(bin && bin->cur, false);
	bin->cur->xtr_obj = rz_bin_cart_new_from_buffer(bin->cur->buf);
	return bin->cur->xtr_obj != NULL;
}

static int size(RzBin *bin) {
	rz_return_val_if_fail(bin && bin->cur && bin->cur->xtr_obj, 0);
	CartObj *obj = (CartObj *)bin->cur->xtr_obj;
	return (int)obj->file_size;
}

static RzBinXtrData *oneshot_buffer(RzBin *bin, RzBuffer *b, int idx) {
	rz_return_val_if_fail(bin && bin->cur && b, NULL);

	if (idx != 0) {
		return NULL;
	}

	if (!bin->cur->xtr_obj) {
		bin->cur->xtr_obj = rz_bin_cart_new_from_buffer(b);
	}
	if (!bin->cur->xtr_obj) {
		return NULL;
	}

	CartObj *obj = (CartObj *)bin->cur->xtr_obj;
	RzBuffer *payload_buf = rz_bin_cart_extract_buf(b, obj);
	if (!payload_buf) {
		return NULL;
	}

	RzBinXtrMetadata *metadata = RZ_NEW0(RzBinXtrMetadata);
	if (!metadata) {
		rz_buf_free(payload_buf);
		return NULL;
	}

	metadata->xtr_type = "cart";
	metadata->libname = rz_str_dup("cart_payload");

	ut64 payload_size = rz_buf_size(payload_buf);
	RzBinXtrData *res = rz_bin_xtrdata_new(payload_buf, 0, payload_size, 1, metadata);

	rz_buf_free(payload_buf);

	return res;
}

static RzList /*<RzBinXtrData *>*/ *oneshotall_buffer(RzBin *bin, RzBuffer *b) {
	RzBinXtrData *data = oneshot_buffer(bin, b, 0);
	if (!data) {
		return NULL;
	}

	RzList *res = rz_list_newf(rz_bin_xtrdata_free);
	if (!res) {
		rz_bin_xtrdata_free(data);
		return NULL;
	}

	rz_list_append(res, data);
	return res;
}

RzBinXtrPlugin rz_bin_xtr_plugin_cart = {
	.name = "xtr.cart",
	.desc = "CaRT (Compressed and RC4 Transport) extractor",
	.license = "LGPL3",
	.check_buffer = check_buffer,
	.load = &load,
	.destroy = &destroy,
	.size = &size,
	.extract_from_buffer = &oneshot_buffer,
	.extractall_from_buffer = &oneshotall_buffer,
	.free_xtr = &free_xtr,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN_XTR,
	.data = &rz_bin_xtr_plugin_cart,
	.version = RZ_VERSION
};
#endif
