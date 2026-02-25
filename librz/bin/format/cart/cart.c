// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "cart.h"
#include <rz_util.h>

static const ut8 CART_DEFAULT_RC4_KEY[CART_ARC4_KEY_LENGTH] = {
	0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06,
	0x03, 0x01, 0x04, 0x01, 0x05, 0x09, 0x02, 0x06
};

static bool cart_key_is_null(const ut8 *key) {
	for (int i = 0; i < CART_ARC4_KEY_LENGTH; i++) {
		if (key[i] != 0) {
			return false;
		}
	}
	return true;
}

static void cart_rc4_crypt(const ut8 *key, int keylen, const ut8 *in, ut8 *out, int len) {
	ut8 S[256];
	int i, j;

	for (i = 0; i < 256; i++) {
		S[i] = (ut8)i;
	}

	for (i = 0, j = 0; i < 256; i++) {
		j = (j + S[i] + key[i % keylen]) % 256;
		ut8 tmp = S[i];
		S[i] = S[j];
		S[j] = tmp;
	}

	i = j = 0;
	for (int k = 0; k < len; k++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		ut8 tmp = S[i];
		S[i] = S[j];
		S[j] = tmp;
		out[k] = in[k] ^ S[(S[i] + S[j]) % 256];
	}
}

RZ_API bool rz_bin_cart_check_buffer(RZ_NONNULL RzBuffer *buf) {
	rz_return_val_if_fail(buf, false);

	ut64 sz = rz_buf_size(buf);
	if (sz < CART_MINIMUM_LENGTH) {
		return false;
	}

	ut8 header_magic[CART_HEADER_MAGIC_SIZE];
	if (rz_buf_read_at(buf, 0, header_magic, CART_HEADER_MAGIC_SIZE) != CART_HEADER_MAGIC_SIZE) {
		return false;
	}

	if (memcmp(header_magic, CART_HEADER_MAGIC, CART_HEADER_MAGIC_SIZE) != 0) {
		return false;
	}

	ut8 footer_magic[CART_FOOTER_MAGIC_SIZE];
	ut64 footer_start = sz - CART_FOOTER_LENGTH;
	if (rz_buf_read_at(buf, footer_start, footer_magic, CART_FOOTER_MAGIC_SIZE) != CART_FOOTER_MAGIC_SIZE) {
		return false;
	}

	if (memcmp(footer_magic, CART_FOOTER_MAGIC, CART_FOOTER_MAGIC_SIZE) != 0) {
		return false;
	}

	return true;
}

RZ_API RZ_OWN CartObj *rz_bin_cart_new_from_buffer(RZ_NONNULL RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);

	if (!rz_bin_cart_check_buffer(buf)) {
		return NULL;
	}

	ut64 sz = rz_buf_size(buf);

	CartObj *obj = RZ_NEW0(CartObj);
	if (!obj) {
		return NULL;
	}

	obj->file_size = sz;

	if (rz_buf_read_at(buf, 0, (ut8 *)obj->header.magic, CART_HEADER_MAGIC_SIZE) != CART_HEADER_MAGIC_SIZE) {
		goto fail;
	}

	if (!rz_buf_read_le16_at(buf, 4, &obj->header.version)) {
		goto fail;
	}

	if (obj->header.version != CART_VERSION) {
		RZ_LOG_WARN("CaRT: Unsupported version %d (expected %d)\n", obj->header.version, CART_VERSION);
		goto fail;
	}

	if (!rz_buf_read_le64_at(buf, 6, &obj->header.reserved)) {
		goto fail;
	}

	if (obj->header.reserved != 0) {
		RZ_LOG_WARN("CaRT: Invalid header reserved value (expected 0)\n");
		goto fail;
	}

	if (rz_buf_read_at(buf, 14, obj->header.arc4_key, CART_ARC4_KEY_LENGTH) != CART_ARC4_KEY_LENGTH) {
		goto fail;
	}

	if (!rz_buf_read_le64_at(buf, 30, &obj->header.opt_header_len)) {
		goto fail;
	}

	ut64 footer_start = sz - CART_FOOTER_LENGTH;
	if (rz_buf_read_at(buf, footer_start, (ut8 *)obj->footer.magic, CART_FOOTER_MAGIC_SIZE) != CART_FOOTER_MAGIC_SIZE) {
		goto fail;
	}

	if (!rz_buf_read_le64_at(buf, footer_start + 4, &obj->footer.reserved)) {
		goto fail;
	}

	if (obj->footer.reserved != 0) {
		RZ_LOG_WARN("CaRT: Invalid footer reserved value (expected 0)\n");
		goto fail;
	}

	if (!rz_buf_read_le64_at(buf, footer_start + 12, &obj->footer.opt_footer_pos)) {
		goto fail;
	}

	if (!rz_buf_read_le64_at(buf, footer_start + 20, &obj->footer.opt_footer_len)) {
		goto fail;
	}

	if (obj->footer.opt_footer_pos + obj->footer.opt_footer_len != footer_start) {
		RZ_LOG_WARN("CaRT: Invalid footer position/length\n");
		goto fail;
	}

	obj->data_start = CART_HEADER_LENGTH + obj->header.opt_header_len;
	obj->data_len = obj->footer.opt_footer_pos - obj->data_start;

	if (obj->data_start > sz || obj->data_start + obj->data_len > sz) {
		RZ_LOG_WARN("CaRT: Invalid data block boundaries\n");
		goto fail;
	}

	return obj;

fail:
	free(obj);
	return NULL;
}

RZ_API void rz_bin_cart_free(RZ_NULLABLE CartObj *obj) {
	free(obj);
}

RZ_API RZ_OWN ut8 *rz_bin_cart_extract(RZ_NONNULL RzBuffer *buf, RZ_NONNULL CartObj *obj, RZ_NONNULL int *out_size) {
	rz_return_val_if_fail(buf && obj && out_size, NULL);

	*out_size = 0;

	if (obj->data_len == 0) {
		RZ_LOG_WARN("CaRT: Empty data block\n");
		return NULL;
	}

	if (obj->data_len > 0x10000000) {
		RZ_LOG_WARN("CaRT: Data block too large\n");
		return NULL;
	}

	ut8 *encrypted = malloc(obj->data_len);
	if (!encrypted) {
		return NULL;
	}

	if (rz_buf_read_at(buf, obj->data_start, encrypted, obj->data_len) != obj->data_len) {
		free(encrypted);
		return NULL;
	}

	const ut8 *key = obj->header.arc4_key;
	if (cart_key_is_null(key)) {
		key = CART_DEFAULT_RC4_KEY;
	}

	ut8 *decrypted = malloc(obj->data_len);
	if (!decrypted) {
		free(encrypted);
		return NULL;
	}

	cart_rc4_crypt(key, CART_ARC4_KEY_LENGTH, encrypted, decrypted, obj->data_len);
	free(encrypted);

	int decompressed_len = 0;
	ut8 *decompressed = rz_inflate(decrypted, obj->data_len, NULL, &decompressed_len);
	free(decrypted);

	if (!decompressed) {
		RZ_LOG_WARN("CaRT: Failed to decompress payload\n");
		return NULL;
	}

	*out_size = decompressed_len;
	return decompressed;
}

RZ_API RZ_OWN RzBuffer *rz_bin_cart_extract_buf(RZ_NONNULL RzBuffer *buf, RZ_NONNULL CartObj *obj) {
	rz_return_val_if_fail(buf && obj, NULL);

	int payload_size = 0;
	ut8 *payload = rz_bin_cart_extract(buf, obj, &payload_size);
	if (!payload) {
		return NULL;
	}

	RzBuffer *result = rz_buf_new_with_pointers(payload, payload_size, true);
	if (!result) {
		free(payload);
		return NULL;
	}

	return result;
}
