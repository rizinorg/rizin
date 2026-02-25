// SPDX-FileCopyrightText: 2025 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_CART_H
#define RZ_BIN_CART_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CART_HEADER_MAGIC      "CART"
#define CART_FOOTER_MAGIC      "TRAC"
#define CART_HEADER_MAGIC_SIZE 4
#define CART_FOOTER_MAGIC_SIZE 4

#define CART_VERSION 1

#define CART_HEADER_LENGTH  38
#define CART_FOOTER_LENGTH  28
#define CART_MINIMUM_LENGTH (CART_HEADER_LENGTH + CART_FOOTER_LENGTH)

#define CART_ARC4_KEY_LENGTH 16
#define CART_BLOCK_SIZE      (64 * 1024)

typedef struct cart_header_t {
	char magic[CART_HEADER_MAGIC_SIZE];
	ut16 version;
	ut64 reserved;
	ut8 arc4_key[CART_ARC4_KEY_LENGTH];
	ut64 opt_header_len;
} CartHeader;

typedef struct cart_footer_t {
	char magic[CART_FOOTER_MAGIC_SIZE];
	ut64 reserved;
	ut64 opt_footer_pos;
	ut64 opt_footer_len;
} CartFooter;

typedef struct cart_obj_t {
	CartHeader header;
	CartFooter footer;
	ut64 data_start;
	ut64 data_len;
	ut64 file_size;
} CartObj;

/** Check if buffer contains valid CaRT magic (CART/TRAC) */
RZ_API bool rz_bin_cart_check_buffer(RZ_NONNULL RzBuffer *buf);
/** Parse CaRT header and footer from buffer */
RZ_API RZ_OWN CartObj *rz_bin_cart_new_from_buffer(RZ_NONNULL RzBuffer *buf);
/** Free CartObj */
RZ_API void rz_bin_cart_free(RZ_NULLABLE CartObj *obj);
/** Extract decrypted and decompressed payload */
RZ_API RZ_OWN ut8 *rz_bin_cart_extract(RZ_NONNULL RzBuffer *buf, RZ_NONNULL CartObj *obj, RZ_NONNULL int *out_size);
/** Extract payload as RzBuffer */
RZ_API RZ_OWN RzBuffer *rz_bin_cart_extract_buf(RZ_NONNULL RzBuffer *buf, RZ_NONNULL CartObj *obj);

#ifdef __cplusplus
}
#endif

#endif
