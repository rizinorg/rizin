// SPDX-FileCopyrightText: 2018-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>

RZ_API RZ_OWN RzAsmOp *rz_asm_op_new(void) {
	return RZ_NEW0(RzAsmOp);
}

RZ_API void rz_asm_op_free(RZ_NULLABLE RzAsmOp *op) {
	rz_asm_op_fini(op);
	free(op);
}

RZ_API void rz_asm_op_init(RZ_NULLABLE RzAsmOp *op) {
	if (!op) {
		return;
	}
	memset(op, 0, sizeof(*op));
}

RZ_API void rz_asm_op_fini(RZ_NULLABLE RzAsmOp *op) {
	if (!op) {
		return;
	}
	rz_strbuf_fini(&op->buf);
	rz_strbuf_fini(&op->buf_asm);
	rz_buf_fini(op->buf_inc);
	rz_asm_token_string_free(op->asm_toks);
	op->asm_toks = NULL;
}

// accessors
RZ_API RZ_OWN char *rz_asm_op_get_hex(RZ_NONNULL RzAsmOp *op) {
	rz_return_val_if_fail(op, NULL);
	int size = rz_strbuf_length(&op->buf);
	char *str = calloc(size + 1, 2);
	rz_return_val_if_fail(str, NULL);
	rz_hex_bin2str((const ut8 *)rz_strbuf_get(&op->buf), size, str);
	return str;
}

RZ_API RZ_BORROW char *rz_asm_op_get_asm(RZ_NONNULL RzAsmOp *op) {
	rz_return_val_if_fail(op, NULL);
	return rz_strbuf_get(&op->buf_asm);
}

RZ_API RZ_BORROW ut8 *rz_asm_op_get_buf(RZ_NONNULL RzAsmOp *op) {
	rz_return_val_if_fail(op, NULL);
	return (ut8 *)rz_strbuf_get(&op->buf);
}

RZ_API int rz_asm_op_get_size(RZ_NONNULL RzAsmOp *op) {
	rz_return_val_if_fail(op, 1);
	const int len = op->size - op->payload;
	return RZ_MAX(1, len);
}

RZ_API void rz_asm_op_set_asm(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *str) {
	rz_return_if_fail(op && str);
	rz_strbuf_set(&op->buf_asm, str);
}

RZ_API void rz_asm_op_setf_asm(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *fmt, ...) {
	rz_return_if_fail(op && fmt);

	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vsetf(&op->buf_asm, fmt, ap);
	va_end(ap);
}

RZ_API int rz_asm_op_set_hex(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(op && str, 0);
	ut8 *bin = (ut8 *)rz_str_dup(str);
	if (!bin) {
		return 0;
	}

	int len = rz_hex_str2bin(str, bin);
	if (len > 0) {
		rz_strbuf_setbin(&op->buf, bin, len);
	}
	free(bin);
	return len;
}

RZ_API int rz_asm_op_set_hexbuf(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const ut8 *buf, int len) {
	rz_return_val_if_fail(op && buf && len >= 0, 0);
	char *hex = malloc(len * 4 + 1);
	if (hex) {
		(void)rz_hex_bin2str(buf, len, hex);
		int olen = rz_asm_op_set_hex(op, hex);
		free(hex);
		return olen;
	}
	return 0;
}

RZ_API void rz_asm_op_set_buf(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const ut8 *buf, int len) {
	rz_return_if_fail(op && buf && len >= 0);
	rz_strbuf_setbin(&op->buf, buf, len);
	rz_asm_op_set_hexbuf(op, buf, len);
}
