// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/* Helpers for handling bytes */
#define DIFF_IS_BYTES_METHOD(x) (x.elem_at == methods_bytes.elem_at)

static const void *byte_elem_at(const ut8 *array, ut32 index) {
	return &array[index];
}

static int byte_compare(const ut8 *a_elem, const ut8 *b_elem) {
	return ((int)b_elem[0]) - ((int)a_elem[0]);
}

static ut32 byte_hash(const char *elem) {
	return elem[0];
}

static void byte_stringify(const ut8 *a_elem, RzStrBuf *sb) {
	rz_strbuf_setf(sb, "%02x", *a_elem);
}

static const MethodsInternal methods_bytes = {
	.elem_at /*  */ = (RzDiffMethodElemAt)byte_elem_at,
	.elem_hash /**/ = (RzDiffMethodElemHash)byte_hash,
	.compare /*  */ = (RzDiffMethodCompare)byte_compare,
	.stringify /**/ = (RzDiffMethodStringify)byte_stringify,
	.ignore /*   */ = fake_ignore,
	.free /*     */ = NULL,
};
