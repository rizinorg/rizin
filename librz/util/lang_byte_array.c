// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#define RZ_LANG_BYTE_ARRAY_TRUNK_SIZE     16
#define RZ_LANG_BYTE_ARRAY_TRUNK_SIZE_STR "16"

static void lang_byte_array_rizin(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	size_t pos = 0;
	rz_strbuf_append(sb, "wx ");
	for (pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % RZ_LANG_BYTE_ARRAY_TRUNK_SIZE)) {
			rz_strbuf_append(sb, " ; sd +" RZ_LANG_BYTE_ARRAY_TRUNK_SIZE_STR "\nwx ");
		}
		rz_strbuf_appendf(sb, "%02x", buffer[pos]);
	}
	if (pos > RZ_LANG_BYTE_ARRAY_TRUNK_SIZE) {
		rz_strbuf_appendf(sb, " ; sd -%" PFMTSZd, pos);
	}
}

static void lang_byte_array_bash(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	bool append = false;
	rz_strbuf_append(sb, "printf \"");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % RZ_LANG_BYTE_ARRAY_TRUNK_SIZE)) {
			rz_strbuf_appendf(sb, "\" %s data.bin\nprintf \"", append ? ">>" : ">");
			append = true;
		}
		rz_strbuf_appendf(sb, "\\%03o", buffer[pos]);
	}
	rz_strbuf_appendf(sb, "\" %s data.bin", append ? ">>" : ">");
}

static void lang_byte_array_c_cpp(RzStrBuf *sb, const ut8 *buffer, size_t size, size_t n_bytes, bool big_endian) {
	const char *hex_c, *hex_e;
	size_t n_bits = n_bytes * 8;
	size_t max_print;
	ut64 value;

	switch (n_bytes) {
	case 2:
		hex_c = " 0x%04" PFMT64x ",";
		hex_e = " 0x%04" PFMT64x "\n};";
		// ensure that is always aligned
		size -= (size % n_bytes);
		break;
	case 4:
		hex_c = " 0x%08" PFMT64x "u,";
		hex_e = " 0x%08" PFMT64x "u\n};";
		// ensure that is always aligned
		size -= (size % n_bytes);
		break;
	case 8:
		hex_c = " 0x%016" PFMT64x "ull,";
		hex_e = " 0x%016" PFMT64x "ull\n};";
		// ensure that is always aligned
		size -= (size % n_bytes);
		break;
	default:
		hex_c = " 0x%02" PFMT64x ",";
		hex_e = " 0x%02" PFMT64x "\n};";
		break;
	}
	max_print = RZ_LANG_BYTE_ARRAY_TRUNK_SIZE / n_bytes;

	if (size < 1 && n_bytes != 1) {
		rz_strbuf_appendf(sb, "// Warning: the number of available bytes is less than %" PFMTSZd, n_bytes);
		return;
	}
	rz_strbuf_appendf(sb, "#define ARRAY_SIZE %" PFMTSZd "\nconst uint%" PFMTSZd "_t array[ARRAY_SIZE] = {\n ", size / n_bytes, n_bits);
	for (size_t pos = 0, n_print = 0; pos < size; pos += n_bytes, n_print++) {
		if (n_print > 0 && !(n_print % max_print)) {
			rz_strbuf_append(sb, "\n ");
		}
		value = rz_read_ble(buffer + pos, big_endian, n_bits);
		rz_strbuf_appendf(sb, (pos + n_bytes) < size ? hex_c : hex_e, value);
	}
}

static void lang_byte_array_asm(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "byte_array:");
	for (size_t pos = 0; pos < size; pos++) {
		if (!(pos % RZ_LANG_BYTE_ARRAY_TRUNK_SIZE)) {
			rz_strbuf_appendf(sb, "\n.byte 0x%02x", buffer[pos]);
		} else {
			rz_strbuf_appendf(sb, ", 0x%02x", buffer[pos]);
		}
	}
	rz_strbuf_appendf(sb, "\n.equ byte_array_len, %" PFMTSZd, size);
}

static void lang_byte_array_golang(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "byteArray := []byte{\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		rz_strbuf_appendf(sb, " 0x%02x,", buffer[pos]);
	}
	rz_strbuf_append(sb, "\n}");
}

static void lang_byte_array_java(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	int value = 0;
	rz_strbuf_append(sb, "byte[] byteArray = new byte[] {\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		value = buffer[pos];
		if (value > 127) {
			value -= 256;
		}
		rz_strbuf_appendf(sb, " %4d,", value);
	}
	rz_strbuf_append(sb, "\n};");
}

static char *lang_byte_array_json(const ut8 *buffer, size_t size) {
	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}
	pj_a(pj);
	for (size_t pos = 0; pos < size; pos++) {
		pj_i(pj, buffer[pos]);
	}
	pj_end(pj);
	return pj_drain(pj);
}

static void lang_byte_array_kotlin(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	int value = 0;
	rz_strbuf_append(sb, "val byteArray = byteArrayOf(\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		value = buffer[pos];
		if (value > 127) {
			value -= 256;
		}
		rz_strbuf_appendf(sb, " %4d,", value);
	}
	rz_strbuf_append(sb, "\n);");
}

static void lang_byte_array_nodejs(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	if (size == 0) {
		rz_strbuf_append(sb, "var byteArray = new Buffer('', 'base64');");
		return;
	}

	char *base64 = calloc(size, 3);
	if (!base64) {
		return;
	}
	rz_base64_encode(base64, buffer, size);
	rz_strbuf_appendf(sb, "var byteArray = new Buffer('%s', 'base64');", base64);
	free(base64);
}

static void lang_byte_array_objective_c_cpp(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "NSData *byteArray = [[NSData alloc] initWithBytes:{\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		rz_strbuf_appendf(sb, (pos + 1) < size ? " 0x%02x," : " 0x%02x\n}];", buffer[pos]);
	}
}

static void lang_byte_array_python(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "byteArray = b'");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "'\nbyteArray += b'");
		}
		rz_strbuf_appendf(sb, "\\x%02x", buffer[pos]);
	}
	rz_strbuf_append(sb, "'");
}

static void lang_byte_array_rust(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_appendf(sb, "let _: [u8; %" PFMTSZd "] = [\n ", size);
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		rz_strbuf_appendf(sb, (pos + 1) < size ? " 0x%02x," : " 0x%02x\n];", buffer[pos]);
	}
}

static void lang_byte_array_swift(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "let byteArray : [UInt8] = [\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		rz_strbuf_appendf(sb, (pos + 1) < size ? " 0x%02x," : " 0x%02x\n];", buffer[pos]);
	}
}

static void lang_byte_array_yara(RzStrBuf *sb, const ut8 *buffer, size_t size) {
	rz_strbuf_append(sb, "$byteArray = {\n ");
	for (size_t pos = 0; pos < size; pos++) {
		if (pos > 0 && !(pos % (RZ_LANG_BYTE_ARRAY_TRUNK_SIZE))) {
			rz_strbuf_append(sb, "\n ");
		}
		rz_strbuf_appendf(sb, " %02x", buffer[pos]);
	}
	rz_strbuf_appendf(sb, "\n};");
}

/**
 * \brief  Generates a string containing a byte array in the specified language
 *
 * \param  buffer  The buffer to read
 * \param  size    The buffer size
 * \param  type    The RzLangByteArrayType type
 *
 * \return On success returns a string, otherwise NULL
 */
RZ_API RZ_OWN char *rz_lang_byte_array(RZ_NONNULL const ut8 *buffer, size_t size, const ut32 size_max, RzLangByteArrayType type) {
	rz_return_val_if_fail(buffer, NULL);
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	if(size == 0) {
		RZ_LOG_ERROR("Length may not be 0\n");
		return rz_strbuf_drain_nofree(&sb);
	}

	if(size < 0) {
		size *= -1;
	}

	if(size > size_max) {
		RZ_LOG_ERROR("Length exceeds max size (%u)\n", size_max);
		return rz_strbuf_drain_nofree(&sb);
	}

	if (size == 0) {
		return rz_strbuf_drain_nofree(&sb);
	}

	switch (type) {
	case RZ_LANG_BYTE_ARRAY_RIZIN:
		lang_byte_array_rizin(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_ASM:
		lang_byte_array_asm(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_BASH:
		lang_byte_array_bash(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_BYTES:
		lang_byte_array_c_cpp(&sb, buffer, size, 1, false);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_BE:
		lang_byte_array_c_cpp(&sb, buffer, size, 2, true);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_LE:
		lang_byte_array_c_cpp(&sb, buffer, size, 2, false);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_BE:
		lang_byte_array_c_cpp(&sb, buffer, size, 4, true);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_LE:
		lang_byte_array_c_cpp(&sb, buffer, size, 4, false);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_BE:
		lang_byte_array_c_cpp(&sb, buffer, size, 8, true);
		break;
	case RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_LE:
		lang_byte_array_c_cpp(&sb, buffer, size, 8, false);
		break;
	case RZ_LANG_BYTE_ARRAY_GOLANG:
		lang_byte_array_golang(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_JAVA:
		lang_byte_array_java(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_JSON:
		rz_strbuf_fini(&sb);
		return lang_byte_array_json(buffer, size);
	case RZ_LANG_BYTE_ARRAY_KOTLIN:
		lang_byte_array_kotlin(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_NODEJS:
		lang_byte_array_nodejs(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_OBJECTIVE_C:
		lang_byte_array_objective_c_cpp(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_PYTHON:
		lang_byte_array_python(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_RUST:
		lang_byte_array_rust(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_SWIFT:
		lang_byte_array_swift(&sb, buffer, size);
		break;
	case RZ_LANG_BYTE_ARRAY_YARA:
		lang_byte_array_yara(&sb, buffer, size);
		break;
	default:
		rz_strbuf_fini(&sb);
		rz_warn_if_reached();
		return NULL;
	}
	return rz_strbuf_drain_nofree(&sb);
}
