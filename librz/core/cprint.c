// SPDX-FileCopyrightText: 2022 Peiwei Hu <jlu.hpw@foxmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#define STRING_CHUNK 16

/**
 * Return a C/C++ string defination with block size as the length
 * \param core RzCore
 * \return a string defination or NULL if the error happens
 */
RZ_API RZ_OWN char *rz_core_print_string_c_cpp(RzCore *core) {
	ut64 value;
	size_t size = core->blocksize;
	RzStrBuf *sb = rz_strbuf_new(NULL);

	if (!sb) {
		RZ_LOG_ERROR("Fail to allocate the memory\n");
		return NULL;
	}
	rz_strbuf_appendf(sb, "#define STRING_SIZE %" PFMTSZd "\nconst char s[STRING_SIZE] = \"", size);
	for (size_t pos = 0; pos < size; pos++) {
		if (pos && !(pos % STRING_CHUNK)) {
			// newline and padding for long string
			rz_strbuf_appendf(sb, "\"\n                            \"");
		}
		value = rz_read_ble(core->block + pos, false, 8);
		rz_strbuf_appendf(sb, "\\x%02" PFMT64x, value);
	}
	rz_strbuf_append(sb, "\";");
	return rz_strbuf_drain(sb);
}

/**
 * \brief Get the hexpair of the assembly
 * \param core RzCore
 * \param assembly assembly
 * \return a string containing the hexpair of the assembly
 */
RZ_API RZ_OWN char *rz_core_hex_of_assembly(RzCore *core, const char *assembly) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return NULL;
	}
	rz_asm_set_pc(core->rasm, core->offset);
	RzAsmCode *acode = rz_asm_massemble(core->rasm, assembly);
	if (!acode) {
		RZ_LOG_ERROR("Fail to assemble by rz_asm_massemble()\n");
		rz_strbuf_free(buf);
		return NULL;
	}
	for (int i = 0; i < acode->len; i++) {
		ut8 b = acode->bytes[i]; // core->print->big_endian? (bytes - 1 - i): i ];
		rz_strbuf_appendf(buf, "%02x", b);
	}
	rz_asm_code_free(acode);
	return rz_strbuf_drain(buf);
}

/**
 * \brief Get the esil of the assembly
 * \param core RzCore
 * \param assembly assembly
 * \return a string containing the esil of the assembly
 */
RZ_API RZ_OWN char *rz_core_esil_of_assembly(RzCore *core, const char *assembly) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return NULL;
	}
	rz_asm_set_pc(core->rasm, core->offset);
	RzAsmCode *acode = rz_asm_massemble(core->rasm, assembly);
	if (!acode) {
		RZ_LOG_ERROR("Fail to assemble by rz_asm_massemble()\n");
		rz_strbuf_free(buf);
		return NULL;
	}
	int printed = 0, bufsz = acode->len;
	RzAnalysisOp aop = { 0 };
	while (printed < bufsz) {
		aop.size = 0;
		if (rz_analysis_op(core->analysis, &aop, core->offset,
			    (const ut8 *)acode->bytes + printed, bufsz - printed, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
			aop.size < 1) {
			RZ_LOG_ERROR("Cannot decode instruction\n");
			rz_analysis_op_fini(&aop);
			rz_strbuf_free(buf);
			rz_asm_code_free(acode);
			return NULL;
		}
		rz_strbuf_appendf(buf, "%s\n", RZ_STRBUF_SAFEGET(&aop.esil));
		printed += aop.size;
		rz_analysis_op_fini(&aop);
	}
	rz_asm_code_free(acode);
	return rz_strbuf_drain(buf);
}

/**
 * \brief Get the assembly of the hexstr
 * \param core RzCore
 * \param hex hex
 * \param len length of hex
 * \return a string containing the assembly of the hexstr
 */
RZ_API RZ_OWN char *rz_core_assembly_of_hex(RzCore *core, ut8 *hex, int len) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return NULL;
	}
	rz_asm_set_pc(core->rasm, core->offset);
	RzAsmCode *acode = rz_asm_mdisassemble(core->rasm, hex, len);
	if (!acode) {
		RZ_LOG_ERROR("Invalid hexstr\n");
		rz_strbuf_free(buf);
		return NULL;
	}
	rz_strbuf_append(buf, acode->assembly);
	rz_asm_code_free(acode);
	return rz_strbuf_drain(buf);
}

/**
 * \brief Get the esil of the hexstr
 * \param core RzCore
 * \param hex hex
 * \param len length of hex
 * \return a string containing the esil of the hexstr
 */
RZ_API RZ_OWN char *rz_core_esil_of_hex(RzCore *core, ut8 *hex, int len) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		goto fail;
	}
	int printed = 0;
	RzAnalysisOp aop = { 0 };
	while (printed < len) {
		aop.size = 0;
		if (rz_analysis_op(core->analysis, &aop, core->offset,
			    (const ut8 *)hex + printed, len - printed, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
			aop.size < 1) {
			RZ_LOG_ERROR("Cannot decode instruction\n");
			rz_analysis_op_fini(&aop);
			goto fail;
		}
		rz_strbuf_appendf(buf, "%s\n", RZ_STRBUF_SAFEGET(&aop.esil));
		printed += aop.size;
		rz_analysis_op_fini(&aop);
	}
	return rz_strbuf_drain(buf);
fail:
	rz_strbuf_free(buf);
	return NULL;
}

RZ_IPI void rz_core_print_hexdump(RZ_NONNULL RzCore *core, ut64 addr, RZ_NONNULL const ut8 *buf,
	int len, int base, int step, size_t zoomsz) {
	char *string = rz_print_hexdump_str(core->print, addr, buf, len, base, step, zoomsz);
	rz_cons_print(string);
	free(string);
}

RZ_IPI void rz_core_print_jsondump(RZ_NONNULL RzCore *core, RZ_NONNULL const ut8 *buf, int len, int wordsize) {
	char *string = rz_print_jsondump_str(core->print, buf, len, wordsize);
	rz_cons_print(string);
	free(string);
}

RZ_IPI void rz_core_print_hexdiff(RzCore *core, ut64 aa, RZ_NONNULL const ut8 *_a, ut64 ba, RZ_NONNULL const ut8 *_b, int len, int scndcol) {
	char *string = rz_print_hexdiff_str(core->print, aa, _a, ba, _b, len, scndcol);
	rz_cons_print(string);
	free(string);
}