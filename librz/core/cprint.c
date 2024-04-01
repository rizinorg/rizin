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
		rz_analysis_op_init(&aop);
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
		rz_analysis_op_init(&aop);
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
	if (!string) {
		RZ_LOG_ERROR("fail to print hexdump at 0x%" PFMT64x "\n", addr);
		return;
	}
	rz_cons_print(string);
	free(string);
}

RZ_IPI void rz_core_print_jsondump(RZ_NONNULL RzCore *core, RZ_NONNULL const ut8 *buf, int len, int wordsize) {
	char *string = rz_print_jsondump_str(core->print, buf, len, wordsize);
	if (!string) {
		RZ_LOG_ERROR("fail to print json hexdump\n");
		return;
	}
	rz_cons_print(string);
	free(string);
}

RZ_IPI void rz_core_print_hexdiff(RZ_NONNULL RzCore *core, ut64 aa, RZ_NONNULL const ut8 *_a, ut64 ba, RZ_NONNULL const ut8 *_b, int len, int scndcol) {
	char *string = rz_print_hexdiff_str(core->print, aa, _a, ba, _b, len, scndcol);
	if (!string) {
		RZ_LOG_ERROR("fail to print hexdiff between 0x%" PFMT64x " and 0x%" PFMT64x "\n", aa, ba);
		return;
	}
	rz_cons_print(string);
	free(string);
}

/**
 * \brief Print hexdump diff between \p aa and \p ba with \p len
 */
RZ_API RZ_OWN char *rz_core_print_hexdump_diff_str(RZ_NONNULL RzCore *core, ut64 aa, ut64 ba, ut64 len) {
	rz_return_val_if_fail(core && core->cons && len > 0, false);
	ut8 *a = malloc(len);
	if (!a) {
		return NULL;
	}
	ut8 *b = malloc(len);
	if (!b) {
		free(a);
		return NULL;
	}

	RZ_LOG_VERBOSE("print hexdump diff 0x%" PFMT64x " 0x%" PFMT64x " with len:%" PFMT64d "\n", aa, ba, len);

	rz_io_read_at(core->io, aa, a, (int)len);
	rz_io_read_at(core->io, ba, b, (int)len);
	int col = core->cons->columns > 123;
	char *pstr = rz_print_hexdiff_str(core->print, aa, a,
		ba, b, (int)len, col);
	free(a);
	free(b);
	return pstr;
}

RZ_IPI bool rz_core_print_hexdump_diff(RZ_NONNULL RzCore *core, ut64 aa, ut64 ba, ut64 len) {
	char *string = rz_core_print_hexdump_diff_str(core, aa, ba, len);
	if (!string) {
		RZ_LOG_ERROR("fail to print hexdump diff between 0x%" PFMT64x " and 0x%" PFMT64x "\n", aa, ba);
		return false;
	}
	rz_cons_print(string);
	free(string);
	return true;
}

static inline st8 format_type_to_base(const RzCorePrintFormatType format, const ut8 n) {
	static const st8 bases[][9] = {
		{ 0, 8 },
		{ 0, -1, -10, [4] = 10, [8] = -8 },
		{ 0, 16, 32, [4] = 32, [8] = 64 },
	};
	if (format >= RZ_CORE_PRINT_FORMAT_TYPE_INVALID || n >= sizeof(bases[0])) {
		return 0;
	}
	return bases[format][n];
}

static inline void fix_size_from_format(const RzCorePrintFormatType format, ut8 *size) {
	if (format != RZ_CORE_PRINT_FORMAT_TYPE_INTEGER) {
		return;
	}
	static const st8 sizes[] = {
		0, 4, 2, [4] = 4, [8] = 4
	};
	if (*size >= sizeof(sizes)) {
		return;
	}
	*size = sizes[*size];
}

static inline void len_fixup(RzCore *core, ut64 *addr, int *len) {
	if (!len) {
		return;
	}
	bool is_positive = *len > 0;
	if (RZ_ABS(*len) > core->blocksize_max) {
		RZ_LOG_ERROR("this <len> is too big (0x%" PFMT32x
			     " < 0x%" PFMT32x ").",
			*len, core->blocksize_max);
		*len = (int)core->blocksize_max;
	}
	if (is_positive) {
		return;
	}
	*len = RZ_ABS(*len);
	if (addr) {
		*addr = *addr - *len;
	}
}

/**
 * \brief Print dump at \p addr
 * \param n Word size by bytes (1,2,4,8)
 * \param len Dump bytes length
 * \param format Print format, such as RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL
 */
RZ_API RZ_OWN char *rz_core_print_dump_str(RZ_NONNULL RzCore *core, RzOutputMode mode,
	ut64 addr, ut8 n, int len, RzCorePrintFormatType format) {
	rz_return_val_if_fail(core, false);
	if (!len) {
		return NULL;
	}
	st8 base = format_type_to_base(format, n);
	if (!base) {
		return NULL;
	}
	len_fixup(core, &addr, &len);
	ut8 *buffer = malloc(len);
	if (!buffer) {
		return NULL;
	}

	char *string = NULL;
	rz_io_read_at(core->io, addr, buffer, len);
	RzPrint *print = core->print;
	rz_print_init_rowoffsets(print);
	bool old_use_comments = print->use_comments;
	print->use_comments = false;

	switch (mode) {
	case RZ_OUTPUT_MODE_JSON:
		string = rz_print_jsondump_str(print, buffer, len, n * 8);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		fix_size_from_format(format, &n);
		string = rz_print_hexdump_str(print, addr, buffer, len, base, (int)n, 1);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	print->use_comments = old_use_comments;
	free(buffer);
	return string;
}

RZ_IPI bool rz_core_print_dump(RZ_NONNULL RzCore *core, RzOutputMode mode,
	ut64 addr, ut8 n, int len, RzCorePrintFormatType format) {
	char *string = rz_core_print_dump_str(core, mode, addr, n, len, format);
	if (!string) {
		RZ_LOG_ERROR("fail to print dump at 0x%" PFMT64x "\n", addr);
		return false;
	}
	rz_cons_print(string);
	free(string);
	return true;
}

/**
 * \brief Print hexdump at \p addr, but maybe print hexdiff if (diff.from or diff.to), \see "el diff"
 * \param len Dump bytes length
 */
RZ_API RZ_OWN char *rz_core_print_hexdump_or_hexdiff_str(RZ_NONNULL RzCore *core, RzOutputMode mode, ut64 addr, int len,
	bool use_comment) {
	rz_return_val_if_fail(core, false);
	if (!len) {
		return NULL;
	}

	char *string = NULL;
	RzPrint *print = core->print;
	bool old_use_comments = print->use_comments;
	print->use_comments = use_comment ? print->flags & RZ_PRINT_FLAGS_COMMENT : false;
	ut64 from = rz_config_get_i(core->config, "diff.from");
	ut64 to = rz_config_get_i(core->config, "diff.to");
	if (from == to && !from) {
		len_fixup(core, &addr, &len);
		ut8 *buffer = malloc(len);
		if (!buffer) {
			return NULL;
		}
		rz_io_read_at(core->io, addr, buffer, len);
		switch (mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			string = rz_print_hexdump_str(core->print, rz_core_pava(core, addr), buffer, len, 16, 1, 1);
			break;
		case RZ_OUTPUT_MODE_JSON:
			string = rz_print_jsondump_str(core->print, buffer, len, 8);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		free(buffer);
	} else {
		switch (mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			string = rz_core_print_hexdump_diff_str(core, addr, addr + to - from, len);
			break;
		default:
			RZ_LOG_ERROR("Hexdiff not supported in JSON");
			return NULL;
		}
	}

	core->num->value = len;
	print->use_comments = old_use_comments;
	return string;
}

RZ_IPI bool rz_core_print_hexdump_or_hexdiff(RZ_NONNULL RzCore *core, RZ_NULLABLE RzOutputMode mode, ut64 addr, int len,
	bool use_comment) {
	char *string = rz_core_print_hexdump_or_hexdiff_str(core, mode, addr, len, use_comment);
	if (!string) {
		RZ_LOG_ERROR("fail to print hexdump at 0x%" PFMT64x "\n", addr);
		return false;
	}
	rz_cons_print(string);
	free(string);
	return true;
}

static inline char *ut64_to_hex(const ut64 x, const ut8 width) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_strbuf_appendf(sb, "%" PFMT64x, x);
	ut8 len = rz_strbuf_length(sb);
	if (len < width) {
		char *pad = rz_str_pad('0', width - len);
		rz_strbuf_prepend(sb, pad);
		free(pad);
	}
	rz_strbuf_prepend(sb, "0x");
	return rz_strbuf_drain(sb);
}

/**
 * \brief Hexdump at \p addr
 * \param len Dump bytes length
 * \param size Word size by bytes (1,2,4,8)
 * \return Hexdump string
 */
RZ_API RZ_OWN char *rz_core_print_hexdump_byline_str(RZ_NONNULL RzCore *core, bool hex_offset,
	ut64 addr, int len, ut8 size) {
	rz_return_val_if_fail(core, false);
	if (!len) {
		return NULL;
	}
	len_fixup(core, &addr, &len);
	ut8 *buffer = malloc(len);
	if (!buffer) {
		return NULL;
	}

	rz_io_read_at(core->io, addr, buffer, len);
	const int round_len = len - (len % size);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	for (int i = 0; i < round_len; i += size) {
		const char *a, *b;
		char *fn;
		RzPrint *p = core->print;
		RzFlagItem *f;
		ut64 v = rz_read_ble(buffer + i, p->big_endian, size * 8);
		if (p->colorfor) {
			a = p->colorfor(p->user, v, true);
			if (a && *a) {
				b = Color_RESET;
			} else {
				a = b = "";
			}
		} else {
			a = b = "";
		}
		f = rz_flag_get_at(core->flags, v, true);
		fn = NULL;
		if (f) {
			st64 delta = (st64)(v - rz_flag_item_get_offset(f));
			if (delta >= 0 && delta < 8192) {
				if (v == rz_flag_item_get_offset(f)) {
					fn = strdup(rz_flag_item_get_name(f));
				} else {
					fn = rz_str_newf("%s+%" PFMT64d, rz_flag_item_get_name(f), v - rz_flag_item_get_offset(f));
				}
			}
		}
		char *vstr = ut64_to_hex(v, size * 2);
		if (vstr) {
			if (hex_offset) {
				char *section_str = rz_print_section_str(core->print, addr + i);
				rz_strbuf_append(sb, section_str);
				free(section_str);
				rz_strbuf_appendf(sb, "0x%08" PFMT64x " %s%s%s%s%s\n",
					(ut64)addr + i, a, vstr, b, fn ? " " : "", fn ? fn : "");
			} else {
				rz_strbuf_appendf(sb, "%s%s%s\n", a, vstr, b);
			}
		}
		free(vstr);
		free(fn);
	}
	free(buffer);
	return rz_strbuf_drain(sb);
}

RZ_IPI bool rz_core_print_hexdump_byline(RZ_NONNULL RzCore *core, bool hexoffset, ut64 addr, int len, ut8 size) {
	char *string = rz_core_print_hexdump_byline_str(core, hexoffset, addr, len, size);
	if (!string) {
		RZ_LOG_ERROR("fail to print hexdump by line at 0x%" PFMT64x "\n", addr);
		return false;
	}
	rz_cons_print(string);
	free(string);
	return true;
}

/**
 * \brief Hexdump containing references at \p addr
 * \param address Dump bytes address
 * \param len Dump bytes length
 * \return Hexdump string
 */
RZ_IPI RZ_OWN char *rz_core_print_hexdump_refs(RZ_NONNULL RzCore *core, ut64 address, size_t len, int wordsize) {
	rz_return_val_if_fail(core, NULL);
	ut8 *buffer = malloc(len);
	if (!buffer) {
		return NULL;
	}

	const int ocols = core->print->cols;
	int bitsize = core->rasm->bits;
	/* Thumb is 16bit arm but handles 32bit data */
	if (bitsize == 16) {
		bitsize = 32;
	}
	core->print->cols = 1;
	core->print->flags |= RZ_PRINT_FLAGS_REFS;
	rz_io_read_at(core->io, address, buffer, len);
	char *hexdump_str = rz_print_hexdump_str(core->print, address, buffer,
		len, wordsize * 8, bitsize / 8, 1);
	core->print->flags &= ~RZ_PRINT_FLAGS_REFS;
	core->print->cols = ocols;
	free(buffer);
	return hexdump_str;
}

/**
 * \brief Bytes string at \p addr with instructions in comments
 */
RZ_API RZ_OWN char *rz_core_print_bytes_with_inst(RZ_NONNULL RzCore *core, RZ_NONNULL const ut8 *buf, ut64 addr, int len) {
	rz_return_val_if_fail(core && buf, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	rz_strbuf_appendf(sb, "sub_0x%08" PFMT64x ":\n", addr);
	for (int i = 0; i < len; i++) {
		RzAsmOp asmop = {
			0
		};
		(void)rz_asm_disassemble(core->rasm, &asmop, buf + i, len - i);
		int sz = asmop.size;
		if (sz < 1) {
			sz = 1;
		}
		rz_strbuf_appendf(sb, " .byte ");
		for (int j = 0; j < sz && i < len; j++) {
			rz_strbuf_appendf(sb, "%s0x%02x", j ? ", " : "", buf[i]);
			i++;
		}
		rz_strbuf_appendf(sb, "  // %s\n", rz_strbuf_get(&asmop.buf_asm));
		rz_asm_op_fini(&asmop);
		i--;
	}
	rz_strbuf_appendf(sb, ".equ shellcode_len, %d", len);
	return rz_strbuf_drain(sb);
}

static void core_handle_call(RzCore *core, char *line, char **str) {
	rz_return_if_fail(core && line && str && core->rasm && core->rasm->cur);
	if (strstr(core->rasm->cur->arch, "x86")) {
		*str = strstr(line, "call ");
	} else if (strstr(core->rasm->cur->arch, "arm")) {
		*str = strstr(line, " b ");
		if (*str && strstr(*str, " 0x")) {
			/*
			 * avoid treating branches to
			 * non-symbols as calls
			 */
			*str = NULL;
		}
		if (!*str) {
			*str = strstr(line, "bl ");
		}
		if (!*str) {
			*str = strstr(line, "bx ");
		}
	}
}

/**
 *  \brief Get the console output of disassembling \p byte_len bytes
 *      or \p inst_len opcodes at \p addr. Restricted by \p byte_len
 *      and \p inst_len at the same time. Set one of them to zero to
 *      ignore its restriction.
 */
RZ_IPI RZ_OWN char *rz_core_print_cons_disassembly(RzCore *core, ut64 addr, ut32 byte_len, ut32 inst_len) {
	rz_return_val_if_fail(core && (byte_len || inst_len), NULL);

	// cbytes in disasm_options decides whether byte_len constrains inst_len
	bool cbytes = true;

	if (byte_len == 0) {
		cbytes = false;
		byte_len = inst_len;
	}

	if (inst_len == 0) {
		inst_len = byte_len;
	}

	ut8 *block = malloc(byte_len + 1);
	if (!block) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return NULL;
	}

	if (rz_io_nread_at(core->io, addr, block, byte_len) == -1) {
		RZ_LOG_ERROR("Fail to read from 0x%" PFMT64x ".", addr);
		free(block);
		return NULL;
	}

	RzCoreDisasmOptions disasm_options = {
		.cbytes = cbytes,
	};

	rz_cons_push();
	rz_core_print_disasm(core, addr, block, byte_len, inst_len, NULL, &disasm_options);
	rz_cons_filter();
	const char *cons_str = rz_str_get(rz_cons_get_buffer());
	char *ret = strdup(cons_str);
	rz_cons_pop();
	rz_cons_echo(NULL);
	free(block);
	return ret;
}

/**
 * \brief Get string in disassembly line for \p mode
 * \param mode RzCorePrintDisasmStringsMode RZ_CORE_DISASM_STRINGS_MODE_{BYTES,INST,BLOCK,FUNCTION}
 * \param n_bytes Number of bytes to disassemble, only used for RZ_CORE_DISASM_STRINGS_MODE_BYTES
 * \param fcn RzAnalysisFunction pointer, only used for RZ_CORE_DISASM_STRINGS_MODE_FUNCTION
 */
// TODO: this is just a PoC, the disasm loop should be rewritten
// TODO: this is based on string matching, it should be written upon RzAnalysisOp to know
// when we have a call and such
RZ_API RZ_OWN char *rz_core_print_disasm_strings(RZ_NONNULL RzCore *core, RzCorePrintDisasmStringsMode mode, ut64 n_bytes, RZ_NULLABLE RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(core, NULL);
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		rz_config_hold_free(hc);
		return NULL;
	}
	rz_config_hold_i(hc,
		"asm.offset",
		"asm.debuginfo",
		"asm.tabs",
		"asm.emu",
		"emu.str",
		"asm.cmt.right",
		"scr.html",
		"scr.color",
		NULL);

	int use_color = (int)rz_config_get_i(core->config, "scr.color");
	bool show_comments = rz_config_get_i(core->config, "asm.comments");
	bool show_offset = rz_config_get_i(core->config, "asm.offset");
	bool asm_flags = rz_config_get_i(core->config, "asm.flags");
	RzConsPrintablePalette *pal = &core->cons->context->pal;
	// force defaults
	rz_config_set_b(core->config, "emu.str", true);
	rz_config_set_b(core->config, "asm.offset", true);
	rz_config_set_b(core->config, "asm.debuginfo", true);
	rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	rz_config_set_i(core->config, "asm.tabs", 0);
	rz_config_set_i(core->config, "scr.html", 0);
	rz_config_set_b(core->config, "asm.cmt.right", true);

	char *dump_string = NULL;
	RzList *lines = NULL;
	switch (mode) {
	case RZ_CORE_DISASM_STRINGS_MODE_BLOCK: {
		RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
		if (bb) {
			dump_string = rz_core_print_cons_disassembly(core, bb->addr, bb->size, 0);
			if (!dump_string) {
				goto restore_conf;
			}
		} else {
			RZ_LOG_ERROR("cannot find block %" PFMT64x ".\n", core->offset);
			goto restore_conf;
		}
		break;
	}
	case RZ_CORE_DISASM_STRINGS_MODE_FUNCTION: {
		RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (f) {
			dump_string = rz_core_cmd_str(core, "pdr");
		} else {
			RZ_LOG_ERROR("cannot find function %" PFMT64x ".\n", core->offset);
			goto restore_conf;
		}
		break;
	}
	case RZ_CORE_DISASM_STRINGS_MODE_INST: {
		dump_string = rz_core_print_cons_disassembly(core, core->offset, 0, core->blocksize);
		if (!dump_string) {
			goto restore_conf;
		}
		break;
	}
	case RZ_CORE_DISASM_STRINGS_MODE_BYTES:
	default: {
		dump_string = rz_core_print_cons_disassembly(core, core->offset, n_bytes, 0);
		if (!dump_string) {
			goto restore_conf;
		}
		break;
	}
	}
	rz_config_hold_restore(hc);

	lines = rz_str_split_duplist(dump_string, "\n", true);
	if (!lines) {
		goto restore_conf;
	}
	int count = (int)rz_list_length(lines);
	if (count < 1) {
		goto restore_conf;
	}
	RzListIter *iter;
	char *line;
	char *switchcmp = NULL;
	rz_list_foreach (lines, iter, line) {
		ut64 addr = UT64_MAX;
		const char *ox = strstr(line, "0x");
		if (ox) {
			addr = rz_num_get(NULL, ox);
		}
		const char *qo = strchr(line, '\"');
		const char *linecolor = NULL;
		char *string = NULL;
		if (qo) {
			char *qoe = strrchr(qo + 1, '"');
			if (qoe) {
				int raw_len = qoe - qo - 1;
				int actual_len = 0;
				const char *ptr = qo + 1;
				for (; ptr < qoe; ptr++) {
					if (*ptr == '\\' && ptr + 1 < qoe) {
						int body_len;
						switch (*(ptr + 1)) {
						case 'x':
							body_len = 3;
							break;
						case 'u':
							body_len = 5;
							break;
						case 'U':
							body_len = 9;
							break;
						default:
							body_len = 1;
						}
						for (int i = 0; i < body_len && ptr < qoe; i++) {
							ptr++;
						}
					}
					actual_len++;
				}
				if (actual_len > 2) {
					string = rz_str_ndup(qo, raw_len + 2);
				}
				linecolor = RZ_CONS_COLOR(comment);
			}
		}
		ox = strstr(line, "; 0x");
		if (!ox) {
			ox = strstr(line, "@ 0x");
		}
		char *string2 = NULL;
		if (ox) {
			char *qoe = strchr(ox + 3, ' ');
			if (!qoe) {
				qoe = strchr(ox + 3, '\x1b');
			}
			int len = qoe ? qoe - ox : strlen(ox + 3);
			string2 = rz_str_ndup(ox + 2, len - 1);
			if (rz_num_get(NULL, string2) < 0x100) {
				RZ_FREE(string2);
			}
		}
		char *str = NULL;
		if (asm_flags) {
			str = strstr(line, ";-- ");
			if (str) {
				if (!rz_str_startswith(str + 4, "case")) {
					rz_strbuf_appendf(sb, "%s\n", str);
				}
			}
		}
		str = strstr(line, " obj.");
		if (!str) {
			str = strstr(line, " str.");
			if (!str) {
				str = strstr(line, " imp.");
				if (!str) {
					str = strstr(line, " fcn.");
					if (!str) {
						str = strstr(line, " sub.");
					}
				}
			}
		}
		if (str) {
			char *qoe = NULL;
			if (!qoe) {
				qoe = strchr(str + 1, '\x1b');
			}
			if (!qoe) {
				qoe = strchr(str + 1, ';');
			}
			if (!qoe) {
				qoe = strchr(str + 1, ' ');
			}
			if (qoe) {
				free(string2);
				string2 = rz_str_ndup(str + 1, qoe - str - 1);
			} else {
				free(string2);
				string2 = strdup(str + 1);
			}
			if (string2) {
				RZ_FREE(string);
				string = string2;
				string2 = NULL;
			}
		}
		RZ_FREE(string2);
		core_handle_call(core, line, &str);
		if (!str) {
			str = strstr(line, "sym.");
			if (!str) {
				str = strstr(line, "fcn.");
			}
		}
		bool mark_malloc = false;
		if (str) {
			char *qoe = strchr(str, ';');
			if (qoe) {
				str = rz_str_ndup(str, qoe - str);
				mark_malloc = true;
			}
		}
		if (str) {
			string2 = mark_malloc ? str : strdup(str);
			linecolor = RZ_CONS_COLOR(call);
		}
		if (!string && string2) {
			string = string2;
			string2 = NULL;
		}
		if (strstr(line, "XREF")) {
			addr = UT64_MAX;
		}
		if (addr != UT64_MAX) {
			if (show_comments) {
				char *comment = rz_core_analysis_get_comments(core, addr);
				if (comment) {
					if (switchcmp) {
						if (strcmp(comment, switchcmp)) {
							if (show_offset) {
								rz_strbuf_appendf(sb, "%s0x%08" PFMT64x " ", use_color ? pal->offset : "", addr);
							}
							rz_strbuf_appendf(sb, "%s%s\n", use_color ? pal->comment : "", comment);
						}
					} else {
						if (show_offset) {
							rz_strbuf_appendf(sb, "%s0x%08" PFMT64x " ", use_color ? pal->offset : "", addr);
						}
						rz_strbuf_appendf(sb, "%s%s\n", use_color ? pal->comment : "", comment);
					}
					if (rz_str_startswith(comment, "switch table")) {
						free(switchcmp);
						switchcmp = strdup(comment);
					}
					RZ_FREE(comment);
				}
			}
			if (fcn) {
				bool label = false;
				/* show labels, basic blocks and (conditional) branches */

				void **vit;
				RzAnalysisBlock *bb;
				rz_pvector_foreach (fcn->bbs, vit) {
					bb = (RzAnalysisBlock *)*vit;
					if (addr == bb->jump) {
						if (show_offset) {
							rz_strbuf_appendf(sb, "%s0x%08" PFMT64x ":\n", use_color ? Color_YELLOW : "", addr);
						}
						label = true;
						break;
					}
				}
				if (!label && strstr(line, "->")) {
					rz_strbuf_appendf(sb, "%s0x%08" PFMT64x ":\n", use_color ? Color_YELLOW : "", addr);
				}
				if (strstr(line, "=<")) {
					RzAnalysisBlock *bb;
					rz_pvector_foreach (fcn->bbs, vit) {
						bb = (RzAnalysisBlock *)*vit;
						if (addr >= bb->addr && addr < bb->addr + bb->size) {
							const char *op;
							if (use_color) {
								op = (bb->fail == UT64_MAX) ? Color_GREEN "jmp" : Color_GREEN "cjmp";
							} else {
								op = (bb->fail == UT64_MAX) ? "jmp" : "cjmp";
							}
							if (show_offset) {
								rz_strbuf_appendf(sb, "%s0x%08" PFMT64x " " Color_RESET, use_color ? pal->offset : "", addr);
							}
							rz_strbuf_appendf(sb, "%s 0x%08" PFMT64x "%s\n",
								op, bb->jump, use_color ? Color_RESET : "");
							break;
						}
					}
				}
			}
			if (string && *string) {
				str = NULL;
				if (!strncmp(string, "0x", 2)) {
					str = string;
				}
				if (string2 && !strncmp(string2, "0x", 2)) {
					str = string2;
				}
				ut64 ptr = rz_num_math(NULL, str);
				RzFlagItem *flag = NULL;
				if (str) {
					flag = rz_core_flag_get_by_spaces(core->flags, ptr);
				}
				if (!flag) {
					if (!strncmp(string, "0x", 2)) {
						RZ_FREE(string);
					}
					if (string2 && !strncmp(string2, "0x", 2)) {
						RZ_FREE(string2);
					}
				}
				if (string && addr != UT32_MAX) {
					rz_str_trim(string);
					if (string2) {
						rz_str_trim(string2);
					}
					//// TODO implememnt avoid duplicated strings
					// eprintf ("---> %s\n", string);
					if (use_color) {
						if (show_offset) {
							rz_strbuf_appendf(sb, "%s0x%08" PFMT64x " " Color_RESET, pal->offset, addr);
						}
						rz_strbuf_appendf(sb, "%s%s%s%s%s%s%s\n",
							linecolor ? linecolor : "",
							string2 ? string2 : "", string2 ? " " : "", string,
							flag ? " " : "", flag ? rz_flag_item_get_name(flag) : "", Color_RESET);
					} else {
						if (show_offset) {
							rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", addr);
						}
						rz_strbuf_appendf(sb, "%s%s%s%s%s\n",
							string2 ? string2 : "", string2 ? " " : "", string,
							flag ? " " : "", flag ? rz_flag_item_get_name(flag) : "");
					}
				}
			}
		}
		free(string);
		free(string2);
	}
	free(switchcmp);
restore_conf:
	free(dump_string);
	rz_list_free(lines);
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return rz_strbuf_drain(sb);
}

RZ_IPI const char *rz_core_print_stack_command(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	if (rz_config_get_b(core->config, "dbg.slow")) {
		return "pxr";
	}
	if (rz_config_get_b(core->config, "stack.bytes")) {
		return "px";
	}
	switch (core->rasm->bits) {
	case 64: return "pxq"; break;
	case 32: return "pxw"; break;
	}
	return "px";
}

///< Pointers to different components of the pf format string
typedef struct {
	char *name; ///< format name
	char *field; ///< format field (e.g. structure field)
	char *value; ///< value to write (after "=")
} pf_components;

// Parses the string into three component's
// to support also the `pfw bla.foo.goo=1235` syntax
static RZ_OWN pf_components *parse_named_pf_string(const char *fmt) {
	pf_components *comp = RZ_NEW0(pf_components);
	if (!comp) {
		return NULL;
	}
	// Format name could be after first dot
	// Note, that regular `pf` format also can start from the dot
	char *cur = (char *)fmt;
	if (fmt[0] == '.') {
		cur++;
	}
	// There is a format field specified
	const char *dot = strchr(cur, '.');
	if (dot) {
		comp->name = rz_sub_str_ptr(fmt, cur, dot - 1);
		cur = (char *)dot;
	} else {
		comp->name = rz_sub_str_ptr(fmt, cur, cur + strlen(cur));
	}
	// Name is mandatory
	if (!comp->name) {
		free(comp);
		return NULL;
	}
	// There is a value to write specified
	const char *eq = strchr(cur, '=');
	if (eq) {
		comp->field = rz_sub_str_ptr(fmt, cur + 1, eq - 1);
		comp->value = rz_sub_str_ptr(fmt, eq + 1, eq + strlen(eq));
	} else {
		comp->field = rz_sub_str_ptr(fmt, cur + 1, cur + strlen(cur));
	}
	return comp;
}

static RZ_OWN char *pf_get_format_name(const char *fmt) {
	// Format name could be after first dot
	// Note, that regular `pf` format also can start from the dot
	char *start = (char *)fmt;
	char *end = (char *)fmt + strlen(fmt);
	if (fmt[0] == '.') {
		start++;
	}
	// There is a format field specified
	const char *dot = strchr(start, '.');
	if (dot) {
		end = (char *)dot - 1;
	}
	return rz_sub_str_ptr(fmt, start, end);
}

/* Function allows to parse and print format in different syntaxes:
 * `pf .bla`
 * `pf foo.goo`
 * `pfw foo.goo=15`
 * `pfw foo.goo 15`
 *  ...
 */
static RZ_OWN char *core_print_format(RzCore *core, const char *fmt, const char *value, int mode, ut64 address) {
	int o_blocksize = core->blocksize;
	ut64 old_offset = core->offset;
	core->print->reg = rz_core_reg_default(core);
	core->print->get_register = rz_reg_get;
	core->print->get_register_value = rz_reg_get_value;

	rz_core_seek(core, address, true);

	// Try to parse the format string and detect if there is a possible name
	pf_components *comp = NULL;
	char *fmtname = pf_get_format_name(fmt);
	if (fmtname) {
		// To be sure it's the format name, receive the format string
		const char *format = rz_type_db_format_get(core->analysis->typedb, fmtname);
		if (format) {
			comp = parse_named_pf_string(fmt);
			// Value was passed not through "="
			if (value && comp && !comp->value) {
				comp->value = rz_str_dup(value);
			}
		}
	}
	int struct_sz = 0;
	if (comp) {
		// If the split into components is finished, use the only format name
		struct_sz = rz_type_format_struct_size(core->analysis->typedb, comp->name, mode, 0);
	} else {
		struct_sz = rz_type_format_struct_size(core->analysis->typedb, fmt, mode, 0);
	}
	size_t size = RZ_MAX(core->blocksize, struct_sz);
	// Make sure the whole format will be processed
	if (size > core->blocksize) {
		rz_core_block_size(core, size);
	}
	char *result = NULL;
	ut8 *buf = calloc(1, size);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %zu byte(s)\n", size);
		goto stage_left;
	}
	memcpy(buf, core->block, core->blocksize);
	free(fmtname);
	// Use the component-based data formatting if split was correct
	if (comp) {
		result = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
			buf, size, comp->name, mode, comp->value, comp->field);
	} else {
		result = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
			buf, size, fmt, mode, value, NULL);
	}
	free(buf);

stage_left:
	rz_core_seek(core, old_offset, true);
	rz_core_block_size(core, o_blocksize);
	return result;
}

RZ_IPI RZ_OWN char *rz_core_print_format(RzCore *core, const char *fmt, int mode, ut64 address) {
	return core_print_format(core, fmt, NULL, mode, address);
}

RZ_IPI RZ_OWN char *rz_core_print_format_write(RzCore *core, const char *fmt, const char *value, ut64 address) {
	return core_print_format(core, fmt, value, RZ_PRINT_MUSTSET, address);
}
