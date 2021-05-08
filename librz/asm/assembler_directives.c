typedef bool (*AsmParseDir)(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc);

typedef struct assembler_directive_t {
	const char* directive;
	size_t dirsize;
	AsmParseDir parse;
} AssemblerDir;

static bool assembler_dir_intel_syntax(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_att_syntax(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_endian(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_big_endian(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_little_endian(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_asciz(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_string(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_ascii(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_align(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_arm(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	rz_asm_use(a, "arm");
	rz_asm_set_bits(a, 32);
	return true;
}

static bool assembler_dir_thumb(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	rz_asm_use(a, "arm");
	rz_asm_set_bits(a, 16);
	return true;
}

static bool assembler_dir_arch(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing architecture name.");
		return false;
	}
	if (!rz_asm_use(a, word)) {
		assembler_error_line(ac, nline, position, " unknown architecture name.");
		return false;
	}
	return true;
}

static bool assembler_dir_bits(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing bits value.");
		return false;
	}

	ut64 bits = rz_num_math(NULL, word);
	if (bits < 1 || !rz_asm_set_bits(a, bits)) {
		assembler_error_line(ac, nline, position, " invalid bits value.");
		return false;
	}
	return true;
}

static bool assembler_dir_fill(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_kernel(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_cpu(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_os(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_hex(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing hexadecimal value.");
		return false;
	}
	return true;
}

static bool assembler_dir_int8(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	ut8 data[sizeof(ut8)];
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing numeric value.");
		return false;
	}

	ut64 value = rz_num_math(NULL, word);
	rz_write_be8(data, value);
	return assembler_bin_cpy(ac->binary, nline, data, sizeof(data));
}

static bool assembler_dir_int16(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	ut8 data[sizeof(ut16)];
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing numeric value.");
		return false;
	}

	ut64 value = rz_num_math(NULL, word);
	if (a->big_endian) {
		rz_write_be16(data, value);
	} else {
		rz_write_le16(data, value);
	}
	return assembler_bin_cpy(ac->binary, nline, data, sizeof(data));
}

static bool assembler_dir_int32(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	ut8 data[sizeof(ut32)];
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing numeric value.");
		return false;
	}

	ut64 value = rz_num_math(NULL, word);
	if (a->big_endian) {
		rz_write_be32(data, value);
	} else {
		rz_write_le32(data, value);
	}
	return assembler_bin_cpy(ac->binary, nline, data, sizeof(data));
}

static bool assembler_dir_int64(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	ut8 data[sizeof(ut64)];
	const char *word = rz_str_trim_head_ro(assembler_ctx_line(ac, nline) + position);
	if (IS_NULLSTR(word)) {
		assembler_error_line(ac, nline, position, " missing numeric value.");
		return false;
	}

	ut64 value = rz_num_math(NULL, word);
	if (a->big_endian) {
		rz_write_be64(data, value);
	} else {
		rz_write_le64(data, value);
	}
	return assembler_bin_cpy(ac->binary, nline, data, sizeof(data));
}

static bool assembler_dir_size(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_section(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_glob(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

static bool assembler_dir_set(RzAsm *a, AssemblerCtx *ac, ut32 nline, ut32 position, ut64 pc) {
	return true;
}

#define DS(x) x, (sizeof(x) - 1)
static AssemblerDir assembler_directives_expression[] = {
	{ DS(".equ"), assembler_dir_set },
	{ DS(".set"), assembler_dir_set },
};

static AssemblerDir assembler_directives_data[] = {
	{ DS(".ascii"), assembler_dir_ascii },
	{ DS(".asciz"), assembler_dir_asciz },
	{ DS(".big_endian"), assembler_dir_big_endian },
	{ DS(".endian"), assembler_dir_endian },
	{ DS(".fill"), assembler_dir_fill },
	{ DS(".glob"), assembler_dir_glob },
	{ DS(".hex"), assembler_dir_hex },
	{ DS(".int8"), assembler_dir_int8 },
	{ DS(".byte"), assembler_dir_int8 },
	{ DS(".int16"), assembler_dir_int16 },
	{ DS(".short"), assembler_dir_int16 },
	{ DS(".int32"), assembler_dir_int32 },
	{ DS(".int64"), assembler_dir_int64 },
	{ DS(".lil_endian"), assembler_dir_little_endian },
	{ DS(".little_endian"), assembler_dir_little_endian },
	{ DS(".section"), assembler_dir_section },
	{ DS(".string"), assembler_dir_string },
};

static AssemblerDir assembler_directives_text[] = {
	{ DS(".align"), assembler_dir_align },
	{ DS(".arch"), assembler_dir_arch },
	{ DS(".arm"), assembler_dir_arm },
	{ DS(".att_syntax"), assembler_dir_att_syntax },
	{ DS(".big_endian"), assembler_dir_big_endian },
	{ DS(".bits"), assembler_dir_bits },
	{ DS(".cpu"), assembler_dir_cpu },
	{ DS(".endian"), assembler_dir_endian },
	{ DS(".glob"), assembler_dir_glob },
	{ DS(".intel_syntax"), assembler_dir_intel_syntax },
	{ DS(".kernel"), assembler_dir_kernel },
	{ DS(".lil_endian"), assembler_dir_little_endian },
	{ DS(".little_endian"), assembler_dir_little_endian },
	{ DS(".os"), assembler_dir_os },
	{ DS(".section"), assembler_dir_section },
	{ DS(".size"), assembler_dir_size },
	{ DS(".thumb"), assembler_dir_thumb },
};

#undef DS
