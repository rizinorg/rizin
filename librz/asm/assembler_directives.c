typedef bool (*AsmParseDir)(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size);

typedef struct assembler_directive_t {
	const char* directive;
	size_t dirsize;
	AsmParseDir parse;
} AssemblerDir;

static bool assembler_dir_intel_syntax(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_att_syntax(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_endian(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_big_endian(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_lil_endian(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_little_endian(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_asciz(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_string(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_ascii(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_align(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_arm(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_thumb(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_arch(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_bits(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_fill(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_kernel(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_cpu(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_os(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_hex(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_int16(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_short(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_int32(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_int64(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_size(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_section(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_byte(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_int8(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_glob(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

static bool assembler_dir_set(RzAsm *a, AssemblerCtx *ac, const char* line, ut32 size) {
	return true;
}

#define DS(x) x, (sizeof(x) - 1)
static AssemblerDir assembler_directives_expression[] = {
	{ DS(".equ"), assembler_dir_set },
	{ DS(".set"), assembler_dir_set },
};

static AssemblerDir assembler_directives_assemble[] = {
	{ DS(".align"), assembler_dir_align },
	{ DS(".arch"), assembler_dir_arch },
	{ DS(".arm"), assembler_dir_arm },
	{ DS(".ascii"), assembler_dir_ascii },
	{ DS(".asciz"), assembler_dir_asciz },
	{ DS(".att_syntax"), assembler_dir_att_syntax },
	{ DS(".big_endian"), assembler_dir_big_endian },
	{ DS(".bits"), assembler_dir_bits },
	{ DS(".cpu"), assembler_dir_cpu },
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
	{ DS(".intel_syntax"), assembler_dir_intel_syntax },
	{ DS(".kernel"), assembler_dir_kernel },
	{ DS(".lil_endian"), assembler_dir_little_endian },
	{ DS(".little_endian"), assembler_dir_little_endian },
	{ DS(".os"), assembler_dir_os },
	{ DS(".section"), assembler_dir_section },
	{ DS(".size"), assembler_dir_size },
	{ DS(".string"), assembler_dir_string },
	{ DS(".thumb"), assembler_dir_thumb },
};

#undef DS
