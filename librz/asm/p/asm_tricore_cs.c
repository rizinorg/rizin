// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include "../arch/tricore/tricore.inc"

#define TRICORE_LONGEST_INSTRUCTION  4
#define TRICORE_SHORTEST_INSTRUCTION 2

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (!buf || len < TRICORE_SHORTEST_INSTRUCTION) {
		return -1;
	}

	csh handle;
	cs_insn *insn;
	cs_mode mode = tricore_cpu_to_cs_mode(a->cpu);
	cs_err err = cs_open(CS_ARCH_TRICORE, mode, &handle);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, RZ_STR_ISNOTEMPTY(a->features) ? CS_OPT_ON : CS_OPT_OFF);

	unsigned count = cs_disasm(handle, buf, len, a->pc, 1, &insn);
	if (count <= 0) {
		cs_close(&handle);
		return -1;
	}

	char *asmstr = rz_str_newf("%s%s%s", insn->mnemonic,
		RZ_STR_ISNOTEMPTY(insn->op_str) ? " " : "", insn->op_str);
	rz_asm_op_set_asm(op, asmstr);
	op->size = insn->size;

	free(asmstr);
	cs_close(&handle);
	cs_free(insn, count);
	return op->size;
}

#define TOKEN(_type, _pat) \
	do { \
		RzAsmTokenPattern *pat = RZ_NEW0(RzAsmTokenPattern); \
		pat->type = RZ_ASM_TOKEN_##_type; \
		pat->pattern = strdup(_pat); \
		rz_pvector_push(pvec, pat); \
	} while (0)

static RZ_OWN RzPVector /*<RzAsmTokenPattern *>*/ *get_token_patterns() {
	static RzPVector *pvec = NULL;
	if (pvec) {
		return pvec;
	}

	pvec = rz_pvector_new(rz_asm_token_pattern_free);

	TOKEN(META, "([\\[\\]])|(\\+[rc]?))");

	TOKEN(REGISTER, "([adep][[:digit:]]{1,2})");
	TOKEN(REGISTER, "(psw|pcxi|pc|fcx|lcx|isp|icr|pipn|biv|btv)");

	TOKEN(NUMBER, "(0x[[:digit:]abcdef]+)");
	TOKEN(NUMBER, "([[:digit:]]+)");

	TOKEN(MNEMONIC, "([[:alpha:]]+[[:alnum:]\\.]*[[:alnum:]]+)");

	TOKEN(SEPARATOR, "([[:blank:]]+)|([,;\\(\\)\\{\\}:])");

	return pvec;
}

typedef struct {
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} State;

static State *get_state() {
	static State *state = NULL;
	if (state) {
		return state;
	}

	state = RZ_NEW0(State);
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for HexState!");
	}
	return state;
}

static bool init(void **user) {
	State *state = get_state();
	rz_return_val_if_fail(state, false);

	*user = state; // user = RzAsm.plugin_data

	state->token_patterns = get_token_patterns();
	rz_asm_compile_token_patterns(state->token_patterns);
	return true;
}

RzAsmPlugin rz_asm_plugin_tricore = {
	.name = "tricore",
	.arch = "tricore",
	.author = "billow",
	.license = "BSD",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Siemens TriCore CPU",
	.disassemble = &disassemble,
	.init = &init,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_tricore,
	.version = RZ_VERSION
};
#endif
