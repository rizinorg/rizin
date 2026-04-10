// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "rz_asm.h"
#include "arch/isa/luac/lua_arch.h"

int rz_luac_disasm(const RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	int r = 0;

	if (!a->cpu) {
		RZ_LOG_ERROR("disassembler: lua: no version info, specify it with `asm.cpu` option\n");
		return -1;
	}

	if (len < 4) {
		RZ_LOG_DEBUG("Cannot disassemble lua %s opcode (truncated).\n", a->cpu);
		return 0;
	}

	opstruct->size = 4;
	const ut32 instruction = rz_read_at_le32(buf, 0);

	if (RZ_STR_EQ(a->cpu, "5.0")) {
		r = lua50_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(a->cpu, "5.1")) {
		r = lua51_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(a->cpu, "5.2")) {
		r = lua52_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(a->cpu, "5.3")) {
		r = lua53_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(a->cpu, "5.4")) {
		r = lua54_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(a->cpu, "5.5")) {
		r = lua55_disasm(opstruct, instruction);
	} else {
		RZ_LOG_ERROR("disassembler: lua: version %s is not supported\n", a->cpu);
		return -1;
	}
	return r;
}

int rz_luac_asm(const RzAsm *a, RzAsmOp *opstruct, const char *str) {
	int str_len = strlen(str);

	rz_return_val_if_fail(str && str_len > 0, false);

	if (!a->cpu) {
		RZ_LOG_ERROR("assembler: lua: no version info, specify it with `asm.cpu` option\n");
		return -1;
	}

	/* Find the opcode */
	const char *opcode_start = str; ///< point to the header
	const char *opcode_end = strchr(str, ' '); ///< point to the first white space
	if (opcode_end == NULL) {
		opcode_end = str + str_len;
	}

	const int opcode_len = opcode_end - opcode_start;
	/* Find the arguments */
	const char *arg_start = rz_str_trim_head_ro(opcode_end);
	ut32 instruction = 0;

	if (RZ_STR_EQ(a->cpu, "5.0")) {
		instruction = lua50_assembly(arg_start, opcode_len, opcode_start);
	} else if (RZ_STR_EQ(a->cpu, "5.1")) {
		instruction = lua51_assembly(arg_start, opcode_len, opcode_start);
	} else if (RZ_STR_EQ(a->cpu, "5.2")) {
		instruction = lua52_assembly(arg_start, opcode_len, opcode_start);
	} else if (RZ_STR_EQ(a->cpu, "5.3")) {
		instruction = lua53_assembly(arg_start, opcode_len, opcode_start);
	} else if (RZ_STR_EQ(a->cpu, "5.4")) {
		instruction = lua54_assembly(arg_start, opcode_len, opcode_start);
	} else if (RZ_STR_EQ(a->cpu, "5.5")) {
		instruction = lua55_assembly(arg_start, opcode_len, opcode_start);
	} else {
		RZ_LOG_ERROR("assembler: lua: version %s is not supported\n", a->cpu);
		return -1;
	}
	if (instruction == LUA_INVALID_INSTRUCTION) {
		return -1;
	}
	rz_write_le32(&instruction, instruction);
	rz_strbuf_setbin(&opstruct->buf, (const ut8 *)&instruction, 4);
	return 4;
}

RzAsmPlugin rz_asm_plugin_luac = {
	.name = "luac",
	.arch = "luac",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.desc = "Lua bytecode (LUAC) disassembler",
	.disassemble = &rz_luac_disasm,
	.assemble = &rz_luac_asm,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = rz_asm_plugin_luac,
	.version = RZ_VERSION
};
#endif
