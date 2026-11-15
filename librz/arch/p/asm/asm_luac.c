// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-FileCopyrightText: 2026 Arya-1-HR

#include <asm_private.h>
#include "rz_asm.h"
#include "arch/isa/luac/lua_arch.h"

int rz_luajit_disasm(const RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len) {
	LuaJITInstructions instr = rz_read_ble32(buf, a->big_endian);
	LuaJITOpCode opcode = LUAJIT_GET_OPCODE(instr);
	LuaJITOpName opname = luajit_get_opname(opcode);
	return luajit_disasm(opstruct, len, opname, instr, opcode);
}

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
	const char *cpu = rz_asm_get_cpu(a);

	if (rz_str_startswith(cpu, "luajit")) {
		return rz_luajit_disasm(a, opstruct, buf, len);
	} else if (RZ_STR_EQ(cpu, "5.0")) {
		r = lua50_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(cpu, "5.1")) {
		r = lua51_disasm(opstruct, instruction, LUA_51_VERSION_VANILLA);
	} else if (RZ_STR_EQ(cpu, "openwrt-5.1")) {
		r = lua51_disasm(opstruct, instruction, LUA_51_VERSION_OPENWRT);
	} else if (RZ_STR_EQ(cpu, "tp-link-5.1")) {
		r = lua51_disasm(opstruct, instruction, LUA_51_VERSION_TPLINK);
	} else if (RZ_STR_EQ(cpu, "5.2")) {
		r = lua52_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(cpu, "5.3")) {
		r = lua53_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(cpu, "5.4")) {
		r = lua54_disasm(opstruct, instruction);
	} else if (RZ_STR_EQ(cpu, "5.5")) {
		r = lua55_disasm(opstruct, instruction);
	} else {
		RZ_LOG_ERROR("disassembler: lua: version %s is not supported\n", a->cpu);
		return -1;
	}
	return r;
}

int rz_luac_asm(const RzAsm *a, RzAsmOp *opstruct, const char *str) {
	if (rz_str_startswith(a->cpu, "luajit")) {
		return 0;
	}
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
		instruction = lua51_assembly(arg_start, opcode_len, opcode_start, LUA_51_VERSION_VANILLA);
	} else if (RZ_STR_EQ(a->cpu, "openwrt-5.1")) {
		instruction = lua51_assembly(arg_start, opcode_len, opcode_start, LUA_51_VERSION_OPENWRT);
	} else if (RZ_STR_EQ(a->cpu, "tp-link-5.1")) {
		instruction = lua51_assembly(arg_start, opcode_len, opcode_start, LUA_51_VERSION_TPLINK);
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

static char **luac_cpu_descriptions() {
	static char *cpu_desc[] = {
		"5.0", "Official 5.0 Lua compiler",
		"5.1", "Official 5.1 Lua compiler",
		"5.2", "Official 5.2 Lua compiler",
		"5.3", "Official 5.3 Lua compiler",
		"5.4", "Official 5.4 Lua compiler",
		"5.5", "Official 5.5 Lua compiler",
		"openwrt-5.1", "5.1 version of Lua compiler, modified by OpenWRT project",
		"tp-link-5.1", "5.1 version of Lua compiler, modified by OpenWRT project and TP-Link vendor",
		NULL
	};
	return cpu_desc;
}

RzAsmPlugin rz_asm_plugin_luac = {
	.name = "luac",
	.arch = "luac",
	.license = "LGPL3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BI,
	.desc = "Lua bytecode (LUAC) disassembler",
	.disassemble = &rz_luac_disasm,
	.assemble = &rz_luac_asm,
	.cpus =
		"5.0,"
		"5.1,"
		"5.2,"
		"5.3,"
		"5.4,"
		"5.5,"
		"openwrt-5.1,"
		"tp-link-5.1",
	.get_cpu_desc = luac_cpu_descriptions,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = rz_asm_plugin_luac,
	.version = RZ_VERSION
};
#endif
