// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Using the RzReg module for register management
 *
 * This example demonstrates:
 * - Creating an RzReg object
 * - Loading a custom register profile
 * - Setting and getting register values by name and role
 * - Using arena snapshots (push/pop)
 */

#include <rz_reg.h>
#include <rz_util.h>
#include <stdio.h>
#include <inttypes.h>

int main(int argc, char **argv) {
	// 1. Create a new register module instance
	RzReg *reg = rz_reg_new();
	if (!reg) {
		fprintf(stderr, "Failed to create RzReg instance\n");
		return 1;
	}

	// 2. Define and load a register profile
	// Definitions: type name .bits offset packed
	// Aliases: =role name
	const char *profile =
		"gpr  rax  .64  0  0\n"
		"gpr  rbx  .64  8  0\n"
		"gpr  rcx  .64  16 0\n"
		"gpr  rip  .64  24 0\n"
		"gpr  rsp  .64  32 0\n"
		"flg  zf   .1   40.0 0\n"
		"flg  cf   .1   40.1 0\n"
		"=PC  rip\n" // program counter
		"=SP  rsp\n"; // stack pointer

	printf("Loading register profile...\n");
	if (!rz_reg_set_profile_string(reg, profile)) {
		fprintf(stderr, "Failed to load register profile\n");
		rz_reg_free(reg);
		return 1;
	}

	// 3. Set and get register values by name
	printf("Setting rip to 0x400000\n");
	rz_reg_setv(reg, "rip", 0x400000);

	ut64 rip_val = rz_reg_getv(reg, "rip");
	printf("rip = 0x%" PRIx64 "\n", rip_val);

	// 4. Access values by role
	ut64 pc_val = rz_reg_get_value_by_role(reg, RZ_REG_NAME_PC);
	printf("PC (rip) = 0x%" PRIx64 "\n", pc_val);

	// 5. Working with flags (bit-level access)
	printf("Setting Zero Flag (zf) and Carry Flag (cf)\n");
	rz_reg_setv(reg, "zf", 1);
	rz_reg_setv(reg, "cf", 0);

	printf("zf = %" PRIu64 "\n", rz_reg_getv(reg, "zf"));
	printf("cf = %" PRIu64 "\n", rz_reg_getv(reg, "cf"));

	// 6. Arena snapshots (Push/Pop)
	printf("\n--- Arena Snapshot Example ---\n");
	printf("Current rip = 0x%" PRIx64 ". Pushing arena...\n", rz_reg_getv(reg, "rip"));
	rz_reg_arena_push(reg);

	printf("Changing rip to 0xDEADBEEF\n");
	rz_reg_setv(reg, "rip", 0xDEADBEEF);
	printf("rip = 0x%" PRIx64 "\n", rz_reg_getv(reg, "rip"));

	printf("Popping arena (restoring state)...\n");
	rz_reg_arena_pop(reg);
	printf("rip = 0x%" PRIx64 "\n", rz_reg_getv(reg, "rip"));

	// Clean up
	rz_reg_free(reg);
	printf("Done.\n");

	return 0;
}
