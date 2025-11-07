// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_util/rz_assert.h>


RZ_IPI RzCmdStatus rz_inquiry_interpreter_prototype_handler(RzCore *core, int argc, const char **argv) {
	// Generate first basic block
	// Setup receive queue
	// setup send queue
	// Push entry point
	// Setup yield queue.
	// Dispatch interpreter into thread
	// pop wait for address.
	rz_interpreter_run(NULL, NULL, NULL);
	return RZ_CMD_STATUS_OK;
}
