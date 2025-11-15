// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_vector.h>
#include <rz_th.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_util/rz_assert.h>

RZ_IPI RzCmdStatus rz_inquiry_interpreter_prototype_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io, RZ_CMD_STATUS_ERROR);
	return rz_inquiry_interpreter(core, argc, argv) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
