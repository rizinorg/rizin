// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

RZ_IPI RzCmdStatus rz_inquiry_analyze_function_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io && core->bin->cur && core->bin->cur->o, RZ_CMD_STATUS_ERROR);
	return rz_core_inquiry_analyze_at(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_inquiry_analyze_all_handler(RzCore *core, int argc, const char **argv) {
	rz_return_val_if_fail(core->analysis && core->io && core->bin->cur && core->bin->cur->o, RZ_CMD_STATUS_ERROR);
	return rz_core_inquiry_analyze_all(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
