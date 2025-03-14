// SPDX-FileCopyrightText: 2023 FXTi <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_310(void) {
	pyc_opcodes *ret = opcode_39();
	if (!ret) {
		return NULL;
	}

	rm_op(.op_obj = ret->opcodes, .op_name = "RERAISE", .op_code = 48);
	def_op(.op_obj = ret->opcodes, .op_name = "RERAISE", .op_code = 119, .pop = 0, .push = 0);
	ret->version_sig = (opcode_func)opcode_310;
	ret->jump_use_instruction_offset = true;

	return ret;
}
