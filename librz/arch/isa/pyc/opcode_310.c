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

	def_op(.op_obj = ret->opcodes, .op_name = "GET_LEN", .op_code = 30, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_KEYS", .op_code = 33, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_SEQUENCE", .op_code = 32, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_MAPPING", .op_code = 31, .pop = 0, .push = 1);
	def_op(.op_obj = ret->opcodes, .op_name = "MATCH_CLASS", .op_code = 152, .pop = 3, .push = 1);

	ret->version_sig = (opcode_func)opcode_310;
	ret->jump_use_instruction_offset = true;

	return ret;
}
