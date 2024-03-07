// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_26(void) {
	pyc_opcodes *ret = opcode_25();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_26;

	// Below are opcode changes since Python 2.5
	store_op(.op_obj = ret->opcodes, .op_name = "STORE_MAP", .op_code = 54, .pop = 3, .push = 1);

	rz_list_purge(ret->opcode_arg_fmt);
	add_arg_fmt(ret, "EXTENDED_ARG", format_extended_arg);

	return ret;
}
