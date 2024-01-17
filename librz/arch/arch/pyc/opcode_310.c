// SPDX-FileCopyrightText: 2023 FXTi <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "opcode.h"

pyc_opcodes *opcode_310(void) {
	pyc_opcodes *ret = opcode_39();
	if (!ret) {
		return NULL;
	}

	ret->version_sig = (void *(*)())opcode_310;
	ret->jump_use_instruction_offset = true;

	return ret;
}
