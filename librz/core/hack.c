// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

/* We can not use some kind of structure type with
 * a string for each case, because some architectures (like ARM)
 * have several modes/alignment requirements.
 */

RZ_API bool rz_core_hack_dalvik(RzCore *core, const char *op, const RzAnalysisOp *aop) {
	if (!strcmp(op, "nop")) {
		rz_core_write_hexpair(core, core->offset, "0000");
	} else if (!strcmp(op, "ret2")) {
		rz_core_write_hexpair(core, core->offset, "12200f00"); // mov v0, 2;ret v0
	} else if (!strcmp(op, "jinf")) {
		rz_core_write_hexpair(core, core->offset, "2800");
	} else if (!strcmp(op, "ret1")) {
		rz_core_write_hexpair(core, core->offset, "12100f00"); // mov v0, 1;ret v0
	} else if (!strcmp(op, "ret0")) {
		rz_core_write_hexpair(core, core->offset, "12000f00"); // mov v0, 0;ret v0
	} else {
		RZ_LOG_ERROR("core: hack: unsupported operation '%s'\n", op);
		return false;
	}
	return true;
}

RZ_API bool rz_core_hack_arm64(RzCore *core, const char *op, const RzAnalysisOp *aop) {
	if (!strcmp(op, "nop")) {
		rz_core_write_hexpair(core, core->offset, "1f2003d5");
	} else if (!strcmp(op, "ret")) {
		rz_core_write_hexpair(core, core->offset, "c0035fd6t");
	} else if (!strcmp(op, "trap")) {
		rz_core_write_hexpair(core, core->offset, "000020d4");
	} else if (!strcmp(op, "jinf")) {
		rz_core_write_hexpair(core, core->offset, "00000014");
	} else if (!strcmp(op, "ret1")) {
		rz_core_write_assembly(core, core->offset, "mov x0, 1,,ret");
	} else if (!strcmp(op, "ret0")) {
		rz_core_write_assembly(core, core->offset, "mov x0, 0,,ret");
	} else if (!strcmp(op, "retn")) {
		rz_core_write_assembly(core, core->offset, "mov x0, -1,,ret");
	} else {
		RZ_LOG_ERROR("core: hack: invalid operation '%s'\n", op);
		return false;
	}
	return true;
}

RZ_API bool rz_core_hack_arm(RzCore *core, const char *op, const RzAnalysisOp *aop) {
	const int bits = core->rasm->bits;
	const ut8 *b = core->block;

	if (!strcmp(op, "nop")) {
		const int nopsize = (bits == 16) ? 2 : 4;
		const char *nopcode = (bits == 16) ? "00bf" : "0000a0e1";
		const int len = aop->size;
		char *str;
		int i;

		if (len % nopsize) {
			RZ_LOG_ERROR("core: hack: invalid nopcode size\n");
			return false;
		}

		str = calloc(len + 1, 2);
		if (!str) {
			return false;
		}
		for (i = 0; i < len; i += nopsize) {
			memcpy(str + i * 2, nopcode, nopsize * 2);
		}
		str[len * 2] = '\0';
		rz_core_write_hexpair(core, core->offset, str);
		free(str);
	} else if (!strcmp(op, "jinf")) {
		rz_core_write_hexpair(core, core->offset, (bits == 16) ? "fee7" : "feffffea");
	} else if (!strcmp(op, "trap")) {
		rz_core_write_hexpair(core, core->offset, (bits == 16) ? "bebe" : "fedeffe7");
	} else if (!strcmp(op, "jz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				rz_core_write_hexpair(core, core->offset + 1, "b1"); // CBZ
				break;
			case 0xbb: // CBNZ
				rz_core_write_hexpair(core, core->offset + 1, "b3"); // CBZ
				break;
			case 0xd1: // BNE
				rz_core_write_hexpair(core, core->offset + 1, "d0"); // BEQ
				break;
			default:
				RZ_LOG_ERROR("core: hack: current opcode is not conditional\n");
				return false;
			}
		} else {
			RZ_LOG_ERROR("core: hack: ARM jz hack not supported\n");
			return false;
		}
	} else if (!strcmp(op, "jnz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				rz_core_write_hexpair(core, core->offset + 1, "b9"); // CBNZ
				break;
			case 0xb3: // CBZ
				rz_core_write_hexpair(core, core->offset + 1, "bb"); // CBNZ
				break;
			case 0xd0: // BEQ
				rz_core_write_hexpair(core, core->offset + 1, "d1"); // BNE
				break;
			default:
				RZ_LOG_ERROR("core: hack: Current opcode is not conditional\n");
				return false;
			}
		} else {
			RZ_LOG_ERROR("core: hack: ARM jnz hack not supported\n");
			return false;
		}
	} else if (!strcmp(op, "nocj")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				rz_core_write_hexpair(core, core->offset + 1, "e0"); // BEQ
				break;
			default:
				RZ_LOG_ERROR("core: hack: Current opcode is not conditional\n");
				return false;
			}
		} else {
			RZ_LOG_ERROR("core: hack: ARM un-cjmp hack not supported\n");
			return false;
		}
	} else if (!strcmp(op, "recj")) {
		RZ_LOG_ERROR("core: hack: please, use jnz or jz\n");
		return false;
	} else if (!strcmp(op, "ret1")) {
		if (bits == 16) {
			rz_core_write_hexpair(core, core->offset, "01207047"); // mov r0, 1; bx lr
		} else {
			rz_core_write_hexpair(core, core->offset, "0100b0e31eff2fe1"); // movs r0, 1; bx lr
		}
	} else if (!strcmp(op, "ret0")) {
		if (bits == 16) {
			rz_core_write_hexpair(core, core->offset, "00207047"); // mov r0, 0; bx lr
		} else {
			rz_core_write_hexpair(core, core->offset, "0000a0e31eff2fe1"); // movs r0, 0; bx lr
		}
	} else if (!strcmp(op, "retn")) {
		if (bits == 16) {
			rz_core_write_hexpair(core, core->offset, "ff207047"); // mov r0, -1; bx lr
		} else {
			rz_core_write_hexpair(core, core->offset, "ff00a0e31eff2fe1"); // movs r0, -1; bx lr
		}
	} else {
		RZ_LOG_ERROR("core: hack: invalid operation\n");
		return false;
	}
	return true;
}

RZ_API bool rz_core_hack_x86(RzCore *core, const char *op, const RzAnalysisOp *aop) {
	const ut8 *b = core->block;
	int i, size = aop->size;
	if (!strcmp(op, "nop")) {
		if (size * 2 + 1 < size) {
			return false;
		}
		char *str = malloc(size * 2 + 1);
		if (!str) {
			return false;
		}
		for (i = 0; i < size; i++) {
			memcpy(str + (i * 2), "90", 2);
		}
		str[size * 2] = '\0';
		rz_core_write_hexpair(core, core->offset, str);
		free(str);
	} else if (!strcmp(op, "trap")) {
		rz_core_write_hexpair(core, core->offset, "cc");
	} else if (!strcmp(op, "jz")) {
		if (b[0] == 0x75) {
			rz_core_write_hexpair(core, core->offset, "74");
		} else {
			RZ_LOG_ERROR("core: hack: current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp(op, "jinf")) {
		rz_core_write_hexpair(core, core->offset, "ebfe");
	} else if (!strcmp(op, "jnz")) {
		if (b[0] == 0x74) {
			rz_core_write_hexpair(core, core->offset, "75");
		} else {
			RZ_LOG_ERROR("core: hack: current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp(op, "nocj")) {
		if (*b == 0xf) {
			rz_core_write_hexpair(core, core->offset, "90e9");
		} else if (b[0] >= 0x70 && b[0] <= 0x7f) {
			rz_core_write_hexpair(core, core->offset, "eb");
		} else {
			RZ_LOG_ERROR("core: hack: current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp(op, "recj")) {
		int is_near = (*b == 0xf);
		if (b[0] < 0x80 && b[0] >= 0x70) { // short jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
			char *opcode = rz_str_newf("%x", (b[0] % 2) ? b[0] - 1 : b[0] + 1);
			rz_core_write_hexpair(core, core->offset, opcode);
			free(opcode);
		} else if (is_near && b[1] < 0x90 && b[1] >= 0x80) { // near jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
			char *opcode = rz_str_newf("0f%x", (b[1] % 2) ? b[1] - 1 : b[1] + 1);
			rz_core_write_hexpair(core, core->offset, opcode);
			free(opcode);
		} else {
			RZ_LOG_ERROR("core: hack: invalid conditional jump opcode\n");
			return false;
		}
	} else if (!strcmp(op, "ret1")) {
		rz_core_write_hexpair(core, core->offset, "c20100");
	} else if (!strcmp(op, "ret0")) {
		rz_core_write_hexpair(core, core->offset, "c20000");
	} else if (!strcmp(op, "retn")) {
		rz_core_write_hexpair(core, core->offset, "c2ffff");
	} else {
		RZ_LOG_ERROR("core: hack: invalid operation '%s'\n", op);
		return false;
	}
	return true;
}

/**
 * \brief Write/Modify instructions at current offset based on \p op.
 *
 * See specific functions rz_core_hack_<arch> for what they accept as \p op .
 *
 * \param core RzCore instance
 * \param op A string representing one of the operation that can be performed on the current offset
 * \return true if the write was done correctly, false otherwise
 */
RZ_API bool rz_core_hack(RzCore *core, const char *op) {
	// TODO: op should not be an unstructered string
	// TODO: asm/analysis plugins should provide the operations, instead of doing this here
	bool (*hack)(RzCore *core, const char *op, const RzAnalysisOp *aop) = NULL;
	const char *asmarch = rz_config_get(core->config, "asm.arch");
	const int asmbits = core->rasm->bits;

	if (!asmarch) {
		return false;
	}
	if (strstr(asmarch, "x86")) {
		hack = rz_core_hack_x86;
	} else if (strstr(asmarch, "dalvik")) {
		hack = rz_core_hack_dalvik;
	} else if (strstr(asmarch, "arm")) {
		if (asmbits == 64) {
			hack = rz_core_hack_arm64;
		} else {
			hack = rz_core_hack_arm;
		}
	} else {
		RZ_LOG_ERROR("core: hack: write hacks are only supported on x86 arch\n");
	}
	if (hack) {
		RzAnalysisOp aop = { 0 };
		rz_analysis_op_init(&aop);
		if (rz_analysis_op(core->analysis, &aop, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
			rz_analysis_op_fini(&aop);
			RZ_LOG_ERROR("core: hack: analysis op fail\n");
			return false;
		}
		bool ret = hack(core, op, &aop);
		rz_analysis_op_fini(&aop);
		return ret;
	}
	return false;
}
