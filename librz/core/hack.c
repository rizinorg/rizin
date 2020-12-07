// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

/* We can not use some kind of structure type with
 * a string for each case, because some architectures (like ARM)
 * have several modes/alignment requirements.
 */

void rz_core_hack_help(const RzCore *core) {
	const char* help_msg[] = {
		"wao", " [op]", "performs a modification on current opcode",
		"wao", " nop", "nop current opcode",
		"wao", " jinf", "assemble an infinite loop",
		"wao", " jz", "make current opcode conditional (zero)",
		"wao", " jnz", "make current opcode conditional (not zero)",
		"wao", " ret1", "make the current opcode return 1",
		"wao", " ret0", "make the current opcode return 0",
		"wao", " retn", "make the current opcode return -1",
		"wao", " nocj", "remove conditional operation from branch (make it unconditional)",
		"wao", " trap", "make the current opcode a trap",
		"wao", " recj", "reverse (swap) conditional branch instruction",
		"WIP:", "", "not all archs are supported and not all commands work on all archs",
		NULL
	};
	rz_core_cmd_help (core, help_msg);
}

RZ_API bool rz_core_hack_dalvik(RzCore *core, const char *op, const RzAnalysisOp *analop) {
	if (!strcmp (op, "nop")) {
		rz_core_cmdf (core, "wx 0000");
	} else if (!strcmp (op, "ret2")) {
		rz_core_cmdf (core, "wx 12200f00"); // mov v0, 2;ret v0
	} else if (!strcmp (op, "jinf")) {
		rz_core_cmd0 (core, "wx 2800\n");
	} else if (!strcmp (op, "ret1")) {
		rz_core_cmdf (core, "wx 12100f00"); // mov v0, 1;ret v0
	} else if (!strcmp (op, "ret0")) {
		rz_core_cmdf (core, "wx 12000f00"); // mov v0, 0;ret v0
	} else {
		eprintf ("Unsupported operation '%s'\n", op);
		return false;
	}
	return true;
}

RZ_API bool rz_core_hack_arm64(RzCore *core, const char *op, const RzAnalysisOp *analop) {
	if (!strcmp (op, "nop")) {
		rz_core_cmdf (core, "wx 1f2003d5");
	} else if (!strcmp (op, "ret")) {
		rz_core_cmdf (core, "wx c0035fd6t");
	} else if (!strcmp (op, "trap")) {
		rz_core_cmdf (core, "wx 000020d4");
	} else if (!strcmp (op, "jz")) {
		eprintf ("ARM jz hack not supported\n");
		return false;
	} else if (!strcmp (op, "jinf")) {
		rz_core_cmdf (core, "wx 00000014");
	} else if (!strcmp (op, "jnz")) {
		eprintf ("ARM jnz hack not supported\n");
		return false;
	} else if (!strcmp (op, "nocj")) {
		eprintf ("ARM jnz hack not supported\n");
		return false;
	} else if (!strcmp (op, "recj")) {
		eprintf ("TODO: use jnz or jz\n");
		return false;
	} else if (!strcmp (op, "ret1")) {
		rz_core_cmdf (core, "wa mov x0, 1,,ret");
	} else if (!strcmp (op, "ret0")) {
		rz_core_cmdf (core, "wa mov x0, 0,,ret");
	} else if (!strcmp (op, "retn")) {
		rz_core_cmdf (core, "wa mov x0, -1,,ret");
	} else {
		eprintf ("Invalid operation '%s'\n", op);
		return false;
	}
	return true;
}
RZ_API bool rz_core_hack_arm(RzCore *core, const char *op, const RzAnalysisOp *analop) {
	const int bits = core->rasm->bits;
	const ut8 *b = core->block;

	if (!strcmp (op, "nop")) {
		const int nopsize = (bits==16)? 2: 4;
		const char *nopcode = (bits==16)? "00bf":"0000a0e1";
		const int len = analop->size;
		char* str;
		int i;

		if (len % nopsize) {
			eprintf ("Invalid nopcode size\n");
			return false;
		}

		str = calloc (len + 1, 2);
		if (!str) {
			return false;
		}
		for (i=0; i < len; i+=nopsize) {
			memcpy (str + i * 2, nopcode, nopsize*2);
		}
		str[len*2] = '\0';
		rz_core_cmdf (core, "wx %s\n", str);
		free (str);
	} else if (!strcmp (op, "jinf")) {
		rz_core_cmdf (core, "wx %s\n", (bits==16)? "fee7": "feffffea");
	} else if (!strcmp (op, "trap")) {
		const char* trapcode = (bits==16)? "bebe": "fedeffe7";
		rz_core_cmdf (core, "wx %s\n", trapcode);
	} else if (!strcmp (op, "jz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb9: // CBNZ
				rz_core_cmd0 (core, "wx b1 @@ $$+1\n"); //CBZ
				break;
			case 0xbb: // CBNZ
				rz_core_cmd0 (core, "wx b3 @@ $$+1\n"); //CBZ
				break;
			case 0xd1: // BNE
				rz_core_cmd0 (core, "wx d0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM jz hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "jnz")) {
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
				rz_core_cmd0 (core, "wx b9 @@ $$+1\n"); //CBNZ
				break;
			case 0xb3: // CBZ
				rz_core_cmd0 (core, "wx bb @@ $$+1\n"); //CBNZ
				break;
			case 0xd0: // BEQ
				rz_core_cmd0 (core, "wx d1 @@ $$+1\n"); //BNE
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM jnz hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "nocj")) {
		// TODO: drop conditional bit instead of that hack
		if (bits == 16) {
			switch (b[1]) {
			case 0xb1: // CBZ
			case 0xb3: // CBZ
			case 0xd0: // BEQ
			case 0xb9: // CBNZ
			case 0xbb: // CBNZ
			case 0xd1: // BNE
				rz_core_cmd0 (core, "wx e0 @@ $$+1\n"); //BEQ
				break;
			default:
				eprintf ("Current opcode is not conditional\n");
				return false;
			}
		} else {
			eprintf ("ARM un-cjmp hack not supported\n");
			return false;
		}
	} else if (!strcmp (op, "recj")) {
		eprintf ("TODO: use jnz or jz\n");
		return false;
	} else if (!strcmp (op, "ret1")) {
		if (bits == 16) {
			rz_core_cmd0 (core, "wx 01207047 @@ $$+1\n"); // mov r0, 1; bx lr
		} else {
			rz_core_cmd0 (core, "wx 0100b0e31eff2fe1 @@ $$+1\n"); // movs r0, 1; bx lr
		}
	} else if (!strcmp (op, "ret0")) {
		if (bits == 16) {
			rz_core_cmd0 (core, "wx 00207047 @@ $$+1\n"); // mov r0, 0; bx lr
		} else {
			rz_core_cmd0 (core, "wx 0000a0e31eff2fe1 @@ $$+1\n"); // movs r0, 0; bx lr
		}
	} else if (!strcmp (op, "retn")) {
		if (bits == 16) {
			rz_core_cmd0 (core, "wx ff207047 @@ $$+1\n"); // mov r0, -1; bx lr
		} else {
			rz_core_cmd0 (core, "wx ff00a0e31eff2fe1 @@ $$+1\n"); // movs r0, -1; bx lr
		}
	} else {
		eprintf ("Invalid operation\n");
		return false;
	}
	return true;
}

RZ_API bool rz_core_hack_x86(RzCore *core, const char *op, const RzAnalysisOp *analop) {
	const ut8 *b = core->block;
	int i, size = analop->size;
	if (!strcmp (op, "nop")) {
		if (size * 2 + 1 < size) {
			return false;
		}
		char *str = malloc (size * 2 + 1);
		if (!str) {
			return false;
		}
		for (i = 0; i < size; i++) {
			memcpy (str + (i * 2), "90", 2);
		}
		str[size*2] = '\0';
		rz_core_cmdf (core, "wx %s\n", str);
		free (str);
	} else if (!strcmp (op, "trap")) {
		rz_core_cmd0 (core, "wx cc\n");
	} else if (!strcmp (op, "jz")) {
		if (b[0] == 0x75) {
			rz_core_cmd0 (core, "wx 74\n");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "jinf")) {
		rz_core_cmd0 (core, "wx ebfe\n");
	} else if (!strcmp (op, "jnz")) {
		if (b[0] == 0x74) {
			rz_core_cmd0 (core, "wx 75\n");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "nocj")) {
		if (*b == 0xf) {
			rz_core_cmd0 (core, "wx 90e9");
		} else if (b[0] >= 0x70 && b[0] <= 0x7f) {
			rz_core_cmd0 (core, "wx eb");
		} else {
			eprintf ("Current opcode is not conditional\n");
			return false;
		}
	} else if (!strcmp (op, "recj")) {
		int is_near = (*b == 0xf);
		if (b[0] < 0x80 && b[0] >= 0x70) { // short jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
				rz_core_cmdf (core, "wx %x\n", (b[0]%2)? b[0] - 1: b[0] + 1);
		} else if (is_near && b[1] < 0x90 && b[1] >= 0x80) { // near jmps: jo, jno, jb, jae, je, jne, jbe, ja, js, jns
				rz_core_cmdf (core, "wx 0f%x\n", (b[1]%2)? b[1] - 1: b[1] + 1);
		} else {
			eprintf ("Invalid conditional jump opcode\n");
			return false;
		}
	} else if (!strcmp (op, "ret1")) {
		rz_core_cmd0 (core, "wx c20100\n");
	} else if (!strcmp (op, "ret0")) {
		rz_core_cmd0 (core, "wx c20000\n");
	} else if (!strcmp (op, "retn")) {
		rz_core_cmd0 (core, "wx c2ffff\n");
	} else {
		eprintf ("Invalid operation '%s'\n", op);
		return false;
	}
	return true;
}

RZ_API int rz_core_hack(RzCore *core, const char *op) {
	bool (*hack)(RzCore *core, const char *op, const RzAnalysisOp *analop) = NULL;
	const char *asmarch = rz_config_get (core->config, "asm.arch");
	const int asmbits = core->rasm->bits;

	if (!asmarch) {
		return false;
	}
	if (strstr (asmarch, "x86")) {
		hack = rz_core_hack_x86;
	} else if (strstr (asmarch, "dalvik")) {
		hack = rz_core_hack_dalvik;
	} else if (strstr (asmarch, "arm")) {
		if (asmbits == 64) {
			hack = rz_core_hack_arm64;
		} else {
			hack = rz_core_hack_arm;
		}
	} else {
		eprintf ("TODO: write hacks are only for x86\n");
	}
	if (hack) {
		RzAnalysisOp analop;
		if (!rz_analysis_op (core->analysis, &analop, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC)) {
			eprintf ("anal op fail\n");
			return false;
		}
		return hack (core, op, &analop);
	}
	return false;
}
