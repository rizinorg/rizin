// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_analysis.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "ops.h"
#include "code.h"

#ifndef RZ_API
#define RZ_API
#endif

static void init_switch_op(void);
static int enter_switch_op(ut64 addr, const ut8 *bytes, int len);
static int update_switch_op(ut64 addr, const ut8 *bytes);
static int update_bytes_consumed(int sz);
static int handle_switch_op(ut64 addr, const ut8 *bytes, char *output, int outlen);

static ut8 IN_SWITCH_OP = 0;
typedef struct current_table_switch_t {
	ut64 addr;
	int def_jmp;
	int min_val;
	int max_val;
	int cur_val;
} CurrentTableSwitch;

static CurrentTableSwitch SWITCH_OP;
static ut64 BYTES_CONSUMED = 0LL;

static void init_switch_op(void) {
	memset(&SWITCH_OP, 0, sizeof(SWITCH_OP));
}

static int enter_switch_op(ut64 addr, const ut8 *bytes, int len) {
	if (len < 16) {
		return 0;
	}
	int sz = 4;
	init_switch_op();
	IN_SWITCH_OP = 1;
	SWITCH_OP.addr = addr;
	SWITCH_OP.def_jmp = (rz_read_at_be32(bytes, sz));
	SWITCH_OP.min_val = (rz_read_at_be32(bytes, sz + 4));
	SWITCH_OP.max_val = (rz_read_at_be32(bytes, sz + 8));
	sz += 12;
	return sz;
}

static bool isRelative(ut32 type) {
	if (type & RZ_ANALYSIS_JAVA_CODEOP_CJMP) {
		return true;
	}
	if (type & RZ_ANALYSIS_JAVA_CODEOP_JMP) {
		return true;
	}
	return false;
}

static int update_bytes_consumed(int sz) {
	BYTES_CONSUMED += sz;
	return sz;
}

static int update_switch_op(ut64 addr, const ut8 *bytes) {
	int sz = 4;
	int ccase = SWITCH_OP.cur_val + SWITCH_OP.min_val;
	SWITCH_OP.cur_val++;
	if (ccase + 1 > SWITCH_OP.max_val) {
		IN_SWITCH_OP = 0;
	}
	return update_bytes_consumed(sz);
}

static int handle_switch_op(ut64 addr, const ut8 *bytes, char *output, int outlen) {
	int sz = 4;
	ut32 jmp = (int)(rz_read_at_be32(bytes, 0)) + SWITCH_OP.addr;
	int ccase = SWITCH_OP.cur_val + SWITCH_OP.min_val;
	snprintf(output, outlen, "case %d: goto 0x%04x", ccase, jmp);
	update_switch_op(addr, bytes);
	return update_bytes_consumed(sz);
}

RZ_API int java_print_opcode(RzBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, int len, char *output, int outlen) {
	char *arg = NULL; //(char *) malloc (1024);
	int sz = 0;
	ut32 val_one = 0;
	ut32 val_two = 0;
	ut8 op_byte = JAVA_OPS[idx].byte;
	if (IN_SWITCH_OP) {
		return handle_switch_op(addr, bytes, output, outlen);
	}

	switch (op_byte) {
	case 0x10: // "bipush"
		snprintf(output, outlen, "%s %d", JAVA_OPS[idx].name, (char)bytes[1]);
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0x11:
		snprintf(output, outlen, "%s %d", JAVA_OPS[idx].name, (int)rz_read_at_be16(bytes, 1));
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0x15: // "iload"
	case 0x16: // "lload"
	case 0x17: // "fload"
	case 0x18: // "dload"
	case 0x19: // "aload"
	case 0x37: // "lstore"
	case 0x38: // "fstore"
	case 0x39: // "dstore"
	case 0x3a: // "astore"
	case 0xbc: // "newarray"
	case 0xa9: // ret <var-num>
		snprintf(output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);

	case 0x12: // ldc
		arg = rz_bin_java_resolve_without_space(obj, (ut16)bytes[1]);
		if (arg) {
			snprintf(output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
			free(arg);
		} else {
			snprintf(output, outlen, "%s #%d", JAVA_OPS[idx].name, rz_read_at_be16(bytes, 1));
		}
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0x13:
	case 0x14:
		arg = rz_bin_java_resolve_without_space(obj, (int)rz_read_at_be16(bytes, 1));
		if (arg) {
			snprintf(output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
			free(arg);
		} else {
			snprintf(output, outlen, "%s #%d", JAVA_OPS[idx].name, rz_read_at_be16(bytes, 1));
		}
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0x84: // iinc
		val_one = (ut32)bytes[1];
		val_two = (ut32)bytes[2];
		snprintf(output, outlen, "%s %d %d", JAVA_OPS[idx].name, val_one, val_two);
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0x99: // ifeq
	case 0x9a: // ifne
	case 0x9b: // iflt
	case 0x9c: // ifge
	case 0x9d: // ifgt
	case 0x9e: // ifle
	case 0x9f: // if_icmpeq
	case 0xa0: // if_icmpne
	case 0xa1: // if_icmplt
	case 0xa2: // if_icmpge
	case 0xa3: // if_icmpgt
	case 0xa4: // if_icmple
	case 0xa5: // if_acmpne
	case 0xa6: // if_acmpne
	case 0xa7: // goto
	case 0xa8: // jsr
		snprintf(output, outlen, "%s 0x%04" PFMT64x, JAVA_OPS[idx].name,
			(addr + (short)rz_read_at_be16(bytes, 1)));
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
		// XXX - Figure out what constitutes the [<high>] value
	case 0xab: // tableswitch
	case 0xaa: // tableswitch
		sz = enter_switch_op(addr, bytes, len);
		snprintf(output, outlen, "%s default: 0x%04" PFMT64x,
			JAVA_OPS[idx].name,
			(ut64)(SWITCH_OP.def_jmp + SWITCH_OP.addr));
		return update_bytes_consumed(sz);
	case 0xb6: // invokevirtual
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb9: // invokeinterface
	case 0xba: // invokedynamic
		arg = rz_bin_java_resolve_without_space(obj, (int)rz_read_at_be16(bytes, 1));
		if (arg) {
			snprintf(output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
			free(arg);
		} else {
			snprintf(output, outlen, "%s #%d", JAVA_OPS[idx].name, rz_read_at_be16(bytes, 1));
		}
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0xbb: // new
	case 0xbd: // anewarray
	case 0xc0: // checkcast
	case 0xc1: // instance of
		arg = rz_bin_java_resolve_without_space(obj, (int)rz_read_at_be16(bytes, 1));
		if (arg) {
			snprintf(output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
			free(arg);
		} else {
			snprintf(output, outlen, "%s #%d", JAVA_OPS[idx].name, rz_read_at_be16(bytes, 1));
		}
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	case 0xb2: // getstatic
	case 0xb3: // putstatic
	case 0xb4: // getfield
	case 0xb5: // putfield
		arg = rz_bin_java_resolve_with_space(obj, (int)rz_read_at_be16(bytes, 1));
		if (arg) {
			snprintf(output, outlen, "%s %s", JAVA_OPS[idx].name, arg);
			free(arg);
		} else {
			snprintf(output, outlen, "%s #%d", JAVA_OPS[idx].name, rz_read_at_be16(bytes, 1));
		}
		output[outlen - 1] = 0;
		return update_bytes_consumed(JAVA_OPS[idx].size);
	}

	/* process arguments */
	switch (JAVA_OPS[idx].size) {
	case 1:
		snprintf(output, outlen, "%s", JAVA_OPS[idx].name);
		break;
	case 2:
		snprintf(output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
		break;
	case 3:
		snprintf(output, outlen, "%s 0x%04x 0x%04x", JAVA_OPS[idx].name, bytes[0], bytes[1]);
		break;
	case 5:
		snprintf(output, outlen, "%s %d", JAVA_OPS[idx].name, bytes[1]);
		break;
	}
	return update_bytes_consumed(JAVA_OPS[idx].size);
}

RZ_API void rz_java_new_method(void) {
	// eprintf("Reseting the bytes consumed, they were: 0x%04" PFMT64x ".\n", BYTES_CONSUMED);
	init_switch_op();
	IN_SWITCH_OP = 0;
	BYTES_CONSUMED = 0;
}

RZ_API int rz_java_disasm(RzBinJavaObj *obj, ut64 addr, const ut8 *bytes, int len, char *output, int outlen) {
	//rz_cons_printf ("rz_java_disasm (allowed %d): 0x%02x, 0x%0x.\n", outlen, bytes[0], addr);
	return java_print_opcode(obj, addr, bytes[0], bytes, len, output, outlen);
}

static int parseJavaArgs(char *str, ut64 *args, int args_sz) {
	int i, nargs = -1;
	char *q, *p = strchr(str, ' ');
	if (p) {
		*p++ = 0;
		nargs++;
		for (i = 0; i < args_sz; i++) {
			nargs++;
			q = strchr(p, ' ');
			if (q) {
				*q++ = 0;
			}
			args[i] = rz_num_math(NULL, p);
			if (q) {
				p = q;
			} else {
				break;
			}
		}
	}
	return nargs;
}

RZ_API int rz_java_assemble(ut64 addr, ut8 *bytes, const char *string) {
	ut64 args[4] = { 0 };
	int i, a, b, c, d;
	char name[128];

	strncpy(name, string, sizeof(name) - 1);
	name[sizeof(name) - 1] = 0;

	int nargs = parseJavaArgs(name, args, 4);
	a = args[0];
	b = args[1];
	c = args[2];
	d = args[3];
	for (i = 0; JAVA_OPS[i].name != NULL; i++) {
		if (!strcmp(name, JAVA_OPS[i].name)) {
			bytes[0] = JAVA_OPS[i].byte;
			switch (JAVA_OPS[i].size) {
			case 2:
				bytes[1] = a;
				break;
			case 3:
				if (nargs == 2) {
					bytes[1] = a;
					bytes[2] = b;
				} else {
					if (isRelative(JAVA_OPS[i].op_type)) {
						// relative jmp
						a -= addr;
					}
					bytes[1] = (a >> 8) & 0xff;
					bytes[2] = a & 0xff;
				}
				break;
			case 5:
				bytes[1] = a;
				bytes[2] = b;
				bytes[3] = c;
				bytes[4] = d;
				break;
			}
			return JAVA_OPS[i].size;
		}
	}
	return 0;
}
