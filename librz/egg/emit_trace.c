// SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#define attsyntax 0

#define EMIT_NAME emit_trace
#define RZ_ARCH   "trace"
#define RZ_SZ     8
#define RZ_SP     "sp"
#define RZ_BP     "bp"
#define RZ_AX     "a0"
#define RZ_GP \
	{ "a0", "a1", "a2", "a3", "a4" }
#define RZ_TMP "t0"
#define RZ_NGP 5

// no attsyntax for arm
static char *regs[] = RZ_GP;

static void emit_init(RzEgg *egg) {
	/* TODO */
}

static char *emit_syscall(RzEgg *egg, int num) {
	char buf[32];
	snprintf(buf, sizeof(buf), "syscall (%d)\n", num);
	return rz_str_dup(buf);
}

static void emit_frame(RzEgg *egg, int sz) {
	rz_egg_printf(egg, "frame (%d)\n", sz);
}

static void emit_frame_end(RzEgg *egg, int sz, int ctx) {
	rz_egg_printf(egg, "frame_end (%d, %d)\n", sz, ctx);
}

static void emit_comment(RzEgg *egg, const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	rz_egg_printf(egg, "# %s\n", buf);
	va_end(ap);
}

static void emit_equ(RzEgg *egg, const char *key, const char *value) {
	rz_egg_printf(egg, "equ (%s, %s)\n", key, value);
}

static void emit_syscall_args(RzEgg *egg, int nargs) {
	rz_egg_printf(egg, "syscall_args (%d)\n", nargs);
}

static void emit_set_string(RzEgg *egg, const char *dstvar, const char *str, int j) {
	// what is j?
	rz_egg_printf(egg, "set (\"%s\", \"%s\", %d)\n", dstvar, str, j);
}

static void emit_call(RzEgg *egg, const char *str, int atr) {
	if (atr) {
		rz_egg_printf(egg, "call ([%s])\n", str);
	} else {
		rz_egg_printf(egg, "call (%s)\n", str);
	}
}

static void emit_jmp(RzEgg *egg, const char *str, int atr) {
	if (atr) {
		rz_egg_printf(egg, "goto ([%s])\n", str);
	} else {
		rz_egg_printf(egg, "goto (%s)\n", str);
	}
}

static void emit_arg(RzEgg *egg, int xs, int num, const char *str) {
	// TODO: enhance output here
	rz_egg_printf(egg, "arg.%d.%d=%s\n", xs, num, str);
}

static void emit_get_result(RzEgg *egg, const char *ocn) {
	rz_egg_printf(egg, "get_result (%s)\n", ocn);
}

static void emit_restore_stack(RzEgg *egg, int size) {
	rz_egg_printf(egg, "restore_stack (%d)\n", size);
	// XXX: must die.. or add emit_store_stack. not needed by ARM
	// rz_egg_printf (egg, "  add sp, %d\n", size);
}

static void emit_get_while_end(RzEgg *egg, char *str, const char *ctxpush, const char *label) {
	rz_egg_printf(egg, "get_while_end (%s, %s, %s)\n", str, ctxpush, label);
}

static void emit_while_end(RzEgg *egg, const char *labelback) {
	rz_egg_printf(egg, "while_end (%s)\n", labelback);
}

static void emit_get_var(RzEgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0: sprintf(out, "fp,$%d", -idx); break; /* variable */
	case 1: sprintf(out, "sp,$%d", idx); break; /* argument */ // XXX: MUST BE r0, r1, r2, ..
	}
}

static void emit_trap(RzEgg *egg) {
	rz_egg_printf(egg, "trap\n");
}

// TODO atoi here?
static void emit_load_ptr(RzEgg *egg, const char *dst) {
	rz_egg_printf(egg, "loadptr (%s)\n", dst);
}

static void emit_branch(RzEgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	// This function signature is bad
	char *p, str[64];
	char *arg = NULL;
	char *op = "beq";
	/* NOTE that jb/ja are inverted to fit cmp opcode */
	if (b) {
		*b = '\0';
		op = e ? "bge" : "bgt";
		arg = b + 1;
	} else if (g) {
		*g = '\0';
		op = e ? "ble" : "blt";
		arg = g + 1;
	}
	if (!arg) {
		if (e) {
			arg = e + 1;
			op = "bne";
		} else {
			arg = "0";
			op = n ? "bne" : "beq";
		}
	}

	if (*arg == '=') {
		arg++; /* for <=, >=, ... */
	}
	p = rz_egg_mkvar(egg, str, arg, 0);
	rz_egg_printf(egg, "%s (%s) => (%s)\n", op, p, dst);
	free(p);
}

// XXX: sz must be char
static void emit_load(RzEgg *egg, const char *dst, int sz) {
	rz_egg_printf(egg, "load (\"%s\", %c)\n", dst, sz);
}

static void emit_mathop(RzEgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	char *op;
	switch (ch) {
	case '^': op = "eor"; break;
	case '&': op = "and"; break;
	case '|': op = "orr"; break;
	case '-': op = "sub"; break;
	case '+': op = "add"; break;
	case '*': op = "mul"; break;
	case '/': op = "div"; break;
	default: op = "mov"; break;
	}
	if (!eq) {
		eq = RZ_AX;
	}
	if (!p) {
		p = RZ_AX;
	}
#if 0
	// TODO:
	eprintf ("TYPE = %c\n", type);
	eprintf ("  %s%c %c%s, %s\n", op, vs, type, eq, p);
	eprintf ("  %s %s, [%s]\n", op, p, eq);
#endif
	if (type == '*') {
		rz_egg_printf(egg, "%s (%s, [%s])\n", op, p, eq);
	} else {
		rz_egg_printf(egg, "%s (%s, %s)\n", op, p, eq);
	}
}

static const char *emit_regs(RzEgg *egg, int idx) {
	return regs[idx % RZ_NGP];
}

RzEggEmit EMIT_NAME = {
	.retvar = "a0",
	.arch = RZ_ARCH,
	.size = RZ_SZ,
	.jmp = emit_jmp,
	.call = emit_call,
	.init = emit_init,
	.equ = emit_equ,
	.regs = emit_regs,
	//.sc = emit_sc,
	.trap = emit_trap,
	.frame = emit_frame,
	.frame_end = emit_frame_end,
	.comment = emit_comment,
	.push_arg = emit_arg,
	.restore_stack = emit_restore_stack,
	.get_result = emit_get_result,
	.syscall_args = emit_syscall_args,
	.set_string = emit_set_string,
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
