// SPDX-FileCopyrightText: 2010-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/* pancake // nopcode.org 2010-2013 -- emit module for rcc */

#include <rz_egg.h>
#include <rz_types.h>

/* hardcoded */
#define attsyntax 0

#ifdef ARCH_X86_64
#define EMIT_NAME     emit_x64
#define RZ_ARCH       "x64"
#define RZ_SZ         8
#define RZ_SP         "rsp"
#define RZ_BP         "rbp"
#define RZ_AX         "rax"
#define SYSCALL_ATT   "syscall"
#define SYSCALL_INTEL "syscall"
#define RZ_REG_AR_OFF 1
static char *regs[] = { "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9" };
#else
#define EMIT_NAME     emit_x86
#define RZ_ARCH       "x86"
#define RZ_SZ         4
#define RZ_SP         "esp"
#define RZ_BP         "ebp"
#define RZ_AX         "eax"
#define SYSCALL_ATT   "int $0x80"
#define SYSCALL_INTEL "int 0x80"
#define RZ_REG_AR_OFF 0
static char *regs[] = { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp" };
#endif

#define RZ_NGP (sizeof(regs) / sizeof(char *))

static void emit_init(RzEgg *egg) {
	// TODO: add 'andb rsp, 0xf0'
	if (attsyntax) {
		rz_egg_printf(egg, "mov %%" RZ_SP ", %%" RZ_BP "\n");
	} else {
		rz_egg_printf(egg, "mov " RZ_BP ", " RZ_SP "\n");
	}
}

static char *emit_syscall(RzEgg *egg, int nargs) {
	char p[512];
	if (attsyntax) {
		return strdup(": mov $`.arg`, %" RZ_AX "\n: " SYSCALL_ATT "\n");
	}
	switch (egg->os) {
	case RZ_EGG_OS_LINUX:
		strcpy(p, "\n : mov " RZ_AX ", `.arg`\n : " SYSCALL_INTEL "\n");
		break;
	case RZ_EGG_OS_OSX:
	case RZ_EGG_OS_MACOS:
	case RZ_EGG_OS_DARWIN:
#if ARCH_X86_64
		snprintf(p, sizeof(p), "\n"
				       "  : mov rax, `.arg`\n"
				       "  : syscall\n");
#else
		snprintf(p, sizeof(p), "\n"
				       "  : mov eax, `.arg`\n"
				       "  : push eax\n"
				       "  : int 0x80\n"
				       "  : add esp, %d\n",
			4); //(nargs+2)*(egg->bits/8));
#endif
		break;
	default:
		return NULL;
	}
	return strdup(p);
}

static void emit_frame(RzEgg *egg, int sz) {
	if (sz < 1) {
		return;
	}
	if (attsyntax) {
		rz_egg_printf(egg,
			"  push %%" RZ_BP "\n"
			"  mov %%" RZ_SP ", %%" RZ_BP "\n"
			"  sub $%d, %%" RZ_SP "\n",
			sz);
	} else {
		rz_egg_printf(egg,
			"  push " RZ_BP "\n"
			"  mov " RZ_BP ", " RZ_SP "\n"
			"  sub " RZ_SP ", %d\n",
			sz);
	}
}

static void emit_frame_end(RzEgg *egg, int sz, int ctx) {
	if (sz > 0) {
		if (attsyntax) {
			rz_egg_printf(egg, "  add $%d, %%" RZ_SP "\n", sz);
			rz_egg_printf(egg, "  pop %%" RZ_BP "\n");
		} else {
			rz_egg_printf(egg, "  add " RZ_SP ", %d\n", sz);
			rz_egg_printf(egg, "  pop " RZ_BP "\n");
		}
	}
	if (ctx > 0) {
		rz_egg_printf(egg, "  ret\n");
	}
}

static void emit_comment(RzEgg *egg, const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	if (attsyntax) {
		rz_egg_printf(egg, "  /* %s */\n", buf);
	} else {
		rz_egg_printf(egg, "# %s\n", buf);
	}
	va_end(ap);
}

static void emit_equ(RzEgg *egg, const char *key, const char *value) {
	rz_egg_printf(egg, ".equ %s,%s\n", key, value);
}

static const char *getreg(int i) {
	if (i < 0 || i >= RZ_NGP) {
		return NULL;
	}
	return regs[i];
}

static void emit_syscall_args(RzEgg *egg, int nargs) {
	int j, k;
	for (j = 0; j < nargs; j++) {
		k = j * RZ_SZ;
		const char *reg = getreg(j + 1);
		if (!reg) {
			eprintf("Cannot find gpr %d\n", j + 1);
			break;
		}
		if (attsyntax) {
			rz_egg_printf(egg, "  mov %d(%%" RZ_SP "), %%%s\n", k, reg);
		} else {
			if (k > 0) {
				rz_egg_printf(egg, "  mov %s, [" RZ_SP "+%d]\n", reg, k);
			} else if (k < 0) {
				rz_egg_printf(egg, "  mov %s, [" RZ_SP "%d]\n", reg, k);
			} else {
				rz_egg_printf(egg, "  mov %s, [" RZ_SP "]\n", reg);
			}
		}
	}
}

static void emit_string(RzEgg *egg, const char *dstvar, const char *str, int j) {
	char *p, str2[64];
	int i, oj = j;

	int len = strlen(str);
	char *s = calloc(1, len + 8);
	if (!s) {
		return;
	}
	memcpy(s, str, len);
	memset(s + len, 0, 4);

	/* XXX: Hack: Adjust offset in RZ_BP correctly for 64b addresses */
#define BPOFF  (RZ_SZ - 4)
#define M32(x) (unsigned int)((x)&0xffffffff)
	/* XXX: Assumes sizeof(ut32) == 4 */
	for (i = 4; i <= oj; i += 4) {
		/* XXX endian issues (non-portable asm) */
		ut32 *n = (ut32 *)(s + i - 4);
		p = rz_egg_mkvar(egg, str2, dstvar, i + BPOFF);
		if (attsyntax) {
			rz_egg_printf(egg, "  movl $0x%x, %s\n", M32(*n), p);
		} else {
			rz_egg_printf(egg, "  mov dword %s, 0x%x\n", p, M32(*n));
		}
		free(p);
		j -= 4;
	}
#undef M32

	/* zero */
	p = rz_egg_mkvar(egg, str2, dstvar, i + BPOFF);
	if (attsyntax) {
		rz_egg_printf(egg, "  movl $0, %s\n", p);
	} else {
		rz_egg_printf(egg, "  mov dword %s, 0\n", p);
	}
	free(p);

	/* store pointer */
	p = rz_egg_mkvar(egg, str2, dstvar, j + 4 + BPOFF);
	if (attsyntax) {
		rz_egg_printf(egg, "  lea %s, %%" RZ_AX "\n", p);
	} else {
		rz_egg_printf(egg, "  lea " RZ_AX ", %s\n", p);
	}
	free(p);

	p = rz_egg_mkvar(egg, str2, dstvar, 0);
	if (attsyntax) {
		rz_egg_printf(egg, "  mov %%" RZ_AX ", %s\n", p);
	} else {
		rz_egg_printf(egg, "  mov %s, " RZ_AX "\n", p);
	}
	free(p);

#undef BPOFF
#if 0
	char *p, str2[64];
	int i, oj = j;
	for (i=0; i<oj; i+=4) {
		/* XXX endian and 32/64bit issues */
		int *n = (int *)(str+i);
		p = rz_egg_mkvar (egg, str2, dstvar, j);
		if (attsyntax) rz_egg_printf (egg, "  movl $0x%x, %s\n", *n, p);
		else rz_egg_printf (egg, "  mov %s, 0x%x\n", p, *n);
		j -= 4;
	}
	p = rz_egg_mkvar (egg, str2, dstvar, oj);
	if (attsyntax) rz_egg_printf (egg, "  lea %s, %%"RZ_AX"\n", p);
	else rz_egg_printf (egg, "  lea "RZ_AX", %s\n", p);
	p = rz_egg_mkvar (egg, str2, dstvar, 0);
	if (attsyntax) rz_egg_printf (egg, "  mov %%"RZ_AX", %s\n", p);
	else rz_egg_printf (egg, "  mov %s, "RZ_AX"\n", p);
#endif
	free(s);
}

static void emit_call(RzEgg *egg, const char *str, int atr) {
	if (atr) {
		if (attsyntax) {
			rz_egg_printf(egg, "  call *%s\n", str);
		} else {
			rz_egg_printf(egg, "  call [%s]\n", str);
		}
	} else {
		rz_egg_printf(egg, "  call %s\n", str);
	}
}

static void emit_jmp(RzEgg *egg, const char *str, int atr) {
	if (str) {
		if (atr) {
			if (attsyntax) {
				rz_egg_printf(egg, "  jmp *%s\n", str);
			} else {
				rz_egg_printf(egg, "  jmp [%s]\n", str);
			}
		} else {
			rz_egg_printf(egg, "  jmp %s\n", str);
		}
	} else {
		eprintf("Jump without destination\n");
	}
}

static void emit_arg(RzEgg *egg, int xs, int num, const char *str) {
	int d = atoi(str);
	if (!attsyntax && (*str == '$')) {
		str = str + 1;
	}
	switch (xs) {
	case 0:
#ifdef ARCH_X86_64
		/*	push imm64 instruction not exist, it´s translated to:
			mov rax, 0x0102030405060708
			push rax
		*/
		if (attsyntax) {
			rz_egg_printf(egg, "  mov %s, %%" RZ_AX "\n", str);
			rz_egg_printf(egg, "  push %%" RZ_AX "\n");
		} else {
			rz_egg_printf(egg, "  mov " RZ_AX ", %s\n", str);
			rz_egg_printf(egg, "  push " RZ_AX "\n");
		}
#else
		rz_egg_printf(egg, "  push %s\n", str);
#endif
		break;
	case '*':
		if (attsyntax) {
			rz_egg_printf(egg, "  push (%s)\n", str);
		} else {
			rz_egg_printf(egg, "  push [%s]\n", str);
		}
		break;
	case '&':
		if (attsyntax) {
			if (d != 0) {
				rz_egg_printf(egg, "  addl $%d, %%" RZ_BP "\n", d);
			}
			rz_egg_printf(egg, "  pushl %%" RZ_BP "\n");
			if (d != 0) {
				rz_egg_printf(egg, "  subl $%d, %%" RZ_BP "\n", d);
			}
		} else {
			if (d != 0) {
				rz_egg_printf(egg, "  add " RZ_BP ", %d\n", d);
			}
			rz_egg_printf(egg, "  push " RZ_BP "\n");
			if (d != 0) {
				rz_egg_printf(egg, "  sub " RZ_BP ", %d\n", d);
			}
		}
		break;
	}
}

static void emit_get_result(RzEgg *egg, const char *ocn) {
	if (attsyntax) {
		rz_egg_printf(egg, "  mov %%" RZ_AX ", %s\n", ocn);
	} else {
		rz_egg_printf(egg, "  mov %s, " RZ_AX "\n", ocn);
	}
}

static void emit_restore_stack(RzEgg *egg, int size) {
	if (attsyntax) {
		rz_egg_printf(egg, "  add $%d, %%" RZ_SP " /* args */\n", size);
	} else {
		rz_egg_printf(egg, "  add " RZ_SP ", %d\n", size);
	}
}

static void emit_get_while_end(RzEgg *egg, char *str, const char *ctxpush, const char *label) {
	sprintf(str, "  push %s\n  jmp %s\n", ctxpush, label);
}

static void emit_while_end(RzEgg *egg, const char *labelback) {
#if 0
	if (attsyntax) {
		rz_egg_printf (egg, "  pop %%"RZ_AX"\n");
		rz_egg_printf (egg, "  cmp $0, %%"RZ_AX"\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
		rz_egg_printf (egg, "  jnz %s\n", labelback);
	} else {
#endif
	rz_egg_printf(egg, "  pop " RZ_AX "\n");
	rz_egg_printf(egg, "  test " RZ_AX ", " RZ_AX "\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
	rz_egg_printf(egg, "  jnz %s\n", labelback);
	//	}
}

// XXX: this is wrong
static void emit_get_var(RzEgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0: /* variable */
		if (idx > 0) {
			sprintf(out, "[" RZ_BP "+%d]", idx);
		} else if (idx < 0) {
			sprintf(out, "[" RZ_BP "%d]", idx);
		} else {
			strcpy(out, "[" RZ_BP "]");
		}
		break;
	case 1: /* argument */
		// OMG WE CAN'T stuff found in relative address in stack in the stack
		eprintf("WARNING: Using stack vars in naked functions\n");
		idx = 8; // HACK to make arg0, arg4, ... work
		if (idx > 0) {
			sprintf(out, "[" RZ_SP "+%d]", idx);
		} else if (idx < 0) {
			sprintf(out, "[" RZ_SP "%d]", idx);
		} else {
			strcpy(out, "[" RZ_SP "]");
		}
		break;
	case 2:
		if (idx > 0) {
			sprintf(out, "[" RZ_BP "+%d]", idx);
		} else if (idx < 0) {
			sprintf(out, "[" RZ_BP "%d]", idx);
		} else {
			strcpy(out, "[" RZ_BP "]");
		}
		break;
	}
}

static void emit_trap(RzEgg *egg) {
	rz_egg_printf(egg, "  int3\n");
}

static void emit_load_ptr(RzEgg *egg, const char *dst) {
	int d = atoi(dst);
	if (d == 0) { // hack to handle stackvarptrz
		char *p = strchr(dst, '+');
		if (p) {
			d = atoi(p + 1);
		}
	}
	// eprintf ("emit_load_ptr: HACK\n");
	//  XXX: 32/64bit care
	// rz_egg_printf (egg, "# DELTA IS (%s)\n", dst);
	if (attsyntax) {
		rz_egg_printf(egg, "  leal %d(%%" RZ_BP "), %%" RZ_AX "\n", d);
	} else {
		rz_egg_printf(egg, "  lea " RZ_AX ", [" RZ_BP "+%d]\n", d);
	}
	// rz_egg_printf (egg, "  movl %%"RZ_BP", %%"RZ_AX"\n");
	// rz_egg_printf (egg, "  addl $%d, %%"RZ_AX"\n", d);
}

static void emit_branch(RzEgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	char *p, str[64];
	char *arg = NULL;
	char *op = "jz";
	int signed_value = 1; // XXX: add support for signed/unsigned variables
	/* NOTE that jb/ja are inverted to fit cmp opcode */
	if (b) {
		*b = '\0';
		if (signed_value) {
			op = e ? "jge" : "jg";
		} else {
			op = e ? "jae" : "ja";
		}
		arg = b + 1;
	} else if (g) {
		*g = '\0';
		if (signed_value) {
			op = e ? "jle" : "jl";
		} else {
			op = e ? "jbe" : "jb";
		}
		arg = g + 1;
	}
	if (!arg) {
		if (e) {
			arg = e + 1;
			op = "jne";
		} else {
			arg = attsyntax ? "$0" : "0";
			if (n) {
				op = "jnz";
			} else {
				op = "jz";
			}
		}
	}

	if (*arg == '=') {
		arg++; /* for <=, >=, ... */
	}
	p = rz_egg_mkvar(egg, str, arg, 0);
	if (attsyntax) {
		rz_egg_printf(egg, "  pop %%" RZ_AX "\n"); /* TODO: add support for more than one arg get arg0 */
		rz_egg_printf(egg, "  cmp%c %s, %%" RZ_AX "\n", sz, p);
	} else {
		rz_egg_printf(egg, "  pop " RZ_AX "\n"); /* TODO: add support for more than one arg get arg0 */
		rz_egg_printf(egg, "  cmp " RZ_AX ", %s\n", p);
	}
	// if (context>0)
	free(p);
	rz_egg_printf(egg, "  %s %s\n", op, dst);
}

static void emit_load(RzEgg *egg, const char *dst, int sz) {
	if (attsyntax) {
		switch (sz) {
		case 'l':
			rz_egg_printf(egg, "  movl %s, %%" RZ_AX "\n", dst);
			rz_egg_printf(egg, "  movl (%%" RZ_AX "), %%" RZ_AX "\n");
			break;
		case 'b':
			rz_egg_printf(egg, "  movl %s, %%" RZ_AX "\n", dst);
			rz_egg_printf(egg, "  movzb (%%" RZ_AX "), %%" RZ_AX "\n");
			break;
		default:
			// TODO: unhandled?!?
			rz_egg_printf(egg, "  mov%c %s, %%" RZ_AX "\n", sz, dst);
			rz_egg_printf(egg, "  mov%c (%%" RZ_AX "), %%" RZ_AX "\n", sz);
		}
	} else {
		switch (sz) {
		case 'l':
			rz_egg_printf(egg, "  mov " RZ_AX ", %s\n", dst);
			rz_egg_printf(egg, "  mov " RZ_AX ", [" RZ_AX "]\n");
			break;
		case 'b':
			rz_egg_printf(egg, "  mov " RZ_AX ", %s\n", dst);
			rz_egg_printf(egg, "  movz " RZ_AX ", [" RZ_AX "]\n");
			break;
		default:
			// TODO: unhandled?!?
			rz_egg_printf(egg, "  mov " RZ_AX ", %s\n", dst);
			rz_egg_printf(egg, "  mov " RZ_AX ", [" RZ_AX "]\n");
		}
	}
}

static void emit_mathop(RzEgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	char *op;
	switch (ch) {
	case '^': op = "xor"; break;
	case '&': op = "and"; break;
	case '|': op = "or"; break;
	case '-': op = "sub"; break;
	case '+': op = "add"; break;
	case '*': op = "mul"; break;
	case '/': op = "div"; break;
	default: op = "mov"; break;
	}
	if (attsyntax) {
		if (!eq) {
			eq = "%" RZ_AX;
		}
		if (!p) {
			p = "%" RZ_AX;
		}
		rz_egg_printf(egg, "  %s%c %c%s, %s\n", op, vs, type, eq, p);
	} else {
		if (!eq) {
			eq = RZ_AX;
		}
		if (!p) {
			p = RZ_AX;
		}
		// TODO:
#if 0
		eprintf ("TYPE = %c\n", type);
		eprintf ("  %s%c %c%s, %s\n", op, vs, type, eq, p);
		eprintf ("  %s %s, [%s]\n", op, p, eq);
#endif
		if (type == '*') {
			rz_egg_printf(egg, "  %s %s, [%s]\n", op, p, eq);
		} else {
			rz_egg_printf(egg, "  %s %s, %s\n", op, p, eq);
		}
	}
}

static const char *emit_regs(RzEgg *egg, int idx) {
	return regs[idx % RZ_NGP];
}

static void emit_get_ar(RzEgg *egg, char *out, int idx) {
	const char *reg = emit_regs(egg, RZ_REG_AR_OFF + idx);

	if (reg) {
		strcpy(out, reg);
	}
}

RzEggEmit EMIT_NAME = {
	.retvar = RZ_AX,
	.arch = RZ_ARCH,
	.size = RZ_SZ,
	.init = emit_init,
	.jmp = emit_jmp,
	.call = emit_call,
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
	.set_string = emit_string,
	.get_ar = emit_get_ar,
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
