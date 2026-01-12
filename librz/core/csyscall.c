// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

static const char *syscallNumberFmt(int n) {
	return n > 1000 ? "0x%x" : "%d";
}

/**
 * \brief Returns the syscall representation as a string
 *
 * Given the syscall number and address it resolves the syscall
 * for the selected `asm.arch` and `asm.os` values and print
 * its arguments.
 *
 * The number of the syscall can also be -1 to try to read
 * the value of the syscall from the register that is the syscall
 * number by the selected calling convention.
 *
 * \param core RzCore instance
 * \param n number of the syscall
 * \param addr address of the syscall
 */
RZ_API RZ_OWN char *rz_core_syscall_as_string(RzCore *core, st64 n, ut64 addr) {
	int i;
	char str[64];
	char tmpbuf[32] = { 0 };
	st64 N = n;
	int defVector = rz_syscall_get_swi(core->analysis->syscall);
	if (defVector > 0) {
		n = -1;
	}
	if (n == -1 || defVector > 0) {
		n = (int)rz_core_reg_getv_by_role_or_name(core, "oeax");
		if (!n || n == -1) {
			const char *a0 = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SN);
			n = (a0 == NULL) ? -1 : (int)rz_core_reg_getv_by_role_or_name(core, a0);
		}
	}
	RzSyscallItem *item = rz_syscall_get(core->analysis->syscall, n, defVector);
	if (!item) {
		item = rz_syscall_get(core->analysis->syscall, N, -1);
	}
	if (!item) {
		const char *syscallnum = rz_strf(tmpbuf, syscallNumberFmt(n), n);
		return rz_str_newf("%s = unknown ()", syscallnum);
	}
	const char *syscallnum = rz_strf(tmpbuf, syscallNumberFmt(item->num), item->num);
	char *res = rz_str_newf("%s = %s (", syscallnum, item->name);
	// TODO: move this to rz_syscall
	const char *cc = rz_analysis_syscc_default(core->analysis);
	// TODO replace the hardcoded CC with the sdb ones
	for (i = 0; i < item->args; i++) {
		// XXX this is a hack to make syscall args work on x86-32 and x86-64
		// we need to shift sn first.. which is bad, but needs to be redesigned
		int regidx = i;
		if (core->rasm->bits == 32 && core->rasm->cur && !strcmp(core->rasm->cur->arch, "x86")) {
			regidx++;
		}
		ut64 arg = rz_core_arg_get(core, cc, regidx); // TODO here
		// rz_cons_printf ("(%d:0x%"PFMT64x")\n", i, arg);
		if (item->sargs) {
			switch (item->sargs[i]) {
			case 'p': // pointer
				res = rz_str_appendf(res, "0x%08" PFMT64x "", arg);
				break;
			case 'i':
				res = rz_str_appendf(res, "%" PFMT64u "", arg);
				break;
			case 'z':
				memset(str, 0, sizeof(str));
				rz_io_read_at_mapped(core->io, arg, (ut8 *)str, sizeof(str) - 1);
				rz_str_filter(str);
				res = rz_str_appendf(res, "\"%s\"", str);
				break;
			case 'Z': {
				// TODO replace the hardcoded CC with the sdb ones
				ut64 len = rz_core_arg_get(core, cc, i + 2);
				len = RZ_MIN(len + 1, sizeof(str) - 1);
				if (len == 0) {
					len = 16; // override default
				}
				(void)rz_io_read_at_mapped(core->io, arg, (ut8 *)str, len);
				str[len] = 0;
				rz_str_filter(str);
				res = rz_str_appendf(res, "\"%s\"", str);
			} break;
			default:
				res = rz_str_appendf(res, "0x%08" PFMT64x "", arg);
				break;
			}
		} else {
			res = rz_str_appendf(res, "0x%08" PFMT64x "", arg);
		}
		if (i + 1 < item->args) {
			res = rz_str_appendf(res, ", ");
		}
	}
	rz_syscall_item_free(item);
	return rz_str_appendf(res, ")");
}
