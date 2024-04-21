// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_vector.h>
#include <rz_core.h>
#include <rz_socket.h>
#include <rz_cmp.h>
#include <rz_util.h>
#if __UNIX__
#include <signal.h>
#endif
#include "core_private.h"

#define DB core->sdb

RZ_LIB_VERSION(rz_core);

static ut64 letter_divs[RZ_CORE_ASMQJMPS_LEN_LETTERS - 1] = {
	RZ_CORE_ASMQJMPS_LETTERS * RZ_CORE_ASMQJMPS_LETTERS * RZ_CORE_ASMQJMPS_LETTERS * RZ_CORE_ASMQJMPS_LETTERS,
	RZ_CORE_ASMQJMPS_LETTERS *RZ_CORE_ASMQJMPS_LETTERS *RZ_CORE_ASMQJMPS_LETTERS,
	RZ_CORE_ASMQJMPS_LETTERS *RZ_CORE_ASMQJMPS_LETTERS,
	RZ_CORE_ASMQJMPS_LETTERS
};

extern bool rz_core_is_project(RzCore *core, const char *name);

/**
 * \brief  Prints a message definining the beginning of a task
 *
 * \param  core    The RzCore to use
 * \param  format  The message to notify
 */
RZ_API void rz_core_notify_begin(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) {
	rz_return_if_fail(core && format);
	va_list args;
	bool use_color = rz_config_get_i(core->config, "scr.color") > 0;
	bool verbose = rz_config_get_b(core->config, "scr.prompt");
	if (!verbose) {
		return;
	}
	va_start(args, format);
	if (use_color) {
		fprintf(stderr, "[ ] " Color_YELLOW);
		vfprintf(stderr, format, args);
		fprintf(stderr, "\r[" Color_RESET);
	} else {
		fprintf(stderr, "[ ] ");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\r[");
	}
	va_end(args);
}

/**
 * \brief  Prints a message definining the end of a task which succeeded
 *
 * \param  core    The RzCore to use
 * \param  format  The message to notify
 */
RZ_API void rz_core_notify_done(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) {
	rz_return_if_fail(core && format);
	va_list args;
	bool use_color = rz_config_get_i(core->config, "scr.color") > 0;
	bool verbose = rz_config_get_b(core->config, "scr.prompt");
	if (!verbose) {
		return;
	}
	va_start(args, format);
	if (use_color) {
		fprintf(stderr, "\r" Color_GREEN "[x]" Color_RESET " ");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	} else {
		fprintf(stderr, "\r[x] ");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	}
	va_end(args);
}

/**
 * \brief  Prints a message definining the end of a task which errored
 *
 * \param  core    The RzCore to use
 * \param  format  The message to notify
 */
RZ_API void rz_core_notify_error(RZ_NONNULL RzCore *core, RZ_NONNULL const char *format, ...) {
	rz_return_if_fail(core && format);
	va_list args;
	bool use_color = rz_config_get_i(core->config, "scr.color") > 0;
	bool verbose = rz_config_get_b(core->config, "scr.prompt");
	if (!verbose) {
		return;
	}
	va_start(args, format);
	if (use_color) {
		fprintf(stderr, "\r" Color_RED "[!]" Color_RESET " ");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	} else {
		fprintf(stderr, "\r[!] ");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	}
	va_end(args);
}

/**
 * \brief  Prints a message definining the beginning of a task
 *
 * \param  core The RzCore to use
 * \param  text The message to notify
 */
RZ_API void rz_core_notify_begin_str(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text) {
	rz_core_notify_begin(core, "%s", text);
}

/**
 * \brief  Prints a message definining the end of a task which succeeded
 *
 * \param  core The RzCore to use
 * \param  text The message to notify
 */
RZ_API void rz_core_notify_done_str(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text) {
	rz_core_notify_done(core, "%s", text);
}

/**
 * \brief  Prints a message definining the end of a task which errored
 *
 * \param  core The RzCore to use
 * \param  text The message to notify
 */
RZ_API void rz_core_notify_error_str(RZ_NONNULL RzCore *core, RZ_NONNULL const char *text) {
	rz_core_notify_error(core, "%s", text);
}

static int on_fcn_new(RzAnalysis *_analysis, void *_user, RzAnalysisFunction *fcn) {
	RzCore *core = (RzCore *)_user;
	const char *cmd = rz_config_get(core->config, "cmd.fcn.new");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		rz_core_seek(core, addr, true);
		rz_core_cmd0(core, cmd);
		rz_core_seek(core, oaddr, true);
	}
	return 0;
}

static int on_fcn_delete(RzAnalysis *_analysis, void *_user, RzAnalysisFunction *fcn) {
	RzCore *core = (RzCore *)_user;
	const char *cmd = rz_config_get(core->config, "cmd.fcn.delete");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		rz_core_seek(core, addr, true);
		rz_core_cmd0(core, cmd);
		rz_core_seek(core, oaddr, true);
	}
	return 0;
}

static int on_fcn_rename(RzAnalysis *_analysis, void *_user, RzAnalysisFunction *fcn, const char *oname) {
	RzCore *core = (RzCore *)_user;
	const char *cmd = rz_config_get(core->config, "cmd.fcn.rename");
	if (cmd && *cmd) {
		// XXX: wat do with old name here?
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		rz_core_seek(core, addr, true);
		rz_core_cmd0(core, cmd);
		rz_core_seek(core, oaddr, true);
	}
	return 0;
}

static void rz_core_debug_breakpoint_hit(RzCore *core, RzBreakpointItem *bpi) {
	const char *cmdbp = rz_config_get(core->config, "cmd.bp");
	const bool cmdbp_exists = (cmdbp && *cmdbp);
	const bool bpcmd_exists = (bpi->data && bpi->data[0]);
	const bool may_output = (cmdbp_exists || bpcmd_exists);
	if (may_output) {
		rz_cons_push();
	}
	if (cmdbp_exists) {
		rz_core_cmd0(core, cmdbp);
	}
	if (bpcmd_exists) {
		rz_core_cmd0(core, bpi->data);
	}
	if (may_output) {
		rz_cons_set_flush(true);
		rz_cons_flush();
		rz_cons_pop();
	}
}

static void rz_core_debug_syscall_hit(RzCore *core) {
	const char *cmdhit = rz_config_get(core->config, "cmd.onsyscall");

	if (cmdhit && cmdhit[0] != 0) {
		rz_core_cmd0(core, cmdhit);
		rz_cons_flush();
	}
}

RZ_API RzBinReloc *rz_core_getreloc(RzCore *core, ut64 addr, int size) {
	if (size < 1 || addr == UT64_MAX) {
		return NULL;
	}
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->relocs) {
		return NULL;
	}
	return rz_bin_reloc_storage_get_reloc_in(bf->o->relocs, addr, size);
}

RZ_API RzBinReloc *rz_core_get_reloc_to(RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core, NULL);
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->relocs) {
		return NULL;
	}
	return rz_bin_reloc_storage_get_reloc_to(bf->o->relocs, addr);
}

/* returns the address of a jmp/call given a shortcut by the user or UT64_MAX
 * if there's no valid shortcut. When is_asmqjmps_letter is true, the string
 * should be of the form XYZWu, where XYZW are uppercase letters and u is a
 * lowercase one. If is_asmqjmps_letter is false, the string should be a number
 * between 1 and 9 included. */
RZ_API ut64 rz_core_get_asmqjmps(RzCore *core, const char *str) {
	if (!core->asmqjmps) {
		return UT64_MAX;
	}
	if (core->is_asmqjmps_letter) {
		int i, pos = 0;
		int len = strlen(str);
		for (i = 0; i < len - 1; i++) {
			if (!isupper((ut8)str[i])) {
				return UT64_MAX;
			}
			pos *= RZ_CORE_ASMQJMPS_LETTERS;
			pos += str[i] - 'A' + 1;
		}
		if (!islower((ut8)str[i])) {
			return UT64_MAX;
		}
		pos *= RZ_CORE_ASMQJMPS_LETTERS;
		pos += str[i] - 'a';
		if (pos < core->asmqjmps_count) {
			return core->asmqjmps[pos + 1];
		}
	} else if (str[0] > '0' && str[1] <= '9') {
		int pos = str[0] - '0';
		if (pos <= core->asmqjmps_count) {
			return core->asmqjmps[pos];
		}
	}
	return UT64_MAX;
}

/**
 * Takes addr and returns already saved shortcut or a new one
 * The returned buffer needs to be freed
 */
RZ_API char *rz_core_add_asmqjmp(RzCore *core, ut64 addr) {
	bool found = false;
	if (!core->asmqjmps) {
		return NULL;
	}
	if (core->is_asmqjmps_letter) {
		if (core->asmqjmps_count >= RZ_CORE_ASMQJMPS_MAX_LETTERS) {
			return NULL;
		}
		if (core->asmqjmps_count >= core->asmqjmps_size - 2) {
			core->asmqjmps = realloc(core->asmqjmps, core->asmqjmps_size * 2 * sizeof(ut64));
			if (!core->asmqjmps) {
				return NULL;
			}
			core->asmqjmps_size *= 2;
		}
	}
	if (core->asmqjmps_count < core->asmqjmps_size - 1) {
		int i = 0;
		char t[RZ_CORE_ASMQJMPS_LEN_LETTERS + 1] = { 0 };
		for (i = 0; i < core->asmqjmps_count + 1; i++) {
			if (core->asmqjmps[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found) {
			i = ++core->asmqjmps_count;
			core->asmqjmps[i] = addr;
		}
		// This check makes pos never be <1, thefor not fill 't' with trash
		if (i < 1) {
			return NULL;
		}
		rz_core_set_asmqjmps(core, t, sizeof(t), i);
		return strdup(t);
	}
	return NULL;
}

/* returns in str a string that represents the shortcut to access the asmqjmp
 * at position pos. When is_asmqjmps_letter is true, pos is converted into a
 * multiletter shortcut of the form XYWZu and returned (see rz_core_get_asmqjmps
 * for more info). Otherwise, the shortcut is the string representation of pos. */
RZ_API void rz_core_set_asmqjmps(RzCore *core, char *str, size_t len, int pos) {
	if (core->is_asmqjmps_letter) {
		int i, j = 0;
		// if (pos > 0) {
		pos--;
		////  }
		for (i = 0; i < RZ_CORE_ASMQJMPS_LEN_LETTERS - 1; i++) {
			int div = pos / letter_divs[i];
			pos %= letter_divs[i];
			if (div > 0 && j < len) {
				str[j++] = 'A' + div - 1;
			}
		}
		if (j < len) {
			int div = pos % RZ_CORE_ASMQJMPS_LETTERS;
			str[j++] = 'a' + div;
		}
		str[j] = '\0';
	} else {
		snprintf(str, len, "%d", pos);
	}
}

static void setab(RzCore *core, const char *arch, int bits) {
	if (arch) {
		rz_config_set(core->config, "asm.arch", arch);
	}
	if (bits > 0) {
		rz_config_set_i(core->config, "asm.bits", bits);
	}
}

static const char *getName(RzCore *core, ut64 addr) {
	RzFlagItem *item = rz_flag_get_i(core->flags, addr);
	if (item) {
		if (core->flags->realnames) {
			return item->realname
				? item->realname
				: item->name;
		}
		return item->name;
	}
	return NULL;
}

static char *getNameDelta(RzCore *core, ut64 addr) {
	RzFlagItem *item = rz_flag_get_at(core->flags, addr, true);
	if (item) {
		if (item->offset != addr) {
			const char *name = core->flags->realnames
				? item->realname
				: item->name;
			return rz_str_newf("%s+%" PFMT64u, name, addr - item->offset);
		}
		return strdup(item->name);
	}
	return NULL;
}

static void archbits(RzCore *core, ut64 addr) {
	rz_core_seek_arch_bits(core, addr);
}

static ut64 cfggeti(RzCore *core, const char *k) {
	return rz_config_get_i(core->config, k);
}

static const char *cfgget(RzCore *core, const char *k) {
	return rz_config_get(core->config, k);
}

static bool cfgseti(RzCore *core, const char *k, ut64 v) {
	return rz_config_set_i(core->config, k, v);
}

static bool cfgset(RzCore *core, const char *k, const char *v) {
	return rz_config_set(core->config, k, v);
}

static ut64 numget(RzCore *core, const char *k) {
	return rz_num_math(core->num, k);
}

static const RzList /*<RzFlagItem *>*/ *__flagsGet(RzCore *core, ut64 offset) {
	return rz_flag_get_list(core->flags, offset);
}

RZ_API int rz_core_bind(RzCore *core, RzCoreBind *bnd) {
	bnd->core = core;
	bnd->bphit = (RzCoreDebugBpHit)rz_core_debug_breakpoint_hit;
	bnd->syshit = (RzCoreDebugSyscallHit)rz_core_debug_syscall_hit;
	bnd->cmd = (RzCoreCmd)rz_core_cmd0;
	bnd->cmdf = (RzCoreCmdF)rz_core_cmdf;
	bnd->cmdstr = (RzCoreCmdStr)rz_core_cmd_str;
	bnd->cmdstrf = (RzCoreCmdStrF)rz_core_cmd_strf;
	bnd->puts = (RzCorePuts)rz_cons_strcat;
	bnd->setab = (RzCoreSetArchBits)setab;
	bnd->getName = (RzCoreGetName)getName;
	bnd->getNameDelta = (RzCoreGetNameDelta)getNameDelta;
	bnd->archbits = (RzCoreSeekArchBits)archbits;
	bnd->cfggeti = (RzCoreConfigGetI)cfggeti;
	bnd->cfgGet = (RzCoreConfigGet)cfgget;
	bnd->cfgSetI = (RzCoreConfigSetI)cfgseti;
	bnd->cfgSet = (RzCoreConfigSet)cfgset;
	bnd->numGet = (RzCoreNumGet)numget;
	bnd->flagsGet = (RzCoreFlagsGet)__flagsGet;
	bnd->applyBinInfo = (RzCoreBinApplyInfo)rz_core_bin_apply_info;
	return true;
}

RZ_API RzCore *rz_core_ncast(ut64 p) {
	return (RzCore *)(size_t)p;
}

RZ_API RzCore *rz_core_cast(void *p) {
	return (RzCore *)p;
}

static ut64 getref(RzCore *core, int n, char t, int type) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	RzListIter *iter;
	RzAnalysisXRef *r;
	RzList *list;
	int i = 0;
	if (!fcn) {
		return UT64_MAX;
	}
	if (t == 'r') {
		list = rz_analysis_function_get_xrefs_from(fcn);
	} else {
		list = rz_analysis_function_get_xrefs_to(fcn);
	}
	rz_list_foreach (list, iter, r) {
		if (r->type == type) {
			if (i == n) {
				ut64 addr = t == 'r' ? r->to : r->from;
				rz_list_free(list);
				return addr;
			}
			i++;
		}
	}
	rz_list_free(list);

	return UT64_MAX;
}

static ut64 bbInstructions(RzAnalysisFunction *fcn, ut64 addr) {
	void **vit;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, vit) {
		bb = (RzAnalysisBlock *)*vit;
		if (RZ_BETWEEN(bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->ninstr;
		}
	}
	return UT64_MAX;
}

static ut64 bbBegin(RzAnalysisFunction *fcn, ut64 addr) {
	void **vit;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, vit) {
		bb = (RzAnalysisBlock *)*vit;
		if (RZ_BETWEEN(bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->addr;
		}
	}
	return UT64_MAX;
}

static ut64 bbJump(RzAnalysisFunction *fcn, ut64 addr) {
	void **vit;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, vit) {
		bb = (RzAnalysisBlock *)*vit;
		if (RZ_BETWEEN(bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->jump;
		}
	}
	return UT64_MAX;
}

static ut64 bbFail(RzAnalysisFunction *fcn, ut64 addr) {
	void **vit;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, vit) {
		bb = (RzAnalysisBlock *)*vit;
		if (RZ_BETWEEN(bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->fail;
		}
	}
	return UT64_MAX;
}

static ut64 bbSize(RzAnalysisFunction *fcn, ut64 addr) {
	void **vit;
	RzAnalysisBlock *bb;
	rz_pvector_foreach (fcn->bbs, vit) {
		bb = (RzAnalysisBlock *)*vit;
		if (RZ_BETWEEN(bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->size;
		}
	}
	return 0;
}

static const char *str_callback(RzNum *user, ut64 off, int *ok) {
	RzFlag *f = (RzFlag *)user;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		RzFlagItem *item = rz_flag_get_i(f, off);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static ut64 num_callback(RzNum *userptr, const char *str, int *ok) {
	RzCore *core = (RzCore *)userptr; // XXX ?
	RzAnalysisFunction *fcn;
	char *ptr, *bptr, *out = NULL;
	RzFlagItem *flag;
	RzBinSection *s;
	RzAnalysisOp op = { 0 };
	ut64 ret = 0;

	if (ok) {
		*ok = false;
	}
	switch (*str) {
	case '.':
		if (str[1] == '.') {
			if (ok) {
				*ok = true;
			}
			return rz_num_tail(core->num, core->offset, str + 2);
		}
		if (core->num->nc.curr_tok == '+') {
			ut64 off = core->num->nc.number_value.n;
			if (!off) {
				off = core->offset;
			}
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, off);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				ut64 dst = rz_analysis_function_get_label(fcn, str + 1);
				if (dst == UT64_MAX) {
					dst = fcn->addr;
				}
				st64 delta = dst - off;
				if (delta < 0) {
					core->num->nc.curr_tok = '-';
					delta = off - dst;
				}
				return delta;
			}
		}
		break;
	case '[': {
		ut64 n = 0LL;
		int refsz = core->rasm->bits / 8;
		const char *p = NULL;
		if (strlen(str) > 5) {
			p = strchr(str + 5, ':');
		}
		if (p) {
			refsz = atoi(str + 1);
			str = p;
		}
		// push state
		if (str[0] && str[1]) {
			const char *q;
			char *o = strdup(str + 1);
			if (o) {
				q = rz_num_calc_index(core->num, NULL);
				if (q) {
					if (rz_str_replace_char(o, ']', 0) > 0) {
						n = rz_num_math(core->num, o);
						if (core->num->nc.errors) {
							return 0;
						}
						rz_num_calc_index(core->num, q);
					}
				}
				free(o);
			}
		} else {
			return 0;
		}
		// pop state
		if (ok) {
			*ok = 1;
		}
		if (!rz_io_read_i(core->io, n, &n, refsz, core->print->big_endian)) {
			return 0LL;
		}
		return n;
	} break;
	case '$':
		if (ok) {
			*ok = 1;
		}
		// TODO: group aop-dependant vars after a char, so i can filter
		rz_analysis_op_init(&op);
		rz_analysis_op(core->analysis, &op, core->offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC);
		rz_analysis_op_fini(&op); // we don't need strings or pointers, just values, which are not nullified in fini
		// XXX the above line is assuming op after fini keeps jump, fail, ptr, val, size and rz_analysis_op_is_eob()
		switch (str[1]) {
		case '.': // can use pc, sp, a0, a1, ...
			return rz_debug_reg_get(core->dbg, str + 2);
		case 'k': // $k{kv}
			if (str[2] != '{') {
				RZ_LOG_ERROR("core: expected '{' after 'k'.\n");
				break;
			}
			bptr = strdup(str + 3);
			ptr = strchr(bptr, '}');
			if (!ptr) {
				// invalid json
				free(bptr);
				break;
			}
			*ptr = '\0';
			ret = 0LL;
			out = sdb_querys(core->sdb, NULL, 0, bptr);
			if (out && *out) {
				if (strstr(out, "$k{")) {
					RZ_LOG_ERROR("core: recursivity is not permitted here\n");
				} else {
					ret = rz_num_math(core->num, out);
				}
			}
			free(bptr);
			free(out);
			return ret;
		case '{': // ${ev} eval var
			bptr = strdup(str + 2);
			ptr = strchr(bptr, '}');
			if (ptr) {
				ptr[0] = '\0';
				ut64 ret = rz_config_get_i(core->config, bptr);
				free(bptr);
				return ret;
			}
			// take flag here
			free(bptr);
			break;
		case 'c': // $c console width
			return rz_cons_get_size(NULL);
		case 'r': // $r
			if (str[2] == '{') {
				bptr = strdup(str + 3);
				ptr = strchr(bptr, '}');
				if (!ptr) {
					free(bptr);
					break;
				}
				*ptr = 0;
				return rz_core_reg_getv_by_role_or_name(core, bptr);
				free(bptr);
				return 0; // UT64_MAX;
			} else {
				int rows;
				(void)rz_cons_get_size(&rows);
				return rows;
			}
			break;
		case 'e': // $e
			if (str[2] == '{') { // $e{flag} flag off + size
				char *flagName = strdup(str + 3);
				int flagLength = strlen(flagName);
				if (flagLength > 0) {
					flagName[flagLength - 1] = 0;
				}
				RzFlagItem *flag = rz_flag_get(core->flags, flagName);
				free(flagName);
				if (flag) {
					return flag->offset + flag->size;
				}
				return UT64_MAX;
			}
			return rz_analysis_op_is_eob(&op);
		case 'j': // $j jump address
			return op.jump;
		case 'p': // $p
			return rz_sys_getpid();
		case 'P': // $P
			return core->dbg->pid > 0 ? core->dbg->pid : 0;
		case 'f': // $f jump fail address
			if (str[2] == 'l') { // $fl flag length
				RzFlagItem *fi = rz_flag_get_i(core->flags, core->offset);
				if (fi) {
					return fi->size;
				}
				return 0;
			}
			return op.fail;
		case 'm': // $m memref
			return op.ptr;
		case 'B': // $B base address
		case 'M': { // $M map address
			ut64 lower = UT64_MAX;
			ut64 size = 0LL;
			RzIOMap *map = rz_io_map_get(core->io, core->offset);
			if (map) {
				lower = rz_itv_begin(map->itv);
				size = rz_itv_size(map->itv);
			}

			if (str[1] == 'B') {
				/* clear lower bits of the lowest map address to define the base address */
				const int clear_bits = 16;
				lower >>= clear_bits;
				lower <<= clear_bits;
			}
			if (str[2] == 'M') {
				return size;
			}
			return (lower == UT64_MAX) ? 0LL : lower;
		} break;
		case 'v': // $v immediate value
			return op.val;
		case 'l': // $l opcode length
			return op.size;
		case 'b': // $b
			return core->blocksize;
		case 's': // $s file size
			if (str[2] == '{') { // $s{flag} flag size
				bptr = strdup(str + 3);
				ptr = strchr(bptr, '}');
				if (!ptr) {
					// invalid json
					free(bptr);
					break;
				}
				*ptr = '\0';
				RzFlagItem *flag = rz_flag_get(core->flags, bptr);
				ret = flag ? flag->size : 0LL; // flag
				free(bptr);
				free(out);
				return ret;
			} else if (core->file) {
				return rz_io_fd_size(core->io, core->file->fd);
			}
			return 0LL;
		case 'w': // $w word size
			return rz_config_get_i(core->config, "asm.bits") / 8;
		case 'S': // $S section offset
		{
			RzBinObject *bo = rz_bin_cur_object(core->bin);
			if (bo && (s = rz_bin_get_section_at(bo, core->offset, true))) {
				return (str[2] == 'S' ? s->size : s->vaddr);
			}
		}
			return 0LL;
		case 'D': // $D
			if (str[2] == 'B') { // $DD
				return rz_debug_get_baddr(core->dbg, NULL);
			} else if (IS_DIGIT(str[2])) {
				return getref(core, atoi(str + 2), 'r', RZ_ANALYSIS_XREF_TYPE_DATA);
			} else {
				RzDebugMap *map;
				RzListIter *iter;
				rz_list_foreach (core->dbg->maps, iter, map) {
					if (core->offset >= map->addr && core->offset < map->addr_end) {
						return (str[2] == 'D') ? map->size : map->addr;
					}
				}
			}
			return 0LL; // maybe // return UT64_MAX;
		case '?': // $?
			return core->num->value; // rc;
		case '$': // $$ offset
			return str[2] == '$' ? core->prompt_offset : core->offset;
		case 'o': { // $o
			RzBinSection *s = rz_bin_get_section_at(rz_bin_cur_object(core->bin), core->offset, true);
			return s ? core->offset - s->vaddr + s->paddr : core->offset;
			break;
		}
		case 'O': // $O
			if (core->print->cur_enabled) {
				return core->offset + core->print->cur;
			}
			return core->offset;
		case 'C': // $C nth call
			return getref(core, atoi(str + 2), 'r', RZ_ANALYSIS_XREF_TYPE_CALL);
		case 'J': // $J nth jump
			return getref(core, atoi(str + 2), 'r', RZ_ANALYSIS_XREF_TYPE_CODE);
		case 'X': // $X nth xref
			return getref(core, atoi(str + 2), 'x', RZ_ANALYSIS_XREF_TYPE_CALL);
		case 'F': // $F function size
			fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			if (fcn) {
				switch (str[2]) {
				/* function bounds (uppercase) */
				case 'B': return fcn->addr; // begin
				case 'E': return rz_analysis_function_max_addr(fcn); // end
				case 'S': return (str[3] == 'S') ? rz_analysis_function_realsize(fcn) : rz_analysis_function_linear_size(fcn);
				case 'I': return fcn->ninstr;
				/* basic blocks (lowercase) */
				case 'b': return bbBegin(fcn, core->offset);
				case 'e': return bbBegin(fcn, core->offset) + bbSize(fcn, core->offset);
				case 'i': return bbInstructions(fcn, core->offset);
				case 's': return bbSize(fcn, core->offset);
				case 'j': return bbJump(fcn, core->offset); // jump
				case 'f': return bbFail(fcn, core->offset); // fail
				}
				return fcn->addr;
			}
			return 0;
		}
		break;
	default:
		if (*str >= 'A') {
			// NOTE: functions override flags
			RzAnalysisFunction *fcn = rz_analysis_get_function_byname(core->analysis, str);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				return fcn->addr;
			}
#if 0
			ut64 addr = rz_analysis_fcn_label_get (core->analysis, core->offset, str);
			if (addr != 0) {
				ret = addr;
			} else {
				...
			}
#endif
			if ((flag = rz_flag_get(core->flags, str))) {
				ret = flag->offset;
				if (ok) {
					*ok = true;
				}
				return ret;
			}

			// check for reg alias
			RzReg *reg = rz_core_reg_default(core);
			struct rz_reg_item_t *r = rz_reg_get(reg, str, -1);
			if (!r) {
				int role = rz_reg_get_name_idx(str);
				if (role != -1) {
					const char *alias = rz_reg_get_name(reg, role);
					if (alias) {
						r = rz_reg_get(reg, alias, -1);
						if (r) {
							if (ok) {
								*ok = true;
							}
							ret = rz_reg_get_value(reg, r);
							return ret;
						}
					}
				}
			} else {
				if (ok) {
					*ok = true;
				}
				ret = rz_reg_get_value(reg, r);
				return ret;
			}
		}
		break;
	}

	return ret;
}

RZ_API RzCore *rz_core_new(void) {
	RzCore *c = RZ_NEW0(RzCore);
	if (c) {
		rz_core_init(c);
	}
	return c;
}

static RzLineNSCompletionResult *rzshell_autocomplete(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	return rz_core_autocomplete_rzshell((RzCore *)user, buf, prompt_type);
}

RZ_API int rz_core_fgets(char *buf, int len, void *user) {
	RzCore *core = (RzCore *)user;
	RzCons *cons = core->cons;
	RzLine *rzline = cons->line;
	bool prompt = cons->context->is_interactive;
	buf[0] = '\0';
	if (prompt) {
		rzline->ns_completion.run = rzshell_autocomplete;
		rzline->ns_completion.run_user = core;
		rzline->completion.run = NULL;
	} else {
		rzline->history.data = NULL;
		rz_line_completion_set(&rzline->completion, 0, NULL);
		rzline->completion.run = NULL;
		rzline->completion.run_user = NULL;
	}
	const char *ptr = rz_line_readline(rzline);
	if (!ptr) {
		return -1;
	}
	return rz_str_ncpy(buf, ptr, len - 1);
}

static const char *rz_core_print_offname(void *p, ut64 addr) {
	RzCore *c = (RzCore *)p;
	RzFlagItem *item = rz_flag_get_i(c->flags, addr);
	return item ? item->name : NULL;
}

static int rz_core_print_offsize(void *p, ut64 addr) {
	RzCore *c = (RzCore *)p;
	RzFlagItem *item = rz_flag_get_i(c->flags, addr);
	return item ? item->size : -1;
}

/**
 * Disassemble one instruction at specified address.
 */
static int __disasm(void *_core, ut64 addr) {
	RzCore *core = _core;
	ut64 prevaddr = core->offset;

	rz_core_seek(core, addr, true);
	int len = rz_core_print_disasm_instructions(core, 0, 1);
	rz_core_seek(core, prevaddr, true);

	return len;
}

static void update_sdb(RzCore *core) {
	Sdb *d;
	RzBinObject *o;
	if (!core) {
		return;
	}
	// SDB// analysis/
	if (core->analysis && core->analysis->sdb) {
		sdb_ns_set(DB, "analysis", core->analysis->sdb);
	}
	// SDB// bin/
	if (core->bin && core->bin->sdb) {
		sdb_ns_set(DB, "bin", core->bin->sdb);
	}
	// SDB// bin/info
	o = rz_bin_cur_object(core->bin);
	if (o) {
		sdb_ns_set(sdb_ns(DB, "bin", 1), "info", o->kv);
	}
	// sdb_ns_set (core->sdb, "flags", core->flags->sdb);
	// sdb_ns_set (core->sdb, "bin", core->bin->sdb);
	// SDB// syscall/
	if (core->rasm && core->rasm->syscall && core->rasm->syscall->db) {
		sdb_ns_set(DB, "syscall", core->rasm->syscall->db);
	}
	d = sdb_ns(DB, "debug", 1);
	if (core->dbg->sgnls) {
		sdb_ns_set(d, "signals", core->dbg->sgnls);
	}
}

static bool get_string(const ut8 *buf, int size, RzDetectedString **dstr, RzStrEnc encoding, bool big_endian) {
	if (!buf || size < 1) {
		return false;
	}

	RzUtilStrScanOptions opt = {
		.buf_size = size,
		.max_uni_blocks = 4,
		.min_str_length = 4,
		.prefer_big_endian = big_endian,
		.check_ascii_freq = false,
	};

	if (rz_scan_strings_single_raw(buf, size, &opt, encoding, dstr) && (*dstr)->addr) {
		rz_detected_string_free(*dstr);
		*dstr = NULL;
	}
	return *dstr;
}

RZ_API char *rz_core_analysis_hasrefs(RzCore *core, ut64 value, int mode) {
	if (mode) {
		PJ *pj = (mode == 'j') ? pj_new() : NULL;
		const int hex_depth = 1; // r_config_get_i (core->config, "hex.depth");
		char *res = rz_core_analysis_hasrefs_to_depth(core, value, pj, hex_depth);
		if (pj) {
			free(res);
			return pj_drain(pj);
		}
		return res;
	}
	RzFlagItem *fi = rz_flag_get_i(core->flags, value);
	return fi ? strdup(fi->name) : NULL;
}

static char *getvalue(ut64 value, int bits) {
	switch (bits) {
	case 16: // umf, not in sync with pxr
	{
		st16 v = (st16)(value & UT16_MAX);
		st16 h = UT16_MAX / 0x100;
		if (v > -h && v < h) {
			return rz_str_newf("%hd", v);
		}
	} break;
	case 32: {
		st32 v = (st32)(value & UT32_MAX);
		st32 h = UT32_MAX / 0x10000;
		if (v > -h && v < h) {
			return rz_str_newf("%d", v);
		}
	} break;
	case 64: {
		st64 v = (st64)(value);
		st64 h = UT64_MAX / 0x1000000;
		if (v > -h && v < h) {
			return rz_str_newf("%" PFMT64d, v);
		}
	} break;
	}
	return NULL;
}

/*
 pxr logic is dupplicated in other places
 * ai, ad
 * no json support
*/
RZ_API char *rz_core_analysis_hasrefs_to_depth(RzCore *core, ut64 value, PJ *pj, int depth) {
	const int bits = core->rasm->bits;
	const bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	rz_return_val_if_fail(core, NULL);
	RzStrBuf *s = rz_strbuf_new(NULL);
	if (pj) {
		pj_o(pj);
		pj_kn(pj, "addr", value);
	}
	if (depth < 1 || value == UT64_MAX) {
		if (pj) {
			pj_end(pj);
		}
		return NULL;
	}

	char *val = getvalue(value, bits);
	if (val) {
		if (pj) {
			pj_ks(pj, "value", val);
		} else {
			rz_strbuf_appendf(s, "%s ", val);
		}
		RZ_FREE(val);
	}

	if (value && value != UT64_MAX) {
		RzDebugMap *map = rz_debug_map_get(core->dbg, value);
		if (map && map->name && map->name[0]) {
			if (pj) {
				pj_ks(pj, "map", map->name);
			} else {
				rz_strbuf_appendf(s, "%s ", map->name);
			}
		}
	}
	ut64 type = rz_core_analysis_address(core, value);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinSection *sect = value && obj ? rz_bin_get_section_at(obj, value, true) : NULL;
	if (!((type & RZ_ANALYSIS_ADDR_TYPE_HEAP) || (type & RZ_ANALYSIS_ADDR_TYPE_STACK))) {
		// Do not repeat "stack" or "heap" words unnecessarily.
		if (sect && sect->name[0]) {
			if (pj) {
				pj_ks(pj, "section", sect->name);
			} else {
				rz_strbuf_appendf(s, "%s ", sect->name);
			}
		}
	}
	if (value != 0 && value != UT64_MAX) {
		if (pj) {
			RzListIter *iter;
			RzFlagItem *f;
			const RzList *flags = rz_flag_get_list(core->flags, value);
			if (flags && !rz_list_empty(flags)) {
				pj_ka(pj, "flags");
				rz_list_foreach (flags, iter, f) {
					pj_s(pj, f->name);
				}
				pj_end(pj);
			}
		} else {
			char *flags = rz_flag_get_liststr(core->flags, value);
			if (flags) {
				rz_strbuf_appendf(s, "%s ", flags);
				free(flags);
			}
		}
	}
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, value, 0);
	if (fcn) {
		if (pj) {
			pj_ks(pj, "fcn", fcn->name);
		} else {
			rz_strbuf_appendf(s, "%s ", fcn->name);
		}
	}
	if (type) {
		const char *c = rz_core_analysis_optype_colorfor(core, value, true);
		const char *cend = (c && *c) ? Color_RESET : "";
		if (!c) {
			c = "";
		}
		if (pj) {
			pj_ka(pj, "attr");
		}
		if (type & RZ_ANALYSIS_ADDR_TYPE_HEAP) {
			if (pj) {
				pj_s(pj, "heap");
			} else {
				rz_strbuf_appendf(s, "%sheap%s ", c, cend);
			}
		} else if (type & RZ_ANALYSIS_ADDR_TYPE_STACK) {
			if (pj) {
				pj_s(pj, "stack");
			} else {
				rz_strbuf_appendf(s, "%sstack%s ", c, cend);
			}
		}
		if (type & RZ_ANALYSIS_ADDR_TYPE_PROGRAM) {
			if (pj) {
				pj_s(pj, "program");
			} else {
				rz_strbuf_appendf(s, "%sprogram%s ", c, cend);
			}
		}
		if (type & RZ_ANALYSIS_ADDR_TYPE_LIBRARY) {
			if (pj) {
				pj_s(pj, "library");
			} else {
				rz_strbuf_appendf(s, "%slibrary%s ", c, cend);
			}
		}
		if (type & RZ_ANALYSIS_ADDR_TYPE_ASCII) {
			if (pj) {
				pj_s(pj, "ascii");
			} else {
				rz_strbuf_appendf(s, "%sascii%s ('%c') ", c, cend, (char)value);
			}
		}
		if (type & RZ_ANALYSIS_ADDR_TYPE_SEQUENCE) {
			if (pj) {
				pj_s(pj, "sequence");
			} else {
				rz_strbuf_appendf(s, "%ssequence%s ", c, cend);
			}
		}
		if (pj) {
			if (type & RZ_ANALYSIS_ADDR_TYPE_READ) {
				pj_s(pj, "R");
			}
			if (type & RZ_ANALYSIS_ADDR_TYPE_WRITE) {
				pj_s(pj, "W");
			}
			if (type & RZ_ANALYSIS_ADDR_TYPE_EXEC) {
				pj_s(pj, "X");
			}
		} else {
			if (type & RZ_ANALYSIS_ADDR_TYPE_READ) {
				rz_strbuf_appendf(s, "%sR%s ", c, cend);
			}
			if (type & RZ_ANALYSIS_ADDR_TYPE_WRITE) {
				rz_strbuf_appendf(s, "%sW%s ", c, cend);
			}
			if (type & RZ_ANALYSIS_ADDR_TYPE_EXEC) {
				RzAsmOp op;
				ut8 buf[32];
				rz_strbuf_appendf(s, "%sX%s ", c, cend);
				/* instruction disassembly */
				rz_io_read_at(core->io, value, buf, sizeof(buf));
				rz_asm_set_pc(core->rasm, value);
				rz_asm_disassemble(core->rasm, &op, buf, sizeof(buf));
				rz_strbuf_appendf(s, "'%s' ", rz_asm_op_get_asm(&op));
				/* get library name */
				{ // NOTE: dup for mapname?
					RzDebugMap *map;
					RzListIter *iter;
					rz_list_foreach (core->dbg->maps, iter, map) {
						if ((value >= map->addr) &&
							(value < map->addr_end)) {
							const char *lastslash = rz_str_lchr(map->name, '/');
							rz_strbuf_appendf(s, "'%s' ", lastslash ? lastslash + 1 : map->name);
							break;
						}
					}
				}
			} else if (type & RZ_ANALYSIS_ADDR_TYPE_READ) {
				ut8 buf[8];
				if (rz_io_read_at(core->io, value, buf, sizeof(buf))) {
					ut64 n = rz_read_ble(buf, big_endian, bits);
					rz_strbuf_appendf(s, "0x%" PFMT64x " ", n);
				}
			}
		}
		if (pj) {
			pj_end(pj);
		}
	}
	{
		ut8 buf[128];
		RzStrEnc encoding = core->bin->str_search_cfg.string_encoding;
		const char *c = rz_config_get_i(core->config, "scr.color") ? core->cons->context->pal.ai_ascii : "";
		const char *cend = (c && *c) ? Color_RESET : "";
		RzDetectedString *dstr = NULL;
		if (rz_io_read_at(core->io, value, buf, sizeof(buf)) &&
			get_string(buf, sizeof(buf), &dstr, encoding, big_endian)) {
			if (pj) {
				pj_ks(pj, "string", dstr->string);
			} else {
				rz_strbuf_appendf(s, "%s%s%s ", c, dstr->string, cend);
			}
			rz_detected_string_free(dstr);
		}
	}
	if ((type & RZ_ANALYSIS_ADDR_TYPE_READ) && !(type & RZ_ANALYSIS_ADDR_TYPE_EXEC) && depth) {
		// Try to telescope further, but only several levels deep.
		ut8 buf[8];
		if (rz_io_read_at(core->io, value, buf, sizeof(buf))) {
			ut64 n = rz_read_ble(buf, big_endian, bits);
			if (n != value) {
				if (pj) {
					pj_k(pj, "ref");
				}
				char *rrstr = rz_core_analysis_hasrefs_to_depth(core, n, pj, depth - 1);
				if (rrstr) {
					if (!pj && rrstr[0]) {
						rz_strbuf_appendf(s, " -> %s", rrstr);
					}
					free(rrstr);
				}
			}
		}
	}
	if (pj) {
		pj_end(pj);
	}
	char *res = rz_strbuf_drain(s);
	rz_str_trim_tail(res);
	return res;
}

RZ_API char *rz_core_analysis_get_comments(RzCore *core, ut64 addr) {
	if (core) {
		const char *type = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, addr);
		const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
		if (type && cmt) {
			return rz_str_newf("%s %s", type, cmt);
		}
		if (type) {
			return strdup(type);
		}
		if (cmt) {
			return strdup(cmt);
		}
	}
	return NULL;
}

RZ_API const char *rz_core_analysis_optype_colorfor(RzCore *core, ut64 addr, bool verbose) {
	ut64 type;
	if (!(core->print->flags & RZ_PRINT_FLAGS_COLOR)) {
		return NULL;
	}
	if (!rz_config_get_i(core->config, "scr.color")) {
		return NULL;
	}
	type = rz_core_analysis_address(core, addr);
	if (type & RZ_ANALYSIS_ADDR_TYPE_EXEC) {
		return core->cons->context->pal.ai_exec; // Color_RED;
	}
	if (type & RZ_ANALYSIS_ADDR_TYPE_WRITE) {
		return core->cons->context->pal.ai_write; // Color_BLUE;
	}
	if (type & RZ_ANALYSIS_ADDR_TYPE_READ) {
		return core->cons->context->pal.ai_read; // Color_GREEN;
	}
	if (type & RZ_ANALYSIS_ADDR_TYPE_SEQUENCE) {
		return core->cons->context->pal.ai_seq; // Color_MAGENTA;
	}
	if (type & RZ_ANALYSIS_ADDR_TYPE_ASCII) {
		return core->cons->context->pal.ai_ascii; // Color_YELLOW;
	}
	return NULL;
}

static int mywrite(const ut8 *buf, int len) {
	return rz_cons_memcat((const char *)buf, len);
}

static bool exists_var(RzPrint *print, ut64 func_addr, char *str) {
	RzAnalysis *analysis = ((RzCore *)(print->user))->analysis;
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, func_addr);
	if (!fcn) {
		return false;
	}
	return !!rz_analysis_function_get_var_byname(fcn, str);
}

static bool rz_core_analysis_read_at(struct rz_analysis_t *analysis, ut64 addr, ut8 *buf, int len) {
	return rz_io_read_at(analysis->iob.io, addr, buf, len);
}

static void rz_core_break(RzCore *core) {
}

static void *rz_core_sleep_begin(RzCore *core) {
	RzCoreTask *task = rz_core_task_self(&core->tasks);
	if (task) {
		rz_core_task_sleep_begin(task);
	}
	return task;
}

static void rz_core_sleep_end(RzCore *core, void *user) {
	RzCoreTask *task = (RzCoreTask *)user;
	if (task) {
		rz_core_task_sleep_end(task);
	}
}

static const char *colorfor_cb(void *user, ut64 addr, bool verbose) {
	return rz_core_analysis_optype_colorfor((RzCore *)user, addr, verbose);
}

static char *hasrefs_cb(void *user, ut64 addr, int mode) {
	return rz_core_analysis_hasrefs((RzCore *)user, addr, mode);
}

static const char *get_section_name(void *user, ut64 addr) {
	return rz_core_get_section_name((RzCore *)user, addr);
}

static char *get_comments_cb(void *user, ut64 addr) {
	return rz_core_analysis_get_comments((RzCore *)user, addr);
}

static RzFlagItem *core_flg_class_set(RzFlag *f, const char *name, ut64 addr, ut32 size) {
	rz_flag_space_push(f, RZ_FLAGS_FS_CLASSES);
	RzFlagItem *res = rz_flag_set(f, name, addr, size);
	rz_flag_space_pop(f);
	return res;
}

static RzFlagItem *core_flg_class_get(RzFlag *f, const char *name) {
	rz_flag_space_push(f, RZ_FLAGS_FS_CLASSES);
	RzFlagItem *res = rz_flag_get(f, name);
	rz_flag_space_pop(f);
	return res;
}

static RzFlagItem *core_flg_fcn_set(RzFlag *f, const char *name, ut64 addr, ut32 size) {
	rz_flag_space_push(f, RZ_FLAGS_FS_FUNCTIONS);
	RzFlagItem *res = rz_flag_set(f, name, addr, size);
	rz_flag_space_pop(f);
	return res;
}

RZ_API RzFlagItem *rz_core_flag_get_by_spaces(RzFlag *f, ut64 off) {
	return rz_flag_get_by_spaces(f, off,
		RZ_FLAGS_FS_FUNCTIONS,
		RZ_FLAGS_FS_SIGNS,
		RZ_FLAGS_FS_CLASSES,
		RZ_FLAGS_FS_SYMBOLS,
		RZ_FLAGS_FS_IMPORTS,
		RZ_FLAGS_FS_RELOCS,
		RZ_FLAGS_FS_STRINGS,
		RZ_FLAGS_FS_RESOURCES,
		RZ_FLAGS_FS_SYMBOLS_SECTIONS,
		RZ_FLAGS_FS_SECTIONS,
		RZ_FLAGS_FS_SEGMENTS,
		NULL);
}

#if __WINDOWS__
// XXX move to rcons?
static int win_eprintf(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	rz_cons_win_vhprintf(STD_ERROR_HANDLE, false, format, ap);
	va_end(ap);
	return 0;
}
#endif

static bool bp_is_mapped(ut64 addr, int perm, void *user) {
	RzCore *core = user;
	if (rz_core_is_debug(core)) {
		// RzList *maps = core->dbg->maps;
		RzDebugMap *map = NULL;
		RzListIter *iter = NULL;

		rz_list_foreach (core->dbg->maps, iter, map) {
			if (addr < map->addr || addr >= map->addr_end) {
				continue;
			}
			if (perm <= 0 || (map->perm & perm)) {
				return true;
			}
		}
		return false;
	}

	return rz_io_map_is_mapped(core->io, addr);
}

static void bp_maps_sync(void *user) {
	RzCore *core = user;
	if (rz_core_is_debug(core)) {
		rz_debug_map_sync(core->dbg);
	}
}

static int bp_bits_at(ut64 addr, void *user) {
	RzCore *core = user;
	int r = 0;
	rz_core_arch_bits_at(core, addr, &r, NULL);
	return r ? r : core->analysis->bits;
}

static void ev_iowrite_cb(RzEvent *ev, int type, void *user, void *data) {
	RzCore *core = user;
	RzEventIOWrite *iow = data;
	if (rz_config_get_i(core->config, "analysis.detectwrites")) {
		rz_analysis_update_analysis_range(core->analysis, iow->addr, iow->len);
		if (core->cons->event_resize && core->cons->event_data) {
			// Force a reload of the graph
			core->cons->event_resize(core->cons->event_data);
		}
	}
}

RZ_IPI void rz_core_file_io_desc_closed(RzCore *core, RzIODesc *desc);
RZ_IPI void rz_core_file_io_map_deleted(RzCore *core, RzIOMap *map);
RZ_IPI void rz_core_file_bin_file_deleted(RzCore *core, RzBinFile *bf);
RZ_IPI void rz_core_vfile_bin_file_deleted(RzCore *core, RzBinFile *bf);

static void ev_iodescclose_cb(RzEvent *ev, int type, void *user, void *data) {
	RzEventIODescClose *ioc = data;
	rz_core_file_io_desc_closed(user, ioc->desc);
}

static void ev_iomapdel_cb(RzEvent *ev, int type, void *user, void *data) {
	RzEventIOMapDel *iod = data;
	rz_core_file_io_map_deleted(user, iod->map);
}

static void ev_binfiledel_cb(RzEvent *ev, int type, void *user, void *data) {
	RzEventBinFileDel *bev = data;
	rz_core_file_bin_file_deleted(user, bev->bf);
	rz_core_vfile_bin_file_deleted(user, bev->bf);
}

RZ_IPI void rz_core_task_ctx_switch(RzCoreTask *next, void *user);
RZ_IPI void rz_core_task_break_cb(RzCoreTask *task, void *user);
RZ_IPI void rz_core_file_free(RzCoreFile *cf);

RZ_IPI extern RzIOPlugin rz_core_io_plugin_vfile;

RZ_API bool rz_core_init(RzCore *core) {
	core->blocksize = RZ_CORE_BLOCKSIZE;
	core->block = (ut8 *)calloc(RZ_CORE_BLOCKSIZE + 1, 1);
	if (!core->block) {
		RZ_LOG_ERROR("core: cannot allocate %d byte(s)\n", RZ_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return false;
	}
	core->ev = rz_event_new(core);
	core->max_cmd_depth = RZ_CONS_CMD_DEPTH + 1;
	core->sdb = sdb_new(NULL, "rzkv.sdb", 0); // XXX: path must be in home?
	rz_core_seek_reset(core);
	core->lastsearch = NULL;
	core->cmdfilter = NULL;
	core->curtheme = strdup("default");
	core->switch_file_view = 0;
	core->cmdremote = 0;
	core->incomment = false;
	core->config = NULL;
	core->http_up = false;
	ZERO_FILL(core->root_cmd_descriptor);
	core->print = rz_print_new();
	core->ropchain = rz_list_newf((RzListFree)free);
	rz_core_bind(core, &(core->print->coreb));
	core->print->user = core;
	core->print->num = core->num;
	core->print->offname = rz_core_print_offname;
	core->print->offsize = rz_core_print_offsize;
	core->print->cb_printf = rz_cons_printf;
	core->print->cb_color = rz_cons_rainbow_get;
	core->print->write = mywrite;
	core->print->exists_var = exists_var;
	core->print->disasm = __disasm;
	core->print->colorfor = colorfor_cb;
	core->print->hasrefs = hasrefs_cb;
	core->print->get_comments = get_comments_cb;
	core->print->get_section_name = get_section_name;
	core->print->use_comments = false;
	rz_core_rtr_init(core);
	core->rtr_n = 0;
	core->blocksize_max = RZ_CORE_BLOCKSIZE_MAX;
	rz_core_task_scheduler_init(&core->tasks, rz_core_task_ctx_switch, NULL, rz_core_task_break_cb, NULL);
	core->watchers = rz_list_new();
	core->watchers->free = (RzListFree)rz_core_cmpwatch_free;
	core->scriptstack = rz_list_new();
	core->scriptstack->free = (RzListFree)free;
	core->times = RZ_NEW0(RzCoreTimes);
	core->vmode = false;
	core->lastcmd = NULL;
	core->cmdlog = NULL;
	core->stkcmd = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = true;
	core->yank_buf = rz_buf_new_with_bytes(NULL, 0);
	core->num = rz_num_new(&num_callback, &str_callback, core);
	core->egg = rz_egg_new();
	rz_egg_setup(core->egg, RZ_SYS_ARCH, RZ_SYS_BITS, 0, RZ_SYS_OS);
	core->crypto = rz_crypto_new();

	core->fixedarch = false;
	core->fixedbits = false;

	/* initialize libraries */
	core->cons = rz_cons_new();
	if (core->cons->refcnt == 1) {
		core->cons = rz_cons_singleton();
		if (core->cons->line) {
			core->cons->line->user = core;
			core->cons->line->cb_editor =
				(RzLineEditorCb)&rz_core_editor;
			core->cons->line->cb_fkey = core->cons->cb_fkey;
		}
#if __EMSCRIPTEN__
		core->cons->user_fgets = NULL;
#else
		core->cons->user_fgets = (void *)rz_core_fgets;
		core->cons->user_fgets_user = core;
#endif
		char *history = rz_path_home_history();
		rz_line_hist_load(core->cons->line, history);
		free(history);
	}
	core->print->cons = core->cons;
	rz_cons_bind(&core->print->consbind);

	// We save the old num ad user, in order to restore it after free
	core->lang = rz_lang_new();
	core->lang->cmd_str = (char *(*)(void *, const char *))rz_core_cmd_str;
	core->lang->cmdf = (int (*)(void *, const char *, ...))rz_core_cmdf;
	rz_core_bind_cons(core);
	core->lang->cb_printf = rz_cons_printf;
	rz_lang_define(core->lang, "RzCore", "core", core);
	rz_lang_set_user_ptr(core->lang, core);
	core->rasm = rz_asm_new();
	core->rasm->num = core->num;
	core->rasm->core = core;
	core->analysis = rz_analysis_new();
	core->gadgets = rz_list_newf((RzListFree)rz_core_gadget_free);
	core->analysis->ev = core->ev;
	core->analysis->read_at = rz_core_analysis_read_at;
	core->analysis->flag_get = rz_core_flag_get_by_spaces;
	core->analysis->cb.on_fcn_new = on_fcn_new;
	core->analysis->cb.on_fcn_delete = on_fcn_delete;
	core->analysis->cb.on_fcn_rename = on_fcn_rename;
	core->rasm->syscall = rz_syscall_ref(core->analysis->syscall); // BIND syscall analysis/asm
	core->analysis->core = core;
	core->parser = rz_parse_new();
	rz_analysis_bind(core->analysis, &(core->parser->analb));
	core->parser->var_expr_for_reg_access = rz_analysis_function_var_expr_for_reg_access_at;
	/// XXX shouhld be using coreb
	rz_parse_set_user_ptr(core->parser, core);
	core->bin = rz_bin_new();
	rz_event_hook(core->bin->event, RZ_EVENT_BIN_FILE_DEL, ev_binfiledel_cb, core);
	rz_cons_bind(&core->bin->consb);
	// XXX we shuold use RzConsBind instead of this hardcoded pointer
	core->bin->cb_printf = (PrintfCallback)rz_cons_printf;
	rz_bin_set_user_ptr(core->bin, core);
	core->io = rz_io_new();
	rz_io_plugin_add(core->io, &rz_core_io_plugin_vfile);
	rz_event_hook(core->io->event, RZ_EVENT_IO_WRITE, ev_iowrite_cb, core);
	rz_event_hook(core->io->event, RZ_EVENT_IO_DESC_CLOSE, ev_iodescclose_cb, core);
	rz_event_hook(core->io->event, RZ_EVENT_IO_MAP_DEL, ev_iomapdel_cb, core);
	core->io->ff = 1;
	core->search = rz_search_new(RZ_SEARCH_KEYWORD);
	core->flags = rz_flag_new();
	core->graph = rz_agraph_new(rz_cons_canvas_new(1, 1));
	core->graph->need_reload_nodes = false;
	core->asmqjmps_size = RZ_CORE_ASMQJMPS_NUM;
	if (sizeof(ut64) * core->asmqjmps_size < core->asmqjmps_size) {
		core->asmqjmps_size = 0;
		core->asmqjmps = NULL;
	} else {
		core->asmqjmps = RZ_NEWS(ut64, core->asmqjmps_size);
	}
	core->hash = rz_hash_new();

	rz_bin_bind(core->bin, &(core->rasm->binb));
	rz_bin_bind(core->bin, &(core->analysis->binb));
	rz_bin_bind(core->bin, &(core->analysis->binb));

	rz_io_bind(core->io, &(core->search->iob));
	rz_io_bind(core->io, &(core->print->iob));
	rz_io_bind(core->io, &(core->analysis->iob));
	rz_io_bind(core->io, &(core->analysis->typedb->iob));
	rz_io_bind(core->io, &(core->bin->iob));
	rz_flag_bind(core->flags, &(core->analysis->flb));
	core->analysis->flg_class_set = core_flg_class_set;
	core->analysis->flg_class_get = core_flg_class_get;
	core->analysis->flg_fcn_set = core_flg_fcn_set;
	rz_analysis_bind(core->analysis, &(core->parser->analb));
	core->parser->flag_get = rz_core_flag_get_by_spaces;
	core->parser->label_get = rz_analysis_function_get_label_at;

	rz_core_bind(core, &(core->analysis->coreb));

	core->file = NULL;
	core->files = rz_list_newf((RzListFree)rz_core_file_free);
	core->offset = 0LL;
	core->prompt_offset = 0LL;
	rz_core_cmd_init(core);
	rz_core_plugin_init(core);

	RzBreakpointContext bp_ctx = {
		.user = core,
		.is_mapped = bp_is_mapped,
		.maps_sync = bp_maps_sync,
		.bits_at = bp_bits_at
	};
	core->dbg = rz_debug_new(&bp_ctx);

	rz_io_bind(core->io, &(core->dbg->iob));
	rz_io_bind(core->io, &(core->dbg->bp->iob));
	rz_core_bind(core, &core->dbg->corebind);
	rz_core_bind(core, &core->io->corebind);
	core->dbg->analysis = core->analysis; // XXX: dupped instance.. can cause lost pointerz
	// rz_debug_use (core->dbg, "native");
	//  XXX pushing uninitialized regstate results in trashed reg values
	//	rz_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
	//	core->dbg->analysis->reg = core->analysis->reg; // XXX: dupped instance.. can cause lost pointerz
	core->io->cb_printf = rz_cons_printf;
	core->dbg->cb_printf = rz_cons_printf;
	core->dbg->bp->cb_printf = rz_cons_printf;
	core->dbg->ev = core->ev;
	// Initialize visual modes after everything else but before config init
	core->visual = rz_core_visual_new();
	// initialize config before any corebind
	rz_core_config_init(core);

	rz_core_loadlibs_init(core);

	// TODO: get arch from rz_bin or from native arch
	rz_asm_use(core->rasm, RZ_SYS_ARCH);
	rz_analysis_use(core->analysis, RZ_SYS_ARCH);
	if (RZ_SYS_BITS & RZ_SYS_BITS_64) {
		rz_config_set_i(core->config, "asm.bits", 64);
	} else {
		if (RZ_SYS_BITS & RZ_SYS_BITS_32) {
			rz_config_set_i(core->config, "asm.bits", 32);
		}
	}
	rz_config_set(core->config, "asm.arch", RZ_SYS_ARCH);
	rz_bp_use(core->dbg->bp, RZ_SYS_ARCH);
	update_sdb(core);
	{
		char *a = rz_path_system(RZ_FLAGS);
		if (a) {
			char *file = rz_file_path_join(a, "tags.rz");
			(void)rz_core_run_script(core, file);
			free(file);
			free(a);
		}
	}
	rz_core_analysis_type_init(core);
	return 0;
}

RZ_API void __cons_cb_fkey(RzCore *core, int fkey) {
	char buf[32];
	snprintf(buf, sizeof(buf), "key.f%d", fkey);
	const char *v = rz_config_get(core->config, buf);
	if (v && *v) {
		rz_cons_printf("%s\n", v);
		rz_core_cmd0(core, v);
		rz_cons_flush();
	}
}

RZ_API void rz_core_bind_cons(RzCore *core) {
	core->cons->num = core->num;
	core->cons->cb_fkey = (RzConsFunctionKey)__cons_cb_fkey;
	core->cons->cb_editor = (RzConsEditorCallback)rz_core_editor;
	core->cons->cb_break = (RzConsBreakCallback)rz_core_break;
	core->cons->cb_sleep_begin = (RzConsSleepBeginCallback)rz_core_sleep_begin;
	core->cons->cb_sleep_end = (RzConsSleepEndCallback)rz_core_sleep_end;
	core->cons->cb_task_oneshot = (RzConsQueueTaskOneshot)rz_core_task_enqueue_oneshot;
	core->cons->user = (void *)core;
}

RZ_API void rz_core_fini(RzCore *c) {
	if (!c) {
		return;
	}
	RZ_FREE_CUSTOM(c->lib, rz_lib_free);
	rz_core_plugin_fini(c);
	rz_core_task_break_all(&c->tasks);
	rz_core_task_join(&c->tasks, NULL, -1);
	rz_core_wait(c);
	//  avoid double free
	RZ_FREE_CUSTOM(c->hash, rz_hash_free);
	RZ_FREE_CUSTOM(c->ropchain, rz_list_free);
	RZ_FREE_CUSTOM(c->ev, rz_event_free);
	RZ_FREE(c->cmdlog);
	RZ_FREE(c->lastsearch);
	RZ_FREE(c->cons->pager);
	RZ_FREE(c->cmdqueue);
	RZ_FREE(c->lastcmd);
	RZ_FREE(c->stkcmd);
	RZ_FREE(c->block);

	RZ_FREE_CUSTOM(c->gadgets, rz_list_free);
	RZ_FREE_CUSTOM(c->num, rz_num_free);
	RZ_FREE(c->table_query);
	RZ_FREE_CUSTOM(c->io, rz_io_free);
	RZ_FREE_CUSTOM(c->files, rz_list_free);
	RZ_FREE_CUSTOM(c->watchers, rz_list_free);
	RZ_FREE_CUSTOM(c->scriptstack, rz_list_free);
	rz_core_task_scheduler_fini(&c->tasks);
	RZ_FREE_CUSTOM(c->rcmd, rz_cmd_free);
	RZ_FREE_CUSTOM(c->cmd_descriptors, rz_list_free);
	RZ_FREE_CUSTOM(c->analysis, rz_analysis_free);
	RZ_FREE_CUSTOM(c->rasm, rz_asm_free);
	RZ_FREE_CUSTOM(c->print, rz_print_free);
	RZ_FREE_CUSTOM(c->bin, rz_bin_free);
	RZ_FREE_CUSTOM(c->lang, rz_lang_free);
	RZ_FREE_CUSTOM(c->dbg, rz_debug_free);
	RZ_FREE_CUSTOM(c->config, rz_config_free);
	/* after rz_config_free, the value of I.teefile is trashed */
	/* rconfig doesnt knows how to deinitialize vars, so we
	should probably need to add a rz_config_free_payload callback */
	rz_cons_free();
	rz_cons_singleton()->teefile = NULL; // HACK
	RZ_FREE_CUSTOM(c->search, rz_search_free);
	RZ_FREE_CUSTOM(c->flags, rz_flag_free);
	RZ_FREE_CUSTOM(c->egg, rz_egg_free);
	RZ_FREE_CUSTOM(c->crypto, rz_crypto_free);
	RZ_FREE_CUSTOM(c->yank_buf, rz_buf_free);
	RZ_FREE_CUSTOM(c->graph, rz_agraph_free);
	RZ_FREE(c->asmqjmps);
	RZ_FREE_CUSTOM(c->sdb, sdb_free);
	RZ_FREE_CUSTOM(c->parser, rz_parse_free);
	RZ_FREE(c->times);
	rz_core_seek_free(c);
	RZ_FREE(c->rtr_host);
	RZ_FREE(c->curtheme);
	rz_core_visual_free(c->visual);
}

RZ_API void rz_core_free(RzCore *c) {
	rz_core_fini(c);
	free(c);
}

RZ_API void rz_core_prompt_loop(RzCore *r) {
	int ret;
	do {
		if (rz_config_get_b(r->config, "dbg.status")) {
			rz_core_debug_print_status(r);
		}
		int err = rz_core_prompt(r, false);
		if (err < 1) {
			// handle ^D
			r->num->value = 0; // r.num->value will be read by rz_main_rizin() after calling this fcn
			break;
		}
		/* -1 means invalid command, -2 means quit prompt loop */
		if ((ret = rz_core_prompt_exec(r)) == -2) {
			break;
		}
	} while (ret != RZ_CORE_CMD_EXIT);
}

static bool prompt_add_file(RzCore *core, RzStrBuf *sb, bool add_sep) {
	if (!rz_config_get_b(core->config, "scr.prompt.file") || !core->io->desc) {
		return add_sep;
	}
	if (add_sep) {
		rz_strbuf_append(sb, ":");
	}
	rz_strbuf_append(sb, rz_file_basename(core->io->desc->name));
	return true;
}

static bool prompt_add_section(RzCore *core, RzStrBuf *sb, bool add_sep) {
	if (!rz_config_get_b(core->config, "scr.prompt.sect")) {
		return add_sep;
	}
	const RzBinSection *sec = rz_bin_get_section_at(rz_bin_cur_object(core->bin), core->offset, true);
	if (!sec) {
		return add_sep;
	}
	if (add_sep) {
		rz_strbuf_append(sb, ":");
	}
	rz_strbuf_append(sb, sec->name);
	return true;
}

static bool prompt_add_offset(RzCore *core, RzStrBuf *sb, bool add_sep) {
	if (add_sep) {
		rz_strbuf_append(sb, ":");
	}
	if (rz_config_get_b(core->config, "scr.prompt.flag")) {
		const RzFlagItem *f = rz_flag_get_at(core->flags, core->offset, true);
		if (f) {
			if (f->offset < core->offset) {
				rz_strbuf_appendf(sb, "%s + %" PFMT64u, f->name, core->offset - f->offset);
			} else {
				rz_strbuf_appendf(sb, "%s", f->name);
			}
			if (rz_config_get_b(core->config, "scr.prompt.flag.only")) {
				return true;
			}

			rz_strbuf_append(sb, ":");
		}
	}

	if (rz_config_get_b(core->config, "asm.segoff")) {
		ut32 a, b;
		unsigned int seggrn = rz_config_get_i(core->config, "asm.seggrn");

		a = ((core->offset >> 16) << (16 - seggrn));
		b = (core->offset & 0xffff);
		rz_strbuf_appendf(sb, "%04x:%04x", a, b);
	} else {
		if (core->print->wide_offsets && core->dbg->bits & RZ_SYS_BITS_64) {
			rz_strbuf_appendf(sb, "0x%016" PFMT64x, core->offset);
		} else {
			rz_strbuf_appendf(sb, "0x%08" PFMT64x, core->offset);
		}
	}
	return true;
}

static void set_prompt(RzCore *r) {
	RzLine *line = r->cons->line;
	const char *cmdprompt = rz_config_get(r->config, "cmd.prompt");
	const char *BEGIN = "";
	const char *END = "";
	const char *remote = "";

	if (cmdprompt && *cmdprompt) {
		rz_core_cmd(r, cmdprompt, 0);
	}

	if (r->cmdremote) {
		char *s = rz_core_cmd_str(r, "s");
		r->offset = rz_num_math(NULL, s);
		free(s);
		remote = "R!";
	}

	if (rz_config_get_i(r->config, "scr.color")) {
		BEGIN = r->cons->context->pal.prompt;
		END = r->cons->context->pal.reset;
	}

	RzStrBuf prompt_ct;
	rz_strbuf_init(&prompt_ct);
	rz_strbuf_appendf(&prompt_ct, "%s[%s", BEGIN, remote);
	bool added = prompt_add_file(r, &prompt_ct, false);
	added = prompt_add_section(r, &prompt_ct, added);
	added = prompt_add_offset(r, &prompt_ct, added);
	rz_strbuf_appendf(&prompt_ct, "]>%s ", END);

	char *prompt = rz_strbuf_drain_nofree(&prompt_ct);
	rz_line_set_prompt(line, prompt);
	free(prompt);
}

RZ_API int rz_core_prompt(RzCore *r, int sync) {
	char line[4096];

	int rnv = r->num->value;
	set_prompt(r);
	int ret = rz_cons_fgets(line, sizeof(line), 0, NULL);
	if (ret == -2) {
		return RZ_CORE_CMD_EXIT; // ^D
	}
	if (ret == -1) {
		return false; // FD READ ERROR
	}
	r->num->value = rnv;
	if (sync) {
		return rz_core_prompt_exec(r);
	}
	free(r->cmdqueue);
	r->cmdqueue = strdup(line);
	if (r->scr_gadgets && *line && *line != 'q') {
		rz_core_gadget_print(r);
	}
	r->num->value = r->rc;
	return true;
}

RZ_API int rz_core_prompt_exec(RzCore *r) {
	int ret = rz_core_cmd(r, r->cmdqueue, true);
	r->rc = r->num->value;
	// int ret = rz_core_cmd (r, r->cmdqueue, true);
	rz_cons_echo(NULL);
	rz_cons_flush();
	if (r->cons && r->cons->line && r->cons->line->zerosep) {
		rz_cons_zero();
	}
	return ret;
}

RZ_API bool rz_core_block_size(RzCore *core, ut32 bsize) {
	ut8 *bump;
	if (bsize == core->blocksize) {
		return true;
	} else if (bsize < 1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize > core->blocksize_max) {
		RZ_LOG_ERROR("block size is bigger than its max 0x%x (check `bm` command)\n", core->blocksize_max);
		return false;
	}
	bump = realloc(core->block, bsize + 1);
	if (!bump) {
		RZ_LOG_ERROR("Oops. cannot allocate that much (%u)\n", bsize);
		return false;
	}
	core->block = bump;
	core->blocksize = bsize;
	memset(core->block, 0xff, core->blocksize);
	rz_core_seek(core, core->offset, true);
	return true;
}

RZ_API char *rz_core_op_str(RzCore *core, ut64 addr) {
	RzAsmOp op = { 0 };
	ut8 buf[64];
	rz_asm_set_pc(core->rasm, addr);
	rz_io_read_at(core->io, addr, buf, sizeof(buf));
	int ret = rz_asm_disassemble(core->rasm, &op, buf, sizeof(buf));
	char *str = (ret > 0) ? strdup(rz_strbuf_get(&op.buf_asm)) : NULL;
	rz_asm_op_fini(&op);
	return str;
}

RZ_API RzAnalysisOp *rz_core_op_analysis(RzCore *core, ut64 addr, RzAnalysisOpMask mask) {
	ut8 buf[64];
	RzAnalysisOp *op = rz_analysis_op_new();
	rz_io_read_at(core->io, addr, buf, sizeof(buf));
	rz_analysis_op(core->analysis, op, addr, buf, sizeof(buf), mask);
	return op;
}

typedef struct {
	RzSocket *fd;
	RzSocket *client;
	bool listener;
} RzIORap;

static void rap_break(void *u) {
	RzIORap *rior = (RzIORap *)u;
	if (u) {
		rz_socket_close(rior->fd);
		rior->fd = NULL;
	}
}

// TODO: PLEASE move into core/io/rap? */
// TODO: use static buffer instead of mallocs all the time. it's network!
RZ_API bool rz_core_serve(RzCore *core, RzIODesc *file) {
	// TODO: use rz_socket_rap_server API instead of duplicating the logic
	ut8 cmd, flg, *ptr = NULL, buf[1024];
	int i, pipefd = -1;
	ut64 x;

	RzIORap *rior = (RzIORap *)file->data;
	if (!rior || !rior->fd) {
		RZ_LOG_ERROR("core: rap: cannot listen.\n");
		return false;
	}
	RzSocket *fd = rior->fd;
	RZ_LOG_WARN("RAP Server started (rap.loop=%s)\n",
		rz_config_get(core->config, "rap.loop"));
	rz_cons_break_push(rap_break, rior);
reaccept:
	while (!rz_cons_is_breaked()) {
		RzSocket *c = rz_socket_accept(fd);
		if (!c) {
			break;
		}
		if (rz_cons_is_breaked()) {
			goto out_of_function;
		}
		if (!c) {
			RZ_LOG_ERROR("core: rap: cannot accept\n");
			rz_socket_free(c);
			goto out_of_function;
		}
		RZ_LOG_INFO("core: rap: client connected\n");
		for (; !rz_cons_is_breaked();) {
			if (!rz_socket_read_block(c, &cmd, 1)) {
				RZ_LOG_ERROR("core: rap: connection closed\n");
				if (rz_config_get_i(core->config, "rap.loop")) {
					RZ_LOG_INFO("core: rap: waiting for new connection\n");
					rz_socket_free(c);
					goto reaccept;
				}
				goto out_of_function;
			}
			switch (cmd) {
			case RAP_PACKET_OPEN:
				rz_socket_read_block(c, &flg, 1); // flags
				RZ_LOG_DEBUG("open (%d): \n", cmd);
				rz_socket_read_block(c, &cmd, 1); // len
				pipefd = -1;
				if (UT8_ADD_OVFCHK(cmd, 1)) {
					goto out_of_function;
				}
				ptr = malloc((size_t)cmd + 1);
				if (!ptr) {
					RZ_LOG_ERROR("core: rap: cannot malloc in rmt-open len = %d\n", cmd);
				} else {
					ut64 baddr = rz_config_get_i(core->config, "bin.laddr");
					rz_socket_read_block(c, ptr, cmd);
					ptr[cmd] = 0;
					ut32 perm = RZ_PERM_R;
					if (flg & RZ_PERM_W) {
						perm |= RZ_PERM_W;
					}
					if (rz_core_file_open(core, (const char *)ptr, perm, 0)) {
						int fd = rz_io_fd_get_current(core->io);
						rz_core_bin_load(core, NULL, baddr);
						rz_io_map_add(core->io, fd, perm, 0, 0, rz_io_fd_size(core->io, fd));
						if (core->file) {
							pipefd = fd;
						} else {
							pipefd = -1;
						}
						RZ_LOG_DEBUG("(flags: %d) len: %d filename: '%s'\n",
							flg, cmd, ptr); // config.file);
					} else {
						RZ_LOG_ERROR("core: rap: cannot open file (%s)\n", ptr);
						rz_socket_close(c);
						if (rz_config_get_i(core->config, "rap.loop")) {
							RZ_LOG_INFO("core: rap: waiting for new connection\n");
							rz_socket_free(c);
							goto reaccept;
						}
						goto out_of_function; // XXX: Close connection and goto accept
					}
				}
				buf[0] = RAP_PACKET_OPEN | RAP_PACKET_REPLY;
				rz_write_be32(buf + 1, pipefd);
				rz_socket_write(c, buf, 5);
				rz_socket_flush(c);
				RZ_FREE(ptr);
				break;
			case RAP_PACKET_READ:
				rz_socket_read_block(c, (ut8 *)&buf, 4);
				i = rz_read_be32(buf);
				ptr = (ut8 *)malloc(i + core->blocksize + 5);
				if (ptr) {
					rz_core_block_read(core);
					ptr[0] = RAP_PACKET_READ | RAP_PACKET_REPLY;
					if (i > RAP_PACKET_MAX) {
						i = RAP_PACKET_MAX;
					}
					if (i > core->blocksize) {
						rz_core_block_size(core, i);
					}
					if (i + 128 < core->blocksize) {
						rz_core_block_size(core, i);
					}
					rz_write_be32(ptr + 1, i);
					memcpy(ptr + 5, core->block, i); // core->blocksize);
					rz_socket_write(c, ptr, i + 5);
					rz_socket_flush(c);
					RZ_FREE(ptr);
				} else {
					RZ_LOG_ERROR("core: rap: cannot read %d byte(s)\n", i);
					rz_socket_free(c);
					// TODO: reply error here
					goto out_of_function;
				}
				break;
			case RAP_PACKET_CMD: {
				char *cmd = NULL, *cmd_output = NULL;
				char bufr[8], *bufw = NULL;
				ut32 cmd_len = 0;
				int i;

				/* read */
				rz_socket_read_block(c, (ut8 *)&bufr, 4);
				i = rz_read_be32(bufr);
				if (i > 0 && i < RAP_PACKET_MAX) {
					if ((cmd = malloc(i + 1))) {
						rz_socket_read_block(c, (ut8 *)cmd, i);
						cmd[i] = '\0';
						int scr_interactive = rz_config_get_i(core->config, "scr.interactive");
						rz_config_set_i(core->config, "scr.interactive", 0);
						cmd_output = rz_core_cmd_str(core, cmd);
						rz_config_set_i(core->config, "scr.interactive", scr_interactive);
						free(cmd);
					} else {
						RZ_LOG_ERROR("core: rap: cannot allocate %u bytes\n", (i + 1));
					}
				} else {
					RZ_LOG_ERROR("core: rap: invalid length '%u'\n", i);
				}
				/* write */
				if (cmd_output) {
					cmd_len = strlen(cmd_output) + 1;
				} else {
					cmd_output = strdup("");
					cmd_len = 0;
				}
				bufw = malloc(cmd_len + 5);
				bufw[0] = (ut8)(RAP_PACKET_CMD | RAP_PACKET_REPLY);
				rz_write_be32(bufw + 1, cmd_len);
				memcpy(bufw + 5, cmd_output, cmd_len);
				rz_socket_write(c, bufw, cmd_len + 5);
				rz_socket_flush(c);
				free(bufw);
				free(cmd_output);
				break;
			}
			case RAP_PACKET_WRITE:
				rz_socket_read_block(c, buf, 4);
				x = rz_read_at_be32(buf, 0);
				ptr = malloc(x);
				rz_socket_read_block(c, ptr, x);
				int ret = rz_core_write_at(core, core->offset, ptr, x);
				buf[0] = RAP_PACKET_WRITE | RAP_PACKET_REPLY;
				rz_write_be32(buf + 1, ret);
				rz_socket_write(c, buf, 5);
				rz_socket_flush(c);
				RZ_FREE(ptr);
				break;
			case RAP_PACKET_SEEK:
				rz_socket_read_block(c, buf, 9);
				x = rz_read_at_be64(buf, 1);
				if (buf[0] == 2) {
					if (core->file) {
						x = rz_io_fd_size(core->io, core->file->fd);
					} else {
						x = 0;
					}
				} else {
					if (buf[0] == 0) {
						rz_core_seek(core, x, true); // buf[0]);
					}
					x = core->offset;
				}
				buf[0] = RAP_PACKET_SEEK | RAP_PACKET_REPLY;
				rz_write_be64(buf + 1, x);
				rz_socket_write(c, buf, 9);
				rz_socket_flush(c);
				break;
			case RAP_PACKET_CLOSE:
				// XXX : proper shutdown
				rz_socket_read_block(c, buf, 4);
				i = rz_read_be32(buf);
				{
					// FIXME: Use rz_socket_close
					int ret = close(i);
					rz_write_be32(buf + 1, ret);
					buf[0] = RAP_PACKET_CLOSE | RAP_PACKET_REPLY;
					rz_socket_write(c, buf, 5);
					rz_socket_flush(c);
				}
				break;
			default:
				if (cmd == 'G') {
					// silly http emulation over rap://
					char line[256] = { 0 };
					rz_socket_read_block(c, (ut8 *)line, sizeof(line));
					if (!strncmp(line, "ET /cmd/", 8)) {
						char *cmd = line + 8;
						char *http = strstr(cmd, "HTTP");
						if (http) {
							*http = 0;
							http--;
							if (*http == ' ') {
								*http = 0;
							}
						}
						rz_str_uri_decode(cmd);
						char *res = rz_core_cmd_str(core, cmd);
						if (res) {
							rz_socket_printf(c, "HTTP/1.0 %d %s\r\n%s"
									    "Connection: close\r\nContent-Length: %d\r\n\r\n",
								200, "OK", "", -1); // strlen (res));
							rz_socket_write(c, res, strlen(res));
							free(res);
						}
						rz_socket_flush(c);
						rz_socket_close(c);
					}
				} else {
					RZ_LOG_ERROR("core: rap: unknown command 0x%02x\n", cmd);
					rz_socket_close(c);
					RZ_FREE(ptr);
				}
				if (rz_config_get_i(core->config, "rap.loop")) {
					RZ_LOG_INFO("core: rap: waiting for new connection\n");
					rz_socket_free(c);
					goto reaccept;
				}
				goto out_of_function;
			}
		}
		RZ_LOG_INFO("core: rap: client disconnected\n");
		rz_socket_free(c);
	}
out_of_function:
	rz_cons_break_pop();
	return false;
}

RZ_API int rz_core_search_cb(RzCore *core, ut64 from, ut64 to, RzCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf = malloc(len);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate blocksize\n");
		return false;
	}
	while (from < to) {
		ut64 delta = to - from;
		if (delta < len) {
			len = (int)delta;
		}
		if (!rz_io_read_at(core->io, from, buf, len)) {
			RZ_LOG_ERROR("core: cannot read at 0x%" PFMT64x "\n", from);
			break;
		}
		for (ret = 0; ret < len;) {
			int done = cb(core, from, buf + ret, len - ret);
			if (done < 1) { /* interrupted */
				free(buf);
				return false;
			}
			ret += done;
		}
		from += len;
	}
	free(buf);
	return true;
}

RZ_API RZ_OWN char *rz_core_editor(const RzCore *core, RZ_NULLABLE const char *file, RZ_NULLABLE const char *str) {
	const bool interactive = rz_cons_is_interactive();
	if (!interactive) {
		return NULL;
	}

	const char *editor = rz_config_get(core->config, "cfg.editor");
	if (RZ_STR_ISEMPTY(editor)) {
		RZ_LOG_ERROR("core: please set \"cfg.editor\" to run the editor\n");
		return NULL;
	}
	char *name = NULL, *ret = NULL;
	int fd;

	bool readonly = false;
	if (file && *file != '*') {
		name = strdup(file);
		fd = rz_sys_open(file, O_RDWR, 0644);
		if (fd == -1) {
			fd = rz_sys_open(file, O_RDWR | O_CREAT, 0644);
			if (fd == -1) {
				fd = rz_sys_open(file, O_RDONLY, 0644);
				readonly = true;
			}
		}
	} else {
		fd = rz_file_mkstemp(file, &name);
	}
	if (fd == -1) {
		free(name);
		return NULL;
	}
	if (readonly) {
		RZ_LOG_WARN("core: opening in read-only\n");
	} else {
		if (str) {
			const size_t str_len = strlen(str);
			if (write(fd, str, str_len) != str_len) {
				close(fd);
				free(name);
				return NULL;
			}
		}
	}
	close(fd);

	if (name) {
		char *escaped_name = rz_str_escape_sh(name);
		rz_sys_cmdf("%s \"%s\"", editor, escaped_name);
		free(escaped_name);
	}
	size_t len = 0;
	ret = name ? rz_file_slurp(name, &len) : 0;
	if (ret) {
		if (len && ret[len - 1] == '\n') {
			ret[len - 1] = 0; // chop
		}
		if (!file) {
			rz_file_rm(name);
		}
	}
	free(name);
	return ret;
}

/* weak getters */
RZ_API RzCons *rz_core_get_cons(RzCore *core) {
	return core->cons;
}

RZ_API RzConfig *rz_core_get_config(RzCore *core) {
	return core->config;
}

RZ_API RzBin *rz_core_get_bin(RzCore *core) {
	return core->bin;
}

RZ_API RzBuffer *rz_core_syscallf(RzCore *core, const char *name, const char *fmt, ...) {
	char str[1024];
	RzBuffer *buf;
	va_list ap;
	va_start(ap, fmt);

	vsnprintf(str, sizeof(str), fmt, ap);
	buf = rz_core_syscall(core, name, str);

	va_end(ap);
	return buf;
}

RZ_API RzBuffer *rz_core_syscall(RzCore *core, const char *name, const char *args) {
	char code[1024];
	int num;

	// arch check
	if (strcmp(core->analysis->cur->arch, "x86")) {
		RZ_LOG_ERROR("architecture '%s' is not yet supported!\n", core->analysis->cur->arch);
		return 0;
	}

	num = rz_syscall_get_num(core->analysis->syscall, name);

	// bits check
	switch (core->rasm->bits) {
	case 32:
		if (strcmp(name, "setup") && !num) {
			RZ_LOG_ERROR("core: syscall not found!\n");
			return 0;
		}
		break;
	case 64:
		if (strcmp(name, "read") && !num) {
			RZ_LOG_ERROR("core: syscall not found!\n");
			return 0;
		}
		break;
	default:
		RZ_LOG_ERROR("core: syscall not found!\n");
		return 0;
	}

	snprintf(code, sizeof(code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%s);\n"
		":int3\n" /// XXX USE trap
		"}\n",
		num, args);
	rz_egg_reset(core->egg);
	// TODO: setup arch/bits/os?
	rz_egg_load(core->egg, code, 0);

	if (!rz_egg_compile(core->egg)) {
		RZ_LOG_ERROR("core: cannot compile.\n");
	}
	if (!rz_egg_assemble(core->egg)) {
		RZ_LOG_ERROR("core: rz_egg_assemble: invalid assembly\n");
	}
	return rz_egg_get_bin(core->egg);
}

RZ_API RzTable *rz_core_table(RzCore *core) {
	RzTable *table = rz_table_new();
	if (table) {
		table->cons = core->cons;
	}
	return table;
}

RZ_API RzCmdStatus rz_core_core_plugin_print(RzCorePlugin *cp, RzCmdStateOutput *state, const char *license) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		pj_o(pj);
		pj_ks(pj, "name", cp->name);
		pj_ks(pj, "description", cp->desc);
		pj_ks(pj, "author", cp->author);
		pj_ks(pj, "version", cp->version);
		pj_ks(pj, "license", license);
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		rz_cons_printf("%s: %s (Made by %s, v%s, %s)\n",
			cp->name, cp->desc, cp->author, cp->version, license);
		break;
	}
	default: {
		rz_warn_if_reached();
		return RZ_CMD_STATUS_NONEXISTINGCMD;
	}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_API RzCmdStatus rz_core_core_plugins_print(RzCore *core, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzCorePlugin *cp;
	RzCmdStatus status;
	if (!core) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (core->plugins, iter, cp) {
		const char *license = cp->license
			? cp->license
			: "???";
		status = rz_core_core_plugin_print(cp, state, license);
		if (status != RZ_CMD_STATUS_OK) {
			return status;
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}
