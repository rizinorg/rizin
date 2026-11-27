// SPDX-FileCopyrightText: 2011-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2021 Oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* Universal calling convention implementation based on sdb */

#include "analysis_private.h"

#define DB analysis->sdb_cc

#define cc_sdb_unsetf(x, ...) \
	do { \
		char key[512]; \
		rz_strf(key, __VA_ARGS__); \
		sdb_unset(x, key); \
	} while (0)

#define cc_sdb_setf(x, y, ...) \
	do { \
		char key[512]; \
		rz_strf(key, __VA_ARGS__); \
		sdb_set(x, key, y); \
	} while (0)

/**
 * \brief Look up a calling-convention SDB property for \p cc and \p suffix.
 *
 * Uses a stack buffer for typical key lengths and falls back to heap allocation
 * for long convention or suffix names.
 *
 * \param db Calling-convention SDB instance
 * \param cc Calling-convention name
 * \param suffix Property suffix (e.g. `ret`, `argn`, `self`, `error`, `maxargs`)
 * \return Const SDB value string, or NULL if not found
 */
static const char *cc_sdb_get(Sdb *db, const char *cc, const char *suffix) {
	size_t clen = strlen(cc);
	size_t slen = strlen(suffix);
	char buf[256];
	if (3 + clen + 1 + slen + 1 <= sizeof(buf)) {
		char *p = buf;
		memcpy(p, "cc.", 3);
		p += 3;
		memcpy(p, cc, clen);
		p += clen;
		*p++ = '.';
		memcpy(p, suffix, slen + 1);
		return sdb_const_get(db, buf);
	}
	char *query = rz_str_newf("cc.%s.%s", cc, suffix);
	const char *ret = query ? sdb_const_get(db, query) : NULL;
	free(query);
	return ret;
}

/**
 * \brief Look up argument \p n of calling convention \p cc in SDB.
 *
 * Uses a stack buffer with a single-digit fast path for `0 <= n < 10` and falls back
 * to heap allocation for long convention names.
 *
 * \param db Calling-convention SDB instance
 * \param cc Calling-convention name
 * \param n Zero-based argument index
 * \return Const SDB value string, or NULL if not found
 */
static const char *cc_sdb_get_arg(Sdb *db, const char *cc, int n) {
	size_t clen = strlen(cc);
	char buf[256];
	if (3 + clen + 4 + 12 + 1 <= sizeof(buf)) {
		char *p = buf;
		memcpy(p, "cc.", 3);
		p += 3;
		memcpy(p, cc, clen);
		p += clen;
		memcpy(p, ".arg", 4);
		p += 4;
		if (n >= 0 && n < 10) {
			*p++ = (char)('0' + n);
			*p = '\0';
		} else {
			snprintf(p, sizeof(buf) - (size_t)(p - buf), "%d", n);
		}
		return sdb_const_get(db, buf);
	}
	char *query = rz_str_newf("cc.%s.arg%d", cc, n);
	const char *ret = query ? sdb_const_get(db, query) : NULL;
	free(query);
	return ret;
}

RZ_API void rz_analysis_cc_del(RzAnalysis *analysis, const char *name) {
	rz_return_if_fail(analysis && name);
	sdb_unset(DB, name);
	cc_sdb_unsetf(DB, "cc.%s.ret", name);
	cc_sdb_unsetf(DB, "cc.%s.maxargs", name);
	cc_sdb_unsetf(DB, "cc.%s.argn", name);
	for (int i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		cc_sdb_unsetf(DB, "cc.%s.arg%d", name, i);
	}
	cc_sdb_unsetf(DB, "cc.%s.self", name);
	cc_sdb_unsetf(DB, "cc.%s.error", name);
}

/**
 * \brief Define a calling convention from a return register, name and argument list.
 *
 * The expression has the form "ret name(arg0, arg1, stack)". The optional stack
 * entry is a fallback for arguments without a register; an empty list has none.
 */
RZ_API bool rz_analysis_cc_set(RzAnalysis *analysis, const char *expr) {
	rz_return_val_if_fail(analysis && expr, false);
	char *e = rz_str_dup(expr);
	char *p = strchr(e, '(');
	if (!p) {
		free(e);
		return false;
	}
	*p++ = 0;
	char *args = rz_str_dup(p);
	rz_str_trim(p);
	char *end = strchr(args, ')');
	if (!end) {
		free(args);
		free(e);
		return false;
	}
	*end++ = 0;
	rz_str_trim(args);
	rz_str_trim(e);
	char *ccname = strchr(e, ' ');
	if (ccname) {
		*ccname++ = 0;
		rz_str_trim(ccname);
	} else {
		free(args);
		free(e);
		return false;
	}
	sdb_set(DB, ccname, "cc");
	cc_sdb_setf(DB, e, "cc.%s.ret", ccname);

	RzList *ccArgs = RZ_STR_ISEMPTY(args) ? NULL : rz_str_split_list(args, ",", 0);
	RzListIter *iter;
	const char *arg;
	int n = 0;
	rz_list_foreach (ccArgs, iter, arg) {
		if (!strcmp(arg, "stack")) {
			cc_sdb_setf(DB, arg, "cc.%s.argn", ccname);
		} else {
			cc_sdb_setf(DB, arg, "cc.%s.arg%d", ccname, n);
			n++;
		}
	}
	if (n > rz_analysis_cc_max_arg(analysis, ccname)) {
		char maxargs[256];
		rz_strf(maxargs, "%d", n);
		cc_sdb_setf(DB, maxargs, "cc.%s.maxargs", ccname);
	}
	rz_list_free(ccArgs);
	free(e);
	free(args);
	return true;
}

RZ_API char *rz_analysis_cc_get(RzAnalysis *analysis, const char *name) {
	rz_return_val_if_fail(analysis && name, NULL);
	// get cc by name and print the expr
	if (rz_str_cmp(sdb_const_get(DB, name), "cc", -1)) {
		RZ_LOG_ERROR("analysis: '%s' is not a valid calling convention name\n", name);
		return NULL;
	}
	const char *ret = cc_sdb_get(DB, name, "ret");
	if (!ret) {
		RZ_LOG_ERROR("analysis: Cannot find return key in calling convention named '%s'\n", name);
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	const char *self = rz_analysis_cc_self(analysis, name);
	rz_strbuf_appendf(sb, "%s %s%s%s (", ret, self ? self : "", self ? "." : "", name);
	bool isFirst = true;
	for (int i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		const char *arg = cc_sdb_get_arg(DB, name, i);
		if (!arg) {
			break;
		}
		rz_strbuf_appendf(sb, "%s%s", isFirst ? "" : ", ", arg);
		isFirst = false;
	}
	const char *argn = cc_sdb_get(DB, name, "argn");
	if (argn) {
		rz_strbuf_appendf(sb, "%s%s", isFirst ? "" : ", ", argn);
	}
	rz_strbuf_append(sb, ")");

	const char *error = rz_analysis_cc_error(analysis, name);
	if (error) {
		rz_strbuf_appendf(sb, " %s", error);
	}

	rz_strbuf_append(sb, ";");
	return rz_strbuf_drain(sb);
}

RZ_API bool rz_analysis_cc_exist(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, false);
	const char *x = sdb_const_get(DB, convention);
	return x && *x && !strcmp(x, "cc");
}

RZ_API const char *rz_analysis_cc_arg(RzAnalysis *analysis, const char *convention, int n) {
	rz_return_val_if_fail(analysis, NULL);
	rz_return_val_if_fail(n >= 0, NULL);
	if (!convention) {
		return NULL;
	}

	const char *ret = cc_sdb_get_arg(DB, convention, n);
	if (!ret) {
		ret = cc_sdb_get(DB, convention, "argn");
	}
	return ret ? rz_str_constpool_get(&analysis->constpool, ret) : NULL;
}

RZ_API const char *rz_analysis_cc_self(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	const char *self = cc_sdb_get(DB, convention, "self");
	return self ? rz_str_constpool_get(&analysis->constpool, self) : NULL;
}

RZ_API void rz_analysis_cc_set_self(RzAnalysis *analysis, const char *convention, const char *self) {
	rz_return_if_fail(analysis && convention && self);
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	cc_sdb_setf(analysis->sdb_cc, self, "cc.%s.self", convention);
}

RZ_API const char *rz_analysis_cc_error(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	const char *error = cc_sdb_get(DB, convention, "error");
	return error ? rz_str_constpool_get(&analysis->constpool, error) : NULL;
}

RZ_API void rz_analysis_cc_set_error(RzAnalysis *analysis, const char *convention, const char *error) {
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	cc_sdb_setf(analysis->sdb_cc, error, "cc.%s.error", convention);
}

RZ_API int rz_analysis_cc_max_arg(RzAnalysis *analysis, const char *cc) {
	rz_return_val_if_fail(analysis && DB && cc, 0);
	const char *res = cc_sdb_get(DB, cc, "maxargs");
	int maxargs = res ? atoi(res) : 0;
	if (maxargs < 0 || maxargs > RZ_ANALYSIS_CC_MAXARG) {
		return 0;
	}
	return maxargs;
}

RZ_API const char *rz_analysis_cc_ret(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	return cc_sdb_get(DB, convention, "ret");
}

/**
 * Get the size of the shadow space, i.e. a pre-allocated space before the callee's stack frame,
 * which can usually be used by the callee to save argument registers.
 */
RZ_API RzStackAddr rz_analysis_cc_shadow_store(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, 0);
	if (!strcmp(convention, "ms")) {
		// Microsoft x64 cc has an additional "shadow space" above the stack frame.
		// TODO: this should be specified in the definition of the "ms" cc instead of beging hardcoded here.
		return 0x28;
	}
	return 0;
}

RZ_API const char *rz_analysis_cc_default(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	return sdb_const_get(DB, "default.cc");
}

RZ_API void rz_analysis_set_cc_default(RzAnalysis *analysis, const char *cc) {
	rz_return_if_fail(analysis && cc);
	sdb_set(DB, "default.cc", cc);
}

RZ_API const char *rz_analysis_syscc_default(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	return sdb_const_get(DB, "default.syscc");
}

RZ_API void rz_analysis_set_syscc_default(RzAnalysis *analysis, const char *cc) {
	rz_return_if_fail(analysis && cc);
	sdb_set(DB, "default.syscc", cc);
}

RZ_API const char *rz_analysis_cc_func(RzAnalysis *analysis, const char *func_name) {
	rz_return_val_if_fail(analysis && func_name, NULL);
	const char *cc = rz_type_func_cc(analysis->typedb, func_name);
	return cc ? cc : rz_analysis_cc_default(analysis);
}

static bool filter_cc(void *user, const SdbKv *kv) {
	return sdbkv_value_len(kv) == 2 && !strcmp(sdbkv_value(kv), "cc");
}

RZ_API RzList /*<char *>*/ *rz_analysis_calling_conventions(RzAnalysis *analysis) {
	RzList *ccl = rz_list_newf(free);
	void **iter;
	RzPVector *items = sdb_get_items_filter(analysis->sdb_cc, filter_cc, NULL, true);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		rz_list_append(ccl, rz_str_dup(sdbkv_key(kv)));
	}
	rz_pvector_free(items);
	return ccl;
}
