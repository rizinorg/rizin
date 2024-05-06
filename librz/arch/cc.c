// SPDX-FileCopyrightText: 2011-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2021 Oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* Universal calling convention implementation based on sdb */

#include <rz_analysis.h>
#define DB analysis->sdb_cc

#define cc_sdb_unsetf(x, ...) \
	do { \
		char key[512]; \
		rz_strf(key, __VA_ARGS__); \
		sdb_unset(x, key, 0); \
	} while (0)

#define cc_sdb_setf(x, y, ...) \
	do { \
		char key[512]; \
		rz_strf(key, __VA_ARGS__); \
		sdb_set(x, key, y, 0); \
	} while (0)

RZ_API void rz_analysis_cc_del(RzAnalysis *analysis, const char *name) {
	rz_return_if_fail(analysis && name);
	sdb_unset(DB, name, 0);
	cc_sdb_unsetf(DB, "cc.%s.ret", name);
	cc_sdb_unsetf(DB, "cc.%s.maxargs", name);
	cc_sdb_unsetf(DB, "cc.%s.argn", name);
	for (int i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		cc_sdb_unsetf(DB, "cc.%s.arg%d", name, i);
	}
	cc_sdb_unsetf(DB, "cc.%s.self", name);
	cc_sdb_unsetf(DB, "cc.%s.error", name);
}

RZ_API bool rz_analysis_cc_set(RzAnalysis *analysis, const char *expr) {
	rz_return_val_if_fail(analysis && expr, false);
	char *e = strdup(expr);
	char *p = strchr(e, '(');
	if (!p) {
		free(e);
		return false;
	}
	*p++ = 0;
	char *args = strdup(p);
	rz_str_trim(p);
	char *end = strchr(args, ')');
	if (!end) {
		free(args);
		free(e);
		return false;
	}
	*end++ = 0;
	rz_str_trim(p);
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
	sdb_set(DB, ccname, "cc", 0);
	cc_sdb_setf(DB, e, "cc.%s.ret", ccname);

	RzList *ccArgs = rz_str_split_list(args, ",", 0);
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
	char *tmp_cc = NULL;
	// get cc by name and print the expr
	if (rz_str_cmp(sdb_const_get(DB, name, 0), "cc", -1)) {
		RZ_LOG_ERROR("analysis: '%s' is not a valid calling convention name\n", name);
		return NULL;
	}
	tmp_cc = rz_str_newf("cc.%s.ret", name);
	const char *ret = tmp_cc ? sdb_const_get(DB, tmp_cc, 0) : NULL;
	free(tmp_cc);
	if (!ret) {
		RZ_LOG_ERROR("analysis: Cannot find return key in calling convention named '%s'\n", name);
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	const char *self = rz_analysis_cc_self(analysis, name);
	rz_strbuf_appendf(sb, "%s %s%s%s (", ret, self ? self : "", self ? "." : "", name);
	bool isFirst = true;
	for (int i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		char *k = rz_str_newf("cc.%s.arg%d", name, i);
		const char *arg = k ? sdb_const_get(DB, k, 0) : NULL;
		free(k);
		if (!arg) {
			break;
		}
		rz_strbuf_appendf(sb, "%s%s", isFirst ? "" : ", ", arg);
		isFirst = false;
	}
	tmp_cc = rz_str_newf("cc.%s.argn", name);
	const char *argn = tmp_cc ? sdb_const_get(DB, tmp_cc, 0) : NULL;
	free(tmp_cc);
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
	const char *x = sdb_const_get(DB, convention, 0);
	return x && *x && !strcmp(x, "cc");
}

RZ_API const char *rz_analysis_cc_arg(RzAnalysis *analysis, const char *convention, int n) {
	rz_return_val_if_fail(analysis, NULL);
	rz_return_val_if_fail(n >= 0, NULL);
	if (!convention) {
		return NULL;
	}

	char *query = rz_str_newf("cc.%s.arg%d", convention, n);
	const char *ret = query ? sdb_const_get(DB, query, 0) : NULL;
	free(query);
	if (!ret) {
		query = rz_str_newf("cc.%s.argn", convention);
		ret = query ? sdb_const_get(DB, query, 0) : NULL;
		free(query);
	}
	return ret ? rz_str_constpool_get(&analysis->constpool, ret) : NULL;
}

RZ_API const char *rz_analysis_cc_self(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	char *query = rz_str_newf("cc.%s.self", convention);
	const char *self = query ? sdb_const_get(DB, query, 0) : NULL;
	free(query);
	return self ? rz_str_constpool_get(&analysis->constpool, self) : NULL;
}

RZ_API void rz_analysis_cc_set_self(RzAnalysis *analysis, const char *convention, const char *self) {
	rz_return_if_fail(analysis && convention && self);
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	char *query = rz_str_newf("cc.%s.self", convention);
	if (!query) {
		RZ_LOG_ERROR("analysis: Cannot allocate key for sdb_set\n");
		return;
	}
	sdb_set(analysis->sdb_cc, query, self, 0);
	free(query);
}

RZ_API const char *rz_analysis_cc_error(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	char *query = rz_str_newf("cc.%s.error", convention);
	const char *error = query ? sdb_const_get(DB, query, 0) : NULL;
	free(query);
	return error ? rz_str_constpool_get(&analysis->constpool, error) : NULL;
}

RZ_API void rz_analysis_cc_set_error(RzAnalysis *analysis, const char *convention, const char *error) {
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	char *key = rz_str_newf("cc.%s.error", convention);
	if (!key) {
		RZ_LOG_ERROR("analysis: Cannot allocate key for sdb_set\n");
		return;
	}
	sdb_set(analysis->sdb_cc, key, error, 0);
	free(key);
}

RZ_API int rz_analysis_cc_max_arg(RzAnalysis *analysis, const char *cc) {
	rz_return_val_if_fail(analysis && DB && cc, 0);
	char *query = rz_str_newf("cc.%s.maxargs", cc);
	if (!query) {
		return 0;
	}
	const char *res = sdb_const_get(DB, query, 0);
	free(query);
	int maxargs = res ? atoi(res) : 0;
	if (maxargs < 0 || maxargs > RZ_ANALYSIS_CC_MAXARG) {
		return 0;
	}
	return maxargs;
}

RZ_API const char *rz_analysis_cc_ret(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	char *query = rz_str_newf("cc.%s.ret", convention);
	const char *res = query ? sdb_const_get(DB, query, 0) : NULL;
	free(query);
	return res;
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
	return sdb_const_get(DB, "default.cc", 0);
}

RZ_API void rz_analysis_set_cc_default(RzAnalysis *analysis, const char *cc) {
	rz_return_if_fail(analysis && cc);
	sdb_set(DB, "default.cc", cc, 0);
}

RZ_API const char *rz_analysis_syscc_default(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	return sdb_const_get(DB, "default.syscc", 0);
}

RZ_API void rz_analysis_set_syscc_default(RzAnalysis *analysis, const char *cc) {
	rz_return_if_fail(analysis && cc);
	sdb_set(DB, "default.syscc", cc, 0);
}

RZ_API const char *rz_analysis_cc_func(RzAnalysis *analysis, const char *func_name) {
	rz_return_val_if_fail(analysis && func_name, NULL);
	const char *cc = rz_type_func_cc(analysis->typedb, func_name);
	return cc ? cc : rz_analysis_cc_default(analysis);
}

static bool filter_cc(void *user, const char *k, ut32 klen, const char *v, ut32 vlen) {
	return vlen == 2 && !strcmp(v, "cc");
}

RZ_API RzList /*<char *>*/ *rz_analysis_calling_conventions(RzAnalysis *analysis) {
	RzList *ccl = rz_list_new();
	void **iter;
	RzPVector *items = sdb_get_items_filter(analysis->sdb_cc, filter_cc, NULL, true);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		rz_list_append(ccl, strdup(sdbkv_key(kv)));
	}
	rz_pvector_free(items);
	return ccl;
}
