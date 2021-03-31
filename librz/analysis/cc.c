// SPDX-FileCopyrightText: 2011-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2021 Oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* Universal calling convention implementation based on sdb */

#include <rz_analysis.h>
#define DB analysis->sdb_cc

RZ_API void rz_analysis_cc_del(RzAnalysis *analysis, const char *name) {
	rz_return_if_fail(analysis && name);
	size_t i;
	RzStrBuf sb;
	sdb_unset(DB, rz_strbuf_initf(&sb, "%s", name), 0);
	sdb_unset(DB, rz_strbuf_setf(&sb, "cc.%s.ret", name), 0);
	sdb_unset(DB, rz_strbuf_setf(&sb, "cc.%s.argn", name), 0);
	for (i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		sdb_unset(DB, rz_strbuf_setf(&sb, "cc.%s.arg%zu", name, i), 0);
	}
	sdb_unset(DB, rz_strbuf_setf(&sb, "cc.%s.self", name), 0);
	sdb_unset(DB, rz_strbuf_setf(&sb, "cc.%s.error", name), 0);
	rz_strbuf_fini(&sb);
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
	sdb_set(DB, sdb_fmt("cc.%s.ret", ccname), e, 0);

	RzList *ccArgs = rz_str_split_list(args, ",", 0);
	RzListIter *iter;
	const char *arg;
	int n = 0;
	rz_list_foreach (ccArgs, iter, arg) {
		if (!strcmp(arg, "stack")) {
			sdb_set(DB, sdb_fmt("cc.%s.argn", ccname), arg, 0);
		} else {
			sdb_set(DB, sdb_fmt("cc.%s.arg%d", ccname, n), arg, 0);
			n++;
		}
	}
	rz_list_free(ccArgs);
	free(e);
	free(args);
	return true;
}

RZ_API char *rz_analysis_cc_get(RzAnalysis *analysis, const char *name) {
	rz_return_val_if_fail(analysis && name, NULL);
	int i;
	// get cc by name and print the expr
	if (rz_str_cmp(sdb_const_get(DB, name, 0), "cc", -1)) {
		eprintf("This is not a valid calling convention name\n");
		return NULL;
	}
	const char *ret = sdb_const_get(DB, sdb_fmt("cc.%s.ret", name), 0);
	if (!ret) {
		eprintf("Cannot find return key\n");
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	const char *self = rz_analysis_cc_self(analysis, name);
	rz_strbuf_appendf(sb, "%s %s%s%s (", ret, self ? self : "", self ? "." : "", name);
	bool isFirst = true;
	for (i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		const char *k = sdb_fmt("cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get(DB, k, 0);
		if (!arg) {
			break;
		}
		rz_strbuf_appendf(sb, "%s%s", isFirst ? "" : ", ", arg);
		isFirst = false;
	}
	const char *argn = sdb_const_get(DB, sdb_fmt("cc.%s.argn", name), 0);
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

	const char *query = sdb_fmt("cc.%s.arg%d", convention, n);
	const char *ret = sdb_const_get(DB, query, 0);
	if (!ret) {
		query = sdb_fmt("cc.%s.argn", convention);
		ret = sdb_const_get(DB, query, 0);
	}
	return ret ? rz_str_constpool_get(&analysis->constpool, ret) : NULL;
}

RZ_API const char *rz_analysis_cc_self(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	const char *query = sdb_fmt("cc.%s.self", convention);
	const char *self = sdb_const_get(DB, query, 0);
	return self ? rz_str_constpool_get(&analysis->constpool, self) : NULL;
}

RZ_API void rz_analysis_cc_set_self(RzAnalysis *analysis, const char *convention, const char *self) {
	rz_return_if_fail(analysis && convention && self);
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	RzStrBuf sb;
	sdb_set(analysis->sdb_cc, rz_strbuf_initf(&sb, "cc.%s.self", convention), self, 0);
	rz_strbuf_fini(&sb);
}

RZ_API const char *rz_analysis_cc_error(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	const char *query = sdb_fmt("cc.%s.error", convention);
	const char *error = sdb_const_get(DB, query, 0);
	return error ? rz_str_constpool_get(&analysis->constpool, error) : NULL;
}

RZ_API void rz_analysis_cc_set_error(RzAnalysis *analysis, const char *convention, const char *error) {
	if (!rz_analysis_cc_exist(analysis, convention)) {
		return;
	}
	RzStrBuf sb;
	sdb_set(analysis->sdb_cc, rz_strbuf_initf(&sb, "cc.%s.error", convention), error, 0);
	rz_strbuf_fini(&sb);
}

RZ_API int rz_analysis_cc_max_arg(RzAnalysis *analysis, const char *cc) {
	int i = 0;
	rz_return_val_if_fail(analysis && DB && cc, 0);
	static void *oldDB = NULL;
	static char *oldCC = NULL;
	static int oldArg = 0;
	if (oldDB == DB && !strcmp(cc, oldCC)) {
		return oldArg;
	}
	oldDB = DB;
	free(oldCC);
	oldCC = strdup(cc);
	for (i = 0; i < RZ_ANALYSIS_CC_MAXARG; i++) {
		const char *query = sdb_fmt("cc.%s.arg%d", cc, i);
		const char *res = sdb_const_get(DB, query, 0);
		if (!res) {
			break;
		}
	}
	oldArg = i;
	return i;
}

RZ_API const char *rz_analysis_cc_ret(RzAnalysis *analysis, const char *convention) {
	rz_return_val_if_fail(analysis && convention, NULL);
	char *query = sdb_fmt("cc.%s.ret", convention);
	return sdb_const_get(DB, query, 0);
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
	const char *query = sdb_fmt("func.%s.cc", func_name);
	const char *cc = sdb_const_get(analysis->sdb_types, query, 0);
	return cc ? cc : rz_analysis_cc_default(analysis);
}
