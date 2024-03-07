// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PARSE_H
#define RZ_PARSE_H

#include <rz_types.h>
#include <rz_flag.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_parse_t {
	void *user;
	RzSpace *flagspace;
	RzSpace *notin_flagspace;
	bool pseudo;
	bool subreg; // replace registers with their respective alias/role name (rdi=A0, ...)
	bool subrel; // replace rip relative expressions in instruction
	bool subtail; // replace any immediate relative to current address with .. prefix syntax
	bool localvar_only; // if true use only the local variable name (e.g. [local_10h] instead of [ebp + local10h])
	ut64 subrel_addr;
	int maxflagnamelen;
	int minval;
	char *retleave_asm;
	struct rz_parse_plugin_t *cur;
	// RzAnalysis *analysis; // weak analysis ref XXX do not use. use analb.anal
	RzList /*<RzParsePlugin *>*/ *parsers;
	RZ_OWN char *(*var_expr_for_reg_access)(RzAnalysisFunction *fcn, ut64 addr, const char *reg, st64 reg_addend);
	RzAnalysisBind analb;
	RzFlagGetAtAddr flag_get; // XXX
	RzAnalysisLabelAt label_get;
} RzParse;

typedef struct rz_parse_plugin_t {
	char *name;
	char *desc;
	bool (*init)(RzParse *p, void *user);
	int (*fini)(RzParse *p, void *user);
	bool (*parse)(RzParse *p, const char *data, RzStrBuf *sb);
	bool (*assemble)(RzParse *p, char *data, char *str);
	int (*filter)(RzParse *p, ut64 addr, RzFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*subvar)(RzParse *p, RzAnalysisFunction *f, RzAnalysisOp *op, char *data, char *str, int len);
	int (*replace)(int argc, const char *argv[], char *newstr);
} RzParsePlugin;

#ifdef RZ_API

/* lifecycle */
RZ_API RzParse *rz_parse_new(void);
RZ_API void rz_parse_free(RzParse *p);

/* plugins */
RZ_API void rz_parse_set_user_ptr(RzParse *p, void *user);
RZ_API bool rz_parse_plugin_add(RzParse *p, RZ_NONNULL RzParsePlugin *plugin);
RZ_API bool rz_parse_plugin_del(RzParse *p, RZ_NONNULL RzParsePlugin *plugin);
RZ_API bool rz_parse_use(RzParse *p, const char *name);

/* action */
RZ_API char *rz_parse_pseudocode(RzParse *p, const char *data);
RZ_API bool rz_parse_assemble(RzParse *p, char *data, char *str); // XXX deprecate, unused and probably useless, related to write-hack
RZ_API bool rz_parse_filter(RzParse *p, ut64 addr, RzFlag *f, RzAnalysisHint *hint, char *data, char *str, int len, bool big_endian);
RZ_API bool rz_parse_subvar(RzParse *p, RZ_NULLABLE RzAnalysisFunction *f, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL RZ_IN char *data, RZ_BORROW RZ_NONNULL RZ_OUT char *str, int len);
RZ_API char *rz_parse_immtrim(char *opstr);

#endif

#ifdef __cplusplus
}
#endif

#endif
