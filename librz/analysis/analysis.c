// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_io.h>
#include <config.h>

RZ_LIB_VERSION(rz_analysis);

static RzAnalysisPlugin *analysis_static_plugins[] = {
	RZ_ANALYSIS_STATIC_PLUGINS
};

RZ_API void rz_analysis_set_limits(RzAnalysis *analysis, ut64 from, ut64 to) {
	free(analysis->limit);
	analysis->limit = RZ_NEW0(RzAnalysisRange);
	if (analysis->limit) {
		analysis->limit->from = from;
		analysis->limit->to = to;
	}
}

RZ_API void rz_analysis_unset_limits(RzAnalysis *analysis) {
	RZ_FREE(analysis->limit);
}

static void meta_unset_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, meta_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	rz_meta_space_unset_for(analysis, se->data.unset.space);
}

static void meta_count_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, meta_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	se->res = rz_meta_space_count_for(analysis, se->data.count.space);
}

static void zign_unset_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	rz_sign_space_unset_for(analysis, se->data.unset.space);
}

static void zign_count_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	se->res = rz_sign_space_count_for(analysis, se->data.count.space);
}

static void zign_rename_for(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *s = (RzSpaces *)ev->user;
	RzAnalysis *analysis = container_of(s, RzAnalysis, zign_spaces);
	RzSpaceEvent *se = (RzSpaceEvent *)data;
	rz_sign_space_rename_for(analysis, se->data.rename.space,
		se->data.rename.oldname, se->data.rename.newname);
}

void rz_analysis_hint_storage_init(RzAnalysis *a);
void rz_analysis_hint_storage_fini(RzAnalysis *a);

static void rz_meta_item_fini(RzAnalysisMetaItem *item) {
	free(item->str);
}

static void rz_meta_item_free(void *_item) {
	if (_item) {
		RzAnalysisMetaItem *item = _item;
		rz_meta_item_fini(item);
		free(item);
	}
}

RZ_API RzAnalysis *rz_analysis_new(void) {
	int i;
	RzAnalysis *analysis = RZ_NEW0(RzAnalysis);
	if (!analysis) {
		return NULL;
	}
	if (!rz_str_constpool_init(&analysis->constpool)) {
		free(analysis);
		return NULL;
	}
	analysis->bb_tree = NULL;
	analysis->ht_addr_fun = ht_up_new0();
	analysis->ht_name_fun = ht_pp_new0();
	analysis->os = strdup(RZ_SYS_OS);
	analysis->esil_goto_limit = RZ_ANALYSIS_ESIL_GOTO_LIMIT;
	analysis->opt.nopskip = true; // skip nops in code analysis
	analysis->opt.hpskip = false; // skip `mov reg,reg` and `lea reg,[reg]`
	analysis->gp = 0LL;
	analysis->sdb = sdb_new0();
	analysis->cpp_abi = RZ_ANALYSIS_CPP_ABI_ITANIUM;
	analysis->opt.depth = 32;
	analysis->opt.noncode = false; // do not analyze data by default
	rz_spaces_init(&analysis->meta_spaces, "CS");
	rz_event_hook(analysis->meta_spaces.event, RZ_SPACE_EVENT_UNSET, meta_unset_for, NULL);
	rz_event_hook(analysis->meta_spaces.event, RZ_SPACE_EVENT_COUNT, meta_count_for, NULL);

	rz_spaces_init(&analysis->zign_spaces, "zs");
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_UNSET, zign_unset_for, NULL);
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_COUNT, zign_count_for, NULL);
	rz_event_hook(analysis->zign_spaces.event, RZ_SPACE_EVENT_RENAME, zign_rename_for, NULL);
	rz_analysis_hint_storage_init(analysis);
	rz_interval_tree_init(&analysis->meta, rz_meta_item_free);
	analysis->typedb = rz_type_db_new();
	analysis->type_links = ht_up_new0();
	analysis->sdb_fmts = sdb_ns(analysis->sdb, "spec", 1);
	analysis->sdb_cc = sdb_ns(analysis->sdb, "cc", 1);
	analysis->sdb_zigns = sdb_ns(analysis->sdb, "zigns", 1);
	analysis->sdb_classes = sdb_ns(analysis->sdb, "classes", 1);
	analysis->sdb_classes_attrs = sdb_ns(analysis->sdb_classes, "attrs", 1);
	analysis->sdb_noret = sdb_ns(analysis->sdb, "noreturn", 1);
	analysis->zign_path = strdup("");
	analysis->cb_printf = (PrintfCallback)printf;
	(void)rz_analysis_pin_init(analysis);
	(void)rz_analysis_xrefs_init(analysis);
	analysis->diff_thbb = RZ_ANALYSIS_THRESHOLDBB;
	analysis->diff_thfcn = RZ_ANALYSIS_THRESHOLDFCN;
	analysis->syscall = rz_syscall_new();
	analysis->arch_target = rz_arch_target_new();
	analysis->platform_target = rz_arch_platform_target_new();
	rz_io_bind_init(analysis->iob);
	rz_flag_bind_init(analysis->flb);
	analysis->reg = rz_reg_new();
	analysis->last_disasm_reg = NULL;
	analysis->stackptr = 0;
	analysis->lineswidth = 0;
	analysis->fcns = rz_list_newf(rz_analysis_function_free);
	analysis->leaddrs = NULL;
	analysis->imports = rz_list_newf(free);
	rz_analysis_set_bits(analysis, 32);
	analysis->plugins = rz_list_newf(NULL);
	if (analysis->plugins) {
		for (i = 0; analysis_static_plugins[i]; i++) {
			rz_analysis_add(analysis, analysis_static_plugins[i]);
		}
	}
	return analysis;
}

RZ_API void plugin_fini(RzAnalysis *analysis) {
	RzAnalysisPlugin *p = analysis->cur;
	if (p && p->fini && !p->fini(analysis->plugin_data)) {
		RZ_LOG_ERROR("analysis plugin '%s' failed to terminate.\n", p->name);
	}
	analysis->plugin_data = NULL;
}

void __block_free_rb(RBNode *node, void *user);

RZ_API RzAnalysis *rz_analysis_free(RzAnalysis *a) {
	if (!a) {
		return NULL;
	}

	plugin_fini(a);

	rz_list_free(a->fcns);
	ht_up_free(a->ht_addr_fun);
	ht_pp_free(a->ht_name_fun);
	set_u_free(a->visited);
	rz_analysis_hint_storage_fini(a);
	rz_interval_tree_fini(&a->meta);
	free(a->cpu);
	free(a->os);
	free(a->zign_path);
	rz_list_free(a->plugins);
	rz_rbtree_free(a->bb_tree, __block_free_rb, NULL);
	rz_spaces_fini(&a->meta_spaces);
	rz_spaces_fini(&a->zign_spaces);
	rz_analysis_pin_fini(a);
	rz_syscall_free(a->syscall);
	rz_arch_target_free(a->arch_target);
	rz_arch_platform_target_free(a->platform_target);
	rz_reg_free(a->reg);
	ht_up_free(a->ht_xrefs_from);
	ht_up_free(a->ht_xrefs_to);
	rz_list_free(a->leaddrs);
	rz_type_db_free(a->typedb);
	sdb_free(a->sdb);
	if (a->esil) {
		rz_analysis_esil_free(a->esil);
		a->esil = NULL;
	}
	free(a->last_disasm_reg);
	rz_list_free(a->imports);
	rz_str_constpool_fini(&a->constpool);
	free(a);
	return NULL;
}

RZ_API int rz_analysis_add(RzAnalysis *analysis, RzAnalysisPlugin *p) {
	rz_list_append(analysis->plugins, p);
	return true;
}

RZ_API bool rz_analysis_use(RzAnalysis *analysis, const char *name) {
	RzListIter *it;
	RzAnalysisPlugin *h;

	if (analysis) {
		rz_list_foreach (analysis->plugins, it, h) {
			if (!h || !h->name || strcmp(h->name, name)) {
				continue;
			}
			plugin_fini(analysis);
			analysis->cur = h;
			if (h->init && !h->init(&analysis->plugin_data)) {
				RZ_LOG_ERROR("analysis plugin '%s' failed to initialize.\n", h->name);
				return false;
			}
			rz_analysis_set_reg_profile(analysis);
			return true;
		}
	}
	return false;
}

RZ_API char *rz_analysis_get_reg_profile(RzAnalysis *analysis) {
	return (analysis && analysis->cur && analysis->cur->get_reg_profile)
		? analysis->cur->get_reg_profile(analysis)
		: NULL;
}

// deprecate.. or at least reuse get_reg_profile...
RZ_API bool rz_analysis_set_reg_profile(RzAnalysis *analysis) {
	bool ret = false;
	if (analysis && analysis->cur && analysis->cur->set_reg_profile) {
		ret = analysis->cur->set_reg_profile(analysis);
	} else {
		char *p = rz_analysis_get_reg_profile(analysis);
		if (p && *p) {
			rz_reg_set_profile_string(analysis->reg, p);
			ret = true;
		}
		free(p);
	}
	return ret;
}

static bool analysis_set_os(RzAnalysis *analysis, const char *os) {
	rz_return_val_if_fail(analysis, false);
	if (!os || !*os) {
		os = RZ_SYS_OS;
	}
	free(analysis->os);
	analysis->os = strdup(os);
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_set_os(analysis->typedb, os);
	rz_type_db_reload(analysis->typedb, dir_prefix);
	return true;
}

RZ_API bool rz_analysis_set_triplet(RzAnalysis *analysis, const char *os, const char *arch, int bits) {
	rz_return_val_if_fail(analysis, false);
	if (!arch || !*arch) {
		arch = analysis->cur ? analysis->cur->arch : RZ_SYS_ARCH;
	}
	if (bits < 1) {
		bits = analysis->bits;
	}
	analysis_set_os(analysis, os);
	rz_analysis_set_bits(analysis, bits);
	return rz_analysis_use(analysis, arch);
}

RZ_API bool rz_analysis_set_os(RzAnalysis *analysis, const char *os) {
	return rz_analysis_set_triplet(analysis, os, NULL, -1);
}

RZ_API bool rz_analysis_set_bits(RzAnalysis *analysis, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 27:
	case 32:
	case 64:
		if (analysis->bits != bits) {
			const char *dir_prefix = rz_sys_prefix(NULL);
			analysis->bits = bits;
			rz_type_db_set_bits(analysis->typedb, bits);
			rz_type_db_reload(analysis->typedb, dir_prefix);
			rz_analysis_set_reg_profile(analysis);
		}
		return true;
	}
	return false;
}

RZ_API void rz_analysis_set_cpu(RzAnalysis *analysis, const char *cpu) {
	free(analysis->cpu);
	analysis->cpu = cpu ? strdup(cpu) : NULL;
	int v = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_ALIGN);
	if (v != -1) {
		analysis->pcalign = v;
	}
	rz_type_db_set_cpu(analysis->typedb, cpu);
	const char *dir_prefix = rz_sys_prefix(NULL);
	rz_type_db_reload(analysis->typedb, dir_prefix);
}

RZ_API int rz_analysis_set_big_endian(RzAnalysis *analysis, int bigend) {
	analysis->big_endian = bigend;
	if (analysis->reg) {
		analysis->reg->big_endian = bigend;
	}
	rz_type_db_set_endian(analysis->typedb, bigend);
	return true;
}

RZ_API ut8 *rz_analysis_mask(RzAnalysis *analysis, int size, const ut8 *data, ut64 at) {
	RzAnalysisOp *op = NULL;
	ut8 *ret = NULL;
	int oplen, idx = 0;

	if (!data) {
		return NULL;
	}

	if (analysis->cur && analysis->cur->analysis_mask) {
		return analysis->cur->analysis_mask(analysis, size, data, at);
	}

	if (!(op = rz_analysis_op_new())) {
		return NULL;
	}

	if (!(ret = malloc(size))) {
		rz_analysis_op_free(op);
		return NULL;
	}

	memset(ret, 0xff, size);

	while (idx < size) {
		if ((oplen = rz_analysis_op(analysis, op, at, data + idx, size - idx, RZ_ANALYSIS_OP_MASK_BASIC)) < 1) {
			break;
		}
		if ((op->ptr != UT64_MAX || op->jump != UT64_MAX) && op->nopcode != 0) {
			memset(ret + idx + op->nopcode, 0, oplen - op->nopcode);
		}
		idx += oplen;
		at += oplen;
	}

	rz_analysis_op_free(op);

	return ret;
}

RZ_API void rz_analysis_trace_bb(RzAnalysis *analysis, ut64 addr) {
	RzAnalysisBlock *bbi;
	RzAnalysisFunction *fcni;
	RzListIter *iter2;
	fcni = rz_analysis_get_fcn_in(analysis, addr, 0);
	if (fcni) {
		rz_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr >= bbi->addr && addr < (bbi->addr + bbi->size)) {
				bbi->traced = true;
				break;
			}
		}
	}
}

RZ_API RzList *rz_analysis_get_fcns(RzAnalysis *analysis) {
	// avoid received to free this thing
	analysis->fcns->free = NULL;
	return analysis->fcns;
}

RZ_API RzAnalysisOp *rz_analysis_op_hexstr(RzAnalysis *analysis, ut64 addr, const char *str) {
	RzAnalysisOp *op = RZ_NEW0(RzAnalysisOp);
	if (!op) {
		return NULL;
	}
	ut8 *buf = calloc(1, strlen(str) + 1);
	if (!buf) {
		free(op);
		return NULL;
	}
	int len = rz_hex_str2bin(str, buf);
	rz_analysis_op(analysis, op, addr, buf, len, RZ_ANALYSIS_OP_MASK_BASIC);
	free(buf);
	return op;
}

RZ_API bool rz_analysis_op_is_eob(RzAnalysisOp *op) {
	if (op->eob) {
		return true;
	}
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
		return true;
	default:
		return false;
	}
}

RZ_API void rz_analysis_purge(RzAnalysis *analysis) {
	rz_analysis_hint_clear(analysis);
	rz_interval_tree_fini(&analysis->meta);
	rz_interval_tree_init(&analysis->meta, rz_meta_item_free);
	rz_type_db_purge(analysis->typedb);
	ht_up_free(analysis->type_links);
	analysis->type_links = ht_up_new0();
	sdb_reset(analysis->sdb_zigns);
	sdb_reset(analysis->sdb_classes);
	sdb_reset(analysis->sdb_classes_attrs);
	rz_analysis_pin_fini(analysis);
	rz_analysis_pin_init(analysis);
	sdb_reset(analysis->sdb_cc);
	sdb_reset(analysis->sdb_noret);
	rz_list_free(analysis->fcns);
	analysis->fcns = rz_list_newf(rz_analysis_function_free);
	rz_analysis_purge_imports(analysis);
}

RZ_API int rz_analysis_archinfo(RzAnalysis *analysis, int query) {
	rz_return_val_if_fail(analysis, -1);
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
	case RZ_ANALYSIS_ARCHINFO_ALIGN:
		if (analysis->cur && analysis->cur->archinfo) {
			return analysis->cur->archinfo(analysis, query);
		}
		break;
	}
	return -1;
}

#define K_NORET_ADDR(x) sdb_fmt("addr.%" PFMT64x ".noreturn", x)
#define K_NORET_FUNC(x) sdb_fmt("func.%s.noreturn", x)

RZ_API bool rz_analysis_noreturn_add(RzAnalysis *analysis, const char *name, ut64 addr) {
	const char *tmp_name = NULL;
	Sdb *NDB = analysis->sdb_noret;
	char *fnl_name = NULL;
	if (addr != UT64_MAX) {
		if (sdb_bool_set(NDB, K_NORET_ADDR(addr), true, 0)) {
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, addr);
			if (fcn) {
				fcn->is_noreturn = true;
			}
			return true;
		}
	}
	if (name && *name) {
		tmp_name = name;
	} else {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, addr, -1);
		RzFlagItem *fi = analysis->flb.get_at(analysis->flb.f, addr, false);
		if (!fcn && !fi) {
			eprintf("Can't find Function at given address\n");
			return false;
		}
		tmp_name = fcn ? fcn->name : fi->name;
		if (fcn) {
			fcn->is_noreturn = true;
		}
	}
	if (rz_type_func_exist(analysis->typedb, tmp_name)) {
		fnl_name = strdup(tmp_name);
	} else if (!(fnl_name = rz_analysis_function_name_guess(analysis->typedb, (char *)tmp_name))) {
		if (addr == UT64_MAX) {
			if (name) {
				sdb_bool_set(NDB, K_NORET_FUNC(name), true, 0);
			} else {
				eprintf("Can't find prototype for: %s\n", tmp_name);
			}
		} else {
			eprintf("Can't find prototype for: %s\n", tmp_name);
		}
		//return false;
	}
	if (fnl_name) {
		sdb_bool_set(NDB, K_NORET_FUNC(fnl_name), true, 0);
		free(fnl_name);
	}
	return true;
}

RZ_API bool rz_analysis_noreturn_drop(RzAnalysis *analysis, const char *expr) {
	Sdb *NDB = analysis->sdb_noret;
	expr = rz_str_trim_head_ro(expr);
	const char *fcnname = NULL;
	if (!strncmp(expr, "0x", 2)) {
		ut64 n = rz_num_math(NULL, expr);
		sdb_unset(NDB, K_NORET_ADDR(n), 0);
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(analysis, n, -1);
		if (!fcn) {
			// eprintf ("can't find function at 0x%"PFMT64x"\n", n);
			return false;
		}
		fcnname = fcn->name;
	} else {
		fcnname = expr;
	}
	sdb_unset(NDB, K_NORET_FUNC(fcnname), 0);
	return false;
}

static bool rz_analysis_is_noreturn(RzAnalysis *analysis, const char *name) {
	return rz_type_func_is_noreturn(analysis->typedb, name) ||
		sdb_bool_get(analysis->sdb_noret, K_NORET_FUNC(name), NULL);
}

static bool rz_analysis_noreturn_at_name(RzAnalysis *analysis, const char *name) {
	if (rz_analysis_is_noreturn(analysis, name)) {
		return true;
	}
	char *tmp = rz_analysis_function_name_guess(analysis->typedb, (char *)name);
	if (tmp) {
		if (rz_analysis_is_noreturn(analysis, tmp)) {
			free(tmp);
			return true;
		}
		free(tmp);
	}
	if (rz_str_startswith(name, "reloc.")) {
		return rz_analysis_noreturn_at_name(analysis, name + 6);
	}
	return false;
}

RZ_API bool rz_analysis_noreturn_at_addr(RzAnalysis *analysis, ut64 addr) {
	return sdb_bool_get(analysis->sdb_noret, K_NORET_ADDR(addr), NULL);
}

static bool noreturn_recurse(RzAnalysis *analysis, ut64 addr) {
	RzAnalysisOp op = { 0 };
	ut8 bbuf[0x10] = { 0 };
	ut64 recurse_addr = UT64_MAX;
	if (!analysis->iob.read_at(analysis->iob.io, addr, bbuf, sizeof(bbuf))) {
		eprintf("Couldn't read buffer\n");
		return false;
	}
	if (rz_analysis_op(analysis, &op, addr, bbuf, sizeof(bbuf), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_VAL) < 1) {
		return false;
	}
	switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
		if (op.jump == UT64_MAX) {
			recurse_addr = op.ptr;
		} else {
			recurse_addr = op.jump;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
		recurse_addr = op.ptr;
		break;
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		recurse_addr = op.jump;
		break;
	}
	if (recurse_addr == UT64_MAX || recurse_addr == addr) {
		return false;
	}
	return rz_analysis_noreturn_at(analysis, recurse_addr);
}

RZ_API bool rz_analysis_noreturn_at(RzAnalysis *analysis, ut64 addr) {
	if (!addr || addr == UT64_MAX) {
		return false;
	}
	if (rz_analysis_noreturn_at_addr(analysis, addr)) {
		return true;
	}
	/* XXX this is very slow */
	RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, addr);
	if (f) {
		if (rz_analysis_noreturn_at_name(analysis, f->name)) {
			return true;
		}
	}
	RzFlagItem *fi = analysis->flag_get(analysis->flb.f, addr);
	if (fi) {
		if (rz_analysis_noreturn_at_name(analysis, fi->realname ? fi->realname : fi->name)) {
			return true;
		}
	}
	if (analysis->recursive_noreturn) {
		return noreturn_recurse(analysis, addr);
	}
	return false;
}

RZ_API RzList *rz_analysis_noreturn_functions(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	// At first we read all noreturn functions from the Types DB
	RzList *noretl = rz_type_noreturn_function_names(analysis->typedb);
	// Then we propagate all noreturn functions that were inferred by
	// the analysis process
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(analysis->sdb_noret, true);
	ls_foreach (l, iter, kv) {
		const char *k = sdbkv_key(kv);
		if (!strncmp(k, "func.", 5) && strstr(k, ".noreturn")) {
			char *s = strdup(k + 5);
			char *d = strchr(s, '.');
			if (d) {
				*d = 0;
			}
			rz_list_append(noretl, strdup(s));
			free(s);
		}
		if (!strncmp(k, "addr.", 5)) {
			char *off;
			if (!(off = strdup(k + 5))) {
				break;
			}
			char *ptr = strstr(off, ".noreturn");
			if (ptr) {
				*ptr = 0;
				char *addr = rz_str_newf("0x%s", off);
				rz_list_append(noretl, addr);
			}
			free(off);
		}
	}
	ls_free(l);
	return noretl;
}

RZ_API void rz_analysis_bind(RzAnalysis *analysis, RzAnalysisBind *b) {
	if (b) {
		b->analysis = analysis;
		b->get_fcn_in = rz_analysis_get_fcn_in;
		b->get_hint = rz_analysis_hint_get;
	}
}

RZ_API RzList *rz_analysis_preludes(RzAnalysis *analysis) {
	if (analysis->cur && analysis->cur->preludes) {
		return analysis->cur->preludes(analysis);
	}
	return NULL;
}

RZ_API bool rz_analysis_is_prelude(RzAnalysis *analysis, const ut8 *data, int len) {
	RzList *l = rz_analysis_preludes(analysis);
	if (l) {
		RzSearchKeyword *kw;
		RzListIter *iter;
		rz_list_foreach (l, iter, kw) {
			int ks = kw->keyword_length;
			if (len >= ks && !memcmp(data, kw->bin_keyword, ks)) {
				rz_list_free(l);
				return true;
			}
		}
		rz_list_free(l);
	}
	return false;
}

RZ_API void rz_analysis_add_import(RzAnalysis *analysis, const char *imp) {
	RzListIter *it;
	const char *eimp;
	rz_list_foreach (analysis->imports, it, eimp) {
		if (!strcmp(eimp, imp)) {
			return;
		}
	}
	char *cimp = strdup(imp);
	if (!cimp) {
		return;
	}
	rz_list_push(analysis->imports, cimp);
}

RZ_API void rz_analysis_remove_import(RzAnalysis *analysis, const char *imp) {
	RzListIter *it;
	const char *eimp;
	rz_list_foreach (analysis->imports, it, eimp) {
		if (!strcmp(eimp, imp)) {
			rz_list_delete(analysis->imports, it);
			return;
		}
	}
}

RZ_API void rz_analysis_purge_imports(RzAnalysis *analysis) {
	rz_list_purge(analysis->imports);
}
