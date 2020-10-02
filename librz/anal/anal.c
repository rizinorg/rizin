/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <rz_anal.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_io.h>
#include <config.h>

R_LIB_VERSION(rz_anal);

static RzAnalPlugin *anal_static_plugins[] = {
	R_ANAL_STATIC_PLUGINS
};

RZ_API void rz_anal_set_limits(RzAnal *anal, ut64 from, ut64 to) {
	free (anal->limit);
	anal->limit = R_NEW0 (RzAnalRange);
	if (anal->limit) {
		anal->limit->from = from;
		anal->limit->to = to;
	}
}

RZ_API void rz_anal_unset_limits(RzAnal *anal) {
	R_FREE (anal->limit);
}

static void meta_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RzAnal *anal = container_of (s, RzAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	rz_meta_space_unset_for (anal, se->data.unset.space);
}

static void meta_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RzAnal *anal = container_of (s, RzAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = rz_meta_space_count_for (anal, se->data.count.space);
}

static void zign_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RzAnal *anal = container_of (s, RzAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	rz_sign_space_unset_for (anal, se->data.unset.space);
}

static void zign_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RzAnal *anal = container_of (s, RzAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = rz_sign_space_count_for (anal, se->data.count.space);
}

static void zign_rename_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RzAnal *anal = container_of (s, RzAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	rz_sign_space_rename_for (anal, se->data.rename.space,
		se->data.rename.oldname, se->data.rename.newname);
}

void rz_anal_hint_storage_init(RzAnal *a);
void rz_anal_hint_storage_fini(RzAnal *a);

static void rz_meta_item_fini(RzAnalMetaItem *item) {
	free (item->str);
}

static void rz_meta_item_free(void *_item) {
	if (_item) {
		RzAnalMetaItem *item = _item;
		rz_meta_item_fini (item);
		free (item);
	}
}

RZ_API RzAnal *rz_anal_new(void) {
	int i;
	RzAnal *anal = R_NEW0 (RzAnal);
	if (!anal) {
		return NULL;
	}
	if (!rz_str_constpool_init (&anal->constpool)) {
		free (anal);
		return NULL;
	}
	anal->bb_tree = NULL;
	anal->ht_addr_fun = ht_up_new0 ();
	anal->ht_name_fun = ht_pp_new0 ();
	anal->os = strdup (R_SYS_OS);
	anal->esil_goto_limit = R_ANAL_ESIL_GOTO_LIMIT;
	anal->opt.nopskip = true; // skip nops in code analysis
	anal->opt.hpskip = false; // skip `mov reg,reg` and `lea reg,[reg]`
	anal->gp = 0LL;
	anal->sdb = sdb_new0 ();
	anal->cpp_abi = R_ANAL_CPP_ABI_ITANIUM;
	anal->opt.depth = 32;
	anal->opt.noncode = false; // do not analyze data by default
	rz_spaces_init (&anal->meta_spaces, "CS");
	rz_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_UNSET, meta_unset_for, NULL);
	rz_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_COUNT, meta_count_for, NULL);

	rz_spaces_init (&anal->zign_spaces, "zs");
	rz_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_UNSET, zign_unset_for, NULL);
	rz_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_COUNT, zign_count_for, NULL);
	rz_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_RENAME, zign_rename_for, NULL);
	rz_anal_hint_storage_init (anal);
	rz_interval_tree_init (&anal->meta, rz_meta_item_free);
	anal->sdb_types = sdb_ns (anal->sdb, "types", 1);
	anal->sdb_fmts = sdb_ns (anal->sdb, "spec", 1);
	anal->sdb_cc = sdb_ns (anal->sdb, "cc", 1);
	anal->sdb_zigns = sdb_ns (anal->sdb, "zigns", 1);
	anal->sdb_classes = sdb_ns (anal->sdb, "classes", 1);
	anal->sdb_classes_attrs = sdb_ns (anal->sdb_classes, "attrs", 1);
	anal->zign_path = strdup ("");
	anal->cb_printf = (PrintfCallback) printf;
	(void)rz_anal_pin_init (anal);
	(void)rz_anal_xrefs_init (anal);
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->syscall = rz_syscall_new ();
	rz_io_bind_init (anal->iob);
	rz_flag_bind_init (anal->flb);
	anal->reg = rz_reg_new ();
	anal->last_disasm_reg = NULL;
	anal->stackptr = 0;
	anal->lineswidth = 0;
	anal->fcns = rz_list_newf (rz_anal_function_free);
	anal->leaddrs = NULL;
	anal->imports = rz_list_newf (free);
	rz_anal_set_bits (anal, 32);
	anal->plugins = rz_list_newf ((RzListFree) rz_anal_plugin_free);
	if (anal->plugins) {
		for (i = 0; anal_static_plugins[i]; i++) {
			rz_anal_add (anal, anal_static_plugins[i]);
		}
	}
	return anal;
}

RZ_API void rz_anal_plugin_free (RzAnalPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

void __block_free_rb(RBNode *node, void *user);

RZ_API RzAnal *rz_anal_free(RzAnal *a) {
	if (!a) {
		return NULL;
	}
	/* TODO: Free anals here */
	rz_list_free (a->fcns);
	ht_up_free (a->ht_addr_fun);
	ht_pp_free (a->ht_name_fun);
	set_u_free (a->visited);
	rz_anal_hint_storage_fini (a);
	rz_interval_tree_fini (&a->meta);
	free (a->cpu);
	free (a->os);
	free (a->zign_path);
	rz_list_free (a->plugins);
	rz_rbtree_free (a->bb_tree, __block_free_rb, NULL);
	rz_spaces_fini (&a->meta_spaces);
	rz_spaces_fini (&a->zign_spaces);
	rz_anal_pin_fini (a);
	rz_syscall_free (a->syscall);
	rz_reg_free (a->reg);
	ht_up_free (a->dict_refs);
	ht_up_free (a->dict_xrefs);
	rz_list_free (a->leaddrs);
	sdb_free (a->sdb);
	if (a->esil) {
		rz_anal_esil_free (a->esil);
		a->esil = NULL;
	}
	free (a->last_disasm_reg);
	rz_list_free (a->imports);
	rz_str_constpool_fini (&a->constpool);
	free (a);
	return NULL;
}

RZ_API void rz_anal_set_user_ptr(RzAnal *anal, void *user) {
	anal->user = user;
}

RZ_API int rz_anal_add(RzAnal *anal, RzAnalPlugin *foo) {
	if (foo->init) {
		foo->init (anal->user);
	}
	rz_list_append (anal->plugins, foo);
	return true;
}

RZ_API bool rz_anal_use(RzAnal *anal, const char *name) {
	RzListIter *it;
	RzAnalPlugin *h;

	if (anal) {
		rz_list_foreach (anal->plugins, it, h) {
			if (!h->name || strcmp (h->name, name)) {
				continue;
			}
#if 0
			// regression happening here for asm.emu
			if (anal->cur && anal->cur == h) {
				return true;
			}
#endif
			anal->cur = h;
			rz_anal_set_reg_profile (anal);
			return true;
		}
	}
	return false;
}

RZ_API char *rz_anal_get_reg_profile(RzAnal *anal) {
	return (anal && anal->cur && anal->cur->get_reg_profile)
		? anal->cur->get_reg_profile (anal) : NULL;
}

// deprecate.. or at least reuse get_reg_profile...
RZ_API bool rz_anal_set_reg_profile(RzAnal *anal) {
	bool ret = false;
	if (anal && anal->cur && anal->cur->set_reg_profile) {
		ret = anal->cur->set_reg_profile (anal);
	} else {
		char *p = rz_anal_get_reg_profile (anal);
		if (p && *p) {
			rz_reg_set_profile_string (anal->reg, p);
			ret = true;
		}
		free (p);
	}
	return ret;
}

RZ_API bool rz_anal_set_triplet(RzAnal *anal, const char *os, const char *arch, int bits) {
	rz_return_val_if_fail (anal, false);
	if (!os || !*os) {
		os = R_SYS_OS;
	}
	if (!arch || !*arch) {
		arch = anal->cur? anal->cur->arch: R_SYS_ARCH;
	}
	if (bits < 1) {
		bits = anal->bits;
	}
	free (anal->os);
	anal->os = strdup (os);
	rz_anal_set_bits (anal, bits);
	return rz_anal_use (anal, arch);
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new (0, path, 0);
	sdb_merge (s, db);
	sdb_close (db);
	sdb_free (db);
}

RZ_API bool rz_anal_set_os(RzAnal *anal, const char *os) {
	Sdb *types = anal->sdb_types;
	const char *dir_prefix = rz_sys_prefix (NULL);
	const char *dbpath = sdb_fmt (R_JOIN_3_PATHS ("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, os);
	if (rz_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	return rz_anal_set_triplet (anal, os, NULL, -1);
}

RZ_API bool rz_anal_set_bits(RzAnal *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 27:
	case 32:
	case 64:
		if (anal->bits != bits) {
			anal->bits = bits;
			rz_anal_set_reg_profile (anal);
		}
		return true;
	}
	return false;
}

RZ_API void rz_anal_set_cpu(RzAnal *anal, const char *cpu) {
	free (anal->cpu);
	anal->cpu = cpu ? strdup (cpu) : NULL;
	int v = rz_anal_archinfo (anal, R_ANAL_ARCHINFO_ALIGN);
	if (v != -1) {
		anal->pcalign = v;
	}
}

RZ_API int rz_anal_set_big_endian(RzAnal *anal, int bigend) {
	anal->big_endian = bigend;
	anal->reg->big_endian = bigend;
	return true;
}

RZ_API ut8 *rz_anal_mask(RzAnal *anal, int size, const ut8 *data, ut64 at) {
	RzAnalOp *op = NULL;
	ut8 *ret = NULL;
	int oplen, idx = 0;

	if (!data) {
		return NULL;
	}

	if (anal->cur && anal->cur->anal_mask) {
		return anal->cur->anal_mask (anal, size, data, at);
	}

	if (!(op = rz_anal_op_new ())) {
		return NULL;
	}

	if (!(ret = malloc (size))) {
		rz_anal_op_free (op);
		return NULL;
	}

	memset (ret, 0xff, size);

	while (idx < size) {
		if ((oplen = rz_anal_op (anal, op, at, data + idx, size - idx, R_ANAL_OP_MASK_BASIC)) < 1) {
			break;
		}
		if ((op->ptr != UT64_MAX || op->jump != UT64_MAX) && op->nopcode != 0) {
			memset (ret + idx + op->nopcode, 0, oplen - op->nopcode);
		}
		idx += oplen;
		at += oplen;
	}

	rz_anal_op_free (op);

	return ret;
}

RZ_API void rz_anal_trace_bb(RzAnal *anal, ut64 addr) {
	RzAnalBlock *bbi;
	RzAnalFunction *fcni;
	RzListIter *iter2;
	fcni = rz_anal_get_fcn_in (anal, addr, 0);
	if (fcni) {
		rz_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr >= bbi->addr && addr < (bbi->addr + bbi->size)) {
				bbi->traced = true;
				break;
			}
		}
	}
}

RZ_API void rz_anal_colorize_bb(RzAnal *anal, ut64 addr, ut32 color) {
	RzAnalBlock *bbi;
	bbi = rz_anal_bb_from_offset (anal, addr);
	if (bbi) {
		bbi->colorize = color;
	}
}

RZ_API RzList* rz_anal_get_fcns (RzAnal *anal) {
	// avoid received to free this thing
	anal->fcns->free = NULL;
	return anal->fcns;
}

RZ_API RzAnalOp *rz_anal_op_hexstr(RzAnal *anal, ut64 addr, const char *str) {
	RzAnalOp *op = R_NEW0 (RzAnalOp);
	if (!op) {
		return NULL;
	}
	ut8 *buf = calloc (1, strlen (str) + 1);
	if (!buf) {
		free (op);
		return NULL;
	}
	int len = rz_hex_str2bin (str, buf);
	rz_anal_op (anal, op, addr, buf, len, R_ANAL_OP_MASK_BASIC);
	free (buf);
	return op;
}

RZ_API bool rz_anal_op_is_eob(RzAnalOp *op) {
	if (op->eob) {
		return true;
	}
	switch (op->type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_TRAP:
		return true;
	default:
		return false;
	}
}

RZ_API void rz_anal_purge(RzAnal *anal) {
	rz_anal_hint_clear (anal);
	rz_interval_tree_fini (&anal->meta);
	rz_interval_tree_init (&anal->meta, rz_meta_item_free);
	sdb_reset (anal->sdb_types);
	sdb_reset (anal->sdb_zigns);
	sdb_reset (anal->sdb_classes);
	sdb_reset (anal->sdb_classes_attrs);
	rz_anal_pin_fini (anal);
	rz_anal_pin_init (anal);
	sdb_reset (anal->sdb_cc);
	rz_list_free (anal->fcns);
	anal->fcns = rz_list_newf (rz_anal_function_free);
	rz_anal_purge_imports (anal);
}

RZ_API int rz_anal_archinfo(RzAnal *anal, int query) {
	rz_return_val_if_fail (anal, -1);
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	case R_ANAL_ARCHINFO_ALIGN:
		if (anal->cur && anal->cur->archinfo) {
			return anal->cur->archinfo (anal, query);
		}
		break;
	}
	return -1;
}

static bool __nonreturn_print_commands(void *p, const char *k, const char *v) {
	RzAnal *anal = (RzAnal *)p;
	if (!strncmp (v, "func", strlen ("func") + 1)) {
		char *query = sdb_fmt ("func.%s.noreturn", k);
		if (sdb_bool_get (anal->sdb_types, query, NULL)) {
			anal->cb_printf ("tnn %s\n", k);
		}
	}
	if (!strncmp (k, "addr.", 5)) {
		anal->cb_printf ("tna 0x%s %s\n", k + 5, v);
	}
	return true;
}

static bool __nonreturn_print(void *p, const char *k, const char *v) {
	RzAnal *anal = (RzAnal *)p;
	if (!strncmp (k, "func.", 5) && strstr (k, ".noreturn")) {
		char *s = strdup (k + 5);
		char *d = strchr (s, '.');
		if (d) {
			*d = 0;
		}
		anal->cb_printf ("%s\n", s);
		free (s);
	}
	if (!strncmp (k, "addr.", 5)) {
		char *off;
		if (!(off = strdup (k + 5))) {
			return 1;
		}
		char *ptr = strstr (off, ".noreturn");
		if (ptr) {
			*ptr = 0;
			anal->cb_printf ("0x%s\n", off);
		}
		free (off);
	}
	return true;
}

RZ_API void rz_anal_noreturn_list(RzAnal *anal, int mode) {
	switch (mode) {
	case 1:
	case '*':
	case 'r':
		sdb_foreach (anal->sdb_types, __nonreturn_print_commands, anal);
		break;
	default:
		sdb_foreach (anal->sdb_types, __nonreturn_print, anal);
		break;
	}
}

#define K_NORET_ADDR(x) sdb_fmt ("addr.%"PFMT64x".noreturn", x)
#define K_NORET_FUNC(x) sdb_fmt ("func.%s.noreturn", x)

RZ_API bool rz_anal_noreturn_add(RzAnal *anal, const char *name, ut64 addr) {
	const char *tmp_name = NULL;
	Sdb *TDB = anal->sdb_types;
	char *fnl_name = NULL;
	if (addr != UT64_MAX) {
		if (sdb_bool_set (TDB, K_NORET_ADDR (addr), true, 0)) {
			RzAnalFunction *fcn = rz_anal_get_function_at (anal, addr);
			if (fcn) {
				fcn->is_noreturn = true;
			}
			return true;
		}
	}
	if (name && *name) {
		tmp_name = name;
	} else {
		RzAnalFunction *fcn = rz_anal_get_fcn_in (anal, addr, -1);
		RzFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
		if (!fcn && !fi) {
			eprintf ("Can't find Function at given address\n");
			return false;
		}
		tmp_name = fcn ? fcn->name: fi->name;
		if (fcn) {
			fcn->is_noreturn = true;
		}
	}
	if (rz_type_func_exist (TDB, tmp_name)) {
		fnl_name = strdup (tmp_name);
	} else if (!(fnl_name = rz_type_func_guess (TDB, (char *)tmp_name))) {
		if (addr == UT64_MAX) {
			if (name) {
				sdb_bool_set (TDB, K_NORET_FUNC (name), true, 0);
			} else {
				eprintf ("Can't find prototype for: %s\n", tmp_name);
			}
		} else {
			eprintf ("Can't find prototype for: %s\n", tmp_name);
		}
		//return false;
	}
	if (fnl_name) {
		sdb_bool_set (TDB, K_NORET_FUNC (fnl_name), true, 0);
		free (fnl_name);
	}
	return true;
}

RZ_API bool rz_anal_noreturn_drop(RzAnal *anal, const char *expr) {
	Sdb *TDB = anal->sdb_types;
	expr = rz_str_trim_head_ro (expr);
	const char *fcnname = NULL;
	if (!strncmp (expr, "0x", 2)) {
		ut64 n = rz_num_math (NULL, expr);
		sdb_unset (TDB, K_NORET_ADDR (n), 0);
		RzAnalFunction *fcn = rz_anal_get_fcn_in (anal, n, -1);
		if (!fcn) {
			// eprintf ("can't find function at 0x%"PFMT64x"\n", n);
			return false;
		}
		fcnname = fcn->name;
	} else {
		fcnname = expr;
	}
	sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
#if 0
	char *tmp;
	// unnsecessary checks, imho the noreturn db should be pretty simple to allow forward and custom declarations without having to define the function prototype before
	if (rz_type_func_exist (TDB, fcnname)) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		return true;
	} else if ((tmp = rz_type_func_guess (TDB, (char *)fcnname))) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		free (tmp);
		return true;
	}
	eprintf ("Can't find prototype for %s in types database", fcnname);
#endif
	return false;
}

static bool rz_anal_noreturn_at_name(RzAnal *anal, const char *name) {
	if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC(name), NULL)) {
		return true;
	}
	char *tmp = rz_type_func_guess (anal->sdb_types, (char *)name);
	if (tmp) {
		if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC (tmp), NULL)) {
			free (tmp);
			return true;
		}
		free (tmp);
	}
	if (rz_str_startswith (name, "reloc.")) {
		return rz_anal_noreturn_at_name (anal, name + 6);
	}
	return false;
}

RZ_API bool rz_anal_noreturn_at_addr(RzAnal *anal, ut64 addr) {
	return sdb_bool_get (anal->sdb_types, K_NORET_ADDR (addr), NULL);
}

static bool noreturn_recurse(RzAnal *anal, ut64 addr) {
	RzAnalOp op = {0};
	ut8 bbuf[0x10] = {0};
	ut64 recurse_addr = UT64_MAX;
	if (!anal->iob.read_at (anal->iob.io, addr, bbuf, sizeof (bbuf))) {
		eprintf ("Couldn't read buffer\n");
		return false;
	}
	if (rz_anal_op (anal, &op, addr, bbuf, sizeof (bbuf), R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_VAL) < 1) {
		return false;
	}
	switch (op.type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_JMP:
		if (op.jump == UT64_MAX) {
			recurse_addr = op.ptr;
		} else {
			recurse_addr = op.jump;
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		recurse_addr = op.ptr;
		break;
	case R_ANAL_OP_TYPE_CCALL:
	case R_ANAL_OP_TYPE_CALL:
		recurse_addr = op.jump;
		break;
	}
	if (recurse_addr == UT64_MAX || recurse_addr == addr) {
		return false;
	}
	return rz_anal_noreturn_at (anal, recurse_addr);
}

RZ_API bool rz_anal_noreturn_at(RzAnal *anal, ut64 addr) {
	if (!addr || addr == UT64_MAX) {
		return false;
	}
	if (rz_anal_noreturn_at_addr (anal, addr)) {
		return true;
	}
	/* XXX this is very slow */
	RzAnalFunction *f = rz_anal_get_function_at (anal, addr);
	if (f) {
		if (rz_anal_noreturn_at_name (anal, f->name)) {
			return true;
		}
	}
	RzFlagItem *fi = anal->flag_get (anal->flb.f, addr);
	if (fi) {
		if (rz_anal_noreturn_at_name (anal, fi->realname ? fi->realname : fi->name)) {
			return true;
		}
	}
	if (anal->recursive_noreturn) {
		return noreturn_recurse (anal, addr);
	}
	return false;
}

RZ_API void rz_anal_bind(RzAnal *anal, RzAnalBind *b) {
	if (b) {
		b->anal = anal;
		b->get_fcn_in = rz_anal_get_fcn_in;
		b->get_hint = rz_anal_hint_get;
	}
}

RZ_API RzList *rz_anal_preludes(RzAnal *anal) {
	if (anal->cur && anal->cur->preludes ) {
		return anal->cur->preludes (anal);
	}
	return NULL;
}

RZ_API bool rz_anal_is_prelude(RzAnal *anal, const ut8 *data, int len) {
	RzList *l = rz_anal_preludes (anal);
	if (l) {
		RzSearchKeyword *kw;
		RzListIter *iter;
		rz_list_foreach (l, iter, kw) {
			int ks = kw->keyword_length;
			if (len >= ks && !memcmp (data, kw->bin_keyword, ks)) {
				rz_list_free (l);
				return true;
			}
		}
		rz_list_free (l);
	}
	return false;
}

RZ_API void rz_anal_add_import(RzAnal *anal, const char *imp) {
	RzListIter *it;
	const char *eimp;
	rz_list_foreach (anal->imports, it, eimp) {
		if (!strcmp (eimp, imp)) {
			return;
		}
	}
	char *cimp = strdup (imp);
	if (!cimp) {
		return;
	}
	rz_list_push (anal->imports, cimp);
}

RZ_API void rz_anal_remove_import(RzAnal *anal, const char *imp) {
	RzListIter *it;
	const char *eimp;
	rz_list_foreach (anal->imports, it, eimp) {
		if (!strcmp (eimp, imp)) {
			rz_list_delete (anal->imports, it);
			return;
		}
	}
}

RZ_API void rz_anal_purge_imports(RzAnal *anal) {
	rz_list_purge (anal->imports);
}
