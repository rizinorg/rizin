// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sdb.h"
#include <rz_project.h>
#include <rz_util/rz_pj.h>

/**
 * \file
 * About Project Migrations:
 * The project format is versioned, which means that a project saved with a certain version
 * will always follow the exact same format.
 * The current version is defined as `RZ_PROJECT_VERSION` and is completely independent of
 * Rizin release versions. Do not confuse them!
 * When any change in Rizin happens that changes the project format, this version must be raised
 * and a migration must be implemented, which converts a given project from the previous version
 * to the current and will be executed when loading an old project with new Rizin.
 * These migrations always bring a project from version x to version x+1 and they may be executed
 * sequentially if multiple versions are skipped. For example loading a project with version 1 in
 * Rizin with version 3 will execute (1->2), then (2->3) and finally load the project just like
 * any regular project of version 3.
 *
 * After introducing format changes in Rizin, do the following:
 *  * Raise RZ_PROJECT_VERSION by exactly 1.
 *  * Implement a function like `bool rz_project_migrate_migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res)`
 *    which edits prj in-place and converts it from the previous to the current version.
 *  * Append this function to the `migrations` array below.
 *  * Implement tests in `test/unit/test_project_migrate.c` that cover all changes (see the documentation there).
 */

// --
// Migration 1 -> 2
//
// Changes from 788fdb3d8ef98f50d61cdee72e0b57c74c814022:
//   Information which addresses are marked as noreturn was previosly saved in "/core/analysis/types" as records like:
//     addr.1337.noreturn=true
//   Now it is available in "/core/analysis/noreturn" while actual type-related info stays in "/core/analysis/types".

typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *noreturn_db;
} V1V2TypesCtx;

bool v1_v2_types_foreach_cb(void *user, const SdbKv *kv) {
	const char *k = sdbkv_key(kv);
	const char *v = sdbkv_value(kv);
	if (!rz_str_startswith(k, "addr.") || !rz_str_endswith(k, ".noreturn")) {
		return true;
	}
	V1V2TypesCtx *ctx = user;
	sdb_set(ctx->noreturn_db, k, v);
	rz_list_push(ctx->moved_keys, strdup(k));
	return true;
}

RZ_API bool rz_project_migrate_v1_v2(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	V1V2TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.noreturn_db = sdb_ns(analysis_db, "noreturn", true)
	};
	if (!ctx.moved_keys || !ctx.noreturn_db) {
		return false;
	}
	sdb_foreach(types_db, v1_v2_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(types_db, s);
	}
	rz_list_free(ctx.moved_keys);
	return true;
}

// --
// Migration 2 -> 3
//
// Changes from 788fdb3d8ef98f50d61cdee72e0b57c74c814022:
//  Types database "analysis/types" was converted into two
//  separate SDBs - types and callables
//  Thus all "func.*" keys from "/core/analysis/types" should be moved to
//  "/core/analysis/callables"
//	Type links information is also separated now from
//	"/core/analysis/types" to "/core/analysis/typelinks"

typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *callables_db;
	Sdb *typelinks_db;
} V2V3TypesCtx;

bool v2_v3_types_foreach_cb(void *user, const SdbKv *kv) {
	V2V3TypesCtx *ctx = user;
	const char *k = sdbkv_key(kv);
	const char *v = sdbkv_value(kv);
	if (rz_str_startswith(k, "func.") || !strcmp(v, "func")) {
		sdb_set(ctx->callables_db, k, v);
		rz_list_push(ctx->moved_keys, strdup(k));
	} else if (rz_str_startswith(k, "link.")) {
		// Old addresses were stored as hexadecimal numbers without `0x` part
		// New addresses have them
		char *tl_key = rz_str_newf("0x%s", k + strlen("link."));
		sdb_set(ctx->typelinks_db, tl_key, v);
		free(tl_key);
		rz_list_push(ctx->moved_keys, strdup(k));
	}
	return true;
}

RZ_API bool rz_project_migrate_v2_v3(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	V2V3TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.callables_db = sdb_ns(analysis_db, "callables", true),
		.typelinks_db = sdb_ns(analysis_db, "typelinks", true)
	};
	if (!ctx.moved_keys || !ctx.callables_db || !ctx.typelinks_db) {
		return false;
	}
	sdb_foreach(types_db, v2_v3_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(types_db, s);
	}
	rz_list_free(ctx.moved_keys);
	return true;
}

// --
// Migration 3 -> 4
//
// Changes from 8d54707ccf8b3492b999dfa42057da0847acb952:
//	Added new global variables in "/core/analysis/vars"

RZ_API bool rz_project_migrate_v3_v4(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	sdb_ns(analysis_db, "vars", true);
	// Typelinks currently still exist. When they will be removed, the following
	// code can be enabled and moved to the respective migration.
#if 0
	V3V4TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.global_vars_db = sdb_ns(analysis_db, "vars", true)
	};

	if (!ctx.moved_keys || !ctx.global_vars_db) {
		return false;
	}
	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", true);
	sdb_foreach(typelinks_db, v3_v4_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(typelinks_db, s);
	}
	rz_list_free(ctx.moved_keys);
#endif
	return true;
}

// --
// Migration 4 -> 5
//
// Changes from a523314fa7c8fde0c2c0d116e82aa77f62991d37
//	Added new type called `unknown_t` in "/core/analysis/types"
//	It is used for all unknown types during the project loading and saving

RZ_API bool rz_project_migrate_v4_v5(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	Sdb *types_db;
	RZ_SERIALIZE_SUB(analysis_db, types_db, res, "types", return false;);
	// Common keys:
	// unknown_t=type
	// type.unknown_t.typeclass=Integral
	sdb_set(types_db, "unknown_t", "type");
	sdb_set(types_db, "type.unknown_t.typeclass", "Integral");
	// Now we read the bits value from "asm.bits=XX" in "/core/config"
	int bits = sdb_num_get(config_db, "asm.bits");
	switch (bits) {
	case 16:
		// type.unknown_t=w
		// type.unknown_t.size=16
		sdb_set(types_db, "type.unknown_t", "w");
		sdb_set(types_db, "type.unknown_t.size", "16");
		break;
	case 64:
		// type.unknown_t=q
		// type.unknown_t.size=64
		sdb_set(types_db, "type.unknown_t", "q");
		sdb_set(types_db, "type.unknown_t.size", "64");
		break;
	case 32:
	default:
		// type.unknown_t=d
		// type.unknown_t.size=32
		sdb_set(types_db, "type.unknown_t", "d");
		sdb_set(types_db, "type.unknown_t.size", "32");
		break;
	}
	return true;
}

// --
// Migration 5 -> 6
//
// Changes from 2c48a91d1332daede8d0640ce407c3abcf0abfb4
//	Added serialization functionality for debug (only for breakpoints as of now)
//	Used to save and load current RzDebug instance (only breakpoints) using serialization
//	New namespaces: /core/debug, /core/debug/breakpoints

RZ_API bool rz_project_migrate_v5_v6(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *debug_db = sdb_ns(core_db, "debug", true);
	sdb_ns(debug_db, "breakpoints", true);

	return true;
}

// --
// Migration 6 -> 7
//
// Changes from 96a85e573e766e3870a01482f36c92df403cc4cd
//	Removed esil pin feature. Namespace deleted: /core/analysis/pins

RZ_API bool rz_project_migrate_v6_v7(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	sdb_ns_unset(analysis_db, "pins", NULL);
	return true;
}

// --
// Migration 7 -> 8
//
// Changes from ea02b0d25f48bb17bc6578259485549cf5c74a20
//	Removed zignature feature. Namespace deleted: /core/analysis/zigns
//	Also removed configs zign.* options.

RZ_API bool rz_project_migrate_v7_v8(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	sdb_ns_unset(analysis_db, "zigns", NULL);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	sdb_unset(config_db, "zign.autoload");
	sdb_unset(config_db, "zign.diff.bthresh");
	sdb_unset(config_db, "zign.diff.gthresh");
	sdb_unset(config_db, "zign.match.bytes");
	sdb_unset(config_db, "zign.match.graph");
	sdb_unset(config_db, "zign.match.hash");
	sdb_unset(config_db, "zign.match.offset");
	sdb_unset(config_db, "zign.match.refs");
	sdb_unset(config_db, "zign.match.types");
	sdb_unset(config_db, "zign.maxsz");
	sdb_unset(config_db, "zign.mincc");
	sdb_unset(config_db, "zign.minsz");
	sdb_unset(config_db, "zign.prefix");
	sdb_unset(config_db, "zign.threshold");
	return true;
}

// --
// Migration 8 -> 9
//
// Changes from fbad0b4859802a62dcc96002c2710e696809a0c3
//	Removed fingerprint from the serialized RzAnalysisFunction & RzAnalysisBlock

RZ_API bool rz_project_migrate_v8_v9(RzProject *prj, RzSerializeResultInfo *res) {
	// there is nothing to be done since the deserializer will ignore the original serialized data
	return true;
}

// --
// Migration 9 -> 10
//
// Changes from 13cd3942d12b61911e27ab82baef045adf57d77c
//	Removed stackptr and parent_stackptr from the serialized RzAnalysisBlock
//	Added sp_entry and sp_delta to serialized RzAnalysisBlock

RZ_API bool rz_project_migrate_v9_v10(RzProject *prj, RzSerializeResultInfo *res) {
	// There is nothing to be done since the deserializer will ignore the original serialized data
	// and missing sp_entry and sp_delta are valid for unknown values.
	// The previous stackptr/parent_stackptr are too nonsensical to be converted to sp_entry/sp_delta
	// unfortunately.
	return true;
}

// --
// Migration 10 -> 11
//
// Changes from d9950f74792c1dfb565ac491cc7ef706b80e6044
//   - Removed analysis.vars.stackname config var
//   - In RzAnalysisVar JSON, "kind", "arg" and "delta" are removed. Instead, there is either a "stack"
//     or a "reg" key, but never both.
//     - {name:<str>, type:<str>, kind:"s|b|r", arg?:<bool>, delta?:<st64>, reg?:<str>, cmt?:<str>,...
//     + {name:<str>, type:<str>, stack?:<st64>, reg?:<str>, cmt?:<str>,...
//   - In RzAnalysisVar.accs JSON, "sp" value is now actually signed in json instead of being casted
//     to and from its unsigned representation (pj_kn before, pj_kN now). The loader should be able
//     to handle both just fine, but we still convert it so we do not have to make this assumption.
//

typedef struct {
	Sdb *db_new;
	RzSerializeResultInfo *res;
} V10V11FunctionsCtx;

bool v10_v11_migrate_variable(const RzJson *var, st64 maxstack, PJ *pj, RzSerializeResultInfo *res) {
	if (var->type != RZ_JSON_OBJECT) {
		goto invalid;
	}
	// read necessary info
	const RzJson *kind = rz_json_get(var, "kind");
	if (!kind || kind->type != RZ_JSON_STRING) {
		goto invalid;
	}
	bool is_reg;
	st64 stack_addr;
	if (!strcmp(kind->str_value, "r")) {
		is_reg = true;
		// reg vars did not change, they just don't have the "delta" anymore because it was redundant.
	} else if (!strcmp(kind->str_value, "b") || !strcmp(kind->str_value, "s")) {
		is_reg = false;
		const RzJson *delta = rz_json_get(var, "delta");
		if (delta && delta->type != RZ_JSON_INTEGER) {
			goto invalid;
		}
		// Despite variables being represented as sp/bp+offset, the delta value
		// already matches our notion of stack addresses.
		stack_addr = delta ? delta->num.s_value : 0;
	} else {
		goto invalid;
	}
	// write new json
	pj_o(pj);
	for (const RzJson *var_member = var->children.first; var_member; var_member = var_member->next) {
		if (!strcmp(var_member->key, "arg") || !strcmp(var_member->key, "delta") || !strcmp(var_member->key, "kind")) {
			// removed keys
			continue;
		}
		// The accesses' "sp" key will be converted to sgned in the call below
		// as a somewhat unexpected side effect. But this is exactly what we want.
		rz_json_to_pj(var_member, pj, true);
	}
	if (!is_reg) {
		pj_kN(pj, "stack", stack_addr);
	}
	pj_end(pj);
	return true;
invalid:
	RZ_SERIALIZE_ERR(res, "invalid json contents for variable");
	return false;
}

bool v10_v11_functions_foreach_cb(void *user, const SdbKv *kv) {
	const char *k = sdbkv_key(kv);
	const char *v = sdbkv_value(kv);
	V10V11FunctionsCtx *ctx = user;
	char *json_str = strdup(v);
	RzJson *j = rz_json_parse(json_str);
	bool ret = false;
	if (!j || j->type != RZ_JSON_OBJECT) {
		RZ_SERIALIZE_ERR(ctx->res, "invalid json in function key %s", k);
		goto end;
	}
	const RzJson *tmp = rz_json_get(j, "maxstack"); // maxstack is mandatory in v10
	if (!tmp || tmp->type != RZ_JSON_INTEGER) {
		RZ_SERIALIZE_ERR(ctx->res, "missing or invalid maxstack in function key %s", k);
		goto end;
	}
	st64 maxstack = tmp->num.s_value;
	PJ *pj = pj_new();
	if (!pj) {
		goto end;
	}
	pj_o(pj);
	for (RzJson *func_member = j->children.first; func_member; func_member = func_member->next) {
		if (!strcmp(func_member->key, "vars")) {
			if (func_member->type != RZ_JSON_ARRAY) {
				RZ_SERIALIZE_ERR(ctx->res, "invalid json contents for function -> vars");
				pj_free(pj);
				goto end;
			}
			pj_ka(pj, "vars");
			for (RzJson *var = func_member->children.first; var; var = var->next) {
				v10_v11_migrate_variable(var, maxstack, pj, ctx->res);
			}
			pj_end(pj);
			continue;
		}
		rz_json_to_pj(func_member, pj, true);
	}
	pj_end(pj);
	char *res = pj_drain(pj);
	if (!res) {
		goto end;
	}
	sdb_set_owned(ctx->db_new, k, res);
	ret = true;
end:
	rz_json_free(j);
	free(json_str);
	return ret;
}

RZ_API bool rz_project_migrate_v10_v11(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	sdb_unset(config_db, "analysis.vars.stackname");

	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *functions_db_old;
	RZ_SERIALIZE_SUB(analysis_db, functions_db_old, res, "functions", return false;);
	functions_db_old->refs++;
	sdb_ns_unset(analysis_db, "functions", NULL);
	V10V11FunctionsCtx ctx = {
		.db_new = sdb_ns(analysis_db, "functions", true),
		.res = res
	};
	bool ret = sdb_foreach(functions_db_old, v10_v11_functions_foreach_cb, &ctx);
	sdb_free(functions_db_old);

	return ret;
}

// --
// Migration 11 -> 12
//
// Changes from 59f32b6db89c09c16fadbda6a098e326b73e03d8
//   - Rename config var `asm.dwarf` to `asm.debuginfo`
//   - Rename config var `asm.dwarf.abspath` to `asm.debuginfo.abspath`
//   - Rename config var `asm.dwarf.file` to `asm.debuginfo.file`
//   - Rename config var `asm.dwarf.lines` to `asm.debuginfo.lines`
//

static inline bool sdb_rename(Sdb *db, const char *old_key, const char *new_key) {
	char *val = sdb_get(db, old_key);
	if (!val) {
		return false;
	}
	sdb_unset(db, old_key);
	sdb_set_owned(db, new_key, val);
	return true;
}

RZ_API bool rz_project_migrate_v11_v12(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	sdb_rename(config_db, "asm.dwarf.abspath", "asm.debuginfo.abspath");
	sdb_rename(config_db, "asm.dwarf.file", "asm.debuginfo.file");
	sdb_rename(config_db, "asm.dwarf.lines", "asm.debuginfo.lines");
	sdb_rename(config_db, "asm.dwarf", "asm.debuginfo");
	return true;
}

// --
// Migration 12 -> 13
//
// Changes from 366dfcfbf0ac2eb4c09c49b0a9e43117864750b7:
//	Removed typelinks from "/core/analysis/typelinks"
//	and converted into global variables in "/core/analysis/vars"

typedef struct {
	RzList /*<char *>*/ *moved_keys; ///< deferred for deletion from the old sdb
	Sdb *global_vars_db;
} V12V13TypesCtx;

bool v12_v13_types_foreach_cb(void *user, const SdbKv *kv) {
	const char *k = sdbkv_key(kv);
	const char *v = sdbkv_value(kv);
	V12V13TypesCtx *ctx = user;
	if (rz_str_startswith(k, "0x")) {
		char name[32];
		PJ *j = pj_new();
		pj_o(j);
		pj_ks(j, "name", rz_strf(name, "gvar_%s", k));
		pj_ks(j, "type", v);
		pj_ks(j, "addr", k);
		// We don't have constraints for typelink here.
		pj_end(j);
		sdb_set(ctx->global_vars_db, k, pj_string(j));
		pj_free(j);
		rz_list_push(ctx->moved_keys, strdup(k));
	}
	return true;
}

RZ_API bool rz_project_migrate_v12_v13(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	sdb_ns(analysis_db, "vars", true);
	V12V13TypesCtx ctx = {
		.moved_keys = rz_list_newf(free),
		.global_vars_db = sdb_ns(analysis_db, "vars", true)
	};

	if (!ctx.moved_keys || !ctx.global_vars_db) {
		return false;
	}
	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", true);
	sdb_foreach(typelinks_db, v12_v13_types_foreach_cb, &ctx);
	RzListIter *it;
	char *s;
	rz_list_foreach (ctx.moved_keys, it, s) {
		sdb_unset(typelinks_db, s);
	}
	rz_list_free(ctx.moved_keys);
	return true;
}

// --
// Migration 13 -> 14
//
// Changes from 8e29b959b86a35bbbfed599989f077dba6e0ebd5:
//	Removed {stack,reg} from "/core/analysis/functions/vars"
//	and converted into storage object { ..., storage: { type: ... }  }

bool v13_v14_foreach_cb(void *user, const SdbKv *kv) {
	const char *k = sdbkv_key(kv);
	const char *v = sdbkv_value(kv);
	static const char *types[] = { "stack", "reg" };
	Sdb *fn_db = user;
	if (rz_str_startswith(k, "0x")) {
		RzJson *fn_j = rz_json_parse((char *)v);
		rz_return_val_if_fail(fn_j->type == RZ_JSON_OBJECT, false);

		PJ *j = pj_new();
		pj_o(j);

		for (RzJson *body = fn_j->children.first; body; body = body->next) {
			bool filtered = false;
			for (int i = 0; i < RZ_ARRAY_SIZE(types); ++i) {
				const char *type = types[i];
				if (rz_str_cmp(body->key, type, -1) != 0) {
					continue;
				}
				filtered = true;
				pj_ko(j, "storage");
				pj_ks(j, "type", types[i]);
				switch (body->type) {
				case RZ_JSON_INTEGER:
					pj_kn(j, types[i], body->num.s_value);
					break;
				case RZ_JSON_STRING:
					pj_ks(j, types[i], body->str_value);
					break;
				default: rz_warn_if_reached();
				}
				pj_end(j);
			}

			if (!filtered) {
				rz_json_to_pj(body, j, true);
			}
		}

		pj_end(j);
		sdb_set(fn_db, k, pj_string(j));
		pj_free(j);
		rz_json_free(fn_j);
	}
	return true;
}

RZ_API bool rz_project_migrate_v13_v14(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *analysis_db;
	RZ_SERIALIZE_SUB(core_db, analysis_db, res, "analysis", return false;);
	Sdb *fn_db = sdb_ns(analysis_db, "functions", true);
	sdb_foreach(fn_db, v13_v14_foreach_cb, fn_db);
	return true;
}

// --
// Migration 14 -> 15
//
// Changes from 0867fd9d3db6f816eaa768f464c6a2919f21209c:
//	Added serialization functionality for seek history
//	New namespace: /core/seek

RZ_API bool rz_project_migrate_v14_v15(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	sdb_ns(core_db, "seek", true);

	return true;
}

// --
// Migration 15 -> 16
//
// Changes from f9422ac0cd6922f73208e5f5e6f47b3d64b3bd0d:
//	Removed options:
//	- `bin.maxstr`
//	Renamed options:
//	- `bin.minstr` to `str.search.min_length`
//	- `bin.str.enc` to `str.search.encoding`
//	- `bin.maxstrbuf` to `str.search.buffer_size`

RZ_API bool rz_project_migrate_v15_v16(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	sdb_rename(config_db, "bin.minstr", "str.search.min_length");
	sdb_rename(config_db, "bin.str.enc", "str.search.encoding");
	sdb_rename(config_db, "bin.maxstrbuf", "str.search.buffer_size");
	sdb_unset(config_db, "bin.maxstr");

	return true;
}

// --
// Migration 16 -> 17
//
// Changes from <commit hash not yet known>:
//	Removed /core/flags/base key (RzFlag.base)

RZ_API bool rz_project_migrate_v16_v17(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *flags_db;
	RZ_SERIALIZE_SUB(core_db, flags_db, res, "flags", return false;);
	sdb_unset(flags_db, "base");
	return true;
}

// --
// Migration 17 -> 18
//
// Changes from <commit hash not yet known>:
//	Removed:
//	- "rop.sdb"
//	- "rop.db"
//	Set:
//	- "rop.cache"

RZ_API bool rz_project_migrate_v17_v18(RzProject *prj, RzSerializeResultInfo *res) {
	Sdb *core_db;
	RZ_SERIALIZE_SUB(prj, core_db, res, "core", return false;);
	Sdb *config_db;
	RZ_SERIALIZE_SUB(core_db, config_db, res, "config", return false;);
	sdb_unset(config_db, "rop.sdb");
	sdb_unset(config_db, "rop.db");
	sdb_set(config_db, "rop.cache", false);
	return true;
}

static bool (*const migrations[])(RzProject *prj, RzSerializeResultInfo *res) = {
	rz_project_migrate_v1_v2,
	rz_project_migrate_v2_v3,
	rz_project_migrate_v3_v4,
	rz_project_migrate_v4_v5,
	rz_project_migrate_v5_v6,
	rz_project_migrate_v6_v7,
	rz_project_migrate_v7_v8,
	rz_project_migrate_v8_v9,
	rz_project_migrate_v9_v10,
	rz_project_migrate_v10_v11,
	rz_project_migrate_v11_v12,
	rz_project_migrate_v12_v13,
	rz_project_migrate_v13_v14,
	rz_project_migrate_v14_v15,
	rz_project_migrate_v15_v16,
	rz_project_migrate_v16_v17,
	rz_project_migrate_v17_v18
};

/// Migrate the given project to the current version in-place
RZ_API bool rz_project_migrate(RzProject *prj, unsigned long version, RzSerializeResultInfo *res) {
	RZ_STATIC_ASSERT(RZ_ARRAY_SIZE(migrations) + 1 == RZ_PROJECT_VERSION);
	while (version < RZ_PROJECT_VERSION) {
		bool succ = migrations[version - 1](prj, res);
		if (!succ) {
			rz_list_push(res, rz_str_newf("project migration from version %lu to %lu failed.", version, version + 1));
			return false;
		}
		rz_list_push(res, rz_str_newf("project migrated from version %lu to %lu.", version, version + 1));
		version++;
	}
	return true;
}
