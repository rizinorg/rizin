// SPDX-FileCopyrightText: 2026 Parth Naik <parthnaik.office@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_util/rz_serialize.h>

/*
 * SDB Format:
 *
 *   /macros
 *     <macro name>={"args":<str list>,"code":<str>}
 */

static bool macro_save_cb(RZ_UNUSED RzCmd *cmd, const RzCmdMacro *macro, void *user) {
	Sdb *db = user;
	PJ *j = pj_new();
	if (!j) {
		return false;
	}

	pj_o(j);
	pj_ka(j, "args");
	for (size_t i = 0; i < macro->nargs; i++) {
		pj_s(j, macro->args[i]);
	}
	pj_end(j);
	pj_ks(j, "code", macro->code);
	pj_end(j);
	bool ret = sdb_set(db, macro->name, pj_string(j));
	pj_free(j);
	return ret;
}

RZ_API void rz_serialize_macros_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzCmd *cmd) {
	rz_return_if_fail(db && cmd);
	rz_cmd_macro_foreach(cmd, macro_save_cb, db);
}

static bool macro_load_cb(void *user, const SdbKv *kv) {
	RzCmd *cmd = user;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return false;
	}

	bool result = false;
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto beach;
	}

	const RzJson *args_json = rz_json_get(json, "args");
	const RzJson *code_json = rz_json_get(json, "code");
	if (!args_json || args_json->type != RZ_JSON_ARRAY ||
		!code_json || code_json->type != RZ_JSON_STRING) {
		goto beach;
	}

	const char **args = RZ_NEWS0(const char *, args_json->children.count + 1);
	if (!args) {
		goto beach;
	}
	for (size_t i = 0; i < args_json->children.count; i++) {
		const RzJson *arg = rz_json_item(args_json, i);
		if (!arg || arg->type != RZ_JSON_STRING) {
			free(args);
			goto beach;
		}
		args[i] = arg->str_value;
	}

	result = rz_cmd_macro_add(cmd, sdbkv_key(kv), args, code_json->str_value);
	free(args);

beach:
	rz_json_free(json);
	free(json_str);
	return result;
}

RZ_API bool rz_serialize_macros_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzCmd *cmd, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && cmd, false);
	bool result = sdb_foreach(db, macro_load_cb, cmd);
	if (!result) {
		RZ_SERIALIZE_ERR(res, "failed to parse macro json");
	}
	return result;
}
