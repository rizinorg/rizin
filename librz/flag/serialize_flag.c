// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_flag.h>

/*
 * SDB Format:
 *
 * /
 *   realnames=<realnames?"1":"0">
 *   /spaces
 *     see spaces.c
 *   /tags
 *     like RzFlag.tags
 *   /zones
 *     <zone name>={"from":<from>,"to":<to>}
 *   /flags
 *     <flag name>={"realname":<str>,"demangled":<bool>,"offset":<uint>,"size":<uint>,"space":<str>,"color":<str>,"comment":<str>,"alias":<str>}
 */

RZ_API void rz_serialize_flag_zones_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzList /*<RzFlagZoneItem *>*/ *zones) {
	RzListIter *it;
	RzFlagZoneItem *item;
	rz_list_foreach (zones, it, item) {
		PJ *j = pj_new();
		if (!j) {
			return;
		}
		pj_o(j);
		pj_kn(j, "from", item->from);
		pj_kn(j, "to", item->to);
		pj_end(j);
		sdb_set(db, item->name, pj_string(j), 0);
		pj_free(j);
	}
}

static bool zone_load_cb(void *user, const SdbKv *kv) {
	RzList *list = user;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json) {
		free(json_str);
		return true;
	}
	if (json->type != RZ_JSON_OBJECT) {
		goto beach;
	}
	const RzJson *child;
	RzFlagZoneItem *item = RZ_NEW0(RzFlagZoneItem);
	if (!item) {
		goto beach;
	}
	item->name = strdup(sdbkv_key(kv));
	if (!item->name) {
		free(item);
		goto beach;
	}
	for (child = json->children.first; child; child = child->next) {
		if (child->type != RZ_JSON_INTEGER) {
			continue;
		}
		if (strcmp(child->key, "from") == 0) {
			item->from = child->num.u_value;
		} else if (strcmp(child->key, "to") == 0) {
			item->to = child->num.u_value;
		}
	}
	rz_list_append(list, item);
beach:
	rz_json_free(json);
	free(json_str);
	return true;
}

RZ_API bool rz_serialize_flag_zones_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzList /*<RzFlagZoneItem *>*/ *zones, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(zones, false);
	rz_list_purge(zones);
	bool r = sdb_foreach(db, zone_load_cb, zones);
	if (!r) {
		RZ_SERIALIZE_ERR(res, "failed to parse a flag zone json");
	}
	return r;
}

static bool flag_save_cb(RzFlagItem *flag, void *user) {
	Sdb *db = user;
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_o(j);
	if (flag->realname) {
		pj_ks(j, "realname", flag->realname);
	}
	pj_kb(j, "demangled", flag->demangled);
	pj_kn(j, "offset", flag->offset);
	pj_kn(j, "size", flag->size);
	if (flag->space) {
		pj_ks(j, "space", flag->space->name);
	}
	if (flag->color) {
		pj_ks(j, "color", flag->color);
	}
	if (flag->comment) {
		pj_ks(j, "comment", flag->comment);
	}
	if (flag->alias) {
		pj_ks(j, "alias", flag->alias);
	}
	pj_end(j);
	sdb_set(db, flag->name, pj_string(j), 0);
	pj_free(j);
	return true;
}

RZ_API void rz_serialize_flag_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag) {
	rz_serialize_spaces_save(sdb_ns(db, "spaces", true), &flag->spaces);
	sdb_set(db, "realnames", flag->realnames ? "1" : "0", 0);
	sdb_copy(flag->tags, sdb_ns(db, "tags", true));
	rz_serialize_flag_zones_save(sdb_ns(db, "zones", true), flag->zones);
	rz_flag_foreach(flag, flag_save_cb, sdb_ns(db, "flags", true));
}

typedef enum {
	FLAG_FIELD_REALNAME,
	FLAG_FIELD_DEMANGLED,
	FLAG_FIELD_OFFSET,
	FLAG_FIELD_SIZE,
	FLAG_FIELD_SPACE,
	FLAG_FIELD_COLOR,
	FLAG_FIELD_COMMENT,
	FLAG_FIELD_ALIAS
} FlagField;

typedef struct {
	RzFlag *flag;
	RzKeyParser *parser;
} FlagLoadCtx;

static bool flag_load_cb(void *user, const SdbKv *kv) {
	FlagLoadCtx *ctx = user;

	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	RzFlagItem proto = { 0 };
	bool offset_set = false;
	bool size_set = false;

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case FLAG_FIELD_REALNAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.realname = (char *)child->str_value;
			break;
		case FLAG_FIELD_DEMANGLED:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			proto.demangled = child->num.u_value != 0;
			break;
		case FLAG_FIELD_OFFSET:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.offset = child->num.u_value;
			offset_set = true;
			break;
		case FLAG_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.size = child->num.u_value;
			size_set = true;
			break;
		case FLAG_FIELD_SPACE:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.space = rz_flag_space_get(ctx->flag, child->str_value);
			break;
		case FLAG_FIELD_COLOR:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.color = (char *)child->str_value;
			break;
		case FLAG_FIELD_COMMENT:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.comment = (char *)child->str_value;
			break;
		case FLAG_FIELD_ALIAS:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.alias = (char *)child->str_value;
			break;
		default:
			break;
	});

	bool res = true;
	if (!offset_set || !size_set) {
		res = false;
		goto beach;
	}

	RzFlagItem *item = rz_flag_set(ctx->flag, sdbkv_key(kv), proto.offset, proto.size);
	if (proto.realname) {
		rz_flag_item_set_realname(item, proto.realname);
	}
	item->demangled = proto.demangled;
	item->space = proto.space;
	if (proto.color) {
		rz_flag_item_set_color(item, proto.color);
	}
	if (proto.comment) {
		rz_flag_item_set_comment(item, proto.comment);
	}
	if (proto.alias) {
		rz_flag_item_set_alias(item, proto.alias);
	}

beach:
	rz_json_free(json);
	free(json_str);
	return res;
}

static bool load_flags(RZ_NONNULL Sdb *flags_db, RZ_NONNULL RzFlag *flag) {
	FlagLoadCtx ctx = { flag, rz_key_parser_new() };
	if (!ctx.parser) {
		return false;
	}
	rz_key_parser_add(ctx.parser, "realname", FLAG_FIELD_REALNAME);
	rz_key_parser_add(ctx.parser, "demangled", FLAG_FIELD_DEMANGLED);
	rz_key_parser_add(ctx.parser, "offset", FLAG_FIELD_OFFSET);
	rz_key_parser_add(ctx.parser, "size", FLAG_FIELD_SIZE);
	rz_key_parser_add(ctx.parser, "space", FLAG_FIELD_SPACE);
	rz_key_parser_add(ctx.parser, "color", FLAG_FIELD_COLOR);
	rz_key_parser_add(ctx.parser, "comment", FLAG_FIELD_COMMENT);
	rz_key_parser_add(ctx.parser, "alias", FLAG_FIELD_ALIAS);
	bool r = sdb_foreach(flags_db, flag_load_cb, &ctx);
	rz_key_parser_free(ctx.parser);
	return r;
}

RZ_API bool rz_serialize_flag_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_flag_unset_all(flag);

	const char *str = sdb_const_get(db, "realnames", 0);
	if (!str) {
		RZ_SERIALIZE_ERR(res, "flag realnames key is missing");
		return false;
	}
	flag->realnames = strtoul(str, NULL, 0) ? true : false;

	Sdb *spaces_db = sdb_ns(db, "spaces", false);
	if (!spaces_db) {
		RZ_SERIALIZE_ERR(res, "missing spaces namespace");
		return false;
	}
	if (!rz_serialize_spaces_load(spaces_db, &flag->spaces, false, res)) {
		return false;
	}

	Sdb *tags_db = sdb_ns(db, "tags", false);
	if (!tags_db) {
		RZ_SERIALIZE_ERR(res, "missing tags namespace");
		return false;
	}
	sdb_copy(tags_db, flag->tags);

	Sdb *zones_db = sdb_ns(db, "zones", false);
	if (!zones_db) {
		RZ_SERIALIZE_ERR(res, "missing zones namespace");
		return false;
	}
	rz_flag_zone_reset(flag);
	if (!rz_serialize_flag_zones_load(zones_db, flag->zones, res)) {
		return false;
	}

	Sdb *flags_db = sdb_ns(db, "flags", false);
	if (!flags_db) {
		RZ_SERIALIZE_ERR(res, "missing flags sub-namespace");
		return false;
	}
	if (!load_flags(flags_db, flag)) {
		RZ_SERIALIZE_ERR(res, "failed to parse a flag json");
		return false;
	}

	return true;
}
