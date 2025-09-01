// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_assert.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_mark.h>

/*
 * SDB Format:
 *
 *   /marks
 *     <mark name>={"realname":<str>,"from":<uint>,"to":<uint>,"color":<str>,"comment":<str>,}
 */

static bool mark_save_cb(RzMarkItem *bm, void *user) {
	Sdb *db = user;
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_o(j);
	if (bm->realname) {
		pj_ks(j, "realname", bm->realname);
	}
	pj_kn(j, "from", bm->from);
	pj_kn(j, "to", bm->to);
	if (bm->color) {
		pj_ks(j, "color", bm->color);
	}
	if (bm->comment) {
		pj_ks(j, "comment", bm->comment);
	}
	pj_end(j);
	sdb_set(db, bm->name, pj_string(j));
	pj_free(j);
	return true;
}

/**
 * \brief Save marks to a database.
 *
 * Serializes all marks from the given container \p bm into the namespace
 * "marks" within the database \p db.
 *
 * \param db Database to save into.
 * \param bm Mark container to serialize.
 */
RZ_API void rz_serialize_mark_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzMark *bm) {
	rz_return_if_fail(db && bm);
	rz_mark_foreach(bm, mark_save_cb, sdb_ns(db, "marks", true));
}

typedef enum {
	BOOKMARK_FIELD_REALNAME,
	BOOKMARK_FIELD_FROM,
	BOOKMARK_FIELD_TO,
	BOOKMARK_FIELD_COLOR,
	BOOKMARK_FIELD_COMMENT,
} MarkField;

typedef struct {
	RzMark *mark;
	RzKeyParser *parser;
} MarkLoadCtx;

static bool marks_load_cb(void *user, const SdbKv *kv) {
	MarkLoadCtx *ctx = user;

	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		free(json_str);
		return false;
	}

	RzMarkItem proto = { 0 };
	bool offset_set = false;
	bool size_set = false;

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case BOOKMARK_FIELD_REALNAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.realname = (char *)child->str_value;
			break;
		case BOOKMARK_FIELD_FROM:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.from = child->num.u_value;
			offset_set = true;
			break;
		case BOOKMARK_FIELD_TO:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			proto.to = child->num.u_value;
			size_set = true;
			break;
		case BOOKMARK_FIELD_COLOR:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.color = (char *)child->str_value;
			break;
		case BOOKMARK_FIELD_COMMENT:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			proto.comment = (char *)child->str_value;
			break;
		default:
			break;
	});

	bool res = true;
	if (!offset_set || !size_set) {
		res = false;
		goto beach;
	}

	RzMarkItem *item = rz_mark_set(ctx->mark, sdbkv_key(kv), proto.from, proto.to);
	if (proto.realname) {
		rz_mark_item_set_realname(item, proto.realname);
	}
	if (proto.color) {
		rz_mark_item_set_color(item, proto.color);
	}
	if (proto.comment) {
		rz_mark_item_set_comment(item, proto.comment);
	}
beach:
	rz_json_free(json);
	free(json_str);
	return res;
}

static bool load_marks(RZ_NONNULL Sdb *marks_db, RZ_NONNULL RzMark *bm) {
	MarkLoadCtx ctx = { bm, rz_key_parser_new() };
	if (!ctx.parser) {
		return false;
	}
	rz_key_parser_add(ctx.parser, "realname", BOOKMARK_FIELD_REALNAME);
	rz_key_parser_add(ctx.parser, "from", BOOKMARK_FIELD_FROM);
	rz_key_parser_add(ctx.parser, "to", BOOKMARK_FIELD_TO);
	rz_key_parser_add(ctx.parser, "color", BOOKMARK_FIELD_COLOR);
	rz_key_parser_add(ctx.parser, "comment", BOOKMARK_FIELD_COMMENT);
	bool r = sdb_foreach(marks_db, marks_load_cb, &ctx);
	rz_key_parser_free(ctx.parser);
	return r;
}

/**
 * \brief Load marks from a database.
 *
 * Clears all existing marks in \p bm and loads marks from the namespace
 * "marks" within the database \p db.
 *
 * \param db Database to load from.
 * \param bm Mark container to populate.
 * \param res Optional result info structure for reporting errors, may be NULL.
 * \return True if loading succeeded. False if an error occurred.
 *
 * \note If no "marks" namespace exists, this is treated as an empty set
 *       of marks (not an error).
 */
RZ_API bool rz_serialize_mark_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzMark *bm, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && bm, false);
	rz_mark_unset_all(bm);

	Sdb *marks_db = sdb_ns(db, "marks", false);
	if (!marks_db) {
		// Old project, no marks saved -> treat as empty, not an error
		return true;
	}
	if (!load_marks(marks_db, bm)) {
		RZ_SERIALIZE_ERR(res, "failed to parse mark json");
		return false;
	}
	return true;
}
