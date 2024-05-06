// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_bp.h>

/**
 * \brief serialize and save the breakpoints in a sdb
 *
 * \param db sdb to save the breakpoints
 * \param bp RzBreakpoint instance to serialize and save
 */
RZ_API void rz_serialize_bp_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzBreakpoint *bp) {
	rz_return_if_fail(db && bp);

	RzListIter *iter;
	RzBreakpointItem *bp_item;
	rz_list_foreach (bp->bps, iter, bp_item) {
		PJ *j = pj_new();
		if (!j) {
			return;
		}
		pj_o(j);
		if (bp_item->cond) {
			pj_ks(j, "cond", bp_item->cond);
		}
		if (bp_item->data) {
			pj_ks(j, "data", bp_item->data);
		}
		pj_kn(j, "delta", bp_item->delta);
		pj_ki(j, "enabled", bp_item->enabled);
		if (bp_item->expr) {
			pj_ks(j, "expr", bp_item->expr);
		}
		pj_ki(j, "hits", bp_item->hits);
		pj_ki(j, "hw", bp_item->hw);
		pj_ki(j, "internal", bp_item->internal);
		pj_kN(j, "module_delta", bp_item->module_delta);
		if (bp_item->module_name) {
			pj_ks(j, "module_name", bp_item->module_name);
		}
		if (bp_item->name) {
			pj_ks(j, "name", bp_item->name);
		}
		pj_ki(j, "perm", bp_item->perm);

		pj_ka(j, "pids");
		for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
			pj_i(j, bp_item->pids[i]);
		}
		pj_end(j);

		pj_ki(j, "size", bp_item->size);
		pj_kb(j, "swstep", bp_item->swstep);
		pj_ki(j, "togglehits", bp_item->togglehits);
		pj_ki(j, "trace", bp_item->trace);
		pj_end(j);

		char key[19];
		sdb_set(db, rz_strf(key, "0x%" PFMT64x, bp_item->addr), pj_string(j), 0);
		pj_free(j);
	}
}

enum {
	BP_FIELD_NAME,
	BP_FIELD_MODULE_NAME,
	BP_FIELD_MODULE_DELTA,
	BP_FIELD_DELTA,
	BP_FIELD_SIZE,
	BP_FIELD_SWSTEP,
	BP_FIELD_PERM,
	BP_FIELD_HW,
	BP_FIELD_TRACE,
	BP_FIELD_INTERNAL,
	BP_FIELD_ENABLED,
	BP_FIELD_TOGGLEHITS,
	BP_FIELD_HITS,
	BP_FIELD_PIDS,
	BP_FIELD_DATA,
	BP_FIELD_COND,
	BP_FIELD_EXPR
};

/**
 * \brief Create a new RzSerializeBpParser instance
 *
 * \return NULL if fail, new instance otherwise
 */
RZ_API RzSerializeBpParser rz_serialize_bp_parser_new(void) {
	RzSerializeBpParser parser = rz_key_parser_new();
	if (!parser) {
		return NULL;
	}

	rz_key_parser_add(parser, "name", BP_FIELD_NAME);
	rz_key_parser_add(parser, "module_name", BP_FIELD_MODULE_NAME);
	rz_key_parser_add(parser, "module_delta", BP_FIELD_MODULE_DELTA);
	rz_key_parser_add(parser, "delta", BP_FIELD_DELTA);
	rz_key_parser_add(parser, "size", BP_FIELD_SIZE);
	rz_key_parser_add(parser, "swstep", BP_FIELD_SWSTEP);
	rz_key_parser_add(parser, "perm", BP_FIELD_PERM);
	rz_key_parser_add(parser, "hw", BP_FIELD_HW);
	rz_key_parser_add(parser, "trace", BP_FIELD_TRACE);
	rz_key_parser_add(parser, "internal", BP_FIELD_INTERNAL);
	rz_key_parser_add(parser, "enabled", BP_FIELD_ENABLED);
	rz_key_parser_add(parser, "togglehits", BP_FIELD_TOGGLEHITS);
	rz_key_parser_add(parser, "hits", BP_FIELD_HITS);
	rz_key_parser_add(parser, "pids", BP_FIELD_PIDS);
	rz_key_parser_add(parser, "data", BP_FIELD_DATA);
	rz_key_parser_add(parser, "cond", BP_FIELD_COND);
	rz_key_parser_add(parser, "expr", BP_FIELD_EXPR);

	return parser;
}

typedef struct {
	RzBreakpoint *bp;
	RzSerializeBpParser parser;
} BpLoadCtx;

static bool bp_load_cb(void *user, const SdbKv *kv) {
	bool ret = false;
	BpLoadCtx *ctx = user;
	char *json_str = sdbkv_dup_value(kv);
	if (!json_str) {
		return true;
	}
	RzJson *json = rz_json_parse(json_str);
	if (!json || json->type != RZ_JSON_OBJECT) {
		goto heaven;
	}
	RzBreakpointItem bp_item_temp = { 0 };
	bp_item_temp.addr = strtoull(sdbkv_key(kv), NULL, 0);

	RZ_KEY_PARSER_JSON(ctx->parser, json, child, {
		case BP_FIELD_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			bp_item_temp.name = (char *)child->str_value;
			break;
		case BP_FIELD_MODULE_NAME:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			bp_item_temp.module_name = (char *)child->str_value;
			break;
		case BP_FIELD_MODULE_DELTA:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.module_delta = child->num.s_value;
			break;
		case BP_FIELD_DELTA:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.delta = child->num.u_value;
			break;
		case BP_FIELD_SIZE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.size = (int)child->num.s_value;
			break;
		case BP_FIELD_SWSTEP:
			if (child->type != RZ_JSON_BOOLEAN) {
				break;
			}
			bp_item_temp.swstep = child->num.u_value ? true : false;
			break;
		case BP_FIELD_PERM:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.perm = (int)child->num.s_value;
			break;
		case BP_FIELD_HW:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.hw = (int)child->num.s_value;
			break;
		case BP_FIELD_TRACE:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.trace = (int)child->num.s_value;
			break;
		case BP_FIELD_INTERNAL:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.internal = (int)child->num.s_value;
			break;
		case BP_FIELD_ENABLED:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.enabled = (int)child->num.s_value;
			break;
		case BP_FIELD_TOGGLEHITS:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.togglehits = (int)child->num.s_value;
			break;
		case BP_FIELD_HITS:
			if (child->type != RZ_JSON_INTEGER) {
				break;
			}
			bp_item_temp.hits = (int)child->num.s_value;
			break;
		case BP_FIELD_PIDS:
			if (child->type != RZ_JSON_ARRAY) {
				break;
			}
			int index = 0;
			for (const RzJson *pid_child = child->children.first; pid_child; pid_child = pid_child->next) {
				if (index >= RZ_BP_MAXPIDS) {
					break;
				}
				bp_item_temp.pids[index] = (int)pid_child->num.s_value;
				++index;
			}
			break;
		case BP_FIELD_DATA:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			bp_item_temp.data = (char *)child->str_value;
			break;
		case BP_FIELD_COND:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			bp_item_temp.cond = (char *)child->str_value;
			break;
		case BP_FIELD_EXPR:
			if (child->type != RZ_JSON_STRING) {
				break;
			}
			bp_item_temp.expr = (char *)child->str_value;
			break;
	})

	RzBreakpointItem *bp_item = NULL;
	if (bp_item_temp.hw) {
		bp_item = rz_bp_add_hw(ctx->bp, bp_item_temp.addr, bp_item_temp.size, bp_item_temp.perm);
	} else {
		bp_item = rz_bp_add_sw(ctx->bp, bp_item_temp.addr, bp_item_temp.size, bp_item_temp.perm);
	}
	if (!bp_item) {
		goto beach;
	}

	if (bp_item_temp.name) {
		bp_item->name = strdup(bp_item_temp.name);
	}
	if (bp_item_temp.module_name) {
		bp_item->module_name = strdup(bp_item_temp.module_name);
	}
	bp_item->module_delta = bp_item_temp.module_delta;
	bp_item->delta = bp_item_temp.delta;
	bp_item->swstep = bp_item_temp.swstep;
	bp_item->hw = bp_item_temp.hw;
	bp_item->trace = bp_item_temp.trace;
	bp_item->internal = bp_item_temp.internal;
	bp_item->enabled = bp_item_temp.enabled;
	bp_item->togglehits = bp_item_temp.togglehits;
	bp_item->hits = bp_item_temp.hits;
	for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
		bp_item->pids[i] = bp_item_temp.pids[i];
	}
	if (bp_item_temp.data) {
		bp_item->data = strdup(bp_item_temp.data);
	}
	if (bp_item_temp.cond) {
		bp_item->cond = strdup(bp_item_temp.cond);
	}
	if (bp_item_temp.expr) {
		bp_item->expr = strdup(bp_item_temp.expr);
	}
	ret = true;

beach:
	rz_json_free(json);
heaven:
	free(json_str);
	return ret;
}

/**
 * \brief Load a serialized breakpoints to a RzBreakpoint instance
 *
 * \param db sdb to load the breakpoints from
 * \param bp RzBreakpoint instance to load the deserialized breakpoints
 * \param res RzSerializeResultInfo to store info/errors/warnings
 * \return true if successful, false otherwise
 */
RZ_API bool rz_serialize_bp_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzBreakpoint *bp, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && bp, false);

	bool ret = false;
	RzSerializeBpParser bp_parser = rz_serialize_bp_parser_new();
	if (!bp_parser) {
		goto heaven;
	}
	if (!rz_list_empty(bp->bps) && !rz_bp_del_all(bp)) {
		goto heaven;
	}

	BpLoadCtx ctx = {
		.bp = bp,
		.parser = bp_parser
	};
	ret = sdb_foreach(db, bp_load_cb, &ctx);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "failed to parse a breakpoint json");
	}

heaven:
	rz_key_parser_free(bp_parser);
	return ret;
}
