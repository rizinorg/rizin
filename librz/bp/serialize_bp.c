// SPDX-FileCopyrightText: 2021 DMaroo <dhruvsmaroo@gmail.com>
// SPDX-License-Identifier: LPGL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_bp.h>

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
		pj_kn(j, "addr", bp_item->addr);
		pj_ks(j, "bbytes", (char *)bp_item->bbytes);
		pj_ks(j, "cond", bp_item->cond);
		pj_ks(j, "data", bp_item->data);
		pj_kn(j, "delta", bp_item->delta);
		pj_ki(j, "enabled", bp_item->enabled);
		pj_ks(j, "expr", bp_item->expr);
		pj_ki(j, "hits", bp_item->hits);
		pj_ki(j, "hw", bp_item->hw);
		pj_ki(j, "internal", bp_item->internal);
		pj_kN(j, "module_delta", bp_item->module_delta);
		pj_ks(j, "module_name", bp_item->module_name);
		pj_ks(j, "obytes", (char *)bp_item->obytes);
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
		sdb_set(db, bp_item->name, pj_string(j), 0);
		pj_free(j);
	}
}

static bool bp_load_cb(void *user, const char *k, const char *v) {
	RzList *list = user;
	char *json_str = strdup(v);
	if (!json_str) {
		return true;
	}

	RzJson *json = rz_json_parse(json_str);
	if (!json) {
		free(json_str);
		return true;
	}
	if (json->type != RZ_JSON_OBJECT) {
		goto return_goto;
	}

	const RzJson *child;
	RzBreakpointItem *bp_item = RZ_NEW0(RzBreakpointItem);
	if (!bp_item) {
		goto return_goto;
	}
	bp_item->name = strdup(k);

	for (child = json->children.first; child; child = child->next) {
		if (child->type == RZ_JSON_INTEGER) {
			if (strcmp(child->key, "addr") == 0) {
				bp_item->addr = child->num.u_value;
			} else if (strcmp(child->key, "delta") == 0) {
				bp_item->delta = child->num.u_value;
			} else if (strcmp(child->key, "enabled") == 0) {
				bp_item->enabled = child->num.s_value;
			} else if (strcmp(child->key, "hits") == 0) {
				bp_item->hits = child->num.s_value;
			} else if (strcmp(child->key, "hw") == 0) {
				bp_item->hw = child->num.s_value;
			} else if (strcmp(child->key, "internal") == 0) {
				bp_item->internal = child->num.s_value;
			} else if (strcmp(child->key, "module_delta") == 0) {
				bp_item->module_delta = child->num.s_value;
			} else if (strcmp(child->key, "perm") == 0) {
				bp_item->perm = child->num.s_value;
			} else if (strcmp(child->key, "size") == 0) {
				bp_item->size = child->num.s_value;
			} else if (strcmp(child->key, "togglehits") == 0) {
				bp_item->togglehits = child->num.s_value;
			} else if (strcmp(child->key, "trace") == 0) {
				bp_item->trace = child->num.s_value;
			}
		} else if (child->type == RZ_JSON_BOOLEAN) {
			if (strcmp(child->key, "swstep") == 0) {
				bp_item->swstep = child->num.u_value ? true : false;
			}
		} else if (child->type == RZ_JSON_STRING) {
			if (strcmp(child->key, "bbytes") == 0) {
				bp_item->bbytes = (unsigned char *)strdup(child->str_value);
			} else if (strcmp(child->key, "cond") == 0) {
				bp_item->cond = strdup(child->str_value);
			} else if (strcmp(child->key, "data") == 0) {
				bp_item->data = strdup(child->str_value);
			} else if (strcmp(child->key, "expr") == 0) {
				bp_item->expr = strdup(child->str_value);
			} else if (strcmp(child->key, "module_name") == 0) {
				bp_item->module_name = strdup(child->str_value);
			} else if (strcmp(child->key, "obytes") == 0) {
				bp_item->obytes = (unsigned char *)strdup(child->str_value);
			}
		} else if (child->type == RZ_JSON_ARRAY) {
			if (strcmp(child->key, "pids") == 0) {
				int index = 0;
				for (const RzJson *pid_child = child->children.first; pid_child; pid_child = pid_child->next) {
					if (index >= RZ_BP_MAXPIDS) {
						break;
					}
					bp_item->pids[index] = pid_child->num.s_value;
					++index;
				}
			}
		}
	}
	rz_list_append(list, bp_item);

return_goto:
	rz_json_free(json);
	free(json_str);
	return true;
}

RZ_API bool rz_serialize_bp_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzBreakpoint *bp, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && bp, false);

	RzList *bp_list = bp->bps;
	rz_list_purge(bp_list);
	bool ret = sdb_foreach(db, bp_load_cb, bp_list);
	if (!ret) {
		RZ_SERIALIZE_ERR(res, "failed to parse a breakpoint json");
	}
	return ret;
}
