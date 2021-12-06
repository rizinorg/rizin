// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "../core_private.h"

#define SYNC_READ(type, failed) \
	do { \
		failed = false; \
		if (sync_cb && !sync_cb(core, type, false)) { \
			RZ_LOG_ERROR("Failed to read registers.\n"); \
			failed = true; \
		} \
	} while (0)
#define SYNC_READ_LIST(ritems, failed) \
	do { \
		failed = false; \
		if (rz_list_length(ritems) == 1) { \
			SYNC_READ(((RzRegItem *)rz_list_head(ritems))->type, failed); \
		} else if (rz_list_length(ritems) > 1) { \
			SYNC_READ(RZ_REG_TYPE_ANY, failed); \
		} \
	} while (0)
#define SYNC_WRITE(type, failed) \
	do { \
		failed = false; \
		if (sync_cb && !sync_cb(core, type, true)) { \
			RZ_LOG_ERROR("Failed to write registers.\n"); \
			failed = true; \
		} \
		rz_core_reg_update_flags(core); \
	} while (0)

static RzList *filter_reg_items(RzReg *reg, RZ_NULLABLE const char *filter) {
	rz_return_val_if_fail(reg, NULL);
	// default
	if (RZ_STR_ISEMPTY(filter)) {
		// default selection (only gpr, omit smaller regs that are fully covered by larger ones)
		return rz_reg_filter_items_covered(reg->regset[RZ_REG_TYPE_GPR].regs);
	}
	// all
	if (!strcmp(filter, "all")) {
		return rz_list_clone(reg->allregs);
	}
	// bit size
	char *end = NULL;
	unsigned long bits = strtoul(filter, &end, 0);
	if (!*end) {
		RzList *ret = rz_list_new();
		if (!ret) {
			return NULL;
		}
		RzListIter *iter;
		RzRegItem *ri;
		rz_list_foreach (reg->regset[RZ_REG_TYPE_GPR].regs, iter, ri) {
			if (ri->size == bits) {
				rz_list_push(ret, ri);
			}
		}
		return ret;
	}
	// type
	int type = rz_reg_type_by_name(filter);
	if (type >= 0) {
		return rz_list_clone(reg->regset[type].regs);
	}
	int role = rz_reg_role_by_name(filter);
	if (role >= 0) {
		const char *itemname = rz_reg_get_name(reg, role);
		if (!itemname) {
			return NULL;
		}
		filter = itemname; // fallthrough to the below query with the resolved reg name
	}
	// single register name
	RzRegItem *ri = rz_reg_get(reg, filter, RZ_REG_TYPE_ANY);
	if (!ri) {
		return NULL;
	}
	return rz_list_new_from_array((const void **)&ri, 1);
}

/// Format the value of a register as a nice hex string
static void format_reg_value(RzReg *reg, RzRegItem *item, char *out, size_t out_size) {
	// TODO: This could be done much nicer with RzBitVector, but it's not in RzUtil yet :-(
	if (item->size < 80) {
		ut64 value = rz_reg_get_value(reg, item);
		snprintf(out, out_size, "0x%08" PFMT64x, value);
	} else {
		utX valueBig;
		rz_reg_get_value_big(reg, item, &valueBig);
		switch (item->size) {
		case 80:
			snprintf(out, out_size, "0x%04x%016" PFMT64x "", valueBig.v80.High, valueBig.v80.Low);
			break;
		case 96:
			snprintf(out, out_size, "0x%08x%016" PFMT64x "", valueBig.v96.High, valueBig.v96.Low);
			break;
		case 128:
			snprintf(out, out_size, "0x%016" PFMT64x "%016" PFMT64x "", valueBig.v128.High, valueBig.v128.Low);
			break;
		case 256:
			snprintf(out, out_size, "0x%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "",
				valueBig.v256.High.High, valueBig.v256.High.Low, valueBig.v256.Low.High, valueBig.v256.Low.Low);
			break;
		default:
			snprintf(out, out_size, "ERROR");
		}
	}
}

/// Check whether the given item's value has changed in the last step
static bool reg_has_changed(RzReg *reg, RzRegItem *item) {
	ut64 value = rz_reg_get_value(reg, item);
	rz_reg_arena_swap(reg, false);
	ut64 old = rz_reg_get_value(reg, item);
	rz_reg_arena_swap(reg, false);
	return old != value;
}

static void print_reg_not_found(const char *arg) {
	RZ_LOG_ERROR("No such register or register type: \"%s\"\n", rz_str_get(arg));
}

/**
 * \brief (Sub)handler for register assignments like reg=0x42
 * \param arg the full argument string, like "reg = 0x42"
 * \param eq_pos index of the '=' in arg
 */
static RzCmdStatus assign_reg(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, RZ_NONNULL const char *arg, size_t eq_pos) {
	char *str = strdup(arg);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	str[eq_pos] = 0;
	char *val = str + eq_pos + 1;
	rz_str_trim(str);
	rz_str_trim(val);
	RzRegItem *ri = rz_reg_get(reg, str, RZ_REG_TYPE_ANY);
	if (!ri) {
		free(str);
		return RZ_CMD_STATUS_ERROR;
	}
	bool failed;
	SYNC_READ(ri->type, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 nval = rz_num_math(core->num, val);
	rz_reg_set_value(reg, ri, nval);
	SYNC_WRITE(ri->type, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

static const char *get_reg_color(RzCore *core, RzReg *reg, RzRegItem *item) {
	if (!rz_config_get_i(core->config, "scr.color")) {
		return NULL;
	}
	if (reg_has_changed(reg, item)) {
		return (core->cons && core->cons->context->pal.creg)
			? core->cons->context->pal.creg
			: Color_BWHITE;
	}
	return NULL;
}

static const char *get_reg_role_name(RzReg *reg, RzRegItem *item) {
	for (int i = 0; i < RZ_REG_NAME_LAST; i++) {
		const char *t = rz_reg_get_name(reg, i);
		if (t && !strcmp(t, item->name)) {
			return rz_reg_get_role(i);
		}
	}
	return NULL;
}

static RzCmdStatus show_regs_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, const char *filter, RzCmdStateOutput *state) {
	RzList *ritems = filter_reg_items(reg, filter);
	if (!ritems) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}

	bool failed;
	SYNC_READ_LIST(ritems, failed);
	if (failed) {
		rz_list_free(ritems);
		return RZ_CMD_STATUS_ERROR;
	}

	if (state->mode == RZ_OUTPUT_MODE_TABLE) {
		rz_table_set_columnsf(state->d.t, "ssXxs", "role", "name", "value", "size", "type");
	} else if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
	}

	RzListIter *iter;
	RzRegItem *item;
	char buf[256] = { 0 };
	rz_list_foreach (ritems, iter, item) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD: {
			format_reg_value(reg, item, buf, sizeof(buf));
			const char *color = get_reg_color(core, reg, item);
			if (color) {
				rz_cons_print(color);
			}
			rz_cons_printf("%s = %s", item->name, buf);
			if (color) {
				rz_cons_print(Color_RESET);
			}
			rz_cons_print("\n");
			break;
		}
		case RZ_OUTPUT_MODE_QUIET:
			format_reg_value(reg, item, buf, sizeof(buf));
			rz_cons_printf("%s\n", buf);
			break;
		case RZ_OUTPUT_MODE_RIZIN:
			format_reg_value(reg, item, buf, sizeof(buf));
			rz_cons_printf("ar %s = %s\n", item->name, buf);
			break;
		case RZ_OUTPUT_MODE_TABLE:
			rz_table_add_rowf(state->d.t, "ssXxs",
				rz_str_get(get_reg_role_name(reg, item)),
				item->name, rz_reg_get_value(reg, item), (ut64)item->size, rz_reg_get_type(item->type));
			break;
		case RZ_OUTPUT_MODE_JSON:
			if (item->size <= 64) {
				pj_kn(state->d.pj, item->name, rz_reg_get_value(reg, item));
			} else {
				format_reg_value(reg, item, buf, sizeof(buf));
				pj_ks(state->d.pj, item->name, buf);
			}
			break;
		default:
			break;
		}
	}
	rz_list_free(ritems);

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(state->d.pj);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *filter = argc > 1 ? argv[1] : NULL;

	// check if the argument is an assignment like reg=0x42
	if (filter) {
		char *eq = strchr(filter, '=');
		if (eq) {
			return assign_reg(core, reg, sync_cb, filter, eq - filter);
		}
	}

	// just show
	return show_regs_handler(core, reg, sync_cb, filter, state);
}

RZ_IPI RzCmdStatus rz_regs_columns_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	RzList *ritems = filter_reg_items(reg, filter);
	if (!ritems) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}

	bool failed;
	SYNC_READ_LIST(ritems, failed);
	if (failed) {
		rz_list_free(ritems);
		return RZ_CMD_STATUS_ERROR;
	}

	int cols = 4; // how many registers in a row
	int colwidth = 24;
	RzListIter *iter;
	RzRegItem *item;
	char whites[32], content[300];
	char strvalue[256] = { 0 };
	size_t idx = 0;
	rz_list_foreach (ritems, iter, item) {
		const char *color = get_reg_color(core, reg, item);
		if (color) {
			rz_cons_print(color);
		}
		format_reg_value(reg, item, strvalue, sizeof(strvalue));
		int len = snprintf(content, sizeof(content), "%7s %s", item->name, strvalue);
		if (len < 0) {
			break;
		}
		rz_cons_print(content);
		if (color) {
			rz_cons_print(Color_RESET);
		}
		if ((idx + 1) % cols) {
			int rem = colwidth - strlen(content);
			rem = RZ_MIN(sizeof(whites) - 1, RZ_MAX(0, rem));
			memset(whites, ' ', rem);
			whites[rem] = 0;
			rz_cons_print(whites);
		} else {
			rz_cons_print("\n");
		}
		idx++;
	}
	if (idx % cols) {
		// only print newline if not already done in the loop above
		rz_cons_print("\n");
	}
	rz_list_free(ritems);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus references_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, RzList *ritems, RzOutputMode mode) {
	bool failed;
	SYNC_READ_LIST(ritems, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}

	int use_colors = rz_config_get_i(core->config, "scr.color");

	int had_colors = use_colors;
	if (use_colors && mode == RZ_OUTPUT_MODE_JSON) {
		use_colors = 0;
		// for rz_core_analysis_hasrefs() below
		rz_config_set_i(core->config, "scr.color", 0);
	}

	RzTable *t = rz_core_table(core);
	rz_table_set_columnsf(t, "ssss", "role", "reg", "value", "refstr");
	RzListIter *iter;
	RzRegItem *r;
	rz_list_foreach (ritems, iter, r) {
		ut64 value = rz_reg_get_value(reg, r);
		const char *color = mode == RZ_OUTPUT_MODE_JSON ? NULL : get_reg_color(core, reg, r);
		char *namestr = rz_str_newf("%s%s%s", rz_str_get(color), r->name, color ? Color_RESET : "");
		char *valuestr = rz_str_newf("%s0x%" PFMT64x "%s", rz_str_get(color), value, color ? Color_RESET : "");
		char *rrstr = rz_core_analysis_hasrefs(core, value, true);
		rz_table_add_rowf(t, "ssss", rz_str_get(get_reg_role_name(reg, r)), namestr, valuestr, rz_str_get(rrstr));
		free(namestr);
		free(valuestr);
		free(rrstr);
	}

	if (mode == RZ_OUTPUT_MODE_JSON && had_colors) {
		rz_config_set_i(core->config, "scr.color", had_colors);
	}

	char *s = (mode == RZ_OUTPUT_MODE_JSON) ? rz_table_tojson(t) : rz_table_tostring(t);
	rz_cons_print(s);
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_cons_print("\n");
	}
	free(s);
	rz_table_free(t);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_references_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzOutputMode mode) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	RzList *ritems = filter_reg_items(reg, filter);
	if (!ritems) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus r = references_handler(core, reg, sync_cb, ritems, mode);
	rz_list_free(ritems);
	return r;
}

static int valgroup_regcmp(const void *a, const void *b) {
	const ut64 *A = (const ut64 *)a;
	const ut64 *B = (const ut64 *)b;
	if (*A > *B) {
		return 1;
	}
	if (*A == *B) {
		return 0;
	}
	return -1;
}

static bool valgroup_regcb(void *u, const ut64 k, const void *v) {
	RzList *sorted = (RzList *)u;
	ut64 *n = ut64_new(k);
	rz_list_add_sorted(sorted, n, valgroup_regcmp);
	return true;
}

RZ_IPI void rz_regs_show_valgroup(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, const RzList *list) {
	int use_colors = rz_config_get_i(core->config, "scr.color");

	RzListIter *iter;
	RzRegItem *r;
	HtUP *db = ht_up_new0();
	rz_list_foreach (list, iter, r) {
		if (r->size != core->rasm->bits) {
			continue;
		}
		ut64 value = rz_reg_get_value(reg, r);
		RzList *list = ht_up_find(db, value, NULL);
		if (!list) {
			list = rz_list_newf(NULL);
			ht_up_update(db, value, list);
		}
		rz_list_append(list, r->name);
	}

	RzList *sorted = rz_list_newf(free);
	ht_up_foreach(db, valgroup_regcb, sorted);
	ut64 *addr;
	rz_list_foreach (sorted, iter, addr) {
		rz_cons_printf("0x%08" PFMT64x " ", *addr);
		RzList *list = ht_up_find(db, *addr, NULL);
		if (list) {
			RzListIter *iter;
			const char *r;
			if (use_colors) {
				rz_cons_strcat(Color_YELLOW);
			}
			rz_list_foreach (list, iter, r) {
				rz_cons_printf(" %s", r);
			}
			if (use_colors) {
				rz_cons_strcat(Color_RESET);
			}
			char *rrstr = rz_core_analysis_hasrefs(core, *addr, true);
			if (rrstr && *rrstr && strchr(rrstr, 'R')) {
				rz_cons_printf("    ;%s%s", rrstr, use_colors ? Color_RESET : "");
			}
			rz_cons_newline();
		}
	}
	rz_list_free(sorted);
	ht_up_free(db);
}

RZ_IPI RzCmdStatus rz_regs_valgroup_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	RzList *list = filter_reg_items(reg, filter);
	if (!list) {
		print_reg_not_found(filter);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_regs_show_valgroup(core, reg, sync_cb, list);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	int i, j;
	RzRegArena *a;
	RzListIter *iter;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegSet *rs = &reg->regset[i];
		j = 0;
		rz_list_foreach (rs->pool, iter, a) {
			rz_cons_printf("%s %p %d %d %s %d\n",
				(a == rs->arena) ? "*" : ".", a,
				i, j, rz_reg_get_type(i), a->size);
			j++;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_push_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	bool failed;
	SYNC_READ(RZ_REG_TYPE_ANY, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_reg_arena_push(reg);
	SYNC_WRITE(RZ_REG_TYPE_ANY, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_pop_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	rz_reg_arena_pop(reg);
	bool failed;
	SYNC_WRITE(RZ_REG_TYPE_ANY, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_swap_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	bool failed;
	SYNC_READ(RZ_REG_TYPE_ANY, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_reg_arena_swap(reg, false);
	SYNC_WRITE(RZ_REG_TYPE_ANY, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_zero_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	int t = RZ_REG_TYPE_ANY;
	if (argc > 1) {
		t = rz_reg_type_by_name(argv[1]);
		if (t < 0) {
			RZ_LOG_ERROR("No such register type: \"%s\"\n", argv[2]);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	rz_reg_arena_zero(reg, t);
	bool failed;
	SYNC_WRITE(t, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_hexdump_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	int t = RZ_REG_TYPE_GPR;
	if (argc > 1) {
		t = rz_reg_type_by_name(argv[1]);
		if (t < 0) {
			RZ_LOG_ERROR("No such register type: \"%s\"\n", argv[2]);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	bool failed;
	SYNC_READ(t, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	int len = 0;
	ut8 *buf = rz_reg_get_bytes(reg, t, &len);
	if (buf) {
		rz_print_hexdump(core->print, 0LL, buf, len, 32, 4, 1);
		free(buf);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_stack_size_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	rz_cons_printf("%d\n", (int)rz_list_length(reg->regset[0].pool));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_arenas_write_hex_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	rz_return_val_if_fail(argc > 1, RZ_CMD_STATUS_WRONG_ARGS);
	RzRegisterType type = RZ_REG_TYPE_GPR;
	if (argc > 2) {
		type = rz_reg_type_by_name(argv[2]);
		if (type < 0 || type >= RZ_REG_TYPE_LAST) {
			RZ_LOG_ERROR("No such register type: \"%s\"\n", argv[2]);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	bool failed;
	SYNC_READ(type, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	const char *hex = argv[1];
	size_t maxsz = (strlen(hex) + 1) / 2;
	if (!maxsz) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *buf = malloc(maxsz);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	int sz = rz_hex_str2bin(hex, buf);
	if (sz <= 0) {
		RZ_LOG_ERROR("Invalid hex string given.\n");
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}
	RzRegArena *a = reg->regset[type].arena;
	if (!a || !a->bytes) {
		free(buf);
		// nothing to write, this is fine
		return RZ_CMD_STATUS_OK;
	}
	memcpy(a->bytes, buf, RZ_MIN(sz, a->size));
	free(buf);
	SYNC_WRITE(type, failed);
	return failed ? RZ_CMD_STATUS_ERROR : RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_args_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, RzOutputMode mode) {
	RzList *ritems = rz_list_new();
	if (!ritems) {
		return RZ_CMD_STATUS_ERROR;
	}
	for (int i = RZ_REG_NAME_A0; i <= RZ_REG_NAME_A9; i++) {
		const char *name = rz_reg_get_name(reg, i);
		if (!name) {
			break;
		}
		RzRegItem *item = rz_reg_get(reg, name, RZ_REG_TYPE_ANY);
		if (!item) {
			continue;
		}
		rz_list_push(ritems, item);
	}
	RzCmdStatus r = RZ_CMD_STATUS_OK;
	if (rz_list_empty(ritems)) {
		eprintf("No argument roles defined.\n");
	} else {
		r = references_handler(core, reg, sync_cb, ritems, mode);
	}
	rz_list_free(ritems);
	return r;
}

RZ_IPI RzCmdStatus rz_reg_types_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	for (int i = 0; i < RZ_REG_TYPE_LAST; i++) {
		rz_cons_println(rz_reg_get_type(i));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_roles_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	for (int i = 0; i < RZ_REG_NAME_LAST; i++) {
		rz_cons_print(rz_reg_get_role(i));
		if (reg->name[i]) {
			rz_cons_printf(" -> %s", reg->name[i]);
		}
		rz_cons_print("\n");
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_flags_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv, bool unset) {
	const char *filter = argc > 1 && *argv[1] ? argv[1] : NULL;
	RzList *ritems;
	if (filter) {
		ritems = filter_reg_items(reg, filter);
		if (!ritems) {
			print_reg_not_found(filter);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		ritems = rz_core_reg_flags_candidates(core, reg);
		if (!ritems) {
			return RZ_CMD_STATUS_ERROR;
		}
	}
	if (!unset) {
		rz_cons_print("fs+ " RZ_FLAGS_FS_REGISTERS "\n");
		bool failed;
		SYNC_READ_LIST(ritems, failed);
		if (failed) {
			rz_list_free(ritems);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	RzListIter *iter;
	RzRegItem *item;
	rz_list_foreach (ritems, iter, item) {
		if (!unset) {
			ut64 v = rz_reg_get_value(reg, item);
			rz_cons_printf("f %s @ 0x%" PFMT64x "\n", item->name, v);
		} else {
			rz_cons_printf("f- %s\n", item->name);
		}
	}
	if (!unset) {
		rz_cons_print("fs-\n");
	}
	rz_list_free(ritems);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_profile_handler(RzCore *core, RzReg *reg, int argc, const char **argv, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		if (reg->reg_profile_str) {
			rz_cons_println(reg->reg_profile_str);
		} else {
			eprintf("No register profile defined.\n");
		}
		break;
	case RZ_OUTPUT_MODE_JSON: {
		RzListIter *iter;
		RzRegItem *r;
		int i;
		PJ *pj = state->d.pj;
		pj_o(pj);
		pj_k(pj, "alias_info");
		pj_a(pj);
		for (i = 0; i < RZ_REG_NAME_LAST; i++) {
			if (reg->name[i]) {
				pj_o(pj);
				pj_kn(pj, "role", i);
				pj_ks(pj, "role_str", rz_reg_get_role(i));
				pj_ks(pj, "reg", reg->name[i]);
				pj_end(pj);
			}
		}
		pj_end(pj);
		pj_k(pj, "reg_info");
		pj_a(pj);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_list_foreach (reg->regset[i].regs, iter, r) {
				pj_o(pj);
				pj_kn(pj, "type", r->type);
				pj_ks(pj, "type_str", rz_reg_get_type(r->type));
				pj_ks(pj, "name", r->name);
				pj_kn(pj, "size", r->size);
				pj_kn(pj, "offset", r->offset);
				pj_end(pj);
			}
		}
		pj_end(pj);
		pj_end(pj);
		break;
	}
	default:
		break;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_profile_comments_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	if (reg->reg_profile_cmt) {
		rz_cons_println(reg->reg_profile_cmt);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_profile_open_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	rz_return_val_if_fail(argc > 1, RZ_CMD_STATUS_WRONG_ARGS);
	rz_reg_set_profile(reg, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_profile_gdb_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	rz_return_val_if_fail(argc > 1, RZ_CMD_STATUS_WRONG_ARGS);
	char *rz_profile = rz_reg_parse_gdb_profile(argv[1]);
	if (!rz_profile) {
		RZ_LOG_ERROR("Cannot parse gdb profile.\n");
		core->num->value = 1;
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(rz_profile);
	core->num->value = 0;
	free(rz_profile);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_cond_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	bool failed;
	SYNC_READ(RZ_REG_TYPE_ANY, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzRegFlags *rf = rz_reg_cond_retrieve(reg, NULL);
	if (!rf) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("| s:%d z:%d c:%d o:%d p:%d\n",
		rf->s, rf->z, rf->c, rf->o, rf->p);
	for (int i = 0; i < RZ_REG_COND_LAST; i++) {
		rz_cons_printf("%d %s\n",
			rz_reg_cond_bits(reg, i, rf),
			rz_reg_cond_to_string(i));
	}
	free(rf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_reg_cc_handler(RzCore *core, RzReg *reg, int argc, const char **argv) {
	char *s = rz_reg_profile_to_cc(reg);
	if (s) {
		rz_cons_printf("%s\n", s);
		free(s);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_diff_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	bool failed;
	SYNC_READ(RZ_REG_TYPE_ANY, failed);
	if (failed) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzRegItem *item;
	rz_list_foreach (reg->allregs, iter, item) {
		ut64 newval = rz_reg_get_value(reg, item);
		rz_reg_arena_swap(reg, false);
		ut64 oldval = rz_reg_get_value(reg, item);
		rz_reg_arena_swap(reg, false);
		ut64 delta = newval - oldval;
		if (delta) {
			rz_cons_printf(
				"%s = 0x%" PFMT64x " was 0x%" PFMT64x " delta 0x%" PFMT64x "\n",
				item->name, newval, oldval, delta);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_regs_prev_handler(RzCore *core, RzReg *reg, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *filter = argc > 1 ? argv[1] : NULL;
	rz_reg_arena_swap(reg, false);
	RzCmdStatus r = show_regs_handler(core, reg, NULL, filter, state); // sync_cb = NULL on purpose to not overwrite
	rz_reg_arena_swap(reg, false);
	return r;
}

RZ_IPI RzCmdStatus rz_regs_fpu_handler(RzCore *core, RzReg *reg, RzCmdRegSync sync_cb, int argc, const char **argv) {
	// TODO: everything here needs to be rewritten. It was taken from the old "drf" command.
	bool failed;
	if (argc <= 1) {
		// TODO: Do not use this hack to print fpu register:
		// By sending a negative value, this is signalling all the way through to the debug plugin,
		// which then does the printing.
		// This should be rewritten directly above the RzReg.
		SYNC_READ(-RZ_REG_TYPE_FPU, failed);
		if (failed) {
			return RZ_CMD_STATUS_ERROR;
		}
		return RZ_CMD_STATUS_OK;
	}
	char *name = rz_str_trim_dup(argv[1]);
	char *eq = strchr(name, '=');
	if (eq) {
		*eq++ = 0;
	}
	char *p = strchr(name, ' ');
	if (p) {
		*p++ = 0;
	}
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	SYNC_READ(RZ_REG_TYPE_GPR, failed);
	if (failed) {
		goto error;
	}
	SYNC_READ(RZ_REG_TYPE_FPU, failed);
	if (failed) {
		goto error;
	}
	RzRegItem *item = rz_reg_get(reg, name, -1);
	if (item) {
		if (eq) {
			long double val = 0.0f;
#if __windows__
			double dval = 0.0f;
			sscanf(eq, "%lf", (double *)&dval);
			val = dval;
#else
			sscanf(eq, "%Lf", &val);
#endif
			rz_reg_set_double(reg, item, val);
			SYNC_WRITE(RZ_REG_TYPE_GPR, failed);
			if (failed) {
				goto error;
			}
			SYNC_WRITE(RZ_REG_TYPE_FPU, failed);
			if (failed) {
				goto error;
			}
		} else {
			long double res = rz_reg_get_longdouble(reg, item);
			rz_cons_printf("%Lf\n", res);
		}
	} else {
		/* note, that negative type forces sync to print the regs from the backend */
		eprintf("cannot find multimedia register '%s'\n", name);
	}

error:
	free(name);
	return ret;
}
