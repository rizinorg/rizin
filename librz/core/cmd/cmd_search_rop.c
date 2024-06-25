// SPDX-FileCopyrightText: 2009-2016 Alexandru Caciulescu <alex.darredevil@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>

#include "rz_core.h"
#include "rz_list.h"
#include "rz_types_base.h"
#include "rz_rop.h"

#include <capstone/x86.h>

static RzList /*<char *>*/ *parse_list(const char *str) {
	char *line, *data, *str_n;

	if (!str) {
		return NULL;
	}
	str_n = strdup(str);
	line = strtok(str_n, "\n");
	data = strchr(line, '=');

	RzList *list = rz_str_split_duplist(data + 1, ",", false);

	free(str_n);
	return list;
}

static RzList /*<char *>*/ *get_constants(const char *str) {
	RzList *list;
	char *p, *data;
	if (!str) {
		return NULL;
	}

	data = strdup(str);
	list = rz_list_newf(free);
	p = strtok(data, ",");
	while (p) {
		if (strtol(p, NULL, 0)) {
			rz_list_append(list, (void *)strdup(p));
		}
		p = strtok(NULL, ",");
	}
	free(data);
	return list;
}

static bool isFlag(RzRegItem *reg) {
	const char *type = rz_reg_get_type(reg->type);

	if (!strcmp(type, "flg"))
		return true;
	return false;
}

// binary op
static bool simulate_op(const char *op, ut64 src1, ut64 src2, ut64 old_src1, ut64 old_src2, ut64 *result, int size) {
	ut64 limit;
	if (size == 64) {
		limit = UT64_MAX;
	} else {
		limit = 1ULL << size;
	}

	if (!strcmp(op, "^")) {
		*result = src1 ^ src2;
		return true;
	}
	if (!strcmp(op, "+")) {
		*result = src1 + src2;
		return true;
	}
	if (!strcmp(op, "-")) {
		if (src2 > src1) {
			*result = limit + (src1 - src2);
		} else {
			*result = src1 - src2;
		}
		return true;
	}
	if (!strcmp(op, "*")) {
		*result = src1 * src2;
		return true;
	}
	if (!strcmp(op, "|")) {
		*result = src1 | src2;
		return true;
	}
	if (!strcmp(op, "/")) {
		*result = src1 / src2;
		return true;
	}
	if (!strcmp(op, "%")) {
		*result = src1 % src2;
		return true;
	}
	if (!strcmp(op, "<<")) {
		*result = src1 << src2;
		return true;
	}
	if (!strcmp(op, ">>")) {
		*result = src1 >> src2;
		return true;
	}
	if (!strcmp(op, "&")) {
		*result = src1 & src2;
		return true;
	}
	if (!strcmp(op, "+=")) {
		*result = old_src1 + src2;
		return true;
	}
	if (!strcmp(op, "-=")) {
		if (src2 > old_src1) {
			*result = limit + (old_src1 - src2);
		} else {
			*result = old_src1 - src2;
		}
		return true;
	}
	if (!strcmp(op, "*=")) {
		*result = old_src1 * src2;
		return true;
	}
	if (!strcmp(op, "/=")) {
		*result = old_src1 / src2;
		return true;
	}
	if (!strcmp(op, "%=")) {
		*result = old_src1 % src2;
		return true;
	}
	if (!strcmp(op, "<<")) {
		*result = src1 << src2;
		return true;
	}
	if (!strcmp(op, ">>")) {
		*result = src1 >> src2;
		return true;
	}
	if (!strcmp(op, "&=")) {
		*result = src1 & src2;
		return true;
	}
	if (!strcmp(op, "^=")) {
		*result = src1 ^ src2;
		return true;
	}
	if (!strcmp(op, "|=")) {
		*result = src1 | src2;
		return true;
	}
	return false;
}

// fill REGs with known values
static void fillRegisterValues(RzCore *core) {
	RzListIter *iter_reg;
	RzRegItem *reg_item;
	int nr = 10;

	const RzList *regs = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (!regs) {
		return;
	}
	rz_list_foreach (regs, iter_reg, reg_item) {
		rz_reg_arena_pop(core->analysis->reg);
		rz_reg_set_value(core->analysis->reg, reg_item, nr);
		rz_reg_arena_push(core->analysis->reg);
		nr += 3;
	}
}

// split esil string in flags part and main instruction
// hacky, only tested for x86, TODO: portable version
// NOTE: esil_main and esil_flg are heap allocated and must be freed by the caller
static void esil_split_flg(char *esil_str, char **esil_main, char **esil_flg) {
	char *split = strstr(esil_str, "f,=");
	const int kCommaHits = 2;
	int hits = 0;

	if (split) {
		while (hits != kCommaHits) {
			--split;
			if (*split == ',') {
				hits++;
			}
		}
		*esil_flg = strdup(++split);
		*esil_main = rz_str_ndup(esil_str, strlen(esil_str) - strlen(*esil_flg) - 1);
	}
}

#define FREE_ROP \
	{ \
		RZ_FREE(out); \
		RZ_FREE(esil_flg); \
		RZ_FREE(esil_main); \
		rz_list_free(ops_list); \
		ops_list = NULL; \
		rz_list_free(flg_read); \
		flg_read = NULL; \
		rz_list_free(flg_write); \
		flg_write = NULL; \
		rz_list_free(reg_read); \
		reg_read = NULL; \
		rz_list_free(reg_write); \
		reg_write = NULL; \
		rz_list_free(mem_read); \
		mem_read = NULL; \
		rz_list_free(mem_write); \
		mem_write = NULL; \
	}

static char *rop_classify_constant(RzCore *core, RzList /*<char *>*/ *ropList) {
	char *esil_str, *constant;
	char *ct = NULL, *esil_main = NULL, *esil_flg = NULL, *out = NULL;
	RzListIter *iter_r, *iter_dst, *iter_const;
	RzRegItem *item_dst;
	const RzList *head;
	RzList *constants;
	RzList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	       *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	       *mem_write = NULL;
	const bool romem = rz_config_get_i(core->config, "esil.romem");
	const bool stats = rz_config_get_i(core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	rz_list_foreach (ropList, iter_r, esil_str) {
		constants = get_constants(esil_str);
		// if there are no constants in the instruction continue
		if (rz_list_empty(constants)) {
			continue;
		}
		// init regs with known values
		fillRegisterValues(core);
		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			ct = NULL;
			goto continue_error;
		}
		esil_split_flg(esil_str, &esil_main, &esil_flg);
		cmd_analysis_esil(core, esil_main ? esil_main : esil_str);
		out = sdb_querys(core->analysis->esil->stats, NULL, 0, "*");
		if (!out) {
			goto continue_error;
		}
		ops_list = parse_list(strstr(out, "ops.list"));
		flg_read = parse_list(strstr(out, "flg.read"));
		flg_write = parse_list(strstr(out, "flg.write"));
		reg_read = parse_list(strstr(out, "reg.read"));
		reg_write = parse_list(strstr(out, "reg.write"));
		mem_read = parse_list(strstr(out, "mem.read"));
		mem_write = parse_list(strstr(out, "mem.write"));
		if (!rz_list_find(ops_list, "=", (RzListComparator)strcmp, NULL)) {
			goto continue_error;
		}
		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		rz_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;
			if (!rz_list_find(reg_write, item_dst->name,
				    (RzListComparator)strcmp, NULL)) {
				continue;
			}

			value_dst = rz_reg_get_value(core->analysis->reg, item_dst);
			rz_reg_arena_swap(core->analysis->reg, false);
			diff_dst = rz_reg_get_value(core->analysis->reg, item_dst);
			rz_reg_arena_swap(core->analysis->reg, false);
			// restore initial value
			rz_reg_set_value(core->analysis->reg, item_dst, diff_dst);

			if (value_dst != diff_dst) {
				rz_list_foreach (constants, iter_const, constant) {
					if (value_dst == rz_num_get(NULL, constant)) {
						ct = rz_str_appendf(ct, "%s <-- 0x%" PFMT64x ";", item_dst->name, value_dst);
					}
				}
			}
		}
	continue_error:
		// coverity may complain here but as long as the pointer is set back to
		// NULL is safe that is why is used RZ_FREE
		FREE_ROP;
		rz_list_free(constants);
	}
	return ct;
out_error:
	FREE_ROP;
	rz_list_free(constants);
	return NULL;
}

static char *rop_classify_mov(RzCore *core, RzList /*<char *>*/ *ropList) {
	char *esil_str;
	char *mov = NULL, *esil_main = NULL, *esil_flg = NULL, *out = NULL;
	RzListIter *iter_src, *iter_r, *iter_dst;
	RzRegItem *item_src, *item_dst;
	const RzList *head;
	RzList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	       *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	       *mem_write = NULL;
	const bool romem = rz_config_get_i(core->config, "esil.romem");
	const bool stats = rz_config_get_i(core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	rz_list_foreach (ropList, iter_r, esil_str) {
		// init regs with known values
		fillRegisterValues(core);
		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		esil_split_flg(esil_str, &esil_main, &esil_flg);
		cmd_analysis_esil(core, esil_main ? esil_main : esil_str);
		out = sdb_querys(core->analysis->esil->stats, NULL, 0, "*");
		if (out) {
			ops_list = parse_list(strstr(out, "ops.list"));
			flg_read = parse_list(strstr(out, "flg.read"));
			flg_write = parse_list(strstr(out, "flg.write"));
			reg_read = parse_list(strstr(out, "reg.read"));
			reg_write = parse_list(strstr(out, "reg.write"));
			mem_read = parse_list(strstr(out, "mem.read"));
			mem_write = parse_list(strstr(out, "mem.write"));
		} else {
			goto continue_error;
		}

		if (!rz_list_find(ops_list, "=", (RzListComparator)strcmp, NULL)) {
			goto continue_error;
		}

		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		rz_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;
			if (!rz_list_find(reg_write, item_dst->name,
				    (RzListComparator)strcmp, NULL)) {
				continue;
			}

			// you never mov into flags
			if (isFlag(item_dst)) {
				continue;
			}

			value_dst = rz_reg_get_value(core->analysis->reg, item_dst);
			rz_reg_arena_swap(core->analysis->reg, false);
			diff_dst = rz_reg_get_value(core->analysis->reg, item_dst);
			rz_reg_arena_swap(core->analysis->reg, false);
			rz_list_foreach (head, iter_src, item_src) {
				ut64 diff_src, value_src;
				if (!rz_list_find(reg_read, item_src->name,
					    (RzListComparator)strcmp, NULL)) {
					continue;
				}
				// you never mov from flags
				if (item_src == item_dst || isFlag(item_src)) {
					continue;
				}
				value_src = rz_reg_get_value(core->analysis->reg, item_src);
				rz_reg_arena_swap(core->analysis->reg, false);
				diff_src = rz_reg_get_value(core->analysis->reg, item_src);
				rz_reg_arena_swap(core->analysis->reg, false);
				// restore initial value
				rz_reg_set_value(core->analysis->reg, item_src, diff_src);
				if (value_dst == value_src && value_dst != diff_dst) {
					mov = rz_str_appendf(mov, "%s <-- %s;",
						item_dst->name, item_src->name);
				}
			}
		}
	continue_error:
		FREE_ROP;
	}
	return mov;
out_error:
	FREE_ROP;
	return NULL;
}

static char *rop_classify_arithmetic(RzCore *core, RzList /*<char *>*/ *ropList) {
	char *esil_str, *op;
	char *arithmetic = NULL, *esil_flg = NULL, *esil_main = NULL,
	     *out = NULL;
	RzListIter *iter_src1, *iter_src2, *iter_r, *iter_dst, *iter_ops;
	RzRegItem *item_src1, *item_src2, *item_dst;
	const RzList *head;
	RzList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	       *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	       *mem_write = NULL;
	const bool romem = rz_config_get_i(core->config, "esil.romem");
	const bool stats = rz_config_get_i(core->config, "esil.stats");
	ut64 *op_result = RZ_NEW0(ut64);
	ut64 *op_result_r = RZ_NEW0(ut64);

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		free(op_result);
		free(op_result_r);
		return NULL;
	}

	rz_list_foreach (ropList, iter_r, esil_str) {
		// init regs with known values
		fillRegisterValues(core);
		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		esil_split_flg(esil_str, &esil_main, &esil_flg);
		if (esil_main) {
			cmd_analysis_esil(core, esil_main);
		} else {
			cmd_analysis_esil(core, esil_str);
		}
		out = sdb_querys(core->analysis->esil->stats, NULL, 0, "*");
		// rz_cons_println (out);
		if (!out) {
			goto continue_error;
		}
		ops_list = parse_list(strstr(out, "ops.list"));
		flg_read = parse_list(strstr(out, "flg.read"));
		flg_write = parse_list(strstr(out, "flg.write"));
		reg_read = parse_list(strstr(out, "reg.read"));
		reg_write = parse_list(strstr(out, "reg.write"));
		mem_read = parse_list(strstr(out, "mem.read"));
		mem_write = parse_list(strstr(out, "mem.write"));

		rz_list_foreach (ops_list, iter_ops, op) {
			rz_list_foreach (head, iter_src1, item_src1) {
				ut64 value_src1, diff_src1;

				value_src1 = rz_reg_get_value(core->analysis->reg, item_src1);
				rz_reg_arena_swap(core->analysis->reg, false);
				diff_src1 = rz_reg_get_value(core->analysis->reg, item_src1);
				rz_reg_arena_swap(core->analysis->reg, false);
				if (!rz_list_find(reg_read, item_src1->name,
					    (RzListComparator)strcmp, NULL)) {
					continue;
				}

				rz_list_foreach (head, iter_src2, item_src2) {
					ut64 value_src2, diff_src2;
					value_src2 = rz_reg_get_value(core->analysis->reg, item_src2);
					rz_reg_arena_swap(core->analysis->reg, false);
					diff_src2 = rz_reg_get_value(core->analysis->reg, item_src2);

					if (!rz_list_find(reg_read, item_src2->name,
						    (RzListComparator)strcmp, NULL)) {
						continue;
					}
					// TODO check condition
					if (iter_src1 == iter_src2) {
						continue;
					}

					rz_list_foreach (head, iter_dst, item_dst) {
						ut64 value_dst;
						bool redundant = false, simulate, simulate_r;

						value_dst = rz_reg_get_value(core->analysis->reg, item_dst);
						rz_reg_arena_swap(core->analysis->reg, false);
						if (!rz_list_find(reg_write, item_dst->name,
							    (RzListComparator)strcmp, NULL)) {
							continue;
						}
						// don't check flags for arithmetic
						if (isFlag(item_dst)) {
							continue;
						}
						simulate = simulate_op(op, value_src1, value_src2, diff_src1, diff_src2, op_result, item_dst->size);
						simulate_r = simulate_op(op, value_src2, value_src1, diff_src2, diff_src1, op_result_r, item_dst->size);
						if (/*value_src1 != 0 && value_src2 != 0 && */ simulate && value_dst == *op_result) {
							// rz_cons_println ("Debug: FOUND ONE !");
							char *tmp = rz_str_newf("%s <-- %s %s %s;", item_dst->name, item_src1->name, op, item_src2->name);
							if (arithmetic && !strstr(arithmetic, tmp)) {
								arithmetic = rz_str_append(arithmetic, tmp);
							} else if (!arithmetic) {
								arithmetic = rz_str_append(arithmetic, tmp);
							}
							free(tmp);
						} else if (!redundant /*&& value_src1 != 0 && value_src2 != 0*/ && simulate_r && value_dst == *op_result_r) {
							// rz_cons_println ("Debug: FOUND ONE reversed!");
							char *tmp = rz_str_newf("%s <-- %s %s %s;", item_dst->name, item_src2->name, op, item_src1->name);
							if (arithmetic && !strstr(arithmetic, tmp)) {
								arithmetic = rz_str_append(arithmetic, tmp);
							} else if (!arithmetic) {
								arithmetic = rz_str_append(arithmetic, tmp);
							}
							free(tmp);
						}
					}
				}
			}
		}
	continue_error:
		FREE_ROP;
	}
	free(op_result);
	free(op_result_r);
	return arithmetic;
out_error:
	FREE_ROP;
	free(op_result);
	free(op_result_r);
	return NULL;
}

static char *rop_classify_arithmetic_const(RzCore *core, RzList /*<char *>*/ *ropList) {
	char *esil_str, *op, *constant;
	char *arithmetic = NULL, *esil_flg = NULL, *esil_main = NULL;
	RzListIter *iter_src1, *iter_r, *iter_dst, *iter_ops, *iter_const;
	RzRegItem *item_src1, *item_dst;
	const RzList *head;
	RzList *constants;
	RzList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL, *reg_read = NULL,
	       *reg_write = NULL, *mem_read = NULL, *mem_write = NULL;
	const bool romem = rz_config_get_i(core->config, "esil.romem");
	const bool stats = rz_config_get_i(core->config, "esil.stats");
	ut64 *op_result = RZ_NEW0(ut64);
	ut64 *op_result_r = RZ_NEW0(ut64);

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		RZ_FREE(op_result);
		RZ_FREE(op_result_r);
		return NULL;
	}

	rz_list_foreach (ropList, iter_r, esil_str) {
		constants = get_constants(esil_str);
		// if there are no constants in the instruction continue
		if (rz_list_empty(constants)) {
			continue;
		}
		// init regs with known values
		fillRegisterValues(core);
		head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
		if (!head) {
			arithmetic = NULL;
			continue;
		}
		esil_split_flg(esil_str, &esil_main, &esil_flg);
		if (esil_main) {
			cmd_analysis_esil(core, esil_main);
		} else {
			cmd_analysis_esil(core, esil_str);
		}
		char *out = sdb_querys(core->analysis->esil->stats, NULL, 0, "*");
		// rz_cons_println (out);
		if (out) {
			ops_list = parse_list(strstr(out, "ops.list"));
			flg_read = parse_list(strstr(out, "flg.read"));
			flg_write = parse_list(strstr(out, "flg.write"));
			reg_read = parse_list(strstr(out, "reg.read"));
			reg_write = parse_list(strstr(out, "reg.write"));
			mem_read = parse_list(strstr(out, "mem.read"));
			mem_write = parse_list(strstr(out, "mem.write"));
		} else {
			RZ_FREE(op_result);
			RZ_FREE(op_result_r);
			goto continue_error;
		}

		rz_list_foreach (ops_list, iter_ops, op) {
			rz_list_foreach (head, iter_src1, item_src1) {
				ut64 value_src1, diff_src1;
				value_src1 = rz_reg_get_value(core->analysis->reg, item_src1);
				rz_reg_arena_swap(core->analysis->reg, false);
				diff_src1 = rz_reg_get_value(core->analysis->reg, item_src1);
				rz_reg_arena_swap(core->analysis->reg, false);

				if (!rz_list_find(reg_read, item_src1->name,
					    (RzListComparator)strcmp, NULL)) {
					continue;
				}
				rz_list_foreach (head, iter_dst, item_dst) {
					ut64 value_dst, diff_dst;
					bool redundant = false, simulate, simulate_r;
					value_dst = rz_reg_get_value(core->analysis->reg, item_dst);
					rz_reg_arena_swap(core->analysis->reg, false);
					diff_dst = rz_reg_get_value(core->analysis->reg, item_dst);
					rz_reg_arena_swap(core->analysis->reg, false);
					if (!rz_list_find(reg_write, item_dst->name,
						    (RzListComparator)strcmp, NULL)) {
						continue;
					}
					// don't check flags for arithmetic
					if (isFlag(item_dst)) {
						continue;
					}
					if (value_dst != diff_dst) {
						rz_list_foreach (constants, iter_const, constant) {
							ut64 value_ct = rz_num_get(NULL, constant);
							simulate = simulate_op(op, value_src1, value_ct,
								diff_src1, value_ct, op_result,
								item_dst->size);
							simulate_r = simulate_op(op, value_ct, value_src1,
								value_ct, diff_src1, op_result_r,
								item_dst->size);
							if (simulate && op_result && value_dst == *op_result) {
								char *tmp = rz_str_newf("%s <-- %s %s %s;", item_dst->name, item_src1->name, op, constant);
								if (arithmetic && !strstr(arithmetic, tmp)) {
									arithmetic = rz_str_append(arithmetic, tmp);
								} else if (!arithmetic) {
									arithmetic = rz_str_append(arithmetic, tmp);
								}
								free(tmp);
								redundant = true;
							} else if (!redundant && simulate_r && value_dst == *op_result_r) {
								char *tmp = rz_str_newf("%s <-- %s %s %s;", item_dst->name, constant, op, item_src1->name);
								if (arithmetic && !strstr(arithmetic, tmp)) {
									arithmetic = rz_str_append(arithmetic, tmp);
								} else if (!arithmetic) {
									arithmetic = rz_str_append(arithmetic, tmp);
								}
								free(tmp);
							}
						}
					}
				}
			}
		}
	continue_error:
		FREE_ROP;
		rz_list_free(constants);
	}
	free(op_result);
	free(op_result_r);
	return arithmetic;
}

static int rop_classify_nops(RzCore *core, RzList /*<char *>*/ *ropList) {
	char *esil_str;
	int changes = 1;
	RzListIter *iter_r;
	const bool romem = rz_config_get_i(core->config, "esil.romem");
	const bool stats = rz_config_get_i(core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE\n");
		return -2;
	}

	rz_list_foreach (ropList, iter_r, esil_str) {
		fillRegisterValues(core);

		// rz_cons_printf ("Emulating nop:%s\n", esil_str);
		cmd_analysis_esil(core, esil_str);
		char *out = sdb_querys(core->analysis->esil->stats, NULL, 0, "*");
		// rz_cons_println (out);
		if (out) {
			free(out);
			return 0;
		}
		// directly say NOP
		continue;
	}

	return changes;
}

static void rop_classify(RzCore *core, Sdb *db, RzList /*<char *>*/ *ropList, const char *key, unsigned int size) {
	int nop = 0;
	rop_classify_nops(core, ropList);
	char *mov, *ct, *arithm, *arithm_ct, *str;
	Sdb *db_nop = sdb_ns(db, "nop", true);
	Sdb *db_mov = sdb_ns(db, "mov", true);
	Sdb *db_ct = sdb_ns(db, "const", true);
	Sdb *db_aritm = sdb_ns(db, "arithm", true);
	Sdb *db_aritm_ct = sdb_ns(db, "arithm_ct", true);

	if (!db_nop || !db_mov || !db_ct || !db_aritm || !db_aritm_ct) {
		RZ_LOG_ERROR("core: could not create SDB 'rop' sub-namespaces\n");
		return;
	}
	nop = rop_classify_nops(core, ropList);
	mov = rop_classify_mov(core, ropList);
	ct = rop_classify_constant(core, ropList);
	arithm = rop_classify_arithmetic(core, ropList);
	arithm_ct = rop_classify_arithmetic_const(core, ropList);
	str = rz_str_newf("0x%u", size);

	if (nop == 1) {
		char *str_nop = rz_str_newf("%s NOP", str);
		sdb_set(db_nop, key, str_nop);
		free(str_nop);
	} else {
		if (mov) {
			char *str_mov = rz_str_newf("%s MOV { %s }", str, mov);
			sdb_set(db_mov, key, str_mov);
			free(str_mov);
			free(mov);
		}
		if (ct) {
			char *str_ct = rz_str_newf("%s LOAD_CONST { %s }", str, ct);
			sdb_set(db_ct, key, str_ct);
			free(str_ct);
			free(ct);
		}
		if (arithm) {
			char *str_arithm = rz_str_newf("%s ARITHMETIC { %s }", str, arithm);
			sdb_set(db_aritm, key, str_arithm);
			free(str_arithm);
			free(arithm);
		}
		if (arithm_ct) {
			char *str_arithm_ct = rz_str_newf("%s ARITHMETIC_CONST { %s }", str, arithm_ct);
			sdb_set(db_aritm_ct, key, str_arithm_ct);
			free(str_arithm_ct);
			free(arithm_ct);
		}
	}

	free(str);
}

static void skip_whitespace(const char *str, int *idx) {
	while (str[*idx] == ' ' || str[*idx] == '\t' || str[*idx] == '\n' || str[*idx] == '\r') {
		(*idx)++;
	}
}

static bool parse_eof(const char *str, int idx) {
	skip_whitespace(str, &idx);
	return str[idx] == '\0';
}

static bool parse_il_equal(char *str, int *idx) {
	skip_whitespace(str, idx);
	if (*idx >= strlen(str)) {
		return false;
	}
	if (str[*idx] == '=') {
		(*idx)++;
		return true;
	}
	return false;
}

static char *parse_register(RzCore *core, char *str, int *idx) {
	char reg[256] = { 0 };
	int reg_idx = 0;

	skip_whitespace(str, idx);

	while (isalnum(str[*idx]) || str[*idx] == '_') {
		reg[reg_idx++] = str[*idx];
		(*idx)++;
	}

	if (reg_idx == 0) {
		return NULL;
	}

	// Check if the register is correct for the given architecture.
	if (rz_analysis_is_reg_in_profile(core->analysis, reg)) {
		return strdup(reg);
	}

	return NULL;
}

static bool parse_constant(const char *str, int *idx, unsigned long long *value) {
	int base = 10;
	int neg = 0;
	char num_str[256] = { 0 };
	int num_idx = 0;

	skip_whitespace(str, idx);

	if (str[*idx] == '-') {
		neg = 1;
		(*idx)++;
	}

	skip_whitespace(str, idx);

	if (str[*idx] == '0' && (str[*idx + 1] == 'x' || str[*idx + 1] == 'X')) {
		base = 16;
		*idx += 2;
	}

	while (isdigit(str[*idx]) || (base == 16 && isxdigit(str[*idx]))) {
		num_str[num_idx++] = str[*idx];
		(*idx)++;
	}

	if (num_idx == 0) {
		return false;
	}

	*value = strtoull(num_str, NULL, base);
	if (neg) {
		*value = -*value;
	}

	return true;
}

static bool parse_reg_to_const(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	unsigned long long const_value;
	if (!parse_constant(str, &idx, &const_value)) {
		free(dst_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		return false;
	}

	rop_constraint->type = MOV_CONST;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = NULL;
	char value_str[256];
	snprintf(value_str, sizeof(value_str), "%llu", const_value);
	rop_constraint->args[SRC_CONST] = strdup(value_str);
	return true;
}

static bool parse_reg_to_reg(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg = parse_register(core, str, &idx);
	if (!src_reg) {
		free(dst_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		return false;
	}

	rop_constraint->type = MOV_REG;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg;
	return true;
}

static bool parse_il_op(RzList *args, const char *str, int *idx) {
	RzILOpPureCode res = RZ_IL_OP_VAR;

	skip_whitespace(str, idx);
	if (*idx >= strlen(str)) {
		return false;
	}

	switch (str[*idx]) {
	case '+':
		(*idx)++;
		res = RZ_IL_OP_ADD;
		break;
	case '/':
		(*idx)++;
		res = RZ_IL_OP_DIV;
		break;
	case '*':
		(*idx)++;
		res = RZ_IL_OP_MUL;
		break;
	case '^':
		(*idx)++;
		res = RZ_IL_OP_XOR;
		break;
	case '&':
		(*idx)++;
		res = RZ_IL_OP_AND;
		break;
	case '|':
		(*idx)++;
		res = RZ_IL_OP_OR;
		break;
	case '%':
		(*idx)++;
		res = RZ_IL_OP_MOD;
		break;
	case '-':
		(*idx)++;
		res = RZ_IL_OP_SUB;
	default: break;
	}
	if (res == RZ_IL_OP_VAR) {
		if (strncmp(&str[*idx], "<<", 2) == 0) {
			*idx += 2;
			res = RZ_IL_OP_SHIFTL;
		} else if (strncmp(&str[*idx], ">>", 2) == 0) {
			*idx += 2;
			res = RZ_IL_OP_SHIFTR;
		} else {
			return false;
		}
	}

	RzILOpPureCode *op_ptr = malloc(sizeof(RzILOpPureCode));
	if (!op_ptr) {
		return false;
	}
	*op_ptr = res;
	rz_list_append(args, op_ptr);

	return true;
}

static bool parse_reg_op_const(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg = parse_register(core, str, &idx);
	if (!src_reg) {
		free(dst_reg);
		return false;
	}
	RzList *args = rz_list_new();
	if (!parse_il_op(args, str, &idx)) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	ut64 const_value;
	if (!parse_constant(str, &idx, &const_value)) {
		free(dst_reg);
		free(src_reg);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	rop_constraint->type = MOV_OP_CONST;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg;
	RzILOpPureCode *op = rz_list_get_n(args, 0);
	if (!op) {
		free(dst_reg);
		free(src_reg);
		rz_list_free(args);
		return false;
	}

	char op_str[16];
	snprintf(op_str, sizeof(op_str), "%s", rz_il_op_pure_code_stringify(*op));
	rop_constraint->args[OP] = strdup(op_str);
	char value_str[256];
	snprintf(value_str, sizeof(value_str), "%llu", const_value);
	rop_constraint->args[SRC_CONST] = strdup(value_str);
	return true;
}

static bool parse_reg_op_reg(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	int idx = 0;
	char *dst_reg = parse_register(core, str, &idx);
	if (!dst_reg) {
		return false;
	}

	if (!parse_il_equal(str, &idx)) {
		free(dst_reg);
		return false;
	}

	char *src_reg1 = parse_register(core, str, &idx);
	if (!src_reg1) {
		free(dst_reg);
		return false;
	}

	RzList *args = rz_list_new();
	if (!parse_il_op(args, str, &idx)) {
		free(dst_reg);
		free(src_reg1);
		rz_list_free(args);
		return false;
	}

	char *dst_reg2 = parse_register(core, str, &idx);
	if (!dst_reg2) {
		free(dst_reg);
		free(src_reg1);
		return false;
	}

	if (!parse_eof(str, idx)) {
		free(dst_reg);
		free(src_reg1);
		free(dst_reg2);
		rz_list_free(args);
		return false;
	}

	rop_constraint->type = MOV_OP_REG;
	rop_constraint->args[DST_REG] = dst_reg;
	rop_constraint->args[SRC_REG] = src_reg1;
	RzILOpPureCode *op = rz_list_get_n(args, 0);
	if (!op) {
		free(dst_reg);
		free(src_reg1);
		free(dst_reg2);
		rz_list_free(args);
		return false;
	}

	char op_str[16];
	snprintf(op_str, sizeof(op_str), "%s", rz_il_op_pure_code_stringify(*op));
	rop_constraint->args[OP] = strdup(op_str);
	rop_constraint->args[SRC_CONST] = dst_reg2;
	return true;
}

RZ_API bool analyze_constraint(RzCore *core, char *str, RzRopConstraint *rop_constraint) {
	rz_return_val_if_fail(core, NULL);
	return parse_reg_to_const(core, str, rop_constraint) ||
		parse_reg_to_reg(core, str, rop_constraint) ||
		parse_reg_op_const(core, str, rop_constraint) ||
		parse_reg_op_reg(core, str, rop_constraint);
}

static RzRopConstraint *rop_constraint_parse_args(RzCore *core, char *token) {
	RzRopConstraint *rop_constraint = RZ_NEW0(RzRopConstraint);
	RzList *l = rz_str_split_duplist_n(token, "=", 1, false);
	char *key = rz_list_get_n(l, 0);
	char *value = rz_list_get_n(l, 1);
	if (RZ_STR_ISEMPTY(key) || RZ_STR_ISEMPTY(value)) {
		RZ_LOG_ERROR("core: Make sure to use the format <key>=<value> without spaces.\n");
		rz_list_free(l);
		return NULL;
	}
	if (!rop_constraint) {
		rz_list_free(l);
		return NULL;
	}
	if (!analyze_constraint(core, token, rop_constraint)) {
		free(rop_constraint);
		rz_list_free(l);
		return NULL;
	}

	rz_list_free(l);
	return rop_constraint;
}

static RzList *rop_constraint_list_parse(RzCore *core, int argc, const char **argv) {
	RzList *constr_list = rz_rop_constraint_list_new();
	for (int i = 1; i < argc; i++) {
		RzList *l = rz_str_split_duplist_n(argv[i], ",", 1, false);
		if (!l) {
			return constr_list;
		}
		size_t llen = rz_list_length(l);
		if (!llen) {
			return constr_list;
		}
		RzListIter *it;
		char *token;
		rz_list_foreach (l, it, token) {
			RzRopConstraint *rop_constraint = rop_constraint_parse_args(core, token);
			if (!rop_constraint) {
				continue;
			}
			rz_list_append(constr_list, rop_constraint);
		}
		rz_list_free(l);
	}
	return constr_list;
}