// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_types.h>
#include <rz_list.h>
#include <rz_flag.h>
#include <rz_core.h>
#include <rz_bin.h>
#include <ht_uu.h>
#include <rz_util/rz_graph_drawable.h>

#include "core_private.h"

static void core_esil_init(RzCore *core) {
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	int romem = rz_config_get_i(core->config, "esil.romem");
	int stats = rz_config_get_i(core->config, "esil.stats");
	int noNULL = rz_config_get_i(core->config, "esil.noNULL");
	int verbose = rz_config_get_i(core->config, "esil.verbose");
	RzAnalysisEsil *esil = NULL;
	if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
		return;
	}
	rz_analysis_esil_setup(esil, core->analysis, romem, stats, noNULL); // setup io
	core->analysis->esil = esil;
	esil->verbose = verbose;
	const char *s = rz_config_get(core->config, "cmd.esil.intr");
	if (s) {
		char *my = strdup(s);
		if (my) {
			rz_config_set(core->config, "cmd.esil.intr", my);
			free(my);
		}
	}
}

RZ_IPI void rz_core_analysis_esil_init(RzCore *core) {
	if (core->analysis->esil) {
		return;
	}
	core_esil_init(core);
}

/**
 * \brief Reinitialize ESIL
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_reinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core && core->analysis);
	rz_analysis_esil_free(core->analysis->esil);
	core_esil_init(core);
	// reinitialize
	rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, core->offset);
}

/**
 * \brief Deinitialize ESIL
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_deinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core && core->analysis);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (esil) {
		sdb_reset(esil->stats);
	}
	rz_analysis_esil_free(esil);
	core->analysis->esil = NULL;
}

static void initialize_stack(RzCore *core, ut64 addr, ut64 size) {
	const char *mode = rz_config_get(core->config, "esil.fillstack");
	if (mode && *mode && *mode != '0') {
		const ut64 bs = 4096 * 32;
		ut64 i;
		for (i = 0; i < size; i += bs) {
			ut64 left = RZ_MIN(bs, size - i);
			//	rz_core_cmdf (core, "wx 10203040 @ 0x%llx", addr);
			switch (*mode) {
			case 'd': { // "debrujn"
				ut8 *buf = (ut8 *)rz_debruijn_pattern(left, 0, NULL);
				if (buf) {
					if (!rz_core_write_at(core, addr + i, buf, left)) {
						RZ_LOG_ERROR("core: cannot write at %" PFMT64x "\n", addr + i);
					}
					free(buf);
				} else {
					RZ_LOG_ERROR("core: cannot generate pattern of length %" PFMT64d "\n", left);
				}
			} break;
			case 's': // "seq"
				rz_core_cmdf(core, "woe 1 0xff 1 4 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
				break;
			case 'r': // "random"
				rz_core_cmdf(core, "woR %" PFMT64u " @ 0x%" PFMT64x "!0x%" PFMT64x, left, addr + i, left);
				break;
			case 'z': // "zero"
			case '0':
				rz_core_cmdf(core, "wb 00 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
				break;
			}
		}
	}
}

static char *get_esil_stack_name(RzCore *core, const char *name, ut64 *addr, ut32 *size) {
	ut64 sx_addr = rz_config_get_i(core->config, "esil.stack.addr");
	ut32 sx_size = rz_config_get_i(core->config, "esil.stack.size");
	RzIOMap *map = rz_io_map_get(core->io, sx_addr);
	if (map) {
		sx_addr = UT64_MAX;
	}
	if (sx_addr == UT64_MAX) {
		const ut64 align = 0x10000000;
		sx_addr = rz_io_map_next_available(core->io, core->offset, sx_size, align);
	}
	if (*addr != UT64_MAX) {
		sx_addr = *addr;
	}
	if (*size != UT32_MAX) {
		sx_size = *size;
	}
	if (sx_size < 1) {
		sx_size = 0xf0000;
	}
	*addr = sx_addr;
	*size = sx_size;
	if (RZ_STR_ISEMPTY(name)) {
		return rz_str_newf("mem.0x%" PFMT64x "_0x%x", sx_addr, sx_size);
	} else {
		return rz_str_newf("mem.%s", name);
	}
}

/**
 * Initialize ESIL memory stack region.
 *
 * \param core RzCore reference
 * \param name Optional name of the memory stack region. If NULL, a name is
 *             computed automatically based on \p addr and \p size
 * \param addr Base address of the stack region, if UT64_MAX it is automatically computed
 * \param size Size of the stack region, if UT32_MAX it is automatically computed
 */
RZ_API void rz_core_analysis_esil_init_mem(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size) {
	rz_return_if_fail(core && core->analysis);
	ut64 current_offset = core->offset;
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (!esil) {
		RZ_LOG_ERROR("core: cannot initialize ESIL\n");
		return;
	}
	RzIOMap *stack_map;
	if (!name && addr == UT64_MAX && size == UT32_MAX) {
		const char *fi = sdb_const_get(core->sdb, "aeim.fd", 0);
		if (fi) {
			// Close the fd associated with the aeim stack
			ut64 fd = sdb_atoi(fi);
			(void)rz_io_fd_close(core->io, fd);
		}
	}
	const char *pattern = rz_config_get(core->config, "esil.stack.pattern");
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);

	char uri[32];
	rz_strf(uri, "malloc://%u", size);
	esil->stack_fd = rz_io_fd_open(core->io, uri, RZ_PERM_RW, 0);
	if (!(stack_map = rz_io_map_add(core->io, esil->stack_fd, RZ_PERM_RW, 0LL, addr, size))) {
		rz_io_fd_close(core->io, esil->stack_fd);
		RZ_LOG_ERROR("core: cannot create map for the stack, fd %d got closed again\n", esil->stack_fd);
		free(stack_name);
		esil->stack_fd = 0;
		return;
	}
	rz_io_map_set_name(stack_map, stack_name);
	free(stack_name);
	char val[128], *v;
	v = sdb_itoa(esil->stack_fd, val, 10);
	sdb_set(core->sdb, "aeim.fd", v, 0);

	rz_config_set_b(core->config, "io.va", true);
	if (pattern && *pattern) {
		switch (*pattern) {
		case '0':
			// do nothing
			break;
		case 'd':
			rz_core_cmdf(core, "wopD %d @ 0x%" PFMT64x, size, addr);
			break;
		case 'i':
			rz_core_cmdf(core, "woe 0 255 1 @ 0x%" PFMT64x "!%d", addr, size);
			break;
		case 'w':
			rz_core_cmdf(core, "woe 0 0xffff 1 4 @ 0x%" PFMT64x "!%d", addr, size);
			break;
		}
	}
	rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_SP, addr + (size / 2)); // size / 2 to have free space in both directions
	rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_BP, addr + (size / 2));
	rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, current_offset);
	rz_core_reg_update_flags(core);
	esil->stack_addr = addr;
	esil->stack_size = size;
	initialize_stack(core, addr, size);
	rz_core_seek(core, current_offset, false);
}

RZ_IPI void rz_core_analysis_esil_init_mem_p(RzCore *core) {
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	RzFlagItem *fi = rz_flag_get(core->flags, "aeim.stack");
	if (fi) {
		addr = fi->offset;
		size = fi->size;
	} else {
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	if (esil) {
		esil->stack_addr = addr;
		esil->stack_size = size;
	}
	initialize_stack(core, addr, size);
	return;
}

/**
 * \brief Remove ESIL VM stack
 * \param core RzCore reference
 * \param name Optional name of the memory stack region. If NULL, a name is computed automatically based on \p addr
 *             and \p size
 * \param addr Base address of the stack region, if UT64_MAX it is automatically computed
 * \param size Size of the stack region, if UT32_MAX it is automatically computed
 */
RZ_API void rz_core_analysis_esil_init_mem_del(RZ_NONNULL RzCore *core, RZ_NULLABLE const char *name, ut64 addr, ut32 size) {
	rz_return_if_fail(core && core->analysis);
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);
	if (esil && esil->stack_fd > 2) { // 0, 1, 2 are reserved for stdio/stderr
		rz_io_fd_close(core->io, esil->stack_fd);
		// no need to kill the maps, rz_io_map_cleanup does that for us in the close
		esil->stack_fd = 0;
	} else {
		RZ_LOG_ERROR("core: cannot deinitialize %s\n", stack_name);
	}
	rz_flag_unset_name(core->flags, stack_name);
	rz_flag_unset_name(core->flags, "aeim.stack");
	sdb_unset(core->sdb, "aeim.fd", 0);
	free(stack_name);
}

/**
 * Initialize ESIL registers.
 *
 * \param core RzCore reference
 */
RZ_API void rz_core_analysis_esil_init_regs(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	rz_core_analysis_set_reg(core, "PC", core->offset);
}

RZ_API void rz_core_analysis_esil_step_over(RZ_NONNULL RzCore *core) {
	RzAnalysisOp *op = rz_core_analysis_op(core, rz_reg_getv(core->analysis->reg, rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC)), RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
	ut64 until_addr = UT64_MAX;
	if (op && op->type == RZ_ANALYSIS_OP_TYPE_CALL) {
		until_addr = op->addr + op->size;
	}
	rz_core_esil_step(core, until_addr, NULL, NULL, false);
	rz_analysis_op_free(op);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_until(RzCore *core, ut64 addr) {
	rz_core_esil_step(core, addr, NULL, NULL, true);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_step_over_untilexpr(RzCore *core, const char *expr) {
	rz_core_esil_step(core, UT64_MAX, expr, NULL, true);
	rz_core_reg_update_flags(core);
}

RZ_IPI void rz_core_analysis_esil_references_all_functions(RzCore *core) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		ut64 from = rz_analysis_function_min_addr(fcn);
		ut64 to = rz_analysis_function_max_addr(fcn);
		rz_core_analysis_esil(core, from, to - from, fcn);
	}
}

/**
 * Emulate \p n_instr instructions from \p addr. If \p until_addr is
 * specified and that address is met before all the instructions are emulated,
 * stop there.
 */
RZ_IPI void rz_core_analysis_esil_emulate(RzCore *core, ut64 addr, ut64 until_addr, int off) {
	RzAnalysisEsil *esil = core->analysis->esil;
	int i = 0, j = 0;
	ut8 *buf = NULL;
	RzAnalysisOp aop = { 0 };
	int ret, bsize = RZ_MAX(4096, core->blocksize);
	const int mininstrsz = rz_analysis_archinfo(core->analysis, RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = RZ_MAX(1, mininstrsz);
	const char *pc = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	int stacksize = rz_config_get_i(core->config, "esil.stack.depth");
	int iotrap = rz_config_get_i(core->config, "esil.iotrap");
	ut64 addrsize = rz_config_get_i(core->config, "esil.addr.size");

	if (!esil) {
		RZ_LOG_WARN("core: cmd_espc: creating new esil instance\n");
		if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
			return;
		}
		core->analysis->esil = esil;
	}
	buf = malloc(bsize);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %d byte(s)\n", bsize);
		return;
	}
	if (addr == -1) {
		addr = rz_reg_getv(core->analysis->reg, pc);
	}
	(void)rz_analysis_esil_setup(core->analysis->esil, core->analysis, 0, 0, 0); // int romem, int stats, int nonull) {
	ut64 cursp = rz_reg_getv(core->analysis->reg, "SP");
	ut64 oldoff = core->offset;
	const ut64 flags = RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_DISASM;
	for (i = 0, j = 0; j < off; i++, j++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			rz_io_read_at(core->io, addr, buf, bsize);
		}
		if (addr == until_addr) {
			break;
		}
		ret = rz_analysis_op(core->analysis, &aop, addr, buf + i, bsize - i, flags);
		if (ret < 1) {
			RZ_LOG_ERROR("core: failed esil analysis at 0x%08" PFMT64x "\n", addr);
			break;
		}
		// skip calls and such
		if (aop.type == RZ_ANALYSIS_OP_TYPE_CALL) {
			// nothing
		} else {
			rz_reg_setv(core->analysis->reg, "PC", aop.addr + aop.size);
			const char *e = RZ_STRBUF_SAFEGET(&aop.esil);
			if (e && *e) {
				// eprintf ("   0x%08llx %d  %s\n", aop.addr, ret, aop.mnemonic);
				(void)rz_analysis_esil_parse(esil, e);
			}
		}
		int inc = (core->search->align > 0) ? core->search->align - 1 : ret - 1;
		if (inc < 0) {
			inc = minopcode;
		}
		i += inc;
		addr += ret; // aop.size;
		rz_analysis_op_fini(&aop);
	}
	rz_core_seek(core, oldoff, true);
	rz_reg_setv(core->analysis->reg, "SP", cursp);
	free(buf);
}

RZ_IPI void rz_core_analysis_esil_emulate_bb(RzCore *core) {
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!bb) {
		RZ_LOG_ERROR("core: cannot find basic block for 0x%08" PFMT64x "\n", core->offset);
		return;
	}
	rz_core_analysis_esil_emulate(core, bb->addr, UT64_MAX, bb->ninstr);
}

RZ_IPI int rz_core_analysis_set_reg(RzCore *core, const char *regname, ut64 val) {
	RzRegItem *r = rz_reg_get(core->analysis->reg, regname, -1);
	if (!r) {
		int role = rz_reg_get_name_idx(regname);
		if (role != -1) {
			const char *alias = rz_reg_get_name(core->analysis->reg, role);
			if (alias) {
				r = rz_reg_get(core->analysis->reg, alias, -1);
			}
		}
	}
	if (!r) {
		RZ_LOG_ERROR("core: unknown register '%s'\n", regname);
		return -1;
	}
	rz_reg_set_value(core->analysis->reg, r, val);
	rz_core_reg_update_flags(core);
	return 0;
}

RZ_IPI void rz_core_analysis_esil_default(RzCore *core) {
	RzIOMap *map;
	RzListIter *iter;
	RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "analysis");
	if (!list) {
		return;
	}
	if (!strcmp("range", rz_config_get(core->config, "analysis.in"))) {
		ut64 from = rz_config_get_i(core->config, "analysis.from");
		ut64 to = rz_config_get_i(core->config, "analysis.to");
		if (to > from) {
			rz_core_analysis_esil(core, from, to - from, NULL);
		} else {
			RZ_LOG_ERROR("core: analysis.from > analysis.to\n");
		}
	} else {
		rz_list_foreach (list, iter, map) {
			if (map->perm & RZ_PERM_X) {
				rz_core_analysis_esil(core, map->itv.addr, map->itv.size, NULL);
			}
		}
	}
	rz_list_free(list);
}

RZ_IPI void rz_core_analysis_il_reinit(RzCore *core) {
	rz_analysis_il_vm_setup(core->analysis);
	if (core->analysis->il_vm) {
		// initialize the program counter with the current offset
		rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, core->offset);
		rz_core_reg_update_flags(core);
	}
}

/**
 * \brief Set a vm variable from user input
 * \return whether the set succeeded
 *
 * Sets the given var, or "PC" to the given value.
 * The type of the variable is handled dynamically.
 * This is intended for setting from user input only.
 */
RZ_IPI bool rz_core_analysis_il_vm_set(RzCore *core, const char *var_name, ut64 value) {
	rz_return_val_if_fail(core && core->analysis && var_name, false);

	RzAnalysisILVM *vm = core->analysis->il_vm;
	if (!vm) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return false;
	}

	if (!strcmp(var_name, "PC")) {
		RzBitVector *bv = rz_bv_new_from_ut64(vm->vm->pc->len, value);
		rz_bv_free(vm->vm->pc);
		vm->vm->pc = bv;
		return true;
	}

	RzILVar *var = rz_il_vm_get_var(vm->vm, RZ_IL_VAR_KIND_GLOBAL, var_name);
	if (!var) {
		return false;
	}
	RzILVal *val = NULL;
	switch (var->sort.type) {
	case RZ_IL_TYPE_PURE_BITVECTOR:
		val = rz_il_value_new_bitv(rz_bv_new_from_ut64(var->sort.props.bv.length, value));
		break;
	case RZ_IL_TYPE_PURE_BOOL:
		val = rz_il_value_new_bool(rz_il_bool_new(value != 0));
		break;
	case RZ_IL_TYPE_PURE_FLOAT:
		// TODO : ut64 value is enough for user input ?
		// TODO : type is different with given value ?
		RZ_LOG_ERROR("RzIL: Set float var from user input not supported yet");
		return false;
	}
	if (val) {
		rz_il_vm_set_global_var(vm->vm, var_name, val);
	}
	return true;
}

typedef struct il_print_t {
	RzOutputMode mode;
	const char *name;
	void *ptr;
} ILPrint;
#define p_sb(x)  ((RzStrBuf *)x)
#define p_tbl(x) ((RzTable *)x)
#define p_pj(x)  ((PJ *)x)

static void rzil_print_register_bool(bool value, ILPrint *p) {
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, rz_str_bool(value));
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "bool", rz_str_bool(value));
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_kb(p_pj(p->ptr), p->name, value);
		break;
	default:
		rz_cons_printf("%s\n", rz_str_bool(value));
		break;
	}
}

static void rzil_print_register_bitv(RzBitVector *number, ILPrint *p) {
	char *hex = rz_bv_as_hex_string(number, true);
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, hex);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "bitv", hex);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_ks(p_pj(p->ptr), p->name, hex);
		break;
	default:
		rz_cons_printf("%s\n", hex);
		break;
	}
	free(hex);
}

static void rzil_print_register_float(RzFloat *number, ILPrint *p) {
	char *hex = rz_float_as_hex_string(number, true);
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: %s", p->name, hex);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "float", hex);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_ks(p_pj(p->ptr), p->name, hex);
		break;
	default:
		rz_cons_printf("%s\n", hex);
		break;
	}
	free(hex);
}

RZ_IPI void rz_core_analysis_il_vm_status(RzCore *core, const char *var_name, RzOutputMode mode) {
	RzAnalysisILVM *vm = core->analysis->il_vm;
	if (!vm) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return;
	}

	ILPrint p = { 0 };
	p.mode = mode;

	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		p.ptr = rz_strbuf_new("");
		break;
	case RZ_OUTPUT_MODE_TABLE:
		p.ptr = rz_table_new();
		rz_table_set_columnsf(p_tbl(p.ptr), "sss", "variable", "type", "value");
		break;
	case RZ_OUTPUT_MODE_JSON:
		p.ptr = pj_new();
		pj_o(p_pj(p.ptr));
		break;
	default:
		break;
	}

	if (!var_name || !strcmp(var_name, "PC")) {
		p.name = "PC";
		rzil_print_register_bitv(vm->vm->pc, &p);
	}

	RzPVector *global_vars = rz_il_vm_get_all_vars(vm->vm, RZ_IL_VAR_KIND_GLOBAL);
	if (global_vars) {
		void **it;
		rz_pvector_foreach (global_vars, it) {
			RzILVar *var = *it;
			if (var_name && strcmp(var_name, var->name)) {
				continue;
			}
			p.name = var->name;
			RzILVal *val = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL, var->name);
			if (!val) {
				continue;
			}
			switch (val->type) {
			case RZ_IL_TYPE_PURE_BITVECTOR:
				rzil_print_register_bitv(val->data.bv, &p);
				break;
			case RZ_IL_TYPE_PURE_BOOL:
				rzil_print_register_bool(val->data.b->b, &p);
				break;
			case RZ_IL_TYPE_PURE_FLOAT:
				rzil_print_register_float(val->data.f, &p);
				break;
			default:
				rz_warn_if_reached();
				break;
			}
			if (var_name) {
				break;
			}
			if (rz_strbuf_length(p_sb(p.ptr)) > 95) {
				rz_cons_printf("%s\n", rz_strbuf_get(p_sb(p.ptr)));
				rz_strbuf_fini(p_sb(p.ptr));
			}
		}
		rz_pvector_free(global_vars);
	}

	char *out = NULL;
	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		if (rz_strbuf_length(p_sb(p.ptr)) > 0) {
			out = rz_strbuf_drain(p_sb(p.ptr));
		} else {
			rz_strbuf_free(p_sb(p.ptr));
			return;
		}
		break;
	case RZ_OUTPUT_MODE_TABLE:
		out = rz_table_tostring((RzTable *)p.ptr);
		rz_table_free(p_tbl(p.ptr));
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_end(p_pj(p.ptr));
		out = pj_drain(p_pj(p.ptr));
		break;
	default:
		return;
	}

	rz_cons_printf("%s\n", out);
	free(out);
}
#undef p_sb
#undef p_tbl
#undef p_pj

static bool step_assert_vm(RzCore *core) {
	if (!core->analysis || !core->analysis->il_vm) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return false;
	}
	return true;
}

static bool step_handle_result(RzCore *core, RzAnalysisILStepResult r) {
	switch (r) {
	case RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS:
		rz_core_reg_update_flags(core);
		return true;
	case RZ_ANALYSIS_IL_STEP_INVALID_OP:
		RZ_LOG_ERROR("RzIL: invalid instruction or lifting not implemented at address 0x%08" PFMT64x "\n",
			rz_reg_get_value_by_role(core->analysis->reg, RZ_REG_NAME_PC));
		break;
	default:
		RZ_LOG_ERROR("RzIL: stepping failed.\n");
		break;
	}
	return false;
}

static bool step_cond_n(RzAnalysisILVM *vm, void *user) {
	if (rz_cons_is_breaked()) {
		rz_cons_printf("Stepping was interrupted.\n");
		return false;
	}
	ut64 *n = user;
	if (!*n) {
		return false;
	}
	(*n)--;
	return true;
}

/**
 * Perform \p n steps starting at the PC given by analysis->reg in RzIL
 * \return false if an error occured (e.g. invalid op)
 */
RZ_IPI bool rz_core_il_step(RzCore *core, ut64 n) {
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while(core->analysis, core->analysis->il_vm, core->analysis->reg,
		step_cond_n, &n);
	return step_handle_result(core, r);
}

static bool step_cond_until(RzAnalysisILVM *vm, void *user) {
	if (rz_cons_is_breaked()) {
		rz_cons_printf("Stepping was interrupted.\n");
		return false;
	}
	ut64 *until = user;
	ut64 pc = rz_bv_to_ut64(vm->vm->pc);
	return pc != *until;
}

/**
 * Perform zero or more steps starting at the PC given by analysis->reg in RzIL
 * until reaching the given PC
 * \param until destination address where to stop
 * \return false if an error occured (e.g. invalid op)
 */
RZ_IPI bool rz_core_il_step_until(RzCore *core, ut64 until) {
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while(core->analysis, core->analysis->il_vm, core->analysis->reg,
		step_cond_until, &until);
	return step_handle_result(core, r);
}

/**
 * Perform a single step at the PC given by analysis->reg in RzIL and print any events that happened
 * \return false if an error occured (e.g. invalid op)
 */
RZ_IPI bool rz_core_analysis_il_step_with_events(RzCore *core, PJ *pj) {
	if (!rz_core_il_step(core, 1)) {
		return false;
	}

	if (!core->analysis || !core->analysis->il_vm) {
		return false;
	}

	RzILVM *vm = core->analysis->il_vm->vm;

	RzStrBuf *sb = NULL;
	RzListIter *it;
	RzILEvent *evt;

	bool evt_read = rz_config_get_b(core->config, "rzil.step.events.read");
	bool evt_write = rz_config_get_b(core->config, "rzil.step.events.write");

	if (!evt_read && !evt_write) {
		RZ_LOG_ERROR("RzIL: cannot print events when all the events are disabled.");
		RZ_LOG_ERROR("RzIL: please set 'rzil.step.events.read' or/and 'rzil.step.events.write' to true and try again.");
		return false;
	}

	if (!pj) {
		sb = rz_strbuf_new("");
	}
	rz_list_foreach (vm->events, it, evt) {
		if (!evt_read && (evt->type == RZ_IL_EVENT_MEM_READ || evt->type == RZ_IL_EVENT_VAR_READ)) {
			continue;
		} else if (!evt_write && (evt->type != RZ_IL_EVENT_MEM_READ && evt->type != RZ_IL_EVENT_VAR_READ)) {
			continue;
		}
		if (!pj) {
			rz_il_event_stringify(evt, sb);
			rz_strbuf_append(sb, "\n");
		} else {
			rz_il_event_json(evt, pj);
		}
	}
	if (!pj) {
		rz_cons_print(rz_strbuf_get(sb));
		rz_strbuf_free(sb);
	}
	return true;
}
