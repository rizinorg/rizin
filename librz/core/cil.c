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
#include <rz_util/ht_uu.h>
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
		const char *fi = sdb_const_get(core->sdb, "aeim.fd");
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
	sdb_set(core->sdb, "aeim.fd", v);

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
	sdb_unset(core->sdb, "aeim.fd");
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
		rz_analysis_op_init(&aop);
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

/**
 * \brief Re-initializes the intermediate language virtual machine for analysis
 *
 * This function re-initializes the IL (Intermediate Language) virtual machine for the analysis module.
 * The initial PC (Program Counter) is set with the current offset.
 * It then updates the register flags and syncs the register info back to the IL VM.
 *
 * \param core The RzCore object, which contains all the rizin classes and their functions.
 */
RZ_API void rz_core_analysis_il_reinit(RZ_NONNULL RzCore *core) {
	rz_return_if_fail(core);
	rz_analysis_il_vm_setup(core->analysis);
	if (core->analysis->il_vm) {
		// initialize the program counter with the current offset
		rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, core->offset);
		rz_core_reg_update_flags(core);

		// sync back to il vm
		rz_analysis_il_vm_sync_from_reg(core->analysis->il_vm, core->analysis->reg);
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
		RZ_LOG_ERROR("RzIL: Set float var from user input not supported yet\n");
		return false;
	}
	if (val) {
		rz_il_vm_set_global_var(vm->vm, var_name, val);
		rz_analysis_il_vm_sync_to_reg(vm, core->analysis->reg);
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
RZ_API bool rz_core_il_step(RZ_NONNULL RzCore *core, ut64 n) {
	rz_return_val_if_fail(core && n, false);
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
RZ_API bool rz_core_il_step_until(RZ_NONNULL RzCore *core, ut64 until) {
	rz_return_val_if_fail(core && until, false);
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while(core->analysis, core->analysis->il_vm, core->analysis->reg,
		step_cond_until, &until);
	return step_handle_result(core, r);
}

/**
 * Perform zero or more steps starting at the PC given by analysis->reg in RzIL
 * until reaching the given PC and output VM changes (read & write)
 * \param until destination address where to stop
 * \return false if an error occured (e.g. invalid op)
 */
RZ_API bool rz_core_il_step_until_with_events(RZ_NONNULL RzCore *core, ut64 until) {
	rz_return_val_if_fail(core && until, false);
	if (!step_assert_vm(core)) {
		return false;
	}
	RzAnalysisILStepResult r = rz_analysis_il_vm_step_while_with_events(
		core->analysis, core->analysis->il_vm, core->analysis->reg,
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
	void **it;
	RzILEvent *evt;

	bool evt_read = rz_config_get_b(core->config, "rzil.step.events.read");
	bool evt_write = rz_config_get_b(core->config, "rzil.step.events.write");

	if (!evt_read && !evt_write) {
		RZ_LOG_ERROR("RzIL: cannot print events when all the events are disabled.\n");
		RZ_LOG_ERROR("RzIL: please set 'rzil.step.events.read' or/and 'rzil.step.events.write' to true and try again.\n");
		return false;
	}

	if (!pj) {
		sb = rz_strbuf_new("");
	}
	rz_pvector_foreach (vm->events, it) {
		evt = *it;
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

static void core_colorify_il_statement(RzConsContext *ctx, const char *il_stmt, const char delim, ut64 addr) {
	rz_cons_printf("%s0x%" PFMT64x Color_RESET "%c", ctx->pal.label, addr, delim);
	if (RZ_STR_ISEMPTY(il_stmt)) {
		rz_cons_newline();
		return;
	}
	const char *color = NULL;
	size_t prev = 0, len = strlen(il_stmt);
	for (size_t i = 0; i < len; ++i) {
		const char ch = il_stmt[i];
		if (ch == '(') {
			color = ctx->pal.flow;
			int plen = i - prev;
			rz_cons_printf("%.*s(", plen, il_stmt + prev);
			prev = i + 1;
		} else if (ch == ')' && color) {
			int plen = i - prev;
			rz_cons_printf("%s%.*s" Color_RESET, color, plen, il_stmt + prev);
			prev = i;
			color = NULL;
		} else if (ch == ' ' && color) {
			int plen = i - prev;
			rz_cons_printf("%s%.*s" Color_RESET, color, plen, il_stmt + prev);
			prev = i;
			color = NULL;
		} else if ((i - 1) == prev && il_stmt[prev] == ' ') {
			color = IS_DIGIT(ch) ? ctx->pal.num : ctx->pal.comment;
		}
	}
	if (prev < len) {
		int plen = len - prev;
		if (color) {
			rz_cons_printf("%s%.*s" Color_RESET, color, plen, il_stmt + prev);
		} else {
			rz_cons_printf("%.*s", plen, il_stmt + prev);
		}
	}
	rz_cons_newline();
}

RZ_IPI void rz_core_il_cons_print(RZ_NONNULL RzCore *core, RZ_NONNULL RZ_BORROW RzIterator *iter, bool pretty) {
	rz_return_if_fail(core && iter);
	bool colorize = rz_config_get_i(core->config, "scr.color") > 0;
	const char *il_stmt = NULL;
	const char delim = pretty ? '\n' : ' ';
	RzStrBuf sb;

	RzAnalysisOp *op = NULL;
	rz_iterator_foreach(iter, op) {
		if (!op->il_op) {
			RZ_LOG_DEBUG("Empty IL at 0x%08" PFMT64x "...\n", op->addr);
			break;
		}

		rz_strbuf_init(&sb);
		rz_il_op_effect_stringify(op->il_op, &sb, pretty);
		il_stmt = rz_strbuf_get(&sb);
		if (colorize) {
			core_colorify_il_statement(core->cons->context, il_stmt, delim, op->addr);
		} else {
			rz_cons_printf("0x%" PFMT64x "%c%s\n", op->addr, delim, il_stmt);
		}
		rz_strbuf_fini(&sb);
	}
}

// used to speedup strcmp with rz_config_get in loops
enum {
	RZ_ARCH_THUMB,
	RZ_ARCH_ARM32,
	RZ_ARCH_ARM64,
	RZ_ARCH_MIPS
};
// 128M
#define MAX_SCAN_SIZE 0x7ffffff

#define ESILISTATE core->analysis->esilinterstate

static void cccb(void *u) {
	RzCore *core = u;
	ESILISTATE->analysis_stop = true;
	eprintf("^C\n");
}

// dup with isValidAddress
static bool myvalid(RzIO *io, ut64 addr) {
	if (addr < 0x100) {
		return false;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) { // the best of the best of the best :(
		return false;
	}
	if (!rz_io_is_valid_offset(io, addr, 0)) {
		return false;
	}
	return true;
}

typedef struct {
	RzAnalysisOp *op;
	RzAnalysisFunction *fcn;
	const char *spname;
	ut64 initial_sp;
	RzStackAddr shadow_store;
} EsilBreakCtx;

static const char *reg_name_for_access(RzAnalysisOp *op, RzAnalysisVarAccessType type) {
	if (type == RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst && op->dst->reg) {
			return op->dst->reg->name;
		}
	} else {
		if (op->src[0] && op->src[0]->reg) {
			return op->src[0]->reg->name;
		}
	}
	return NULL;
}

static ut64 delta_for_access(RzAnalysisOp *op, RzAnalysisVarAccessType type) {
	if (type == RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst) {
			return op->dst->imm + op->dst->delta;
		}
	} else {
		if (op->src[1] && (op->src[1]->imm || op->src[1]->delta)) {
			return op->src[1]->imm + op->src[1]->delta;
		}
		if (op->src[0]) {
			return op->src[0]->imm + op->src[0]->delta;
		}
	}
	return 0;
}

static void handle_var_stack_access(RzAnalysisEsil *esil, ut64 addr, RzAnalysisVarAccessType type, int len) {
	EsilBreakCtx *ctx = esil->user;
	const char *regname = reg_name_for_access(ctx->op, type);
	if (ctx->fcn && regname) {
		ut64 spaddr = rz_reg_getv(esil->analysis->reg, ctx->spname);
		if (addr >= spaddr && addr < ctx->initial_sp) {
			st64 stack_off = addr - ctx->initial_sp + ctx->shadow_store;
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_stack(&stor, stack_off);
			RzAnalysisVar *var = rz_analysis_function_get_var_at(ctx->fcn, &stor);
			if (!var && stack_off >= -ctx->fcn->maxstack) {
				// "s" for positive shadow space to avoid conflicts
				char *varname = rz_str_newf("var_%s%" PFMT64x "h", stack_off > 0 ? "s" : "", RZ_ABS(stack_off));
				var = rz_analysis_function_set_var(ctx->fcn, &stor, NULL, len, varname);
				free(varname);
			}
			if (var) {
				rz_analysis_var_set_access(var, regname, ctx->op->addr, type, delta_for_access(ctx->op, type));
			}
		}
	}
}

static int esilbreak_mem_write(RzAnalysisEsil *esil, ut64 addr, const ut8 *buf, int len) {
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, len);
	return 1;
}

// TODO differentiate endian-aware mem_read with other reads
static int esilbreak_mem_read(RzAnalysisEsil *esil, ut64 addr, ut8 *buf, int len) {
	RzCore *core = esil->analysis->coreb.core;
	ut8 str[128];
	if (addr != UT64_MAX) {
		ESILISTATE->last_read = addr;
	}
	handle_var_stack_access(esil, addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, len);
	if (myvalid(core->io, addr) && rz_io_read_at(core->io, addr, (ut8 *)buf, len)) {
		ut64 refptr;
		bool trace = true;
		switch (len) {
		case 2:
			ESILISTATE->last_data = refptr = (ut64)rz_read_ble16(buf, esil->analysis->big_endian);
			break;
		case 4:
			ESILISTATE->last_data = refptr = (ut64)rz_read_ble32(buf, esil->analysis->big_endian);
			break;
		case 8:
			ESILISTATE->last_data = refptr = rz_read_ble64(buf, esil->analysis->big_endian);
			break;
		default:
			trace = false;
			rz_io_read_at(core->io, addr, (ut8 *)buf, len);
			break;
		}
		// TODO incorrect
		if (trace && myvalid(core->io, refptr)) {
			str[0] = 0;
			if (rz_io_read_at(core->io, refptr, str, sizeof(str)) < 1) {
				// RZ_LOG_ERROR("core: invalid read\n");
				str[0] = 0;
			} else {
				rz_analysis_xrefs_set(core->analysis, esil->address, refptr, RZ_ANALYSIS_XREF_TYPE_DATA);
				str[sizeof(str) - 1] = 0;
				rz_core_add_string_ref(core, esil->address, refptr);
				ESILISTATE->last_data = UT64_MAX;
			}
		}

		/** resolve ptr */
		rz_analysis_xrefs_set(core->analysis, esil->address, addr, RZ_ANALYSIS_XREF_TYPE_DATA);
	}
	return 0; // fallback
}

static int esilbreak_reg_write(RzAnalysisEsil *esil, const char *name, ut64 *val) {
	if (!esil) {
		return 0;
	}
	RzAnalysis *analysis = esil->analysis;
	EsilBreakCtx *ctx = esil->user;
	RzAnalysisOp *op = ctx->op;
	RzCore *core = analysis->coreb.core;
	handle_var_stack_access(esil, *val, RZ_ANALYSIS_VAR_ACCESS_TYPE_PTR, rz_analysis_guessed_mem_access_width(esil->analysis));
	// specific case to handle blx/bx cases in arm through emulation
	//  XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (analysis && analysis->opt.armthumb) {
		if (analysis->cur && analysis->cur->arch && analysis->bits < 33 &&
			strstr(analysis->cur->arch, "arm") && !strcmp(name, "pc") && op) {
			switch (op->type) {
			case RZ_ANALYSIS_OP_TYPE_RCALL: // BLX
			case RZ_ANALYSIS_OP_TYPE_RJMP: // BX
				// maybe UJMP/UCALL is enough here
				if (!(*val & 1)) {
					rz_analysis_hint_set_bits(analysis, *val, 32);
				} else {
					ut64 snv = rz_reg_getv(analysis->reg, "pc");
					if (snv != UT32_MAX && snv != UT64_MAX) {
						if (rz_io_is_valid_offset(analysis->iob.io, *val, 1)) {
							rz_analysis_hint_set_bits(analysis, *val - 1, 16);
						}
					}
				}
				break;
			default:
				break;
			}
		}
	}
	if (core->rasm->bits == 32 && strstr(core->rasm->cur->name, "arm")) {
		if ((!(at & 1)) && rz_io_is_valid_offset(analysis->iob.io, at, 0)) { //  !core->analysis->opt.noncode)) {
			rz_core_add_string_ref(analysis->coreb.core, esil->address, at);
		}
	}
	return 0;
}

static void getpcfromstack(RzCore *core, RzAnalysisEsil *esil) {
	ut64 cur;
	ut64 addr;
	ut64 size;
	int idx;
	RzAnalysisEsil esil_cpy;
	RzAnalysisOp op = { 0 };
	RzAnalysisFunction *fcn = NULL;
	ut8 *buf = NULL;
	char *tmp_esil_str = NULL;
	int tmp_esil_str_len;
	const char *esilstr;
	const int maxaddrlen = 20;
	const char *spname = NULL;
	if (!esil) {
		return;
	}

	memcpy(&esil_cpy, esil, sizeof(esil_cpy));
	addr = cur = esil_cpy.cur;
	fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (!fcn) {
		return;
	}

	size = rz_analysis_function_linear_size(fcn);
	if (size <= 0) {
		return;
	}

	buf = malloc(size + 2);
	if (!buf) {
		perror("malloc");
		return;
	}

	rz_io_read_at(core->io, addr, buf, size + 1);

	// TODO Hardcoding for 2 instructions (mov e_p,[esp];ret). More work needed
	idx = 0;
	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, cur, buf + idx, size - idx, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
		op.size <= 0 ||
		(op.type != RZ_ANALYSIS_OP_TYPE_MOV && op.type != RZ_ANALYSIS_OP_TYPE_CMOV)) {
		goto err_analysis_op;
	}

	rz_asm_set_pc(core->rasm, cur);
	esilstr = RZ_STRBUF_SAFEGET(&op.esil);
	if (!esilstr) {
		goto err_analysis_op;
	}
	// Ugly code
	// This is a hack, since ESIL doesn't always preserve values pushed on the stack. That probably needs to be rectified
	spname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	if (!spname || !*spname) {
		goto err_analysis_op;
	}
	tmp_esil_str_len = strlen(esilstr) + strlen(spname) + maxaddrlen;
	tmp_esil_str = (char *)malloc(tmp_esil_str_len);
	if (!tmp_esil_str) {
		goto err_analysis_op;
	}
	tmp_esil_str[tmp_esil_str_len - 1] = '\0';
	snprintf(tmp_esil_str, tmp_esil_str_len - 1, "%s,[", spname);
	if (!*esilstr || (strncmp(esilstr, tmp_esil_str, strlen(tmp_esil_str)))) {
		free(tmp_esil_str);
		goto err_analysis_op;
	}

	snprintf(tmp_esil_str, tmp_esil_str_len - 1, "%20" PFMT64u "%s", esil_cpy.old, &esilstr[strlen(spname) + 4]);
	rz_str_trim(tmp_esil_str);
	idx += op.size;
	rz_analysis_esil_set_pc(&esil_cpy, cur);
	rz_analysis_esil_parse(&esil_cpy, tmp_esil_str);
	rz_analysis_esil_stack_free(&esil_cpy);
	free(tmp_esil_str);

	cur = addr + idx;
	rz_analysis_op_fini(&op);
	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, cur, buf + idx, size - idx, RZ_ANALYSIS_OP_MASK_ESIL) <= 0 ||
		op.size <= 0 ||
		(op.type != RZ_ANALYSIS_OP_TYPE_RET && op.type != RZ_ANALYSIS_OP_TYPE_CRET)) {
		goto err_analysis_op;
	}
	rz_asm_set_pc(core->rasm, cur);

	esilstr = RZ_STRBUF_SAFEGET(&op.esil);
	rz_analysis_esil_set_pc(&esil_cpy, cur);
	if (!esilstr || !*esilstr) {
		goto err_analysis_op;
	}
	rz_analysis_esil_parse(&esil_cpy, esilstr);
	rz_analysis_esil_stack_free(&esil_cpy);

	memcpy(esil, &esil_cpy, sizeof(esil_cpy));

err_analysis_op:
	rz_analysis_op_fini(&op);
	free(buf);
}

typedef struct {
	ut64 start_addr;
	ut64 end_addr;
	RzAnalysisFunction *fcn;
	RzAnalysisBlock *cur_bb;
	RzList /*<RzAnalysisBlock *>*/ *bbl, *path;
	RzList /*<RzAnalysisCaseOp *>*/ *switch_path;
} IterCtx;

static int find_bb(ut64 *addr, RzAnalysisBlock *bb, void *user) {
	return *addr != bb->addr;
}

static RzList /*<void *>*/ *pvector_to_list(RzPVector /*<void *>*/ *pvec) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (pvec, it) {
		rz_list_append(list, *it);
	}
	return list;
}

static inline bool get_next_i(IterCtx *ctx, size_t *next_i) {
	(*next_i)++;
	ut64 cur_addr = *next_i + ctx->start_addr;
	if (ctx->fcn) {
		if (!ctx->cur_bb) {
			ctx->path = rz_list_new();
			ctx->switch_path = rz_list_new();
			ctx->bbl = pvector_to_list(ctx->fcn->bbs);
			ctx->cur_bb = rz_analysis_get_block_at(ctx->fcn->analysis, ctx->fcn->addr);
			rz_list_push(ctx->path, ctx->cur_bb);
		}
		RzAnalysisBlock *bb = ctx->cur_bb;
		if (cur_addr >= bb->addr + bb->size) {
			rz_reg_arena_push(ctx->fcn->analysis->reg);
			RzListIter *bbit = NULL;
			if (bb->switch_op) {
				RzAnalysisCaseOp *cop = rz_list_first(bb->switch_op->cases);
				bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb, NULL);
				if (bbit) {
					rz_list_push(ctx->switch_path, bb->switch_op->cases->head);
				}
			} else {
				bbit = rz_list_find(ctx->bbl, &bb->jump, (RzListComparator)find_bb, NULL);
				if (!bbit && bb->fail != UT64_MAX) {
					bbit = rz_list_find(ctx->bbl, &bb->fail, (RzListComparator)find_bb, NULL);
				}
			}
			if (!bbit) {
				RzListIter *cop_it = rz_list_last(ctx->switch_path);
				RzAnalysisBlock *prev_bb = NULL;
				do {
					rz_reg_arena_pop(ctx->fcn->analysis->reg);
					prev_bb = rz_list_pop(ctx->path);
					if (prev_bb->fail != UT64_MAX) {
						bbit = rz_list_find(ctx->bbl, &prev_bb->fail, (RzListComparator)find_bb, NULL);
						if (bbit) {
							rz_reg_arena_push(ctx->fcn->analysis->reg);
							rz_list_push(ctx->path, prev_bb);
						}
					}
					if (!bbit && cop_it) {
						RzAnalysisCaseOp *cop = rz_list_iter_get_data(cop_it);
						if (cop->jump == prev_bb->addr && rz_list_iter_has_next(cop_it)) {
							cop = rz_list_iter_get_next_data(cop_it);
							rz_list_pop(ctx->switch_path);
							rz_list_push(ctx->switch_path, rz_list_iter_get_next(cop_it));
							cop_it = rz_list_iter_get_next(cop_it);
							bbit = rz_list_find(ctx->bbl, &cop->jump, (RzListComparator)find_bb, NULL);
						}
					}
					if (cop_it && !rz_list_iter_has_next(cop_it)) {
						rz_list_pop(ctx->switch_path);
						cop_it = rz_list_last(ctx->switch_path);
					}
				} while (!bbit && !rz_list_empty(ctx->path));
			}
			if (!bbit) {
				rz_list_free(ctx->path);
				rz_list_free(ctx->switch_path);
				rz_list_free(ctx->bbl);
				return false;
			}
			ctx->cur_bb = rz_list_iter_get_data(bbit);
			rz_list_push(ctx->path, ctx->cur_bb);
			rz_list_delete(ctx->bbl, bbit);
			*next_i = ctx->cur_bb->addr - ctx->start_addr;
		}
	} else if (cur_addr >= ctx->end_addr) {
		return false;
	}
	return true;
}

/**
 * Analyze references with esil (aae)
 *
 * \p addr start address
 * \p size number of bytes to analyze
 * \p fcn optional, when analyzing for a specific function
 */
RZ_API void rz_core_analysis_esil(RzCore *core, ut64 addr, ut64 size, RZ_NULLABLE RzAnalysisFunction *fcn) {
	bool cfg_analysis_strings = rz_config_get_i(core->config, "analysis.strings");
	bool emu_lazy = rz_config_get_i(core->config, "emu.lazy");
	bool gp_fixed = rz_config_get_i(core->config, "analysis.gpfixed");
	ut64 refptr = 0LL;
	const char *pcname;
	RzAnalysisOp op = RZ_EMPTY;
	ut8 *buf = NULL;
	ut64 iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	bool archIsArm = false;
	ut64 start = addr;
	ut64 end = addr + size;
	if (end <= start) {
		return;
	}
	iend = end - start;
	if (iend < 0) {
		return;
	} else if (iend > MAX_SCAN_SIZE) {
		RZ_LOG_WARN("core: not going to analyze 0x%08" PFMT64x " bytes.\n", iend);
		return;
	}

	buf = malloc((size_t)iend + 2);
	if (!buf) {
		RZ_LOG_ERROR("core: cannot allocate %" PFMT64u "\n", (iend + 2));
		return;
	}
	ESILISTATE->last_read = UT64_MAX;
	rz_io_read_at(core->io, start, buf, iend + 1);
	rz_reg_arena_push(core->analysis->reg);

	RzAnalysisEsil *ESIL = core->analysis->esil;
	if (!ESIL) {
		rz_core_analysis_esil_reinit(core);
		ESIL = core->analysis->esil;
		if (!ESIL) {
			RZ_LOG_ERROR("core: ESIL has not been initialized\n");
			goto out_pop_regs;
		}
		rz_core_analysis_esil_init_mem(core, NULL, UT64_MAX, UT32_MAX);
	}
	const char *spname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	EsilBreakCtx ctx = {
		.op = &op,
		.fcn = fcn,
		.spname = spname,
		.initial_sp = rz_reg_getv(core->analysis->reg, spname),
		.shadow_store = fcn && fcn->cc ? rz_analysis_cc_shadow_store(core->analysis, fcn->cc) : 0
	};
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;
	// this is necessary for the hook to read the id of RzAnalysisOp
	ESIL->user = &ctx;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;
	if (ctx.shadow_store) {
		rz_reg_setv(core->analysis->reg, ctx.spname, ctx.initial_sp - ctx.shadow_store);
	}
	// RZ_LOG_ERROR("core: analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	//  TODO: backup/restore register state before/after analysis
	pcname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
	if (!pcname || !*pcname) {
		RZ_LOG_ERROR("core: cannot find program counter register in the current profile.\n");
		goto out_pop_regs;
	}
	ESILISTATE->analysis_stop = false;
	rz_cons_break_push(cccb, core);

	int arch = -1;
	if (!strcmp(core->analysis->cur->arch, "arm")) {
		switch (core->analysis->bits) {
		case 64: arch = RZ_ARCH_ARM64; break;
		case 32: arch = RZ_ARCH_ARM32; break;
		case 16: arch = RZ_ARCH_THUMB; break;
		}
		archIsArm = true;
	}

	ut64 gp = rz_config_get_i(core->config, "analysis.gp");
	const char *gp_reg = NULL;
	if (!strcmp(core->analysis->cur->arch, "mips")) {
		gp_reg = "gp";
		arch = RZ_ARCH_MIPS;
	}

	RZ_NULLABLE const char *sn = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SN);

	IterCtx ictx = { start, end, fcn, NULL };
	size_t i = 0;
	do {
		if (ESILISTATE->analysis_stop || rz_cons_is_breaked()) {
			break;
		}
		size_t i_old = i;
		ut64 cur = start + i;
		if (!rz_io_is_valid_offset(core->io, cur, 0)) {
			break;
		}
		{
			RzPVector *list = rz_meta_get_all_in(core->analysis, cur, RZ_META_TYPE_ANY);
			void **it;
			rz_pvector_foreach (list, it) {
				RzIntervalNode *node = *it;
				RzAnalysisMetaItem *meta = node->data;
				switch (meta->type) {
				case RZ_META_TYPE_DATA:
				case RZ_META_TYPE_STRING:
				case RZ_META_TYPE_FORMAT:
					i += 4;
					rz_pvector_free(list);
					goto repeat;
				default:
					break;
				}
			}
			rz_pvector_free(list);
		}

		/* realign address if needed */
		rz_core_seek_arch_bits(core, cur);
		int opalign = core->analysis->pcalign;
		if (opalign > 0) {
			cur -= (cur % opalign);
		}

		rz_analysis_op_fini(&op);
		rz_asm_set_pc(core->rasm, cur);
		if (i >= iend) {
			goto repeat;
		}
		rz_analysis_op_init(&op);
		rz_analysis_op(core->analysis, &op, cur, buf + i, iend - i, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_HINT);
		// if (op.type & 0x80000000 || op.type == 0) {
		if (op.type == RZ_ANALYSIS_OP_TYPE_ILL || op.type == RZ_ANALYSIS_OP_TYPE_UNK) {
			// i += 2
			rz_analysis_op_fini(&op);
			goto repeat;
		}
		// we need to check again i because buf+i may goes beyond its boundaries
		// because of i+= minopsize - 1
		if (i > iend) {
			goto repeat;
		}
		if (op.size < 1) {
			i += minopsize - 1;
			goto repeat;
		}
		if (emu_lazy) {
			if (op.type & RZ_ANALYSIS_OP_TYPE_REP) {
				i += op.size - 1;
				goto repeat;
			}
			switch (op.type & RZ_ANALYSIS_OP_TYPE_MASK) {
			case RZ_ANALYSIS_OP_TYPE_JMP:
			case RZ_ANALYSIS_OP_TYPE_CJMP:
			case RZ_ANALYSIS_OP_TYPE_CALL:
			case RZ_ANALYSIS_OP_TYPE_RET:
			case RZ_ANALYSIS_OP_TYPE_ILL:
			case RZ_ANALYSIS_OP_TYPE_NOP:
			case RZ_ANALYSIS_OP_TYPE_UJMP:
			case RZ_ANALYSIS_OP_TYPE_IO:
			case RZ_ANALYSIS_OP_TYPE_LEAVE:
			case RZ_ANALYSIS_OP_TYPE_CRYPTO:
			case RZ_ANALYSIS_OP_TYPE_CPL:
			case RZ_ANALYSIS_OP_TYPE_SYNC:
			case RZ_ANALYSIS_OP_TYPE_SWI:
			case RZ_ANALYSIS_OP_TYPE_CMP:
			case RZ_ANALYSIS_OP_TYPE_ACMP:
			case RZ_ANALYSIS_OP_TYPE_NULL:
			case RZ_ANALYSIS_OP_TYPE_CSWI:
			case RZ_ANALYSIS_OP_TYPE_TRAP:
				i += op.size - 1;
				goto repeat;
			//  those require write support
			case RZ_ANALYSIS_OP_TYPE_PUSH:
			case RZ_ANALYSIS_OP_TYPE_POP:
				i += op.size - 1;
				goto repeat;
			}
		}
		if (sn && op.type == RZ_ANALYSIS_OP_TYPE_SWI) {
			char tmpbuf[256];
			rz_flag_space_set(core->flags, RZ_FLAGS_FS_SYSCALLS);
			int snv = (arch == RZ_ARCH_THUMB) ? op.val : (int)rz_reg_getv(core->analysis->reg, sn);
			RzSyscallItem *si = rz_syscall_get(core->analysis->syscall, snv, -1);
			if (si) {
				//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				rz_flag_set_next(core->flags, rz_strf(tmpbuf, "syscall.%s", si->name), cur, 1);
				rz_syscall_item_free(si);
			} else {
				// todo were doing less filtering up top because we can't match against 80 on all platforms
				//  might get too many of this path now..
				//	eprintf ("0x%08"PFMT64x" SYSCALL %d\n", cur, snv);
				rz_flag_set_next(core->flags, rz_strf(tmpbuf, "syscall.%d", snv), cur, 1);
			}
			rz_flag_space_set(core->flags, NULL);
		}
		const char *esilstr = RZ_STRBUF_SAFEGET(&op.esil);
		i += op.size - 1;
		if (!esilstr || !*esilstr) {
			goto repeat;
		}
		rz_analysis_esil_set_pc(ESIL, cur);
		rz_reg_setv(core->analysis->reg, pcname, cur + op.size);
		if (gp_fixed && gp_reg) {
			rz_reg_setv(core->analysis->reg, gp_reg, gp);
		}
		(void)rz_analysis_esil_parse(ESIL, esilstr);
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_LEA:
			// arm64
			if (core->analysis->cur && arch == RZ_ARCH_ARM64) {
				if (CHECKREF(ESIL->cur)) {
					rz_analysis_xrefs_set(core->analysis, cur, ESIL->cur, RZ_ANALYSIS_XREF_TYPE_STRING);
				}
			}
			if (CHECKREF(ESIL->cur)) {
				if (op.ptr && rz_io_is_valid_offset(core->io, op.ptr, !core->analysis->opt.noncode)) {
					rz_analysis_xrefs_set(core->analysis, cur, op.ptr, RZ_ANALYSIS_XREF_TYPE_STRING);
				} else {
					rz_analysis_xrefs_set(core->analysis, cur, ESIL->cur, RZ_ANALYSIS_XREF_TYPE_STRING);
				}
			}
			if (cfg_analysis_strings) {
				rz_core_add_string_ref(core, op.addr, op.ptr);
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			/* TODO: test if this is valid for other archs too */
			if (core->analysis->cur && archIsArm) {
				/* This code is known to work on Thumb, ARM and ARM64 */
				ut64 dst = ESIL->cur;
				if (CHECKREF(dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
				}
				if (cfg_analysis_strings) {
					rz_core_add_string_ref(core, op.addr, dst);
				}
			} else if ((core->analysis->bits == 32 && core->analysis->cur && arch == RZ_ARCH_MIPS)) {
				ut64 dst = ESIL->cur;
				if (!op.src[0] || !op.src[0]->reg || !op.src[0]->reg->name) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "sp")) {
					break;
				}
				if (!strcmp(op.src[0]->reg->name, "zero")) {
					break;
				}
				if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) && myvalid(core->io, dst)) {
					RzFlagItem *f;
					char *str = NULL;
					if (CHECKREF(dst) || CHECKREF(cur)) {
						rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
						if (cfg_analysis_strings) {
							rz_core_add_string_ref(core, op.addr, dst);
						}
						if ((f = rz_core_flag_get_by_spaces(core->flags, dst))) {
							rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, f->name);
						} else if (rz_core_get_string_at(core, dst, &str, NULL, NULL, true)) {
							char *str2 = rz_str_newf("esilref: '%s'", str);
							// HACK avoid format string inside string used later as format
							// string crashes disasm inside agf under some conditions.
							rz_str_replace_char(str2, '%', '&');
							rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, cur, str2);
							free(str);
							free(str2);
						}
					}
				}
			}
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD: {
			ut64 dst = ESILISTATE->last_read;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
					if (cfg_analysis_strings) {
						rz_core_add_string_ref(core, op.addr, dst);
					}
				}
			}
			dst = ESILISTATE->last_data;
			if (dst != UT64_MAX && CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_DATA);
					if (cfg_analysis_strings) {
						rz_core_add_string_ref(core, op.addr, dst);
					}
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_JMP: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_CODE);
				}
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_CALL: {
			ut64 dst = op.jump;
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					rz_analysis_xrefs_set(core->analysis, cur, dst, RZ_ANALYSIS_XREF_TYPE_CALL);
				}
				ESIL->old = cur + op.size;
				getpcfromstack(core, ESIL);
			}
		} break;
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
		case RZ_ANALYSIS_OP_TYPE_MJMP: {
			ut64 dst = ESIL->jump_target;
			if (dst == 0 || dst == UT64_MAX) {
				dst = rz_reg_getv(core->analysis->reg, pcname);
			}
			if (CHECKREF(dst)) {
				if (myvalid(core->io, dst)) {
					RzAnalysisXRefType ref =
						(op.type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_UCALL
						? RZ_ANALYSIS_XREF_TYPE_CALL
						: RZ_ANALYSIS_XREF_TYPE_CODE;
					rz_analysis_xrefs_set(core->analysis, cur, dst, ref);
					rz_core_analysis_fcn(core, dst, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
				}
			}
		} break;
		default:
			break;
		}
		rz_analysis_esil_stack_free(ESIL);
	repeat:
		if (!rz_analysis_get_block_at(core->analysis, cur)) {
			for (size_t bb_i = i_old + 1; bb_i <= i; bb_i++) {
				if (rz_analysis_get_block_at(core->analysis, start + bb_i)) {
					i = bb_i - 1;
					break;
				}
			}
		}
		if (i > iend) {
			break;
		}
	} while (get_next_i(&ictx, &i));
#undef CHECKREF
	free(buf);
	ESIL->cb.hook_mem_read = NULL;
	ESIL->cb.hook_mem_write = NULL;
	ESIL->cb.hook_reg_write = NULL;
	ESIL->user = NULL;
	rz_analysis_op_fini(&op);
	rz_cons_break_pop();
out_pop_regs:
	// restore register
	rz_reg_arena_pop(core->analysis->reg);
}
