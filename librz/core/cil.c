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

RZ_IPI void rz_core_analysis_esil_reinit(RzCore *core) {
	rz_analysis_esil_free(core->analysis->esil);
	core_esil_init(core);
	// reinitialize
	rz_reg_set_value_by_role(core->analysis->reg, RZ_REG_NAME_PC, core->offset);
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
						eprintf("Couldn't write at %" PFMT64x "\n", addr + i);
					}
					free(buf);
				} else {
					eprintf("Couldn't generate pattern of length %" PFMT64d "\n", left);
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
				rz_core_cmdf(core, "wow 00 @ 0x%" PFMT64x "!0x%" PFMT64x, addr + i, left);
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
RZ_IPI void rz_core_analysis_esil_init_mem(RzCore *core, const char *name, ut64 addr, ut32 size) {
	ut64 current_offset = core->offset;
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	if (!esil) {
		eprintf("Cannot initialize ESIL\n");
		return;
	}
	RzIOMap *stack_map;
	if (!name && addr == UT64_MAX && size == UT32_MAX) {
		char *fi = sdb_get(core->sdb, "aeim.fd", 0);
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
		eprintf("Cannot create map for tha stack, fd %d got closed again\n", esil->stack_fd);
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

RZ_IPI void rz_core_analysis_esil_init_mem_del(RzCore *core, const char *name, ut64 addr, ut32 size) {
	rz_core_analysis_esil_init(core);
	RzAnalysisEsil *esil = core->analysis->esil;
	char *stack_name = get_esil_stack_name(core, name, &addr, &size);
	if (esil->stack_fd > 2) { // 0, 1, 2 are reserved for stdio/stderr
		rz_io_fd_close(core->io, esil->stack_fd);
		// no need to kill the maps, rz_io_map_cleanup does that for us in the close
		esil->stack_fd = 0;
	} else {
		eprintf("Cannot deinitialize %s\n", stack_name);
	}
	rz_flag_unset_name(core->flags, stack_name);
	rz_flag_unset_name(core->flags, "aeim.stack");
	sdb_unset(core->sdb, "aeim.fd", 0);
	free(stack_name);
	return;
}

/**
 * Initialize ESIL registers.
 *
 * \param core RzCore reference
 */
RZ_IPI void rz_core_analysis_esil_init_regs(RzCore *core) {
	rz_core_analysis_set_reg(core, "PC", core->offset);
}

RZ_IPI void rz_core_analysis_esil_step_over(RzCore *core) {
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
	ut64 cur_seek = core->offset;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		rz_core_seek(core, fcn->addr, true);
		rz_core_analysis_esil(core, "f", NULL);
	}
	rz_core_seek(core, cur_seek, true);
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
		eprintf("Warning: cmd_espc: creating new esil instance\n");
		if (!(esil = rz_analysis_esil_new(stacksize, iotrap, addrsize))) {
			return;
		}
		core->analysis->esil = esil;
	}
	buf = malloc(bsize);
	if (!buf) {
		eprintf("Cannot allocate %d byte(s)\n", bsize);
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
			eprintf("Warning: Chomp\n");
		}
		if (!i) {
			rz_io_read_at(core->io, addr, buf, bsize);
		}
		if (addr == until_addr) {
			break;
		}
		ret = rz_analysis_op(core->analysis, &aop, addr, buf + i, bsize - i, flags);
		if (ret < 1) {
			eprintf("Failed analysis at 0x%08" PFMT64x "\n", addr);
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
		RZ_LOG_ERROR("Cannot find basic block for 0x%08" PFMT64x "\n", core->offset);
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
		eprintf("ar: Unknown register '%s'\n", regname);
		return -1;
	}
	rz_reg_set_value(core->analysis->reg, r, val);
	rz_core_reg_update_flags(core);
	return 0;
}

RZ_IPI void rz_core_analysis_esil_default(RzCore *core) {
	ut64 at = core->offset;
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
			char *len = rz_str_newf(" 0x%" PFMT64x, to - from);
			rz_core_seek(core, from, true);
			rz_core_analysis_esil(core, len, NULL);
			free(len);
		} else {
			eprintf("Assert: analysis.from > analysis.to\n");
		}
	} else {
		rz_list_foreach (list, iter, map) {
			if (map->perm & RZ_PERM_X) {
				char *ss = rz_str_newf(" 0x%" PFMT64x, map->itv.size);
				rz_core_seek(core, map->itv.addr, true);
				rz_core_analysis_esil(core, ss, NULL);
				free(ss);
			}
		}
	}
	rz_list_free(list);
	rz_core_seek(core, at, true);
}

RZ_IPI void rz_core_analysis_rzil_reinit(RzCore *core) {
	rz_analysis_rzil_cleanup(core->analysis);
	rz_analysis_rzil_setup(core->analysis);
	if (core->analysis->rzil) {
		// initialize the program counter with the current offset
		rz_bv_set_from_ut64(core->analysis->rzil->vm->pc, core->offset);
	}
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
	char *hex = rz_bv_as_hex_string(number);
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

static void rzil_print_register_unk(ILPrint *p) {
	switch (p->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_strbuf_appendf(p_sb(p->ptr), " %s: unk", p->name);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(p_tbl(p->ptr), "sss", p->name, "unkn", "");
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_knull(p_pj(p->ptr), p->name);
		break;
	default:
		rz_cons_printf("unknown\n");
		break;
	}
}

RZ_IPI void rz_core_analysis_rzil_vm_status(RzCore *core, const char *var_name, RzOutputMode mode) {
	RzAnalysisRzil *rzil = core->analysis->rzil;
	if (!rzil || !rzil->vm) {
		RZ_LOG_ERROR("RzIL: the VM is not initialized.\n")
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
		rzil_print_register_bitv(rzil->vm->pc, &p);
	}

	void **it;
	rz_pvector_foreach (&rzil->vm->vm_global_variable_list, it) {
		RzILVar *var = *it;
		if (var_name && strcmp(var_name, var->var_name)) {
			continue;
		}
		p.name = var->var_name;
		RzILVal *val = rz_il_hash_find_val_by_var(rzil->vm, var);
		switch (val->type) {
		case RZIL_VAR_TYPE_BV:
			rzil_print_register_bitv(val->data.bv, &p);
			break;
		case RZIL_VAR_TYPE_BOOL:
			rzil_print_register_bool(val->data.b->b, &p);
			break;
		case RZIL_VAR_TYPE_UNK:
			rzil_print_register_unk(&p);
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

// step a list of ct_opcode at a given address
RZ_IPI void rz_core_rzil_step(RzCore *core) {
	RzPVector *oplist;

	if (!core->analysis || !core->analysis->rzil) {
		RZ_LOG_ERROR("RzIL: Run 'aezi' first to initialize the VM\n");
		return;
	}

	RzAnalysis *analysis = core->analysis;
	RzAnalysisRzil *rzil = analysis->rzil;
	RzILVM *vm = rzil->vm;
	RzAnalysisPlugin *cur = analysis->cur;
	RzAnalysisOp op = { 0 };

	if (!cur) {
		// No analysis plugin
		return;
	}

	ut64 addr = rz_bv_to_ut64(vm->pc);

	// try load from vm
	// fetch and parse if no opcode
	ut8 code[32];
	// analysis current data to trigger rzil_set_op_code
	(void)rz_io_read_at_mapped(core->io, addr, code, sizeof(code));
	int size = rz_analysis_op(analysis, &op, addr, code, sizeof(code), RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_HINT);
	oplist = op.rzil_op ? op.rzil_op->ops : NULL;

	if (oplist) {
		rz_il_vm_list_step(vm, oplist, size > 0 ? size : 1);
	} else {
		RZ_LOG_ERROR("RzIL: invalid instruction detected or reach the end of code at address 0x%08" PFMT64x "\n", addr);
	}

	rz_analysis_op_fini(&op);
}

RZ_IPI void rz_core_analysis_rzil_step_with_events(RzCore *core, PJ *pj) {
	rz_core_rzil_step(core);

	if (!core->analysis || !core->analysis->rzil || !core->analysis->rzil->vm) {
		return;
	}

	RzILVM *vm = core->analysis->rzil->vm;

	RzStrBuf *sb = NULL;
	RzListIter *it;
	RzILEvent *evt;

	bool evt_read = rz_config_get_b(core->config, "rzil.step.events.read");
	bool evt_write = rz_config_get_b(core->config, "rzil.step.events.write");

	if (!evt_read && !evt_write) {
		RZ_LOG_ERROR("RzIL: cannot print events when all the events are disabled.");
		RZ_LOG_ERROR("RzIL: please set 'rzil.step.events.read' or/and 'rzil.step.events.write' to true and try again.");
		return;
	}

	if (!pj) {
		sb = rz_strbuf_new("");
	}
	rz_list_foreach (vm->events, it, evt) {
		if (!evt_read && (evt->type == RZIL_EVENT_MEM_READ || evt->type == RZIL_EVENT_VAR_READ)) {
			continue;
		} else if (!evt_write && (evt->type != RZIL_EVENT_MEM_READ && evt->type != RZIL_EVENT_VAR_READ)) {
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
}
