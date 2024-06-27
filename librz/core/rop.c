// SPDX-FileCopyrightText: 2010-2021 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_asm.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_regex.h>
#include <rz_rop.h>

static bool is_end_gadget(const RzAnalysisOp *aop, const ut8 crop) {
	if (aop->family == RZ_ANALYSIS_OP_FAMILY_SECURITY) {
		return false;
	}
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
		return true;
	}
	if (crop) { // if conditional jumps, calls and returns should be used for the gadget-search too
		switch (aop->type) {
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
		case RZ_ANALYSIS_OP_TYPE_CCALL:
		case RZ_ANALYSIS_OP_TYPE_UCCALL:
		case RZ_ANALYSIS_OP_TYPE_CRET:
			return true;
		}
	}
	return false;
}

static int rz_rop_process_asm_op(RzCore *core, RzCoreAsmHit *hit, RzAsmOp *asmop, RzAnalysisOp *aop, unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	ut8 *buf = malloc(hit->len);
	if (!buf) {
		return -1;
	}
	rz_io_read_at(core->io, hit->addr, buf, hit->len);
	rz_asm_set_pc(core->rasm, hit->addr);
	rz_asm_disassemble(core->rasm, asmop, buf, hit->len);
	rz_analysis_op_init(aop);
	rz_analysis_op(core->analysis, aop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_ESIL);
	*size += hit->len;

	// Append assembly operation string
	if (asmop_str) {
		*asmop_str = rz_str_append(*asmop_str, rz_asm_op_get_asm(asmop));
		*asmop_str = rz_str_append(*asmop_str, "; ");
	}

	// Append hex string of assembly operation
	if (asmop_hex_str) {
		char *asmop_hex = rz_asm_op_get_hex(asmop);
		*asmop_hex_str = rz_str_append(*asmop_hex_str, asmop_hex);
		free(asmop_hex);
	}

	free(buf);
	return 0;
}

static int rz_rop_print_table_mode(RzCore *core, RzCoreAsmHit *hit, RzList *hitlist, RzAsmOp *asmop, unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, asmop_str, asmop_hex_str) != 0) {
		return -1;
	}
	const ut64 addr_last = ((RzCoreAsmHit *)rz_list_last(hitlist))->addr;
	if (addr_last != hit->addr) {
		*asmop_str = rz_str_append(*asmop_str, "; ");
	}
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_quiet_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzAsmOp *asmop, unsigned int *size, bool esil, bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}
	const char *opstr = RZ_STRBUF_SAFEGET(&aop.esil);
	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		rz_list_append(ropList, rz_str_newf(" %s", opstr));
	}
	if (esil) {
		rz_cons_printf("%s\n", opstr);
	} else if (colorize) {
		RzStrBuf *bw_str = rz_strbuf_new(rz_asm_op_get_asm(asmop));
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
		RzStrBuf *colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop->asm_toks);
		rz_asm_parse_param_free(param);
		rz_cons_printf(" %s%s;", colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(bw_str);
	} else {
		rz_cons_printf(" %s;", rz_asm_op_get_asm(asmop));
	}
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_standard_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzAsmOp *asmop, unsigned int *size, bool rop_comments, bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}
	const char *comment = rop_comments ? rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, hit->addr) : NULL;
	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&aop.esil));
		rz_list_append(ropList, opstr_n);
	}
	char *asm_op_hex = rz_asm_op_get_hex(asmop);
	if (colorize) {
		RzStrBuf *bw_str = rz_strbuf_new(rz_asm_op_get_asm(asmop));
		RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
		RzStrBuf *colored_asm = rz_asm_colorize_asm_str(bw_str, core->print, param, asmop->asm_toks);
		rz_asm_parse_param_free(param);
		if (comment) {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s ; %s\n",
				hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET, comment);
		} else {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s%s\n",
				hit->addr, asm_op_hex, colored_asm ? rz_strbuf_get(colored_asm) : "", Color_RESET);
		}
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(bw_str);
	} else {
		if (comment) {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s ; %s\n",
				hit->addr, asm_op_hex, rz_asm_op_get_asm(asmop), comment);
		} else {
			rz_cons_printf("  0x%08" PFMT64x " %18s  %s\n",
				hit->addr, asm_op_hex, rz_asm_op_get_asm(asmop));
		}
	}
	free(asm_op_hex);
	rz_analysis_op_fini(&aop);
	return 0;
}

static int rz_rop_print_json_mode(RzCore *core, RzCoreAsmHit *hit, RzList *ropList, RzCmdStateOutput *state, RzAsmOp *asmop, unsigned int *size) {
	RzAnalysisOp aop = RZ_EMPTY;

	if (rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL) != 0) {
		return -1;
	}

	if (aop.type != RZ_ANALYSIS_OP_TYPE_RET) {
		char *opstr_n = rz_str_newf(" %s", RZ_STRBUF_SAFEGET(&aop.esil));
		rz_list_append(ropList, opstr_n);
	}

	pj_o(state->d.pj);
	pj_kn(state->d.pj, "offset", hit->addr);
	pj_ki(state->d.pj, "size", hit->len);
	pj_ks(state->d.pj, "opcode", rz_asm_op_get_asm(asmop));
	pj_ks(state->d.pj, "type", rz_analysis_optype_to_string(aop.type));
	pj_end(state->d.pj);

	rz_analysis_op_fini(&aop);
	return 0;
}

void rz_reg_info_free(RzRegInfo *reg_info) {
	if (!reg_info) {
		return;
	}
	free(reg_info->name);
	free(reg_info);
}

RzRegInfo *rz_reg_info_new(RzCore *core, RzILEvent *evt, ut64 init_val, ut64 new_val) {
	RzRegInfo *reg_info = RZ_NEW0(RzRegInfo);
	const char *name = NULL;
	if (evt->type == RZ_IL_EVENT_VAR_READ) {
		reg_info->is_var_read = true;
		name = evt->data.var_read.variable;
	} else if (evt->type == RZ_IL_EVENT_VAR_WRITE) {
		reg_info->is_var_write = true;
		name = evt->data.var_write.variable;
	}
	if (!reg_info) {
		return NULL;
	}
	const RzList *head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (!head) {
		free(reg_info);
		return NULL;
	}
	RzListIter *iter_dst;
	RzRegItem *item_dst;
	rz_list_foreach (head, iter_dst, item_dst) {
		if (!strcmp(name, item_dst->name) && item_dst->type == RZ_REG_TYPE_GPR) {
			reg_info->name = strdup(name);
			break;
		}
	}

	if (!reg_info->name) {
		free(reg_info);
		return NULL;
	}
	reg_info->init_val = init_val;
	reg_info->new_val = new_val;
	return reg_info;
}

RzRopGadgetInfo *rz_rop_gadget_info_new(ut64 address) {
	RzRopGadgetInfo *gadget_info = RZ_NEW0(RzRopGadgetInfo);
	if (!gadget_info) {
		return NULL;
	}
	gadget_info->address = address;
	gadget_info->stack_change = 0LL;
	gadget_info->curr_pc_val = address;
	gadget_info->is_pc_write = false;
	gadget_info->is_syscall = false;
	gadget_info->modified_registers = rz_pvector_new((RzPVectorFree)rz_reg_info_free);
	gadget_info->dependencies = rz_list_newf((RzListFree)rz_reg_info_free);
	return gadget_info;
}

void rz_rop_gadget_info_free(RzRopGadgetInfo *gadget_info) {
	if (!gadget_info) {
		return;
	}
	rz_pvector_free(gadget_info->modified_registers);
	rz_list_free(gadget_info->dependencies);
	free(gadget_info);
}

void rz_rop_gadget_info_add_register(RzRopGadgetInfo *gadget_info, RzRegInfo *reg_info, bool is_dependency) {
	if (!gadget_info || !reg_info) {
		return;
	}
	if (!is_dependency) {
		rz_pvector_push(gadget_info->modified_registers, reg_info);
	}
}

RzRegInfo *rz_rop_gadget_info_get_modified_register(RzRopGadgetInfo *gadget_info, const char *name) {
	if (!gadget_info) {
		return NULL;
	}
	RzRegInfo *reg_info;
	void **it;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		reg_info = *it;
		if (strcmp(reg_info->name, name) == 0) {
			return reg_info;
		}
	}
	return NULL;
}

void rz_rop_gadget_info_update_register(RzRopGadgetInfo *gadget_info, RzRegInfo *new_reg_info) {
	if (!gadget_info || !new_reg_info) {
		return;
	}

	RzRegInfo *existing_reg_info = rz_rop_gadget_info_get_modified_register(gadget_info, new_reg_info->name);
	if (existing_reg_info) {
		existing_reg_info->init_val = new_reg_info->init_val;
		existing_reg_info->new_val = new_reg_info->new_val;
		existing_reg_info->is_mem_read = new_reg_info->is_mem_read;
		existing_reg_info->is_pc_write = new_reg_info->is_pc_write;
		existing_reg_info->is_mem_write = new_reg_info->is_mem_write;
		existing_reg_info->is_var_read = new_reg_info->is_var_read;
	} else {
		rz_pvector_push(gadget_info->modified_registers, new_reg_info);
	}
}

RzRegInfo *rz_reg_info_dup(RzRegInfo *src) {
	if (!src) {
		return NULL;
	}

	RzRegInfo *dup = RZ_NEW0(RzRegInfo);
	if (!dup) {
		return NULL;
	}

	dup->name = strdup(src->name);
	dup->is_mem_read = src->is_mem_read;
	dup->is_pc_write = src->is_pc_write;
	dup->is_mem_write = src->is_mem_write;
	dup->is_var_read = src->is_var_read;
	dup->is_var_write = src->is_var_write;
	dup->init_val = src->init_val;
	dup->new_val = src->new_val;

	return dup;
}

bool is_stack_pointer(RzCore *core, const char *name) {
	RzRegItem *reg_item = rz_reg_get(core->analysis->reg, name, RZ_REG_TYPE_GPR);
	if (!reg_item) {
		return false;
	}
	if (core->analysis->bits == 32 && !strcmp(core->analysis->cpu, "x86")) {
		return !strcmp(reg_item->name, "esp");
	}
	if (core->analysis->bits == 64) {
		return !strcmp(reg_item->name, "rsp") || !strcmp(reg_item->name, "esp");
	}
	if (core->analysis->bits == 64 && !strcmp(core->analysis->cpu, "arm")) {
		return !strcmp(reg_item->name, "r13");
	}
	return reg_item->name;
}

bool is_base_pointer(RzCore *core, const char *name) {
	RzRegItem *reg_item = rz_reg_get(core->analysis->reg, name, RZ_REG_TYPE_GPR);
	if (!reg_item) {
		return false;
	}
	if (core->analysis->bits == 32 && !strcmp(core->analysis->cpu, "x86")) {
		return !strcmp(reg_item->name, "ebp");
	}
	if (core->analysis->bits == 64) {
		return !strcmp(reg_item->name, "rbp") || !strcmp(reg_item->name, "ebp");
	}
	if (core->analysis->bits == 64 && !strcmp(core->analysis->cpu, "arm")) {
		return !strcmp(reg_item->name, "r11");
	}
	return reg_item->name;
}

void rz_rop_gadget_info_add_dependency(RzCore *core, RzRopGadgetInfo *gadget_info, RzILEvent *evt, RzRegInfo *reg_info) {
	if (!gadget_info || !reg_info) {
		return;
	}

	RzRegInfo *reg_info_dup = rz_reg_info_dup(reg_info);
	if (!reg_info_dup) {
		return;
	}
	switch (evt->type) {
	case RZ_IL_EVENT_MEM_READ:
		// Used for reading this address
		const RzILEventMemRead *mem_read = &evt->data.mem_read;
		reg_info->is_mem_read = true;
		reg_info->is_mem_write = false;
		reg_info->is_var_write = false;
		reg_info_dup->new_val = rz_bv_to_ut64(mem_read->address);
		break;
	case RZ_IL_EVENT_MEM_WRITE:
		reg_info->is_mem_write = true;
		reg_info->is_mem_read = false;
		reg_info->is_var_write = false;
		RzILEventMemWrite *mem_write = &evt->data.mem_write;
		reg_info_dup->init_val = rz_bv_to_ut64(mem_write->old_value);
		reg_info_dup->new_val = rz_bv_to_ut64(mem_write->new_value);
		break;
	case RZ_IL_EVENT_VAR_WRITE:
		reg_info->is_var_write = true;
		reg_info->is_mem_read = false;
		reg_info->is_mem_write = false;
		RzILEventVarWrite *var_write = &evt->data.var_write;
		RzBitVector *init_val = rz_il_value_to_bv(var_write->old_value);
		RzBitVector *new_val = rz_il_value_to_bv(var_write->new_value);
		if (!init_val || !new_val) {
			rz_bv_free(init_val);
			rz_bv_free(new_val);
			break;
		}
		// reg_info_dup->init_val = rz_bv_to_ut64(init_val);
		reg_info_dup->new_val = rz_bv_to_ut64(new_val);
		if (is_stack_pointer(core, reg_info->name)) {
			gadget_info->stack_change += rz_bv_to_ut64(new_val) - reg_info->new_val;
		}
		rz_bv_free(init_val);
		rz_bv_free(new_val);
		break;
	default:
		break;
	}
	rz_list_append(gadget_info->dependencies, reg_info_dup);
}

static void fill_rop_gadget_info_from_events(RzCore *core, RzRopGadgetInfo *gadget_info, RzILEvent *curr_event, RzILEvent *event, RzPVector *vec, bool is_dependency) {
	if (!gadget_info) {
		return;
	}
	switch (event->type) {
	case RZ_IL_EVENT_VAR_READ: {
		RzILEventVarRead *var_read = &event->data.var_read;
		RzRegInfo *reg_info = rz_rop_gadget_info_get_modified_register(gadget_info, var_read->variable);
		if (reg_info && !is_dependency) {
			RzRegInfo *new_reg_info = rz_reg_info_dup(reg_info);
			if (!new_reg_info) {
				break;
			}
			RzBitVector *val = rz_il_value_to_bv(var_read->value);
			if (!val) {
				break;
			}
			new_reg_info->new_val = rz_bv_to_ut64(val);
			rz_rop_gadget_info_update_register(gadget_info, new_reg_info);
			rz_reg_info_free(new_reg_info);
			rz_pvector_push(vec, event);
			rz_bv_free(val);
			break;
		}
		if (is_dependency && curr_event) {
			// shouldn't take this path if it is a dependency
			if (curr_event->type == RZ_IL_EVENT_VAR_READ) {
				break;
			}
			rz_rop_gadget_info_add_dependency(core, gadget_info, curr_event, reg_info);
			break;
		}
		if (reg_info) {
			break;
		}
		RzBitVector *val = rz_il_value_to_bv(var_read->value);
		if (!val) {
			break;
		}
		reg_info = rz_reg_info_new(core, event, rz_bv_to_ut64(val), rz_bv_to_ut64(val));
		rz_rop_gadget_info_add_register(gadget_info, reg_info, is_dependency);
		if (!is_dependency) {
			rz_pvector_push(vec, event);
		}
		rz_bv_free(val);
	} break;
	case RZ_IL_EVENT_VAR_WRITE: {
		if (is_dependency) {
			break;
		}
		while (!rz_pvector_empty(vec)) {
			RzILEvent *evt = rz_pvector_pop(vec);
			fill_rop_gadget_info_from_events(core, gadget_info, event, evt, vec, true);
		}
		RzILEventVarWrite *var_write = &event->data.var_write;
		RzRegInfo *reg_info = rz_rop_gadget_info_get_modified_register(gadget_info, var_write->variable);
		if (reg_info && !is_dependency) {
			RzRegInfo *new_reg_info = rz_reg_info_dup(reg_info);
			if (!new_reg_info) {
				break;
			}
			RzBitVector *old_val = rz_il_value_to_bv(var_write->old_value);
			RzBitVector *new_val = rz_il_value_to_bv(var_write->old_value);
			if (!old_val || !new_val) {
				rz_bv_free(old_val);
				rz_bv_free(new_val);
				break;
			}
			// new_reg_info->init_val = rz_bv_to_ut64(old_val);
			new_reg_info->new_val = rz_bv_to_ut64(new_val);
			new_reg_info->is_mem_write = true;
			rz_rop_gadget_info_update_register(gadget_info, new_reg_info);
			rz_reg_info_free(new_reg_info);
			rz_bv_free(old_val);
			rz_bv_free(new_val);
			break;
		}

		if (!reg_info) {
			RzBitVector *old_val = rz_il_value_to_bv(var_write->old_value);
			RzBitVector *new_val = rz_il_value_to_bv(var_write->new_value);
			if (!old_val || !new_val) {
				rz_bv_free(old_val);
				rz_bv_free(new_val);
				break;
			}
			reg_info = rz_reg_info_new(core, event, rz_bv_to_ut64(old_val),
				rz_bv_to_ut64(new_val));
			rz_rop_gadget_info_add_register(gadget_info, reg_info, is_dependency);
			rz_bv_free(old_val);
			rz_bv_free(new_val);
		}
	} break;
	case RZ_IL_EVENT_MEM_READ: {
		// RzILEventMemRead *mem_read = &event->data.mem_read;
		while (!rz_pvector_empty(vec)) {
			RzILEvent *evt = rz_pvector_pop(vec);
			fill_rop_gadget_info_from_events(core, gadget_info, event, evt, vec, true);
		}
	} break;
	case RZ_IL_EVENT_MEM_WRITE: {
		while (!rz_pvector_empty(vec)) {
			RzILEvent *evt = rz_pvector_pop(vec);
			fill_rop_gadget_info_from_events(core, gadget_info, event, evt, vec, true);
		}
	} break;
	case RZ_IL_EVENT_PC_WRITE: {
		RzILEventPCWrite *pc_write = &event->data.pc_write;
		if (!gadget_info->is_pc_write) {
			gadget_info->is_pc_write = true;
		}
	} break;
	default:
		break;
	}
}

static void analyze_gadget(RzCore *core, RzCoreAsmHit /*<RzCoreAsmHit *>*/ *hit, RzRopGadgetInfo *rop_gadget_info) {
	if (!core->analysis) {
		return;
	}
	ut64 old_addr = core->offset;
	rz_core_seek(core, hit->addr, true);
	rz_core_analysis_il_reinit(core);
	rz_config_set(core->config, "io.cache", "true");
	rz_core_il_step(core, 1);
	if (!core->analysis || !core->analysis->il_vm) {
		goto cleanup;
	}
	RzILVM *vm = core->analysis->il_vm->vm;
	if (!vm) {
		goto cleanup;
	}
	void **it;
	RzILEvent *evt;

	RzPVector vec;
	rz_pvector_init(&vec, (RzPVectorFree)rz_il_event_free);
	rz_pvector_foreach (vm->events, it) {
		evt = *it;
		fill_rop_gadget_info_from_events(core, rop_gadget_info, NULL, evt, &vec, false);
	}

cleanup:
	rz_pvector_flush(&vec);
	rz_core_seek(core, old_addr, true);
}

void print_rop_gadget_info(RzCore *core, RzRopGadgetInfo *gadget_info) {
	rz_cons_printf("Gadget 0x%" PFMT64x "\n", gadget_info->address);
	rz_cons_printf("Stack change: 0x%" PFMT64x "\n", gadget_info->stack_change);

	rz_cons_printf("Changed registers: ");
	RzRegInfo *reg_info;
	void **it;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		reg_info = *it;
		if (reg_info->is_var_write) {
			rz_cons_printf("%s ", reg_info->name);
		}
	}
	rz_cons_printf("\n");

	rz_cons_printf("Register dependencies:\n");
	RzListIter *iter;
	rz_list_foreach (gadget_info->dependencies, iter, reg_info) {
		if (is_stack_pointer(core, reg_info->name) || is_base_pointer(core, reg_info->name)) {
			continue;
		}
		if (reg_info->is_var_write) {
			rz_cons_printf("Var write: %s %llu %llu\n", reg_info->name, reg_info->init_val, reg_info->new_val);
		} else if (reg_info->is_mem_read) {
			rz_cons_printf("Memory Read: %s %llu\n", reg_info->name, reg_info->new_val);
		} else if (reg_info->is_mem_write) {
			rz_cons_printf("Memory Write: %s %llu %llu\n", reg_info->name, reg_info->init_val, reg_info->new_val);
		}
	}
}
static void print_rop(RzCore *core, RzList /*<RzCoreAsmHit *>*/ *hitlist, RzCmdStateOutput *state) {
	RzCoreAsmHit *hit = NULL;
	RzListIter *iter;
	unsigned int size = 0;
	RzList *ropList = NULL;
	char *asmop_str = NULL, *asmop_hex_str = NULL;
	Sdb *db = NULL;
	const bool colorize = rz_config_get_i(core->config, "scr.color");
	const bool rop_comments = rz_config_get_i(core->config, "rop.comments");
	const bool esil = rz_config_get_i(core->config, "asm.esil");
	const bool rop_db = rz_config_get_i(core->config, "rop.db");
	if (rop_db) {
		db = sdb_ns(core->sdb, "rop", true);
		ropList = rz_list_newf(free);
		if (!db) {
			RZ_LOG_ERROR("core: Could not create SDB 'rop' namespace\n");
			rz_list_free(ropList);
			return;
		}
	}

	rz_cmd_state_output_set_columnsf(state, "XXs", "addr", "bytes", "disasm");
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
		pj_ka(state->d.pj, "opcodes");
	} else if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		rz_cons_printf("0x%08" PFMT64x ":", ((RzCoreAsmHit *)rz_list_first(hitlist))->addr);
	}
	const ut64 addr = ((RzCoreAsmHit *)rz_list_first(hitlist))->addr;

	rz_list_foreach (hitlist, iter, hit) {
		RzAsmOp *asmop = rz_asm_op_new();
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			if (rz_rop_print_json_mode(core, hit, ropList, state, asmop, &size) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_QUIET:
			if (rz_rop_print_quiet_mode(core, hit, ropList, asmop, &size, esil, colorize) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			if (rz_rop_print_standard_mode(core, hit, ropList, asmop, &size, rop_comments, colorize) != 0) {
				goto cleanup;
			}
			break;
		case RZ_OUTPUT_MODE_TABLE:
			if (rz_rop_print_table_mode(core, hit, hitlist, asmop, &size, &asmop_str, &asmop_hex_str) != 0) {
				goto cleanup;
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		rz_asm_op_free(asmop);
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_end(state->d.pj);
		if (db && hit) {
			// const char *key = rz_strf(tmpbuf, "0x%08" PFMT64x, addr);
			// rop_classify(core, db, ropList, key, size);
		}
		if (hit) {
			pj_kn(state->d.pj, "retaddr", hit->addr);
			pj_ki(state->d.pj, "size", size);
		}
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_newline();
		break;
		// fallthrough
	case RZ_OUTPUT_MODE_STANDARD:
		if (db && hit) {
			rz_cons_printf("Gadget size: %d\n", (int)size);
			// rop_classify(core, db, ropList, key, size);
			if (rz_list_empty(hitlist)) {
				return;
			}
			const ut64 addr_start = ((RzCoreAsmHit *)rz_list_first(hitlist))->addr;
			RzRopGadgetInfo *rop_gadget_info = rz_rop_gadget_info_new(addr_start);
			rz_list_foreach (hitlist, iter, hit) {
				analyze_gadget(core, hit, rop_gadget_info);
			}
			print_rop_gadget_info(core, rop_gadget_info);
			rz_rop_gadget_info_free(rop_gadget_info);
		}
		rz_cons_newline();
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "Xss", addr, asmop_hex_str, asmop_str);
		free(asmop_str);
		free(asmop_hex_str);
		break;
	default:
		rz_warn_if_reached();
	}
cleanup:
	rz_list_free(ropList);
}

static bool insert_into(void *user, const ut64 k, const ut64 v) {
	HtUU *ht = (HtUU *)user;
	ht_uu_insert(ht, k, v);
	return true;
}

// TODO: follow unconditional jumps
static RzList /*<RzCoreAsmHit *>*/ *construct_rop_gadget(RzCore *core, ut64 addr, ut8 *buf, int buflen,
	int idx, const char *grep, int regex, RzList /*<char *>*/ *rx_list,
	RzRopEndListPair *end_gadget, HtUU *badstart, int delta, RzStrBuf *sb) {
	int endaddr = end_gadget->instr_offset;
	int branch_delay = end_gadget->delay_size;
	RzAnalysisOp aop = { 0 };
	const char *start = NULL, *end = NULL;
	char *grep_str = NULL;
	RzCoreAsmHit *hit = NULL;
	RzList *hitlist = rz_core_asm_hit_list_new();
	ut8 nb_instr = 0;
	const ut8 max_instr = rz_config_get_i(core->config, "rop.len");
	bool valid = false;
	int grep_find;
	int search_hit;
	char *rx = NULL;
	HtUUOptions opt = { 0 };
	HtUU *localbadstart = ht_uu_new_opt(&opt);
	int count = 0;

	if (grep) {
		start = grep;
		end = strchr(grep, ';');
		if (!end) { // We filter on a single opcode, so no ";"
			end = start + strlen(grep);
		}
		grep_str = calloc(1, end - start + 1);
		strncpy(grep_str, start, end - start);
		if (regex) {
			// get the first regexp.
			if (rz_list_length(rx_list) > 0) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
	}

	bool found;
	ht_uu_find(badstart, idx, &found);
	if (found) {
		valid = false;
		goto ret;
	}
	ut32 end_gadget_cnt = 0;
	while (nb_instr < max_instr) {
		// ht_uu_insert(localbadstart, idx, 1);
		rz_analysis_op_init(&aop);
		if (idx >= delta) {
			valid = false;
			goto ret;
		}
		int error = rz_analysis_op(core->analysis, &aop, addr, buf + idx, buflen - idx, RZ_ANALYSIS_OP_MASK_DISASM);
		if (error < 0 || (nb_instr == 0 && aop.type == RZ_ANALYSIS_OP_TYPE_NOP)) {
			valid = false;
			goto ret;
		}

		if (is_end_gadget(&aop, 0)) {
			end_gadget_cnt++;
		}
		const int opsz = aop.size;
		// opsz = rz_strbuf_length (asmop.buf);
		char *opst = aop.mnemonic;
		RzAsmOp asmop;
		int asm_ret = rz_asm_disassemble(core->rasm, &asmop, buf + idx, buflen - idx);
		if (!opst) {
			RZ_LOG_WARN("Analysis plugin %s did not return disassembly\n", core->analysis->cur->name);
			rz_asm_set_pc(core->rasm, addr);
			if (asm_ret < 0) {
				valid = false;
				goto ret;
			}
			opst = strdup(rz_asm_op_get_asm(&asmop));
		}
		if (!rz_str_ncasecmp(opst, "invalid", strlen("invalid")) ||
			!rz_str_ncasecmp(opst, ".byte", strlen(".byte")) || end_gadget_cnt > 1) {
			valid = false;
			goto ret;
		}

		hit = rz_core_asm_hit_new();
		if (hit) {
			hit->addr = addr;
			hit->len = opsz;
			char *asm_op_hex = rz_asm_op_get_hex(&asmop);
			rz_strbuf_append(sb, asm_op_hex);
			free(asm_op_hex);
			rz_list_append(hitlist, hit);
		}
		if (asm_ret >= 0) {
			rz_asm_op_fini(&asmop);
		}

		// Move on to the next instruction
		idx += opsz;
		addr += opsz;
		if (rx) {
			grep_find = rz_regex_contains(rx, opst, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
			search_hit = (end && grep && grep_find);
		} else {
			search_hit = (end && grep && strstr(opst, grep_str));
		}

		// Handle (possible) grep
		if (search_hit) {
			if (end[0] == ';') { // fields are semicolon-separated
				start = end + 1; // skip the ;
				end = strchr(start, ';');
				end = end ? end : start + strlen(start); // latest field?
				free(grep_str);
				grep_str = calloc(1, end - start + 1);
				if (grep_str) {
					strncpy(grep_str, start, end - start);
				}
			} else {
				end = NULL;
			}
			if (regex) {
				rx = rz_list_get_n(rx_list, count++);
			}
		}
		if (endaddr <= (idx - opsz)) {
			valid = (endaddr == idx - opsz);
			goto ret;
		}
		rz_analysis_op_fini(&aop);
		nb_instr++;
	}
ret:
	rz_analysis_op_fini(&aop);
	free(grep_str);
	if (regex && rx) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	if (!valid || (grep && end)) {
		rz_list_free(hitlist);
		ht_uu_free(localbadstart);
		return NULL;
	}
	ht_uu_foreach(localbadstart, insert_into, badstart);
	ht_uu_free(localbadstart);
	// If our arch has bds then we better be including them
	if (branch_delay && rz_list_length(hitlist) < (1 + branch_delay)) {
		rz_list_free(hitlist);
		return NULL;
	}
	return hitlist;
}

RZ_API int rz_core_search_rop(RzCore *core, const char *greparg, int regexp, RzCmdStateOutput *state) {
	const ut8 crop = rz_config_get_i(core->config, "rop.conditional"); // decide if cjmp, cret, and ccall should be used too for the gadget-search
	const ut8 subchain = rz_config_get_i(core->config, "rop.subchains");
	const ut8 max_instr = rz_config_get_i(core->config, "rop.len");
	const char *arch = rz_config_get(core->config, "asm.arch");
	int max_count = rz_config_get_i(core->config, "search.maxhits");
	int i = 0, end = 0, increment = 1, ret, result = true;
	RzList /*<endlist_pair>*/ *end_list = rz_list_newf(free);
	RzList /*<char *>*/ *rx_list = NULL;
	int align = core->search->align;
	RzListIter *itermap = NULL;
	char *grep_arg = NULL;
	char *tok, *gregexp = NULL;
	char *rx = NULL;
	RzAsmOp *asmop = NULL;
	RzList *boundaries = NULL;
	int delta = 0;
	ut8 *buf;
	RzIOMap *map;
	HtSU *unique_hitlists = ht_su_new(HT_STR_DUP);

	const ut64 search_from = rz_config_get_i(core->config, "search.from"),
		   search_to = rz_config_get_i(core->config, "search.to");
	if (search_from > search_to && search_to) {
		RZ_LOG_ERROR("core: search.from > search.to is not supported\n");
		ret = false;
		goto bad;
	}
	// {.addr = UT64_MAX, .size = 0} means search range is unspecified
	RzInterval search_itv = { search_from, search_to - search_from };
	bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		RZ_LOG_ERROR("core: `from` address is equal `to`\n");
		ret = false;
		goto bad;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv.addr = 0;
		search_itv.size = UT64_MAX;
	}

	Sdb *gadgetSdb = NULL;
	if (rz_config_get_i(core->config, "rop.sdb")) {
		if (!(gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", false))) {
			gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", true);
		}
	}
	if (max_count == 0) {
		max_count = -1;
	}
	if (max_instr <= 1) {
		rz_list_free(end_list);
		RZ_LOG_ERROR("core: ROP length (rop.len) must be greater than 1.\n");
		if (max_instr == 1) {
			RZ_LOG_ERROR("core: For rop.len = 1, use /c to search for single "
				     "instructions. See /c? for help.\n");
		}
		return false;
	}

	if (!strcmp(arch, "mips")) { // MIPS has no jump-in-the-middle
		increment = 4;
	} else if (!strcmp(arch, "arm")) { // ARM has no jump-in-the-middle
		increment = rz_config_get_i(core->config, "asm.bits") == 16 ? 2 : 4;
	} else if (!strcmp(arch, "avr")) { // AVR is halfword aligned.
		increment = 2;
	}

	if (greparg) {
		grep_arg = strdup(greparg);
		grep_arg = rz_str_replace(grep_arg, ",,", ";", true);
	}

	// Deal with the grep guy.
	if (grep_arg && regexp) {
		if (!rx_list) {
			rx_list = rz_list_newf(free);
		}
		gregexp = strdup(grep_arg);
		tok = strtok(gregexp, ";");
		while (tok) {
			rx = strdup(tok);
			rz_list_append(rx_list, rx);
			tok = strtok(NULL, ";");
		}
	}
	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	const char *mode_str = rz_config_get(core->config, "search.in");
	boundaries = rz_core_get_boundaries_prot(core, -1, mode_str, "search");
	if (!boundaries) {
		rz_cmd_state_output_array_end(state);
	}
	rz_list_foreach (boundaries, itermap, map) {
		HtUUOptions opt = { 0 };
		HtUU *badstart = ht_uu_new_opt(&opt);
		if (!rz_itv_overlap(search_itv, map->itv)) {
			continue;
		}
		RzInterval itv = rz_itv_intersect(search_itv, map->itv);
		ut64 from = itv.addr, to = rz_itv_end(itv);
		if (rz_cons_is_breaked()) {
			break;
		}
		delta = to - from;
		buf = calloc(1, delta);
		if (!buf) {
			result = false;
			goto bad;
		}
		(void)rz_io_read_at(core->io, from, buf, delta);

		// Find the end gadgets.
		for (i = 0; i < delta; i += increment) {
			RzAnalysisOp end_gadget = RZ_EMPTY;
			// Disassemble one.
			rz_analysis_op_init(&end_gadget);
			if (rz_analysis_op(core->analysis, &end_gadget, from + i, buf + i,
				    delta - i, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
				rz_analysis_op_fini(&end_gadget);
				continue;
			}
			if (is_end_gadget(&end_gadget, crop)) {
				RzRopEndListPair *epair = RZ_NEW0(RzRopEndListPair);
				if (epair) {
					// If this arch has branch delay slots, add the next instr as well
					if (end_gadget.delay) {
						epair->instr_offset = i + increment;
						epair->delay_size = end_gadget.delay;
					} else {
						epair->instr_offset = (intptr_t)i;
						epair->delay_size = end_gadget.delay;
					}
					rz_list_append(end_list, (void *)(intptr_t)epair);
				}
			}
			rz_analysis_op_fini(&end_gadget);
			if (rz_cons_is_breaked()) {
				break;
			}
			// Right now we have a list of all of the end/stop gadgets.
			// We can just construct gadgets from a little bit before them.
		}
		rz_list_reverse(end_list);
		// If we have no end gadgets, just skip all of this search nonsense.
		if (!rz_list_empty(end_list)) {
			int prev, next, ropdepth;
			const int max_inst_size_x86 = 15;
			// Get the depth of rop search, should just be max_instr
			// instructions, x86 and friends are weird length instructions, so
			// we'll just assume 15 byte instructions.
			ropdepth = increment == 1 ? max_instr * max_inst_size_x86 /* wow, x86 is long */ : max_instr * increment;
			if (rz_cons_is_breaked()) {
				break;
			}
			RzRopEndListPair *end_gadget = rz_list_pop(end_list);
			next = end_gadget->instr_offset;
			prev = 0;
			// Start at just before the first end gadget.
			for (i = 0; i < delta && max_count; i += increment) {
				if (increment == 1) {
					// give in-boundary instructions a shot
					if (i < prev - max_inst_size_x86) {
						i = prev - max_inst_size_x86;
					}
				} else {
					if (i < prev) {
						i = prev;
					}
				}
				if (i < 0) {
					i = 0;
				}
				if (rz_cons_is_breaked()) {
					break;
				}
				if (i >= end) { // read by chunk of 4k
					rz_io_read_at(core->io, from + i, buf + i,
						RZ_MIN((delta - i), 4096));
					end = i + 2048;
				}
				asmop = rz_asm_op_new();
				ret = rz_asm_disassemble(core->rasm, asmop, buf + i, delta - i);
				if (ret) {
					rz_asm_set_pc(core->rasm, from + i);
					RzStrBuf *sb = rz_strbuf_new("");
					RzList *hitlist = construct_rop_gadget(core,
						from + i, buf, delta, i, greparg, regexp,
						rx_list, end_gadget, badstart, delta, sb);

					if (!hitlist) {
						rz_asm_op_free(asmop);
						asmop = NULL;
						rz_strbuf_free(sb);
						continue;
					}
					if (align && 0 != (from + i) % align) {
						rz_asm_op_free(asmop);
						asmop = NULL;
						rz_strbuf_free(sb);
						continue;
					}
					bool is_found = true;
					char *asm_op_hex = NULL;
					if (sb->len) {
						asm_op_hex = rz_strbuf_get(sb);
						ht_su_find(unique_hitlists, asm_op_hex, &is_found);
					}
					if (!is_found && asm_op_hex) {
						ht_su_insert(unique_hitlists, asm_op_hex, 1);
					} else {
						rz_list_free(hitlist);
						rz_asm_op_free(asmop);
						asmop = NULL;
						rz_strbuf_free(sb);
						continue;
					}
					rz_strbuf_free(sb);
					if (gadgetSdb) {
						RzListIter *iter;

						RzCoreAsmHit *hit = rz_list_first(hitlist);
						char *headAddr = rz_str_newf("%" PFMT64x, hit->addr);
						if (!headAddr) {
							result = false;
							free(buf);
							ht_uu_free(badstart);
							goto bad;
						}

						rz_list_foreach (hitlist, iter, hit) {
							char *addr = rz_str_newf("%" PFMT64x "(%" PFMT32d ")", hit->addr, hit->len);
							if (!addr) {
								free(headAddr);
								result = false;
								free(buf);
								ht_uu_free(badstart);
								goto bad;
							}
							sdb_concat(gadgetSdb, headAddr, addr);
							free(addr);
						}
						free(headAddr);
					}

					if (subchain) {
						do {
							print_rop(core, hitlist, state);
							hitlist->head = hitlist->head->next;
						} while (hitlist->head->next);
					} else {
						print_rop(core, hitlist, state);
					}
					rz_list_free(hitlist);
					if (max_count > 0) {
						max_count--;
						if (max_count < 1) {
							break;
						}
					}
				}
				if (increment != 1) {
					i = next;
				}
				rz_asm_op_free(asmop);
				asmop = NULL;
				if (i >= next) {
					// We've exhausted the first end-gadget section,
					// move to the next one.
					free(end_gadget);
					if (rz_list_get_n(end_list, 0)) {
						prev = i;
						end_gadget = (RzRopEndListPair *)rz_list_pop(end_list);
						next = end_gadget->instr_offset;
						i = next - ropdepth;
						if (i < 0) {
							i = 0;
						}
					} else {
						end_gadget = NULL;
						break;
					}
				}
			}
			free(end_gadget);
		}
		free(buf);
		ht_uu_free(badstart);
	}
	if (rz_cons_is_breaked()) {
		eprintf("\n");
	}

bad:
	rz_cmd_state_output_array_end(state);
	rz_cons_break_pop();
	rz_asm_op_free(asmop);
	ht_su_free(unique_hitlists);
	rz_list_free(rx_list);
	rz_list_free(end_list);
	rz_list_free(boundaries);
	free(grep_arg);
	free(gregexp);
	return result;
}

RZ_API RzCmdStatus rz_core_rop_gadget_info(RzCore *core, const char *input, RzCmdStateOutput *state) {
	Sdb *gadgetSdb = sdb_ns(core->sdb, "gadget_sdb", false);

	if (!gadgetSdb) {
		rz_core_search_rop(core, input, 0, state);
		return RZ_CMD_STATUS_OK;
	}
	void **iter;
	RzPVector *items = sdb_get_items(gadgetSdb, true);

	rz_cmd_state_output_array_start(state);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		RzList *hitlist = rz_core_asm_hit_list_new();
		if (!hitlist) {
			break;
		}

		const char *s = sdbkv_value(kv);
		ut64 addr;
		int opsz;
		do {
			RzCoreAsmHit *hit = rz_core_asm_hit_new();
			if (!hit) {
				rz_list_free(hitlist);
				break;
			}
			sscanf(s, "%" PFMT64x "(%" PFMT32d ")", &addr, &opsz);
			hit->addr = addr;
			hit->len = opsz;
			rz_list_append(hitlist, hit);
		} while (*(s = strchr(s, ')') + 1) != '\0');

		print_rop(core, hitlist, state);
		rz_list_free(hitlist);
	}
	rz_pvector_free(items);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_API void rz_rop_constraint_free(RZ_NULLABLE void *data) {
	RzRopConstraint *constraint = data;
	if (!constraint) {
		return;
	}
	for (int i = 0; i < NUM_ARGS; i++) {
		if (constraint->args[i]) {
			free(constraint->args[i]);
		}
	}
	free(constraint);
}

RZ_API RzList /*<RzRopConstraint *>*/ *rz_rop_constraint_list_new(void) {
	RzList *list = rz_list_new();
	if (list) {
		list->free = &rz_rop_constraint_free;
	}
	return list;
}