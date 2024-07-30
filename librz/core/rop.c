// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_asm.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_regex.h>
#include <rz_rop.h>

static bool is_cond_end_gadget(const RzAnalysisOp *aop) {
	switch (aop->type) {
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
	case RZ_ANALYSIS_OP_TYPE_CRET:
		return true;
	default:
		return false;
	}
}

static bool is_ret_gadget(const RzCore *core, const RzCoreAsmHit *hit, const ut8 crop) {
	rz_return_val_if_fail(core && core->analysis && hit, false);
	bool status = false;
	RzAnalysisOp aop = { 0 };
	ut8 *buf = malloc(hit->len);
	if (rz_io_nread_at(core->io, hit->addr, buf, hit->len) < 0) {
		free(buf);
		return status;
	}
	rz_analysis_op_init(&aop);
	if (rz_analysis_op(core->analysis, &aop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_DISASM) < 0) {
		free(buf);
		return status;
	}
	switch (aop.type) {
	case RZ_ANALYSIS_OP_TYPE_RET:
		if (crop) {
			status = is_cond_end_gadget(&aop);
			break;
		}
		status = true;
		break;
	default:
		break;
	}
	rz_analysis_op_fini(&aop);
	free(buf);
	return status;
}

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
		if (crop) {
			return is_cond_end_gadget(aop);
		}
		return true;
	default:
		return false;
	}
}

static bool rz_rop_process_asm_op(const RzCore *core, const RzCoreAsmHit *hit, RzAsmOp *asmop, RzAnalysisOp *aop, unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	ut8 *buf = malloc(hit->len);
	if (!buf) {
		return false;
	}
	if (rz_io_nread_at(core->io, hit->addr, buf, hit->len) < 0) {
		free(buf);
		return false;
	}
	rz_asm_set_pc(core->rasm, hit->addr);
	if (rz_asm_disassemble(core->rasm, asmop, buf, hit->len) < 0) {
		free(buf);
		return false;
	}
	rz_analysis_op_init(aop);
	rz_analysis_op(core->analysis, aop, hit->addr, buf, hit->len, RZ_ANALYSIS_OP_MASK_DISASM);
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
	return true;
}

static bool rz_rop_print_table_mode(const RzCore *core, const RzCoreAsmHit *hit, const RzList /*<RzCoreAsmHit *>*/ *hitlist,
	unsigned int *size, char **asmop_str, char **asmop_hex_str) {
	RzAnalysisOp aop = RZ_EMPTY;
	RzAsmOp *asmop = rz_asm_op_new();
	if (!asmop) {
		return false;
	}

	if (!rz_rop_process_asm_op(core, hit, asmop, &aop, size, asmop_str, asmop_hex_str)) {
		rz_asm_op_free(asmop);
		return false;
	}
	const ut64 addr_last = ((RzCoreAsmHit *)rz_list_last(hitlist))->addr;
	if (addr_last != hit->addr) {
		*asmop_str = rz_str_append(*asmop_str, "; ");
	}
	rz_asm_op_free(asmop);
	rz_analysis_op_fini(&aop);
	return true;
}

static bool rz_rop_print_quiet_mode(const RzCore *core, const RzCoreAsmHit *hit, unsigned int *size, const bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	RzAsmOp *asmop = rz_asm_op_new();
	if (!asmop) {
		return false;
	}

	if (!rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL)) {
		rz_asm_op_free(asmop);
		return false;
	}
	if (colorize) {
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
	rz_asm_op_free(asmop);
	rz_analysis_op_fini(&aop);
	return true;
}

static bool rz_rop_print_standard_mode(const RzCore *core, const RzCoreAsmHit *hit,
	unsigned int *size, const bool rop_comments, const bool colorize) {
	RzAnalysisOp aop = RZ_EMPTY;
	RzAsmOp *asmop = rz_asm_op_new();
	if (!asmop) {
		return false;
	}
	if (!rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL)) {
		rz_asm_op_free(asmop);
		return false;
	}
	const char *comment = rop_comments ? rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, hit->addr) : NULL;
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
	rz_asm_op_free(asmop);
	return true;
}

static bool rz_rop_print_json_mode(const RzCore *core, const RzCoreAsmHit *hit, unsigned int *size, PJ *pj) {
	RzAnalysisOp aop = RZ_EMPTY;
	RzAsmOp *asmop = rz_asm_op_new();
	if (!asmop) {
		return false;
	}
	if (!rz_rop_process_asm_op(core, hit, asmop, &aop, size, NULL, NULL)) {
		rz_asm_op_free(asmop);
		return false;
	}

	pj_o(pj);
	pj_kn(pj, "offset", hit->addr);
	pj_ki(pj, "size", hit->len);
	pj_ks(pj, "opcode", rz_asm_op_get_asm(asmop));
	pj_ks(pj, "type", rz_analysis_optype_to_string(aop.type));
	pj_end(pj);

	rz_analysis_op_fini(&aop);
	rz_asm_op_free(asmop);
	return true;
}

RZ_IPI void rz_core_rop_reg_info_free(RzRopRegInfo *reg_info) {
	if (!reg_info) {
		return;
	}
	free(reg_info->name);
	free(reg_info->value_transformations);
	free(reg_info);
}

RZ_IPI RzRopRegInfo *rz_core_rop_reg_info_new(const RzCore *core, const RzILEvent *evt, const ut64 init_val, const ut64 new_val) {
	rz_return_val_if_fail(core && evt, NULL);
	RzRopRegInfo *reg_info = RZ_NEW0(RzRopRegInfo);
	if (!reg_info) {
		return NULL;
	}
	const char *name = NULL;
	if (evt->type == RZ_IL_EVENT_VAR_READ) {
		reg_info->is_var_read = true;
		name = evt->data.var_read.variable;
	} else if (evt->type == RZ_IL_EVENT_VAR_WRITE) {
		reg_info->is_var_write = true;
		name = evt->data.var_write.variable;
	}
	const RzList *head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (!head) {
		free(reg_info);
		return NULL;
	}
	RzListIter *iter_dst;
	RzRegItem *item_dst;
	rz_list_foreach (head, iter_dst, item_dst) {
		if (RZ_STR_EQ(name, item_dst->name) && item_dst->type == RZ_REG_TYPE_GPR) {
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
	reg_info->bits = core->analysis->bits;
	reg_info->value_transformations = NULL; // Fill this as you need
	return reg_info;
}

/**
 * \brief Create a new RzRopGadgetInfo object.
 * \param address The address of the ROP gadget.
 * \return RZ_OUT A pointer to the newly created RzRopGadgetInfo object, or NULL if memory allocation fails.
 *
 * This function allocates and initializes a new RzRopGadgetInfo object with the given address.
 */
RZ_API RZ_OWN RzRopGadgetInfo *rz_core_rop_gadget_info_new(const ut64 address) {
	RzRopGadgetInfo *gadget_info = RZ_NEW0(RzRopGadgetInfo);
	if (!gadget_info) {
		return NULL;
	}

	gadget_info->address = address;
	gadget_info->stack_change = 0LL;
	gadget_info->curr_pc_val = address;
	gadget_info->is_pc_write = false;
	gadget_info->is_syscall = false;
	gadget_info->modified_registers = rz_pvector_new((RzPVectorFree)rz_core_rop_reg_info_free);
	gadget_info->dependencies = rz_list_newf((RzListFree)rz_core_rop_reg_info_free);

	return gadget_info;
}

/**
 * \brief Free an RzRopGadgetInfo object.
 * \param gadget_info RZ_NULLABLE Pointer to the RzRopGadgetInfo object to free.
 *
 * Frees the memory allocated for an RzRopGadgetInfo object, including its modified registers and dependencies.
 */
RZ_API void rz_core_rop_gadget_info_free(RZ_NULLABLE RzRopGadgetInfo *gadget_info) {
	rz_return_if_fail(gadget_info);

	rz_pvector_free(gadget_info->modified_registers);
	rz_list_free(gadget_info->dependencies);
	free(gadget_info);
}

/**
 * \brief Add a register info to an RzRopGadgetInfo object.
 * \param gadget_info RZ_NONNULL Pointer to the RzRopGadgetInfo object.
 * \param reg_info RZ_NONNULL Pointer to the RzRopRegInfo object.
 * \param is_dependency Boolean indicating whether the register is a dependency.
 *
 * Adds the given register info to the modified registers of the RzRopGadgetInfo object if it is not a dependency.
 */
RZ_API void rz_core_rop_gadget_info_add_register(const RZ_NONNULL RZ_OUT RzRopGadgetInfo *gadget_info,
	RZ_NONNULL RzRopRegInfo *reg_info, const bool is_dependency) {
	rz_return_if_fail(gadget_info);

	if (!is_dependency && reg_info) {
		rz_pvector_push(gadget_info->modified_registers, reg_info);
	}
}

/**
 * \brief Get the modified register info by name.
 * \param gadget_info RZ_NONNULL Pointer to the RzRopGadgetInfo object.
 * \param name RZ_NONNULL Pointer to the name of the register.
 * \return RZ_OUT A pointer to the RzRopRegInfo object if found, or NULL if not found or if gadget_info is NULL.
 *
 * Searches the modified registers in the RzRopGadgetInfo object for the register with the given name and returns its info.
 */
RZ_BORROW RZ_API RzRopRegInfo *rz_core_rop_gadget_info_get_modified_register(const RZ_NONNULL RzRopGadgetInfo *gadget_info, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(gadget_info && name, NULL);
	void **it;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		RzRopRegInfo *reg_info = *it;
		if (RZ_STR_EQ(reg_info->name, name)) {
			return reg_info;
		}
	}
	return NULL;
}

/**
 * \brief Update a register info in the RzRopGadgetInfo object.
 * \param gadget_info RZ_INOUT Pointer to the RzRopGadgetInfo object.
 * \param new_reg_info RZ_NONNULL Pointer to the new RzRopRegInfo object.
 * \return 0 on success, -1 on failure.
 *
 * Updates the register info in the RzRopGadgetInfo object with the values from the new register info.
 * If the register is not already in the modified registers list, it is added.
 */
RZ_API int rz_core_rop_gadget_info_update_register(RZ_INOUT RzRopGadgetInfo *gadget_info, RZ_NONNULL RzRopRegInfo *new_reg_info) {
	rz_return_val_if_fail(gadget_info, -1);
	rz_return_val_if_fail(new_reg_info, -1);

	RzRopRegInfo *existing_reg_info = rz_core_rop_gadget_info_get_modified_register(gadget_info, new_reg_info->name);
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
	return 0;
}

RZ_IPI RzRopRegInfo *rz_core_rop_reg_info_dup(RzRopRegInfo *src) {
	rz_return_val_if_fail(src, NULL);

	RzRopRegInfo *dup = RZ_NEW0(RzRopRegInfo);
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

/**
 * \brief Check if a register with a specific name exists in the modified registers of a RzRopGadgetInfo object.
 * \param gadget_info RZ_NONNULL Pointer to the RzRopGadgetInfo object.
 * \param name RZ_NONNULL Pointer to the name of the register.
 * \return true if a register with the given name exists, false otherwise.
 *
 * Checks the modified registers in the RzRopGadgetInfo object to see if a register with the given name exists.
 */
RZ_API bool rz_core_rop_gadget_info_has_register(const RZ_NONNULL RzRopGadgetInfo *gadget_info, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(gadget_info && name, false);
	void **it;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		const RzRopRegInfo *reg_info = *it;
		if (RZ_STR_EQ(reg_info->name, name)) {
			return true;
		}
	}
	return false;
}

static bool is_var_write_event(const RzRopRegInfo *reg_info) {
	return reg_info->is_var_write;
}

static bool is_mem_read_event(const RzRopRegInfo *reg_info) {
	return reg_info->is_mem_read;
}

static bool is_mem_write_event(const RzRopRegInfo *reg_info) {
	return reg_info->is_mem_write;
}

static bool is_pc_write_event(const RzRopRegInfo *reg_info) {
	return reg_info->is_pc_write;
}

event_check_fn event_functions[RZ_ROP_EVENT_COUNT] = {
	is_var_write_event,
	is_mem_read_event,
	is_mem_write_event,
	is_pc_write_event,
};

/**
 * \brief Find all dependencies based on a specific event in the dependencies of a RzRopGadgetInfo object.
 * \param gadget_info RZ_NONNULL Pointer to the RzRopGadgetInfo object.
 * \param event The RzRopEvent to check.
 * \return RZ_OUT A pointer to a list of RzRopRegInfo objects matching the given event, or NULL if none are found or if gadget_info is NULL.
 */
RZ_API RzPVector /*<RzRopRegInfo *>*/ *rz_core_rop_gadget_get_reg_info_by_event(const RZ_NONNULL RzRopGadgetInfo *gadget_info, const RzRopEvent event) {
	rz_return_val_if_fail(gadget_info, NULL);
	if (event < 0 || event >= RZ_ROP_EVENT_COUNT) {
		return NULL;
	}
	RzPVector *matches = rz_pvector_new((RzPVectorFree)rz_core_rop_reg_info_free);
	RzListIter *iter;
	RzRopRegInfo *reg_info;
	rz_list_foreach (gadget_info->dependencies, iter, reg_info) {
		if (event_functions[event](reg_info)) {
			rz_pvector_push(matches, reg_info);
		}
	}
	return matches;
}

/**
 * \brief Find all registers with specific names in the modified registers of a RzRopGadgetInfo object.
 * \param gadget_info RZ_NONNULL Pointer to the RzRopGadgetInfo object.
 * \param registers RZ_NONNULL Pointer to a RzPvector of register names.
 * \return RZ_OUT A pointer to a RzPvector of RzRopRegInfo objects matching the given names, or NULL if none are found or if gadget_info is NULL.
 *
 * Searches the modified registers in the RzRopGadgetInfo object for all registers with the given registers and returns their info in a vector.
 */
RZ_API RzPVector /*<RzRopRegInfo *>*/ *rz_core_rop_get_reg_info_by_reg_names(const RZ_NONNULL RzRopGadgetInfo *gadget_info,
	RZ_NONNULL const RzPVector /*<char *>*/ *registers) {
	rz_return_val_if_fail(gadget_info && registers, NULL);

	RzPVector *result = rz_pvector_new((RzPVectorFree)rz_core_rop_reg_info_free);
	void **it;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		RzRopRegInfo *reg_info = *it;
		void **reg_it;
		rz_pvector_foreach (registers, reg_it) {
			const char *reg = *reg_it;
			if (RZ_STR_EQ(reg_info->name, reg)) {
				rz_pvector_push(result, reg_info);
				break;
			}
		}
	}

	if (rz_pvector_empty(result)) {
		rz_pvector_free(result);
		return NULL;
	}

	return result;
}

static void rz_rop_gadget_info_add_dependency(const RzCore *core, RzRopGadgetInfo *gadget_info, const RzILEvent *evt, RzRopRegInfo *reg_info) {
	rz_return_if_fail(core && core->analysis && core->analysis->reg);
	if (!reg_info) {
		return;
	}
	RzRopRegInfo *reg_info_dup = rz_core_rop_reg_info_dup(reg_info);
	if (!reg_info_dup) {
		return;
	}
	switch (evt->type) {
	case RZ_IL_EVENT_MEM_READ: {
		const RzILEventMemRead *mem_read = &evt->data.mem_read;
		reg_info_dup->is_mem_read = true;
		reg_info_dup->is_mem_write = false;
		reg_info_dup->is_var_write = false;
		reg_info_dup->new_val = rz_bv_to_ut64(mem_read->address);
		break;
	}
	case RZ_IL_EVENT_MEM_WRITE: {
		reg_info_dup->is_mem_write = true;
		reg_info_dup->is_mem_read = false;
		reg_info_dup->is_var_write = false;
		const RzILEventMemWrite *mem_write = &evt->data.mem_write;
		reg_info_dup->init_val = rz_bv_to_ut64(mem_write->old_value);
		reg_info_dup->new_val = rz_bv_to_ut64(mem_write->new_value);
		break;
	}
	case RZ_IL_EVENT_VAR_WRITE: {
		reg_info->is_var_write = true;
		reg_info->is_mem_read = false;
		reg_info->is_mem_write = false;
		const RzILEventVarWrite *var_write = &evt->data.var_write;
		RzBitVector *init_val = rz_il_value_to_bv(var_write->old_value);
		RzBitVector *new_val = rz_il_value_to_bv(var_write->new_value);
		if (!init_val || !new_val) {
			rz_bv_free(init_val);
			rz_bv_free(new_val);
			break;
		}
		reg_info_dup->new_val = rz_bv_to_ut64(new_val);
		if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP)) {
			gadget_info->stack_change += rz_bv_to_ut64(new_val) - rz_bv_to_ut64(init_val);
		}
		rz_bv_free(init_val);
		rz_bv_free(new_val);

		break;
	}
	default:
		break;
	}
	rz_list_append(gadget_info->dependencies, reg_info_dup);
}

static int fill_rop_gadget_info_from_events(RzCore *core, RzRopGadgetInfo *gadget_info, const RzILEvent *curr_event,
	RzILEvent *event, RzPVector /*<RzILEvent *>*/ *vec, const bool is_dependency) {
	if (!gadget_info) {
		return -1;
	}
	const RzList *head = rz_reg_get_list(core->analysis->reg, RZ_REG_TYPE_GPR);
	if (!head) {
		return -1;
	}
	switch (event->type) {
	case RZ_IL_EVENT_VAR_READ: {
		const RzILEventVarRead *var_read = &event->data.var_read;
		RzRopRegInfo *reg_info = rz_core_rop_gadget_info_get_modified_register(gadget_info, var_read->variable);
		if (reg_info && !is_dependency) {
			RzRopRegInfo *new_reg_info = rz_core_rop_reg_info_dup(reg_info);
			if (!new_reg_info) {
				break;
			}
			RzBitVector *val = rz_il_value_to_bv(var_read->value);
			if (!val) {
				break;
			}
			new_reg_info->new_val = rz_bv_to_ut64(val);
			if (rz_core_rop_gadget_info_update_register(gadget_info, new_reg_info) < 0) {
				break;
			}
			rz_core_rop_reg_info_free(new_reg_info);
			rz_pvector_push(vec, event);
			rz_bv_free(val);
			break;
		}
		if (is_dependency && curr_event) {
			bool is_stack_evt = false;
			if (curr_event->type == RZ_IL_EVENT_VAR_READ) {
				break;
			}
			// Stack reads during pop, push
			if (rz_reg_is_role(core->analysis->reg, var_read->variable, RZ_REG_NAME_SP)) {
				is_stack_evt = true;
				RzBitVector *val = rz_il_value_to_bv(var_read->value);
				if (!val) {
					break;
				}
				reg_info = rz_core_rop_reg_info_new(core, event, rz_bv_to_ut64(val), rz_bv_to_ut64(val));
				if (!reg_info) {
					break;
				}
				rz_bv_free(val);
			}
			rz_rop_gadget_info_add_dependency(core, gadget_info, curr_event, reg_info);
			if (is_stack_evt) {
				rz_core_rop_reg_info_free(reg_info);
			}
			break;
		}
		if (reg_info) {
			break;
		}
		RzBitVector *val = rz_il_value_to_bv(var_read->value);
		if (!val) {
			break;
		}
		if (!is_dependency) {
			rz_pvector_push(vec, event);
		}
		rz_bv_free(val);
	} break;
	case RZ_IL_EVENT_VAR_WRITE: {
		RzListIter *iter_dst;
		RzRegItem *item_dst;
		if (is_dependency) {
			break;
		}
		const RzILEventVarWrite *var_write = &event->data.var_write;
		bool is_reg = false;
		rz_list_foreach (head, iter_dst, item_dst) {
			if (RZ_STR_EQ(var_write->variable, item_dst->name) && item_dst->type == RZ_REG_TYPE_GPR) {
				is_reg = true;
				break;
			}
		}
		if (!is_reg) {
			break;
		}
		while (!rz_pvector_empty(vec)) {
			RzILEvent *evt = rz_pvector_pop(vec);
			fill_rop_gadget_info_from_events(core, gadget_info, event, evt, vec, true);
		}
		RzRopRegInfo *reg_info = rz_core_rop_gadget_info_get_modified_register(gadget_info, var_write->variable);
		if (!reg_info) {
			RzBitVector *old_val = rz_il_value_to_bv(var_write->old_value);
			RzBitVector *new_val = rz_il_value_to_bv(var_write->new_value);
			if (!old_val || !new_val) {
				rz_bv_free(old_val);
				rz_bv_free(new_val);
				break;
			}
			reg_info = rz_core_rop_reg_info_new(core, event, rz_bv_to_ut64(old_val),
				rz_bv_to_ut64(new_val));
			rz_core_rop_gadget_info_add_register(gadget_info, reg_info, is_dependency);
			rz_bv_free(old_val);
			rz_bv_free(new_val);
		}
	} break;
	case RZ_IL_EVENT_MEM_READ: {
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
		if (!gadget_info->is_pc_write) {
			gadget_info->is_pc_write = true;
		} else {
			gadget_info->is_syscall = true;
		}
	} break;
	default:
		break;
	}
	return 0;
}

static int analyze_gadget(RzCore *core, const RzCoreAsmHit *hit, RzRopGadgetInfo *rop_gadget_info) {
	rz_return_val_if_fail(core && core->analysis, -1);
	int ret = 0;

	ut64 old_addr = core->offset;
	rz_core_seek(core, hit->addr, true);
	rz_core_analysis_il_reinit(core);
	rz_config_set(core->config, "io.cache", "true");
	rz_core_il_step(core, 1);

	if (!core->analysis->il_vm) {
		ret = -1;
		goto cleanup;
	}
	RzILVM *vm = core->analysis->il_vm->vm;
	if (!vm) {
		ret = -1;
		goto cleanup;
	}
	void **it;

	RzPVector vec;
	rz_pvector_init(&vec, (RzPVectorFree)rz_il_event_free);
	rz_pvector_foreach (vm->events, it) {
		RzILEvent *evt = *it;
		ret = fill_rop_gadget_info_from_events(core, rop_gadget_info, NULL, evt,
			&vec, false);
		if (ret < 0) {
			break;
		}
	}

cleanup:
	rz_pvector_flush(&vec);
	rz_core_seek(core, old_addr, true);
	return ret;
}

static void rz_rop_gadget_print_standard_mode(const RzCore *core, const RzRopGadgetInfo *gadget_info) {
	rz_return_if_fail(core && core->analysis && core->analysis->reg && gadget_info);

	rz_cons_printf("Gadget 0x%" PFMT64x "\n", gadget_info->address);
	rz_cons_printf("Stack change: 0x%" PFMT64x "\n", gadget_info->stack_change);

	rz_cons_printf("Changed registers: ");
	void **it;
	RzRopRegInfo *reg_info;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		reg_info = *it;
		rz_cons_printf("%s ", reg_info->name);
	}
	rz_cons_printf("\n");

	rz_cons_printf("Register dependencies:\n");
	RzListIter *iter;
	rz_list_foreach (gadget_info->dependencies, iter, reg_info) {
		if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) ||
			rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_BP)) {
			continue;
		}
		if (reg_info->is_var_write) {
			rz_cons_printf("Var write: %s Initial value: %llu New Value: %llu\n", reg_info->name, reg_info->init_val, reg_info->new_val);
		} else if (reg_info->is_mem_read) {
			rz_cons_printf("Memory Read: %s Value: %llu\n", reg_info->name, reg_info->new_val);
		} else if (reg_info->is_mem_write) {
			rz_cons_printf("Memory Write: %s Initial Value: %llu New Value: %llu\n", reg_info->name, reg_info->init_val, reg_info->new_val);
		}
	}

	rz_cons_printf("\n");
}

static void rz_rop_gadget_print_json_mode(const RzCore *core, const RzRopGadgetInfo *gadget_info, PJ *pj) {
	rz_return_if_fail(gadget_info && pj);

	pj_o(pj);
	pj_kn(pj, "address", gadget_info->address);
	pj_kn(pj, "stack_change", gadget_info->stack_change);

	pj_k(pj, "modified_registers");
	pj_a(pj);
	void **it;
	RzRopRegInfo *reg_info;
	rz_pvector_foreach (gadget_info->modified_registers, it) {
		reg_info = *it;
		pj_o(pj);
		pj_ks(pj, "name", reg_info->name);
		pj_ks(pj, "type", "var_write");
		pj_end(pj);
	}
	pj_end(pj);

	pj_k(pj, "dependencies");
	pj_a(pj);
	RzListIter *iter;
	rz_list_foreach (gadget_info->dependencies, iter, reg_info) {
		if (rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_SP) ||
			rz_reg_is_role(core->analysis->reg, reg_info->name, RZ_REG_NAME_BP)) {
			continue;
		}
		pj_o(pj);
		pj_ks(pj, "name", reg_info->name);
		if (reg_info->is_var_write) {
			pj_ks(pj, "type", "var_write");
			pj_kn(pj, "init_val", reg_info->init_val);
			pj_kn(pj, "new_val", reg_info->new_val);
		} else if (reg_info->is_mem_read) {
			pj_ks(pj, "type", "mem_read");
			pj_kn(pj, "new_val", reg_info->new_val);
		} else if (reg_info->is_mem_write) {
			pj_ks(pj, "type", "mem_write");
			pj_kn(pj, "init_val", reg_info->init_val);
			pj_kn(pj, "new_val", reg_info->new_val);
		}
		pj_end(pj);
	}
	pj_end(pj);

	pj_end(pj);
}

static void print_rop_gadget_info(const RzCore *core, const RzRopGadgetInfo *gadget_info, const RzRopSearchContext *context) {
	rz_return_if_fail(gadget_info && context && context->state);
	if (RZ_STR_NE(context->greparg, "")) {
		const ut64 addr = rz_num_math(core->num, context->greparg);
		if (!addr || gadget_info->address != addr) {
			return;
		}
	}

	switch (context->state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		rz_rop_gadget_print_json_mode(core, gadget_info, context->state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_rop_gadget_print_standard_mode(core, gadget_info);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static int print_rop(const RzCore *core, const RzList /*<RzCoreAsmHit *>*/ *hitlist, RzCmdStateOutput *state) {
	const RzCoreAsmHit *hit = NULL;
	RzListIter *iter;
	unsigned int size = 0;
	char *asmop_str = NULL, *asmop_hex_str = NULL;
	const bool colorize = rz_config_get_i(core->config, "scr.color");
	const bool rop_comments = rz_config_get_i(core->config, "rop.comments");

	rz_cmd_state_output_set_columnsf(state, "XXs", "addr", "bytes", "disasm");
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(state->d.pj);
		pj_ka(state->d.pj, "opcodes");
	} else if (state->mode == RZ_OUTPUT_MODE_QUIET) {
		rz_cons_printf("0x%08" PFMT64x ":", ((RzCoreAsmHit *)rz_list_first(hitlist))->addr);
	}
	const ut64 addr = ((RzCoreAsmHit *)rz_list_first(hitlist))->addr;

	bool result = 0;
	rz_list_foreach (hitlist, iter, hit) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			result = rz_rop_print_json_mode(core, hit, &size, state->d.pj) != 0;
			break;
		case RZ_OUTPUT_MODE_QUIET:
			result = rz_rop_print_quiet_mode(core, hit, &size, colorize) != 0;
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			result = rz_rop_print_standard_mode(core, hit, &size, rop_comments, colorize) != 0;
			break;
		case RZ_OUTPUT_MODE_TABLE:
			result = rz_rop_print_table_mode(core, hit, hitlist, &size, &asmop_str, &asmop_hex_str) != 0;
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		if (!result) {
			return result;
		}
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_end(state->d.pj);
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
		if (hit) {
			rz_cons_printf("Gadget size: %d\n", (int)size);
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
	return 0;
}

static int handle_rop_list(RzStrBuf *sb, const RzRopSearchContext *context,
	const RzRopEndListPair *end_gadget, RZ_OWN RzList /*<RzCoreAsmHit *>*/ *hitlist) {
	rz_return_val_if_fail(sb && context && context->unique_hitlists, -1);
	if (end_gadget->delay_size && rz_list_length(hitlist) < 1 + end_gadget->delay_size) {
		rz_list_free(hitlist);
		return -1;
	}

	bool is_found = true;
	const char *asm_op_hex = NULL;
	if (sb->len) {
		asm_op_hex = rz_strbuf_get(sb);
		ht_su_find(context->unique_hitlists, asm_op_hex, &is_found);
	}
	if (!is_found && asm_op_hex) {
		ht_su_insert(context->unique_hitlists, asm_op_hex, 1);
	} else {
		rz_list_free(hitlist);
		return -1;
	}
	return 0;
}

static void init_grep_context(const RzRopSearchContext *context, char **grep_str,
	const char **start, const char **end, const RzList /*<char *>*/ *rx_list, char **rx, int *count) {
	if (context->greparg) {
		*start = context->greparg;
		*end = strchr(context->greparg, ';');
		if (!*end) {
			*end = *start + strlen(context->greparg);
		}
		*grep_str = calloc(1, *end - *start + 1);
		strncpy(*grep_str, *start, *end - *start);
		if (context->regexp && rz_list_length(rx_list) > 0) {
			*rx = rz_list_get_n(rx_list, (*count)++);
		}
	}
}

static bool process_instruction(const RzCore *core, RzAnalysisOp *aop, const int addr, const ut8 *buf, const int buf_len, ut32 *end_gadget_cnt) {
	const int error = rz_analysis_op(core->analysis, aop, addr, buf, buf_len, RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_IL);
	if (!aop) {
		return false;
	}
	if (error < 0 || (aop->type == RZ_ANALYSIS_OP_TYPE_NOP && aop->size == 0)) {
		return false;
	}
	if (is_end_gadget(aop, 0)) {
		(*end_gadget_cnt)++;
	}
	return true;
}

static bool is_invalid_instruction(const char *opst, const int end_gadget_cnt) {
	rz_return_val_if_fail(opst, false);
	return !rz_str_ncasecmp(opst, "invalid", strlen("invalid")) ||
		!rz_str_ncasecmp(opst, ".byte", strlen(".byte")) ||
		end_gadget_cnt > 1;
}

static void update_search_context(const RzRopSearchContext *context, const char **start, const char **end,
	char **grep_str, const RzList /*<char *>*/ *rx_list, char **rx, int *count) {
	if (*end && (*end)[0] == ';') { // fields are semicolon-separated
		*start = *end + 1; // skip the ;
		*end = strchr(*start, ';');
		if (!*end) {
			*end = *start + strlen(*start); // latest field?
		}
		free(*grep_str);
		*grep_str = calloc(1, *end - *start + 1);
		if (*grep_str) {
			strncpy(*grep_str, *start, *end - *start);
		}
	} else {
		*end = NULL;
	}

	if (context->regexp) {
		*rx = rz_list_get_n(rx_list, (*count)++);
	}
}

static RzList /*<RzCoreAsmHit *>*/ *construct_rop_gadget(RzCore *core, ut8 *buf, int idx, RzRopSearchContext *context,
	RzList /*<char *>*/ *rx_list, RzRopEndListPair *end_gadget) {
	const char *start = NULL, *end = NULL;
	int count = 0;
	char *rx = NULL;
	char *grep_str = NULL;
	bool is_greparg = !(context->mask & (RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE)) && context->greparg;
	if (is_greparg) {
		init_grep_context(context, &grep_str, &start, &end, rx_list, &rx, &count);
	}

	RzList *hitlist = rz_core_asm_hit_list_new();
	if (!hitlist) {
		free(grep_str);
		return NULL;
	}

	ut8 nb_instr = 0;
	int addr = context->from + idx;
	int delta = context->to - context->from;
	ut32 end_gadget_cnt = 0;

	RzAnalysisOp aop = { 0 };
	bool valid = false;
	RzStrBuf *sb = rz_strbuf_new("");
	while (nb_instr < context->max_instr) {
		rz_analysis_op_init(&aop);
		if (idx >= delta || !process_instruction(core, &aop, addr, buf + idx, delta - idx, &end_gadget_cnt)) {
			valid = false;
			goto cleanup;
		}

		char *opst = aop.mnemonic;
		RzAsmOp asmop = RZ_EMPTY;
		int ret = rz_asm_disassemble(core->rasm, &asmop, buf + idx, delta - idx);
		if (ret < 0) {
			valid = false;
			goto cleanup;
		}

		if (is_invalid_instruction(opst, end_gadget_cnt)) {
			valid = false;
			goto cleanup;
		}

		RzCoreAsmHit *hit = rz_core_asm_hit_new();
		if (!hit) {
			valid = false;
			goto cleanup;
		}

		hit->addr = addr;
		hit->len = aop.size;
		char *asm_op_hex = rz_asm_op_get_hex(&asmop);
		rz_strbuf_append(sb, asm_op_hex);
		free(asm_op_hex);
		rz_list_append(hitlist, hit);
		if (ret >= 0) {
			rz_asm_op_fini(&asmop);
		}
		idx += aop.size;
		addr += aop.size;

		bool search_hit = false;
		if (rx) {
			int grep_find = rz_regex_contains(rx, opst, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
			search_hit = end && context->greparg && grep_find;
		} else if (is_greparg) {
			search_hit = end && context->greparg && strstr(opst, grep_str);
		}

		if (search_hit) {
			update_search_context(context, &start, &end, &grep_str, rx_list, &rx, &count);
		}
		if (end_gadget->instr_offset <= idx - aop.size) {
			valid = end_gadget->instr_offset == idx - aop.size;
			goto cleanup;
		}
		rz_analysis_op_fini(&aop);
		nb_instr++;
	}

cleanup:
	rz_analysis_op_fini(&aop);
	free(grep_str);
	if ((context->regexp && rx) || (!valid || (is_greparg && end))) {
		rz_list_free(hitlist);
		rz_strbuf_free(sb);
		return NULL;
	}
	if (handle_rop_list(sb, context, end_gadget, hitlist) < 0) {
		rz_strbuf_free(sb);
		return NULL;
	}
	rz_strbuf_free(sb);
	return hitlist;
}

static RzRopGadgetInfo *perform_gadget_analysis(RzCore *core, const RzRopSearchContext *context, const RzList /*<RzCoreAsmHit *>*/ *hitlist) {
	RzRopGadgetInfo *rop_gadget_info = NULL;

	if (!core->analysis->ht_rop_semantics) {
		core->analysis->ht_rop_semantics = ht_up_new(NULL, (HtUPFreeValue)rz_core_rop_gadget_info_free);
	}
	const RzCoreAsmHit *hit_last = (RzCoreAsmHit *)rz_list_last(hitlist);
	if (!is_ret_gadget(core, hit_last, context->crop)) {
		return rop_gadget_info;
	}
	const ut64 addr_start = ((RzCoreAsmHit *)rz_list_first(hitlist))->addr;
	rop_gadget_info = ht_up_find(core->analysis->ht_rop_semantics, addr_start, NULL);
	if (!rop_gadget_info) {
		RzListIter *iter;
		RzCoreAsmHit *hit;
		rop_gadget_info = rz_core_rop_gadget_info_new(addr_start);
		const bool is_rop_analysis = core->analysis->is_rop_analysis;
		core->analysis->is_rop_analysis = true;
		rz_list_foreach (hitlist, iter, hit) {
			if (analyze_gadget(core, hit, rop_gadget_info) < 0) {
				RZ_LOG_WARN("Failed to analyze gadget at 0x%" PFMT64x "\n", hit->addr);
			}
		}
		core->analysis->is_rop_analysis = is_rop_analysis;
		ht_up_insert(core->analysis->ht_rop_semantics, addr_start, rop_gadget_info);
	}

	return rop_gadget_info;
}

static int handle_rop_request_type(RzCore *core, const RzRopSearchContext *context, RzList /*<RzCoreAsmHit *>*/ *hitlist) {
	rz_return_val_if_fail(core && core->analysis, -1);
	if (context->mask & RZ_ROP_GADGET_PRINT) {
		if (context->subchain) {
			do {
				print_rop(core, hitlist, context->state);
				hitlist->head = hitlist->head->next;
			} while (hitlist->head->next);
		} else {
			print_rop(core, hitlist, context->state);
		}
	}

	RzRopGadgetInfo *rop_gadget_info = NULL;
	bool is_analysis = false;
	if (context->mask & RZ_ROP_GADGET_ANALYZE) {
		rop_gadget_info = perform_gadget_analysis(core, context, hitlist);
		is_analysis = true;
	}

	if (context->mask & RZ_ROP_GADGET_PRINT_DETAIL) {
		if (!rop_gadget_info && is_analysis) {
			return 0;
		}
		print_rop_gadget_info(core, rop_gadget_info, context);
	}
	return 0;
}

static int fetch_search_itv(const RzCore *core, RzInterval *search_itv) {
	rz_return_val_if_fail(core && core->config, -1);
	const ut64 search_from = rz_config_get_i(core->config, "search.from"),
		   search_to = rz_config_get_i(core->config, "search.to");
	if (search_from > search_to && search_to) {
		RZ_LOG_ERROR("core: search.from > search.to is not supported\n");
		return -1;
	}
	search_itv->addr = search_from;
	search_itv->size = search_to - search_from;

	const bool empty_search_itv = search_from == search_to && search_from != UT64_MAX;
	if (empty_search_itv) {
		RZ_LOG_ERROR("core: `from` address is equal `to`\n");
		return -1;
	}
	// TODO full address cannot be represented, shrink 1 byte to [0, UT64_MAX)
	if (search_from == UT64_MAX && search_to == UT64_MAX) {
		search_itv->addr = 0;
		search_itv->size = UT64_MAX;
	}
	return 0;
}

static RzList /*<RzRopEndListPair *>*/ *compute_end_gadget_list(const RzCore *core, const ut8 *buf, const RzRopSearchContext *context) {
	RzList /*<RzRopEndListPair *>*/ *end_list = rz_list_newf(free);
	const int delta = context->to - context->from;

	for (int i = 0; i < delta; i += context->increment) {
		RzAnalysisOp end_gadget = RZ_EMPTY;
		// Disassemble one.
		rz_analysis_op_init(&end_gadget);
		if (rz_analysis_op(core->analysis, &end_gadget, context->from + i, buf + i,
			    delta - i, RZ_ANALYSIS_OP_MASK_BASIC) < 1) {
			rz_analysis_op_fini(&end_gadget);
			continue;
		}

		if (is_end_gadget(&end_gadget, context->crop)) {
			RzRopEndListPair *epair = RZ_NEW0(RzRopEndListPair);
			if (epair) {
				epair->instr_offset = i + (end_gadget.delay ? context->increment : 0);
				epair->delay_size = end_gadget.delay;
				rz_list_append(end_list, epair);
			}
		}
		rz_analysis_op_fini(&end_gadget);
		if (rz_cons_is_breaked()) {
			break;
		}
	}
	return end_list;
}

static void set_increment_based_on_arch(const RzCore *core, const char *arch, int *increment) {
	if (RZ_STR_EQ(arch, "mips")) { // MIPS has no jump-in-the-middle
		*increment = 4;
	} else if (RZ_STR_EQ(arch, "arm")) { // ARM has no jump-in-the-middle
		*increment = rz_config_get_i(core->config, "asm.bits") == 16 ? 2 : 4;
	} else if (RZ_STR_EQ(arch, "avr")) { // AVR is halfword aligned.
		*increment = 2;
	}
}

static RzList /*<char *>*/ *handle_grep_args(const char *greparg, const bool regexp) {
	if (!greparg || !regexp) {
		return NULL;
	}

	char *grep_arg = strdup(greparg);
	if (!grep_arg) {
		return NULL;
	}
	char *gregexp = rz_str_replace(grep_arg, ",,", ";", true);
	if (!gregexp) {
		return NULL;
	}

	RzList *rx_list = rz_list_newf(free);
	if (!rx_list) {
		free(gregexp);
		return NULL;
	}

	const char *tok = strtok(gregexp, ";");
	while (tok) {
		char *rx = strdup(tok);
		if (!rx) {
			break;
		}
		rz_list_append(rx_list, rx);
		tok = strtok(NULL, ";");
	}

	free(gregexp);
	return rx_list;
}

static bool process_disassembly(RzCore *core, ut8 *buf, const int idx, RzRopSearchContext *context,
	RzList /*<char *>*/ *rx_list, RzRopEndListPair *end_gadget) {
	RzAsmOp *asmop = rz_asm_op_new();
	bool status = false;
	const int ret = rz_asm_disassemble(core->rasm, asmop, buf + idx, context->to - context->from - idx);
	if (!ret) {
		goto fini;
	}

	rz_asm_set_pc(core->rasm, context->from + idx);
	RzList *hitlist = construct_rop_gadget(core, buf, idx, context, rx_list, end_gadget);
	if (!hitlist) {
		goto fini;
	}

	if (core->search->align && (context->from + idx) % core->search->align != 0) {
		rz_list_free(hitlist);
		goto fini;
	}

	if (handle_rop_request_type(core, context, hitlist) < 0) {
		rz_list_free(hitlist);
		goto fini;
	}
	rz_list_free(hitlist);

	if (context->max_count > 0) {
		context->max_count--;
		if (context->max_count < 1) {
			status = true;
		}
	}

fini:
	rz_asm_op_free(asmop);
	return status;
}

RZ_BORROW static int update_end_gadget(int *i, const int ropdepth, RzRopEndListPair **end_gadget, const RzRopSearchContext *context) {
	if (*i > (*end_gadget)->instr_offset) {
		// We've exhausted the first end-gadget section,
		// move to the next one.
		free(*end_gadget);

		if (rz_list_get_n(context->end_list, 0)) {
			*end_gadget = (RzRopEndListPair *)rz_list_pop(context->end_list);
			*i = (*end_gadget)->instr_offset - ropdepth;
			if (*i < 0) {
				*i = 0;
			}
		} else {
			*end_gadget = NULL;
			return -1;
		}
	}
	return 0;
}

/**
 * \brief Search for ROP gadgets.
 * \param core Pointer to the RzCore object.
 * \param context Pointer to the RzRopSearchContext object.
 * \return true if the search is successful, false otherwise.
 *
 * Searches for ROP gadgets within the address range specified by configuration.
 * Disassembles instructions, identifies end gadgets, constructs ROP gadgets, and
 * filters results based on the grep argument and request mask. Outputs results to
 * the provided state object.
 */
RZ_API RzCmdStatus rz_core_rop_search(RZ_NONNULL RzCore *core, RZ_OWN RzRopSearchContext *context) {
	rz_return_val_if_fail(core && core->search, RZ_CMD_STATUS_ERROR);
	int result = -1;

	RzInterval search_itv;
	result = fetch_search_itv(core, &search_itv);
	if (result != 0) {
		return -1;
	}

	if (context->max_instr <= 1) {
		RZ_LOG_ERROR("core: ROP length (rop.len) must be greater than 1.\n");
		if (context->max_instr == 1) {
			RZ_LOG_ERROR("core: For rop.len = 1, use /c to search for single "
				     "instructions. See /c? for help.\n");
		}
		return -1;
	}
	set_increment_based_on_arch(core, context->arch, &context->increment);
	RzList /*<char *>*/ *rx_list = handle_grep_args(context->greparg, context->regexp);
	rz_cmd_state_output_array_start(context->state);
	rz_cons_break_push(NULL, NULL);
	RzList *boundaries = rz_core_get_boundaries_prot(core, -1, context->mode_str, "search");
	if (!boundaries) {
		rz_cmd_state_output_array_end(context->state);
	}
	if (context->max_count == 0) {
		context->max_count = -1;
	}
	context->unique_hitlists = ht_su_new(HT_STR_DUP);
	RzListIter *itermap;
	RzIOMap *map;
	rz_list_foreach (boundaries, itermap, map) {
		if (!rz_itv_overlap(search_itv, map->itv)) {
			continue;
		}
		const RzInterval itv = rz_itv_intersect(search_itv, map->itv);
		context->from = itv.addr;
		context->to = rz_itv_end(itv);
		if (rz_cons_is_breaked()) {
			break;
		}
		const ut64 delta = context->to - context->from;
		ut8 *buf = calloc(1, delta);
		if (!buf) {
			result = false;
			continue;
		}
		if (rz_io_nread_at(core->io, context->from, buf, delta) < 0) {
			free(buf);
			continue;
		}

		context->end_list = compute_end_gadget_list(core, buf, context);
		// If we have no end gadgets, just skip all of this search nonsense.
		if (rz_list_empty(context->end_list)) {
			free(buf);
			rz_list_free(context->end_list);
			continue;
		}
		rz_list_reverse(context->end_list);
		const int max_inst_size_x86 = 15;
		// Get the depth of rop search, should just be max_instr
		// instructions, x86 and friends are weird length instructions, so
		// we'll just assume 15 byte instructions.
		const int ropdepth = context->increment == 1 ? context->max_instr * max_inst_size_x86 /* wow, x86 is long */ : context->max_instr * context->increment;
		if (rz_cons_is_breaked()) {
			break;
		}
		RzRopEndListPair *end_gadget = rz_list_pop(context->end_list);
		// Start at just before the first end gadget.
		const int next = end_gadget->instr_offset;
		for (int i = 0; i < delta && context->max_count; i += context->increment) {
			// TODO: Test this and check if this line is needed in x86
			const int prev = 0;
			if (context->increment == 1 && i < prev - max_inst_size_x86) {
				i = prev - max_inst_size_x86;
			} else if (context->increment != 1 && i < prev) {
				i = prev;
			}
			if (rz_cons_is_breaked()) {
				break;
			}
			if (i > next && update_end_gadget(&i, ropdepth, &end_gadget, context) < 0) {
				break;
			}
			if (process_disassembly(core, buf, i, context, rx_list, end_gadget)) {
				break;
			}
		}
		free(end_gadget);
		free(buf);
		rz_list_free(context->end_list);
	}
	ht_su_free(context->unique_hitlists);
	if (rz_cons_is_breaked()) {
		eprintf("\n");
	}

	rz_cmd_state_output_array_end(context->state);
	rz_cons_break_pop();
	rz_list_free(rx_list);
	rz_core_rop_search_context_free(context);
	rz_list_free(boundaries);
	return result;
}

/**
 * \brief Display ROP gadget information.
 * \param core Pointer to the RzCore object.
 * \param context Pointer to the RzRopSearchContext object.
 * \return RZ_CMD_STATUS_OK on success.
 *
 * Displays ROP gadgets from the gadgetSdb.
 * If unavailable, performs a ROP search with the input.
 */
RZ_API RzCmdStatus rz_core_rop_gadget_info(RZ_NONNULL RzCore *core, RZ_OWN RzRopSearchContext *context) {
	rz_return_val_if_fail(core && core->analysis, RZ_CMD_STATUS_ERROR);

	if (!core->analysis->ht_rop_semantics) {
		// TODO: resolve this logic later.
	}
	return rz_core_rop_search(core, context);
}

/**
 * \brief Free an RzRopConstraint object.
 * \param data Pointer to the RzRopConstraint object to free.
 *
 * Frees the memory allocated for an RzRopConstraint object.
 */
RZ_API void rz_core_rop_constraint_free(RZ_NULLABLE void *data) {
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

/**
 * \brief Create a new list of RzRopConstraint objects.
 * \return Pointer to the newly created list.
 *
 * Creates a new RzList for RzRopConstraint object.
 */
RZ_OWN RZ_API RzPVector /*<RzRopConstraint *>*/ *rz_core_rop_constraint_map_new(void) {
	RzPVector *list = rz_pvector_new((RzPVectorFree)rz_core_rop_constraint_free);
	if (!list) {
		return NULL;
	}
	return list;
}