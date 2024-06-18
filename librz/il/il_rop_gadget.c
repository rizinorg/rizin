// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_rop.h>
#include <rz_core.h>

RZ_API void il_op_pure_rop_gadget_resolve(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info);

// TODO: Refactor this, added here because arch is dependent on IL and won't compile
static char *get_reg_profile(RzAnalysis *analysis) {
	return analysis && analysis->cur && analysis->cur->get_reg_profile
		? analysis->cur->get_reg_profile(analysis)
		: NULL;
}

static bool is_reg_in_profile(const char *reg_profile, const char *str) {
	if (strstr(reg_profile, str) != NULL) {
		return true;
	}
	return false;
}

RZ_API void add_reg_to_list(RzCore *core, RzList *list, const char *str) {
	if (!str) {
		return;
	}
	char *reg_prof = get_reg_profile(core->analysis);
	if (!reg_prof) {
		return;
	}

	// Check if the register is correct for the given architecture.
	if (is_reg_in_profile(reg_prof, str)) {
		free(reg_prof);
		char *copy = strdup(str);
		rz_list_append(list, copy);
		return;
	}

	free(reg_prof);
}

static void resolve_var_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	if (op->code == RZ_IL_OP_VAR) {
		add_reg_to_list(core, info->modified_registers, op->op.var.v);
	}
}

static void resolve_ite_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	if (op->code == RZ_IL_OP_ITE) {
		il_op_pure_rop_gadget_resolve(core, op->op.ite.condition, info);
		il_op_pure_rop_gadget_resolve(core, op->op.ite.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.ite.y, info);
	}
}

static void resolve_bool_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	switch (op->code) {
	case RZ_IL_OP_AND:
		il_op_pure_rop_gadget_resolve(core, op->op.booland.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.booland.y, info);
		break;
	case RZ_IL_OP_OR:
		il_op_pure_rop_gadget_resolve(core, op->op.boolor.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.boolor.y, info);
		break;
	case RZ_IL_OP_XOR:
		il_op_pure_rop_gadget_resolve(core, op->op.boolxor.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.boolxor.y, info);
		break;
	case RZ_IL_OP_INV:
		il_op_pure_rop_gadget_resolve(core, op->op.boolinv.x, info);
		break;
	default:
		break;
	}
}

static void resolve_bitvector_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	switch (op->code) {
	case RZ_IL_OP_BITV:

		break;
	case RZ_IL_OP_MSB:
		il_op_pure_rop_gadget_resolve(core, op->op.msb.bv, info);
		break;
	case RZ_IL_OP_LSB:
		il_op_pure_rop_gadget_resolve(core, op->op.lsb.bv, info);
		break;
	case RZ_IL_OP_IS_ZERO:
		il_op_pure_rop_gadget_resolve(core, op->op.is_zero.bv, info);
		break;
	case RZ_IL_OP_NEG:
		il_op_pure_rop_gadget_resolve(core, op->op.neg.bv, info);
		break;
	case RZ_IL_OP_LOGNOT:
		il_op_pure_rop_gadget_resolve(core, op->op.lognot.bv, info);
		break;
	case RZ_IL_OP_ADD:
		il_op_pure_rop_gadget_resolve(core, op->op.add.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.add.y, info);
		break;
	case RZ_IL_OP_SUB:
		il_op_pure_rop_gadget_resolve(core, op->op.sub.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.sub.y, info);
		break;
	case RZ_IL_OP_MUL:
		il_op_pure_rop_gadget_resolve(core, op->op.mul.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.mul.y, info);
		break;
	case RZ_IL_OP_DIV:
		il_op_pure_rop_gadget_resolve(core, op->op.div.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.div.y, info);
		break;
	case RZ_IL_OP_SDIV:
		il_op_pure_rop_gadget_resolve(core, op->op.sdiv.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.sdiv.y, info);
		break;
	case RZ_IL_OP_MOD:
		il_op_pure_rop_gadget_resolve(core, op->op.mod.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.mod.y, info);
		break;
	case RZ_IL_OP_SMOD:
		il_op_pure_rop_gadget_resolve(core, op->op.smod.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.smod.y, info);
		break;
	case RZ_IL_OP_LOGAND:
		il_op_pure_rop_gadget_resolve(core, op->op.logand.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.logand.y, info);
		break;
	case RZ_IL_OP_LOGOR:
		il_op_pure_rop_gadget_resolve(core, op->op.logor.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.logor.y, info);
		break;
	case RZ_IL_OP_LOGXOR:
		il_op_pure_rop_gadget_resolve(core, op->op.logxor.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.logxor.y, info);
		break;
	case RZ_IL_OP_SHIFTR:
		il_op_pure_rop_gadget_resolve(core, op->op.shiftr.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.shiftr.y, info);
		il_op_pure_rop_gadget_resolve(core, op->op.shiftr.fill_bit, info);
		break;
	case RZ_IL_OP_SHIFTL:
		il_op_pure_rop_gadget_resolve(core, op->op.shiftl.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.shiftl.y, info);
		il_op_pure_rop_gadget_resolve(core, op->op.shiftl.fill_bit, info);
		break;
	case RZ_IL_OP_APPEND:
		il_op_pure_rop_gadget_resolve(core, op->op.append.high, info);
		il_op_pure_rop_gadget_resolve(core, op->op.append.low, info);
		break;
	default:
		break;
	}
}

static void update_gadget_info_stack_change(RzRopGadgetInfo *info, ut64 change) {
	info->stack_change += change;
}

static void set_memory_read_register(RzCore *core, RzRopGadgetInfo *info, const char *register_name) {
	add_reg_to_list(core, info->memory_read.stored_in_regs, register_name);
}

static void add_memory_dependency(RzCore *core, RzRopGadgetInfo *info, const char *register_name) {
	add_reg_to_list(core, info->memory_write.dependencies, register_name);
	add_reg_to_list(core, info->memory_read.dependencies, register_name);
}

static void resolve_load_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	if (op->code == RZ_IL_OP_LOAD) {
		add_memory_dependency(core, info, (const char *)op->op.load.key);
	} else if (op->code == RZ_IL_OP_LOADW) {
		add_memory_dependency(core, info, (const char *)op->op.loadw.key);
	}
}

static void resolve_cast_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	if (op->code == RZ_IL_OP_CAST) {
		il_op_pure_rop_gadget_resolve(core, op->op.cast.val, info);
	}
}

static void resolve_float_op(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	switch (op->code) {
	case RZ_IL_OP_FLOAT:
		il_op_pure_rop_gadget_resolve(core, op->op.float_.bv, info);
		break;
	case RZ_IL_OP_FNEG:
		il_op_pure_rop_gadget_resolve(core, op->op.fneg.f, info);
		break;
	case RZ_IL_OP_FABS:
		il_op_pure_rop_gadget_resolve(core, op->op.fabs.f, info);
		break;
	case RZ_IL_OP_FADD:
		il_op_pure_rop_gadget_resolve(core, op->op.fadd.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fadd.y, info);
		break;
	case RZ_IL_OP_FSUB:
		il_op_pure_rop_gadget_resolve(core, op->op.fsub.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fsub.y, info);
		break;
	case RZ_IL_OP_FMUL:
		il_op_pure_rop_gadget_resolve(core, op->op.fmul.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fmul.y, info);
		break;
	case RZ_IL_OP_FDIV:
		il_op_pure_rop_gadget_resolve(core, op->op.fdiv.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fdiv.y, info);
		break;
	case RZ_IL_OP_FMOD:
		il_op_pure_rop_gadget_resolve(core, op->op.fmod.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fmod.y, info);
		break;
	case RZ_IL_OP_FMAD:
		il_op_pure_rop_gadget_resolve(core, op->op.fmad.x, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fmad.y, info);
		il_op_pure_rop_gadget_resolve(core, op->op.fmad.z, info);
		break;
	default:
		break;
	}
}

RZ_API void il_op_pure_rop_gadget_resolve(RzCore *core, RzILOpPure *op, RzRopGadgetInfo *info) {
	if (!op) {
		return;
	}
	switch (op->code) {
	case RZ_IL_OP_VAR:
		resolve_var_op(core, op, info);
		break;
	case RZ_IL_OP_ITE:
		resolve_ite_op(core, op, info);
		break;
	case RZ_IL_OP_AND:
	case RZ_IL_OP_OR:
	case RZ_IL_OP_XOR:
	case RZ_IL_OP_INV:
		resolve_bool_op(core, op, info);
		break;
	case RZ_IL_OP_BITV:
	case RZ_IL_OP_MSB:
	case RZ_IL_OP_LSB:
	case RZ_IL_OP_IS_ZERO:
	case RZ_IL_OP_NEG:
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_ADD:
	case RZ_IL_OP_SUB:
	case RZ_IL_OP_MUL:
	case RZ_IL_OP_DIV:
	case RZ_IL_OP_SDIV:
	case RZ_IL_OP_MOD:
	case RZ_IL_OP_SMOD:
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_SHIFTR:
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_APPEND:
		resolve_bitvector_op(core, op, info);
		break;
	case RZ_IL_OP_LOAD:
	case RZ_IL_OP_LOADW:
		resolve_load_op(core, op, info);
		break;
	case RZ_IL_OP_CAST:
		resolve_cast_op(core, op, info);
		break;
	case RZ_IL_OP_FLOAT:
	case RZ_IL_OP_FNEG:
	case RZ_IL_OP_FABS:
	case RZ_IL_OP_FADD:
	case RZ_IL_OP_FSUB:
	case RZ_IL_OP_FMUL:
	case RZ_IL_OP_FDIV:
	case RZ_IL_OP_FMOD:
	case RZ_IL_OP_FMAD:
		resolve_float_op(core, op, info);
		break;
	default:
		break;
	}
}

static void il_rop_gadget_resolve_set(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect) {
	add_reg_to_list(core, info->modified_registers, effect->op.set.v);
	il_op_pure_rop_gadget_resolve(core, effect->op.set.x, info);
}

static void il_rop_gadget_resolve_store(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect) {
	add_reg_to_list(core, info->memory_write.dependencies, (const char *)effect->op.store.key);
	add_reg_to_list(core, info->memory_write.stored_in_regs, (const char *)effect->op.store.value);
}

static void il_rop_gadget_resolve_seq(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect) {
	populate_gadget_info(core, info, effect->op.seq.x);
	populate_gadget_info(core, info, effect->op.seq.y);
}

static void il_rop_gadget_resolve_branch(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect) {
	populate_gadget_info(core, info, effect->op.branch.true_eff);
	populate_gadget_info(core, info, effect->op.branch.false_eff);
}

static void il_rop_gadget_resolve_jmp(RzCore *core, RzRopGadgetInfo *info) {
	add_reg_to_list(core, info->modified_registers, "rip");
}

static void il_rop_gadget_resolve_nop(RzCore *core, RzRopGadgetInfo *info) {
	// NOP does not change any state or register
}

RZ_API void populate_gadget_info(RzCore *core, RzRopGadgetInfo *info, RzILOpEffect *effect) {
	if (!effect) {
		return;
	}
	switch (effect->code) {
	case RZ_IL_OP_SET:
		il_rop_gadget_resolve_set(core, info, effect);
		break;
	case RZ_IL_OP_STORE:
		il_rop_gadget_resolve_store(core, info, effect);
		break;
	case RZ_IL_OP_SEQ:
		il_rop_gadget_resolve_seq(core, info, effect);
		break;
	case RZ_IL_OP_BRANCH:
		il_rop_gadget_resolve_branch(core, info, effect);
		break;
	case RZ_IL_OP_JMP:
		il_rop_gadget_resolve_jmp(core, info);
		break;
	case RZ_IL_OP_NOP:
		il_rop_gadget_resolve_nop(core, info);
		break;
	default:
		break;
	}
}
