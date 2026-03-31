// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_events.h>

/**
 * Get the exception message for the exception id.
 * \param id The exception identifier.
 * \return The exception message.
 */
RZ_API const char *rz_il_event_exception_msg(const RzILEventException id) {
	switch (id) {
	case RZ_IL_EVENT_EXC_NONE:
		return "None";
	case RZ_IL_EVENT_EXC_DIV_ZERO:
		return "division by zero";
	case RZ_IL_EVENT_EXC_FP_INVALID_OP:
		return "float invalid operation";
	case RZ_IL_EVENT_EXC_FP_DIV_ZERO:
		return "float division by zero";
	case RZ_IL_EVENT_EXC_FP_OVERFLOW:
		return "float overflow";
	case RZ_IL_EVENT_EXC_FP_UNDERFLOW:
		return "float underflow";
	case RZ_IL_EVENT_EXC_FP_INEXACT:
		return "float inexact";
	}
	return "unknown exception";
}

/**
 * Frees an RzILEvent struct
 * \param evt, RzILEvent, pointer to the RzILEvent to free
 */
RZ_API void rz_il_event_free(RZ_NULLABLE RzILEvent *evt) {
	if (!evt) {
		return;
	}
	switch (evt->type) {
	case RZ_IL_EVENT_EXCEPTION:
		break;
	case RZ_IL_EVENT_PC_WRITE:
		rz_bv_free(evt->data.pc_write.old_pc);
		rz_bv_free(evt->data.pc_write.new_pc);
		break;
	case RZ_IL_EVENT_MEM_READ:
		rz_bv_free(evt->data.mem_read.address);
		rz_bv_free(evt->data.mem_read.value);
		break;
	case RZ_IL_EVENT_VAR_READ:
		free(evt->data.var_read.variable);
		rz_il_value_free(evt->data.var_read.value);
		break;
	case RZ_IL_EVENT_MEM_WRITE:
		rz_bv_free(evt->data.mem_write.address);
		rz_bv_free(evt->data.mem_write.old_value);
		rz_bv_free(evt->data.mem_write.new_value);
		break;
	case RZ_IL_EVENT_VAR_WRITE:
		free(evt->data.var_write.variable);
		rz_il_value_free(evt->data.var_write.old_value);
		rz_il_value_free(evt->data.var_write.new_value);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(evt);
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_EXCEPTION
 * \param id The exception identifier.
 * \param msg Pointer to the exception message
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_exception_new(RzILEventException id) {
	rz_return_val_if_fail(id != RZ_IL_EVENT_EXC_NONE, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		RZ_LOG_ERROR("RzIL: cannot allocate exception RzILEvent\n");
		return NULL;
	}

	evt->type = RZ_IL_EVENT_EXCEPTION;
	evt->data.exception = id;
	return evt;
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_PC_WRITE
 * \param old_pc, RzBitVector, old program counter value before the change
 * \param new_pc, RzBitVector, new program counter value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_pc_write_new(RZ_NONNULL const RzBitVector *old_pc, RZ_NONNULL const RzBitVector *new_pc) {
	rz_return_val_if_fail(old_pc && new_pc, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZ_IL_EVENT_PC_WRITE;
	evt->data.pc_write.old_pc = rz_bv_dup(old_pc);
	evt->data.pc_write.new_pc = rz_bv_dup(new_pc);
	if (!evt->data.pc_write.old_pc || !evt->data.pc_write.new_pc) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_MEM_READ
 * \param index, RzILMemIndex, index of the memory to read
 * \param addr, RzBitVector, address of the memory where the read op has occurred
 * \param value, RzBitVector, value read from the variable
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_read_new(RzILMemIndex index, RZ_NONNULL const RzBitVector *address, RZ_NULLABLE const RzBitVector *value) {
	rz_return_val_if_fail(address && value, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZ_IL_EVENT_MEM_READ;
	evt->data.mem_read.index = index;
	evt->data.mem_read.address = rz_bv_dup(address);
	evt->data.mem_read.value = rz_bv_dup(value);
	if (!evt->data.mem_read.address || !evt->data.mem_read.value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_MEM_WRITE
 * \param index, RzILMemIndex, index of the memory to store data
 * \param addr, RzBitVector, address of the memory that has changed
 * \param old_v, RzBitVector, old value before the change
 * \param new_v, RzBitVector, new value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_write_new(RzILMemIndex index, RZ_NONNULL const RzBitVector *addr, RZ_NONNULL const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v) {
	rz_return_val_if_fail(addr && old_v && new_v, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZ_IL_EVENT_MEM_WRITE;
	evt->data.mem_write.index = index;
	evt->data.mem_write.address = rz_bv_dup(addr);
	evt->data.mem_write.old_value = rz_bv_dup(old_v);
	evt->data.mem_write.new_value = rz_bv_dup(new_v);
	if (!evt->data.mem_write.address ||
		!evt->data.mem_write.old_value ||
		!evt->data.mem_write.new_value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_VAR_READ
 * \param name register name that has changed
 * \param value value read from the variable
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_var_read_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzILVal *value) {
	rz_return_val_if_fail(name && value, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZ_IL_EVENT_VAR_READ;
	evt->data.var_read.variable = rz_str_dup(name);
	evt->data.var_read.value = rz_il_value_dup(value);
	if (!evt->data.var_read.variable || !evt->data.var_read.value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZ_IL_EVENT_VAR_WRITE
 * \param name register name that has changed
 * \param old_v old value before the change
 * \param new_v new value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_var_write_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzILVal *old_v, RZ_NONNULL const RzILVal *new_v) {
	rz_return_val_if_fail(name && old_v && new_v, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZ_IL_EVENT_VAR_WRITE;
	evt->data.var_write.variable = rz_str_dup(name);
	evt->data.var_write.old_value = rz_il_value_dup(old_v);
	evt->data.var_write.new_value = rz_il_value_dup(new_v);
	if (!evt->data.var_write.variable ||
		!evt->data.var_write.old_value ||
		!evt->data.var_write.new_value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}
