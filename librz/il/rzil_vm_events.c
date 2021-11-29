// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm_events.h>

/**
 * Frees an RzILEvent struct
 * \param evt, RzILEvent, pointer to the RzILEvent to free
 */
RZ_API void rz_il_event_free(RZ_NULLABLE RzILEvent *evt) {
	if (!evt) {
		return;
	}
	switch (evt->type) {
	case RZIL_EVENT_EXCEPTION:
		free(evt->data.exception);
		break;
	case RZIL_EVENT_PC_WRITE:
		rz_bitvector_free(evt->data.pc_write.old_pc);
		rz_bitvector_free(evt->data.pc_write.new_pc);
		break;
	case RZIL_EVENT_MEM_READ:
		rz_bitvector_free(evt->data.mem_read.address);
		rz_bitvector_free(evt->data.mem_read.value);
		break;
	case RZIL_EVENT_VAR_READ:
		free(evt->data.var_read.variable);
		rz_bitvector_free(evt->data.var_read.value);
		break;
	case RZIL_EVENT_MEM_WRITE:
		rz_bitvector_free(evt->data.mem_write.address);
		rz_bitvector_free(evt->data.mem_write.old_value);
		rz_bitvector_free(evt->data.mem_write.new_value);
		break;
	case RZIL_EVENT_VAR_WRITE:
		free(evt->data.var_write.variable);
		rz_bitvector_free(evt->data.var_write.old_value);
		rz_bitvector_free(evt->data.var_write.new_value);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	free(evt);
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_EXCEPTION
 * \param exception, const char, pointer to the exception message
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_exception_new(RZ_NONNULL const char *exception) {
	rz_return_val_if_fail(exception, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		RZ_LOG_ERROR("RzIL: cannot allocate exception RzILEvent");
		return NULL;
	}

	evt->type = RZIL_EVENT_EXCEPTION;
	evt->data.exception = strdup(exception);
	if (!evt->data.exception) {
		rz_il_event_free(evt);
		RZ_LOG_ERROR("RzIL: cannot allocate exception string");
		return NULL;
	}
	return evt;
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_PC_WRITE
 * \param old_pc, RzBitVector, old program counter value before the change
 * \param new_pc, RzBitVector, new program counter value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_pc_write_new(RZ_NONNULL const RzBitVector *old_pc, RZ_NONNULL const RzBitVector *new_pc) {
	rz_return_val_if_fail(old_pc && new_pc, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZIL_EVENT_PC_WRITE;
	evt->data.pc_write.old_pc = rz_bitvector_dup(old_pc);
	evt->data.pc_write.new_pc = rz_bitvector_dup(new_pc);
	if (!evt->data.pc_write.old_pc || !evt->data.pc_write.new_pc) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_MEM_READ
 * \param addr, RzBitVector, address of the memory where the read op has occurred
 * \param value, RzBitVector, value read from the variable (could be null, i.e. garbage value)
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_read_new(RZ_NONNULL const RzBitVector *address, RZ_NULLABLE const RzBitVector *value) {
	rz_return_val_if_fail(address, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZIL_EVENT_MEM_READ;
	evt->data.mem_read.address = rz_bitvector_dup(address);
	evt->data.mem_read.value = value ? rz_bitvector_dup(value) : NULL;
	if (!evt->data.mem_read.address || (value && !evt->data.mem_read.value)) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_MEM_WRITE
 * \param addr, RzBitVector, address of the memory that has changed
 * \param old_v, RzBitVector, old value before the change (could be null, i.e. garbage value)
 * \param new_v, RzBitVector, new value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_write_new(RZ_NONNULL const RzBitVector *addr, RZ_NULLABLE const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v) {
	rz_return_val_if_fail(addr && new_v, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZIL_EVENT_MEM_WRITE;
	evt->data.mem_write.address = rz_bitvector_dup(addr);
	evt->data.mem_write.old_value = old_v ? rz_bitvector_dup(old_v) : NULL;
	evt->data.mem_write.new_value = rz_bitvector_dup(new_v);
	if (!evt->data.mem_write.address ||
		(old_v && !evt->data.mem_write.old_value) ||
		!evt->data.mem_write.new_value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_VAR_READ
 * \param name, const char, register name that has changed
 * \param value, RzBitVector, value read from the variable (could be null, i.e. garbage value)
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_var_read_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzBitVector *value) {
	rz_return_val_if_fail(name, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZIL_EVENT_VAR_READ;
	evt->data.var_read.variable = strdup(name);
	evt->data.var_read.value = value ? rz_bitvector_dup(value) : NULL;
	if (!evt->data.var_read.variable || (value && !evt->data.var_read.value)) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}

/**
 * Creates an RzILEvent of type RZIL_EVENT_VAR_WRITE
 * \param name, const char, register name that has changed
 * \param old_v, RzBitVector, old value before the change (could be null, i.e. garbage value)
 * \param new_v, RzBitVector, new value after the change
 */
RZ_API RZ_OWN RzILEvent *rz_il_event_var_write_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v) {
	rz_return_val_if_fail(name && new_v, NULL);

	RzILEvent *evt = RZ_NEW(RzILEvent);
	if (!evt) {
		return NULL;
	}

	evt->type = RZIL_EVENT_VAR_WRITE;
	evt->data.var_write.variable = strdup(name);
	evt->data.var_write.old_value = old_v ? rz_bitvector_dup(old_v) : NULL;
	evt->data.var_write.new_value = rz_bitvector_dup(new_v);
	if (!evt->data.var_write.variable ||
		(old_v && !evt->data.var_write.old_value) ||
		!evt->data.var_write.new_value) {
		rz_il_event_free(evt);
		return NULL;
	}

	return evt;
}
