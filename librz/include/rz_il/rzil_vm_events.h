// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_VM_EVENTS_H
#define RZIL_VM_EVENTS_H

#include <rz_il/definitions/definitions.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file rzil_vm_events.h
 * \brief list of types of events that can happen on the VM
 */

typedef enum rz_il_event_id_t {
	RZIL_EVENT_EXCEPTION = 0,
	RZIL_EVENT_PC_WRITE,
	RZIL_EVENT_MEM_READ,
	RZIL_EVENT_VAR_READ,
	RZIL_EVENT_MEM_WRITE,
	RZIL_EVENT_VAR_WRITE,
} RzILEventId;

typedef struct rzil_vm_event_mem_read_t {
	RzBitVector *address;
	RzBitVector *value;
} RzILEventMemRead;

typedef struct rzil_vm_event_var_read_t {
	char *variable;
	RzBitVector *value;
} RzILEventVarRead;

typedef struct rzil_vm_event_pc_write_t {
	RzBitVector *old_pc;
	RzBitVector *new_pc;
} RzILEventPCWrite;

typedef struct rzil_vm_event_mem_write_t {
	RzBitVector *address;
	RzBitVector *old_value;
	RzBitVector *new_value;
} RzILEventMemWrite;

typedef struct rzil_vm_event_var_write_t {
	char *variable;
	RzBitVector *old_value;
	RzBitVector *new_value;
} RzILEventVarWrite;

typedef struct rzil_vm_event_t {
	RzILEventId type;
	union {
		char *exception;
		RzILEventPCWrite pc_write;
		RzILEventMemRead mem_read;
		RzILEventMemWrite mem_write;
		RzILEventVarRead var_read;
		RzILEventVarWrite var_write;
	} data;
} RzILEvent;

RZ_API RZ_OWN RzILEvent *rz_il_event_exception_new(RZ_NONNULL const char *exception);
RZ_API RZ_OWN RzILEvent *rz_il_event_pc_write_new(RZ_NONNULL const RzBitVector *old_pc, RZ_NONNULL const RzBitVector *new_pc);
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_read_new(RZ_NONNULL const RzBitVector *addr, RZ_NULLABLE const RzBitVector *value);
RZ_API RZ_OWN RzILEvent *rz_il_event_var_read_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzBitVector *value);
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_write_new(RZ_NONNULL const RzBitVector *addr, RZ_NULLABLE const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v);
RZ_API RZ_OWN RzILEvent *rz_il_event_var_write_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v);
RZ_API void rz_il_event_free(RZ_NULLABLE RzILEvent *evt);

#ifdef __cplusplus
}
#endif

#endif // RZIL_VM_EVENTS_H
