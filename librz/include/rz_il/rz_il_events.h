// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VM_EVENTS_H
#define RZ_IL_VM_EVENTS_H

#include "rz_il_opcodes.h"

#include <rz_il/definitions/definitions.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief list of types of events that can happen on the VM
 */

typedef enum rz_il_event_id_t {
	RZ_IL_EVENT_EXCEPTION = 0,
	RZ_IL_EVENT_PC_WRITE,
	RZ_IL_EVENT_MEM_READ,
	RZ_IL_EVENT_VAR_READ,
	RZ_IL_EVENT_MEM_WRITE,
	RZ_IL_EVENT_VAR_WRITE,
	RZ_IL_EVENT_IL_LOG_EFFECT,
	RZ_IL_EVENT_IL_LOG_PURE,
} RzILEventId;

typedef union {
	RzILOpEffectCode op_effect;
	RzILOpPureCode op_pure;
} RzILOpUnion;

typedef struct {
	RzILOpUnion op;
} RzILEventILLog;

typedef struct rz_il_vm_event_mem_read_t {
	RZ_NONNULL RzBitVector *address;
	RZ_NONNULL RzBitVector *value;
} RzILEventMemRead;

typedef struct rz_il_vm_event_var_read_t {
	RZ_NONNULL char *variable;
	RZ_NONNULL RzILVal *value;
} RzILEventVarRead;

typedef struct rz_il_vm_event_pc_write_t {
	RzBitVector *old_pc;
	RzBitVector *new_pc;
} RzILEventPCWrite;

typedef struct rz_il_vm_event_mem_write_t {
	RZ_NONNULL RzBitVector *address;
	RZ_NONNULL RzBitVector *old_value;
	RZ_NONNULL RzBitVector *new_value;
} RzILEventMemWrite;

typedef struct rz_il_vm_event_var_write_t {
	RZ_NONNULL char *variable;
	RZ_NONNULL RzILVal *old_value;
	RZ_NONNULL RzILVal *new_value;
} RzILEventVarWrite;

typedef struct rz_il_vm_event_t {
	RzILEventId type;
	union {
		char *exception;
		RzILEventPCWrite pc_write;
		RzILEventMemRead mem_read;
		RzILEventMemWrite mem_write;
		RzILEventVarRead var_read;
		RzILEventVarWrite var_write;
		RzILEventILLog il_log;
	} data;
} RzILEvent;

RZ_API RZ_OWN RzILEvent *rz_il_event_exception_new(RZ_NONNULL const char *exception);
RZ_API RZ_OWN RzILEvent *rz_il_event_pc_write_new(RZ_NONNULL const RzBitVector *old_pc, RZ_NONNULL const RzBitVector *new_pc);
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_read_new(RZ_NONNULL const RzBitVector *addr, RZ_NULLABLE const RzBitVector *value);
RZ_API RZ_OWN RzILEvent *rz_il_event_var_read_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzILVal *value);
RZ_API RZ_OWN RzILEvent *rz_il_event_mem_write_new(RZ_NONNULL const RzBitVector *addr, RZ_NONNULL const RzBitVector *old_v, RZ_NONNULL const RzBitVector *new_v);
RZ_API RZ_OWN RzILEvent *rz_il_event_var_write_new(RZ_NONNULL const char *name, RZ_NULLABLE const RzILVal *old_v, RZ_NONNULL const RzILVal *new_v);
RZ_API RZ_OWN RzILEvent *rz_il_event_effect_new(RZ_NONNULL RzILOpEffect *op);
RZ_API RZ_OWN RzILEvent *rz_il_event_pure_new(RZ_NONNULL RzILOpPure *op);
RZ_API void rz_il_event_free(RZ_NULLABLE RzILEvent *evt);

// Printing/Export
RZ_API void rz_il_event_stringify(RZ_NONNULL const RzILEvent *evt, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VM_EVENTS_H
