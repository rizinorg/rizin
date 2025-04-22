// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "jvm.h"
#include "const.h"
#include <rz_analysis.h>

#define fail_if_no_enough_buffer_or_set(bytecode, jvm, n) \
	if ((jvm->size - jvm->current) < n) { \
		RZ_LOG_DEBUG("java: buffer is not big enough (available: %u, needed: %u)\n", jvm->size - jvm->current, n); \
		return false; \
	} \
	bytecode->size = n

#define load_ut8(bytecode, jvm, t, c) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 2); \
	bytecode->args[0] = (c)jvm->buffer[jvm->current + 1]; \
	bytecode->type[0] = (t)

#define load_ut8x2(bytecode, jvm, t0, t1, c0, c1) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 3); \
	bytecode->args[0] = (c0)jvm->buffer[jvm->current + 1]; \
	bytecode->type[0] = (t0); \
	bytecode->args[1] = (c1)jvm->buffer[jvm->current + 2]; \
	bytecode->type[1] = (t1)

#define load_ut16(bytecode, jvm, t, c) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 3); \
	bytecode->args[0] = (c)rz_read_at_be16(jvm->buffer, jvm->current + 1); \
	bytecode->type[0] = (t)

#define load_ut32(bytecode, jvm, t, c) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 5); \
	bytecode->args[0] = (c)rz_read_at_be32(jvm->buffer, jvm->current + 1); \
	bytecode->type[0] = (t)

#define load_ut16_ut8(bytecode, jvm, t0, t1, c0, c1) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 4); \
	bytecode->args[0] = (c0)rz_read_at_be16(jvm->buffer, jvm->current + 1); \
	bytecode->type[0] = (t0); \
	bytecode->args[1] = (c1)rz_read_at_be8(jvm->buffer, jvm->current + 3); \
	bytecode->type[1] = (t1)

#define load_ut16x2(bytecode, jvm, t0, t1, c0, c1) \
	fail_if_no_enough_buffer_or_set(bytecode, jvm, 5); \
	bytecode->args[0] = (c0)rz_read_at_be16(jvm->buffer, jvm->current + 1); \
	bytecode->type[0] = (t0); \
	bytecode->args[1] = (c1)rz_read_at_be16(jvm->buffer, jvm->current + 3); \
	bytecode->type[1] = (t1)

static inline ut32 align_upper(JavaVM *jvm) {
	ut64 base = jvm->pc - jvm->section + jvm->current + 1;
	ut64 mod = base % 4;
	if (mod != 0) {
		return 4 - mod;
	}
	return 0;
}

static bool decode_lookupswitch(JavaVM *jvm, Bytecode *bytecode) {
	ut32 offset = jvm->current + align_upper(jvm);

	if ((jvm->size - offset) < 8) {
		return false;
	}
	ut32 pc_default = rz_read_at_be32(jvm->buffer, offset);
	offset += sizeof(ut32);

	ut32 npairs = rz_read_at_be32(jvm->buffer, offset);
	offset += sizeof(ut32);

	LookupSwitch *ls = RZ_NEW(LookupSwitch);
	if (!ls) {
		rz_warn_if_reached();
		return false;
	}

	ls->pc_default = pc_default;
	ls->npairs = npairs;

	bytecode->args[0] = pc_default;
	bytecode->type[0] = BYTECODE_TYPE_ADDRESS;
	bytecode->extra = ls;
	bytecode->size = offset - jvm->current;
	return true;
}

static bool decode_tableswitch(JavaVM *jvm, Bytecode *bytecode) {
	ut32 offset = jvm->current + align_upper(jvm) + 1;

	if ((jvm->size - offset) < 12) {
		rz_warn_if_reached();
		return false;
	}

	ut32 pc_default = rz_read_at_be32(jvm->buffer, offset);
	offset += sizeof(ut32);

	ut32 low = rz_read_at_be32(jvm->buffer, offset);
	offset += sizeof(ut32);

	ut32 high = rz_read_at_be32(jvm->buffer, offset);
	offset += sizeof(ut32);

	ut32 length = high - low;

	TableSwitch *ts = RZ_NEW(TableSwitch);
	if (!ts) {
		rz_warn_if_reached();
		return false;
	}

	ts->pc_default = pc_default;
	ts->low = low;
	ts->high = high;
	ts->length = length;

	bytecode->args[0] = pc_default;
	bytecode->type[0] = BYTECODE_TYPE_ADDRESS;
	bytecode->extra = ts;
	bytecode->size = offset - jvm->current;
	return true;
}

static bool decode_instruction(JavaVM *jvm, Bytecode *bytecode) {
	rz_return_val_if_fail((jvm->size - jvm->current) >= 1, false);

	memset(bytecode, 0, sizeof(Bytecode));

	const ut8 *buffer = jvm->buffer;

	ut8 byte = buffer[jvm->current];
	switch (byte) {
	case BYTECODE_00_NOP:
		strcpy(bytecode->name, "nop");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case BYTECODE_01_ACONST_NULL:
		strcpy(bytecode->name, "aconst_null");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_02_ICONST_M1:
		strcpy(bytecode->name, "iconst_m1");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_03_ICONST_0:
		strcpy(bytecode->name, "iconst_0");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_04_ICONST_1:
		strcpy(bytecode->name, "iconst_1");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_05_ICONST_2:
		strcpy(bytecode->name, "iconst_2");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_06_ICONST_3:
		strcpy(bytecode->name, "iconst_3");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_07_ICONST_4:
		strcpy(bytecode->name, "iconst_4");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_08_ICONST_5:
		strcpy(bytecode->name, "iconst_5");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_09_LCONST_0:
		strcpy(bytecode->name, "lconst_0");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0A_LCONST_1:
		strcpy(bytecode->name, "lconst_1");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0B_FCONST_0:
		strcpy(bytecode->name, "fconst_0");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0C_FCONST_1:
		strcpy(bytecode->name, "fconst_1");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0D_FCONST_2:
		strcpy(bytecode->name, "fconst_2");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0E_DCONST_0:
		strcpy(bytecode->name, "dconst_0");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_0F_DCONST_1:
		strcpy(bytecode->name, "dconst_1");
		bytecode->size = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_10_BIPUSH:
		strcpy(bytecode->name, "bipush");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, st32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_11_SIPUSH:
		strcpy(bytecode->name, "sipush");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_NUMBER, st32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_12_LDC:
		strcpy(bytecode->name, "ldc");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_13_LDC_W:
		strcpy(bytecode->name, "ldc_w");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_14_LDC2_W:
		strcpy(bytecode->name, "ldc2_w");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_15_ILOAD:
		strcpy(bytecode->name, "iload");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_16_LLOAD:
		strcpy(bytecode->name, "lload");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_17_FLOAD:
		strcpy(bytecode->name, "fload");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_18_DLOAD:
		strcpy(bytecode->name, "dload");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_19_ALOAD:
		strcpy(bytecode->name, "aload");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1A_ILOAD_0:
		strcpy(bytecode->name, "iload_0");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1B_ILOAD_1:
		strcpy(bytecode->name, "iload_1");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1C_ILOAD_2:
		strcpy(bytecode->name, "iload_2");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1D_ILOAD_3:
		strcpy(bytecode->name, "iload_3");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1E_LLOAD_0:
		strcpy(bytecode->name, "lload_0");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_1F_LLOAD_1:
		strcpy(bytecode->name, "lload_1");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_20_LLOAD_2:
		strcpy(bytecode->name, "lload_2");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_21_LLOAD_3:
		strcpy(bytecode->name, "lload_3");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_22_FLOAD_0:
		strcpy(bytecode->name, "fload_0");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_23_FLOAD_1:
		strcpy(bytecode->name, "fload_1");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_24_FLOAD_2:
		strcpy(bytecode->name, "fload_2");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_25_FLOAD_3:
		strcpy(bytecode->name, "fload_3");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_26_DLOAD_0:
		strcpy(bytecode->name, "dload_0");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_27_DLOAD_1:
		strcpy(bytecode->name, "dload_1");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_28_DLOAD_2:
		strcpy(bytecode->name, "dload_2");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_29_DLOAD_3:
		strcpy(bytecode->name, "dload_3");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2A_ALOAD_0:
		strcpy(bytecode->name, "aload_0");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2B_ALOAD_1:
		strcpy(bytecode->name, "aload_1");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2C_ALOAD_2:
		strcpy(bytecode->name, "aload_2");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2D_ALOAD_3:
		strcpy(bytecode->name, "aload_3");
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2E_IALOAD:
		strcpy(bytecode->name, "iaload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_2F_LALOAD:
		strcpy(bytecode->name, "laload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_30_FALOAD:
		strcpy(bytecode->name, "faload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_31_DALOAD:
		strcpy(bytecode->name, "daload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_32_AALOAD:
		strcpy(bytecode->name, "aaload");
		bytecode->size = 1;
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_33_BALOAD:
		strcpy(bytecode->name, "baload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_34_CALOAD:
		strcpy(bytecode->name, "caload");
		bytecode->size = 1;
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_35_SALOAD:
		strcpy(bytecode->name, "saload");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BYTECODE_36_ISTORE:
		strcpy(bytecode->name, "istore");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_37_LSTORE:
		strcpy(bytecode->name, "lstore");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_38_FSTORE:
		strcpy(bytecode->name, "fstore");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_39_DSTORE:
		strcpy(bytecode->name, "dstore");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3A_ASTORE:
		strcpy(bytecode->name, "astore");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3B_ISTORE_0:
		strcpy(bytecode->name, "istore_0");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3C_ISTORE_1:
		strcpy(bytecode->name, "istore_1");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3D_ISTORE_2:
		strcpy(bytecode->name, "istore_2");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3E_ISTORE_3:
		strcpy(bytecode->name, "istore_3");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_3F_LSTORE_0:
		strcpy(bytecode->name, "lstore_0");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_40_LSTORE_1:
		strcpy(bytecode->name, "lstore_1");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_41_LSTORE_2:
		strcpy(bytecode->name, "lstore_2");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_42_LSTORE_3:
		strcpy(bytecode->name, "lstore_3");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_43_FSTORE_0:
		strcpy(bytecode->name, "fstore_0");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_44_FSTORE_1:
		strcpy(bytecode->name, "fstore_1");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_45_FSTORE_2:
		strcpy(bytecode->name, "fstore_2");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_46_FSTORE_3:
		strcpy(bytecode->name, "fstore_3");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_47_DSTORE_0:
		strcpy(bytecode->name, "dstore_0");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_48_DSTORE_1:
		strcpy(bytecode->name, "dstore_1");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_49_DSTORE_2:
		strcpy(bytecode->name, "dstore_2");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4A_DSTORE_3:
		strcpy(bytecode->name, "dstore_3");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4B_ASTORE_0:
		strcpy(bytecode->name, "astore_0");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4C_ASTORE_1:
		strcpy(bytecode->name, "astore_1");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4D_ASTORE_2:
		strcpy(bytecode->name, "astore_2");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4E_ASTORE_3:
		strcpy(bytecode->name, "astore_3");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_4F_IASTORE:
		strcpy(bytecode->name, "iastore");
		bytecode->stack_input = 3;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_50_LASTORE:
		strcpy(bytecode->name, "lastore");
		bytecode->stack_input = 3;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_51_FASTORE:
		strcpy(bytecode->name, "fastore");
		bytecode->stack_input = 3;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_52_DASTORE:
		strcpy(bytecode->name, "dastore");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_53_AASTORE:
		strcpy(bytecode->name, "aastore");
		bytecode->size = 1;
		bytecode->stack_input = 3;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_54_BASTORE:
		strcpy(bytecode->name, "bastore");
		bytecode->stack_input = 3;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_55_CASTORE:
		strcpy(bytecode->name, "castore");
		bytecode->size = 1;
		bytecode->stack_input = 3;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_56_SASTORE:
		strcpy(bytecode->name, "sastore");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BYTECODE_57_POP:
		strcpy(bytecode->name, "pop");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case BYTECODE_58_POP2:
		strcpy(bytecode->name, "pop2");
		bytecode->stack_input = 2;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case BYTECODE_59_DUP:
		strcpy(bytecode->name, "dup");
		bytecode->stack_input = 1;
		bytecode->stack_output = 2;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5A_DUP_X1:
		strcpy(bytecode->name, "dup_x1");
		bytecode->stack_input = 2;
		bytecode->stack_output = 3;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5B_DUP_X2:
		strcpy(bytecode->name, "dup_x2");
		bytecode->stack_input = 3;
		bytecode->stack_output = 4;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5C_DUP2:
		strcpy(bytecode->name, "dup2");
		bytecode->stack_input = 2;
		bytecode->stack_output = 4;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5D_DUP2_X1:
		strcpy(bytecode->name, "dup2_x1");
		bytecode->stack_input = 3;
		bytecode->stack_output = 5;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5E_DUP2_X2:
		strcpy(bytecode->name, "dup2_x2");
		bytecode->stack_input = 4;
		bytecode->stack_output = 6;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_5F_SWAP:
		strcpy(bytecode->name, "swap");
		bytecode->size = 1;
		bytecode->stack_input = 2;
		bytecode->stack_output = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case BYTECODE_60_IADD:
		strcpy(bytecode->name, "iadd");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BYTECODE_61_LADD:
		strcpy(bytecode->name, "ladd");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BYTECODE_62_FADD:
		strcpy(bytecode->name, "fadd");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BYTECODE_63_DADD:
		strcpy(bytecode->name, "dadd");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BYTECODE_64_ISUB:
		strcpy(bytecode->name, "isub");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_65_LSUB:
		strcpy(bytecode->name, "lsub");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_66_FSUB:
		strcpy(bytecode->name, "fsub");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_67_DSUB:
		strcpy(bytecode->name, "dsub");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_68_IMUL:
		strcpy(bytecode->name, "imul");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case BYTECODE_69_LMUL:
		strcpy(bytecode->name, "lmul");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case BYTECODE_6A_FMUL:
		strcpy(bytecode->name, "fmul");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case BYTECODE_6B_DMUL:
		strcpy(bytecode->name, "dmul");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case BYTECODE_6C_IDIV:
		strcpy(bytecode->name, "idiv");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case BYTECODE_6D_LDIV:
		strcpy(bytecode->name, "ldiv");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case BYTECODE_6E_FDIV:
		strcpy(bytecode->name, "fdiv");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case BYTECODE_6F_DDIV:
		strcpy(bytecode->name, "ddiv");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case BYTECODE_70_IREM:
		strcpy(bytecode->name, "irem");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case BYTECODE_71_LREM:
		strcpy(bytecode->name, "lrem");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case BYTECODE_72_FREM:
		strcpy(bytecode->name, "frem");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case BYTECODE_73_DREM:
		strcpy(bytecode->name, "drem");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case BYTECODE_74_INEG:
		strcpy(bytecode->name, "ineg");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_75_LNEG:
		strcpy(bytecode->name, "lneg");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_76_FNEG:
		strcpy(bytecode->name, "fneg");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_77_DNEG:
		strcpy(bytecode->name, "dneg");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BYTECODE_78_ISHL:
		strcpy(bytecode->name, "ishl");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case BYTECODE_79_LSHL:
		strcpy(bytecode->name, "lshl");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case BYTECODE_7A_ISHR:
		strcpy(bytecode->name, "ishr");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case BYTECODE_7B_LSHR:
		strcpy(bytecode->name, "lshr");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case BYTECODE_7C_IUSHR:
		strcpy(bytecode->name, "iushr");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case BYTECODE_7D_LUSHR:
		strcpy(bytecode->name, "lushr");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case BYTECODE_7E_IAND:
		strcpy(bytecode->name, "iand");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case BYTECODE_7F_LAND:
		strcpy(bytecode->name, "land");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case BYTECODE_80_IOR:
		strcpy(bytecode->name, "ior");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case BYTECODE_81_LOR:
		strcpy(bytecode->name, "lor");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case BYTECODE_82_IXOR:
		strcpy(bytecode->name, "ixor");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case BYTECODE_83_LXOR:
		strcpy(bytecode->name, "lxor");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case BYTECODE_84_IINC:
		strcpy(bytecode->name, "iinc");
		load_ut8x2(bytecode, jvm, BYTECODE_TYPE_NUMBER, BYTECODE_TYPE_NUMBER, ut32, ut32);
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BYTECODE_85_I2L:
		strcpy(bytecode->name, "i2l");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_86_I2F:
		strcpy(bytecode->name, "i2f");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_87_I2D:
		strcpy(bytecode->name, "i2d");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_88_L2I:
		strcpy(bytecode->name, "l2i");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_89_L2F:
		strcpy(bytecode->name, "l2f");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8A_L2D:
		strcpy(bytecode->name, "l2d");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8B_F2I:
		strcpy(bytecode->name, "f2i");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8C_F2L:
		strcpy(bytecode->name, "f2l");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8D_F2D:
		strcpy(bytecode->name, "f2d");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8E_D2I:
		strcpy(bytecode->name, "d2i");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_8F_D2L:
		strcpy(bytecode->name, "d2l");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_90_D2F:
		strcpy(bytecode->name, "d2f");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_91_I2B:
		strcpy(bytecode->name, "i2b");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_92_I2C:
		strcpy(bytecode->name, "i2c");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_93_I2S:
		strcpy(bytecode->name, "i2s");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case BYTECODE_94_LCMP:
		strcpy(bytecode->name, "lcmp");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_95_FCMPL:
		strcpy(bytecode->name, "fcmpl");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_96_FCMPG:
		strcpy(bytecode->name, "fcmpg");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_97_DCMPL:
		strcpy(bytecode->name, "dcmpl");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_98_DCMPG:
		strcpy(bytecode->name, "dcmpg");
		bytecode->stack_input = 2;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_99_IFEQ:
		strcpy(bytecode->name, "ifeq");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9A_IFNE:
		strcpy(bytecode->name, "ifne");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9B_IFLT:
		strcpy(bytecode->name, "iflt");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9C_IFGE:
		strcpy(bytecode->name, "ifge");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9D_IFGT:
		strcpy(bytecode->name, "ifgt");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9E_IFLE:
		strcpy(bytecode->name, "ifle");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_9F_IF_ICMPEQ:
		strcpy(bytecode->name, "if_icmpeq");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A0_IF_ICMPNE:
		strcpy(bytecode->name, "if_icmpne");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A1_IF_ICMPLT:
		strcpy(bytecode->name, "if_icmplt");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A2_IF_ICMPGE:
		strcpy(bytecode->name, "if_icmpge");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A3_IF_ICMPGT:
		strcpy(bytecode->name, "if_icmpgt");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A4_IF_ICMPLE:
		strcpy(bytecode->name, "if_icmple");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A5_IF_ACMPEQ:
		strcpy(bytecode->name, "if_acmpeq");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A6_IF_ACMPNE:
		strcpy(bytecode->name, "if_acmpne");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case BYTECODE_A7_GOTO:
		strcpy(bytecode->name, "goto");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case BYTECODE_A8_JSR:
		strcpy(bytecode->name, "jsr");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->stack_output = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case BYTECODE_A9_RET:
		strcpy(bytecode->name, "ret");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_NUMBER, ut32);
		bytecode->size = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_AA_TABLESWITCH:
		strcpy(bytecode->name, "tableswitch");
		if (!decode_tableswitch(jvm, bytecode)) {
			rz_warn_if_reached();
			return false;
		}
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		bytecode->stack_input = 1;
		break;
	case BYTECODE_AB_LOOKUPSWITCH:
		strcpy(bytecode->name, "lookupswitch");
		if (!decode_lookupswitch(jvm, bytecode)) {
			rz_warn_if_reached();
			return false;
		}
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		bytecode->stack_input = 1;
		break;
	case BYTECODE_AC_IRETURN:
		strcpy(bytecode->name, "ireturn");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_AD_LRETURN:
		strcpy(bytecode->name, "lreturn");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_AE_FRETURN:
		strcpy(bytecode->name, "freturn");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_AF_DRETURN:
		strcpy(bytecode->name, "dreturn");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_B0_ARETURN:
		strcpy(bytecode->name, "areturn");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_B1_RETURN:
		strcpy(bytecode->name, "return");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case BYTECODE_B2_GETSTATIC:
		strcpy(bytecode->name, "getstatic");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_B3_PUTSTATIC:
		strcpy(bytecode->name, "putstatic");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case BYTECODE_B4_GETFIELD:
		strcpy(bytecode->name, "getfield");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case BYTECODE_B5_PUTFIELD:
		strcpy(bytecode->name, "putfield");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 2;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case BYTECODE_B6_INVOKEVIRTUAL:
		strcpy(bytecode->name, "invokevirtual");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case BYTECODE_B7_INVOKESPECIAL:
		strcpy(bytecode->name, "invokespecial");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case BYTECODE_B8_INVOKESTATIC:
		strcpy(bytecode->name, "invokestatic");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case BYTECODE_B9_INVOKEINTERFACE:
		strcpy(bytecode->name, "invokeinterface");
		load_ut16_ut8(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, BYTECODE_TYPE_NUMBER, ut32, ut32);
		bytecode->stack_input = 1;
		bytecode->size = 5; // not an error
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case BYTECODE_BA_INVOKEDYNAMIC:
		strcpy(bytecode->name, "invokedynamic");
		load_ut16_ut8(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, BYTECODE_TYPE_NUMBER, ut32, ut32);
		bytecode->size = 5; // not an error
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case BYTECODE_BB_NEW:
		strcpy(bytecode->name, "new");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_NEW;
		break;
	case BYTECODE_BC_NEWARRAY:
		/* bool 4, char 5, float 6, double 7, byte 8, short 9, int 10, long 11 */
		strcpy(bytecode->name, "newarray");
		load_ut8(bytecode, jvm, BYTECODE_TYPE_ATYPE, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_NEW;
		break;
	case BYTECODE_BD_ANEWARRAY:
		strcpy(bytecode->name, "anewarray");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_NEW;
		break;
	case BYTECODE_BE_ARRAYLENGTH:
		strcpy(bytecode->name, "arraylength");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_LENGTH;
		break;
	case BYTECODE_BF_ATHROW:
		strcpy(bytecode->name, "athrow");
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case BYTECODE_C0_CHECKCAST:
		strcpy(bytecode->name, "checkcast");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UCJMP;
		break;
	case BYTECODE_C1_INSTANCEOF:
		strcpy(bytecode->name, "instanceof");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case BYTECODE_C2_MONITORENTER:
		strcpy(bytecode->name, "monitorenter");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;
	case BYTECODE_C3_MONITOREXIT:
		strcpy(bytecode->name, "monitorexit");
		bytecode->stack_input = 1;
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;
	case BYTECODE_C4_WIDE:
		strcpy(bytecode->name, "wide");
		bytecode->size = 1;
		break;
	case BYTECODE_C5_MULTIANEWARRAY:
		strcpy(bytecode->name, "multianewarray");
		load_ut16_ut8(bytecode, jvm, BYTECODE_TYPE_CONST_POOL, BYTECODE_TYPE_NUMBER, ut32, ut32);
		bytecode->stack_input = 1;
		bytecode->stack_output = 1;
		break;
	case BYTECODE_C6_IFNULL:
		strcpy(bytecode->name, "ifnull");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		bytecode->stack_input = 1;
		break;
	case BYTECODE_C7_IFNONNULL:
		strcpy(bytecode->name, "ifnonnull");
		load_ut16(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st16);
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CJMP;
		bytecode->stack_input = 1;
		break;
	case BYTECODE_C8_GOTO_W:
		strcpy(bytecode->name, "goto_w");
		load_ut32(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case BYTECODE_C9_JSR_W:
		strcpy(bytecode->name, "jsr_w");
		load_ut32(bytecode, jvm, BYTECODE_TYPE_ADDRESS, st32);
		bytecode->stack_output = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case BYTECODE_CA_BREAKPOINT:
		strcpy(bytecode->name, "breakpoint");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case BYTECODE_FE_IMPDEP1:
		strcpy(bytecode->name, "impdep1");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case BYTECODE_FF_IMPDEP2:
		strcpy(bytecode->name, "impdep2");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	default:
		strcpy(bytecode->name, "illegal");
		bytecode->size = 1;
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_ILL;
		jvm->current++;
		return true;
	}
	if (!bytecode->atype) {
		bytecode->atype = RZ_ANALYSIS_OP_TYPE_UNK;
	}
	bytecode->opcode = byte;
	bytecode->pc = jvm->pc + jvm->current;
	jvm->current += bytecode->size;
	return true;
}

void bytecode_snprint(RzStrBuf *sb, Bytecode *bytecode) {
	rz_return_if_fail(sb && bytecode);
	ut64 address;
	if (bytecode->opcode == BYTECODE_AA_TABLESWITCH) {
		rz_return_if_fail(bytecode->extra);
		TableSwitch *ts = (TableSwitch *)bytecode->extra;

		address = bytecode->pc + ts->pc_default;
		rz_strbuf_setf(sb, "%s default: 0x%" PFMT64x, bytecode->name, address);
	} else if (bytecode->opcode == BYTECODE_AB_LOOKUPSWITCH) {
		rz_return_if_fail(bytecode->extra);
		LookupSwitch *ls = (LookupSwitch *)bytecode->extra;

		address = bytecode->pc + ls->pc_default;
		rz_strbuf_setf(sb, "%s default: 0x%" PFMT64x, bytecode->name, address);
	} else if (bytecode->type[0] > 0 && !bytecode->type[1]) {
		if (bytecode->type[0] == BYTECODE_TYPE_NUMBER) {
			rz_strbuf_setf(sb, "%s %d", bytecode->name, bytecode->args[0]);
		} else if (bytecode->type[0] == BYTECODE_TYPE_CONST_POOL) {
			rz_strbuf_setf(sb, "%s " JAVA_ASM_CONSTANT_POOL_STR "%u", bytecode->name, bytecode->args[0]);
		} else if (bytecode->type[0] == BYTECODE_TYPE_ADDRESS) {
			address = bytecode->pc + bytecode->args[0];
			rz_strbuf_setf(sb, "%s 0x%" PFMT64x, bytecode->name, address);
		} else if (bytecode->type[0] == BYTECODE_TYPE_ATYPE) {
			const char *type = NULL;
			switch (bytecode->args[0]) {
			case 4:
				type = "bool";
				break;
			case 5:
				type = "char";
				break;
			case 6:
				type = "float";
				break;
			case 7:
				type = "double";
				break;
			case 8:
				type = "byte";
				break;
			case 9:
				type = "short";
				break;
			case 10:
				type = "int";
				break;
			case 11:
				type = "long";
				break;
			default:
				break;
			}
			if (type) {
				rz_strbuf_setf(sb, "%s %s", bytecode->name, type);
			} else {
				rz_strbuf_setf(sb, "%s unknown_type_%u", bytecode->name, bytecode->args[0]);
			}
		} else {
			rz_strbuf_setf(sb, "%s %u", bytecode->name, bytecode->args[0]);
			rz_warn_if_reached();
		}
	} else if (bytecode->type[0] > 0 && bytecode->type[1] > 0) {
		if (bytecode->type[0] == BYTECODE_TYPE_NUMBER &&
			bytecode->type[1] == BYTECODE_TYPE_NUMBER) {
			rz_strbuf_setf(sb, "%s %d %d", bytecode->name, bytecode->args[0], bytecode->args[1]);
		} else if (bytecode->type[0] == BYTECODE_TYPE_CONST_POOL &&
			bytecode->type[1] == BYTECODE_TYPE_NUMBER) {
			rz_strbuf_setf(sb, "%s " JAVA_ASM_CONSTANT_POOL_STR "%u %d", bytecode->name, bytecode->args[0], bytecode->args[1]);
		} else {
			rz_strbuf_setf(sb, "%s %d %d", bytecode->name, bytecode->args[0], bytecode->args[1]);
			rz_warn_if_reached();
		}
	} else {
		rz_strbuf_setf(sb, "%s", bytecode->name);
	}
}

void bytecode_clean(Bytecode *bytecode) {
	rz_return_if_fail(bytecode);
	free(bytecode->extra);
}

bool jvm_init(JavaVM *jvm, const ut8 *buffer, const ut32 size, ut64 pc, ut64 section) {
	rz_return_val_if_fail(jvm && buffer && size > 0, false);

	jvm->buffer = buffer;
	jvm->size = size;
	jvm->current = 0;
	jvm->pc = pc;
	jvm->section = section;

	return true;
}

bool jvm_fetch(JavaVM *jvm, Bytecode *bytecode) {
	rz_return_val_if_fail(jvm && bytecode, false);

	return decode_instruction(jvm, bytecode);
}
