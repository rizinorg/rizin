// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <cil/cil_dis.h>

/**
 * Resolves InlineMethod token to paddr
 * \returns offset normally, UT64_MAX if fail
 */
static ut64 analyze_InlineMethod(RzAnalysis *analysis, CILOp *cilop) {
	RzBinGetOffset get_offset;
	RzBin *bin;

	if (!analysis ||
		!(bin = analysis->binb.bin) ||
		!(get_offset = analysis->binb.get_offset)) {
		return UT64_MAX;
	}

	ut32 tok = cilop->tok;
	ut32 table = tok >> 24;
	if (table == 0x06) { // MethodDef index
		return get_offset(bin, 'd', tok & 0xffffff);
	}

	return UT64_MAX;
}

static int cil_analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	CILOp cilop = { { { 0 } } };
	if (cil_dis(&cilop, buf, len)) {
		return 0;
	}
	rz_strbuf_fini(&cilop.strbuf);

	op->addr = addr;

	switch (cilop.byte1) {
	case CIL_OP_LDARG_0:
	case CIL_OP_LDARG_1:
	case CIL_OP_LDARG_2:
	case CIL_OP_LDARG_3:
	case CIL_OP_LDLOC_0:
	case CIL_OP_LDLOC_1:
	case CIL_OP_LDLOC_2:
	case CIL_OP_LDLOC_3:
	case CIL_OP_LDARG_S:
	case CIL_OP_LDARGA_S:
	case CIL_OP_LDLOC_S:
	case CIL_OP_LDLOCA_S:
	case CIL_OP_LDNULL:
	case CIL_OP_LDC_I4_M1:
	case CIL_OP_LDC_I4_0:
	case CIL_OP_LDC_I4_1:
	case CIL_OP_LDC_I4_2:
	case CIL_OP_LDC_I4_3:
	case CIL_OP_LDC_I4_4:
	case CIL_OP_LDC_I4_5:
	case CIL_OP_LDC_I4_6:
	case CIL_OP_LDC_I4_7:
	case CIL_OP_LDC_I4_8:
	case CIL_OP_LDC_I4_S:
	case CIL_OP_LDC_I4:
	case CIL_OP_LDC_I8:
	case CIL_OP_LDC_R4:
	case CIL_OP_LDC_R8:
	case CIL_OP_LDIND_I1:
	case CIL_OP_LDIND_U1:
	case CIL_OP_LDIND_I2:
	case CIL_OP_LDIND_U2:
	case CIL_OP_LDIND_I4:
	case CIL_OP_LDIND_U4:
	case CIL_OP_LDIND_I8:
	case CIL_OP_LDIND_I:
	case CIL_OP_LDIND_R4:
	case CIL_OP_LDIND_R8:
	case CIL_OP_LDIND_REF:
	case CIL_OP_LDOBJ:
	case CIL_OP_LDSTR:
	case CIL_OP_LDFLD:
	case CIL_OP_LDFLDA:
	case CIL_OP_LDSFLDA:
	case CIL_OP_LDLEN:
	case CIL_OP_LDELEMA:
	case CIL_OP_LDELEM_I1:
	case CIL_OP_LDELEM_U1:
	case CIL_OP_LDELEM_I2:
	case CIL_OP_LDELEM_U2:
	case CIL_OP_LDELEM_I4:
	case CIL_OP_LDELEM_U4:
	case CIL_OP_LDELEM_I8:
	case CIL_OP_LDELEM_I:
	case CIL_OP_LDELEM_R4:
	case CIL_OP_LDELEM_R8:
	case CIL_OP_LDELEM_REF:
	case CIL_OP_LDELEM:
	case CIL_OP_LDTOKEN:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case CIL_OP_STLOC_0:
	case CIL_OP_STLOC_1:
	case CIL_OP_STLOC_2:
	case CIL_OP_STLOC_3:
	case CIL_OP_STARG_S:
	case CIL_OP_STLOC_S:
	case CIL_OP_STIND_REF:
	case CIL_OP_STIND_I1:
	case CIL_OP_STIND_I2:
	case CIL_OP_STIND_I4:
	case CIL_OP_STIND_I8:
	case CIL_OP_STIND_R4:
	case CIL_OP_STIND_R8:
	case CIL_OP_STFLD:
	case CIL_OP_STSFLD:
	case CIL_OP_STOBJ:
	case CIL_OP_STELEM_I:
	case CIL_OP_STELEM_I1:
	case CIL_OP_STELEM_I2:
	case CIL_OP_STELEM_I4:
	case CIL_OP_STELEM_I8:
	case CIL_OP_STELEM_R4:
	case CIL_OP_STELEM_R8:
	case CIL_OP_STELEM_REF:
	case CIL_OP_STELEM:
	case CIL_OP_STIND_I:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case CIL_OP_ADD:
	case CIL_OP_ADD_OVF:
	case CIL_OP_ADD_OVF_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case CIL_OP_SUB:
	case CIL_OP_SUB_OVF:
	case CIL_OP_SUB_OVF_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case CIL_OP_MUL:
	case CIL_OP_MUL_OVF:
	case CIL_OP_MUL_OVF_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case CIL_OP_DIV:
	case CIL_OP_DIV_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case CIL_OP_REM:
	case CIL_OP_REM_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case CIL_OP_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case CIL_OP_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case CIL_OP_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case CIL_OP_SHL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case CIL_OP_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case CIL_OP_SHR_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case CIL_OP_NEG:
	case CIL_OP_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case CIL_OP_CONV_I1:
	case CIL_OP_CONV_I2:
	case CIL_OP_CONV_I4:
	case CIL_OP_CONV_I8:
	case CIL_OP_CONV_R4:
	case CIL_OP_CONV_R8:
	case CIL_OP_CONV_U4:
	case CIL_OP_CONV_U8:
	case CIL_OP_CONV_R_UN:
	case CIL_OP_CONV_OVF_I1_UN:
	case CIL_OP_CONV_OVF_I2_UN:
	case CIL_OP_CONV_OVF_I4_UN:
	case CIL_OP_CONV_OVF_I8_UN:
	case CIL_OP_CONV_OVF_U1_UN:
	case CIL_OP_CONV_OVF_U2_UN:
	case CIL_OP_CONV_OVF_U4_UN:
	case CIL_OP_CONV_OVF_U8_UN:
	case CIL_OP_CONV_OVF_I_UN:
	case CIL_OP_CONV_OVF_U_UN:
	case CIL_OP_CONV_OVF_I1:
	case CIL_OP_CONV_OVF_U1:
	case CIL_OP_CONV_OVF_I2:
	case CIL_OP_CONV_OVF_U2:
	case CIL_OP_CONV_OVF_I4:
	case CIL_OP_CONV_OVF_U4:
	case CIL_OP_CONV_OVF_I8:
	case CIL_OP_CONV_OVF_U8:
	case CIL_OP_CONV_U2:
	case CIL_OP_CONV_U1:
	case CIL_OP_CONV_I:
	case CIL_OP_CONV_OVF_I:
	case CIL_OP_CONV_OVF_U:
	case CIL_OP_CONV_U:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	// InlineMethod
	case CIL_OP_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = analyze_InlineMethod(analysis, &cilop);
		break;
	case CIL_OP_CALL:
	case CIL_OP_CALLI:
	case CIL_OP_CALLVIRT:
	case CIL_OP_NEWOBJ:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = analyze_InlineMethod(analysis, &cilop);
		break;
	// InlineBrTarget / ShortInlineBrTarget
	case CIL_OP_BR_S:
	case CIL_OP_BR:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + 2 + cilop.target;
		break;
	case CIL_OP_BRFALSE_S:
	case CIL_OP_BRTRUE_S:
	case CIL_OP_BEQ_S:
	case CIL_OP_BGE_S:
	case CIL_OP_BGT_S:
	case CIL_OP_BLE_S:
	case CIL_OP_BLT_S:
	case CIL_OP_BNE_UN_S:
	case CIL_OP_BGE_UN_S:
	case CIL_OP_BGT_UN_S:
	case CIL_OP_BLE_UN_S:
	case CIL_OP_BLT_UN_S:
	case CIL_OP_BRFALSE:
	case CIL_OP_BRTRUE:
	case CIL_OP_BEQ:
	case CIL_OP_BGE:
	case CIL_OP_BGT:
	case CIL_OP_BLE:
	case CIL_OP_BLT:
	case CIL_OP_BNE_UN:
	case CIL_OP_BGE_UN:
	case CIL_OP_BGT_UN:
	case CIL_OP_BLE_UN:
	case CIL_OP_BLT_UN:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 5 + cilop.target;
		break;
	case CIL_OP_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case CIL_OP_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case 0xFE:
		switch (cilop.byte2) {
		case CIL_OP2_CEQ:
		case CIL_OP2_CGT:
		case CIL_OP2_CGT_UN:
		case CIL_OP2_CLT:
		case CIL_OP2_CLT_UN:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		case CIL_OP2_LDFTN:
		case CIL_OP2_LDVIRTFTN:
		case CIL_OP2_LDARG:
		case CIL_OP2_LDARGA:
		case CIL_OP2_LDLOC:
		case CIL_OP2_LDLOCA:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case CIL_OP2_STARG:
		case CIL_OP2_STLOC:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		}
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
	}

	return op->size = cilop.size;
}

RzAnalysisPlugin rz_analysis_plugin_cil = {
	.name = "cil",
	.desc = ".NET Common Intermediate Language",
	.license = "LGPL3",
	.arch = "cil",
	.bits = 16 | 32 | 64,
	.op = &cil_analyze_op,
};
