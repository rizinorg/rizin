#include "rx.h"
#include "rx_str.inc"

static ut64 prefetch_bytes(const ut8 *buf, size_t buf_len) {
	ut64 result = 0;
	size_t i;
	size_t end = buf_len < 8 ? buf_len : 8; // Determine end based on buf_len
	for (i = 0; i < end; i++) {
		result |= ((ut64)buf[i]) << ((7 - i) * 8); // Shift and combine
	}
	return result;
}

bool rx_operand_stringify(RxInst *inst, RxOperand *opr, RZ_OUT RzStrBuf *buf) {
	// construct string output to RzStrBuf
	if (opr->kind == RX_OPERAND_NULL) {
		// ignore
		return false;
	}

	if (opr->kind == RX_OPERAND_COND) {

		if (opr->v.cond.pc_dsp_len) {
			rz_strf(buf->buf, "%s #0x%" PFMT32x,
				RxNameCond(opr->v.cond.cond),
				opr->v.cond.pc_dsp_val);
		} else {
			rz_strf(buf->buf, "%s",
				RxNameCond(opr->v.cond.cond));
		}
		return true;
	}

	if (opr->kind == RX_OPERAND_FLAG) {
		rz_strf(buf->buf, "%s", RxNameFlag(opr->v.flag));
		return true;
	}

	if (opr->kind == RX_OPERAND_IMM) {
		rz_strf(buf->buf, "#IMM:%d(#0x%" PFMT32x ")",
			opr->v.imm.imm_width,
			opr->v.imm.imm);
		return true;
	}

	if (opr->kind == RX_OPERAND_REG) {
		if (opr->v.reg.dsp_width) {
			// dsp value
			rz_strbuf_appendf(buf, "dsp:%d(#0x%" PFMT32x ")",
				opr->v.reg.dsp_width,
				opr->v.reg.dsp_val);
		}

		if (opr->v.reg.as_indirect) {
			rz_strbuf_appendf(buf, "[");
		}
		if (opr->v.reg.fix_mode == RX_FIXOP_PRE_DEC) {
			rz_strbuf_appendf(buf, "-");
		}

		if (opr->v.reg.as_base) {
			rz_strbuf_appendf(buf, "%s, %s",
				RxNameReg(opr->v.reg.ri),
				RxNameReg(opr->v.reg.reg));
		} else {
			rz_strbuf_appendf(buf, "%s", RxNameReg(opr->v.reg.reg));
		}

		if (opr->v.reg.fix_mode == RX_FIXOP_POST_INC) {
			rz_strbuf_appendf(buf, "+");
		}
		if (opr->v.reg.as_indirect) {
			rz_strbuf_appendf(buf, "]");
		}

		if (opr->v.reg.memex != RX_EXT_NON) {
			rz_strbuf_appendf(buf, ".%s", RxNameExt(opr->v.reg.memex));
		}
	}

	return true;
}

bool rx_inst_stringify(RxInst *inst, RzStrBuf *buf) {
	// construct string output to RzStrBuf
	rz_return_val_if_fail(inst->op != RX_OP_INVALID, false);

	RzStrBuf opr0_buf, opr1_buf, opr2_buf;
	bool has_opr0 = inst->v0.kind != RX_OPERAND_NULL ||
		rx_operand_stringify(inst, &inst->v0, &opr0_buf);
	bool has_opr1 = inst->v1.kind != RX_OPERAND_NULL ||
		rx_operand_stringify(inst, &inst->v1, &opr1_buf);
	bool has_opr2 = inst->v2.kind != RX_OPERAND_NULL ||
		rx_operand_stringify(inst, &inst->v2, &opr2_buf);

	if (inst->sz_mark != RX_EXT_NON) {
		rz_strbuf_appendf(buf, "%s.%s ",
			RxNameOp(inst->op),
			RxNameExt(inst->sz_mark));
	} else {
		rz_strbuf_appendf(buf, "%s ",
			RxNameOp(inst->op));
	}

	if (has_opr0 && has_opr1 && has_opr2) {
		rz_strbuf_appendf(buf, "%s, %s, %s",
			opr0_buf.buf,
			opr1_buf.buf,
			opr2_buf.buf);
	} else if (has_opr0 && has_opr1) {
		rz_strbuf_appendf(buf, "%s, %s",
			opr0_buf.buf,
			opr1_buf.buf);
	} else if (has_opr0) {
		rz_strbuf_appendf(buf, "%s",
			opr0_buf.buf);
	} else {
		rz_strbuf_appendf(buf, "");
	}

	return true;
}

/**
 * Parse binary data to RxInst according to RxDesc
 * \param inst
 * \param bytes_read
 * \param buf
 * \param buf_len
 * \return
 */
bool rx_dis(RxInst RZ_OUT *inst, st32 RZ_OUT *bytes_read, const ut8 *buf, size_t buf_len) {
	// rx instruction length vary from 1 to 8 Bytes
	ut64 prefetched_bytes = prefetch_bytes(buf, buf_len);
	RxInst current_inst = { 0 };
	st32 bytes_read_real = 0;
	for (ut32 desc_id = 0; desc_id < RX_DESC_SIZE; ++desc_id) {
		bool is_valid = rx_try_match_and_parse(&current_inst, &rx_inst_descs[desc_id],
			&bytes_read_real, prefetched_bytes);
		if (is_valid) {
			*inst = current_inst;
			*bytes_read = bytes_read_real;
			return true;
		}
	}

	// nothing matched known instruction
	return false;
}
