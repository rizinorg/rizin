// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

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
			rz_strbuf_appendf(buf, " #0x%" PFMT32x, opr->v.cond.pc_dsp_val);
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
			rz_strbuf_appendf(buf, "%s,%s",
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
	if (inst->op == RX_OP_INVALID) {
		return false;
	}

	RzStrBuf opr0_buf, opr1_buf, opr2_buf;
	rz_strbuf_init(&opr0_buf);
	rz_strbuf_init(&opr1_buf);
	rz_strbuf_init(&opr2_buf);

	bool has_opr0 = inst->v0.kind != RX_OPERAND_NULL &&
		rx_operand_stringify(inst, &inst->v0, &opr0_buf);
	bool has_opr1 = inst->v1.kind != RX_OPERAND_NULL &&
		rx_operand_stringify(inst, &inst->v1, &opr1_buf);
	bool has_opr2 = inst->v2.kind != RX_OPERAND_NULL &&
		rx_operand_stringify(inst, &inst->v2, &opr2_buf);

	if (inst->op == RX_OP_BCND_W || inst->op == RX_OP_BCND_B || inst->op == RX_OP_BCND_S ||
		inst->op == RX_OP_BMCND || inst->op == RX_OP_SCCOND) {
		if (has_opr0 && inst->v0.kind == RX_OPERAND_COND) {
			// build b[cnd]
			RzStrBuf cond_buf;
			rz_strbuf_init(&cond_buf);
			rz_strf(cond_buf.buf, "%s", RxNameCond(inst->v0.v.cond.cond));
			rz_strbuf_appendf(buf, RxNameOp(inst->op), cond_buf.buf);

			if (!inst->v0.v.cond.pc_dsp_len) {
				has_opr0 = false;
			}
		} else {
			rz_strbuf_appendf(buf, "%s[invalid]",
				RxNameOp(inst->op));
		}
	} else {
		rz_strbuf_appendf(buf, "%s", RxNameOp(inst->op));
	}

	if (inst->sz_mark != RX_EXT_NON) {
		rz_strbuf_appendf(buf, ".%s ", RxNameExt(inst->sz_mark));
	} else {
		rz_strbuf_appendf(buf, " ");
	}

	if (has_opr0) {
		rz_strbuf_appendf(buf, "%s, ", opr0_buf.buf);
	}
	if (has_opr1) {
		rz_strbuf_appendf(buf, "%s, ", opr1_buf.buf);
	}
	if (has_opr2) {
		rz_strbuf_appendf(buf, "%s", opr2_buf.buf);
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
RZ_API bool rx_dis(RxInst RZ_OUT *inst, st32 RZ_OUT *bytes_read, const ut8 *buf, size_t buf_len) {
	// rx instruction length vary from 1 to 8 Bytes
	ut64 prefetched_bytes = prefetch_bytes(buf, buf_len);
	RxInst current_inst = { 0 };
	st32 bytes_read_real = 0;
	for (ut32 desc_id = 0; desc_id < RX_DESC_SIZE; ++desc_id) {
		memset(&current_inst, 0, sizeof(RxInst));
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
