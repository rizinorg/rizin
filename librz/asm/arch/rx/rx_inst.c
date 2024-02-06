#include "rx_inst.h"

#define AssignOpVar(vid, field, expr) { \
    switch (vid){                \
    case 0: inst->v0.field = (expr); break; \
    case 1: inst->v1.field = (expr); break; \
    default: inst->v2.field = (expr); break; }}

static inline ut64 getbits(ut64 bytes, ut8 s, ut8 l) {
    return (bytes >> (64 - s - l)) & ((1ULL << l) - 1);
}

bool match_code(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.inst.tk_len;
    ut64 bits = getbits(bytes, s, l);
    if (bits == token->tk.inst.detail) {
        *bits_read += l;
        return true;
    }

    return false;
}

RxOpExtMark bits2mark(ut64 bits) {
    // 00 - B, 01 - W, 10 - L, 11 - UW
    return RX_EXT_B + bits;
}

bool match_mi(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.mi.tk_len;
    inst->v0.v.reg.memex = bits2mark(getbits(bytes, s, l));
    inst->v0.kind = RX_OPERAND_REG;
    *bits_read += l;
    return true;
}

ut8 bits2dsplen(ut64 bits) {
    // 11 - None, 00 - None
    // 01 - dsp: 8, 10 - dsp: 16
    switch (bits) {
        case 0:
        case 3:
            return 0xff;
        case 1:
            return 8;
        case 2:
            return 16;
        default:
            rz_warn_if_reached();
            return 0;
    }
}

bool match_ld(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.ld.tk_len;
    AssignOpVar(token->tk.ld.vid, v.reg.dsp_width, bits2dsplen(getbits(bytes, s, l)));
    *bits_read += l;
    return true;
}

bool match_ldr(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.ldr.tk_len;
    ut8 ldr = getbits(bytes, s, l);
    ut8 dsp_width;
    // 00 - None, 01 - dsp:8, 10 - dsp:16, 11 - invalid
    switch (ldr) {
        case 0:
            dsp_width = 0xff;
            break;
        case 1:
            dsp_width = 8;
            break;
        case 2:
            dsp_width = 16;
            break;
        case 3:
            return false;
        default:
            rz_warn_if_reached();
            return false;
    }

    AssignOpVar(token->tk.ldr.vid, v.reg.dsp_width, dsp_width);
    *bits_read += l;
    return true;
}

ut8 bits2immlen(ut64 bits) {
    // 00 - SIMM: 8, 01 - SIMM: 16
    // 02 - SIMM: 24, 03 - IMM: 32
    return (bits + 1) * 8;
}

bool match_li(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.li.tk_len;
    AssignOpVar(token->tk.li.vid, imm_width, bits2immlen(getbits(bytes, s, l)));
    *bits_read += l;
    return true;
}

RxReg bits2reg(ut64 bits) {
    return RX_REG_R0 + bits;
}

bool match_reg(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes, ut8 operand_cnt) {
    ut8 s = *bits_read;
    ut8 l = token->tk.reg.tk_len;
    AssignOpVar(operand_cnt, v.reg.reg, bits2reg(getbits(bytes, s, l)));
    AssignOpVar(operand_cnt, kind, RX_OPERAND_REG);
    *bits_read += l;
    return true;
}

bool match_cr(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes, ut8 operand_cnt) {
    ut8 s = *bits_read;
    ut8 l = token->tk.reg.tk_len;
    AssignOpVar(operand_cnt, v.reg.reg, rx_cr_map[(getbits(bytes, s, l))]);
    AssignOpVar(operand_cnt, kind, RX_OPERAND_REG);
    *bits_read += l;
    return true;
}

bool match_imm(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes, ut8 operand_cnt) {
    ut8 s = *bits_read;
    ut8 l = token->tk.imm.tk_len;
    AssignOpVar(operand_cnt, v.imm.imm, getbits(bytes, s, l));
    *bits_read += l;
    return true;
}

bool match_cond(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.cond.tk_len;
    inst->v0.v.cond.cond = RX_COND_BEQ + getbits(bytes, s, l);
    inst->v0.v.cond.pc_dsp_len = token->tk.cond.pcdsp;
    inst->v0.kind = RX_OPERAND_COND;
    *bits_read += l;
    return true;
}

bool match_dsp(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    // TODO add cond disp
    // TODO dsp may be split to two part
}

bool match_sz(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.sz.tk_len;
    ut8 sz = getbits(bytes, s, l);
    inst->sz_mark = sz == 2 ? RX_EXT_L : RX_EXT_B + sz;
    *bits_read += l;
    return true;
}

bool match_ad(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.ad.tk_len;
    ut8 addr_bits = getbits(bytes, s, l);

    // 00 Rs, [Rd+], 01: Rs, [-Rd], inc/dec on Rd
    // 10 [Rs+], Rd, 11: [-Rs], Rd, inc/dec on Rs
    switch (addr_bits) {
        case 0:
            inst->v1.v.reg.as_indirect = true;
            inst->v1.v.reg.fix_mode = RX_FIXOP_POST_INC;
            break;
        case 1:
            inst->v1.v.reg.as_indirect = true;
            inst->v1.v.reg.fix_mode = RX_FIXOP_PRE_DEC;
            break;
        case 2:
            inst->v0.v.reg.as_indirect = true;
            inst->v0.v.reg.fix_mode = RX_FIXOP_POST_INC;
            break;
        case 3:
            inst->v0.v.reg.as_indirect = true;
            inst->v0.v.reg.as_indirect = RX_FIXOP_PRE_DEC;
            break;
        default:
            rz_warn_if_reached();
            return false;
    }

    *bits_read += l;
    return true;
}

bool match_cb(RZ_OUT RxInst *inst, RxToken *token, RZ_OUT ut8 *bits_read, ut64 bytes) {
    ut8 s = *bits_read;
    ut8 l = token->tk.cb.tk_len;
    ut8 control_bits = getbits(bytes, s, l);

    inst->v0.v.flag = control_bits;
    inst->v0.kind = RX_OPERAND_FLAG;

    *bits_read += l;
    return true;
}

bool rx_try_match_and_parse(RZ_OUT RxInst *inst, RxDesc *desc, size_t RZ_OUT *bytes_read, ut64 bytes) {
    /**
     * psuedo code
     * bytes = read_4
     * if fail, read remain bytes or finish
     *
     * s = 0
     * for tk in tks
     *  tk_bits = get_bits(bytes, s, tk.len)
     *  switch tk.type
     *      case code
     *          match if tk_bits = code.detail, s += tk.len
     *          else return 0 show fail match
     *      case mi
     *          memex = tk_bits
     *          s += tk.len
     *
     *
     *
     */
}
