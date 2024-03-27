// SPDX-FileCopyrightText: 2023 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LPGL-3.0-only

#include "msp430_il.h"


// ``The 16-bit program counter (PC/R0) points to the next instruction to be executed.``
//      -- userguide, p. 44
#define PC_SIZE 16
// ``The low byte of a word is always an even address. The high byte is at the next odd address. 
//   For example, if a data word is located at address xxx4h, then the low byte of that data word 
//   is located at address xxx4h, and the high byte of that word is located at address xxx5h.``
//      -- userguide, p. 26
#define IS_BIG_ENDIAN false
// implied by the width of the PC and other registers (which are used as pointers in the relevant addressing modes)
#define MEM_ADDR_SIZE 16U

#include "rz_il_opbuilder_begin.h"

#define MSP430_GETR(r) VARG(msp430_register_names[r])
#define MSP430_SETR(r,v) SETG(msp430_register_names[r],v)

typedef struct {
    RzILOpBitVector *first;
    RzILOpBitVector *second;
} BVPair;

RzILOpEffect *rz_msp430_dummy() {
	return NOP(); 
}

RzILOpPure *get_destination(const Msp430Instruction *op) {
    switch (op->dst_mode) {
        case REG: {
            RzILOpBitVector *reg = MSP430_GETR(op->dst);
            if (op->word_sized & WORD_SIZED_READ) {
                return reg;
            }
            return CAST(8, NULL, reg);
        } 
        default: return U16(0); // TODO : other addressing modes
    }
}

BVPair get_destination_destructured(const Msp430Instruction *op) {
    switch (op->dst_mode) {
        case REG: {
            RzILOpBitVector *reg = MSP430_GETR(op->dst);
            BVPair res = {
                .first = CAST(8, NULL, reg),
                .second = CAST(8, NULL, SHIFTR(IL_FALSE, reg, UN8(8)))
            };
            return res;
        }
        default: {
            BVPair dummy = {.first = U8(0), .second = U8(0)}; 
            return dummy; // TODO : other addressing modes
        }
    }
}

RzILOpEffect *set_destination(const Msp430Instruction *op, RzILOpBitVector *old_value, RzILOpBitVector *new_value) {
    switch (op->dst_mode) {
        case REG: {
            if (op->word_sized & WORD_SIZED_WRITE) {
                return MSP430_SETR(op->dst, new_value);
            }
            // the general idea is: First we zero the lower byte through ANDing with 0xFF00
            //                      Then we assign the lower byte to the (byte-length) result through ORing with 0x00<result>
            // the overall effect is that only the lower byte is assigned, which is what byte-sized operations do
            return MSP430_SETR(op->dst, OR(AND(old_value, U16(0xFF00)), UNSIGNED(16, new_value)));
        } 
        default: return U16(0); // TODO : other addressing modes
    }
}

RzILOpBitVector *update_sr_nz_flags(const RzILOpBitVector *new_value, const RzILOpBitVector *old_sr_value) {
    // the general idea is that we zero out the N and Z bits in the old SR value 
    // (by ANDing with a mask of all 1s except in those positions)
    // and then we OR that resulting value with the new bits in the relevant positions and all 0s everywhere else

    // index of the N flag in the SR register: 2
    RzILOpBool *n_flag_value = MSB(new_value);
    RzILOpBitVector *n_or_mask = SHIFTL(IL_FALSE, UNSIGNED(16, n_flag_value), UN8(2));
    
    // index of the Z flag in the SR register: 1
    RzILOpBool *z_flag_value = IS_ZERO(new_value);
    RzILOpBitVector *z_or_mask = SHIFTL(IL_FALSE, UNSIGNED(16, z_flag_value), UN8(1));
    
    RzILOpBitVector *and_mask = UN16(~(1 << 2 | 1 << 1));
    RzILOpBitVector *or_mask = OR(n_or_mask, z_or_mask);
    
    return OR(AND(old_sr_value, and_mask), or_mask);
}

RzILOpBitVector *update_sr_v_flag_rcc(const RzILOpBitVector *old_value, const RzILOpBool *old_carry, const RzILOpBitVector *old_sr_value) {
    // the idea is the same as set_nz_flags_from_result(...): we AND with a mask that zeroes out the bit we care about
    // then we OR with a mask that have the bit we care about in the same position that we zeroed
    RzILOpBool *v_flag_value = AND(
        INV(MSB(old_value)),
        old_carry
    );

    return OR(
        AND(old_sr_value, UN16(1 << 8)), // zero out position 8, leave all else the same
        SHIFTL(IL_FALSE, UNSIGNED(16, v_flag_value), UN8(8)) // OR with the new value for the bit 
    ); 
}

RzILOpBitVector *update_sr_c_flag(const RzILOpBool *new_carry, const RzILOpBitVector *old_sr_value) {
    return MSP430_SETR(MSP430_SR, OR(
        AND(old_sr_value, UN16(1)), // zero out the 0th position (i.e. the carry bit)
        UNSIGNED(16, new_carry)    // OR with the new carry 
    ));
}

RzILOpEffect *rz_msp430_lift_single_operand_instr(RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op) {
	switch (op->iopcode) {
    // rotation is just a shift with filling
    case MSP430_RRC: {
        // 1- get the carry (to use later as the filling for the MSB of the operand)
        RzILOpBitVector *sr = MSP430_GETR(MSP430_SR);
        RzILOpBool *carry = LSB(sr);
        // 2- get LSB of the operand (register, memory location, ...)
        RzILOpBitVector *operand = get_destination(op);
        RzILOpBool *lsb = LSB(operand);
        // 3- Perform the Rotate Right through Carry operation: 
        //      a- Shift the operand by 1 to the right and fill with carry
        RzILOpBitVector *result = SHIFTR(carry, operand, U8(1));
        
        // ...  b- and set the operand to the value of the previous computation 
        RzILOpEffect *set_operand = set_destination(op, operand, result);
        // ...  c- and finally set the flags: NZ as usual, v espeically for RCC, and the carry flag from the discarded LSB
        RzILOpBitVector *sr_1 = update_sr_nz_flags(result, sr);
        RzILOpBitVector *sr_2 = update_sr_v_flag_rcc(operand, carry, sr_1);
        RzILOpBitVector *sr_new = update_sr_c_flag(lsb, sr_2);

        return SEQ2(set_operand, MSP430_SETR(MSP430_SR,sr_new));
    }

    case MSP430_SWPB: {
        // 1- get lower byte and upper byte of the operand
        BVPair low_high = get_destination_destructured(op);
        RzILOpBitVector *low_byte = low_high.first;
        RzILOpBitVector *high_byte = low_high.second;

        // 2- append them in reverse order
        RzILOpBitVector *result = APPEND(low_byte, high_byte);

        // 3- set them (flags aren't affected)
        return set_destination(op, NULL, result);
    }

    case MSP430_SXT: {
        return set_destination(op, NULL, SIGNED(16, get_destination(op)));
    }
    // TODO add the rest of instructions
    default:
        rz_warn_if_reached();
        return rz_msp430_dummy();
    }
}

RzILOpEffect *rz_msp430_lift_double_operand_instr(RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op) {
	return NOP(); // TODO
}

RzILOpEffect *rz_msp430_lift_jump_instr(RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op) {
	return NOP(); // TODO
}

RZ_IPI RzILOpEffect *rz_msp430_lift_instr(RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op) {
	switch (op->itype) {
    case MSP430_ONEOP: {
        return rz_msp430_lift_single_operand_instr(analysis, op);
    }
    case MSP430_TWOOP: {
        return rz_msp430_lift_double_operand_instr(analysis, op);
    }
    case MSP430_JUMP: {
        return rz_msp430_lift_jump_instr(analysis, op);
    }

    // should never happen, op can't be an invalid instruction
    default:
        rz_warn_if_reached();
        return rz_msp430_dummy();
    }
}

RZ_IPI RzAnalysisILConfig *rz_msp430_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

    RzAnalysisILConfig *ilconf = rz_analysis_il_config_new(PC_SIZE, IS_BIG_ENDIAN, MEM_ADDR_SIZE);
    
    ilconf->reg_bindings = msp430_register_names;

    return ilconf;
}
