#include "pic_il.h"
#include "../../../arm/arch/pic/pic_midrange.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// HELPER DEFINES & TYPEDEFS

typedef RzILOpEffect *(PicILUplifter)(ut16 instr);
#define IL_LIFTER(op) pic_##op_il_lifter(PicMidrangeOpArgs opargs, ut16 instr)

// REGISTER DECLARATIONS & DEFINITIONS
#include "pic16f_memmaps/memmaps.h"
#define GET_WREG() VARG("W")

// fields inside status register
const char *pic_midrange_status_flags[] = {
	"IRP", "RP1", "RP0", "TO", "PD", "Z", "DC", "C"
};

// clang-format off
PicILUplifter pic_midrange_il_uplifters[] = {
    [PIC_MIDRANGE_OPCODE_NOP]             = IL_LIFTER(NOP),
    [PIC_MIDRANGE_OPCODE_RETURN]          = IL_LIFTER(RETURN),
    [PIC_MIDRANGE_OPCODE_RETFIE]          = IL_LIFTER(RETFIE),
    [PIC_MIDRANGE_OPCODE_OPTION]          = IL_LIFTER(OPTION),
    [PIC_MIDRANGE_OPCODE_SLEEP]           = IL_LIFTER(SLEEP),
    [PIC_MIDRANGE_OPCODE_CLRWDT]          = IL_LIFTER(CLRWDT),
    [PIC_MIDRANGE_OPCODE_TRIS]            = IL_LIFTER(TRIS),
    [PIC_MIDRANGE_OPCODE_MOVWF]           = IL_LIFTER(MOVWF),
    [PIC_MIDRANGE_OPCODE_CLR]             = IL_LIFTER(CLR),
    [PIC_MIDRANGE_OPCODE_SUBWF]           = IL_LIFTER(SUBWF),
    [PIC_MIDRANGE_OPCODE_DECF]            = IL_LIFTER(DECF),
    [PIC_MIDRANGE_OPCODE_IORWF]           = IL_LIFTER(IORWF),
    [PIC_MIDRANGE_OPCODE_ANDWF]           = IL_LIFTER(ANDWF),
    [PIC_MIDRANGE_OPCODE_XORWF]           = IL_LIFTER(XORWF),
    [PIC_MIDRANGE_OPCODE_ADDWF]           = IL_LIFTER(ADDWF),
    [PIC_MIDRANGE_OPCODE_MOVF]            = IL_LIFTER(MOVF),
    [PIC_MIDRANGE_OPCODE_COMF]            = IL_LIFTER(COMF),
    [PIC_MIDRANGE_OPCODE_INCF]            = IL_LIFTER(INCF),
    [PIC_MIDRANGE_OPCODE_DECFSZ]          = IL_LIFTER(DECFSZ),
    [PIC_MIDRANGE_OPCODE_RRF]             = IL_LIFTER(RRF),
    [PIC_MIDRANGE_OPCODE_RLF]             = IL_LIFTER(RLF),
    [PIC_MIDRANGE_OPCODE_SWAPF]           = IL_LIFTER(SWAPF),
    [PIC_MIDRANGE_OPCODE_INCFSZ]          = IL_LIFTER(INCFSZ),
    [PIC_MIDRANGE_OPCODE_BCF]             = IL_LIFTER(BCF),
    [PIC_MIDRANGE_OPCODE_BSF]             = IL_LIFTER(BSF),
    [PIC_MIDRANGE_OPCODE_BTFSC]           = IL_LIFTER(BTFSC),
    [PIC_MIDRANGE_OPCODE_BTFSS]           = IL_LIFTER(BTFSS),
    [PIC_MIDRANGE_OPCODE_CALL]            = IL_LIFTER(CALL),
    [PIC_MIDRANGE_OPCODE_GOTO]            = IL_LIFTER(GOTO),
    [PIC_MIDRANGE_OPCODE_MOVLW]           = IL_LIFTER(MOVLW),
    [PIC_MIDRANGE_OPCODE_RETLW]           = IL_LIFTER(RETLW),
    [PIC_MIDRANGE_OPCODE_IORLW]           = IL_LIFTER(IORLW),
    [PIC_MIDRANGE_OPCODE_ANDLW]           = IL_LIFTER(ANDLW),
    [PIC_MIDRANGE_OPCODE_XORLW]           = IL_LIFTER(XORLW),
    [PIC_MIDRANGE_OPCODE_SUBLW]           = IL_LIFTER(SUBLW),
    [PIC_MIDRANGE_OPCODE_ADDLW]           = IL_LIFTER(ADDLW),
    [PIC_MIDRANGE_OPCODE_RESET]           = IL_LIFTER(RESET),
    [PIC_MIDRANGE_OPCODE_CALLW]           = IL_LIFTER(CALLW),
    [PIC_MIDRANGE_OPCODE_BRW]             = IL_LIFTER(BRW),
    [PIC_MIDRANGE_OPCODE_MOVIW_1]         = IL_LIFTER(MOVIW_1),
    [PIC_MIDRANGE_OPCODE_MOVWI_1]         = IL_LIFTER(MOVWI_1),
    [PIC_MIDRANGE_OPCODE_MOVLB]           = IL_LIFTER(MOVLB),
    [PIC_MIDRANGE_OPCODE_LSLF]            = IL_LIFTER(LSLF),
    [PIC_MIDRANGE_OPCODE_LSRF]            = IL_LIFTER(LSRF),
    [PIC_MIDRANGE_OPCODE_ASRF]            = IL_LIFTER(ASRF),
    [PIC_MIDRANGE_OPCODE_SUBWFB]          = IL_LIFTER(SUBWFB),
    [PIC_MIDRANGE_OPCODE_ADDWFC]          = IL_LIFTER(ADDWFC),
    [PIC_MIDRANGE_OPCODE_ADDFSR]          = IL_LIFTER(ADDFSR),
    [PIC_MIDRANGE_OPCODE_MOVLP]           = IL_LIFTER(MOVLP),
    [PIC_MIDRANGE_OPCODE_BRA]             = IL_LIFTER(BRA),
    [PIC_MIDRANGE_OPCODE_MOVIW_2]         = IL_LIFTER(MOVIW_2),
    [PIC_MIDRANGE_OPCODE_MOVWI_2]         = IL_LIFTER(MOVWI_2),
    [PIC_MIDRANGE_OPCODE_INVALID]         = NULL
};
// clang-format on

/**
 * NOP
 * Operation: No Operation.
 * Operands: NONE
 * Status affected : NONE
 * */
IL_LIFTER(NOP) {
	NOP();
}

IL_LIFTER(RETURN) {}
IL_LIFTER(RETFIE) {}
IL_LIFTER(OPTION) {}
IL_LIFTER(SLEEP) {}
IL_LIFTER(CLRWDT) {}
IL_LIFTER(TRIS) {}
IL_LIFTER(MOVWF) {}
IL_LIFTER(CLR) {}
IL_LIFTER(SUBWF) {}
IL_LIFTER(DECF) {}
IL_LIFTER(IORWF) {}
IL_LIFTER(ANDWF) {}
IL_LIFTER(XORWF) {}
IL_LIFTER(ADDWF) {}
IL_LIFTER(MOVF) {}
IL_LIFTER(COMF) {}
IL_LIFTER(INCF) {}
IL_LIFTER(DECFSZ) {}
IL_LIFTER(RRF) {}
IL_LIFTER(RLF) {}
IL_LIFTER(SWAPF) {}
IL_LIFTER(INCFSZ) {}
IL_LIFTER(BCF) {}
IL_LIFTER(BSF) {}
IL_LIFTER(BTFSC) {}
IL_LIFTER(BTFSS) {}
IL_LIFTER(CALL) {}
IL_LIFTER(GOTO) {}
IL_LIFTER(MOVLW) {}
IL_LIFTER(RETLW) {}
IL_LIFTER(IORLW) {}
IL_LIFTER(ANDLW) {}
IL_LIFTER(XORLW) {}
IL_LIFTER(SUBLW) {}

/**
 * ADDLW.
 * Operation: Add Literal To WREG
 * Operands: Literal (k)
 * Status affected : C, DC, Z
 * */
IL_LIFTER(ADDLW) {
	return ADD(GET_WREG(), U8(PIC_MIDRANGE_OP_ARGS_8K_GET_K(instr)));
}

IL_LIFTER(RESET) {}
IL_LIFTER(CALLW) {}
IL_LIFTER(BRW) {}
IL_LIFTER(MOVIW_1) {}
IL_LIFTER(MOVWI_1) {}
IL_LIFTER(MOVLB) {}
IL_LIFTER(LSLF) {}
IL_LIFTER(LSRF) {}
IL_LIFTER(ASRF) {}
IL_LIFTER(SUBWFB) {}
IL_LIFTER(ADDWFC) {}
IL_LIFTER(ADDFSR) {}
IL_LIFTER(MOVLP) {}
IL_LIFTER(BRA) {}
IL_LIFTER(MOVIW_2) {}
IL_LIFTER(MOVWI_2) {}
IL_LIFTER(INVALID) {}

RZ_IPI RzILOpEffect *rz_pic16f_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, Pic16fDeviceType device_type, ut16 instr) {
	// get opcode
	PicMidrangeOpcode opcode = pic_midrange_get_opcode(instr);
	if (opcode == PIC_MIDRANGE_OPCODE_INVALID) {
		return NULL;
	}

	// get opargs
	PicMidrangeOpArgs opargs = pic_midrange_get_opargs(instr);

	// uplift
	PicILUplifter uplifter = pic_midrange_il_uplifters[opcode];
	if (uplifter) {
		return uplifter(opargs, instr);
	}

	// return NULL on failure
	return NULL;
}

/**
 * \brief Returns IL VM config for given PIC16F device type.
 *
 * \param analysis \c RzAnalysis instance.
 * \param device_type Device type in PIC16F family.
 *
 * \return valid ptr to RzAnalysisILConfig on success, NULL otherwise.
 * */
RZ_IPI RzAnalysisILConfig *rz_pic16f_il_vm_config(RZ_NONNULL RzAnalysis *analysis, Pic16fDeviceType device_type) {
}
