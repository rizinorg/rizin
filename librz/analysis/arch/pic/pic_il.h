// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC_IL_H_
#define PIC_IL_H_

#include <rz_il.h>

/**
 * PIC Mid-Range Device Type.
 * Since each device has it's own set of supported instructions
 * and memory map (# of banks, register arrangement etc...),
 * we'll support analysis of each of these devices differently!
 * */
typedef enum pic16f_device_type_t {
	PIC16F882,
	PIC16F883,
	PIC16F884,
	PIC16F886,
	PIC16F887,
	PIC_MIDRANGE_SUPPORTED_DEVICE_NUM
} PicMidrangeDeviceType;

/**
 * This struct will store the CPU state of a PIC Mid-Range
 * device while being uplifted.
 *
 * Register are indexed using a value between 0x00-0x7f and a selected bank.
 * Instructions are indexed using a page selector (PCLATH)
 * Hence we need to maintain a state of CPU while being analyzed.
 *
 * This opens possibilities of storing more useful data to improve the process.
 * */
typedef struct pic_midrange_cpu_state_t {
	PicMidrangeDeviceType device_type;
	ut8 selected_bank; ///< for register indexing.
	ut8 selected_page; ///< for instruction indexing.
} PicMidrangeCPUState;

RZ_IPI RZ_OWN PicMidrangeCPUState *rz_pic_midrange_new_cpu_state(PicMidrangeDeviceType device_type);
RZ_IPI RzAnalysisILConfig *rz_midrange_il_vm_config(RZ_NONNULL RzAnalysis *analysis, PicMidrangeDeviceType device_type);
RZ_IPI RzILOpEffect *rz_midrange_il_op(RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzAnalysisOp *op,
	RZ_NONNULL PicMidrangeCPUState *cpu_state,
	ut16 instr);

// baseline
/* RZ_IPI RzAnalysisILConfig *rz_pic_baseline_il_vm_config(RZ_NONNULL RzAnalysis *analysis); */
/* RZ_IPI RzILOpEffect *rz_pic_baseline_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, ut16 instr ; */

// TODO: Add support for PIC18F & other device families

#endif // PIC_IL_H_
