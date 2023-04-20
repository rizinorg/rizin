// SPDX-FileCopyrightText: 2023 Siddharth Mishra <misra.cxx@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC_IL_H_
#define PIC_IL_H_

#include <rz_il.h>

// PIC16F family
typedef enum pic16f_device_type_t {
	PIC16F882,
	PIC16F883,
	PIC16F884,
	PIC16F886,
	PIC16F887
} Pic16fDeviceType;

RZ_IPI RzAnalysisILConfig *rz_pic16f_il_vm_config(RZ_NONNULL RzAnalysis *analysis, Pic16DeviceType device_type);
RZ_IPI RzILOpEffect *rz_pic16f_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, Pic16deviceType device_type, ut16 instr);

// baseline
/* RZ_IPI RzAnalysisILConfig *rz_pic_baseline_il_vm_config(RZ_NONNULL RzAnalysis *analysis); */
/* RZ_IPI RzILOpEffect *rz_pic_baseline_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, ut16 instr ; */

// TODO: Add support for PIC18F

#endif // PIC_IL_H_
