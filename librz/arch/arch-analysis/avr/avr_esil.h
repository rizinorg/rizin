// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_AVR_ESIL_H
#define RZ_AVR_ESIL_H
#include <rz_analysis.h>

RZ_IPI int rz_avr_esil_init(RzAnalysisEsil *esil);
RZ_IPI int rz_avr_esil_fini(RzAnalysisEsil *esil);
RZ_IPI void rz_avr_esil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len);

#endif /* RZ_AVR_ESIL_H */