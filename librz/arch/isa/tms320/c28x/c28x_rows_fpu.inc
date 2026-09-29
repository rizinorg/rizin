// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// TMS320C28x FPU32, FPU64, TMU and fast integer division rows, ordered by
// opcode, derived from TI's dis2000 (C2000 CGT 20.2.6.LTS) and checked against
// it on random encodings of every row. The trailing comment is the
// instruction's syntax line.
// clang-format off
	{ OP(0xff000000, 0xad000000), .mnem = "movst0", RZTYPE(MOV), .ops = { FFLAGS(16) } }, // MOVST0 flags
	{ OP(0xfff00000, 0xe0000000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), LOC32(0), FREG(8) } }, // MPYF32 RaH,RbH,RcH || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0100000), .mnem = "addf32", RZTYPE(ADD), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), LOC32(0), FREG(8) } }, // ADDF32 RaH,RbH,RcH || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0200000), .mnem = "subf32", RZTYPE(SUB), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), LOC32(0), FREG(8) } }, // SUBF32 RaH,RbH,RcH || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0400000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREG(8) } }, // MPYF64 Ra,Rb,Rc || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0500000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREG(8) } }, // ADDF64 Ra,Rb,Rc || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0600000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREG(8) } }, // SUBF64 Ra,Rb,Rc || MOV32 mem32,RdH
	{ OP(0xfff00000, 0xe0800000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREGL(8) } }, // MPYF64 Ra,Rb,Rc || MOV32 mem32,RdL
	{ OP(0xfff00000, 0xe0900000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREGL(8) } }, // ADDF64 Ra,Rb,Rc || MOV32 mem32,RdL
	{ OP(0xfff00000, 0xe0a00000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), LOC32(0), FREGL(8) } }, // SUBF64 Ra,Rb,Rc || MOV32 mem32,RdL
	{ OP(0xffff0000, 0xe2000000), .mnem = "mov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), REG(STF) } }, // MOV32 mem32,STF
	{ OP(0xffff0000, 0xe2020000), .mnem = "mov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), FREGL(8) } }, // MOV32 mem32,RaL
	{ OP(0xffff0000, 0xe2030000), .mnem = "mov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), FREG(8) } }, // MOV32 mem32,RaH
	// MOV32 between CPU and FPU registers is VMOV32 *(0:16bit) at the FPU
	// register's data address, 0x0f10 + 4n for RnL. dis2000 names offsets 1-3
	// of each group RnH; the assembler emits only offsets 0 and 2.
	{ OP(0xff00fff3, 0xbd000f10), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R0L), LOC32(16) } }, // MOV32 RaL,loc32
	{ OP(0xff00fff3, 0xbd000f20), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R4L), LOC32(16) } }, // MOV32 RaL,loc32
	{ OP(0xff00fff2, 0xbd000f12), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R0H), LOC32(16) } }, // MOV32 RaH,loc32
	{ OP(0xff00fff2, 0xbd000f22), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R4H), LOC32(16) } }, // MOV32 RaH,loc32
	{ OP(0xff00fff3, 0xbd000f11), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R0H), LOC32(16) } }, // MOV32 RaH,loc32
	{ OP(0xff00fff3, 0xbd000f21), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGM(C28X_REG_R4H), LOC32(16) } }, // MOV32 RaH,loc32
	{ OP(0xff00fff3, 0xbf000f10), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R0L) } }, // MOV32 loc32,RaL
	{ OP(0xff00fff3, 0xbf000f20), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R4L) } }, // MOV32 loc32,RaL
	{ OP(0xff00fff2, 0xbf000f12), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R0H) } }, // MOV32 loc32,RaH
	{ OP(0xff00fff2, 0xbf000f22), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R4H) } }, // MOV32 loc32,RaH
	{ OP(0xff00fff3, 0xbf000f11), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R0H) } }, // MOV32 loc32,RaH
	{ OP(0xff00fff3, 0xbf000f21), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), FREGM(C28X_REG_R4H) } }, // MOV32 loc32,RaH
	{ OP(0xfffff800, 0xe2130000), .mnem = "mov16", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), FREG(8) } }, // MOV16 mem32,RaH
	{ OP(0xfffff800, 0xe2210000), .mnem = "f32dtof64", RZTYPE(LOAD), .len = 4, .ops = { FREG64(8), LOC32(0) } }, // F32DTOF64 Ra,mem32
	{ OP(0xffff0000, 0xe2230000), .mnem = "movd32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // MOVD32 RaH,mem32
	{ OP(0xffff0000, 0xe2420000), .mnem = "movdd32", RZTYPE(LOAD), .len = 4, .ops = { FREGL(8), LOC32(0) } }, // MOVDD32 RaL,mem32
	{ OP(0xffff0000, 0xe2430000), .mnem = "movdd32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // MOVDD32 RaH,mem32
	{ OP(0xffff0000, 0xe2500000), .mnem = "macf32", RZTYPE(MUL), .len = 4, .ops = { FREG(8), FREG(11), LOC32(0), INDR(XAR_POSTINC, 7) } }, // MACF32 RaH,RbH,mem32,*XAR7++
	{ OP(0xffffffc0, 0xe2700000), .mnem = "mpy2pif32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // MPY2PIF32 RaH,RbH
	{ OP(0xffffffc0, 0xe2710000), .mnem = "div2pif32", RZTYPE(DIV), .len = 4, .ops = { FREG(0), FREG(3) } }, // DIV2PIF32 RaH,RbH
	{ OP(0xffffffc0, 0xe2720000), .mnem = "log2f32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // LOG2F32 RaH,RbH
	{ OP(0xffffffc0, 0xe2730000), .mnem = "iexp2f32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // IEXP2F32 RaH,RbH
	{ OP(0xfffffe00, 0xe2740000), .mnem = "divf32", RZTYPE(DIV), .len = 4, .ops = { FREG(0), FREG(3), FREG(6) } }, // DIVF32 RaH,RbH,RcH
	{ OP(0xffffffc0, 0xe2770000), .mnem = "sqrtf32", RZTYPE(DIV), .len = 4, .ops = { FREG(0), FREG(3) } }, // SQRTF32 RaH,RbH
	{ OP(0xffffffc0, 0xe2780000), .mnem = "sinpuf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // SINPUF32 RaH,RbH
	{ OP(0xffffffc0, 0xe2790000), .mnem = "cospuf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // COSPUF32 RaH,RbH
	{ OP(0xffffffc0, 0xe27a0000), .mnem = "atanpuf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3) } }, // ATANPUF32 RaH,RbH
	{ OP(0xfffff000, 0xe27c0000), .mnem = "quadf32", RZTYPE(CMP), .len = 4, .ops = { FREG(0), FREG(3), FREG(6), FREG(9) } }, // QUADF32 RaH,RbH,RcH,RdH
	{ OP(0xffffff00, 0xe2800000), .mnem = "mov32", RZTYPE(LOAD), .len = 4, .ops = { REG(STF), LOC32(0) } }, // MOV32 STF,mem32
	{ OP(0xfffff800, 0xe2840000), .mnem = "ui32tof32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // UI32TOF32 RaH,mem32
	{ OP(0xfffff800, 0xe2850000), .mnem = "ui32tof64", RZTYPE(LOAD), .len = 4, .ops = { FREG64(8), LOC32(0) } }, // UI32TOF64 Ra,mem32
	{ OP(0xfffff800, 0xe2880000), .mnem = "i32tof32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // I32TOF32 RaH,mem32
	{ OP(0xfffff800, 0xe2890000), .mnem = "i32tof64", RZTYPE(LOAD), .len = 4, .ops = { FREG64(8), LOC32(0) } }, // I32TOF64 Ra,mem32
	{ OP(0xfffff800, 0xe28c0000), .mnem = "f32tof64", RZTYPE(LOAD), .len = 4, .ops = { FREG64(8), LOC32(0) } }, // F32TOF64 Ra,mem32
	{ OP(0xfff00000, 0xe2900000), .mnem = "mov32", RZTYPE(LOAD), .len = 4, .ops = { FREGL(8), LOC16(0), FCOND(16) } }, // MOV32 RaL,mem16,CNDF
	{ OP(0xfff00000, 0xe2a00000), .mnem = "mov32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC16(0), FCOND(16) } }, // MOV32 RaH,mem16,CNDF
	{ OP(0xfffff800, 0xe2c40000), .mnem = "ui16tof32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // UI16TOF32 RaH,mem32
	{ OP(0xfffff800, 0xe2c80000), .mnem = "i16tof32", RZTYPE(LOAD), .len = 4, .ops = { FREG(8), LOC32(0) } }, // I16TOF32 RaH,mem32
	{ OP(0xfff00000, 0xe3000000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MPYF32 RaH,RbH,RcH || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3100000), .mnem = "addf32", RZTYPE(ADD), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), FREG(8), LOC32(0) } }, // ADDF32 RaH,RbH,RcH || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3200000), .mnem = "subf32", RZTYPE(SUB), .len = 4, .ops = { FREG(11), FREG(14), FREG(17), PAR(MOV32), FREG(8), LOC32(0) } }, // SUBF32 RaH,RbH,RcH || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3300000), .mnem = "macf32", RZTYPE(MUL), .len = 4, .ops = { FREGFIX(3), FREGFIX(2), FREG(11), FREG(14), FREG(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MACF32 R3H,R2H,RaH,RbH,RcH || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3400000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MPYF64 Ra,Rb,Rc || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3500000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREG(8), LOC32(0) } }, // ADDF64 Ra,Rb,Rc || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3600000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREG(8), LOC32(0) } }, // SUBF64 Ra,Rb,Rc || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3700000), .mnem = "macf64", RZTYPE(MUL), .len = 4, .ops = { REG(R3), REG(R2), FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MACF64 R3,R2,Ra,Rb,Rc || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3800000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREGL(8), LOC32(0) } }, // MPYF64 Ra,Rb,Rc || MOV32 RdL,mem32
	{ OP(0xfff00000, 0xe3900000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREGL(8), LOC32(0) } }, // ADDF64 Ra,Rb,Rc || MOV32 RdL,mem32
	{ OP(0xfff00000, 0xe3a00000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREGL(8), LOC32(0) } }, // SUBF64 Ra,Rb,Rc || MOV32 RdL,mem32
	{ OP(0xfff00000, 0xe3b00000), .mnem = "macf64", RZTYPE(MUL), .len = 4, .ops = { REG(R3), REG(R2), FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREGL(8), LOC32(0) } }, // MACF64 R3,R2,Ra,Rb,Rc || MOV32 RdL,mem32
	{ OP(0xfff00000, 0xe3c00000), .mnem = "macf32", RZTYPE(MUL), .len = 4, .ops = { FREGFIX(7), FREGFIX(6), FREG(11), FREG(14), FREG(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MACF32 R7H,R6H,RaH,RbH,RcH || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3d00000), .mnem = "macf64", RZTYPE(MUL), .len = 4, .ops = { REG(R7), REG(R6), FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREG(8), LOC32(0) } }, // MACF64 R7,R6,Ra,Rb,Rc || MOV32 RdH,mem32
	{ OP(0xfff00000, 0xe3e00000), .mnem = "macf64", RZTYPE(MUL), .len = 4, .ops = { REG(R7), REG(R6), FREG64(11), FREG64(14), FREG64(17), PAR(MOV32), FREGL(8), LOC32(0) } }, // MACF64 R7,R6,Ra,Rb,Rc || MOV32 RdL,mem32
	{ OP(0xffff0000, 0xe5620000), .mnem = "restore", RZTYPE(MOV) }, // RESTORE
	{ OP(0xfff70000, 0xe5630000), .mnem = "zeroa", RZTYPE(MOV) }, // ZEROA
	{ OP(0xffff0000, 0xe5640000), .mnem = "subc4ui32", RZTYPE(DIV), .ops = { FREGFIX(2), FREGFIX(1), FREGFIX(3) } }, // SUBC4UI32 R2H,R1H,R3H
	{ OP(0xffff0000, 0xe5650000), .mnem = "subc2ui64", RZTYPE(DIV), .ops = { REG(R2H_R4H), REG(R1H_R0H), REG(R3H_R5H) } }, // SUBC2UI64 R2H:R4H,R1H:R0H,R3H:R5H
	{ OP(0xffff0000, 0xe5660000), .mnem = "subc3f64", RZTYPE(DIV), .ops = { REG(R2), REG(R1), REG(R3) } }, // SUBC3F64 R2,R1,R3
	{ OP(0xffff0000, 0xe5680000), .mnem = "absi32div32", RZTYPE(DIV), .ops = { FREGFIX(2), FREGFIX(1), FREGFIX(3) } }, // ABSI32DIV32 R2H,R1H,R3H
	{ OP(0xffff0000, 0xe5690000), .mnem = "absi32div32u", RZTYPE(DIV), .ops = { FREGFIX(2), FREGFIX(1) } }, // ABSI32DIV32U R2H,R1H
	{ OP(0xffff0000, 0xe56a0000), .mnem = "negi32div32", RZTYPE(DIV), .ops = { FREGFIX(1), FREGFIX(2) } }, // NEGI32DIV32 R1H,R2H
	{ OP(0xffff0000, 0xe56b0000), .mnem = "enegi32div32", RZTYPE(DIV), .ops = { FREGFIX(1), FREGFIX(2), FREGFIX(3) } }, // ENEGI32DIV32 R1H,R2H,R3H
	{ OP(0xffff0000, 0xe56c0000), .mnem = "mnegi32div32", RZTYPE(DIV), .ops = { FREGFIX(1), FREGFIX(2), FREGFIX(3) } }, // MNEGI32DIV32 R1H,R2H,R3H
	{ OP(0xfff00000, 0xe5800000), .mnem = "testtf", RZTYPE(CMP), .ops = { FCOND(16) } }, // TESTTF CNDF
	{ OP(0xfff00000, 0xe5900000), .mnem = "zero", RZTYPE(MOV), .ops = { FREG64(16) } }, // ZERO Ra
	{ OP(0xfff80000, 0xe5a00000), .mnem = "cmpf32", RZTYPE(CMP), .ops = { FREG(16), FZERO } }, // CMPF32 RaH,#0.0
	{ OP(0xffff0000, 0xe5a80000), .mnem = "absi64div32", RZTYPE(DIV), .ops = { FREGFIX(2), REG(R1H_R0H), FREGFIX(3) } }, // ABSI64DIV32 R2H,R1H:R0H,R3H
	{ OP(0xffff0000, 0xe5a90000), .mnem = "absi64div32u", RZTYPE(DIV), .ops = { FREGFIX(2), REG(R1H_R0H) } }, // ABSI64DIV32U R2H,R1H:R0H
	{ OP(0xffff0000, 0xe5aa0000), .mnem = "negi64div32", RZTYPE(DIV), .ops = { REG(R1H_R0H), FREGFIX(2) } }, // NEGI64DIV32 R1H:R0H,R2H
	{ OP(0xffff0000, 0xe5ab0000), .mnem = "enegi64div32", RZTYPE(DIV), .ops = { REG(R1H_R0H), FREGFIX(2), FREGFIX(3) } }, // ENEGI64DIV32 R1H:R0H,R2H,R3H
	{ OP(0xffff0000, 0xe5ac0000), .mnem = "mnegi64div32", RZTYPE(DIV), .ops = { REG(R1H_R0H), FREGFIX(2), FREGFIX(3) } }, // MNEGI64DIV32 R1H:R0H,R2H,R3H
	{ OP(0xfff80000, 0xe5b00000), .mnem = "cmpf64", RZTYPE(CMP), .ops = { FREG64(16), FZERO } }, // CMPF64 Ra,#0.0
	{ OP(0xffff0000, 0xe5b80000), .mnem = "absi64div64", RZTYPE(DIV), .ops = { REG(R2H_R4H), REG(R1H_R0H), REG(R3H_R5H) } }, // ABSI64DIV64 R2H:R4H,R1H:R0H,R3H:R5H
	{ OP(0xffff0000, 0xe5b90000), .mnem = "absi64div64u", RZTYPE(DIV), .ops = { REG(R2H_R4H), REG(R1H_R0H) } }, // ABSI64DIV64U R2H:R4H,R1H:R0H
	{ OP(0xffff0000, 0xe5ba0000), .mnem = "negi64div64", RZTYPE(DIV), .ops = { REG(R1H_R0H), REG(R2H_R4H) } }, // NEGI64DIV64 R1H:R0H,R2H:R4H
	{ OP(0xffff0000, 0xe5bb0000), .mnem = "enegi64div64", RZTYPE(DIV), .ops = { REG(R1H_R0H), REG(R2H_R4H), REG(R3H_R5H) } }, // ENEGI64DIV64 R1H:R0H,R2H:R4H,R3H:R5H
	{ OP(0xffff0000, 0xe5bc0000), .mnem = "mnegi64div64", RZTYPE(DIV), .ops = { REG(R1H_R0H), REG(R2H_R4H), REG(R3H_R5H) } }, // MNEGI64DIV64 R1H:R0H,R2H:R4H,R3H:R5H
	{ OP(0xffff0000, 0xe5be0000), .mnem = "predivf64", RZTYPE(DIV), .ops = { FREGFIX(0), REG(R2), REG(R1), REG(R3) } }, // PREDIVF64 R0H,R2,R1,R3
	{ OP(0xffff0000, 0xe5bf0000), .mnem = "postdivf64", RZTYPE(DIV), .ops = { REG(R1), FREGFIX(0) } }, // POSTDIVF64 R1,R0H
	{ OP(0xffc00000, 0xe6000000), .mnem = "setflg", RZTYPE(MOV), .len = 4, .ops = { FSETFLG } }, // SETFLG flag=value,...
	{ OP(0xffc00000, 0xe6400000), .mnem = "save", RZTYPE(MOV), .len = 4, .ops = { FSETFLG } }, // SAVE flag=value,...
	{ OP(0xffffffc0, 0xe6840000), .mnem = "f64toi32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG64(3) } }, // F64TOI32 RaH,Rb
	{ OP(0xffffffc0, 0xe6848000), .mnem = "f64toi64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // F64TOI64 Ra,Rb
	{ OP(0xffffffc0, 0xe6850000), .mnem = "i32tof64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG(3) } }, // I32TOF64 Ra,RbH
	{ OP(0xffffffc0, 0xe6858000), .mnem = "i64tof64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // I64TOF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6860000), .mnem = "f64toui32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG64(3) } }, // F64TOUI32 RaH,Rb
	{ OP(0xffffffc0, 0xe6868000), .mnem = "f64toui64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // F64TOUI64 Ra,Rb
	{ OP(0xffffffc0, 0xe6870000), .mnem = "ui32tof64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG(3) } }, // UI32TOF64 Ra,RbH
	{ OP(0xffffffc0, 0xe6878000), .mnem = "ui64tof64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // UI64TOF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6880000), .mnem = "f32toi32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOI32 RaH,RbH
	{ OP(0xffffffc0, 0xe6890000), .mnem = "i32tof32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // I32TOF32 RaH,RbH
	{ OP(0xffffffc0, 0xe68a0000), .mnem = "f32toui32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOUI32 RaH,RbH
	{ OP(0xffffffc0, 0xe68b0000), .mnem = "ui32tof32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // UI32TOF32 RaH,RbH
	{ OP(0xffffffc0, 0xe68c0000), .mnem = "f32toi16", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOI16 RaH,RbH
	{ OP(0xffffffc0, 0xe68c8000), .mnem = "f32toi16r", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOI16R RaH,RbH
	{ OP(0xffffffc0, 0xe68d0000), .mnem = "i16tof32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // I16TOF32 RaH,RbH
	{ OP(0xffffffc0, 0xe68e0000), .mnem = "f32toui16", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOUI16 RaH,RbH
	{ OP(0xffffffc0, 0xe68e8000), .mnem = "f32toui16r", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // F32TOUI16R RaH,RbH
	{ OP(0xffffffc0, 0xe68f0000), .mnem = "ui16tof32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // UI16TOF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6900000), .mnem = "f64tof32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG64(3) } }, // F64TOF32 RaH,Rb
	{ OP(0xffffffc0, 0xe6910000), .mnem = "f32tof64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG(3) } }, // F32TOF64 Ra,RbH
	{ OP(0xffffffc0, 0xe6920000), .mnem = "eisqrtf32", RZTYPE(DIV), .len = 4, .ops = { FREG(0), FREG(3) } }, // EISQRTF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6928000), .mnem = "eisqrtf64", RZTYPE(DIV), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // EISQRTF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6930000), .mnem = "einvf32", RZTYPE(DIV), .len = 4, .ops = { FREG(0), FREG(3) } }, // EINVF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6938000), .mnem = "einvf64", RZTYPE(DIV), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // EINVF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6940000), .mnem = "cmpf32", RZTYPE(CMP), .len = 4, .ops = { FREG(0), FREG(3) } }, // CMPF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6950000), .mnem = "absf32", RZTYPE(ABS), .len = 4, .ops = { FREG(0), FREG(3) } }, // ABSF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6960000), .mnem = "maxf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), FREG(3) } }, // MAXF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6970000), .mnem = "minf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), FREG(3) } }, // MINF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6980000), .mnem = "cmpf64", RZTYPE(CMP), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // CMPF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6990000), .mnem = "absf64", RZTYPE(ABS), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // ABSF64 Ra,Rb
	{ OP(0xffffffc0, 0xe69a0000), .mnem = "maxf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // MAXF64 Ra,Rb
	{ OP(0xffffffc0, 0xe69b0000), .mnem = "minf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // MINF64 Ra,Rb
	{ OP(0xffff0000, 0xe69c0000), .mnem = "maxf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), FREG(3), PAR(MOV32), FREG(6), FREG(9) } }, // MAXF32 RaH,RbH || MOV32 RcH,RdH
	{ OP(0xffff0000, 0xe69d0000), .mnem = "minf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), FREG(3), PAR(MOV32), FREG(6), FREG(9) } }, // MINF32 RaH,RbH || MOV32 RcH,RdH
	{ OP(0xffff0000, 0xe69e0000), .mnem = "maxf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), FREG64(3), PAR(MOV64), FREG64(6), FREG64(9) } }, // MAXF64 Ra,Rb || MOV64 Rc,Rd
	{ OP(0xffff0000, 0xe69f0000), .mnem = "minf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), FREG64(3), PAR(MOV64), FREG64(6), FREG64(9) } }, // MINF64 Ra,Rb || MOV64 Rc,Rd
	{ OP(0xfff00000, 0xe6a00000), .mnem = "negf32", RZTYPE(CPL), .len = 4, .ops = { FREG(0), FREG(3), FCOND(16) } }, // NEGF32 RaH,RbH,CNDF
	{ OP(0xfff00000, 0xe6b00000), .mnem = "negf64", RZTYPE(CPL), .len = 4, .ops = { FREG64(0), FREG64(3), FCOND(16) } }, // NEGF64 Ra,Rb,CNDF
	{ OP(0xfff00000, 0xe6c00000), .mnem = "mov32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), FREG(3), FCOND(16) } }, // MOV32 RaH,RbH,CNDF
	{ OP(0xfff00000, 0xe6d00000), .mnem = "mov64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), FREG64(3), FCOND(16) } }, // MOV64 Ra,Rb,CNDF
	{ OP(0xfff00000, 0xe6e00000), .mnem = "swapf", RZTYPE(XCHG), .len = 4, .ops = { FREG64(0), FREG64(3), FCOND(16) } }, // SWAPF Ra,Rb,CNDF
	{ OP(0xffffffc0, 0xe6f10000), .mnem = "fracf32", RZTYPE(CAST), .len = 4, .ops = { FREG(0), FREG(3) } }, // FRACF32 RaH,RbH
	{ OP(0xffffffc0, 0xe6f18000), .mnem = "fracf64", RZTYPE(CAST), .len = 4, .ops = { FREG64(0), FREG64(3) } }, // FRACF64 Ra,Rb
	{ OP(0xffffffc0, 0xe6f40000), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREG(0), FREGL(3) } }, // MOV32 RaH,RbL
	{ OP(0xffffffc0, 0xe6f50000), .mnem = "mov32", RZTYPE(MOV), .len = 4, .ops = { FREGL(0), FREG(3) } }, // MOV32 RaL,RbH
	{ OP(0xffff0000, 0xe7000000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3), FREG(6) } }, // MPYF32 RaH,RbH,RcH
	{ OP(0xffff0000, 0xe7100000), .mnem = "addf32", RZTYPE(ADD), .len = 4, .ops = { FREG(0), FREG(3), FREG(6) } }, // ADDF32 RaH,RbH,RcH
	{ OP(0xffff0000, 0xe7200000), .mnem = "subf32", RZTYPE(SUB), .len = 4, .ops = { FREG(0), FREG(3), FREG(6) } }, // SUBF32 RaH,RbH,RcH
	{ OP(0xfffc0000, 0xe7400000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3), FREG(6), PAR(ADDF32), FREG(9), FREG(12), FREG(15) } }, // MPYF32 RaH,RbH,RcH || ADDF32 RdH,ReH,RfH
	{ OP(0xfffc0000, 0xe7500000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), FREG(3), FREG(6), PAR(SUBF32), FREG(9), FREG(12), FREG(15) } }, // MPYF32 RaH,RbH,RcH || SUBF32 RdH,ReH,RfH
	{ OP(0xffff0000, 0xe7800000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(0), FREG64(3), FREG64(6) } }, // MPYF64 Ra,Rb,Rc
	{ OP(0xffff0000, 0xe7900000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(0), FREG64(3), FREG64(6) } }, // ADDF64 Ra,Rb,Rc
	{ OP(0xffff0000, 0xe7a00000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(0), FREG64(3), FREG64(6) } }, // SUBF64 Ra,Rb,Rc
	{ OP(0xfff00000, 0xe7c00000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(0), FREG64(3), FREG64(6), PAR(ADDF64), FREG64(9), FREG64(12), FREG64(15) } }, // MPYF64 Ra,Rb,Rc || ADDF64 Rd,Re,Rf
	{ OP(0xfff00000, 0xe7d00000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(0), FREG64(3), FREG64(6), PAR(SUBF64), FREG64(9), FREG64(12), FREG64(15) } }, // MPYF64 Ra,Rb,Rc || SUBF64 Rd,Re,Rf
	{ OP(0xfff80000, 0xe8000000), .mnem = "moviz", RZTYPE(MOV), .len = 4, .ops = { FREG64(0), IMMU(3, 16) } }, // MOVIZ Ra,#16bit
	{ OP(0xfff80000, 0xe8080000), .mnem = "movxi", RZTYPE(MOV), .len = 4, .ops = { FREG(0), IMMU(3, 16) } }, // MOVXI RaH,#16bit
	{ OP(0xfff80000, 0xe8100000), .mnem = "cmpf32", RZTYPE(CMP), .len = 4, .ops = { FREG(0), IMMU(3, 16) } }, // CMPF32 RaH,#16bit
	{ OP(0xfff80000, 0xe8200000), .mnem = "maxf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), IMMU(3, 16) } }, // MAXF32 RaH,#16bit
	{ OP(0xfff80000, 0xe8300000), .mnem = "minf32", RZTYPE(CMOV), .len = 4, .ops = { FREG(0), IMMU(3, 16) } }, // MINF32 RaH,#16bit
	{ OP(0xffc00000, 0xe8400000), .mnem = "mpyf32", RZTYPE(MUL), .len = 4, .ops = { FREG(0), IMMU(6, 16), FREG(3) } }, // MPYF32 RaH,#16bit,RbH
	{ OP(0xffc00000, 0xe8800000), .mnem = "addf32", RZTYPE(ADD), .len = 4, .ops = { FREG(0), IMMU(6, 16), FREG(3) } }, // ADDF32 RaH,#16bit,RbH
	{ OP(0xffc00000, 0xe8c00000), .mnem = "subf32", RZTYPE(SUB), .len = 4, .ops = { FREG(0), IMMU(6, 16), FREG(3) } }, // SUBF32 RaH,#16bit,RbH
	{ OP(0xfff80000, 0xe9000000), .mnem = "movix", RZTYPE(MOV), .len = 4, .ops = { FREGL(0), IMMU(3, 16) } }, // MOVIX RaL,#16bit
	{ OP(0xfff80000, 0xe9080000), .mnem = "movxi", RZTYPE(MOV), .len = 4, .ops = { FREGL(0), IMMU(3, 16) } }, // MOVXI RaL,#16bit
	{ OP(0xfff80000, 0xe9100000), .mnem = "cmpf64", RZTYPE(CMP), .len = 4, .ops = { FREG64(0), IMMU(3, 16) } }, // CMPF64 Ra,#16bit
	{ OP(0xfff80000, 0xe9200000), .mnem = "maxf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), IMMU(3, 16) } }, // MAXF64 Ra,#16bit
	{ OP(0xfff80000, 0xe9300000), .mnem = "minf64", RZTYPE(CMOV), .len = 4, .ops = { FREG64(0), IMMU(3, 16) } }, // MINF64 Ra,#16bit
	{ OP(0xffc00000, 0xe9400000), .mnem = "mpyf64", RZTYPE(MUL), .len = 4, .ops = { FREG64(0), IMMU(6, 16), FREG64(3) } }, // MPYF64 Ra,#16bit,Rb
	{ OP(0xffc00000, 0xe9800000), .mnem = "addf64", RZTYPE(ADD), .len = 4, .ops = { FREG64(0), IMMU(6, 16), FREG64(3) } }, // ADDF64 Ra,#16bit,Rb
	{ OP(0xffc00000, 0xe9c00000), .mnem = "subf64", RZTYPE(SUB), .len = 4, .ops = { FREG64(0), IMMU(6, 16), FREG64(3) } }, // SUBF64 Ra,#16bit,Rb
	{ OP(0xffff0000, 0xfff00000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(RB) } }, // PUSH RB
	{ OP(0xffff0000, 0xfff10000), .mnem = "pop", RZTYPE(POP), .ops = { REG(RB) } }, // POP RB
	// clang-format on
