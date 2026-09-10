// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// TMS320C28x instruction rows, ordered by opcode. Bit patterns are SPRU430F
// chapter 6; the trailing comment on each row is the manual's syntax line.
//
// The OBJMODE = 0 (C27x-compatible) alternate encodings are deliberately absent:
// they collide with the OBJMODE = 1 opcode map, and OBJMODE = 1 is what the C28x
// boot ROM selects and every C28x toolchain emits. The same applies to the
// AMODE = 1 loc16 readings (see the file comment in c28x.h).

// clang-format off
	// --- 0x00: control transfer, stack and interrupt ---
	{ OP(0xffff0000, 0x00010000), .mnem = "aborti", RZTYPE(NULL) },                                                    // ABORTI
	{ OP(0xffff0000, 0x00020000), .mnem = "pop", RZTYPE(POP), .ops = { REG(IFR) } },                                   // POP IFR
	{ OP(0xffff0000, 0x00030000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR1H_AR0H) } },                             // POP AR1H:AR0H
	{ OP(0xffff0000, 0x00040000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(RPC) } },                                 // PUSH RPC
	{ OP(0xffff0000, 0x00050000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(AR1H_AR0H) } },                           // PUSH AR1H:AR0H
	{ OP(0xffff0000, 0x00060000), .mnem = "lretr", RZTYPE(RET) },                                                      // LRETR
	{ OP(0xffff0000, 0x00070000), .mnem = "pop", RZTYPE(POP), .ops = { REG(RPC) } },                                   // POP RPC
	{ OP(0xfff80000, 0x00080000), .mnem = "banz", RZTYPE(CJMP), .len = 4, .ops = { REL(0, 16), ARN(16) } },            // BANZ 16bitOffset,ARn--
	{ OP(0xfff00000, 0x00100000), .mnem = "intr", RZTYPE(SWI), .ops = { INTRN(16) } },                               // INTR INTx / DLOGINT / RTOSINT
	{ OP(0xffe00000, 0x00200000), .mnem = "trap", RZTYPE(SWI), .ops = { IMMU(16, 5) } },                               // TRAP #VectorNumber
	{ OP(0xffc00000, 0x00400000), .mnem = "lb", RZTYPE(JMP), .len = 4, .ops = { PMA(0, 22) } },                        // LB 22bit
	{ OP(0xffc00000, 0x00800000), .mnem = "lc", RZTYPE(CALL), .len = 4, .ops = { PMA(0, 22) } },                       // LC 22bit
	{ OP(0xffc00000, 0x00c00000), .mnem = "ffc", RZTYPE(CALL), .len = 4, .ops = { REG(XAR7), PMA(0, 22) } },           // FFC XAR7,22bit

	// --- 0x01-0x0f: accumulator arithmetic ---
	{ OP(0xff000000, 0x01000000), .mnem = "subu", RZTYPE(SUB), .ops = { REG(ACC), LOC16(16) }, RPTABLE },              // SUBU ACC,loc16
	{ OP(0xff000000, 0x02000000), .mnem = "movb", RZTYPE(MOV), .ops = { REG(ACC), IMMU(16, 8) } },                     // MOVB ACC,#8bit
	{ OP(0xff000000, 0x03000000), .mnem = "subl", RZTYPE(SUB), .ops = { REG(ACC), LOC32(16) } },                       // SUBL ACC,loc32
	{ OP(0xff000000, 0x04000000), .mnem = "sub", RZTYPE(SUB), .ops = { REG(ACC), LOC16(16), SHIFTC(16) }, RPTABLE },   // SUB ACC,loc16 << #16
	{ OP(0xff000000, 0x05000000), .mnem = "add", RZTYPE(ADD), .ops = { REG(ACC), LOC16(16), SHIFTC(16) }, RPTABLE },   // ADD ACC,loc16 << #16
	{ OP(0xffff0000, 0x06be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(ACC) } },                                   // POP ACC
	{ OP(0xff000000, 0x06000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(ACC), LOC32(16) } },                       // MOVL ACC,loc32
	{ OP(0xff000000, 0x07000000), .mnem = "addl", RZTYPE(ADD), .ops = { REG(ACC), LOC32(16) } },                       // ADDL ACC,loc32
	{ OP(0xff000000, 0x08000000), .mnem = "add", RZTYPE(ADD), .len = 4, .ops = { LOC16(16), IMMS(0, 16) } },           // ADD loc16,#16bitSigned
	{ OP(0xff000000, 0x09000000), .mnem = "addb", RZTYPE(ADD), .ops = { REG(ACC), IMMU(16, 8) } },                     // ADDB ACC,#8bit
	{ OP(0xff000000, 0x0a000000), .mnem = "inc", RZTYPE(ADD), .ops = { LOC16(16) }, RPTABLE },                         // INC loc16
	{ OP(0xff000000, 0x0b000000), .mnem = "dec", RZTYPE(SUB), .ops = { LOC16(16) }, RPTABLE },                         // DEC loc16
	{ OP(0xff000000, 0x0c000000), .mnem = "addcu", RZTYPE(ADD), .ops = { REG(ACC), LOC16(16) }, RPTABLE },             // ADDCU ACC,loc16
	{ OP(0xff000000, 0x0d000000), .mnem = "addu", RZTYPE(ADD), .ops = { REG(ACC), LOC16(16) }, RPTABLE },              // ADDU ACC,loc16
	{ OP(0xff000000, 0x0e000000), .mnem = "movu", RZTYPE(MOV), .ops = { REG(ACC), LOC16(16) }, RPTABLE },              // MOVU ACC,loc16
	{ OP(0xff000000, 0x0f000000), .mnem = "cmpl", RZTYPE(CMP), .ops = { REG(ACC), LOC32(16) } },                       // CMPL ACC,loc32

	// --- 0x10-0x17: T/P register loads and multiplies ---
	{ OP(0xffff0000, 0x10ac0000), .mnem = "addl", RZTYPE(ADD), .ops = { REG(ACC), REG(P_PM) } },                       // ADDL ACC,P << PM
	{ OP(0xff000000, 0x10000000), .mnem = "mova", RZTYPE(MOV), .ops = { REG(T), LOC16(16) }, RPTABLE },                // MOVA T,loc16
	{ OP(0xffff0000, 0x11ac0000), .mnem = "subl", RZTYPE(SUB), .ops = { REG(ACC), REG(P_PM) } },                       // SUBL ACC,P << PM
	{ OP(0xff000000, 0x11000000), .mnem = "movs", RZTYPE(MOV), .ops = { REG(T), LOC16(16) }, RPTABLE },                // MOVS T,loc16
	{ OP(0xff000000, 0x12000000), .mnem = "mpy", RZTYPE(MUL), .ops = { REG(ACC), REG(T), LOC16(16) } },                // MPY ACC,T,loc16
	{ OP(0xff000000, 0x13000000), .mnem = "mpys", RZTYPE(MUL), .ops = { REG(P), REG(T), LOC16(16) }, RPTABLE },        // MPYS P,T,loc16
	{ OP(0xff000000, 0x14000000), .mnem = "mac", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(16), PMA_DP(0, 16) }, RPTABLE }, // MAC P,loc16,0:pma
	{ OP(0xff000000, 0x15000000), .mnem = "mpya", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(16), IMMS(0, 16) } },  // MPYA P,loc16,#16bit
	{ OP(0xffff0000, 0x16ac0000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(ACC), REG(P_PM) } },                       // MOVL ACC,P << PM
	{ OP(0xff000000, 0x16000000), .mnem = "movp", RZTYPE(MOV), .ops = { REG(T), LOC16(16) }, RPTABLE },                // MOVP T,loc16
	{ OP(0xff000000, 0x17000000), .mnem = "mpya", RZTYPE(MUL), .ops = { REG(P), REG(T), LOC16(16) }, RPTABLE },        // MPYA P,T,loc16

	// --- 0x18-0x1f: logical and long arithmetic ---
	{ OP(0xff000000, 0x18000000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { LOC16(16), IMMS(0, 16) } },           // AND loc16,#16bitSigned
	{ OP(0xff000000, 0x19000000), .mnem = "subb", RZTYPE(SUB), .ops = { REG(ACC), IMMU(16, 8) } },                     // SUBB ACC,#8bit
	{ OP(0xff000000, 0x1a000000), .mnem = "or", RZTYPE(OR), .len = 4, .ops = { LOC16(16), IMMU(0, 16) } },             // OR loc16,#16bit
	{ OP(0xff000000, 0x1b000000), .mnem = "cmp", RZTYPE(CMP), .len = 4, .ops = { LOC16(16), IMMS(0, 16) } },           // CMP loc16,#16bitSigned
	{ OP(0xff000000, 0x1c000000), .mnem = "xor", RZTYPE(XOR), .len = 4, .ops = { LOC16(16), IMMU(0, 16) } },           // XOR loc16,#16bit
	{ OP(0xff000000, 0x1d000000), .mnem = "sbbu", RZTYPE(SUB), .ops = { REG(ACC), LOC16(16) }, RPTABLE },              // SBBU ACC,loc16
	{ OP(0xffff0000, 0x1ebd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(ACC) } },                                 // PUSH ACC
	{ OP(0xff000000, 0x1e000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(ACC) } },                       // MOVL loc32,ACC
	{ OP(0xff000000, 0x1f000000), .mnem = "subcu", RZTYPE(SUB), .ops = { REG(ACC), LOC16(16) }, RPTABLE },             // SUBCU ACC,loc16

	// --- 0x20-0x2f: moves, stack and program memory ---
	{ OP(0xff000000, 0x20000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), REG(IER) } },                        // MOV loc16,IER
	{ OP(0xff000000, 0x21000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), REG(T) } },                          // MOV loc16,T
	{ OP(0xff000000, 0x22000000), .mnem = "push", RZTYPE(PUSH), .ops = { LOC16(16) } },                                // PUSH loc16
	{ OP(0xff000000, 0x23000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(IER), LOC16(16) } },                        // MOV IER,loc16
	{ OP(0xff000000, 0x24000000), .mnem = "pread", RZTYPE(LOAD), .ops = { LOC16(16), INDR(XAR_NONE, 7) }, RPTABLE },    // PREAD loc16,*XAR7
	{ OP(0xff000000, 0x25000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(ACC), LOC16(16), SHIFTC(16) }, RPTABLE },  // MOV ACC,loc16 << #16
	{ OP(0xff000000, 0x26000000), .mnem = "pwrite", RZTYPE(STORE), .ops = { INDR(XAR_NONE, 7), LOC16(16) }, RPTABLE },  // PWRITE *XAR7,loc16
	{ OP(0xff000000, 0x27000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(PL), LOC16(16) } },                         // MOV PL,loc16
	{ OP(0xff000000, 0x28000000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { LOC16(16), IMMU(0, 16) } },           // MOV loc16,#16bit
	{ OP(0xffff0000, 0x29100000), .mnem = "eint", RZTYPE(NULL) },                                                      // EINT (= CLRC INTM)
	{ OP(0xff000000, 0x29000000), .mnem = "clrc", RZTYPE(NULL), .ops = { MODE(16) } },                                 // CLRC mode
	{ OP(0xff000000, 0x2a000000), .mnem = "pop", RZTYPE(POP), .ops = { LOC16(16) } },                                  // POP loc16
	{ OP(0xff000000, 0x2b000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), IMMC(0) }, RPTABLE },                // MOV loc16,#0
	{ OP(0xff000000, 0x2c000000), .mnem = "loopz", RZTYPE(CJMP), .len = 4, .ops = { LOC16(16), IMMU(0, 16) } },        // LOOPZ loc16,#16bit
	{ OP(0xff000000, 0x2d000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(T), LOC16(16) } },                          // MOV T,loc16
	{ OP(0xff000000, 0x2e000000), .mnem = "loopnz", RZTYPE(CJMP), .len = 4, .ops = { LOC16(16), IMMU(0, 16) } },       // LOOPNZ loc16,#16bit
	{ OP(0xff000000, 0x2f000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(PH), LOC16(16) } },                         // MOV PH,loc16

	// --- 0x30-0x37: multiplies ---
	{ OP(0xff000000, 0x30000000), .mnem = "mpyxu", RZTYPE(MUL), .ops = { REG(ACC), REG(T), LOC16(16) } },              // MPYXU ACC,T,loc16
	{ OP(0xff000000, 0x31000000), .mnem = "mpyb", RZTYPE(MUL), .ops = { REG(P), REG(T), IMMU(16, 8) } },               // MPYB P,T,#8bit
	{ OP(0xff000000, 0x32000000), .mnem = "mpyxu", RZTYPE(MUL), .ops = { REG(P), REG(T), LOC16(16) }, RPTABLE },       // MPYXU P,T,loc16
	{ OP(0xff000000, 0x33000000), .mnem = "mpy", RZTYPE(MUL), .ops = { REG(P), REG(T), LOC16(16) }, RPTABLE },         // MPY P,T,loc16
	{ OP(0xff000000, 0x34000000), .mnem = "mpy", RZTYPE(MUL), .len = 4, .ops = { REG(ACC), LOC16(16), IMMS(0, 16) } }, // MPY ACC,loc16,#16bit
	{ OP(0xff000000, 0x35000000), .mnem = "mpyb", RZTYPE(MUL), .ops = { REG(ACC), REG(T), IMMU(16, 8) } },             // MPYB ACC,T,#8bit
	{ OP(0xff000000, 0x36000000), .mnem = "mpyu", RZTYPE(MUL), .ops = { REG(ACC), REG(T), LOC16(16) } },               // MPYU ACC,T,loc16
	{ OP(0xff000000, 0x37000000), .mnem = "mpyu", RZTYPE(MUL), .ops = { REG(P), REG(T), LOC16(16) }, RPTABLE },        // MPYU P,T,loc16

	// --- 0x38-0x3f: byte moves, mode bits and the 0x3e escape ---
	{ OP(0xfe000000, 0x38000000), .mnem = "movb", RZTYPE(MOV), .ops = { AXMSB, LOC16(16) } },                          // MOVB AX.MSB,loc16
	{ OP(0xffff0000, 0x3abd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR0) } },                                // PUSH XAR0
	{ OP(0xff000000, 0x3a000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR0) } },                      // MOVL loc32,XAR0
	{ OP(0xffff0000, 0x3b100000), .mnem = "dint", RZTYPE(NULL) },                                                      // DINT (= SETC INTM)
	{ OP(0xff000000, 0x3b000000), .mnem = "setc", RZTYPE(NULL), .ops = { MODE(16) } },                                 // SETC mode
	{ OP(0xfe000000, 0x3c000000), .mnem = "movb", RZTYPE(MOV), .ops = { LOC16(16), AXLSB } },                          // MOVB loc16,AX.LSB
	{ OP(0xfff00000, 0x3e000000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } }, // AND ACC,#16bit << #0..15
	{ OP(0xfff00000, 0x3e100000), .mnem = "or", RZTYPE(OR), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } },   // OR ACC,#16bit << #0..15
	{ OP(0xfff00000, 0x3e200000), .mnem = "xor", RZTYPE(XOR), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } }, // XOR ACC,#16bit << #0..15
	{ OP(0xfff80000, 0x3e300000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_SET, 16) } },       // XBANZ pma,*,ARPn
	{ OP(0xfff80000, 0x3e380000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_POSTINC, 0), ARPN(16) } }, // XBANZ pma,*++,ARPn
	{ OP(0xfff80000, 0x3e400000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_POSTDEC, 0), ARPN(16) } }, // XBANZ pma,*--,ARPn
	{ OP(0xfff80000, 0x3e480000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_IDX_INC, 0), ARPN(16) } }, // XBANZ pma,*0++,ARPn
	{ OP(0xfff80000, 0x3e500000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_IDX_DEC, 0), ARPN(16) } }, // XBANZ pma,*0--,ARPn
	{ OP(0xfff80000, 0x3e580000), .mnem = "mov", RZTYPE(MOV), .ops = { XARN(16), REG(PC) } },                          // MOV XARn,PC
	{ OP(0xfff80000, 0x3e600000), .mnem = "lcr", RZTYPE(RCALL), .ops = { IND(XAR_NONE, 16) } },                        // LCR *XARn
	{ OP(0xfff80000, 0x3e680000), .mnem = "xcall", RZTYPE(CALL), .len = 4, .ops = { PMA(0, 16), IND(ARP, 0), ARPN(16) } }, // XCALL pma,*,ARPn
	{ OP(0xfff80000, 0x3e700000), .mnem = "xb", RZTYPE(JMP), .len = 4, .ops = { PMA(0, 16), IND(ARP, 0), ARPN(16) } }, // XB pma,*,ARPn
	{ OP(0xff000000, 0x3f000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), REG(P) } },                          // MOV loc16,P

	// --- 0x40-0x4f: bit test ---
	{ OP(0xf0000000, 0x40000000), .mnem = "tbit", RZTYPE(CMP), .ops = { LOC16(16), BITN(24) } },                       // TBIT loc16,#bit

	// --- 0x50-0x57: AX compare/or, the 0x56 escape group and MOVH ---
	{ OP(0xfe000000, 0x50000000), .mnem = "orb", RZTYPE(OR), .ops = { AXREG, IMMU(16, 8) } },                          // ORB AX,#8bit
	{ OP(0xfe000000, 0x52000000), .mnem = "cmpb", RZTYPE(CMP), .ops = { AXREG, IMMU(16, 8) } },                        // CMPB AX,#8bit
	{ OP(0xfe000000, 0x54000000), .mnem = "cmp", RZTYPE(CMP), .ops = { AXREG, LOC16(16) } },                           // CMP AX,loc16
#include "c28x_rows_56.inc"
	{ OP(0xff000000, 0x57000000), .mnem = "movh", RZTYPE(MOV), .ops = { LOC16(16), REG(P) } },                         // MOVH loc16,P

	// --- 0x58-0x5f: ARn loads (MOVZ clears the upper half, AR6/AR7 do not) ---
	{ OP(0xff000000, 0x5e000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(AR6), LOC16(16) } },                        // MOV AR6,loc16
	{ OP(0xff000000, 0x5f000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(AR7), LOC16(16) } },                        // MOV AR7,loc16
	{ OP(0xf8000000, 0x58000000), .mnem = "movz", RZTYPE(MOV), .ops = { ARN(24), LOC16(16) } },                        // MOVZ AR0..5,loc16

	// --- 0x60-0x6f: short conditional branch ---
	{ OP(0xf0000000, 0x60000000), .mnem = "sb", RZTYPE(CJMP), .ops = { REL(16, 8), COND(24) } },                       // SB 8bitOffset,COND

	// --- 0x70-0x77: AX logic, the 0x76 escape group and NOP ---
	{ OP(0xfe000000, 0x70000000), .mnem = "xor", RZTYPE(XOR), .ops = { AXREG, LOC16(16) } },                           // XOR AX,loc16
	{ OP(0xfe000000, 0x72000000), .mnem = "add", RZTYPE(ADD), .ops = { LOC16(16), AXREG } },                           // ADD loc16,AX
	{ OP(0xfe000000, 0x74000000), .mnem = "sub", RZTYPE(SUB), .ops = { LOC16(16), AXREG } },                           // SUB loc16,AX
#include "c28x_rows_76.inc"
	{ OP(0xff000000, 0x77000000), .mnem = "nop", RZTYPE(NOP), .ops = { LOC16(16) } },                                  // NOP {*ind}{ARPn}

	// --- 0x78-0x7f: store ARn ---
	{ OP(0xf8000000, 0x78000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), ARN(24) } },                         // MOV loc16,ARn

	// --- 0x80-0x8f: ACC/XARn loads, MOVZ AR6/AR7 and BAR ---
	{ OP(0xffff0000, 0x80be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR7) } },                                   // POP AR7 (MOVZ AR7,*--SP)
	{ OP(0xff000000, 0x80000000), .mnem = "movz", RZTYPE(MOV), .ops = { REG(AR7), LOC16(16) } },                       // MOVZ AR7,loc16
	{ OP(0xff000000, 0x81000000), .mnem = "add", RZTYPE(ADD), .ops = { REG(ACC), LOC16(16), SHIFTC(0) }, RPTABLE },    // ADD ACC,loc16 << #0
	{ OP(0xffff0000, 0x82be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR3) } },                                  // POP XAR3
	{ OP(0xff000000, 0x82000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR3), LOC32(16) } },                      // MOVL XAR3,loc32
	{ OP(0xffff0000, 0x83be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR5) } },                                  // POP XAR5
	{ OP(0xff000000, 0x83000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR5), LOC32(16) } },                      // MOVL XAR5,loc32
	{ OP(0xff000000, 0x84000000), .mnem = "xmac", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(16), PMA_IND(0, 16) } },   // XMAC P,loc16,*(pma)
	{ OP(0xffff0000, 0x86be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR2) } },                                  // POP XAR2
	{ OP(0xff000000, 0x85000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(ACC), LOC16(16) }, RPTABLE },            // MOV ACC,loc16 << #0
	{ OP(0xff000000, 0x86000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR2), LOC32(16) } },                      // MOVL XAR2,loc32
	{ OP(0xffff0000, 0x87be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XT) } },                                    // POP XT
	{ OP(0xff000000, 0x87000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XT), LOC32(16) } },                        // MOVL XT,loc32
	{ OP(0xffff0000, 0x88be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR6) } },                                   // POP AR6 (MOVZ AR6,*--SP)
	{ OP(0xff000000, 0x88000000), .mnem = "movz", RZTYPE(MOV), .ops = { REG(AR6), LOC16(16) } },                       // MOVZ AR6,loc16
	{ OP(0xff000000, 0x89000000), .mnem = "and", RZTYPE(AND), .ops = { REG(ACC), LOC16(16) }, RPTABLE },               // AND ACC,loc16
	{ OP(0xffff0000, 0x8abe0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR4) } },                                  // POP XAR4
	{ OP(0xff000000, 0x8a000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR4), LOC32(16) } },                      // MOVL XAR4,loc32
	{ OP(0xffff0000, 0x8bbe0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR1) } },                                  // POP XAR1
	{ OP(0xff000000, 0x8b000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR1), LOC32(16) } },                      // MOVL XAR1,loc32
	{ OP(0xff000000, 0x8c000000), .mnem = "mpy", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(16), IMMS(0, 16) } },   // MPY P,loc16,#16bit
	{ OP(0xffff0000, 0x8ebe0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR0) } },                                  // POP XAR0
	{ OP(0xff000000, 0x8e000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR0), LOC32(16) } },                      // MOVL XAR0,loc32
	{ OP(0xffc00000, 0x8f800000), .mnem = "bar", RZTYPE(CJMP), .len = 4, .ops = { REL(0, 16), ARN(19), ARN(16) }, .cond = C28X_COND_EQ },  // BAR 16bitOffset,ARn,ARm,EQ
	{ OP(0xffc00000, 0x8fc00000), .mnem = "bar", RZTYPE(CJMP), .len = 4, .ops = { REL(0, 16), ARN(19), ARN(16) }, .cond = C28X_COND_NEQ }, // BAR 16bitOffset,ARn,ARm,NEQ

	// --- 0x90-0x9f: AX arithmetic and moves ---
	{ OP(0xfe000000, 0x90000000), .mnem = "andb", RZTYPE(AND), .ops = { AXREG, IMMU(16, 8) } },                        // ANDB AX,#8bit
	{ OP(0xfe000000, 0x92000000), .mnem = "mov", RZTYPE(MOV), .ops = { AXREG, LOC16(16) } },                           // MOV AX,loc16
	{ OP(0xfe000000, 0x94000000), .mnem = "add", RZTYPE(ADD), .ops = { AXREG, LOC16(16) } },                           // ADD AX,loc16
	{ OP(0xfe000000, 0x96000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), AXREG } },                           // MOV loc16,AX
	{ OP(0xfe000000, 0x98000000), .mnem = "or", RZTYPE(OR), .ops = { LOC16(16), AXREG } },                             // OR loc16,AX
	{ OP(0xfe000000, 0x9a000000), .mnem = "movb", RZTYPE(MOV), .ops = { AXREG, IMMU(16, 8) } },                        // MOVB AX,#8bit
	{ OP(0xfe000000, 0x9c000000), .mnem = "addb", RZTYPE(ADD), .ops = { AXREG, IMMS(16, 8) } },                        // ADDB AX,#8bitSigned
	{ OP(0xfe000000, 0x9e000000), .mnem = "sub", RZTYPE(SUB), .ops = { AXREG, LOC16(16) } },                           // SUB AX,loc16

	// --- 0xa0-0xaf: XARn stores, program-memory MACs ---
	{ OP(0xffff0000, 0xa0bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR5) } },                                // PUSH XAR5
	{ OP(0xff000000, 0xa0000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR5) } },                      // MOVL loc32,XAR5
	{ OP(0xffff0000, 0xa2bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR3) } },                                // PUSH XAR3
	{ OP(0xff000000, 0xa2000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR3) } },                      // MOVL loc32,XAR3
	{ OP(0xff000000, 0xa3000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(P), LOC32(16) } },                         // MOVL P,loc32
	{ OP(0xff000000, 0xa4000000), .mnem = "xmacd", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(16), PMA_IND(0, 16) } },  // XMACD P,loc16,*(pma)
	{ OP(0xff000000, 0xa5000000), .mnem = "dmov", RZTYPE(MOV), .ops = { LOC16(16) }, RPTABLE },                        // DMOV loc16
	{ OP(0xff000000, 0xa6000000), .mnem = "movdl", RZTYPE(MOV), .ops = { REG(XT), LOC32(16) }, RPTABLE },              // MOVDL XT,loc32
	{ OP(0xff000000, 0xa7000000), .mnem = "movad", RZTYPE(MOV), .ops = { REG(T), LOC16(16) } },                        // MOVAD T,loc16
	{ OP(0xffff0000, 0xa8bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR4) } },                                // PUSH XAR4
	{ OP(0xff000000, 0xa8000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR4) } },                      // MOVL loc32,XAR4
	{ OP(0xff000000, 0xa9000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(P) } },                         // MOVL loc32,P
	{ OP(0xffff0000, 0xaabd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR2) } },                                // PUSH XAR2
	{ OP(0xff000000, 0xaa000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR2) } },                      // MOVL loc32,XAR2
	{ OP(0xffff0000, 0xabbd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XT) } },                                  // PUSH XT
	{ OP(0xff000000, 0xab000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XT) } },                        // MOVL loc32,XT
	{ OP(0xff000000, 0xac000000), .mnem = "xpread", RZTYPE(LOAD), .len = 4, .ops = { LOC16(16), PMA_IND(0, 16) } },         // XPREAD loc16,*(pma)
	{ OP(0xff000000, 0xae000000), .mnem = "sub", RZTYPE(SUB), .ops = { REG(ACC), LOC16(16), SHIFTC(0) }, RPTABLE },    // SUB ACC,loc16 << #0
	{ OP(0xff000000, 0xaf000000), .mnem = "or", RZTYPE(OR), .ops = { REG(ACC), LOC16(16) }, RPTABLE },                 // OR ACC,loc16

	// --- 0xb0-0xbf: I/O, shifted stores, DP loads ---
	{ OP(0xff000000, 0xb0000000), .mnem = "uout", RZTYPE(IO), .len = 4, .ops = { PORT(0, 16), LOC16(16) } },           // UOUT *(PA),loc16
	{ OP(0xff000000, 0xb1000000), .mnem = "mov", RZTYPE(MOV), .ops = { LOC16(16), REG(ACC), SHIFTC(1) }, RPTABLE },    // MOV loc16,ACC << 1
	{ OP(0xffff0000, 0xb2bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR1) } },                                // PUSH XAR1
	{ OP(0xff000000, 0xb2000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR1) } },                      // MOVL loc32,XAR1
	{ OP(0xff800000, 0xb5000000), .mnem = "rptb", RZTYPE(NULL), .len = 4, .ops = { IMMU(16, 7), LOC16(0) } },      // RPTB label,loc16
	{ OP(0xff800000, 0xb5800000), .mnem = "rptb", RZTYPE(NULL), .len = 4, .ops = { IMMU(16, 7), IMMU(0, 16) } },    // RPTB label,#16bit
	{ OP(0xff000000, 0xb3000000), .mnem = "movh", RZTYPE(MOV), .ops = { LOC16(16), REG(ACC), SHIFTC(1) }, RPTABLE },   // MOVH loc16,ACC << 1
	{ OP(0xff000000, 0xb4000000), .mnem = "in", RZTYPE(IO), .len = 4, .ops = { LOC16(16), PORT(0, 16) } },             // IN loc16,*(PA)
	{ OP(0xff000000, 0xb6000000), .mnem = "movb", RZTYPE(MOV), .ops = { REG(XAR7), IMMU(16, 8) } },                    // MOVB XAR7,#8bit
	{ OP(0xff000000, 0xb7000000), .mnem = "xor", RZTYPE(XOR), .ops = { REG(ACC), LOC16(16) }, RPTABLE },               // XOR ACC,loc16
	{ OP(0xfc000000, 0xb8000000), .mnem = "movz", RZTYPE(MOV), .ops = { REG(DP), IMMU(16, 10) } },                     // MOVZ DP,#10bit
	{ OP(0xff000000, 0xbc000000), .mnem = "out", RZTYPE(IO), .len = 4, .ops = { PORT(0, 16), LOC16(16) } },            // OUT *(PA),loc16
	{ OP(0xff000000, 0xbe000000), .mnem = "movb", RZTYPE(MOV), .ops = { REG(XAR6), IMMU(16, 8) } },                    // MOVB XAR6,#8bit

	// --- 0xc0-0xcf: AX logic and XAR6/XAR7 ---
	{ OP(0xfe000000, 0xc0000000), .mnem = "and", RZTYPE(AND), .ops = { LOC16(16), AXREG } },                           // AND loc16,AX
	{ OP(0xffff0000, 0xc2bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR6) } },                                // PUSH XAR6
	{ OP(0xff000000, 0xc2000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR6) } },                      // MOVL loc32,XAR6
	{ OP(0xffff0000, 0xc3bd0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(XAR7) } },                                // PUSH XAR7
	{ OP(0xff000000, 0xc3000000), .mnem = "movl", RZTYPE(MOV), .ops = { LOC32(16), REG(XAR7) } },                      // MOVL loc32,XAR7
	{ OP(0xffff0000, 0xc4be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR6) } },                                  // POP XAR6
	{ OP(0xff000000, 0xc4000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR6), LOC32(16) } },                      // MOVL XAR6,loc32
	{ OP(0xffff0000, 0xc5be0000), .mnem = "pop", RZTYPE(POP), .ops = { REG(XAR7) } },                                  // POP XAR7
	{ OP(0xff000000, 0xc5000000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(XAR7), LOC32(16) } },                      // MOVL XAR7,loc32
	{ OP(0xfe000000, 0xc6000000), .mnem = "movb", RZTYPE(MOV), .ops = { AXLSB, LOC16(16) } },                          // MOVB AX.LSB,loc16
	{ OP(0xfe000000, 0xc8000000), .mnem = "movb", RZTYPE(MOV), .ops = { LOC16(16), AXMSB } },                          // MOVB loc16,AX.MSB
	{ OP(0xfe000000, 0xca000000), .mnem = "or", RZTYPE(OR), .ops = { AXREG, LOC16(16) } },                             // OR AX,loc16
	{ OP(0xfe000000, 0xcc000000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { AXREG, LOC16(16), IMMU(0, 16) } },    // AND AX,loc16,#16bit
	{ OP(0xfe000000, 0xce000000), .mnem = "and", RZTYPE(AND), .ops = { AXREG, LOC16(16) } },                           // AND AX,loc16

	// --- 0xd0-0xdf: 8-bit immediate loads and pointer adjust ---
	{ OP(0xff000000, 0xd6000000), .mnem = "movb", RZTYPE(MOV), .ops = { REG(AR6), IMMU(16, 8) } },                     // MOVB AR6,#8bit
	{ OP(0xff000000, 0xd7000000), .mnem = "movb", RZTYPE(MOV), .ops = { REG(AR7), IMMU(16, 8) } },                     // MOVB AR7,#8bit
	{ OP(0xf8000000, 0xd0000000), .mnem = "movb", RZTYPE(MOV), .ops = { XARN(24), IMMU(16, 8) } },                     // MOVB XAR0..5,#8bit
	{ OP(0xf8800000, 0xd8000000), .mnem = "addb", RZTYPE(ADD), .ops = { XARN(24), IMMU(16, 7) } },                     // ADDB XARn,#7bit
	{ OP(0xf8800000, 0xd8800000), .mnem = "subb", RZTYPE(SUB), .ops = { XARN(24), IMMU(16, 7) } },                     // SUBB XARn,#7bit

	// --- 0xe0-0xef: reverse subtract and short fast branches ---
	{ OP(0xfe000000, 0xea000000), .mnem = "subr", RZTYPE(SUB), .ops = { LOC16(16), AXREG } },                          // SUBR loc16,AX
	{ OP(0xff000000, 0xec000000), .mnem = "sbf", RZTYPE(CJMP), .ops = { REL(16, 8) }, .cond = C28X_COND_EQ },          // SBF 8bitOffset,EQ
	{ OP(0xff000000, 0xed000000), .mnem = "sbf", RZTYPE(CJMP), .ops = { REL(16, 8) }, .cond = C28X_COND_NEQ },         // SBF 8bitOffset,NEQ
	{ OP(0xff000000, 0xee000000), .mnem = "sbf", RZTYPE(CJMP), .ops = { REL(16, 8) }, .cond = C28X_COND_TC },          // SBF 8bitOffset,TC
	{ OP(0xff000000, 0xef000000), .mnem = "sbf", RZTYPE(CJMP), .ops = { REL(16, 8) }, .cond = C28X_COND_NTC },         // SBF 8bitOffset,NTC

	// --- 0xf0-0xfd: absolute data moves, repeat, SP/DP adjust ---
	{ OP(0xfe000000, 0xf0000000), .mnem = "xorb", RZTYPE(XOR), .ops = { AXREG, IMMU(16, 8) } },                        // XORB AX,#8bit
	{ OP(0xfe000000, 0xf2000000), .mnem = "xor", RZTYPE(XOR), .ops = { LOC16(16), AXREG } },                           // XOR loc16,AX
	{ OP(0xff000000, 0xf4000000), .mnem = "mov", RZTYPE(STORE), .len = 4, .ops = { DMA(0, 16), LOC16(16) }, RPTABLE }, // MOV *(0:16bit),loc16
	{ OP(0xff000000, 0xf5000000), .mnem = "mov", RZTYPE(LOAD), .len = 4, .ops = { LOC16(16), DMA(0, 16) }, RPTABLE },  // MOV loc16,*(0:16bit)
	{ OP(0xff000000, 0xf6000000), .mnem = "rpt", RZTYPE(REP), .ops = { IMMU(16, 8) } },                                // RPT #8bit
	{ OP(0xff000000, 0xf7000000), .mnem = "rpt", RZTYPE(REP), .ops = { LOC16(16) } },                                  // RPT loc16
	{ OP(0xfc000000, 0xf8000000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(DP), IMMU(16, 10) } },                      // MOV DP,#10bit
	{ OP(0xff000000, 0xfc000000), .mnem = "adrk", RZTYPE(ADD), .ops = { IMMU(16, 8) } },                               // ADRK #8bit
	{ OP(0xff000000, 0xfd000000), .mnem = "sbrk", RZTYPE(SUB), .ops = { IMMU(16, 8) } },                               // SBRK #8bit
	{ OP(0xff800000, 0xfe000000), .mnem = "addb", RZTYPE(ADD), .ops = { REG(SP), IMMU(16, 7) } },                      // ADDB SP,#7bit
	{ OP(0xff800000, 0xfe800000), .mnem = "subb", RZTYPE(SUB), .ops = { REG(SP), IMMU(16, 7) } },                      // SUBB SP,#7bit

	// --- 0xff: the shift/unary escape group ---
	{ OP(0xfff00000, 0xff000000), .mnem = "sub", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } }, // SUB ACC,#16bit << #0..15
	{ OP(0xfffe0000, 0xff600000), .mnem = "sxtb", RZTYPE(MOV), .ops = { AXAT(16) } },                             // SXTB AX
	{ OP(0xfff00000, 0xff100000), .mnem = "add", RZTYPE(ADD), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } }, // ADD ACC,#16bit << #0..15
	{ OP(0xfff00000, 0xff200000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFT(16, 4) } }, // MOV ACC,#16bit << #0..15
	{ OP(0xfff00000, 0xff300000), .mnem = "lsl", RZTYPE(SHL), .ops = { REG(ACC), SHIFT1(16, 4) } },                    // LSL ACC,#1..16
	{ OP(0xfff00000, 0xff400000), .mnem = "sfr", RZTYPE(SAR), .ops = { REG(ACC), SHIFT1(16, 4) } },                    // SFR ACC,#1..16
	{ OP(0xffff0000, 0xff500000), .mnem = "lsl", RZTYPE(SHL), .ops = { REG(ACC), REG(T) } },                           // LSL ACC,T
	{ OP(0xffff0000, 0xff510000), .mnem = "sfr", RZTYPE(SAR), .ops = { REG(ACC), REG(T) } },                           // SFR ACC,T
	{ OP(0xffff0000, 0xff520000), .mnem = "ror", RZTYPE(ROR), .ops = { REG(ACC) }, RPTABLE },                          // ROR ACC
	{ OP(0xffff0000, 0xff530000), .mnem = "rol", RZTYPE(ROL), .ops = { REG(ACC) }, RPTABLE },                          // ROL ACC
	{ OP(0xffff0000, 0xff540000), .mnem = "neg", RZTYPE(NOT), .ops = { REG(ACC) } },                                   // NEG ACC
	{ OP(0xffff0000, 0xff550000), .mnem = "not", RZTYPE(NOT), .ops = { REG(ACC) } },                                   // NOT ACC
	{ OP(0xffff0000, 0xff560000), .mnem = "abs", RZTYPE(ABS), .ops = { REG(ACC) } },                                   // ABS ACC
	{ OP(0xffff0000, 0xff570000), .mnem = "sat", RZTYPE(MOV), .ops = { REG(ACC) } },                                   // SAT ACC
	{ OP(0xffff0000, 0xff580000), .mnem = "test", RZTYPE(CMP), .ops = { REG(ACC) } },                                  // TEST ACC
	{ OP(0xffff0000, 0xff590000), .mnem = "cmpl", RZTYPE(CMP), .ops = { REG(ACC), REG(P_PM) } },                       // CMPL ACC,P << PM
	{ OP(0xffff0000, 0xff5a0000), .mnem = "movl", RZTYPE(MOV), .ops = { REG(P), REG(ACC) } },                          // MOVL P,ACC
	{ OP(0xfffe0000, 0xff5c0000), .mnem = "neg", RZTYPE(NOT), .ops = { AXAT(16) } },                                      // NEG AX
	{ OP(0xfffe0000, 0xff5e0000), .mnem = "not", RZTYPE(NOT), .ops = { AXAT(16) } },                                      // NOT AX
	{ OP(0xfffe0000, 0xff620000), .mnem = "lsr", RZTYPE(SHR), .ops = { AXAT(16), REG(T) } },                              // LSR AX,T
	{ OP(0xfffe0000, 0xff640000), .mnem = "asr", RZTYPE(SAR), .ops = { AXAT(16), REG(T) } },                              // ASR AX,T
	{ OP(0xfffe0000, 0xff660000), .mnem = "lsl", RZTYPE(SHL), .ops = { AXAT(16), REG(T) } },                              // LSL AX,T
	{ OP(0xfff80000, 0xff680000), .mnem = "spm", RZTYPE(NULL), .ops = { PMSHIFT(16) } },                               // SPM shift
	{ OP(0xfff80000, 0xff700000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(XAR_MOD_DEC, 16) } },            // NORM ACC,XARn--
	{ OP(0xfff80000, 0xff780000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(XAR_MOD_INC, 16) } },            // NORM ACC,XARn++
	{ OP(0xffe00000, 0xff800000), .mnem = "lsl", RZTYPE(SHL), .ops = { AXAT(20), SHIFT1(16, 4) } },                       // LSL AX,#1..16
	{ OP(0xffe00000, 0xffa00000), .mnem = "asr", RZTYPE(SAR), .ops = { AXAT(20), SHIFT1(16, 4) } },                       // ASR AX,#1..16
	{ OP(0xffe00000, 0xffc00000), .mnem = "lsr", RZTYPE(SHR), .ops = { AXAT(20), SHIFT1(16, 4) } },                       // LSR AX,#1..16
	{ OP(0xfff00000, 0xffe00000), .mnem = "b", RZTYPE(CJMP), .len = 4, .ops = { REL(0, 16), COND(16) } },              // B 16bitOffset,COND
	// clang-format on
