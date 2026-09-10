// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// The 0x56 prefix opens a second opcode page: the low byte of the first word
// selects the operation and the second word carries the loc16/loc32 field, a
// condition or a shift. Included from c28x_rows.inc.

// clang-format off
	{ OP(0xfffff000, 0x56000000), .mnem = "sub", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), LOC16(0), SHIFT(8, 4) }, RPTABLE },  // SUB ACC,loc16 << #1..15
	{ OP(0xffffff00, 0x56010000), .mnem = "addl", RZTYPE(ADD), .len = 4, .ops = { LOC32(0), REG(ACC) } },              // ADDL loc32,ACC
	{ OP(0xffffff00, 0x56020000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { REG(OVC), LOC16(0) } },               // MOV OVC,loc16
	{ OP(0xfffff000, 0x56040000), .mnem = "add", RZTYPE(ADD), .len = 4, .ops = { REG(ACC), LOC16(0), SHIFT(8, 4) }, RPTABLE },  // ADD ACC,loc16 << #1..15
	{ OP(0xffffff00, 0x56050000), .mnem = "impyl", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },      // IMPYL P,XT,loc32
	{ OP(0xffffff00, 0x56060000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { REG(ACC), LOC16(0), REG(T) } },       // MOV ACC,loc16 << T
	{ OP(0xffffff00, 0x5607c700), .mnem = "mac", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(0), INDR(XAR_NONE, 7) }, RPTABLE },    // MAC P,loc16,*XAR7
	{ OP(0xffffff00, 0x56078700), .mnem = "mac", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC16(0), INDR(XAR_POSTINC, 7) }, RPTABLE }, // MAC P,loc16,*XAR7++
	{ OP(0xffff0000, 0x56080000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFTC(16) } },     // AND ACC,#16bit << #16
	{ OP(0xfffff000, 0x56090000), .mnem = "tclr", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), BITN(8) } },               // TCLR loc16,#bit
	{ OP(0xffff0000, 0x560a0000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_POSTINC, 0) } },   // XBANZ pma,*++
	{ OP(0xffff0000, 0x560b0000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_POSTDEC, 0) } },   // XBANZ pma,*--
	{ OP(0xffff0000, 0x560c0000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP, 0) } },       // XBANZ pma,*
	{ OP(0xfffff000, 0x560d0000), .mnem = "tset", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), BITN(8) } },               // TSET loc16,#bit
	{ OP(0xffff0000, 0x560e0000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_IDX_INC, 0) } },   // XBANZ pma,*0++
	{ OP(0xffff0000, 0x560f0000), .mnem = "xbanz", RZTYPE(CJMP), .len = 4, .ops = { PMA(0, 16), IND(ARP_IDX_DEC, 0) } },   // XBANZ pma,*0--
	{ OP(0xffff0000, 0x56100000), .mnem = "asrl", RZTYPE(SAR), .ops = { REG(ACC), REG(T) } },                          // ASRL ACC,T
	{ OP(0xffffff00, 0x56110000), .mnem = "sqrs", RZTYPE(MUL), .len = 4, .ops = { LOC16(0) }, RPTABLE },               // SQRS loc16
	{ OP(0xffffff00, 0x56130000), .mnem = "zalr", RZTYPE(MOV), .len = 4, .ops = { REG(ACC), LOC16(0) }, RPTABLE },     // ZALR ACC,loc16
	{ OP(0xffff0000, 0x56140000), .mnem = "xb", RZTYPE(RJMP), .ops = { REG(AL) } },                                    // XB *AL
	{ OP(0xffffff00, 0x56150000), .mnem = "sqra", RZTYPE(MUL), .len = 4, .ops = { LOC16(0) }, RPTABLE },               // SQRA loc16
	{ OP(0xffff0000, 0x56160000), .mnem = "clrc", RZTYPE(NULL), .ops = { REG(AMODE) } },                               // CLRC AMODE (= C28ADDR)
	{ OP(0xffffff00, 0x56170000), .mnem = "subcul", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), LOC32(0) }, RPTABLE },   // SUBCUL ACC,loc32
	{ OP(0xffff0000, 0x56180000), .mnem = "cmpr", RZTYPE(CMP), .ops = { IMMC(2) } },                                   // CMPR 2
	{ OP(0xffff0000, 0x56190000), .mnem = "cmpr", RZTYPE(CMP), .ops = { IMMC(1) } },                                   // CMPR 1
	{ OP(0xffff0000, 0x561a0000), .mnem = "setc", RZTYPE(NULL), .ops = { REG(M0M1MAP) } },                             // SETC M0M1MAP (= C28MAP)
	{ OP(0xffff0000, 0x561b0000), .mnem = "clrc", RZTYPE(NULL), .ops = { REG(XF) } },                                  // CLRC XF
	{ OP(0xffff0000, 0x561c0000), .mnem = "cmpr", RZTYPE(CMP), .ops = { IMMC(3) } },                                   // CMPR 3
	{ OP(0xffff0000, 0x561d0000), .mnem = "cmpr", RZTYPE(CMP), .ops = { IMMC(0) } },                                   // CMPR 0
	{ OP(0xffff0000, 0x561e0000), .mnem = "lpaddr", RZTYPE(NULL) },                                                    // LPADDR
	{ OP(0xffff0000, 0x561f0000), .mnem = "setc", RZTYPE(NULL), .ops = { REG(OBJMODE) } },                             // SETC OBJMODE (= C28OBJ)
	{ OP(0xffff0000, 0x56200000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(ARP_POSTDEC, 0) } },             // NORM ACC,*--
	{ OP(0xffffff00, 0x56210000), .mnem = "movx", RZTYPE(MOV), .len = 4, .ops = { REG(TL), LOC16(0) } },               // MOVX TL,loc16
	{ OP(0xffff0000, 0x56220000), .mnem = "lsrl", RZTYPE(SHR), .ops = { REG(ACC), REG(T) } },                          // LSRL ACC,T
	{ OP(0xffffff00, 0x56230000), .mnem = "add", RZTYPE(ADD), .len = 4, .ops = { REG(ACC), LOC16(0), REG(T) } },       // ADD ACC,loc16 << T
	{ OP(0xffff0000, 0x56240000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(ARP, 0) } },                     // NORM ACC,*
	{ OP(0xffffff00, 0x56250000), .mnem = "tbit", RZTYPE(CMP), .len = 4, .ops = { LOC16(0), REG(T) } },                // TBIT loc16,T
	{ OP(0xffff0000, 0x56260000), .mnem = "setc", RZTYPE(NULL), .ops = { REG(XF) } },                                  // SETC XF
	{ OP(0xffffff00, 0x56270000), .mnem = "sub", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), LOC16(0), REG(T) } },       // SUB ACC,loc16 << T
	{ OP(0xffffff00, 0x56280000), .mnem = "movu", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), REG(OVC) } },              // MOVU loc16,OVC
	{ OP(0xffffff00, 0x56290000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), REG(OVC) } },               // MOV loc16,OVC
	{ OP(0xfffe0000, 0x562a0000), .mnem = "mov", RZTYPE(CMOV), .len = 4, .ops = { LOC16(0), AXAT(16), COND(8) } },        // MOV loc16,AX,COND
	{ OP(0xffff0000, 0x562c0000), .mnem = "asr64", RZTYPE(SAR), .ops = { REG(ACC_P), REG(T) } },                       // ASR64 ACC:P,T
	{ OP(0xfffff800, 0x562d0000), .mnem = "mov", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), REG(ACC), SHIFT(8, 3) }, RPTABLE },  // MOV loc16,ACC << 2..8
	{ OP(0xfffff800, 0x562f0000), .mnem = "movh", RZTYPE(MOV), .len = 4, .ops = { LOC16(0), REG(ACC), SHIFT(8, 3) }, RPTABLE }, // MOVH loc16,ACC << 2..8
	{ OP(0xffff0000, 0x56300000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(ARP_IDX_DEC, 0) } },             // NORM ACC,*0--
	{ OP(0xffff0000, 0x56320000), .mnem = "negtc", RZTYPE(NOT), .ops = { REG(ACC) } },                                 // NEGTC ACC
	{ OP(0xffff0000, 0x56330000), .mnem = "zapa", RZTYPE(MOV) },                                                       // ZAPA
	{ OP(0xffff0000, 0x56340000), .mnem = "xcall", RZTYPE(RCALL), .ops = { REG(AL) } },                                // XCALL *AL
	{ OP(0xffff0000, 0x56350000), .mnem = "csb", RZTYPE(MOV), .ops = { REG(ACC) } },                                   // CSB ACC
	{ OP(0xffff0000, 0x56360000), .mnem = "clrc", RZTYPE(NULL), .ops = { REG(OBJMODE) } },                             // CLRC OBJMODE (= C27OBJ)
	{ OP(0xfffe0000, 0x56380000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(PM), AXAT(16) } },                             // MOV PM,AX
	{ OP(0xffff0000, 0x563b0000), .mnem = "lsll", RZTYPE(SHL), .ops = { REG(ACC), REG(T) } },                          // LSLL ACC,T
	{ OP(0xffffff00, 0x563c0000), .mnem = "xpread", RZTYPE(LOAD), .len = 4, .ops = { LOC16(0), REG(AL) } },            // XPREAD loc16,*AL
	{ OP(0xffffff00, 0x563d0000), .mnem = "xpwrite", RZTYPE(STORE), .len = 4, .ops = { REG(AL), LOC16(0) } },          // XPWRITE *AL,loc16
	{ OP(0xffff0000, 0x563e0000), .mnem = "sat64", RZTYPE(MOV), .ops = { REG(ACC_P) } },                               // SAT64 ACC:P
	{ OP(0xffff0000, 0x563f0000), .mnem = "clrc", RZTYPE(NULL), .ops = { REG(M0M1MAP) } },                             // CLRC M0M1MAP (= C27MAP)
	{ OP(0xffffff00, 0x56400000), .mnem = "addcl", RZTYPE(ADD), .len = 4, .ops = { REG(ACC), LOC32(0) } },             // ADDCL ACC,loc32
	{ OP(0xffffff00, 0x56410000), .mnem = "subl", RZTYPE(SUB), .len = 4, .ops = { LOC32(0), REG(ACC) } },              // SUBL loc32,ACC
	{ OP(0xffffff00, 0x56420000), .mnem = "qmpyxul", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },    // QMPYXUL P,XT,loc32
	{ OP(0xffffff00, 0x56430000), .mnem = "impysl", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },     // IMPYSL P,XT,loc32
	{ OP(0xffffff00, 0x56440000), .mnem = "impyl", RZTYPE(MUL), .len = 4, .ops = { REG(ACC), REG(XT), LOC32(0) } },    // IMPYL ACC,XT,loc32
	{ OP(0xffffff00, 0x56450000), .mnem = "qmpysl", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },     // QMPYSL P,XT,loc32
	{ OP(0xffffff00, 0x56460000), .mnem = "qmpyal", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },     // QMPYAL P,XT,loc32
	{ OP(0xffffff00, 0x56470000), .mnem = "qmpyul", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },     // QMPYUL P,XT,loc32
	{ OP(0xfffff000, 0x56480000), .mnem = "movl", RZTYPE(CMOV), .len = 4, .ops = { LOC32(0), REG(ACC), COND(8) } },    // MOVL loc32,ACC,COND
	{ OP(0xffffff00, 0x56490000), .mnem = "subrl", RZTYPE(SUB), .len = 4, .ops = { LOC32(0), REG(ACC) } },             // SUBRL loc32,ACC
	{ OP(0xffff0000, 0x564a0000), .mnem = "or", RZTYPE(OR), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFTC(16) } },  // OR ACC,#16bit << #16
	{ OP(0xffffff00, 0x564bc700), .mnem = "dmac", RZTYPE(MUL), .len = 4, .ops = { REG(ACC_P), LOC32(0), INDR(XAR_NONE, 7) }, RPTABLE }, // DMAC ACC:P,loc32,*XAR7
	{ OP(0xffffff00, 0x564c0000), .mnem = "impyal", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },     // IMPYAL P,XT,loc32
	{ OP(0xffffff00, 0x564d8700), .mnem = "imacl", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC32(0), INDR(XAR_POSTINC, 7) }, RPTABLE }, // IMACL P,loc32,*XAR7++
	{ OP(0xffff0000, 0x564e0000), .mnem = "xor", RZTYPE(XOR), .len = 4, .ops = { REG(ACC), IMMU(0, 16), SHIFTC(16) } },// XOR ACC,#16bit << #16
	{ OP(0xffffff00, 0x564fc700), .mnem = "qmacl", RZTYPE(MUL), .len = 4, .ops = { REG(P), LOC32(0), INDR(XAR_NONE, 7) }, RPTABLE },    // QMACL P,loc32,*XAR7
	{ OP(0xffffff00, 0x56500000), .mnem = "minl", RZTYPE(MOV), .len = 4, .ops = { REG(ACC), LOC32(0) } },              // MINL ACC,loc32
	{ OP(0xffffff00, 0x56510000), .mnem = "maxcul", RZTYPE(MOV), .len = 4, .ops = { REG(P), LOC32(0) } },              // MAXCUL P,loc32
	{ OP(0xffff0000, 0x56520000), .mnem = "lsl64", RZTYPE(SHL), .ops = { REG(ACC_P), REG(T) } },                       // LSL64 ACC:P,T
	{ OP(0xffffff00, 0x56530000), .mnem = "addul", RZTYPE(ADD), .len = 4, .ops = { REG(ACC), LOC32(0) } },             // ADDUL ACC,loc32
	{ OP(0xffffff00, 0x56540000), .mnem = "subbl", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), LOC32(0) } },             // SUBBL ACC,loc32
	{ OP(0xffffff00, 0x56550000), .mnem = "subul", RZTYPE(SUB), .len = 4, .ops = { REG(ACC), LOC32(0) } },             // SUBUL ACC,loc32
	{ OP(0xffff0000, 0x56560000), .mnem = "mov", RZTYPE(MOV), .ops = { REG(TL), IMMC(0) } },                           // MOV TL,#0
	{ OP(0xffffff00, 0x56570000), .mnem = "addul", RZTYPE(ADD), .len = 4, .ops = { REG(P), LOC32(0) } },               // ADDUL P,loc32
	{ OP(0xffff0000, 0x56580000), .mnem = "neg64", RZTYPE(NOT), .ops = { REG(ACC_P) } },                               // NEG64 ACC:P
	{ OP(0xffffff00, 0x56590000), .mnem = "mincul", RZTYPE(MOV), .len = 4, .ops = { REG(P), LOC32(0) } },              // MINCUL P,loc32
	{ OP(0xffff0000, 0x565a0000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(ARP_POSTINC, 0) } },             // NORM ACC,*++
	{ OP(0xffff0000, 0x565b0000), .mnem = "lsr64", RZTYPE(SHR), .ops = { REG(ACC_P), REG(T) } },                       // LSR64 ACC:P,T
	{ OP(0xffff0000, 0x565c0000), .mnem = "zap", RZTYPE(MOV), .ops = { REG(OVC) } },                                   // ZAP OVC (= CLRC OVC)
	{ OP(0xffffff00, 0x565d0000), .mnem = "subul", RZTYPE(SUB), .len = 4, .ops = { REG(P), LOC32(0) } },               // SUBUL P,loc32
	{ OP(0xffff0000, 0x565e0000), .mnem = "cmp64", RZTYPE(CMP), .ops = { REG(ACC_P) } },                               // CMP64 ACC:P
	{ OP(0xffff0000, 0x565f0000), .mnem = "abstc", RZTYPE(ABS), .ops = { REG(ACC) } },                                 // ABSTC ACC
	{ OP(0xffffff00, 0x56610000), .mnem = "maxl", RZTYPE(MOV), .len = 4, .ops = { REG(ACC), LOC32(0) } },              // MAXL ACC,loc32
	{ OP(0xffffff00, 0x56620000), .mnem = "movu", RZTYPE(MOV), .len = 4, .ops = { REG(OVC), LOC16(0) } },              // MOVU OVC,loc16
	{ OP(0xffffff00, 0x56630000), .mnem = "qmpyl", RZTYPE(MUL), .len = 4, .ops = { REG(ACC), REG(XT), LOC32(0) } },    // QMPYL ACC,XT,loc32
	{ OP(0xffffff00, 0x56650000), .mnem = "impyxul", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },    // IMPYXUL P,XT,loc32
	{ OP(0xffffff00, 0x56670000), .mnem = "qmpyl", RZTYPE(MUL), .len = 4, .ops = { REG(P), REG(XT), LOC32(0) } },      // QMPYL P,XT,loc32
	{ OP(0xfffe0000, 0x56700000), .mnem = "flip", RZTYPE(MOV), .ops = { AXAT(16) } },                                     // FLIP AX
	{ OP(0xfffe0000, 0x56720000), .mnem = "max", RZTYPE(MOV), .len = 4, .ops = { AXAT(16), LOC16(0) }, RPTABLE },         // MAX AX,loc16
	{ OP(0xfffe0000, 0x56740000), .mnem = "min", RZTYPE(MOV), .len = 4, .ops = { AXAT(16), LOC16(0) }, RPTABLE },         // MIN AX,loc16
	{ OP(0xffff0000, 0x56770000), .mnem = "norm", RZTYPE(MOV), .ops = { REG(ACC), IND(ARP_IDX_INC, 0) } },             // NORM ACC,*0++
	{ OP(0xfff00000, 0x56800000), .mnem = "asr64", RZTYPE(SAR), .ops = { REG(ACC_P), SHIFT1(16, 4) } },                // ASR64 ACC:P,#1..16
	{ OP(0xfff00000, 0x56900000), .mnem = "lsr64", RZTYPE(SHR), .ops = { REG(ACC_P), SHIFT1(16, 4) } },                // LSR64 ACC:P,#1..16
	{ OP(0xfff00000, 0x56a00000), .mnem = "lsl64", RZTYPE(SHL), .ops = { REG(ACC_P), SHIFT1(16, 4) } },                // LSL64 ACC:P,#1..16
	{ OP(0xfff00000, 0x56b00000), .mnem = "movb", RZTYPE(CMOV), .len = 4, .ops = { LOC16(0), IMMU(8, 8), COND(16) } }, // MOVB loc16,#8bit,COND
	{ OP(0xfff00000, 0x56c00000), .mnem = "bf", RZTYPE(CJMP), .len = 4, .ops = { REL(0, 16), COND(16) } },             // BF 16bitOffset,COND
	{ OP(0xfff00000, 0x56d00000), .mnem = "xb", RZTYPE(JMP), .len = 4, .ops = { PMA(0, 16), COND(16) } },              // XB pma,COND
	{ OP(0xfff00000, 0x56e00000), .mnem = "xcall", RZTYPE(CALL), .len = 4, .ops = { PMA(0, 16), COND(16) } },          // XCALL pma,COND
	{ OP(0xffff0000, 0x56ff0000), .mnem = "xret", RZTYPE(RET) },                                                       // XRET (= XRETC UNC)
	{ OP(0xfff00000, 0x56f00000), .mnem = "xretc", RZTYPE(CRET), .ops = { COND(16) } },                                // XRETC COND
	// clang-format on
