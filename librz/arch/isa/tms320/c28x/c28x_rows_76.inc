// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// The 0x76 prefix opens the status/stack and long-call opcode page: the low
// byte of the first word selects the operation outright. Included from
// c28x_rows.inc.

// clang-format off
	{ OP(0xffff0000, 0x76000000), .mnem = "pop", RZTYPE(POP), .ops = { REG(ST1) } },              // POP ST1
	{ OP(0xffff0000, 0x76010000), .mnem = "pop", RZTYPE(POP), .ops = { REG(DP_ST1) } },           // POP DP:ST1
	{ OP(0xffff0000, 0x76020000), .mnem = "iret", RZTYPE(RET) },                                  // IRET
	{ OP(0xffff0000, 0x76030000), .mnem = "pop", RZTYPE(POP), .ops = { REG(DP) } },               // POP DP
	{ OP(0xffff0000, 0x76040000), .mnem = "lc", RZTYPE(RCALL), .ops = { INDR(XAR_NONE, 7) } },     // LC *XAR7
	{ OP(0xffff0000, 0x76050000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR3_AR2) } },          // POP AR3:AR2
	{ OP(0xffff0000, 0x76060000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR5_AR4) } },          // POP AR5:AR4
	{ OP(0xffff0000, 0x76070000), .mnem = "pop", RZTYPE(POP), .ops = { REG(AR1_AR0) } },          // POP AR1:AR0
	{ OP(0xffff0000, 0x76080000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(ST1) } },            // PUSH ST1
	{ OP(0xffff0000, 0x76090000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(DP_ST1) } },         // PUSH DP:ST1
	{ OP(0xffff0000, 0x760a0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(IFR) } },            // PUSH IFR
	{ OP(0xffff0000, 0x760b0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(DP) } },             // PUSH DP
	{ OP(0xffff0000, 0x760c0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(AR5_AR4) } },        // PUSH AR5:AR4
	{ OP(0xffff0000, 0x760d0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(AR1_AR0) } },        // PUSH AR1:AR0
	{ OP(0xffff0000, 0x760e0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(DBGIER) } },         // PUSH DBGIER
	{ OP(0xffff0000, 0x760f0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(AR3_AR2) } },        // PUSH AR3:AR2
	{ OP(0xffff0000, 0x76100000), .mnem = "lrete", RZTYPE(RET) },                                 // LRETE
	{ OP(0xffff0000, 0x76110000), .mnem = "pop", RZTYPE(POP), .ops = { REG(P) } },                // POP P
	{ OP(0xffff0000, 0x76120000), .mnem = "pop", RZTYPE(POP), .ops = { REG(DBGIER) } },           // POP DBGIER
	{ OP(0xffff0000, 0x76130000), .mnem = "pop", RZTYPE(POP), .ops = { REG(ST0) } },              // POP ST0
	{ OP(0xffff0000, 0x76140000), .mnem = "lret", RZTYPE(RET) },                                  // LRET
	{ OP(0xffff0000, 0x76150000), .mnem = "pop", RZTYPE(POP), .ops = { REG(T_ST0) } },            // POP T:ST0
	{ OP(0xffff0000, 0x76160000), .mnem = "intr", RZTYPE(SWI), .ops = { REG(NMI) } },             // INTR NMI
	{ OP(0xffff0000, 0x76170000), .mnem = "nasp", RZTYPE(SUB) },                                  // NASP
	{ OP(0xffff0000, 0x76180000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(ST0) } },            // PUSH ST0
	{ OP(0xffff0000, 0x76190000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(T_ST0) } },          // PUSH T:ST0
	{ OP(0xffff0000, 0x761a0000), .mnem = "edis", RZTYPE(NULL) },                                 // EDIS
	{ OP(0xffff0000, 0x761b0000), .mnem = "asp", RZTYPE(ADD) },                                   // ASP
	{ OP(0xffff0000, 0x761c0000), .mnem = "intr", RZTYPE(SWI), .ops = { REG(EMUINT) } },          // INTR EMUINT
	{ OP(0xffff0000, 0x761d0000), .mnem = "push", RZTYPE(PUSH), .ops = { REG(P) } },              // PUSH P
	{ OP(0xffff0000, 0x761f0000), .mnem = "movw", RZTYPE(MOV), .len = 4, .ops = { REG(DP), IMMU(0, 16) } }, // MOVW DP,#16bit
	{ OP(0xffff0000, 0x76200000), .mnem = "lb", RZTYPE(RJMP), .ops = { INDR(XAR_NONE, 7) } },      // LB *XAR7
	{ OP(0xffff0000, 0x76210000), .mnem = "idle", RZTYPE(NULL) },                                 // IDLE
	{ OP(0xffff0000, 0x76220000), .mnem = "eallow", RZTYPE(NULL) },                               // EALLOW
	{ OP(0xffff0000, 0x76230000), .mnem = "or", RZTYPE(OR), .len = 4, .ops = { REG(IER), IMMU(0, 16) } },   // OR IER,#16bit
	{ OP(0xffff0000, 0x76240000), .mnem = "estop1", RZTYPE(TRAP) },                               // ESTOP1
	{ OP(0xffff0000, 0x76250000), .mnem = "estop0", RZTYPE(TRAP) },                               // ESTOP0
	{ OP(0xffff0000, 0x76260000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { REG(IER), IMMU(0, 16) } },  // AND IER,#16bit
	{ OP(0xffff0000, 0x76270000), .mnem = "or", RZTYPE(OR), .len = 4, .ops = { REG(IFR), IMMU(0, 16) } },    // OR IFR,#16bit
	{ OP(0xffff0000, 0x762f0000), .mnem = "and", RZTYPE(AND), .len = 4, .ops = { REG(IFR), IMMU(0, 16) } },  // AND IFR,#16bit
	{ OP(0xffff0000, 0x763f0000), .mnem = "iack", RZTYPE(IO), .len = 4, .ops = { IMMU(0, 16) } }, // IACK #16bit
	{ OP(0xffc00000, 0x76400000), .mnem = "lcr", RZTYPE(CALL), .len = 4, .ops = { PMA(0, 22) } }, // LCR #22bit
	{ OP(0xffc00000, 0x76800000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR6), IMMU(0, 22) } },        // MOVL XAR6,#22bit
	{ OP(0xffc00000, 0x76c00000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR7), IMMU(0, 22) } },        // MOVL XAR7,#22bit
	{ OP(0xffc00000, 0x8d000000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR0), IMMU(0, 22) } },        // MOVL XAR0,#22bit
	{ OP(0xffc00000, 0x8d400000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR1), IMMU(0, 22) } },        // MOVL XAR1,#22bit
	{ OP(0xffc00000, 0x8d800000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR2), IMMU(0, 22) } },        // MOVL XAR2,#22bit
	{ OP(0xffc00000, 0x8dc00000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR3), IMMU(0, 22) } },        // MOVL XAR3,#22bit
	{ OP(0xffc00000, 0x8f000000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR4), IMMU(0, 22) } },        // MOVL XAR4,#22bit
	{ OP(0xffc00000, 0x8f400000), .mnem = "movl", RZTYPE(MOV), .len = 4, .ops = { REG(XAR5), IMMU(0, 22) } },        // MOVL XAR5,#22bit
	// clang-format on
