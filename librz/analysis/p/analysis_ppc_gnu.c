// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

// NOTE: buf should be at least 16 bytes!
// XXX addr should be off_t for 64 love
static int ppc_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *bytes, int len, RzAnalysisOpMask mask) {
	//int arch_ppc_op(ut64 addr, const u8 *bytes, struct op_t *op)
	// XXX hack
	int opcode = (bytes[0] & 0xf8) >> 3; // bytes 0-5
	short baddr = ((bytes[2] << 8) | (bytes[3] & 0xfc)); // 16-29
	int aa = bytes[3] & 0x2;
	int lk = bytes[3] & 0x1;
	//if (baddr>0x7fff)
	//      baddr = -baddr;

	op->addr = addr;
	op->type = 0;
	op->size = 4;

	//eprintf("OPCODE IS %08x : %02x (opcode=%d) baddr = %d\n", addr, bytes[0], opcode, baddr);

	switch (opcode) {
		//	case 0: // bl op->type = RZ_ANALYSIS_OP_TYPE_NOP; break;
	case 11: // cmpi
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case 9: // pure branch
		if (bytes[0] == 0x4e) {
			// bctr
		} else {
			op->jump = (aa) ? (baddr) : (addr + baddr);
			if (lk) {
				op->fail = addr + 4;
			}
		}
		op->eob = 1;
		break;
	case 6: // bc // conditional jump
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (aa) ? (baddr) : (addr + baddr + 4);
		op->eob = 1;
		break;
#if 0
	case 7: // sc/svc
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
#endif
#if 0
	case 15: // bl
		// OK
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = (aa)?(baddr):(addr+baddr);
		op->fail = addr+4;
		op->eob = 1;
		break;
#endif
	case 8: // bne i tal
		// OK
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = (aa) ? (baddr) : (addr + baddr + 4);
		op->fail = addr + 4;
		op->eob = 1;
		break;
	case 19: // bclr/bcr/bcctr/bcc
		op->type = RZ_ANALYSIS_OP_TYPE_RET; // jump to LR
		if (lk) {
			op->jump = 0xFFFFFFFF; // LR ?!?
			op->fail = addr + 4;
		}
		op->eob = 1;
		break;
	}
	op->size = 4;
	return op->size;
}

static bool set_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	srr0\n"
		"=SR	srr1\n" // status register
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
#if 0
	"=a4	r4\n"
	"=a5	r5\n"
	"=a6	r6\n"
	"=a7	r7\n"
#endif
		"gpr	srr0	.32	0	0\n"
		"gpr	srr1	.32	4	0\n"
		"gpr	r0	.32	8	0\n"
		"gpr	r1	.32	12	0\n"
		"gpr	r2	.32	16	0\n"
		"gpr	r3	.32	20	0\n"
		"gpr	r4	.32	24	0\n"
		"gpr	r5	.32	28	0\n"
		"gpr	r6	.32	32	0\n"
		"gpr	r7	.32	36	0\n"
		"gpr	r8	.32	40	0\n"
		"gpr	r9	.32	44	0\n"
		"gpr	r10	.32	48	0\n"
		"gpr	r11	.32	52	0\n"
		"gpr	r12	.32	56	0\n"
		"gpr	r13	.32	60	0\n"
		"gpr	r14	.32	64	0\n"
		"gpr	r15	.32	68	0\n"
		"gpr	r16	.32	72	0\n"
		"gpr	r17	.32	76	0\n"
		"gpr	r18	.32	80	0\n"
		"gpr	r19	.32	84	0\n"
		"gpr	r20	.32	88	0\n"
		"gpr	r21	.32	92	0\n"
		"gpr	r22	.32	96	0\n"

		"gpr	r23	.32	100	0\n"
		"gpr	r24	.32	104	0\n"
		"gpr	r25	.32	108	0\n"
		"gpr	r26	.32	112	0\n"
		"gpr	r27	.32	116	0\n"
		"gpr	r28	.32	120	0\n"
		"gpr	r29	.32	124	0\n"
		"gpr	r30	.32	128	0\n"
		"gpr	r31	.32	132	0\n"
		"gpr	cr	.32	136	0\n"
		"gpr	xer	.32	140	0\n"
		"gpr	lr	.32	144	0\n"
		"gpr	ctr	.32	148	0\n"
		"gpr	mq	.32	152	0\n"
		"gpr	vrsave	.32	156	0\n";
	return rz_reg_set_profile_string(analysis->reg, p);
}

static int archinfo(RzAnalysis *analysis, int q) {
	return 4; /* :D */
}

RzAnalysisPlugin rz_analysis_plugin_ppc_gnu = {
	.name = "ppc.gnu",
	.desc = "PowerPC analysis plugin",
	.license = "LGPL3",
	.arch = "ppc",
	.archinfo = archinfo,
	.bits = 32 | 64,
	.op = &ppc_op,
	.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_ppc_gnu,
	.version = RZ_VERSION
};
#endif

#if 0
NOTES:
======
     10000
     AA = absolute address
     LK = link bit
     BD = bits 16-19
       address
     if (AA) {
       address = (int32) BD << 2
     } else {
       address += (int32) BD << 2
     }
    AA LK
    30 31
     0  0  bc
     1  0  bca
     0  1  bcl
     1  1  bcla

     10011
     BCCTR
     LK = 31

     bclr or bcr (Branch Conditional Link Register) Instruction
     10011

     6-29 -> LL (addr) ?
     B  10010 -> branch
     30 31
     0  0   b
     1  0   ba
     0  1   bl
     1  1   bla
     SC SYSCALL 5 first bytes 10001
     SVC SUPERVISORCALL
     30 31
     0  0  svc
     0  1  svcl
     1  0  svca
     1  1  svcla
#endif
