// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/ppc.h>
#include "ppc/libvle/vle.h"
#include "ppc/ppc_analysis.h"
#include "ppc/ppc_il.h"
#include "rz_util/rz_strbuf.h"

#define SPR_HID0 0x3f0 /* Hardware Implementation Register 0 */
#define SPR_HID1 0x3f1 /* Hardware Implementation Register 1 */
#define SPR_HID2 0x3f3 /* Hardware Implementation Register 2 */
#define SPR_HID4 0x3f4 /* Hardware Implementation Register 4 */
#define SPR_HID5 0x3f6 /* Hardware Implementation Register 5 */
#define SPR_HID6 0x3f9 /* Hardware Implementation Register 6 */

struct Getarg {
	csh handle;
	cs_insn *insn;
	int bits;
};

#ifndef PFMT32x
#define PFMT32x "lx"
#endif

static ut64 mask64(ut64 mb, ut64 me) {
	ut64 maskmb = UT64_MAX >> mb;
	ut64 maskme = UT64_MAX << (63 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

static ut32 mask32(ut32 mb, ut32 me) {
	ut32 maskmb = UT32_MAX >> mb;
	ut32 maskme = UT32_MAX << (31 - me);
	return (mb <= me) ? maskmb & maskme : maskmb | maskme;
}

typedef struct {
	char cmask1[32];
	char cmask2[32];
	char words[8][64];
	char cspr[16];
	csh handle;
	int omode;
	int obits;
} PPCContext;

static bool ppc_init(void **user) {
	PPCContext *ctx = RZ_NEW0(PPCContext);
	if (!ctx) {
		return false;
	}
	ctx->handle = 0;
	ctx->omode = -1;
	ctx->obits = -1;
	*user = ctx;
	return true;
}

static const char *cmask64(RzAnalysis *a, const char *mb_c, const char *me_c) {
	PPCContext *ctx = (PPCContext *)a->plugin_data;
	ut64 mb = 0;
	ut64 me = 0;
	if (mb_c) {
		mb = strtol(mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol(me_c, NULL, 16);
	}
	snprintf(ctx->cmask1, sizeof(ctx->cmask1), "0x%" PFMT64x "", mask64(mb, me));
	return ctx->cmask1;
}

static const char *cmask32(RzAnalysis *a, const char *mb_c, const char *me_c) {
	PPCContext *ctx = (PPCContext *)a->plugin_data;
	ut32 mb = 0;
	ut32 me = 0;
	if (mb_c) {
		mb = strtol(mb_c, NULL, 16);
	}
	if (me_c) {
		me = strtol(me_c, NULL, 16);
	}
	snprintf(ctx->cmask2, sizeof(ctx->cmask2), "0x%" PFMT32x "", mask32(mb, me));
	return ctx->cmask2;
}

static char *getarg2(RzAnalysis *a, struct Getarg *gop, int n, const char *setstr) {
	PPCContext *ctx = (PPCContext *)a->plugin_data;
	cs_insn *insn = gop->insn;
	csh handle = gop->handle;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return NULL;
	}
	op = INSOP(n);
	switch (op.type) {
	case PPC_OP_INVALID:
		ctx->words[n][0] = '\0';
		// strcpy (words[n], "invalid");
		break;
	case PPC_OP_REG:
		snprintf(ctx->words[n], sizeof(ctx->words[n]),
			"%s%s", cs_reg_name(handle, op.reg), setstr);
		break;
	case PPC_OP_IMM:
		snprintf(ctx->words[n], sizeof(ctx->words[n]),
			"0x%" PFMT64x "%s", (ut64)op.imm, setstr);
		break;
	case PPC_OP_MEM:
		snprintf(ctx->words[n], sizeof(ctx->words[n]),
			"%" PFMT64d ",%s,+,%s",
			(ut64)op.mem.disp,
			cs_reg_name(handle, op.mem.base), setstr);
		break;
#if CS_NEXT_VERSION < 6
	case PPC_OP_CRX: // Condition Register field
		snprintf(ctx->words[n], sizeof(ctx->words[n]),
			"%" PFMT64d "%s", (ut64)op.imm, setstr);
		break;
#endif
	}
	return ctx->words[n];
}

static ut64 getarg(struct Getarg *gop, int n) {
	ut64 value = 0;
	cs_insn *insn = gop->insn;
	cs_ppc_op op;

	if (n < 0 || n >= 8) {
		return 0;
	}

	op = INSOP(n);
	switch (op.type) {
	case PPC_OP_INVALID:
		break;
	case PPC_OP_REG:
		value = op.reg;
		break;
	case PPC_OP_IMM:
		value = (ut64)op.imm;
		break;
	case PPC_OP_MEM:
		value = op.mem.disp + op.mem.base;
		break;
#if CS_NEXT_VERSION < 6
	case PPC_OP_CRX: // Condition Register field
		value = (ut64)op.imm;
		break;
#endif
	}
	return value;
}

static const char *getspr(RzAnalysis *a, struct Getarg *gop, int n) {
	PPCContext *ctx = (PPCContext *)a->plugin_data;
	ut32 spr = 0;
	if (n < 0 || n >= 8) {
		return NULL;
	}
	spr = getarg(gop, 0);
	switch (spr) {
	case SPR_HID0:
		return "hid0";
	case SPR_HID1:
		return "hid1";
	case SPR_HID2:
		return "hid2";
	case SPR_HID4:
		return "hid4";
	case SPR_HID5:
		return "hid5";
	case SPR_HID6:
		return "hid6";
	default:
		snprintf(ctx->cspr, sizeof(ctx->cspr), "spr_%u", spr);
		break;
	}
	return ctx->cspr;
}

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_ppc *x = &insn->detail->ppc;
	for (i = 0; i < x->op_count; i++) {
		cs_ppc_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case PPC_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case PPC_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case PPC_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != PPC_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_ki(pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		pj_end(pj); /* o operand */
	}
	pj_end(pj); /* a operands */
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
}

#define PPCSPR(n)  getspr(a, &gop, n)
#define ARG(n)     getarg2(a, &gop, n, "")
#define ARG2(n, m) getarg2(a, &gop, n, m)

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	if (analysis->bits == 64) {
		p =
			"=PC	pc\n"
			"=SP	r1\n"
			"=BP	r31\n"
			"=SN	r3\n" // also for ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"=OF	ov\n"
			"=CF	ca\n"

			"gpr	r0	.64	0	0	\n"
			"gpr	r1	.64	8	0	\n"
			"gpr	r2	.64	16	0	\n"
			"gpr	r3	.64	24	0	\n"
			"gpr	r4	.64	32	0	\n"
			"gpr	r5	.64	40	0	\n"
			"gpr	r6	.64	48	0	\n"
			"gpr	r7	.64	56	0	\n"
			"gpr	r8	.64	64	0	\n"
			"gpr	r9	.64	72	0	\n"
			"gpr	r10	.64	80	0	\n"
			"gpr	r11	.64	88	0	\n"
			"gpr	r12	.64	96	0	\n"
			"gpr	r13	.64	104	0	\n"
			"gpr	r14	.64	112	0	\n"
			"gpr	r15	.64	120	0	\n"
			"gpr	r16	.64	128	0	\n"
			"gpr	r17	.64	136	0	\n"
			"gpr	r18	.64	144	0	\n"
			"gpr	r19	.64	152	0	\n"
			"gpr	r20	.64	160	0	\n"
			"gpr	r21	.64	168	0	\n"
			"gpr	r22	.64	176	0	\n"
			"gpr	r23	.64	184	0	\n"
			"gpr	r24	.64	192	0	\n"
			"gpr	r25	.64	200	0	\n"
			"gpr	r26	.64	208	0	\n"
			"gpr	r27	.64	216	0	\n"
			"gpr	r28	.64	224	0	\n"
			"gpr	r29	.64	232	0	\n"
			"gpr	r30	.64	240	0	\n"
			"gpr	r31	.64	248	0	\n"
			"vc	vs0	.128	256	0	\n"
			"vc	vs1	.128	272	0	\n"
			"vc	vs2	.128	288	0	\n"
			"vc	vs3	.128	304	0	\n"
			"vc	vs4	.128	320	0	\n"
			"vc	vs5	.128	336	0	\n"
			"vc	vs6	.128	352	0	\n"
			"vc	vs7	.128	368	0	\n"
			"vc	vs8	.128	384	0	\n"
			"vc	vs9	.128	400	0	\n"
			"vc	vs10	.128	416	0	\n"
			"vc	vs11	.128	432	0	\n"
			"vc	vs12	.128	448	0	\n"
			"vc	vs13	.128	464	0	\n"
			"vc	vs14	.128	480	0	\n"
			"vc	vs15	.128	496	0	\n"
			"vc	vs16	.128	512	0	\n"
			"vc	vs17	.128	528	0	\n"
			"vc	vs18	.128	544	0	\n"
			"vc	vs19	.128	560	0	\n"
			"vc	vs20	.128	576	0	\n"
			"vc	vs21	.128	592	0	\n"
			"vc	vs22	.128	608	0	\n"
			"vc	vs23	.128	624	0	\n"
			"vc	vs24	.128	640	0	\n"
			"vc	vs25	.128	656	0	\n"
			"vc	vs26	.128	672	0	\n"
			"vc	vs27	.128	688	0	\n"
			"vc	vs28	.128	704	0	\n"
			"vc	vs29	.128	720	0	\n"
			"vc	vs30	.128	736	0	\n"
			"vc	vs31	.128	752	0	\n"
			"vc	vs32	.128	768	0	\n"
			"vc	vs33	.128	784	0	\n"
			"vc	vs34	.128	800	0	\n"
			"vc	vs35	.128	816	0	\n"
			"vc	vs36	.128	832	0	\n"
			"vc	vs37	.128	848	0	\n"
			"vc	vs38	.128	864	0	\n"
			"vc	vs39	.128	880	0	\n"
			"vc	vs40	.128	896	0	\n"
			"vc	vs41	.128	912	0	\n"
			"vc	vs42	.128	928	0	\n"
			"vc	vs43	.128	944	0	\n"
			"vc	vs44	.128	960	0	\n"
			"vc	vs45	.128	976	0	\n"
			"vc	vs46	.128	992	0	\n"
			"vc	vs47	.128	1008	0	\n"
			"vc	vs48	.128	1024	0	\n"
			"vc	vs49	.128	1040	0	\n"
			"vc	vs50	.128	1056	0	\n"
			"vc	vs51	.128	1072	0	\n"
			"vc	vs52	.128	1088	0	\n"
			"vc	vs53	.128	1104	0	\n"
			"vc	vs54	.128	1120	0	\n"
			"vc	vs55	.128	1136	0	\n"
			"vc	vs56	.128	1152	0	\n"
			"vc	vs57	.128	1168	0	\n"
			"vc	vs58	.128	1184	0	\n"
			"vc	vs59	.128	1200	0	\n"
			"vc	vs60	.128	1216	0	\n"
			"vc	vs61	.128	1232	0	\n"
			"vc	vs62	.128	1248	0	\n"
			"vc	vs63	.128	1264	0	\n"
			"fpu	f0	.64	1280	0	\n"
			"fpu	f1	.64	1288	0	\n"
			"fpu	f2	.64	1296	0	\n"
			"fpu	f3	.64	1304	0	\n"
			"fpu	f4	.64	1312	0	\n"
			"fpu	f5	.64	1320	0	\n"
			"fpu	f6	.64	1328	0	\n"
			"fpu	f7	.64	1336	0	\n"
			"fpu	f8	.64	1344	0	\n"
			"fpu	f9	.64	1352	0	\n"
			"fpu	f10	.64	1360	0	\n"
			"fpu	f11	.64	1368	0	\n"
			"fpu	f12	.64	1376	0	\n"
			"fpu	f13	.64	1384	0	\n"
			"fpu	f14	.64	1392	0	\n"
			"fpu	f15	.64	1400	0	\n"
			"fpu	f16	.64	1408	0	\n"
			"fpu	f17	.64	1416	0	\n"
			"fpu	f18	.64	1424	0	\n"
			"fpu	f19	.64	1432	0	\n"
			"fpu	f20	.64	1440	0	\n"
			"fpu	f21	.64	1448	0	\n"
			"fpu	f22	.64	1456	0	\n"
			"fpu	f23	.64	1464	0	\n"
			"fpu	f24	.64	1472	0	\n"
			"fpu	f25	.64	1480	0	\n"
			"fpu	f26	.64	1488	0	\n"
			"fpu	f27	.64	1496	0	\n"
			"fpu	f28	.64	1504	0	\n"
			"fpu	f29	.64	1512	0	\n"
			"fpu	f30	.64	1520	0	\n"
			"fpu	f31	.64	1528	0	\n"
			"vc	v0	.128	1536	0	\n"
			"vc	v1	.128	1552	0	\n"
			"vc	v2	.128	1568	0	\n"
			"vc	v3	.128	1584	0	\n"
			"vc	v4	.128	1600	0	\n"
			"vc	v5	.128	1616	0	\n"
			"vc	v6	.128	1632	0	\n"
			"vc	v7	.128	1648	0	\n"
			"vc	v8	.128	1664	0	\n"
			"vc	v9	.128	1680	0	\n"
			"vc	v10	.128	1696	0	\n"
			"vc	v11	.128	1712	0	\n"
			"vc	v12	.128	1728	0	\n"
			"vc	v13	.128	1744	0	\n"
			"vc	v14	.128	1760	0	\n"
			"vc	v15	.128	1776	0	\n"
			"vc	v16	.128	1792	0	\n"
			"vc	v17	.128	1808	0	\n"
			"vc	v18	.128	1824	0	\n"
			"vc	v19	.128	1840	0	\n"
			"vc	v20	.128	1856	0	\n"
			"vc	v21	.128	1872	0	\n"
			"vc	v22	.128	1888	0	\n"
			"vc	v23	.128	1904	0	\n"
			"vc	v24	.128	1920	0	\n"
			"vc	v25	.128	1936	0	\n"
			"vc	v26	.128	1952	0	\n"
			"vc	v27	.128	1968	0	\n"
			"vc	v28	.128	1984	0	\n"
			"vc	v29	.128	2000	0	\n"
			"vc	v30	.128	2016	0	\n"
			"vc	v31	.128	2032	0	\n"
			"ctr	xer	.64	2048	0	# Fixed-Point Exception Register\n"
			"vcc	vrsave	.32	2056	0	# VR Save Register\n"
			"ctr	fpscr	.64	2060	0	# Floating-Point Status and Control Register\n"
			"vcc	vscr	.32	2068	0	# Vector Status and Control Register\n"
			"ctr	cr	.32	2072	0	# Condition Register\n"
			"ctr	lr	.64	2076	0	# Link Register\n"
			"ctr	ctr	.64	2084	0	# Count Register\n"
			"ctr	tar	.64	2092	0	# Target Address Register\n"
			"ctr	ppr	.64	2100	0	# Process Priority Register\n"
			"ctr	dscr	.64	2108	0	# Data Stream Control Register\n"
			"ctr	bescr	.64	2116	0	# Branch Event Status and Control Register\n"
			"ctr	ebbhr	.64	2124	0	# Event-Based Branch Handler Register\n"
			"ctr	ebbrr	.64	2132	0	# Event-Based Branch Return Register\n"
			"ctr	lpcr	.64	2140	0	# Logical Partitioning Control Register\n"
			"ctr	hrmor	.64	2148	0	# Hypervisor Real Mode Offset Register\n"
			"ctr	lpidr	.32	2156	0	# Logical Partition Identification Regiser\n"
			"ctr	pcr	.64	2160	0	# Processor Compatibility Register\n"
			"ctr	tir	.64	2168	0	# Thread Identification Register\n"
			"ctr	urmor	.64	2176	0	# Ultravisor Real Mode Offset Register\n"
			"ctr	smfctrl	.64	2184	0	# Secure Memory Facility Control Register\n"
			"ctr	msr	.64	2192	0	# Machine State Register\n"
			"ctr	pvr	.32	2200	0	# Processor Version Register\n"
			"ctr	pir	.32	2204	0	# Processor Version Register\n"
			"ctr	pidr	.32	2208	0	# Processor Identification Register\n"
			"ctr	ctrl	.32	2212	0	# Control Register\n"
			"ctr	pspb	.32	2216	0	# Problem State Priority Boost Register\n"
			"ctr	rpr	.64	2220	0	# Relative Priority Register\n"
			"ctr	hashkey	.64	2228	0	# Hash Key Register\n"
			"ctr	hashpkey	.64	2236	0	# Hash Privileged Key Register\n"
			"ctr	sprg0	.64	2244	0	# Software-use SPR 0\n"
			"ctr	sprg1	.64	2252	0	# Software-use SPR 1\n"
			"ctr	sprg2	.64	2260	0	# Software-use SPR 2\n"
			"ctr	sprg3	.64	2268	0	# Software-use SPR 3\n"
			"ctr	hsprg0	.64	2276	0	# Hypervisor Software-use SPR 0\n"
			"ctr	hsprg1	.64	2284	0	# Hypervisor Software-use SPR 1\n"
			"ctr	usprg0	.64	2292	0	# Ultravisor Software-use SPR 0\n"
			"ctr	usprg1	.64	2300	0	# Ultravisor Software-use SPR 1\n"
			"ctr	srr0	.64	2308	0	# Machine Status Save/Restore Register 0\n"
			"ctr	srr1	.64	2316	0	# Machine Status Save/Restore Register 1\n"
			"ctr	hsrr0	.64	2324	0	# Hypervisor Machine Status Save/Restore Register 0\n"
			"ctr	hsrr1	.64	2332	0	# Hypervisor Machine Status Save/Restore Register 1\n"
			"ctr	usrr0	.64	2340	0	# Hypervisor Machine Status Save/Restore Register 0\n"
			"ctr	usrr1	.64	2348	0	# Ultravisor Machine Status Save/Restore Register 1\n"
			"ctr	asdr	.64	2356	0	# Access Segment Descriptor Register\n"
			"ctr	dar	.64	2364	0	# Data Address Register\n"
			"ctr	hdar	.64	2372	0	# Hypervisor Data Address Register\n"
			"ctr	dsisr	.32	2380	0	# Data Storage Interrupt Status Register\n"
			"ctr	hdsisr	.32	2384	0	# Hypervisor Data Storage Interrupt Status Register\n"
			"ctr	heir	.64	2388	0	# Hypervisor Emulation Instruction Register\n"
			"ctr	hmer	.64	2396	0	# Hypervisor Maintenance Exception Register\n"
			"ctr	hmeer	.64	2404	0	# Hypervisor Maintenance Exception Enable Register\n"
			"ctr	fscr	.64	2412	0	# Facility Status and Control Register\n"
			"ctr	hfscr	.64	2420	0	# Hypervisor Facility Status and Control Register\n"
			"ctr	purr	.64	2428	0	# Process Utilization of Resources Register\n"
			"ctr	spurr	.64	2436	0	# Scaled Process Utilization of Resources Register\n"
			"ctr	dexcr	.64	2444	0	# Dynamic Execution Control Register\n"
			"ctr	hdexcr	.64	2452	0	# Hypervisor Dynamic Execution Control Register\n"
			"ctr	udexcr	.64	2460	0	# Ultravisor Dynamic Execution Control Register\n"
			"ctr	cfar	.64	2468	0	# Come-From Address Register\n"
			"ctr	mmcr0	.64	2476	0	# Monitor Mode Control Register 0\n"
			"ctr	mmcr1	.64	2484	0	# Monitor Mode Control Register 1\n"
			"ctr	mmcr2	.64	2492	0	# Monitor Mode Control Register 2\n"
			"ctr	mmcra	.64	2500	0	# Monitor Mode Control Register A\n"
			"ctr	siar	.64	2508	0	# Sampled Instruction Address Register\n"
			"ctr	sdar	.64	2516	0	# Sampled Data Address Register\n"
			"ctr	sier	.64	2524	0	# Sampled Instruction Event Register\n"
			"ctr	sier2	.64	2532	0	# Sampled Instruction Event Register 2\n"
			"ctr	sier3	.64	2540	0	# Sampled Instruction Event Register 3\n"
			"ctr	mmcr3	.64	2548	0	# Monitor Mode Control Register 2\n"
			"ctr	dpdes	.64	2556	0	# Directed Privileged Doorbell Exception State Register\n"
			"ctr	pc	.64	2564	0	# Programm Counter\n"
			"ctr	cr0	.4	2572	0	# Condition Register Field 0\n"
			"ctr	cr1	.4	2573	0	# Condition Register Field 1\n"
			"ctr	cr2	.4	2574	0	# Condition Register Field 2\n"
			"ctr	cr3	.4	2575	0	# Condition Register Field 3\n"
			"ctr	cr4	.4	2576	0	# Condition Register Field 4\n"
			"ctr	cr5	.4	2577	0	# Condition Register Field 5\n"
			"ctr	cr6	.4	2578	0	# Condition Register Field 6\n"
			"ctr	cr7	.4	2579	0	# Condition Register Field 7\n"
			"ctr	ppr32	.32	2580	0	# Process Priority Register 32-bit\n"
			"flg	so	.1	2584	0	# Summary Overflow\n"
			"flg	ov	.1	2585	0	# Overflow\n"
			"flg	ca	.1	2586	0	# Carry\n"
			"gpr	0	.64	2587	0	# The zero register.\n";
		return rz_str_dup(p);
	} else {
		p =
			"=PC	pc\n"
			"=SP	r1\n"
			"=BP	r31\n"
			"=SN	r3\n" // also for ret
			"=A0	r3\n" // also for ret
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"=OF	ov\n"
			"=CF	ca\n"

			"gpr	r0	.32	0	0	\n"
			"gpr	r1	.32	8	0	\n"
			"gpr	r2	.32	16	0	\n"
			"gpr	r3	.32	24	0	\n"
			"gpr	r4	.32	32	0	\n"
			"gpr	r5	.32	40	0	\n"
			"gpr	r6	.32	48	0	\n"
			"gpr	r7	.32	56	0	\n"
			"gpr	r8	.32	64	0	\n"
			"gpr	r9	.32	72	0	\n"
			"gpr	r10	.32	80	0	\n"
			"gpr	r11	.32	88	0	\n"
			"gpr	r12	.32	96	0	\n"
			"gpr	r13	.32	104	0	\n"
			"gpr	r14	.32	112	0	\n"
			"gpr	r15	.32	120	0	\n"
			"gpr	r16	.32	128	0	\n"
			"gpr	r17	.32	136	0	\n"
			"gpr	r18	.32	144	0	\n"
			"gpr	r19	.32	152	0	\n"
			"gpr	r20	.32	160	0	\n"
			"gpr	r21	.32	168	0	\n"
			"gpr	r22	.32	176	0	\n"
			"gpr	r23	.32	184	0	\n"
			"gpr	r24	.32	192	0	\n"
			"gpr	r25	.32	200	0	\n"
			"gpr	r26	.32	208	0	\n"
			"gpr	r27	.32	216	0	\n"
			"gpr	r28	.32	224	0	\n"
			"gpr	r29	.32	232	0	\n"
			"gpr	r30	.32	240	0	\n"
			"gpr	r31	.32	248	0	\n"
			"vc	vs0	.128	256	0	\n"
			"vc	vs1	.128	272	0	\n"
			"vc	vs2	.128	288	0	\n"
			"vc	vs3	.128	304	0	\n"
			"vc	vs4	.128	320	0	\n"
			"vc	vs5	.128	336	0	\n"
			"vc	vs6	.128	352	0	\n"
			"vc	vs7	.128	368	0	\n"
			"vc	vs8	.128	384	0	\n"
			"vc	vs9	.128	400	0	\n"
			"vc	vs10	.128	416	0	\n"
			"vc	vs11	.128	432	0	\n"
			"vc	vs12	.128	448	0	\n"
			"vc	vs13	.128	464	0	\n"
			"vc	vs14	.128	480	0	\n"
			"vc	vs15	.128	496	0	\n"
			"vc	vs16	.128	512	0	\n"
			"vc	vs17	.128	528	0	\n"
			"vc	vs18	.128	544	0	\n"
			"vc	vs19	.128	560	0	\n"
			"vc	vs20	.128	576	0	\n"
			"vc	vs21	.128	592	0	\n"
			"vc	vs22	.128	608	0	\n"
			"vc	vs23	.128	624	0	\n"
			"vc	vs24	.128	640	0	\n"
			"vc	vs25	.128	656	0	\n"
			"vc	vs26	.128	672	0	\n"
			"vc	vs27	.128	688	0	\n"
			"vc	vs28	.128	704	0	\n"
			"vc	vs29	.128	720	0	\n"
			"vc	vs30	.128	736	0	\n"
			"vc	vs31	.128	752	0	\n"
			"vc	vs32	.128	768	0	\n"
			"vc	vs33	.128	784	0	\n"
			"vc	vs34	.128	800	0	\n"
			"vc	vs35	.128	816	0	\n"
			"vc	vs36	.128	832	0	\n"
			"vc	vs37	.128	848	0	\n"
			"vc	vs38	.128	864	0	\n"
			"vc	vs39	.128	880	0	\n"
			"vc	vs40	.128	896	0	\n"
			"vc	vs41	.128	912	0	\n"
			"vc	vs42	.128	928	0	\n"
			"vc	vs43	.128	944	0	\n"
			"vc	vs44	.128	960	0	\n"
			"vc	vs45	.128	976	0	\n"
			"vc	vs46	.128	992	0	\n"
			"vc	vs47	.128	1008	0	\n"
			"vc	vs48	.128	1024	0	\n"
			"vc	vs49	.128	1040	0	\n"
			"vc	vs50	.128	1056	0	\n"
			"vc	vs51	.128	1072	0	\n"
			"vc	vs52	.128	1088	0	\n"
			"vc	vs53	.128	1104	0	\n"
			"vc	vs54	.128	1120	0	\n"
			"vc	vs55	.128	1136	0	\n"
			"vc	vs56	.128	1152	0	\n"
			"vc	vs57	.128	1168	0	\n"
			"vc	vs58	.128	1184	0	\n"
			"vc	vs59	.128	1200	0	\n"
			"vc	vs60	.128	1216	0	\n"
			"vc	vs61	.128	1232	0	\n"
			"vc	vs62	.128	1248	0	\n"
			"vc	vs63	.128	1264	0	\n"
			"fpu	f0	.64	1280	0	\n"
			"fpu	f1	.64	1288	0	\n"
			"fpu	f2	.64	1296	0	\n"
			"fpu	f3	.64	1304	0	\n"
			"fpu	f4	.64	1312	0	\n"
			"fpu	f5	.64	1320	0	\n"
			"fpu	f6	.64	1328	0	\n"
			"fpu	f7	.64	1336	0	\n"
			"fpu	f8	.64	1344	0	\n"
			"fpu	f9	.64	1352	0	\n"
			"fpu	f10	.64	1360	0	\n"
			"fpu	f11	.64	1368	0	\n"
			"fpu	f12	.64	1376	0	\n"
			"fpu	f13	.64	1384	0	\n"
			"fpu	f14	.64	1392	0	\n"
			"fpu	f15	.64	1400	0	\n"
			"fpu	f16	.64	1408	0	\n"
			"fpu	f17	.64	1416	0	\n"
			"fpu	f18	.64	1424	0	\n"
			"fpu	f19	.64	1432	0	\n"
			"fpu	f20	.64	1440	0	\n"
			"fpu	f21	.64	1448	0	\n"
			"fpu	f22	.64	1456	0	\n"
			"fpu	f23	.64	1464	0	\n"
			"fpu	f24	.64	1472	0	\n"
			"fpu	f25	.64	1480	0	\n"
			"fpu	f26	.64	1488	0	\n"
			"fpu	f27	.64	1496	0	\n"
			"fpu	f28	.64	1504	0	\n"
			"fpu	f29	.64	1512	0	\n"
			"fpu	f30	.64	1520	0	\n"
			"fpu	f31	.64	1528	0	\n"
			"vc	v0	.128	1536	0	\n"
			"vc	v1	.128	1552	0	\n"
			"vc	v2	.128	1568	0	\n"
			"vc	v3	.128	1584	0	\n"
			"vc	v4	.128	1600	0	\n"
			"vc	v5	.128	1616	0	\n"
			"vc	v6	.128	1632	0	\n"
			"vc	v7	.128	1648	0	\n"
			"vc	v8	.128	1664	0	\n"
			"vc	v9	.128	1680	0	\n"
			"vc	v10	.128	1696	0	\n"
			"vc	v11	.128	1712	0	\n"
			"vc	v12	.128	1728	0	\n"
			"vc	v13	.128	1744	0	\n"
			"vc	v14	.128	1760	0	\n"
			"vc	v15	.128	1776	0	\n"
			"vc	v16	.128	1792	0	\n"
			"vc	v17	.128	1808	0	\n"
			"vc	v18	.128	1824	0	\n"
			"vc	v19	.128	1840	0	\n"
			"vc	v20	.128	1856	0	\n"
			"vc	v21	.128	1872	0	\n"
			"vc	v22	.128	1888	0	\n"
			"vc	v23	.128	1904	0	\n"
			"vc	v24	.128	1920	0	\n"
			"vc	v25	.128	1936	0	\n"
			"vc	v26	.128	1952	0	\n"
			"vc	v27	.128	1968	0	\n"
			"vc	v28	.128	1984	0	\n"
			"vc	v29	.128	2000	0	\n"
			"vc	v30	.128	2016	0	\n"
			"vc	v31	.128	2032	0	\n"
			"ctr	xer	.64	2048	0	# Fixed-Point Exception Register\n"
			"vcc	vrsave	.32	2056	0	# VR Save Register\n"
			"ctr	fpscr	.64	2060	0	# Floating-Point Status and Control Register\n"
			"vcc	vscr	.32	2068	0	# Vector Status and Control Register\n"
			"ctr	cr	.32	2072	0	# Condition Register\n"
			"ctr	lr	.32	2076	0	# Link Register\n"
			"ctr	ctr	.32	2084	0	# Count Register\n"
			"ctr	tar	.32	2092	0	# Target Address Register\n"
			"ctr	ppr	.64	2100	0	# Process Priority Register\n"
			"ctr	dscr	.64	2108	0	# Data Stream Control Register\n"
			"ctr	bescr	.64	2116	0	# Branch Event Status and Control Register\n"
			"ctr	ebbhr	.64	2124	0	# Event-Based Branch Handler Register\n"
			"ctr	ebbrr	.64	2132	0	# Event-Based Branch Return Register\n"
			"ctr	lpcr	.64	2140	0	# Logical Partitioning Control Register\n"
			"ctr	hrmor	.64	2148	0	# Hypervisor Real Mode Offset Register\n"
			"ctr	lpidr	.32	2156	0	# Logical Partition Identification Regiser\n"
			"ctr	pcr	.64	2160	0	# Processor Compatibility Register\n"
			"ctr	tir	.64	2168	0	# Thread Identification Register\n"
			"ctr	urmor	.64	2176	0	# Ultravisor Real Mode Offset Register\n"
			"ctr	smfctrl	.64	2184	0	# Secure Memory Facility Control Register\n"
			"ctr	msr	.64	2192	0	# Machine State Register\n"
			"ctr	pvr	.32	2200	0	# Processor Version Register\n"
			"ctr	pir	.32	2204	0	# Processor Version Register\n"
			"ctr	pidr	.32	2208	0	# Processor Identification Register\n"
			"ctr	ctrl	.32	2212	0	# Control Register\n"
			"ctr	pspb	.32	2216	0	# Problem State Priority Boost Register\n"
			"ctr	rpr	.64	2220	0	# Relative Priority Register\n"
			"ctr	hashkey	.64	2228	0	# Hash Key Register\n"
			"ctr	hashpkey	.64	2236	0	# Hash Privileged Key Register\n"
			"ctr	sprg0	.64	2244	0	# Software-use SPR 0\n"
			"ctr	sprg1	.64	2252	0	# Software-use SPR 1\n"
			"ctr	sprg2	.64	2260	0	# Software-use SPR 2\n"
			"ctr	sprg3	.64	2268	0	# Software-use SPR 3\n"
			"ctr	hsprg0	.64	2276	0	# Hypervisor Software-use SPR 0\n"
			"ctr	hsprg1	.64	2284	0	# Hypervisor Software-use SPR 1\n"
			"ctr	usprg0	.64	2292	0	# Ultravisor Software-use SPR 0\n"
			"ctr	usprg1	.64	2300	0	# Ultravisor Software-use SPR 1\n"
			"ctr	srr0	.64	2308	0	# Machine Status Save/Restore Register 0\n"
			"ctr	srr1	.64	2316	0	# Machine Status Save/Restore Register 1\n"
			"ctr	hsrr0	.64	2324	0	# Hypervisor Machine Status Save/Restore Register 0\n"
			"ctr	hsrr1	.64	2332	0	# Hypervisor Machine Status Save/Restore Register 1\n"
			"ctr	usrr0	.64	2340	0	# Hypervisor Machine Status Save/Restore Register 0\n"
			"ctr	usrr1	.64	2348	0	# Ultravisor Machine Status Save/Restore Register 1\n"
			"ctr	asdr	.64	2356	0	# Access Segment Descriptor Register\n"
			"ctr	dar	.64	2364	0	# Data Address Register\n"
			"ctr	hdar	.64	2372	0	# Hypervisor Data Address Register\n"
			"ctr	dsisr	.32	2380	0	# Data Storage Interrupt Status Register\n"
			"ctr	hdsisr	.32	2384	0	# Hypervisor Data Storage Interrupt Status Register\n"
			"ctr	heir	.64	2388	0	# Hypervisor Emulation Instruction Register\n"
			"ctr	hmer	.64	2396	0	# Hypervisor Maintenance Exception Register\n"
			"ctr	hmeer	.64	2404	0	# Hypervisor Maintenance Exception Enable Register\n"
			"ctr	fscr	.64	2412	0	# Facility Status and Control Register\n"
			"ctr	hfscr	.64	2420	0	# Hypervisor Facility Status and Control Register\n"
			"ctr	purr	.64	2428	0	# Process Utilization of Resources Register\n"
			"ctr	spurr	.64	2436	0	# Scaled Process Utilization of Resources Register\n"
			"ctr	dexcr	.64	2444	0	# Dynamic Execution Control Register\n"
			"ctr	hdexcr	.64	2452	0	# Hypervisor Dynamic Execution Control Register\n"
			"ctr	udexcr	.64	2460	0	# Ultravisor Dynamic Execution Control Register\n"
			"ctr	cfar	.64	2468	0	# Come-From Address Register\n"
			"ctr	mmcr0	.64	2476	0	# Monitor Mode Control Register 0\n"
			"ctr	mmcr1	.64	2484	0	# Monitor Mode Control Register 1\n"
			"ctr	mmcr2	.64	2492	0	# Monitor Mode Control Register 2\n"
			"ctr	mmcra	.64	2500	0	# Monitor Mode Control Register A\n"
			"ctr	siar	.64	2508	0	# Sampled Instruction Address Register\n"
			"ctr	sdar	.64	2516	0	# Sampled Data Address Register\n"
			"ctr	sier	.64	2524	0	# Sampled Instruction Event Register\n"
			"ctr	sier2	.64	2532	0	# Sampled Instruction Event Register 2\n"
			"ctr	sier3	.64	2540	0	# Sampled Instruction Event Register 3\n"
			"ctr	mmcr3	.64	2548	0	# Monitor Mode Control Register 2\n"
			"ctr	dpdes	.64	2556	0	# Directed Privileged Doorbell Exception State Register\n"
			"ctr	pc	.64	2564	0	# Programm Counter\n"
			"ctr	cr0	.4	2572	0	# Condition Register Field 0\n"
			"ctr	cr1	.4	2573	0	# Condition Register Field 1\n"
			"ctr	cr2	.4	2574	0	# Condition Register Field 2\n"
			"ctr	cr3	.4	2575	0	# Condition Register Field 3\n"
			"ctr	cr4	.4	2576	0	# Condition Register Field 4\n"
			"ctr	cr5	.4	2577	0	# Condition Register Field 5\n"
			"ctr	cr6	.4	2578	0	# Condition Register Field 6\n"
			"ctr	cr7	.4	2579	0	# Condition Register Field 7\n"
			"ctr	ppr32	.32	2580	0	# Process Priority Register 32-bit\n"
			"flg	so	.1	2584	0	# Summary Overflow\n"
			"flg	ov	.1	2585	0	# Overflow\n"
			"flg	ca	.1	2586	0	# Carry\n"
			"gpr	0	.32	2587	0	# The zero register.\n";
		return rz_str_dup(p);
	}
}

static int analyze_op_vle(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	vle_t *instr = NULL;
	vle_handle handle = { 0 };
	op->size = 2;
	if (len > 1 && !vle_init(&handle, buf, len) && (instr = vle_next(&handle))) {
		op->size = instr->size;
		op->type = instr->analysis_op;
		// op->id = instr->type;

		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup(instr->name);
		}
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_ILL:
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			break;
		case RZ_ANALYSIS_OP_TYPE_AND:
			break;
		case RZ_ANALYSIS_OP_TYPE_CALL:
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CCALL:
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			op->cond = instr->cond; // RZ_TYPE_COND_NE;
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case RZ_ANALYSIS_OP_TYPE_CMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
			op->jump = addr + instr->fields[instr->n - 1].value;
			break;
		case RZ_ANALYSIS_OP_TYPE_LOAD:
			break;
		case RZ_ANALYSIS_OP_TYPE_MOV:
			break;
		case RZ_ANALYSIS_OP_TYPE_MUL:
			break;
		case RZ_ANALYSIS_OP_TYPE_NOT:
			break;
		case RZ_ANALYSIS_OP_TYPE_OR:
			break;
		case RZ_ANALYSIS_OP_TYPE_ROR:
			break;
		case RZ_ANALYSIS_OP_TYPE_ROL:
			break;
		case RZ_ANALYSIS_OP_TYPE_RCALL:
			op->eob = true;
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			op->eob = true;
			break;
		case RZ_ANALYSIS_OP_TYPE_RJMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_SHL:
			break;
		case RZ_ANALYSIS_OP_TYPE_SHR:
			break;
		case RZ_ANALYSIS_OP_TYPE_STORE:
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			break;
		case RZ_ANALYSIS_OP_TYPE_SWI:
			break;
		case RZ_ANALYSIS_OP_TYPE_SYNC:
			break;
		case RZ_ANALYSIS_OP_TYPE_TRAP:
			break;
		case RZ_ANALYSIS_OP_TYPE_XOR:
			break;
		default:
			// RZ_LOG_ERROR("Missing an RZ_ANALYSIS_OP_TYPE (%"PFMT64u")\n", op->type);
			break;
		}
		vle_free(instr);
		return op->size;
	}
	return -1;
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (INSOP(reg_num).type) {
	case PPC_OP_REG:
		reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).reg);
		break;
	case PPC_OP_MEM:
		if (INSOP(reg_num).mem.base != PPC_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).mem.base);
		}
		break;
	default:
		break;
	}
	return 0;
}

static RzRegItem base_regs[4];

static void create_src_dst(RzAnalysisOp *op) {
	op->src[0] = rz_analysis_value_new();
	op->src[1] = rz_analysis_value_new();
	op->src[2] = rz_analysis_value_new();
	op->dst = rz_analysis_value_new();
	ZERO_FILL(base_regs[0]);
	ZERO_FILL(base_regs[1]);
	ZERO_FILL(base_regs[2]);
	ZERO_FILL(base_regs[3]);
}

static void set_src_dst(RzAnalysisValue *val, csh *handle, cs_insn *insn, int x) {
	cs_ppc_op ppcop = INSOP(x);
	parse_reg_name(&base_regs[x], *handle, insn, x);
	switch (ppcop.type) {
	case PPC_OP_REG:
		break;
	case PPC_OP_MEM:
		val->delta = ppcop.mem.disp;
		break;
	case PPC_OP_IMM:
		val->imm = ppcop.imm;
		break;
	default:
		break;
	}
	val->reg = &base_regs[x];
}

static void op_fillval(RzAnalysisOp *op, csh handle, cs_insn *insn) {
	create_src_dst(op);
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_CAST:
		set_src_dst(op->src[2], &handle, insn, 3);
		set_src_dst(op->src[1], &handle, insn, 2);
		set_src_dst(op->src[0], &handle, insn, 1);
		set_src_dst(op->dst, &handle, insn, 0);
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		set_src_dst(op->dst, &handle, insn, 1);
		set_src_dst(op->src[0], &handle, insn, 0);
		break;
	}
}

static char *shrink(char *op) {
	if (!op) {
		return NULL;
	}
	size_t len = strlen(op);
	if (!len) {
		return NULL;
	}
	op[len - 1] = 0;
	return op;
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	PPCContext *ctx = (PPCContext *)a->plugin_data;
	int n, ret;
	cs_insn *insn;
	char *op1;
	int mode = (a->bits == 64) ? CS_MODE_64 : (a->bits == 32) ? CS_MODE_32
								  : 0;
	mode |= a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;

	if (a->cpu && strncmp(a->cpu, "vle", 3) == 0) {
		// vle is big-endian only
		if (!a->big_endian) {
			return -1;
		}
		ret = analyze_op_vle(a, op, addr, buf, len, mask);
		if (ret >= 0) {
			return op->size;
		}
	} else if (a->cpu && RZ_STR_EQ(a->cpu, "qpx")) {
		mode |= CS_MODE_QPX;
	}

	if (mode != ctx->omode || a->bits != ctx->obits) {
		cs_close(&ctx->handle);
		ctx->handle = 0;
		ctx->omode = mode;
		ctx->obits = a->bits;
	}
	if (ctx->handle == 0) {
		ret = cs_open(CS_ARCH_PPC, mode, &ctx->handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
#if CS_NEXT_VERSION >= 6
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
#endif
	}
	op->size = 4;

	// capstone-next
	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->il_op = rz_il_op_new_empty();
	} else {
		op->il_op = rz_ppc_cs_get_il_op(ctx->handle, insn, mode);
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup(insn->mnemonic);
		}
		if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
			opex(&op->opex, ctx->handle, insn);
		}
		struct Getarg gop = {
			.handle = ctx->handle,
			.insn = insn,
			.bits = a->bits
		};
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case PPC_INS_CMPB:
		case PPC_INS_CMPD:
		case PPC_INS_CMPDI:
		case PPC_INS_CMPLD:
		case PPC_INS_CMPLDI:
		case PPC_INS_CMPLW:
		case PPC_INS_CMPLWI:
		case PPC_INS_CMPW:
		case PPC_INS_CMPWI:
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
		case PPC_INS_CMP:
		case PPC_INS_CMPI:
#endif
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			op->sign = true;
			/* 0b01 == equal
			 * 0b10 == less than */
			if (ARG(2)[0] == '\0') {
				esilprintf(op, ",%s,%s,-,!,cr0,=,%s,%s,<,?{2,cr0,|=,}", ARG(1), ARG(0), ARG(1), ARG(0));
			} else {
				esilprintf(op, ",%s,%s,-,!,%s,=,%s,%s,<,?{2,%s,|=,}", ARG(2), ARG(1), ARG(0), ARG(2), ARG(1), ARG(0));
			}
			break;
		case PPC_INS_MFLR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "lr,%s,=", ARG(0));
			break;
		case PPC_INS_MTLR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,lr,=", ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_MR:
		case PPC_INS_LI:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			op->val = IMM(1);
			esilprintf(op, "%s,%s,=", ARG(1), ARG(0));
			break;
		case PPC_INS_LIS:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			op->val = IMM(1);
			op->val <<= 16;
			esilprintf(op, "%s0000,%s,=", ARG(1), ARG(0));
			break;
		case PPC_INS_CLRLWI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf(op, "%s,%s,&,%s,=", ARG(1), cmask32(a, ARG(2), "0x1F"), ARG(0));
			break;
#endif
		case PPC_INS_RLWINM:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf(op, "%s,%s,<<<,%s,&,%s,=", ARG(2), ARG(1), cmask32(a, ARG(3), ARG(4)), ARG(0));
			break;
		case PPC_INS_SC:
			op->type = RZ_ANALYSIS_OP_TYPE_SWI;
			esilprintf(op, "0,$");
			break;
		case PPC_INS_EXTSB:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			if (a->bits == 64) {
				esilprintf(op, "%s,0x80,&,?{,0xFFFFFFFFFFFFFF00,%s,|,%s,=,}", ARG(1), ARG(1), ARG(0));
			} else {
				esilprintf(op, "%s,0x80,&,?{,0xFFFFFF00,%s,|,%s,=,}", ARG(1), ARG(1), ARG(0));
			}
			break;
		case PPC_INS_EXTSH:
			op->sign = true;
			if (a->bits == 64) {
				esilprintf(op, "%s,0x8000,&,?{,0xFFFFFFFFFFFF0000,%s,|,%s,=,}", ARG(1), ARG(1), ARG(0));
			} else {
				esilprintf(op, "%s,0x8000,&,?{,0xFFFF0000,%s,|,%s,=,}", ARG(1), ARG(1), ARG(0));
			}
			break;
		case PPC_INS_EXTSW:
			op->sign = true;
			esilprintf(op, "%s,0x80000000,&,?{,0xFFFFFFFF00000000,%s,|,%s,=,}", ARG(1), ARG(1), ARG(0));
			break;
		case PPC_INS_SYNC:
		case PPC_INS_ISYNC:
#if CS_NEXT_VERSION < 6
		case PPC_INS_LWSYNC:
		case PPC_INS_MSYNC:
		case PPC_INS_PTESYNC:
#endif
		case PPC_INS_TLBSYNC:
		case PPC_INS_SLBIA:
		case PPC_INS_SLBIE:
		case PPC_INS_SLBMFEE:
		case PPC_INS_SLBMTE:
		case PPC_INS_EIEIO:
		case PPC_INS_NOP:
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			esilprintf(op, ",");
			break;
		case PPC_INS_STW:
		case PPC_INS_STWUX:
		case PPC_INS_STWX:
		case PPC_INS_STWCX:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf(op, "%s,%s", ARG(0), ARG2(1, "=[4]"));
			break;
		case PPC_INS_STWU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,%s,=[4],%s=", ARG(0), op1, op1);
			if (strstr(op1, "r1")) {
				op->stackop = RZ_ANALYSIS_STACK_INC;
				op->stackptr = -atoi(op1);
			}
			break;
		case PPC_INS_STWBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case PPC_INS_STB:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf(op, "%s,%s", ARG(0), ARG2(1, "=[1]"));
			break;
		case PPC_INS_STBU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,%s,=[1],%s=", ARG(0), op1, op1);
			break;
		case PPC_INS_STH:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf(op, "%s,%s", ARG(0), ARG2(1, "=[2]"));
			break;
		case PPC_INS_STHU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,%s,=[2],%s=", ARG(0), op1, op1);
			break;
		case PPC_INS_STD:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf(op, "%s,%s", ARG(0), ARG2(1, "=[8]"));
			break;
		case PPC_INS_STDU:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,%s,=[8],%s=", ARG(0), op1, op1);
			break;
		case PPC_INS_LBZ:
		case PPC_INS_LBZCIX:
		case PPC_INS_LBZU:
		case PPC_INS_LBZUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,[1],%s,=,%s=", op1, ARG(0), op1);
			break;
		case PPC_INS_LBZX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf(op, "%s,%s,=", ARG2(1, "[1]"), ARG(0));
			break;
		case PPC_INS_LD:
		case PPC_INS_LDARX:
		case PPC_INS_LDCIX:
		case PPC_INS_LDU:
		case PPC_INS_LDUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,[8],%s,=,%s=", op1, ARG(0), op1);
			break;
		case PPC_INS_LDX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf(op, "%s,%s,=", ARG2(1, "[8]"), ARG(0));
			break;
		case PPC_INS_LDBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_LFD:
		case PPC_INS_LFDU:
		case PPC_INS_LFDUX:
		case PPC_INS_LFDX:
		case PPC_INS_LFIWAX:
		case PPC_INS_LFIWZX:
		case PPC_INS_LFS:
		case PPC_INS_LFSU:
		case PPC_INS_LFSUX:
		case PPC_INS_LFSX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf(op, "%s,%s,=", ARG2(1, "[4]"), ARG(0));
			break;
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
		case PPC_INS_LHAUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,[2],%s,=,%s=", op1, ARG(0), op1);
			break;
		case PPC_INS_LHBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_LWA:
		case PPC_INS_LWARX:
		case PPC_INS_LWAUX:
		case PPC_INS_LWAX:
		case PPC_INS_LWZ:
		case PPC_INS_LWZCIX:
		case PPC_INS_LWZX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			esilprintf(op, "%s,%s,=", ARG2(1, "[4]"), ARG(0));
			break;
		case PPC_INS_LWZU:
		case PPC_INS_LWZUX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			op1 = shrink(ARG(1));
			if (!op1) {
				break;
			}
			esilprintf(op, "%s,[4],%s,=,%s=", op1, ARG(0), op1);
			break;
		case PPC_INS_LWBRX:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case PPC_INS_SLW:
		case PPC_INS_SLWI:
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
			esilprintf(op, "%s,%s,<<,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_SRW:
		case PPC_INS_SRWI:
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
			esilprintf(op, "%s,%s,>>,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_MULLI:
			op->sign = true;
			// fallthrough
		case PPC_INS_MULLW:
		case PPC_INS_MULLD:
			op->type = RZ_ANALYSIS_OP_TYPE_MUL;
			esilprintf(op, "%s,%s,*,%s,=", ARG(2), ARG(1), ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_SUB:
		case PPC_INS_SUBC:
#endif
		case PPC_INS_SUBF:
		case PPC_INS_SUBFIC:
		case PPC_INS_SUBFZE:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			esilprintf(op, "%s,%s,-,%s,=", ARG(1), ARG(2), ARG(0));
			break;
		case PPC_INS_ADDI:
			op->val = ((st16)IMM(2));
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf(op, "%" PFMT64d ",%s,+,%s,=", (st64)op->val, ARG(1), ARG(0));
			break;
		case PPC_INS_ADD:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf(op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_CRCLR:
		case PPC_INS_CRSET:
		case PPC_INS_CRMOVE:
		case PPC_INS_CRNOT:
#endif
		case PPC_INS_CRXOR:
		case PPC_INS_CRNOR:
			// reset conditional bits
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case PPC_INS_ADDC:
		case PPC_INS_ADDIC:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf(op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_ADDE:
		case PPC_INS_ADDIS:
		case PPC_INS_ADDME:
		case PPC_INS_ADDZE:
#if CS_NEXT_VERSION >= 6
			switch (insn->alias_id) {
			default:
				op->type = RZ_ANALYSIS_OP_TYPE_ADD;
				esilprintf(op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
				break;
			case PPC_INS_ALIAS_LIS:
				op->type = RZ_ANALYSIS_OP_TYPE_MOV;
				op->val = IMM(2);
				op->val <<= 16;
				esilprintf(op, "0x%llx0000,%s,=", IMM(2), ARG(0));
				break;
			}
#else
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			esilprintf(op, "%s,%s,+,%s,=", ARG(2), ARG(1), ARG(0));
#endif
			break;
		case PPC_INS_MTSPR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,%s,=", ARG(1), PPCSPR(0));
			break;
		case PPC_INS_BCTR: // switch table here
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			esilprintf(op, "ctr,pc,=");
			break;
		case PPC_INS_BCTRL: // switch table here
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			esilprintf(op, "pc,lr,=,ctr,pc,=");
			break;
#if CS_API_MAJOR == 5 && CS_NEXT_VERSION < 6
		case PPC_INS_BEQ:
		case PPC_INS_BEQA:
		case PPC_INS_BFA:
		case PPC_INS_BGE:
		case PPC_INS_BGEA:
		case PPC_INS_BGT:
		case PPC_INS_BGTA:
		case PPC_INS_BLE:
		case PPC_INS_BLEA:
		case PPC_INS_BLT:
		case PPC_INS_BLTA:
		case PPC_INS_BNE:
		case PPC_INS_BNEA:
		case PPC_INS_BNG:
		case PPC_INS_BNGA:
		case PPC_INS_BNL:
		case PPC_INS_BNLA:
		case PPC_INS_BNS:
		case PPC_INS_BNSA:
		case PPC_INS_BNU:
		case PPC_INS_BNUA:
		case PPC_INS_BSO:
		case PPC_INS_BSOA:
		case PPC_INS_BUN:
		case PPC_INS_BUNA:
#endif
#if CS_NEXT_VERSION < 6
		case PPC_INS_BT:
		case PPC_INS_BF:
			switch (insn->detail->ppc.operands[0].type) {
			case PPC_OP_CRX:
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->fail = addr + op->size;
				break;
			case PPC_OP_REG:
				if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
					op->type = RZ_ANALYSIS_OP_TYPE_UCJMP;
				} else {
					op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				}
				op->jump = IMM(1);
				op->fail = addr + op->size;
				// op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			default:
				break;
			}
			break;
		case PPC_INS_BDNZ:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf(op, "1,ctr,-=,$z,!,?{,%s,pc,=,}", ARG(0));
			break;
		case PPC_INS_BDNZA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDNZLR:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf(op, "1,ctr,-=,$z,!,?{,lr,pc,=,},");
			break;
		case PPC_INS_BDNZLRL:
			op->fail = addr + op->size;
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			break;
		case PPC_INS_BDZ:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf(op, "1,ctr,-=,$z,?{,%s,pc,=,}", ARG(0));
			break;
		case PPC_INS_BDZA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			break;
		case PPC_INS_BDZLR:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			esilprintf(op, "1,ctr,-=,$z,?{,lr,pc,=,}");
			break;
		case PPC_INS_BDZLRL:
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->fail = addr + op->size;
			break;
#endif
		case PPC_INS_B:
		case PPC_INS_BC:
		case PPC_INS_BA:
		case PPC_INS_BCL:
		case PPC_INS_BLR:
		case PPC_INS_BLRL:
		case PPC_INS_BCLR:
		case PPC_INS_BCLRL:
		case PPC_INS_BCCTR:
		case PPC_INS_BCCTRL: {
			if (insn->id == PPC_INS_BC || insn->id == PPC_INS_BCCTR) {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			} else if (insn->id == PPC_INS_B || insn->id == PPC_INS_BA) {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			} else if (insn->id == PPC_INS_BCLR || insn->id == PPC_INS_BCLRL) {
				op->type = RZ_ANALYSIS_OP_TYPE_CRET;
			} else if (insn->id == PPC_INS_BLR || insn->id == PPC_INS_BLRL) {
				op->type = RZ_ANALYSIS_OP_TYPE_RET;
			} else if (insn->id == PPC_INS_BCCTRL) {
				op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
			}
			bool cr_cond_set = true;
			bool ctr_cond_set = true;
#if CS_NEXT_VERSION >= 6
			switch (insn->detail->ppc.bc.pred_cr) {
			case PPC_PRED_LT:
				esilprintf(op, "2,%s,&,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			switch (insn->detail->ppc.bc) {
			case PPC_BC_LT:
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "2,cr0,&,");
				} else {
					esilprintf(op, "2,%s,&,", ARG(0));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_LE:
				esilprintf(op, "3,%s,&,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			case PPC_BC_LE:
				/* 0b01 == equal
				 * 0b10 == less than */
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "3,cr0,&,?{,%s,pc,=,},", ARG(0));
				} else {
					esilprintf(op, "3,%s,&,?{,%s,pc,=,},", ARG(0), ARG(1));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_EQ:
				esilprintf(op, "1,%s,&,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			case PPC_BC_EQ:
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "1,cr0,&,");
				} else {
					esilprintf(op, "1,%s,&,", ARG(0));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_GE:
				esilprintf(op, "2,%s,^,3,&,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			case PPC_BC_GE:
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "2,cr0,^,3,&,");
				} else {
					esilprintf(op, "2,%s,^,3,&,", ARG(0));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_GT:
				esilprintf(op, "2,%s,&,!,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			case PPC_BC_GT:
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "2,cr0,&,!,");
				} else {
					esilprintf(op, "2,%s,&,!,", ARG(0));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_NE:
				esilprintf(op, "%s,1,&,!,", cs_reg_name(ctx->handle, insn->detail->ppc.bc.crX));
#else
			case PPC_BC_NE:
				if (ARG(1)[0] == '\0') {
					esilprintf(op, "cr0,1,&,!,");
				} else {
					esilprintf(op, "%s,1,&,!,", ARG(0));
				}
#endif
				break;
#if CS_NEXT_VERSION >= 6
			case PPC_PRED_INVALID:
			case PPC_PRED_UN: // unordered + PPC_PRED_SO - summary overflow
			case PPC_PRED_NU: // not unordered + PPC_PRED_NS - not summary overflow
#else
			case PPC_BC_INVALID:
			case PPC_BC_UN: // unordered
			case PPC_BC_NU: // not unordered
			case PPC_BC_SO: // summary overflow
			case PPC_BC_NS: // not summary overflow
#endif
			default:
				cr_cond_set = false;
				break;
			}
#if CS_NEXT_VERSION >= 6
			switch (insn->detail->ppc.bc.pred_ctr) {
			default:
				ctr_cond_set = false;
				break;
			case PPC_PRED_Z:
				rz_strbuf_appendf(&op->esil, "1,ctr,-=,$z,%s", cr_cond_set ? "&&,?" : "?");
				break;
			case PPC_PRED_NZ:
				rz_strbuf_appendf(&op->esil, "1,ctr,-=,$z,!,%s", cr_cond_set ? "&&,?" : "?");
				break;
			}
#endif
			bool is_cond = cr_cond_set || ctr_cond_set;
			if (is_cond) {
				rz_strbuf_appendf(&op->esil, "{,");
				op->fail = addr + op->size;
			}

			if (insn->id == PPC_INS_B || insn->id == PPC_INS_BC || insn->id == PPC_INS_BA || insn->id == PPC_INS_BCL) {
#if CS_NEXT_VERSION >= 6
				op->jump = (insn->id == PPC_INS_BC || insn->id == PPC_INS_BCL) ? IMM(2) : IMM(0);
#else
				op->jump = ARG(1)[0] == '\0' ? IMM(0) : IMM(1);
#endif
			}

			if (insn->id == PPC_INS_BLRL ||
				insn->id == PPC_INS_BCLRL ||
				insn->id == PPC_INS_BCCTRL ||
				insn->id == PPC_INS_BCL) {
				op->fail = addr + op->size;
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",lr,=,", op->fail);
			}

			// Set target source
			if (insn->id == PPC_INS_BCCTR || insn->id == PPC_INS_BCCTRL) {
				rz_strbuf_appendf(&op->esil, "ctr,pc,=,");
			} else if (op->type == RZ_ANALYSIS_OP_TYPE_CRET || op->type == RZ_ANALYSIS_OP_TYPE_RET) {
				rz_strbuf_appendf(&op->esil, "lr,pc,=,");
			} else {
				rz_strbuf_appendf(&op->esil, "0x%" PFMT64x ",pc,=,", op->jump);
			}
			if (is_cond) {
				rz_strbuf_appendf(&op->esil, "},");
			}
			break;
		}
		case PPC_INS_NOR:
			op->type = RZ_ANALYSIS_OP_TYPE_NOR;
			esilprintf(op, "%s,%s,|,!,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_XOR:
		case PPC_INS_XORI:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			esilprintf(op, "%s,%s,^,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_XORIS:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			esilprintf(op, "16,%s,<<,%s,^,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_DIVD:
		case PPC_INS_DIVW:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			esilprintf(op, "%s,%s,/,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_DIVDU:
		case PPC_INS_DIVWU:
			op->type = RZ_ANALYSIS_OP_TYPE_DIV;
			esilprintf(op, "%s,%s,/,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_BL:
		case PPC_INS_BLA:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = IMM(0);
			op->fail = addr + op->size;
			esilprintf(op, "pc,lr,=,%s,pc,=", ARG(0));
			break;
		case PPC_INS_TRAP:
			op->sign = true;
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			break;
		case PPC_INS_AND:
		case PPC_INS_NAND:
		case PPC_INS_ANDI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf(op, "%s,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_ANDIS:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf(op, "16,%s,<<,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_OR:
		case PPC_INS_ORI:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			esilprintf(op, "%s,%s,|,%s,=", ARG(2), ARG(1), ARG(0));
			break;
		case PPC_INS_ORIS:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			esilprintf(op, "16,%s,<<,%s,|,%s,=", ARG(2), ARG(1), ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_MFPVR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "pvr,%s,=", ARG(0));
			break;
#endif
		case PPC_INS_MFSPR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,%s,=", PPCSPR(1), ARG(0));
			break;
		case PPC_INS_MFCTR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "ctr,%s,=", ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_MFDCCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "dccr,%s,=", ARG(0));
			break;
		case PPC_INS_MFICCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "iccr,%s,=", ARG(0));
			break;
		case PPC_INS_MFDEAR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "dear,%s,=", ARG(0));
			break;
#endif
		case PPC_INS_MFMSR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "msr,%s,=", ARG(0));
			break;
		case PPC_INS_MTCTR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,ctr,=", ARG(0));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_MTDCCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,dccr,=", ARG(0));
			break;
		case PPC_INS_MTICCR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,iccr,=", ARG(0));
			break;
		case PPC_INS_MTDEAR:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,dear,=", ARG(0));
			break;
#endif
		case PPC_INS_MTMSR:
		case PPC_INS_MTMSRD:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			esilprintf(op, "%s,msr,=", ARG(0));
			break;
			// Data Cache Block Zero
		case PPC_INS_DCBZ:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			esilprintf(op, "%s,%s", ARG(0), ARG2(1, ",=[128]"));
			break;
#if CS_NEXT_VERSION < 6
		case PPC_INS_CLRLDI:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			esilprintf(op, "%s,%s,&,%s,=", ARG(1), cmask64(a, ARG(2), "0x3F"), ARG(0));
			break;
		case PPC_INS_ROTLDI:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf(op, "%s,%s,<<<,%s,=", ARG(2), ARG(1), ARG(0));
			break;
#endif
		case PPC_INS_RLDCL:
		case PPC_INS_RLDICL:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf(op, "%s,%s,<<<,%s,&,%s,=", ARG(2), ARG(1), cmask64(a, ARG(3), "0x3F"), ARG(0));
			break;
		case PPC_INS_RLDCR:
		case PPC_INS_RLDICR:
			op->type = RZ_ANALYSIS_OP_TYPE_ROL;
			esilprintf(op, "%s,%s,<<<,%s,&,%s,=", ARG(2), ARG(1), cmask64(a, 0, ARG(3)), ARG(0));
			break;
		}
		if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
			op_fillval(op, ctx->handle, insn);
		}
		if (!(mask & RZ_ANALYSIS_OP_MASK_ESIL)) {
			rz_strbuf_fini(&op->esil);
		}
		cs_free(insn, n);
		// cs_close (&handle);
	}
	return op->size;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	bool is_vle = a && a->cpu && !strncmp(a->cpu, "vle", 3);

	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return is_vle ? 2 : 4;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	KW("\x7c\x08\x02\xa6", 4, NULL, 0);
	return l;
}

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	if (analysis->bits == 64) {
		return rz_ppc_cs_64_il_config(analysis->big_endian);
	}
	return rz_ppc_cs_32_il_config(analysis->big_endian);
}

static bool ppc_fini(void *user) {
	PPCContext *ctx = (PPCContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_ppc_cs = {
	.name = "ppc",
	.desc = "Capstone PowerPC analysis",
	.license = "BSD",
	.esil = true,
	.arch = "ppc",
	.bits = 32 | 64,
	.archinfo = archinfo,
	.preludes = analysis_preludes,
	.op = &analyze_op,
	.init = ppc_init,
	.fini = ppc_fini,
	.get_reg_profile = &get_reg_profile,
	.il_config = il_config,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_ppc_cs,
	.version = RZ_VERSION
};
#endif
