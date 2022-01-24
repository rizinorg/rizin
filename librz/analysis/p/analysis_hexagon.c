// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-01-21 03:37:58-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"
#include "hexagon_arch.h"

RZ_API int hexagon_v6_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (analysis->pcalign == 0) {
		analysis->pcalign = 0x4;
	}

	HexReversedOpcode rev = { .action = HEXAGON_ANALYSIS, .ana_op = op, .asm_op = NULL };

	hexagon_reverse_opcode(NULL, &rev, buf, addr);

	return op->size;
}

RZ_API char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =

		"=PC	pc\n"
		"=SP	R29\n"
		"=BP	R30\n"
		"=LR	R31\n"
		"=SR	usr\n"
		"=SN	r0\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=A4	r4\n"
		"=A5	r5\n"
		"=A6	r1:0\n"
		"=A7	r3:2\n"
		"=A8	r5:4\n"
		"=R0	r0\n"
		"=R1	r1\n"
		"=R2	r1:0\n"

		"gpr	lc0	.32	0	0\n"
		"gpr	sa0	.32	4	0\n"
		"gpr	lc1	.32	8	0\n"
		"gpr	sa1	.32	12	0\n"
		"gpr	p3:0	.32	16	0\n"
		"gpr	c5	.32	20	0\n"
		"gpr	pc	.32	24	0\n"
		"gpr	ugp	.32	28	0\n"
		"gpr	gp	.32	32	0\n"
		"gpr	cs0	.32	36	0\n"
		"gpr	cs1	.32	40	0\n"
		"gpr	upcyclelo	.32	44	0\n"
		"gpr	upcyclehi	.32	48	0\n"
		"gpr	framelimit	.32	52	0\n"
		"gpr	framekey	.32	56	0\n"
		"gpr	pktcountlo	.32	60	0\n"
		"gpr	pktcounthi	.32	64	0\n"
		"gpr	utimerlo	.32	68	0\n"
		"gpr	utimerhi	.32	72	0\n"
		"gpr	m0	.32	76	0\n"
		"gpr	m1	.32	80	0\n"
		"gpr	usr	.32	84	0\n"

		"gpr	c1:0	.64	88	0\n"
		"gpr	c3:2	.64	96	0\n"
		"gpr	c5:4	.64	104	0\n"
		"gpr	c7:6	.64	112	0\n"
		"gpr	c9:8	.64	120	0\n"
		"gpr	c11:10	.64	128	0\n"
		"gpr	c13:12	.64	136	0\n"
		"gpr	c15:14	.64	144	0\n"
		"gpr	c17:16	.64	152	0\n"
		"gpr	c19:18	.64	160	0\n"
		"gpr	c31:30	.64	168	0\n"

		"gpr	r1:0	.64	176	0\n"
		"gpr	r3:2	.64	184	0\n"
		"gpr	r5:4	.64	192	0\n"
		"gpr	r7:6	.64	200	0\n"
		"gpr	r9:8	.64	208	0\n"
		"gpr	r13:12	.64	216	0\n"
		"gpr	r15:14	.64	224	0\n"
		"gpr	r17:16	.64	232	0\n"
		"gpr	r19:18	.64	240	0\n"
		"gpr	r21:20	.64	248	0\n"
		"gpr	r23:22	.64	256	0\n"
		"gpr	r25:24	.64	264	0\n"
		"gpr	r27:26	.64	272	0\n"
		"gpr	r11:10	.64	280	0\n"
		"gpr	r29:28	.64	288	0\n"
		"gpr	r31:30	.64	296	0\n"

		"gpr	gelr	.32	304	0\n"
		"gpr	gsr	.32	308	0\n"
		"gpr	gosp	.32	312	0\n"
		"gpr	gbadva	.32	316	0\n"
		"gpr	g4	.32	320	0\n"
		"gpr	g5	.32	324	0\n"
		"gpr	g6	.32	328	0\n"
		"gpr	g7	.32	332	0\n"
		"gpr	g8	.32	336	0\n"
		"gpr	g9	.32	340	0\n"
		"gpr	g10	.32	344	0\n"
		"gpr	g11	.32	348	0\n"
		"gpr	g12	.32	352	0\n"
		"gpr	g13	.32	356	0\n"
		"gpr	g14	.32	360	0\n"
		"gpr	g15	.32	364	0\n"
		"gpr	gpmucnt4	.32	368	0\n"
		"gpr	gpmucnt5	.32	372	0\n"
		"gpr	gpmucnt6	.32	376	0\n"
		"gpr	gpmucnt7	.32	380	0\n"
		"gpr	g20	.32	384	0\n"
		"gpr	g21	.32	388	0\n"
		"gpr	g22	.32	392	0\n"
		"gpr	g23	.32	396	0\n"
		"gpr	gpcyclelo	.32	400	0\n"
		"gpr	gpcyclehi	.32	404	0\n"
		"gpr	gpmucnt0	.32	408	0\n"
		"gpr	gpmucnt1	.32	412	0\n"
		"gpr	gpmucnt2	.32	416	0\n"
		"gpr	gpmucnt3	.32	420	0\n"
		"gpr	g30	.32	424	0\n"
		"gpr	g31	.32	428	0\n"

		"gpr	g1:0	.64	432	0\n"
		"gpr	g3:2	.64	440	0\n"
		"gpr	g5:4	.64	448	0\n"
		"gpr	g7:6	.64	456	0\n"
		"gpr	g9:8	.64	464	0\n"
		"gpr	g11:10	.64	472	0\n"
		"gpr	g13:12	.64	480	0\n"
		"gpr	g15:14	.64	488	0\n"
		"gpr	g17:16	.64	496	0\n"
		"gpr	g19:18	.64	504	0\n"
		"gpr	g21:20	.64	512	0\n"
		"gpr	g23:22	.64	520	0\n"
		"gpr	g25:24	.64	528	0\n"
		"gpr	g27:26	.64	536	0\n"
		"gpr	g29:28	.64	544	0\n"
		"gpr	g31:30	.64	552	0\n"

		"gpr	q0	.128	560	0\n"
		"gpr	q1	.128	576	0\n"
		"gpr	q2	.128	592	0\n"
		"gpr	q3	.128	608	0\n"

		"gpr	v3:0	.4096	624	0\n"
		"gpr	v7:4	.4096	1136	0\n"
		"gpr	v11:8	.4096	1648	0\n"
		"gpr	v15:12	.4096	2160	0\n"
		"gpr	v19:16	.4096	2672	0\n"
		"gpr	v23:20	.4096	3184	0\n"
		"gpr	v27:24	.4096	3696	0\n"
		"gpr	v31:28	.4096	4208	0\n"

		"gpr	v0	.1024	4720	0\n"
		"gpr	v1	.1024	4848	0\n"
		"gpr	v2	.1024	4976	0\n"
		"gpr	v3	.1024	5104	0\n"
		"gpr	v4	.1024	5232	0\n"
		"gpr	v5	.1024	5360	0\n"
		"gpr	v6	.1024	5488	0\n"
		"gpr	v7	.1024	5616	0\n"
		"gpr	v8	.1024	5744	0\n"
		"gpr	v9	.1024	5872	0\n"
		"gpr	v10	.1024	6000	0\n"
		"gpr	v11	.1024	6128	0\n"
		"gpr	v12	.1024	6256	0\n"
		"gpr	v13	.1024	6384	0\n"
		"gpr	v14	.1024	6512	0\n"
		"gpr	v15	.1024	6640	0\n"
		"gpr	v16	.1024	6768	0\n"
		"gpr	v17	.1024	6896	0\n"
		"gpr	v18	.1024	7024	0\n"
		"gpr	v19	.1024	7152	0\n"
		"gpr	v20	.1024	7280	0\n"
		"gpr	v21	.1024	7408	0\n"
		"gpr	v22	.1024	7536	0\n"
		"gpr	v23	.1024	7664	0\n"
		"gpr	v24	.1024	7792	0\n"
		"gpr	v25	.1024	7920	0\n"
		"gpr	v26	.1024	8048	0\n"
		"gpr	v27	.1024	8176	0\n"
		"gpr	v28	.1024	8304	0\n"
		"gpr	v29	.1024	8432	0\n"
		"gpr	v30	.1024	8560	0\n"
		"gpr	v31	.1024	8688	0\n"

		"gpr	v1:0	.2048	8816	0\n"
		"gpr	v3:2	.2048	9072	0\n"
		"gpr	v5:4	.2048	9328	0\n"
		"gpr	v7:6	.2048	9584	0\n"
		"gpr	v9:8	.2048	9840	0\n"
		"gpr	v11:10	.2048	10096	0\n"
		"gpr	v13:12	.2048	10352	0\n"
		"gpr	v15:14	.2048	10608	0\n"
		"gpr	v17:16	.2048	10864	0\n"
		"gpr	v19:18	.2048	11120	0\n"
		"gpr	v21:20	.2048	11376	0\n"
		"gpr	v23:22	.2048	11632	0\n"
		"gpr	v25:24	.2048	11888	0\n"
		"gpr	v27:26	.2048	12144	0\n"
		"gpr	v29:28	.2048	12400	0\n"
		"gpr	v31:30	.2048	12656	0\n"

		"gpr	r0	.32	12912	0\n"
		"gpr	r1	.32	12916	0\n"
		"gpr	r2	.32	12920	0\n"
		"gpr	r3	.32	12924	0\n"
		"gpr	r4	.32	12928	0\n"
		"gpr	r5	.32	12932	0\n"
		"gpr	r6	.32	12936	0\n"
		"gpr	r7	.32	12940	0\n"
		"gpr	r8	.32	12944	0\n"
		"gpr	r9	.32	12948	0\n"
		"gpr	r12	.32	12952	0\n"
		"gpr	r13	.32	12956	0\n"
		"gpr	r14	.32	12960	0\n"
		"gpr	r15	.32	12964	0\n"
		"gpr	r16	.32	12968	0\n"
		"gpr	r17	.32	12972	0\n"
		"gpr	r18	.32	12976	0\n"
		"gpr	r19	.32	12980	0\n"
		"gpr	r20	.32	12984	0\n"
		"gpr	r21	.32	12988	0\n"
		"gpr	r22	.32	12992	0\n"
		"gpr	r23	.32	12996	0\n"
		"gpr	r24	.32	13000	0\n"
		"gpr	r25	.32	13004	0\n"
		"gpr	r26	.32	13008	0\n"
		"gpr	r27	.32	13012	0\n"
		"gpr	r28	.32	13016	0\n"
		"gpr	r10	.32	13020	0\n"
		"gpr	r11	.32	13024	0\n"
		"gpr	r29	.32	13028	0\n"
		"gpr	r30	.32	13032	0\n"
		"gpr	r31	.32	13036	0\n"

		"gpr	p0	.32	13040	0\n"
		"gpr	p1	.32	13044	0\n"
		"gpr	p2	.32	13048	0\n"
		"gpr	p3	.32	13052	0\n"

		"gpr	sgp0	.32	13056	0\n"
		"gpr	sgp1	.32	13060	0\n"
		"gpr	stid	.32	13064	0\n"
		"gpr	elr	.32	13068	0\n"
		"gpr	badva0	.32	13072	0\n"
		"gpr	badva1	.32	13076	0\n"
		"gpr	ssr	.32	13080	0\n"
		"gpr	ccr	.32	13084	0\n"
		"gpr	htid	.32	13088	0\n"
		"gpr	badva	.32	13092	0\n"
		"gpr	imask	.32	13096	0\n"
		"gpr	s11	.32	13100	0\n"
		"gpr	s12	.32	13104	0\n"
		"gpr	s13	.32	13108	0\n"
		"gpr	s14	.32	13112	0\n"
		"gpr	s15	.32	13116	0\n"
		"gpr	s19	.32	13120	0\n"
		"gpr	s23	.32	13124	0\n"
		"gpr	s25	.32	13128	0\n"
		"gpr	evb	.32	13132	0\n"
		"gpr	modectl	.32	13136	0\n"
		"gpr	syscfg	.32	13140	0\n"
		"gpr	s20	.32	13144	0\n"
		"gpr	vid	.32	13148	0\n"
		"gpr	s22	.32	13152	0\n"
		"gpr	s24	.32	13156	0\n"
		"gpr	s26	.32	13160	0\n"
		"gpr	cfgbase	.32	13164	0\n"
		"gpr	diag	.32	13168	0\n"
		"gpr	rev	.32	13172	0\n"
		"gpr	pcyclehi	.32	13176	0\n"
		"gpr	pcyclelo	.32	13180	0\n"
		"gpr	isdbst	.32	13184	0\n"
		"gpr	isdbcfg0	.32	13188	0\n"
		"gpr	isdbcfg1	.32	13192	0\n"
		"gpr	s35	.32	13196	0\n"
		"gpr	brkptpc0	.32	13200	0\n"
		"gpr	brkptcfg0	.32	13204	0\n"
		"gpr	brkptpc1	.32	13208	0\n"
		"gpr	brkptcfg1	.32	13212	0\n"
		"gpr	isdbmbxin	.32	13216	0\n"
		"gpr	isdbmbxout	.32	13220	0\n"
		"gpr	isdben	.32	13224	0\n"
		"gpr	isdbgpr	.32	13228	0\n"
		"gpr	s44	.32	13232	0\n"
		"gpr	s45	.32	13236	0\n"
		"gpr	s46	.32	13240	0\n"
		"gpr	s47	.32	13244	0\n"
		"gpr	pmucnt0	.32	13248	0\n"
		"gpr	pmucnt1	.32	13252	0\n"
		"gpr	pmucnt2	.32	13256	0\n"
		"gpr	pmucnt3	.32	13260	0\n"
		"gpr	pmuevtcfg	.32	13264	0\n"
		"gpr	pmucfg	.32	13268	0\n"
		"gpr	s54	.32	13272	0\n"
		"gpr	s55	.32	13276	0\n"
		"gpr	s56	.32	13280	0\n"
		"gpr	s57	.32	13284	0\n"
		"gpr	s58	.32	13288	0\n"
		"gpr	s59	.32	13292	0\n"
		"gpr	s60	.32	13296	0\n"
		"gpr	s61	.32	13300	0\n"
		"gpr	s62	.32	13304	0\n"
		"gpr	s63	.32	13308	0\n"
		"gpr	s64	.32	13312	0\n"
		"gpr	s65	.32	13316	0\n"
		"gpr	s66	.32	13320	0\n"
		"gpr	s67	.32	13324	0\n"
		"gpr	s68	.32	13328	0\n"
		"gpr	s69	.32	13332	0\n"
		"gpr	s70	.32	13336	0\n"
		"gpr	s71	.32	13340	0\n"
		"gpr	s72	.32	13344	0\n"
		"gpr	s73	.32	13348	0\n"
		"gpr	s74	.32	13352	0\n"
		"gpr	s75	.32	13356	0\n"
		"gpr	s76	.32	13360	0\n"
		"gpr	s77	.32	13364	0\n"
		"gpr	s78	.32	13368	0\n"
		"gpr	s79	.32	13372	0\n"
		"gpr	s80	.32	13376	0\n"

		"gpr	s1:0	.64	13380	0\n"
		"gpr	s3:2	.64	13388	0\n"
		"gpr	s5:4	.64	13396	0\n"
		"gpr	s7:6	.64	13404	0\n"
		"gpr	s9:8	.64	13412	0\n"
		"gpr	s11:10	.64	13420	0\n"
		"gpr	s13:12	.64	13428	0\n"
		"gpr	s15:14	.64	13436	0\n"
		"gpr	s17:16	.64	13444	0\n"
		"gpr	s19:18	.64	13452	0\n"
		"gpr	s21:20	.64	13460	0\n"
		"gpr	s23:22	.64	13468	0\n"
		"gpr	s25:24	.64	13476	0\n"
		"gpr	s27:26	.64	13484	0\n"
		"gpr	s29:28	.64	13492	0\n"
		"gpr	s31:30	.64	13500	0\n"
		"gpr	s33:32	.64	13508	0\n"
		"gpr	s35:34	.64	13516	0\n"
		"gpr	s37:36	.64	13524	0\n"
		"gpr	s39:38	.64	13532	0\n"
		"gpr	s41:40	.64	13540	0\n"
		"gpr	s43:42	.64	13548	0\n"
		"gpr	s45:44	.64	13556	0\n"
		"gpr	s47:46	.64	13564	0\n"
		"gpr	s49:48	.64	13572	0\n"
		"gpr	s51:50	.64	13580	0\n"
		"gpr	s53:52	.64	13588	0\n"
		"gpr	s55:54	.64	13596	0\n"
		"gpr	s57:56	.64	13604	0\n"
		"gpr	s59:58	.64	13612	0\n"
		"gpr	s61:60	.64	13620	0\n"
		"gpr	s63:62	.64	13628	0\n"
		"gpr	s65:64	.64	13636	0\n"
		"gpr	s67:66	.64	13644	0\n"
		"gpr	s69:68	.64	13652	0\n"
		"gpr	s71:70	.64	13660	0\n"
		"gpr	s73:72	.64	13668	0\n"
		"gpr	s75:74	.64	13676	0\n"
		"gpr	s77:76	.64	13684	0\n"
		"gpr	s79:78	.64	13692	0\n";
	return strdup(p);
}

RzAnalysisPlugin rz_analysis_plugin_hexagon = {
	.name = "hexagon",
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.license = "LGPL3",
	.arch = "hexagon",
	.bits = 32,
	.op = hexagon_v6_op,
	.esil = false,
	.get_reg_profile = get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_hexagon_v6,
	.version = RZ_VERSION
};
#endif
