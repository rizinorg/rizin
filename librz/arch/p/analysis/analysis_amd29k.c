// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include "amd29k/amd29k.h"

static char *amd29k_get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	rsp\n"
		"=BP	rab\n"
		"=SR	gr3\n" // status register ??
		"=SN	gr4\n" // also for ret
		"=A0	lr1\n" // also for ret
		"=A1	lr2\n"
		"=A2	lr3\n"
		"=A3	lr4\n"
		"=A4	lr5\n"
		"=A5	lr6\n"
		"=A6	lr7\n"
		"gpr	gr0     .32 0 0\n" // indirect pointer (ipa)
		"gpr	rsp     .32 8 0\n" // stack pointer
		"gpr	gr2     .32 16 0\n" // frame pointer
		"gpr	gr3     .32 24 0\n"
		"gpr	gr4     .32 32 0\n"
		"gpr	gr5     .32 40 0\n"
		"gpr	gr6     .32 48 0\n"
		"gpr	gr7     .32 56 0\n"
		"gpr	gr8     .32 64 0\n"
		"gpr	gr9     .32 72 0\n"
		"gpr	gr10    .32 80 0\n"
		"gpr	gr11    .32 88 0\n"
		"gpr	gr12    .32 96 0\n"
		"gpr	gr13    .32 104 0\n"
		"gpr	gr14    .32 112 0\n"
		"gpr	gr15    .32 120 0\n"
		"gpr	gr16    .32 128 0\n"
		"gpr	gr17    .32 136 0\n"
		"gpr	gr18    .32 144 0\n"
		"gpr	gr19    .32 152 0\n"
		"gpr	gr20    .32 160 0\n"
		"gpr	gr21    .32 168 0\n"
		"gpr	gr22    .32 176 0\n"
		"gpr	gr23    .32 184 0\n"
		"gpr	gr24    .32 192 0\n"
		"gpr	gr25    .32 200 0\n"
		"gpr	gr26    .32 208 0\n"
		"gpr	gr27    .32 216 0\n"
		"gpr	gr28    .32 224 0\n"
		"gpr	gr29    .32 232 0\n"
		"gpr	gr30    .32 240 0\n"
		"gpr	gr31    .32 248 0\n"
		"gpr	gr32    .32 256 0\n"
		"gpr	gr33    .32 264 0\n"
		"gpr	gr34    .32 272 0\n"
		"gpr	gr35    .32 280 0\n"
		"gpr	gr36    .32 288 0\n"
		"gpr	gr37    .32 296 0\n"
		"gpr	gr38    .32 304 0\n"
		"gpr	gr39    .32 312 0\n"
		"gpr	gr40    .32 320 0\n"
		"gpr	gr41    .32 328 0\n"
		"gpr	gr42    .32 336 0\n"
		"gpr	gr43    .32 344 0\n"
		"gpr	gr44    .32 352 0\n"
		"gpr	gr45    .32 360 0\n"
		"gpr	gr46    .32 368 0\n"
		"gpr	gr47    .32 376 0\n"
		"gpr	gr48    .32 384 0\n"
		"gpr	gr49    .32 392 0\n"
		"gpr	gr50    .32 400 0\n"
		"gpr	gr51    .32 408 0\n"
		"gpr	gr52    .32 416 0\n"
		"gpr	gr53    .32 424 0\n"
		"gpr	gr54    .32 432 0\n"
		"gpr	gr55    .32 440 0\n"
		"gpr	gr56    .32 448 0\n"
		"gpr	gr57    .32 456 0\n"
		"gpr	gr58    .32 464 0\n"
		"gpr	gr59    .32 472 0\n"
		"gpr	gr60    .32 480 0\n"
		"gpr	gr61    .32 488 0\n"
		"gpr	gr62    .32 496 0\n"
		"gpr	gr63    .32 504 0\n"
		"gpr	it0     .32 512 0\n"
		"gpr	it1     .32 520 0\n" // Interrupt Handler Temporary Register
		"gpr	it2     .32 528 0\n" // Interrupt Handler Temporary Register
		"gpr	it3     .32 536 0\n" // Interrupt Handler Temporary Register
		"gpr	kt0     .32 544 0\n" // Operating System Temporary Register
		"gpr	kt1     .32 552 0\n" // Operating System Temporary Register
		"gpr	kt2     .32 560 0\n" // Operating System Temporary Register
		"gpr	kt3     .32 568 0\n" // Operating System Temporary Register
		"gpr	kt4     .32 576 0\n" // Operating System Temporary Register
		"gpr	kt5     .32 584 0\n" // Operating System Temporary Register
		"gpr	kt6     .32 592 0\n" // Operating System Temporary Register
		"gpr	kt7     .32 600 0\n" // Operating System Temporary Register
		"gpr	kt8     .32 608 0\n" // Operating System Temporary Register
		"gpr	kt9     .32 616 0\n" // Operating System Temporary Register
		"gpr	kt10    .32 624 0\n" // Operating System Temporary Register
		"gpr	kt11    .32 632 0\n" // Operating System Temporary Register
		"gpr	ks0     .32 640 0\n" // Operating System Static Register
		"gpr	ks1     .32 648 0\n" // Operating System Static Register
		"gpr	ks2     .32 656 0\n" // Operating System Static Register
		"gpr	ks3     .32 664 0\n" // Operating System Static Register
		"gpr	ks4     .32 672 0\n" // Operating System Static Register
		"gpr	ks5     .32 680 0\n" // Operating System Static Register
		"gpr	ks6     .32 688 0\n" // Operating System Static Register
		"gpr	ks7     .32 696 0\n" // Operating System Static Register
		"gpr	ks8     .32 704 0\n" // Operating System Static Register
		"gpr	ks9     .32 712 0\n" // Operating System Static Register
		"gpr	ks10    .32 720 0\n" // Operating System Static Register
		"gpr	ks11    .32 728 0\n" // Operating System Static Register
		"gpr	ks12    .32 736 0\n" // Operating System Static Register
		"gpr	ks13    .32 744 0\n" // Operating System Static Register
		"gpr	ks14    .32 752 0\n" // Operating System Static Register
		"gpr	ks15    .32 760 0\n" // Operating System Static Register
		"gpr	v0      .32 768 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v1      .32 776 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v2      .32 784 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v3      .32 792 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v4      .32 800 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v5      .32 808 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v6      .32 816 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v7      .32 824 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v8      .32 832 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v9      .32 840 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v10     .32 848 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v11     .32 856 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v12     .32 864 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v13     .32 872 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v14     .32 880 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	v15     .32 888 0\n" // Compiler Temporary Registers and Function Return Values
		"gpr	r1      .32 896 0\n" // Reserved for developers
		"gpr	r2      .32 904 0\n" // Reserved for developers
		"gpr	r3      .32 912 0\n" // Reserved for developers
		"gpr	r4      .32 920 0\n" // Reserved for developers
		"gpr	x0      .32 928 0\n" // Compiler Temporary register
		"gpr	x1      .32 936 0\n" // Compiler Temporary register
		"gpr	x2      .32 944 0\n" // Compiler Temporary register
		"gpr	x3      .32 952 0\n" // Compiler Temporary register
		"gpr	x4      .32 960 0\n" // Compiler Temporary register
		"gpr	tav     .32 968 0\n" // Trap Argument Vector
		"gpr	tpc     .32 976 0\n" // Trap Return Pointer
		"gpr	lrp     .32 984 0\n" // Large Return Pointer
		"gpr	slp     .32 992 0\n" // Static Link Pointer
		"gpr	msp     .32 1000 0\n" // Register and Memory stack support
		"gpr	rab     .32 1008 0\n" // Register and Memory stack support
		"gpr	rfb     .32 1016 0\n" // Register and Memory stack support
		// Local Register Cache
		"gpr	lr0     .32 1024 0\n"
		"gpr	lr1     .32 1032 0\n"
		"gpr	p0      .32 1040 0\n" // Parameter Register
		"gpr	p1      .32 1048 0\n" // Parameter Register
		"gpr	p2      .32 1056 0\n" // Parameter Register
		"gpr	p3      .32 1064 0\n" // Parameter Register
		"gpr	p4      .32 1072 0\n" // Parameter Register
		"gpr	p5      .32 1080 0\n" // Parameter Register
		"gpr	p6      .32 1088 0\n" // Parameter Register
		"gpr	p7      .32 1096 0\n" // Parameter Register
		"gpr	p8      .32 1104 0\n" // Parameter Register
		"gpr	p9      .32 1112 0\n" // Parameter Register
		"gpr	p10     .32 1120 0\n" // Parameter Register
		"gpr	p11     .32 1128 0\n" // Parameter Register
		"gpr	p12     .32 1136 0\n" // Parameter Register
		"gpr	p13     .32 1144 0\n" // Parameter Register
		"gpr	p14     .32 1152 0\n" // Parameter Register
		"gpr	p15     .32 1160 0\n" // Parameter Register
		"gpr	lr18    .32 1168 0\n"
		"gpr	lr19    .32 1176 0\n"
		"gpr	lr20    .32 1184 0\n"
		"gpr	lr21    .32 1192 0\n"
		"gpr	lr22    .32 1200 0\n"
		"gpr	lr23    .32 1208 0\n"
		"gpr	lr24    .32 1216 0\n"
		"gpr	lr25    .32 1224 0\n"
		"gpr	lr26    .32 1232 0\n"
		"gpr	lr27    .32 1240 0\n"
		"gpr	lr28    .32 1248 0\n"
		"gpr	lr29    .32 1256 0\n"
		"gpr	lr30    .32 1264 0\n"
		"gpr	lr31    .32 1272 0\n"
		"gpr	lr32    .32 1280 0\n"
		"gpr	lr33    .32 1288 0\n"
		"gpr	lr34    .32 1296 0\n"
		"gpr	lr35    .32 1304 0\n"
		"gpr	lr36    .32 1312 0\n"
		"gpr	lr37    .32 1320 0\n"
		"gpr	lr38    .32 1328 0\n"
		"gpr	lr39    .32 1336 0\n"
		"gpr	lr40    .32 1344 0\n"
		"gpr	lr41    .32 1352 0\n"
		"gpr	lr42    .32 1360 0\n"
		"gpr	lr43    .32 1368 0\n"
		"gpr	lr44    .32 1376 0\n"
		"gpr	lr45    .32 1384 0\n"
		"gpr	lr46    .32 1392 0\n"
		"gpr	lr47    .32 1400 0\n"
		"gpr	lr48    .32 1408 0\n"
		"gpr	lr49    .32 1416 0\n"
		"gpr	lr50    .32 1424 0\n"
		"gpr	lr51    .32 1432 0\n"
		"gpr	lr52    .32 1440 0\n"
		"gpr	lr53    .32 1448 0\n"
		"gpr	lr54    .32 1456 0\n"
		"gpr	lr55    .32 1464 0\n"
		"gpr	lr56    .32 1472 0\n"
		"gpr	lr57    .32 1480 0\n"
		"gpr	lr58    .32 1488 0\n"
		"gpr	lr59    .32 1496 0\n"
		"gpr	lr60    .32 1504 0\n"
		"gpr	lr61    .32 1512 0\n"
		"gpr	lr62    .32 1520 0\n"
		"gpr	lr63    .32 1528 0\n"
		"gpr	lr64    .32 1536 0\n"
		"gpr	lr65    .32 1544 0\n"
		"gpr	lr66    .32 1552 0\n"
		"gpr	lr67    .32 1560 0\n"
		"gpr	lr68    .32 1568 0\n"
		"gpr	lr69    .32 1576 0\n"
		"gpr	lr70    .32 1584 0\n"
		"gpr	lr71    .32 1592 0\n"
		"gpr	lr72    .32 1600 0\n"
		"gpr	lr73    .32 1608 0\n"
		"gpr	lr74    .32 1616 0\n"
		"gpr	lr75    .32 1624 0\n"
		"gpr	lr76    .32 1632 0\n"
		"gpr	lr77    .32 1640 0\n"
		"gpr	lr78    .32 1648 0\n"
		"gpr	lr79    .32 1656 0\n"
		"gpr	lr80    .32 1664 0\n"
		"gpr	lr81    .32 1672 0\n"
		"gpr	lr82    .32 1680 0\n"
		"gpr	lr83    .32 1688 0\n"
		"gpr	lr84    .32 1696 0\n"
		"gpr	lr85    .32 1704 0\n"
		"gpr	lr86    .32 1712 0\n"
		"gpr	lr87    .32 1720 0\n"
		"gpr	lr88    .32 1728 0\n"
		"gpr	lr89    .32 1736 0\n"
		"gpr	lr90    .32 1744 0\n"
		"gpr	lr91    .32 1752 0\n"
		"gpr	lr92    .32 1760 0\n"
		"gpr	lr93    .32 1768 0\n"
		"gpr	lr94    .32 1776 0\n"
		"gpr	lr95    .32 1784 0\n"
		"gpr	v0      .32 1792 0\n"
		"gpr	v1      .32 1800 0\n"
		"gpr	v2      .32 1808 0\n"
		"gpr	v3      .32 1816 0\n"
		"gpr	v4      .32 1824 0\n"
		"gpr	v5      .32 1832 0\n"
		"gpr	v6      .32 1840 0\n"
		"gpr	v7      .32 1848 0\n"
		"gpr	v8      .32 1856 0\n"
		"gpr	v9      .32 1864 0\n"
		"gpr	v10     .32 1872 0\n"
		"gpr	v11     .32 1880 0\n"
		"gpr	v12     .32 1888 0\n"
		"gpr	v13     .32 1896 0\n"
		"gpr	v14     .32 1904 0\n"
		"gpr	v15     .32 1912 0\n"
		"gpr	lr112   .32 1920 0\n"
		"gpr	lr113   .32 1928 0\n"
		"gpr	lr114   .32 1936 0\n"
		"gpr	lr115   .32 1944 0\n"
		"gpr	lr116   .32 1952 0\n"
		"gpr	lr117   .32 1960 0\n"
		"gpr	lr118   .32 1968 0\n"
		"gpr	lr119   .32 1976 0\n"
		"gpr	lr120   .32 1984 0\n"
		"gpr	lr121   .32 1992 0\n"
		"gpr	lr122   .32 2000 0\n"
		"gpr	lr123   .32 2008 0\n"
		"gpr	lr124   .32 2016 0\n"
		"gpr	lr125   .32 2024 0\n"
		"gpr	lr126   .32 2032 0\n"
		"gpr	lr127   .32 2040 0\n";
	return rz_str_dup(p);
}

static int amd29k_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static int amd29k_analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	op->size = 4;
	op->eob = false;

	ut32 cpu_id = AMD29K_29000;
	if (RZ_STR_EQ(a->cpu, "29050")) {
		cpu_id = AMD29K_29050;
	}

	amd29k_instr_t instruction = { 0 };
	if (amd29k_instr_decode(buf, len, &instruction, cpu_id)) {
		op->type = instruction.op_type;
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
			op->jump = amd29k_instr_jump(&instruction, addr);
			op->delay = 1;
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			op->jump = amd29k_instr_jump(&instruction, addr);
			op->fail = addr + 4;
			op->delay = 1;
			break;
		case RZ_ANALYSIS_OP_TYPE_ICALL:
			if (amd29k_instr_is_ret(&instruction)) {
				op->type = RZ_ANALYSIS_OP_TYPE_RET;
				op->eob = true;
			}
			op->delay = 1;
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			op->eob = true;
			op->delay = 1;
			break;
		default:
			op->delay = 0;
			break;
		}
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_dup(instruction.mnemonic);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = amd29k_instr_opex(&instruction, addr);
	}

	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_amd29k = {
	.name = "amd29k",
	.desc = "AMD 29k analysis",
	.license = "BSD",
	.esil = false,
	.arch = "amd29k",
	.bits = 32,
	.archinfo = amd29k_archinfo,
	.op = &amd29k_analyze_op,
	.get_reg_profile = &amd29k_get_reg_profile,
};
