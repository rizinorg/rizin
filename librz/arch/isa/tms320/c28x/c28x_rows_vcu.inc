// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

// clang-format off
	{ OP(0xffff0000, 0xe5020000), .mnem = "vcadd", RZTYPE(ADD), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2) } },
	{ OP(0xffff0000, 0xe5010000), .mnem = "vcmac", RZTYPE(MUL), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0) } },
	{ OP(0xffff0000, 0xe50f0000), .mnem = "vccmac", RZTYPE(MUL), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0) } },
	{ OP(0xfffffff8, 0xe6f20b08), .mnem = "vdec", RZTYPE(SUB), .len = 4, .ops = { VRREGL(0) } },
	{ OP(0xfffffe00, 0xe6810400), .mnem = "vgfacc", RZTYPE(ADD), .len = 4, .ops = { VRREG3(3), VRREG3(0), REG(VR7) } },
	{ OP(0xfffffe00, 0xe6802200), .mnem = "vgfmac4", RZTYPE(MUL), .len = 4, .ops = { VRREG3(6), VRREG3(3), VRREG3(0) } },
	{ OP(0xfffffe00, 0xe6802000), .mnem = "vgfmpy4", RZTYPE(MUL), .len = 4, .ops = { VRREG3(6), VRREG3(3), VRREG3(0) } },
	{ OP(0xfff00000, 0xe5700000), .mnem = "vitdhaddsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(16) } },
	{ OP(0xfff00000, 0xe5f00000), .mnem = "vitdhsubadd", RZTYPE(SUB), .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(16) } },
	{ OP(0xfff00000, 0xe5300000), .mnem = "vitdladdsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(16) } },
	{ OP(0xfff00000, 0xe5e00000), .mnem = "vitdlsubadd", RZTYPE(SUB), .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(16) } },
	{ OP(0xffff0000, 0xe52b0000), .mnem = "vcfft1", RZTYPE(MOV), .ops = { REG(VR2), REG(VR5), REG(VR4) } },
	{ OP(0xffff0000, 0xe5f30000), .mnem = "vitdhsubadd", RZTYPE(SUB), .ops = { REG(VR4), REG(VR3), REG(VR2), REG(VR3) } },
	{ OP(0xffff0000, 0xe5310000), .mnem = "vitdladdsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), REG(VR1) } },
	{ OP(0xffff0000, 0xe5330000), .mnem = "vitdladdsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), REG(VR3) } },
	{ OP(0xffff0000, 0xe5350000), .mnem = "vitdladdsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), REG(VR5) } },
	{ OP(0xffff0000, 0xe5370000), .mnem = "vitdladdsub", RZTYPE(ADD), .ops = { REG(VR4), REG(VR3), REG(VR2), REG(VR7) } },
	{ OP(0xffff0000, 0xe5410000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(1) } },
	{ OP(0xffff0000, 0xe54b0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(11) } },
	{ OP(0xffff0000, 0xe54d0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(13) } },
	{ OP(0xffff0000, 0xe54f0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(15) } },
	{ OP(0xffff0000, 0xe5510000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(17) } },
	{ OP(0xffff0000, 0xe5530000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(19) } },
	{ OP(0xffff0000, 0xe5550000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(21) } },
	{ OP(0xffff0000, 0xe5570000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(23) } },
	{ OP(0xffff0000, 0xe5590000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(25) } },
	{ OP(0xffff0000, 0xe55b0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(27) } },
	{ OP(0xffff0000, 0xe55d0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(29) } },
	{ OP(0xffff0000, 0xe5430000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(3) } },
	{ OP(0xffff0000, 0xe5450000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(5) } },
	{ OP(0xffff0000, 0xe5470000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(7) } },
	{ OP(0xffff0000, 0xe5490000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(9) } },
	{ OP(0xffff0000, 0xe52b0000), .mnem = "vcfft1", RZTYPE(MOV), .ops = { REG(VR2), REG(VR5), REG(VR4) } },
	{ OP(0xffff0000, 0xe52d0000), .mnem = "vclrcrcmsgflip", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5410000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(1) } },
	{ OP(0xffff0000, 0xe54b0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(11) } },
	{ OP(0xffff0000, 0xe54d0000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(13) } },
	{ OP(0xffff0000, 0xe5570000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(23) } },
	{ OP(0xffff0000, 0xe5430000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(3) } },
	{ OP(0xffff0000, 0xe5450000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(5) } },
	{ OP(0xffff0000, 0xe5470000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(7) } },
	{ OP(0xffff0000, 0xe5490000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMV(9) } },
	{ OP(0xfff00000, 0xe7700000), .mnem = "vmovxi", RZTYPE(MOV), .len = 4, .ops = { VRREG(0), IMMSPLIT(4, 12, 16) } },
	{ OP(0xfff00000, 0xe7e00000), .mnem = "vmovix", RZTYPE(MOV), .len = 4, .ops = { VRREG(0), IMMSPLIT(4, 12, 16) } },
	{ OP(0xfff00000, 0xe7f00000), .mnem = "vmovzi", RZTYPE(MOV), .len = 4, .ops = { VRREG(0), IMMSPLIT(4, 12, 16) } },
	{ OP(0xfff00000, 0xa1000000), .mnem = "vcflip", RZTYPE(REV), .ops = { VRREG(16) } },
	{ OP(0xfff00000, 0xa1100000), .mnem = "vccon", RZTYPE(MOV), .ops = { VRREG(16) } },
	{ OP(0xfff00000, 0xa1200000), .mnem = "vbitflip", RZTYPE(REV), .ops = { VRREG(16) } },
	{ OP(0xff000000, 0xbd000000), .mnem = "vmov32", RZTYPE(MOV), .len = 4, .ops = { DMA(0, 16), LOC32(16) } },
	{ OP(0xff000000, 0xbf000000), .mnem = "vmov32", RZTYPE(MOV), .len = 4, .ops = { LOC32(16), DMA(0, 16) } },
	{ OP(0xffff0000, 0xe5060000), .mnem = "vsaton", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5070000), .mnem = "vsatoff", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5080000), .mnem = "vrndon", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5090000), .mnem = "vrndoff", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe50c0000), .mnem = "vitbm2", RZTYPE(CMP), .ops = { REG(VR0) } },
	{ OP(0xffff0000, 0xe50d0000), .mnem = "vitbm3", RZTYPE(CMP), .ops = { REG(VR0), REG(VR1), REG(VR2) } },
	{ OP(0xfff00000, 0xe5100000), .mnem = "vneg", RZTYPE(CPL), .ops = { VRREG(16) } },
	{ OP(0xffff0000, 0xe5200000), .mnem = "vclrdive", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5210000), .mnem = "vsetcpack", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5220000), .mnem = "vclrcpack", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5230000), .mnem = "vsetopack", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5240000), .mnem = "vcrcclr", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5250000), .mnem = "vclropack", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5260000), .mnem = "vitstage", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe5270000), .mnem = "vnop", RZTYPE(NOP) },
	{ OP(0xffff0000, 0xe5290000), .mnem = "vtclear", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe52c0000), .mnem = "vsetcrcmsgflip", RZTYPE(MOV) },
	{ OP(0xffff0000, 0xe52d0000), .mnem = "vclrcrcmsgflip", RZTYPE(MOV) },
	{ OP(0xffe00000, 0xe5400000), .mnem = "vsetshr", RZTYPE(SHR), .ops = { IMMU(16, 5) } },
	{ OP(0xffe00000, 0xe5c00000), .mnem = "vsetshl", RZTYPE(SHL), .ops = { IMMU(16, 5) } },
	{ OP(0xfffe0000, 0xa1300000), .mnem = "vcfft2", RZTYPE(MUL), .ops = { REG(VR7), REG(VR6), REG(VR4), REG(VR2), REG(VR1), REG(VR0), IMMU(16, 1) } }, // VCFFT2 VR7,VR6,VR4,VR2,VR1,VR0,#1bit
	{ OP(0xfffe0000, 0xa1320000), .mnem = "vcfft3", RZTYPE(MUL), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR0), IMMU(16, 1) } }, // VCFFT3 VR5,VR4,VR3,VR2,VR0,#1bit
	{ OP(0xfffe0000, 0xa1340000), .mnem = "vcfft4", RZTYPE(MUL), .ops = { REG(VR4), REG(VR2), REG(VR1), REG(VR0), IMMU(16, 1) } }, // VCFFT4 VR4,VR2,VR1,VR0,#1bit
	{ OP(0xfffe0000, 0xa1360000), .mnem = "vcfft8", RZTYPE(MUL), .ops = { REG(VR3), REG(VR2), IMMU(16, 1) } }, // VCFFT8 VR3,VR2,#1bit
	{ OP(0xfffe0000, 0xa1380000), .mnem = "vcfft9", RZTYPE(MUL), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(16, 1) } }, // VCFFT9 VR5,VR4,VR3,VR2,VR1,VR0,#1bit
	{ OP(0xfffe0000, 0xa13a0000), .mnem = "vcfft10", RZTYPE(MUL), .ops = { REG(VR7), REG(VR6), REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(16, 1) } }, // VCFFT10 VR7,VR6,VR3,VR2,VR1,VR0,#1bit
	{ OP(0xfffff000, 0xe2040000), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), VRREG(8) } }, // VMOV32 mem32,VRa
	{ OP(0xfffffc00, 0xe2050000), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), VTREG2(8) } }, // VMOV32 mem32,VTa
	{ OP(0xffffff00, 0xe2060000), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), REG(VCRC) } }, // VMOV32 mem32,VCRC
	{ OP(0xffffff00, 0xe2060100), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC16(0), REG(VCRCPOLY) } }, // VMOV32 mem16,VCRCPOLY
	{ OP(0xffffff00, 0xe2060200), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC16(0), REG(VCRCSIZE) } }, // VMOV32 mem16,VCRCSIZE
	{ OP(0xfffff000, 0xe2070000), .mnem = "vcmpy", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), LOC32(0), VRREG(8) } }, // VCMPY VR3,VR2,VR1,VR0 || VMOV32 mem32,VRa
	{ OP(0xfffff000, 0xe2071000), .mnem = "vccmpy", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), LOC32(0), VRREG(8) } }, // VCCMPY VR3,VR2,VR1,VR0 || VMOV32 mem32,VRa
	{ OP(0xfffffe00, 0xe2072000), .mnem = "vcfft2", RZTYPE(MUL), .len = 4, .ops = { REG(VR7), REG(VR6), REG(VR4), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), LOC32(0), REG(VR1) } }, // VCFFT2 VR7,VR6,VR4,VR2,VR1,VR0,#1bit || VMOV32 mem32,VR1
	{ OP(0xfffffe00, 0xe2072200), .mnem = "vcfft5", RZTYPE(MUL), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), LOC32(0), REG(VR1) } }, // VCFFT5 VR5,VR4,VR3,VR2,VR1,VR0,#1bit || VMOV32 mem32,VR1
	{ OP(0xfffffe00, 0xe2072400), .mnem = "vcfft6", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), LOC32(0), REG(VR1) } }, // VCFFT6 VR3,VR2,VR1,VR0,#1bit || VMOV32 mem32,VR1
	{ OP(0xfffffe00, 0xe2072600), .mnem = "vcfft8", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), IMMU(8, 1), PAR(VMOV32), LOC32(0), REG(VR4) } }, // VCFFT8 VR3,VR2,#1bit || VMOV32 mem32,VR4
	{ OP(0xfffffe00, 0xe2072800), .mnem = "vcfft9", RZTYPE(MUL), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), LOC32(0), REG(VR5) } }, // VCFFT9 VR5,VR4,VR3,VR2,VR1,VR0,#1bit || VMOV32 mem32,VR5
	{ OP(0xffff0000, 0xe2080000), .mnem = "vitdladdsub", RZTYPE(ADD), .len = 4, .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(8), PAR(VMOV32), LOC32(0), VRREG(12) } }, // VITDLADDSUB VR4,VR3,VR2,VRa || VMOV32 mem32,VRb
	{ OP(0xffff0000, 0xe2090000), .mnem = "vitdhaddsub", RZTYPE(ADD), .len = 4, .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(8), PAR(VMOV32), LOC32(0), VRREG(12) } }, // VITDHADDSUB VR4,VR3,VR2,VRa || VMOV32 mem32,VRb
	{ OP(0xffff0000, 0xe20a0000), .mnem = "vitdlsubadd", RZTYPE(ADD), .len = 4, .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(8), PAR(VMOV32), LOC32(0), VRREG(12) } }, // VITDLSUBADD VR4,VR3,VR2,VRa || VMOV32 mem32,VRb
	{ OP(0xffff0000, 0xe20b0000), .mnem = "vitdhsubadd", RZTYPE(ADD), .len = 4, .ops = { REG(VR4), REG(VR3), REG(VR2), VRREG(8), PAR(VMOV32), LOC32(0), VRREG(12) } }, // VITDHSUBADD VR4,VR3,VR2,VRa || VMOV32 mem32,VRb
	{ OP(0xffffff00, 0xe20c0000), .mnem = "vtrace", RZTYPE(MOV), .len = 4, .ops = { LOC32(0), REG(VR0), REG(VT0), REG(VT1) } }, // VTRACE mem32,VR0,VT0,VT1
	{ OP(0xffffff00, 0xe20d0000), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), REG(VSTATUS) } }, // VMOV32 mem32,VSTATUS
	{ OP(0xffffe000, 0xe20e0000), .mnem = "vmov32", RZTYPE(STORE), .len = 4, .ops = { LOC32(0), VSMPAIR(8, 5) } }, // VMOV32 mem32,VSMn+1:VSMn
	{ OP(0xfffff000, 0xe2180000), .mnem = "vmov16", RZTYPE(STORE), .len = 4, .ops = { LOC16(0), VRREGL4(8) } }, // VMOV16 mem16,VRaL
	{ OP(0xfffff000, 0xe2181000), .mnem = "vmov16", RZTYPE(STORE), .len = 4, .ops = { LOC16(0), VRREGH4(8) } }, // VMOV16 mem16,VRaH
	{ OP(0xfffff000, 0xe2240000), .mnem = "vmovd32", RZTYPE(LOAD), .len = 4, .ops = { VRREG(8), LOC32(0) } }, // VMOVD32 VRa,mem32
	{ OP(0xffffff00, 0xe2510000), .mnem = "vcmac", RZTYPE(MUL), .len = 4, .ops = { REG(VR7), REG(VR6), REG(VR5), REG(VR4), LOC32(0), INDR(XAR_POSTINC, 7) } }, // VCMAC VR7,VR6,VR5,VR4,mem32,*XAR7++
	{ OP(0xffffff00, 0xe2800100), .mnem = "vitbm2", RZTYPE(CMP), .len = 4, .ops = { REG(VR0), LOC32(0) } }, // VITBM2 VR0,mem32
	{ OP(0xffffff00, 0xe2800200), .mnem = "vitstage", RZTYPE(CMP), .len = 4, .ops = { PAR(VITBM2), REG(VR0), LOC32(0) } }, // VITSTAGE || VITBM2 VR0,mem32
	{ OP(0xffffe000, 0xe2802000), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { VSMPAIR(8, 5), LOC32(0) } }, // VMOV32 VSMn+1:VSMn,mem32
	{ OP(0xffffc000, 0xe2810000), .mnem = "vinc", RZTYPE(ADD), .len = 4, .ops = { VRREGL(8), PAR(VMOV32), VRREG3(11), LOC32(0) } }, // VINC VRaL || VMOV32 VRb,mem32
	{ OP(0xffffc000, 0xe2814000), .mnem = "vdec", RZTYPE(SUB), .len = 4, .ops = { VRREGL(8), PAR(VMOV32), VRREG3(11), LOC32(0) } }, // VDEC VRaL || VMOV32 VRb,mem32
	{ OP(0xffffff00, 0xe2b00000), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { REG(VSTATUS), LOC32(0) } }, // VMOV32 VSTATUS,mem32
	{ OP(0xffffff00, 0xe2b00100), .mnem = "vtrace", RZTYPE(MOV), .len = 4, .ops = { REG(VR1), REG(VR0), REG(VT0), REG(VT1), PAR(VMOV32), REG(VT0), LOC32(0) } }, // VTRACE VR1,VR0,VT0,VT1 || VMOV32 VT0,mem32
	{ OP(0xfffffe00, 0xe2b00200), .mnem = "vcfft3", RZTYPE(MUL), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR0), IMMU(8, 1), PAR(VMOV32), REG(VR5), LOC32(0) } }, // VCFFT3 VR5,VR4,VR3,VR2,VR0,#1bit || VMOV32 VR5,mem32
	{ OP(0xfffffe00, 0xe2b00400), .mnem = "vcfft4", RZTYPE(MUL), .len = 4, .ops = { REG(VR4), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), REG(VR7), LOC32(0) } }, // VCFFT4 VR4,VR2,VR1,VR0,#1bit || VMOV32 VR7,mem32
	{ OP(0xfffffe00, 0xe2b00600), .mnem = "vcfft7", RZTYPE(MUL), .len = 4, .ops = { REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), REG(VR2), LOC32(0) } }, // VCFFT7 VR1,VR0,#1bit || VMOV32 VR2,mem32
	{ OP(0xfffffe00, 0xe2b00800), .mnem = "vcfft10", RZTYPE(MUL), .len = 4, .ops = { REG(VR7), REG(VR6), REG(VR3), REG(VR2), REG(VR1), REG(VR0), IMMU(8, 1), PAR(VMOV32), REG(VR0), LOC32(0) } }, // VCFFT10 VR7,VR6,VR3,VR2,VR1,VR0,#1bit || VMOV32 VR0,mem32
	{ OP(0xffffe000, 0xe2b10000), .mnem = "vpack4", RZTYPE(MOV), .len = 4, .ops = { VRREG3(10), LOC32(0), IMMU(8, 2) } }, // VPACK4 VRa,mem32,#2bit
	{ OP(0xfffe0000, 0xe2b40000), .mnem = "vgfmpy4", RZTYPE(MUL), .len = 4, .ops = { VRSPLIT(16, 1, 14), VRREG3(11), VRREG3(8), PAR(VMOV32), REG(VR0), LOC32(0) } }, // VGFMPY4 VRa,VRb,VRc || VMOV32 VR0,mem32
	{ OP(0xfffe0000, 0xe2b60000), .mnem = "vgfacc", RZTYPE(ADD), .len = 4, .ops = { VRSPLIT(16, 1, 14), VRREG3(11), REG(VR7), PAR(VMOV32), VRREG3(8), LOC32(0) } }, // VGFACC VRa,VRb,VR7 || VMOV32 VRc,mem32
	{ OP(0xfff80000, 0xe2b80000), .mnem = "vgfmac4", RZTYPE(MUL), .len = 4, .ops = { VRSPLIT(16, 1, 14), VRREG3(11), VRREG3(8), PAR(VPACK4), REG(VR0), LOC32(0), IMMU(17, 2) } }, // VGFMAC4 VRa,VRb,VRc || VPACK4 VR0,mem32,#2bit
	{ OP(0xffffff00, 0xe2c10000), .mnem = "vcrc32l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC32L_1 mem16
	{ OP(0xffffff00, 0xe2c20000), .mnem = "vcrc32h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC32H_1 mem16
	{ OP(0xffffff00, 0xe2c50000), .mnem = "vgfinit", RZTYPE(MOV), .len = 4, .ops = { LOC16(0) } }, // VGFINIT mem16
	{ OP(0xffffff00, 0xe2c50100), .mnem = "vsminit", RZTYPE(MOV), .len = 4, .ops = { LOC16(0) } }, // VSMINIT mem16
	{ OP(0xffffff00, 0xe2c50200), .mnem = "vitbm3", RZTYPE(CMP), .len = 4, .ops = { VRLFIX(0), VRLFIX(1), LOC32(0) } }, // VITBM3 VR0L,VR1L,mem32
	{ OP(0xffffff00, 0xe2c50300), .mnem = "vitstage", RZTYPE(CMP), .len = 4, .ops = { PAR(VMOV16), VRLFIX(0), LOC32(0) } }, // VITSTAGE || VMOV16 VR0L,mem32
	{ OP(0xfffff000, 0xe2c90000), .mnem = "vmov16", RZTYPE(LOAD), .len = 4, .ops = { VRREGL4(8), LOC16(0) } }, // VMOV16 VRaL,mem16
	{ OP(0xfffff000, 0xe2c91000), .mnem = "vmov16", RZTYPE(LOAD), .len = 4, .ops = { VRREGH4(8), LOC16(0) } }, // VMOV16 VRaH,mem16
	{ OP(0xffffff00, 0xe2cb0000), .mnem = "vcrc8l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC8L_1 mem16
	{ OP(0xffffff00, 0xe2cb0100), .mnem = "vcrc24l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC24L_1 mem16
	{ OP(0xffffff00, 0xe2cb0200), .mnem = "vcrc24h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC24H_1 mem16
	{ OP(0xffffff00, 0xe2cb0300), .mnem = "vcrc32p2l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC32P2L_1 mem16
	{ OP(0xffffff00, 0xe2cb0400), .mnem = "vcrc32p2h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC32P2H_1 mem16
	{ OP(0xffffff00, 0xe2cb0500), .mnem = "vmov16", RZTYPE(LOAD), .len = 4, .ops = { REG(VCRCDSIZE), LOC16(0) } }, // VMOV16 VCRCDSIZE,mem16
	{ OP(0xffffff00, 0xe2cb0600), .mnem = "vcrcl", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRCL mem16
	{ OP(0xffffff00, 0xe2cb0700), .mnem = "vcrch", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRCH mem16
	{ OP(0xffffff00, 0xe2cb0800), .mnem = "vmov16", RZTYPE(LOAD), .len = 4, .ops = { REG(VCRCPSIZE), LOC16(0) } }, // VMOV16 VCRCPSIZE,mem16
	{ OP(0xffffff00, 0xe2cc0000), .mnem = "vcrc8h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC8H_1 mem16
	{ OP(0xffffff00, 0xe2ce0000), .mnem = "vcrc16p1l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC16P1L_1 mem16
	{ OP(0xffffff00, 0xe2ce1000), .mnem = "vcrc16p2l_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC16P2L_1 mem16
	{ OP(0xffffff00, 0xe2cf0000), .mnem = "vcrc16p1h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC16P1H_1 mem16
	{ OP(0xffffff00, 0xe2cf1000), .mnem = "vcrc16p2h_1", RZTYPE(CRYPTO), .len = 4, .ops = { LOC16(0) } }, // VCRC16P2H_1 mem16
	{ OP(0xfffff000, 0xe3f00000), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { VRREG(8), LOC32(0) } }, // VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f01000), .mnem = "vxormov32", RZTYPE(XOR), .len = 4, .ops = { VRREG(8), LOC16(0) } }, // VXORMOV32 VRa,mem16
	{ OP(0xfffffc00, 0xe3f10000), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { VTREG2(8), LOC32(0) } }, // VMOV32 VTa,mem32
	{ OP(0xffffff00, 0xe3f20000), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { REG(VCRC), LOC32(0) } }, // VMOV32 VCRC,mem32
	{ OP(0xffffff00, 0xe3f20100), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { REG(VCRCPOLY), LOC16(0) } }, // VMOV32 VCRCPOLY,mem16
	{ OP(0xffffff00, 0xe3f20200), .mnem = "vmov32", RZTYPE(LOAD), .len = 4, .ops = { REG(VCRCSIZE), LOC16(0) } }, // VMOV32 VCRCSIZE,mem16
	{ OP(0xfffff000, 0xe3f60000), .mnem = "vcmpy", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCMPY VR3,VR2,VR1,VR0 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f61000), .mnem = "vccmpy", RZTYPE(MUL), .len = 4, .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCCMPY VR3,VR2,VR1,VR0 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f70000), .mnem = "vcmac", RZTYPE(MUL), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCMAC VR5,VR4,VR3,VR2,VR1,VR0 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f71000), .mnem = "vccmac", RZTYPE(MUL), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), REG(VR1), REG(VR0), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCCMAC VR5,VR4,VR3,VR2,VR1,VR0 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f80000), .mnem = "vcadd", RZTYPE(ADD), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCADD VR5,VR4,VR3,VR2 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3f90000), .mnem = "vcsub", RZTYPE(SUB), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCSUB VR5,VR4,VR3,VR2 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3fa0000), .mnem = "vcdadd16", RZTYPE(ADD), .len = 4, .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCDADD16 VR5,VR4,VR3,VR2 || VMOV32 VRa,mem32
	{ OP(0xfffff000, 0xe3fb0000), .mnem = "vcdsub16", RZTYPE(SUB), .len = 4, .ops = { REG(VR6), REG(VR4), REG(VR3), REG(VR2), PAR(VMOV32), VRREG(8), LOC32(0) } }, // VCDSUB16 VR6,VR4,VR3,VR2 || VMOV32 VRa,mem32
	{ OP(0xffffff00, 0xe3fc0000), .mnem = "vitbm2", RZTYPE(CMP), .len = 4, .ops = { REG(VR0), PAR(VMOV32), REG(VR2), LOC32(0) } }, // VITBM2 VR0 || VMOV32 VR2,mem32
	{ OP(0xffffff00, 0xe3fd0000), .mnem = "vitbm3", RZTYPE(CMP), .len = 4, .ops = { REG(VR0), REG(VR1), REG(VR2), PAR(VMOV32), REG(VR2), LOC32(0) } }, // VITBM3 VR0,VR1,VR2 || VMOV32 VR2,mem32
	{ OP(0xffff0000, 0xe3fe0000), .mnem = "vitlsel", RZTYPE(CMOV), .len = 4, .ops = { VRREG(8), VRREG(12), REG(VR4), REG(VR3), PAR(VMOV32), REG(VR2), LOC32(0) } }, // VITLSEL VRa,VRb,VR4,VR3 || VMOV32 VR2,mem32
	{ OP(0xffff0000, 0xe3ff0000), .mnem = "vithsel", RZTYPE(CMOV), .len = 4, .ops = { VRREG(8), VRREG(12), REG(VR4), REG(VR3), PAR(VMOV32), REG(VR2), LOC32(0) } }, // VITHSEL VRa,VRb,VR4,VR3 || VMOV32 VR2,mem32
	{ OP(0xffff0000, 0xe5000000), .mnem = "vcmpy", RZTYPE(MUL), .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0) } }, // VCMPY VR3,VR2,VR1,VR0
	{ OP(0xffff0000, 0xe5030000), .mnem = "vcsub", RZTYPE(SUB), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2) } }, // VCSUB VR5,VR4,VR3,VR2
	{ OP(0xffff0000, 0xe5040000), .mnem = "vcdadd16", RZTYPE(ADD), .ops = { REG(VR5), REG(VR4), REG(VR3), REG(VR2) } }, // VCDADD16 VR5,VR4,VR3,VR2
	{ OP(0xffff0000, 0xe5050000), .mnem = "vcdsub16", RZTYPE(SUB), .ops = { REG(VR6), REG(VR4), REG(VR3), REG(VR2) } }, // VCDSUB16 VR6,VR4,VR3,VR2
	{ OP(0xffff0000, 0xe50a0000), .mnem = "a_vclrovfr", RZTYPE(MOV) }, // A_VCLROVFR
	{ OP(0xffff0000, 0xe50b0000), .mnem = "a_vclrovfi", RZTYPE(MOV) }, // A_VCLROVFI
	{ OP(0xffff0000, 0xe50e0000), .mnem = "vccmpy", RZTYPE(MUL), .ops = { REG(VR3), REG(VR2), REG(VR1), REG(VR0) } }, // VCCMPY VR3,VR2,VR1,VR0
	{ OP(0xffff0000, 0xe5280000), .mnem = "vtrace", RZTYPE(MOV), .ops = { REG(VR1), REG(VR0), REG(VT0), REG(VT1) } }, // VTRACE VR1,VR0,VT0,VT1
	{ OP(0xffff0000, 0xe52a0000), .mnem = "vcadd", RZTYPE(ADD), .ops = { REG(VR7), REG(VR6), REG(VR5), REG(VR4) } }, // VCADD VR7,VR6,VR5,VR4
	{ OP(0xffff0000, 0xe52e0000), .mnem = "vswapcrc", RZTYPE(MOV) }, // VSWAPCRC
	{ OP(0xffffe000, 0xe6800000), .mnem = "vgfadd4", RZTYPE(ADD), .len = 4, .ops = { VRREG3(10), VRREG3(7), VRREG3(4), IMMU(0, 4) } }, // VGFADD4 VRa,VRb,VRc,#4bit
	{ OP(0xfffffff8, 0xe6802400), .mnem = "vrevb", RZTYPE(MOV), .len = 4, .ops = { VRREG3(0) } }, // VREVB VRa
	{ OP(0xffffffc0, 0xe6802440), .mnem = "vshlmb", RZTYPE(SHL), .len = 4, .ops = { VRREG3(3), VRREG3(0) } }, // VSHLMB VRa,VRb
	{ OP(0xfffffe00, 0xe6802600), .mnem = "vmod32", RZTYPE(MOD), .len = 4, .ops = { VRREGH(6), VRREG3(3), VRREGL(0) } }, // VMOD32 VRaH,VRb,VRcL
	{ OP(0xfffffe00, 0xe6802800), .mnem = "vmod32", RZTYPE(MOD), .len = 4, .ops = { VRREGH(6), VRREG3(3), VRREGH(0) } }, // VMOD32 VRaH,VRb,VRcH
	{ OP(0xfffffc00, 0xe6810000), .mnem = "vgfacc", RZTYPE(ADD), .len = 4, .ops = { VRREG3(7), VRREG3(4), IMMU(0, 4) } }, // VGFACC VRa,VRb,#4bit
	{ OP(0xffffff00, 0xe6f20000), .mnem = "vcshl16", RZTYPE(SHL), .len = 4, .ops = { VRREG(0), VSHIFT(4, 4, 0) } }, // VCSHL16 VRa << #shift
	{ OP(0xffffff00, 0xe6f20100), .mnem = "vcshr16", RZTYPE(SHR), .len = 4, .ops = { VRREG(0), VSHIFT(4, 4, 1) } }, // VCSHR16 VRa >> #shift
	{ OP(0xffffff00, 0xe6f20200), .mnem = "vmov32", RZTYPE(MOV), .len = 4, .ops = { VRREG(4), VRREG(0) } }, // VMOV32 VRa,VRb
	{ OP(0xffffff00, 0xe6f20300), .mnem = "vswap32", RZTYPE(XCHG), .len = 4, .ops = { VRREG(4), VRREG(0) } }, // VSWAP32 VRa,VRb
	{ OP(0xffffff00, 0xe6f20400), .mnem = "vcmag", RZTYPE(MUL), .len = 4, .ops = { VRREG(4), VRREG(0) } }, // VCMAG VRa,VRb
	{ OP(0xffffff00, 0xe6f20500), .mnem = "vlshl32", RZTYPE(SHL), .len = 4, .ops = { VRREG3(0), VSHIFT(3, 5, 0) } }, // VLSHL32 VRa << #shift
	{ OP(0xffffff00, 0xe6f20600), .mnem = "vlshr32", RZTYPE(SHR), .len = 4, .ops = { VRREG3(0), VSHIFT(3, 5, 1) } }, // VLSHR32 VRa >> #shift
	{ OP(0xffffff00, 0xe6f20700), .mnem = "vashl32", RZTYPE(SHL), .len = 4, .ops = { VRREG3(0), VSHIFT(3, 5, 0) } }, // VASHL32 VRa << #shift
	{ OP(0xffffff00, 0xe6f20800), .mnem = "vashr32", RZTYPE(SAR), .len = 4, .ops = { VRREG3(0), VSHIFT(3, 5, 1) } }, // VASHR32 VRa >> #shift
	{ OP(0xfffffff8, 0xe6f20900), .mnem = "vsetk", RZTYPE(MOV), .len = 4, .ops = { IMMU(0, 3) } }, // VSETK #3bit
	{ OP(0xffffffc0, 0xe6f20a00), .mnem = "vmov16", RZTYPE(MOV), .len = 4, .ops = { VRREGL(0), VRREGH(3) } }, // VMOV16 VRaL,VRbH
	{ OP(0xffffffc0, 0xe6f20a40), .mnem = "vmov16", RZTYPE(MOV), .len = 4, .ops = { VRREGH(0), VRREGL(3) } }, // VMOV16 VRaH,VRbL
	{ OP(0xffffffc0, 0xe6f20a80), .mnem = "vmov16", RZTYPE(MOV), .len = 4, .ops = { VRREGH(0), VRREGH(3) } }, // VMOV16 VRaH,VRbH
	{ OP(0xffffffc0, 0xe6f20ac0), .mnem = "vmov16", RZTYPE(MOV), .len = 4, .ops = { VRREGL(0), VRREGL(3) } }, // VMOV16 VRaL,VRbL
	{ OP(0xfffffff8, 0xe6f20b00), .mnem = "vinc", RZTYPE(ADD), .len = 4, .ops = { VRREGL(0) } }, // VINC VRaL
	{ OP(0xffffffc0, 0xe6f20c00), .mnem = "vmpyadd", RZTYPE(MUL), .len = 4, .ops = { VRREG3(0), VRREGL(0), VRREGH(0), VRREGH(3) } }, // VMPYADD VRa,VRbL,VRcH,VRdH
	{ OP(0xffffffc0, 0xe6f20c40), .mnem = "vmpyadd", RZTYPE(MUL), .len = 4, .ops = { VRREG3(0), VRREGL(0), VRREGH(0), VRREGL(3) } }, // VMPYADD VRa,VRbL,VRcH,VRdL
	{ OP(0xffff8000, 0xe6f30000), .mnem = "vmod32", RZTYPE(MOD), .len = 4, .ops = { VRREGH(0), VRREG3(3), VRREGL(6), PAR(VMOV32), VRREG3(9), VRREG3(12) } }, // VMOD32 VRaH,VRb,VRcL || VMOV32 VRd,VRe
	{ OP(0xffff8000, 0xe6f38000), .mnem = "vmod32", RZTYPE(MOD), .len = 4, .ops = { VRREGH(0), VRREG3(3), VRREGH(6), PAR(VMOV32), VRREG3(9), VRREG3(12) } }, // VMOD32 VRaH,VRb,VRcH || VMOV32 VRd,VRe
	{ OP(0xffffff00, 0xe6f60000), .mnem = "vitlsel", RZTYPE(CMOV), .len = 4, .ops = { VRREG(0), VRREG(4), REG(VR4), REG(VR3) } }, // VITLSEL VRa,VRb,VR4,VR3
	{ OP(0xffffff00, 0xe6f70000), .mnem = "vithsel", RZTYPE(CMOV), .len = 4, .ops = { VRREG(0), VRREG(4), REG(VR4), REG(VR3) } }, // VITHSEL VRa,VRb,VR4,VR3
	{ OP(0xfffffff0, 0xe6f80000), .mnem = "vclear", RZTYPE(MOV), .len = 4, .ops = { VRREG(0) } }, // VCLEAR VRa
	{ OP(0xffffffff, 0xe6f90000), .mnem = "vclearall", RZTYPE(MOV), .len = 4 }, // VCLEARALL
	{ OP(0xffff0000, 0xe7540000), .mnem = "vmovzi", RZTYPE(MOV), .len = 4, .ops = { REG(VCRCPOLY), IMMU(0, 16) } }, // VMOVZI VCRCPOLY,#16bit
	{ OP(0xffff0000, 0xe7550000), .mnem = "vmovix", RZTYPE(MOV), .len = 4, .ops = { REG(VCRCPOLY), IMMU(0, 16) } }, // VMOVIX VCRCPOLY,#16bit
	{ OP(0xffff0000, 0xe7560000), .mnem = "vsetcrcsize", RZTYPE(MOV), .len = 4, .ops = { IMMDEC(0, 5), IMMCOLON(8, 3) } }, // VSETCRCSIZE #a:#b
