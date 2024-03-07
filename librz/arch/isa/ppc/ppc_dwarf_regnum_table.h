// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Most of the registers comes from the PPC ELF ABI v1
 * https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#DW-REG
 *
 * But there are some different mapping in the PPC ELF ABI v2
 * https://ftp.rtems.org/pub/rtems/people/sebh/ABI64BitOpenPOWERv1.1_16July2015_pub.pdf
 *
 * Also 32bit registers matches these
 * http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf
 */
static const char *map_dwarf_reg_to_ppc_reg(ut32 reg_num) {
	switch (reg_num) {
	// General Register
	case 0: return "r0";
	case 1: return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "r16";
	case 17: return "r17";
	case 18: return "r18";
	case 19: return "r19";
	case 20: return "r20";
	case 21: return "r21";
	case 22: return "r22";
	case 23: return "r23";
	case 24: return "r24";
	case 25: return "r25";
	case 26: return "r26";
	case 27: return "r27";
	case 28: return "r28";
	case 29: return "r29";
	case 30: return "r30";
	case 31: return "r31";
	// Floating Register
	case 32: return "f0";
	case 33: return "f1";
	case 34: return "f2";
	case 35: return "f3";
	case 36: return "f4";
	case 37: return "f5";
	case 38: return "f6";
	case 39: return "f7";
	case 40: return "f8";
	case 41: return "f9";
	case 42: return "f10";
	case 43: return "f11";
	case 44: return "f12";
	case 45: return "f13";
	case 46: return "f14";
	case 47: return "f15";
	case 48: return "f16";
	case 49: return "f17";
	case 50: return "f18";
	case 51: return "f19";
	case 52: return "f20";
	case 53: return "f21";
	case 54: return "f22";
	case 55: return "f23";
	case 56: return "f24";
	case 57: return "f25";
	case 58: return "f26";
	case 59: return "f27";
	case 60: return "f28";
	case 61: return "f29";
	case 62: return "f30";
	case 63: return "f31";
	// Special Register
	case 64: return "cr"; // Condition Register
	case 65: return "fpscr"; // Floating-Point Status and Control Register
	case 66: return "msr"; // Machine State Register
	case 70: return "sr0"; // Segment Register 0
	case 71: return "sr1"; // Segment Register 1
	case 72: return "sr2"; // Segment Register 2
	case 73: return "sr3"; // Segment Register 3
	case 74: return "sr4"; // Segment Register 4
	case 75: return "sr5"; // Segment Register 5
	case 76: return "sr6"; // Segment Register 6
	case 77: return "sr7"; // Segment Register 7
	case 78: return "sr8"; // Segment Register 8
	case 79: return "sr9"; // Segment Register 9
	case 80: return "sr10"; // Segment Register 10
	case 81: return "sr11"; // Segment Register 11
	case 82: return "sr12"; // Segment Register 12
	case 83: return "sr13"; // Segment Register 13
	case 84: return "sr14"; // Segment Register 14
	case 85: return "sr15"; // Segment Register 15
	case 99:
		return "acc"; // Accumulator Register
	// SPRs 100–1123
	case 100: return "mq"; // MQ Register
	case 101: return "xer"; // Fixed-Point Exception Register
	case 104: return "rtcu"; // Real Time Clock Upper Register
	case 105: return "rtcl"; // Real Time Clock Lower Register
	case 108: return "lr"; // Link Register
	case 109: return "ctr"; // Count Register
	case 118: return "dsisr"; // Data Storage Interrupt Status Register
	case 119: return "dar"; // Data Address Register
	case 122: return "dec"; // Decrement Register
	case 125: return "sdr1"; // Storage Description Register 1
	case 126: return "srr0"; // Machine Status Save/Restore Register 0
	case 127: return "srr1"; // Machine Status Save/Restore Register 1
	case 356: return "vrsave"; // Vector Save/Restore Register
	case 372: return "sprg0"; // Software-use Special Purpose Register 0
	case 373: return "sprg1"; // Software-use Special Purpose Register 1
	case 374: return "sprg2"; // Software-use Special Purpose Register 2
	case 375: return "sprg3"; // Software-use Special Purpose Register 3
	case 380: return "asr"; // Address Space Register
	case 382: return "ear"; // External Access Register
	case 384: return "tb"; // Time Base
	case 385: return "tbu"; // Time Base Upper
	case 387: return "pvr"; // Processor Version Register
	case 612: return "spefscr"; // Signal processing and embedded floating-point status and control register
	case 628: return "ibat0u"; // Instruction BAT Upper Register 0
	case 629: return "ibat0l"; // Instruction BAT Lower Register 0
	case 630: return "ibat1u"; // Instruction BAT Upper Register 1
	case 631: return "ibat1l"; // Instruction BAT Lower Register 1
	case 632: return "ibat2u"; // Instruction BAT Upper Register 2
	case 633: return "ibat2l"; // Instruction BAT Lower Register 2
	case 634: return "ibat3u"; // Instruction BAT Upper Register 3
	case 635: return "ibat3l"; // Instruction BAT Lower Register 3
	case 636: return "dbat0u"; // Data BAT Upper Register 0
	case 637: return "dbat0l"; // Data BAT Lower Register 0
	case 638: return "dbat1u"; // Data BAT Upper Register 1
	case 639: return "dbat1l"; // Data BAT Lower Register 1
	case 640: return "dbat2u"; // Data BAT Upper Register 2
	case 641: return "dbat2l"; // Data BAT Lower Register 2
	case 642: return "dbat3u"; // Data BAT Upper Register 3
	case 643: return "dbat3l"; // Data BAT Lower Register 3
	case 1108: return "hid0"; // Hardware Implementation Register 0
	case 1109: return "hid1"; // Hardware Implementation Register 1
	case 1110: return "hid2"; // Hardware Implementation Register 2
	case 1113: return "hid5"; // Hardware Implementation Register 5
	case 1123:
		return "hid15"; // Hardware Implementation Register 15
	// AltiVec registers 1124–1155
	case 1124: return "vr0"; // Vector Registers 0
	case 1125: return "vr1"; // Vector Registers 1
	case 1126: return "vr2"; // Vector Registers 2
	case 1127: return "vr3"; // Vector Registers 3
	case 1128: return "vr4"; // Vector Registers 4
	case 1129: return "vr5"; // Vector Registers 5
	case 1130: return "vr6"; // Vector Registers 6
	case 1131: return "vr7"; // Vector Registers 7
	case 1132: return "vr8"; // Vector Registers 8
	case 1133: return "vr9"; // Vector Registers 9
	case 1134: return "vr10"; // Vector Registers 10
	case 1135: return "vr11"; // Vector Registers 11
	case 1136: return "vr12"; // Vector Registers 12
	case 1137: return "vr13"; // Vector Registers 13
	case 1138: return "vr14"; // Vector Registers 14
	case 1139: return "vr15"; // Vector Registers 15
	case 1140: return "vr16"; // Vector Registers 16
	case 1141: return "vr17"; // Vector Registers 17
	case 1142: return "vr18"; // Vector Registers 18
	case 1143: return "vr19"; // Vector Registers 19
	case 1144: return "vr20"; // Vector Registers 20
	case 1145: return "vr21"; // Vector Registers 21
	case 1146: return "vr22"; // Vector Registers 22
	case 1147: return "vr23"; // Vector Registers 23
	case 1148: return "vr24"; // Vector Registers 24
	case 1149: return "vr25"; // Vector Registers 25
	case 1150: return "vr26"; // Vector Registers 26
	case 1151: return "vr27"; // Vector Registers 27
	case 1152: return "vr28"; // Vector Registers 28
	case 1153: return "vr29"; // Vector Registers 29
	case 1154: return "vr30"; // Vector Registers 30
	case 1155:
		return "vr31"; // Vector Registers 31
	// From ABI v1
	// Reserved 1156–1199
	// Most-significant 32 bits of gpr r0-r31 1200-1231
	// Reserved 1232-2047
	// Device control registers 3072–4095 DCRs
	// Performance monitor registers 4096-5120 PMRs
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}
