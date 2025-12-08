// SPDX-FileCopyrightText: 2015-2019 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2025 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <string.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include "mcs96/mcs96.h"

static int mcs96_len(RzAsm *a, ut32 isa_bit, const ut8 *buf, int len, RzStrBuf *asm_buf) {
	if (!(mcs96_op[buf[0]].isa & isa_bit)) {
		rz_strbuf_set(asm_buf, "invalid");
		return 1;
	}

	int ret = 1;
	if (buf[0] == 0xfe) {
		if (isa_bit == MCS96_80296) {
			rz_strbuf_set(asm_buf, "invalid");
			return 1;
		}

		if (len < 2) {
			return 0;
		}
		if (mcs96_op[buf[1]].type & MCS96_FE) {
			if (mcs96_op[buf[1]].type & MCS96_5B_OR_6B) {
				if (len < 3) {
					return 0;
				}
				ret = 6 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_4B_OR_5B) {
				if (len < 3) {
					return 0;
				}
				ret = 5 + (buf[2] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_3B_OR_4B) {
				if (len < 3) {
					return 0;
				}
				ret = 4 + (buf[1] & 0x1);
			}
			if (mcs96_op[buf[1]].type & MCS96_5B) {
				ret = 6;
			}
			if (mcs96_op[buf[1]].type & MCS96_4B) {
				ret = 5;
			}
			if (mcs96_op[buf[1]].type & MCS96_3B) {
				ret = 4;
			}
			if (mcs96_op[buf[1]].type & MCS96_2B) {
				ret = 3;
			}
			if (ret <= len) {
				const ut32 fe_idx = ((buf[1] & 0x70) >> 4) ^ 0x4;
				rz_strbuf_set(asm_buf, mcs96_fe_op[fe_idx]);
				if ((mcs96_op[buf[1]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) &&
					buf[2] > 0x19 && buf[3] > 0x19) {
					rz_strbuf_appendf(asm_buf, " rb%02x, rb%02x", buf[2] - 0x1a, buf[3] - 0x1a);
				}
			} else {
				ret = 0;
			}
			return ret;
		}
	}
	if (mcs96_op[buf[0]].type & MCS96_5B_OR_6B) {
		if (len < 2) {
			return 0;
		}
		ret = 5 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_4B_OR_5B) {
		if (len < 2) {
			return 0;
		}
		ret = 4 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_3B_OR_4B) {
		if (len < 2) {
			return 0;
		}
		ret = 3 + (buf[1] & 0x1);
	}
	if (mcs96_op[buf[0]].type & MCS96_6B) {
		ret = 6;
	}
	if (mcs96_op[buf[0]].type & MCS96_5B) {
		ret = 5;
	}
	if (mcs96_op[buf[0]].type & MCS96_4B) {
		ret = 4;
	}
	if (mcs96_op[buf[0]].type & MCS96_3B) {
		ret = 3;
	}
	if (mcs96_op[buf[0]].type & MCS96_2B) {
		ret = 2;
	}
	if (ret <= len) {
		rz_strbuf_set(asm_buf, mcs96_op[buf[0]].ins);
		if ((mcs96_op[buf[0]].type & (MCS96_2OP | MCS96_REG_8)) == (MCS96_2OP | MCS96_REG_8) &&
			buf[1] > 0x19 && buf[2] > 0x19) {
			rz_strbuf_appendf(asm_buf, " rb%02x, rb%02x", buf[1] - 0x1a, buf[2] - 0x1a);
		}
	} else {
		ret = 0;
	}
	return ret;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len > 1 && !memcmp(buf, "\xff\xff", 2)) {
		return -1;
	}

	RzStrBuf* asm_buf = &op->buf_asm;

	ut32 isa_bit = MCS96_8096;  // default
	if (a->cpu && *a->cpu) {
		if (strstr(a->cpu, "80296")) {
			isa_bit = MCS96_80296;
		} else if (strstr(a->cpu, "80196")) {
			isa_bit = MCS96_80196;
		}
	}

	op->size = mcs96_len(a, isa_bit, buf, len, asm_buf);

	if (op->size > 0) {
		if (buf[0] == 0x0d && isa_bit == MCS96_80296) {  // SHLL/MVAC/MSAC
			ut8 lreg_bits = buf[2] & 0x3;
			// lreg.1 lreg.0 Execute
			// 0      0      SHLL
			// 0      1      MVAC
			// 1      0      Reserved
			// 1      1      MSAC
			const char *mnemonic;
			switch (lreg_bits) {
			case 0x0:
				mnemonic = "shll";
				break;
			case 0x1:
				mnemonic = "mvac";
				break;
			case 0x3:
				mnemonic = "msac";
				break;
			default:
				mnemonic = "invalid";
				break;
			}
			rz_strbuf_set(asm_buf, mnemonic);
		}

		if (buf[0] == 0x40 && isa_bit == MCS96_80296 && buf[op->size - 1] == 0x04) {  // AND/RPT/RPTxxx/RPTI/RPTIxxx
			// RPT waop
			// (010000aa) (waop) (00) (04)
			// RPTxxx
			// (010000aa) (waop) (10 - 1F) (04)
			// RPTI
			// (010000aa) (waop) (20) (04)
			// RPTIxxx
			// (010000aa) (waop) (30 - 3F) (04)
			const char *mnemonic;
			switch (buf[op->size - 2]) {
				case 0x00:
					mnemonic = "rpt";
					break;
				case 0x10: 
					mnemonic = "rptnst";
					break;
				case 0x11: 
					mnemonic = "rptnh";
					break;
				case 0x12: 
					mnemonic = "rptgt";
					break;
				case 0x13: 
					mnemonic = "rptnc";
					break;
				case 0x14: 
					mnemonic = "rptnvt";
					break;
				case 0x15: 
					mnemonic = "rptnv";
					break;
				case 0x16: 
					mnemonic = "rptge";
					break;
				case 0x17: 
					mnemonic = "rptne";
					break;
				case 0x18: 
					mnemonic = "rptst";
					break;
				case 0x19: 
					mnemonic = "rpth";
					break;
				case 0x1a: 
					mnemonic = "rptle";
					break;
				case 0x1b: 
					mnemonic = "rptc";
					break;
				case 0x1c: 
					mnemonic = "rptvt";
					break;
				case 0x1d: 
					mnemonic = "rptv";
					break;
				case 0x1e: 
					mnemonic = "rptlt";
					break;
				case 0x1f: 
					mnemonic = "rpte";
					break;
				case 0x20:
					mnemonic = "rpti";
					break;
				case 0x30:
					mnemonic = "rptinst";
					break;
				case 0x31:
					mnemonic = "rptinh";
					break;
				case 0x32:
					mnemonic = "rptigt";
					break;
				case 0x33:
					mnemonic = "rptinc";
					break;
				case 0x34:
					mnemonic = "rptinvt";
					break;
				case 0x35:
					mnemonic = "rptinv";
					break;
				case 0x36:
					mnemonic = "rptige";
					break;
				case 0x37:
					mnemonic = "rptine";
					break;
				case 0x38:
					mnemonic = "rptist";
					break;
				case 0x39:
					mnemonic = "rptih";
					break;
				case 0x3a:
					mnemonic = "rptile";
					break;
				case 0x3b:
					mnemonic = "rptic";
					break;
				case 0x3c:
					mnemonic = "rptivt";
					break;
				case 0x3d:
					mnemonic = "rptiv";
					break;
				case 0x3e:
					mnemonic = "rptilt";
					break;
				case 0x3f:
					mnemonic = "rptie";
					break;
				default:
					mnemonic = "and";
					break;
			}
			rz_strbuf_set(asm_buf, mnemonic);
		}
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_mcs96 = {
	.name = "mcs96",
	.desc = "Intel MCS-96 disassembler",
	.cpus = "8096,80196,80296",
	.arch = "mcs96",
	.license = "LGPL3",
	.author = "condret",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_NONE,
	.disassemble = &disassemble
};
