// SPDX-FileCopyrightText: 2023 gogo <gogo246475@gmail.com>
// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_types.h>
#include <rz_asm.h>
#include <string.h>
#include <stdlib.h>

static int evmAsm(RzAsm *a, RzAsmOp *op, const char *buf) {
	int j, len = 1;
	size_t i;
	if (!a || !op || !buf) {
		return 0;
	}
	ut8 opbuf[40] = { 0 };
	
	if (!strcmp("stop", buf)) {
		opbuf[0] = 0x00;
	} else if (!strcmp("add", buf)) {
		opbuf[0] = 0x01;
	} else if (!strcmp("sub", buf)) {
		opbuf[0] = 0x03;
	} else if (!strcmp("div", buf)) {
		opbuf[0] = 0x04;
	} else if (!strcmp("sdiv", buf)) {
		opbuf[0] = 0x05;
	} else if (!strcmp("mod", buf)) {
		opbuf[0] = 0x06;
	} else if (!strcmp("smod", buf)) {
		opbuf[0] = 0x07;
	} else if (!strcmp("addmod", buf)) {
		opbuf[0] = 0x08;
	} else if (!strcmp("mulmod", buf)) {
		opbuf[0] = 0x09;
	} else if (!strcmp("exp", buf)) {
		opbuf[0] = 0x0a;
	} else if (!strcmp("signextend", buf)) {
		opbuf[0] = 0x0b;
	} else if (!strcmp("gt", buf)) {
		opbuf[0] = 0x11;
	} else if (!strcmp("slt", buf)) {
		opbuf[0] = 0x12;
	} else if (!strcmp("sgt", buf)) {
		opbuf[0] = 0x13;
	} else if (!strcmp("eq", buf)) {
		opbuf[0] = 0x14;
	} else if (!strcmp("iszero", buf)) {
		opbuf[0] = 0x15;
	} else if (!strcmp("and", buf)) {
		opbuf[0] = 0x16;
	} else if (!strcmp("or", buf)) {
		opbuf[0] = 0x17;
	} else if (!strcmp("xor", buf)) {
		opbuf[0] = 0x18;
	} else if (!strcmp("not", buf)) {
		opbuf[0] = 0x19;
	} else if (!strcmp("byte", buf)) {
		opbuf[0] = 0x1a;
	} else if (!strcmp("shl", buf)) {
		opbuf[0] = 0x1b;
	} else if (!strcmp("shr", buf)) {
		opbuf[0] = 0x1c;
	} else if (!strcmp("sar", buf)) {
		opbuf[0] = 0x1d;
	} else if (!strcmp("sha3", buf)) {
		opbuf[0] = 0x20;
	} else if (!strcmp("address", buf)) {
		opbuf[0] = 0x30;
	} else if (!strcmp("balance", buf)) {
		opbuf[0] = 0x31;
	} else if (!strcmp("origin", buf)) {
		opbuf[0] = 0x32;
	} else if (!strcmp("caller", buf)) {
		opbuf[0] = 0x33;
	} else if (!strcmp("callvalue", buf)) {
		opbuf[0] = 0x34;
	} else if (!strcmp("calldataload", buf)) {
		opbuf[0] = 0x35;
	} else if (!strcmp("calldatasize", buf)) {
		opbuf[0] = 0x36;
	} else if (!strcmp("calldatacopy", buf)) {
		opbuf[0] = 0x37;
	} else if (!strcmp("codesize", buf)) {
		opbuf[0] = 0x38;
	} else if (!strcmp("codecopy", buf)) {
		opbuf[0] = 0x39;
	} else if (!strcmp("gasprice", buf)) {
		opbuf[0] = 0x3a;
	} else if (!strcmp("extcodesize", buf)) {
		opbuf[0] = 0x3b;
	} else if (!strcmp("extcodecopy", buf)) {
		opbuf[0] = 0x3c;
	} else if (!strcmp("returndatasize", buf)) {
		opbuf[0] = 0x3d;
	} else if (!strcmp("returndatacopy", buf)) {
		opbuf[0] = 0x3e;
	} else if (!strcmp("extcodehash", buf)) {
		opbuf[0] = 0x3f;
	} else if (!strcmp("blockhash", buf)) {
		opbuf[0] = 0x40;
	} else if (!strcmp("coinbase", buf)) {
		opbuf[0] = 0x41;
	} else if (!strcmp("timestamp", buf)) {
		opbuf[0] = 0x42;
	} else if (!strcmp("number", buf)) {
		opbuf[0] = 0x43;
	} else if (!strcmp("difficulty", buf)) {
		opbuf[0] = 0x44;
	} else if (!strcmp("gaslimit", buf)) {
		opbuf[0] = 0x45;
	} else if (!strcmp("chainid", buf)) {
		opbuf[0] = 0x46;
	} else if (!strcmp("selfbalance", buf)) {
		opbuf[0] = 0x47;
	} else if (!strcmp("pop", buf)) {
		opbuf[0] = 0x50;
	} else if (!strcmp("mload", buf)) {
		opbuf[0] = 0x51;
	} else if (!strcmp("mstore", buf)) {
		opbuf[0] = 0x52;
	} else if (!strcmp("mstore8", buf)) {
		opbuf[0] = 0x53;
	} else if (!strcmp("sload", buf)) {
		opbuf[0] = 0x54;
	} else if (!strcmp("sstore", buf)) {
		opbuf[0] = 0x55;
	} else if (!strcmp("jump", buf)) {
		opbuf[0] = 0x56;
	} else if (!strcmp("jump", buf)) {
		opbuf[0] = 0x56;
	} else if (!strcmp("jumpi", buf)) {
		opbuf[0] = 0x57;
	} else if (!strcmp("pc", buf)) {
		opbuf[0] = 0x58;
	} else if (!strcmp("msize", buf)) {
		opbuf[0] = 0x59;
	} else if (!strcmp("gas", buf)) {
		opbuf[0] = 0x5a;
	} else if (!strcmp("jumpdest", buf)) {
		opbuf[0] = 0x5b;
	} else if (!strncmp("push", buf, 3)) {
		char out[100];
		int number = atoi(buf+4);
		switch (number) {
			case 1:
			len = 2;
			opbuf[0] = 0x60;
			break;
		case 2:
			len = 3;
			opbuf[0] = 0x61;
			break;
		case 3:
			len = 4;
			opbuf[0] = 0x62;
			break;
		case 4:
			len = 5;
			opbuf[0] = 0x63;
			break;
		case 5:
			len = 6;
			opbuf[0] = 0x64;
			break;
		case 6:
			len = 7;
			opbuf[0] = 0x65;
			break;
		case 7:
			len = 8;
			opbuf[0] = 0x66;
			break;
		case 8:
			len = 9;
			opbuf[0] = 0x67;
			break;
		case 9:
			len = 10;
			opbuf[0] = 0x68;
			break;
		case 10:
			len = 11;
			opbuf[0] = 0x69;
			break;
		case 11:
			len = 12;
			opbuf[0] = 0x6a;
			break;
		case 12:
			len = 13;
			opbuf[0] = 0x6b;
			break;
		case 13:
			len = 14;
			opbuf[0] = 0x6c;
			break;
		case 14:
			len = 15;
			opbuf[0] = 0x6d;
			break;
		case 15:
			len = 16;
			opbuf[0] = 0x6e;
			break;
		case 16:
			len = 17;
			opbuf[0] = 0x6f;
			break;
		case 17:
			len = 18;
			opbuf[0] = 0x70;
			break;
				case 18:
			len = 19;
			opbuf[0] = 0x71;
			break;
		case 19:
			len = 20;
			opbuf[0] = 0x72;
			break;
		case 20:
			len = 21;
			opbuf[0] = 0x73;
			break;
		case 21:
			len = 22;
			opbuf[0] = 0x74;
			break;
		case 22:
			len = 23;
			opbuf[0] = 0x75;
			break;
		case 23:
			len = 24;
			opbuf[0] = 0x76;
			break;
		case 24:
			len = 25;
			opbuf[0] = 0x77;
			break;
		case 25:
			len = 26;
			opbuf[0] = 0x78;
			break;
		case 26:
			len = 27;
			opbuf[0] = 0x79;
			break;
		case 27:
			len = 28;
			opbuf[0] = 0x7a;
			break;
		case 28:
			len = 29;
			opbuf[0] = 0x7b;
			break;
		case 29:
			len = 30;
			opbuf[0] = 0x7c;
			break;
		case 30:
			len = 31;
			opbuf[0] = 0x7d;
			break;
		case 31:
			len = 32;
			opbuf[0] = 0x7e;
			break;
		case 32:
			len = 33;
			opbuf[0] = 0x7f;
			break;
		}
		int opbuf_len;
	    	char two_chars_str[3];
	    	if (number <= 9) {
			for (int j = 8, i = 0; i < len-1; j += 2, i ++) {
				two_chars_str[0] = buf[j];
				two_chars_str[1] = buf[j+1];
				two_chars_str[2] = '\0';
				opbuf[i+1] = strtol(two_chars_str, NULL, 16);
			}
	    	} else if (number > 9) {
			for (int j = 9, i = 0; i < len-1; j += 2, i ++) {
				two_chars_str[0] = buf[j];
				two_chars_str[1] = buf[j+1];
				two_chars_str[2] = '\0';
				opbuf[i+1] = strtol(two_chars_str, NULL, 16);
			}
	    	}
	} else if (!strcmp("swap1", buf)) {
		opbuf[0] = 0x90;
	} else if (!strcmp("swap2", buf)) {
		opbuf[0] = 0x91;
	} else if (!strcmp("swap3", buf)) {
		opbuf[0] = 0x92;
	} else if (!strcmp("swap4", buf)) {
		opbuf[0] = 0x93;
	}  else if (!strcmp("swap5", buf)) {
		opbuf[0] = 0x94;
	}  else if (!strcmp("swap6", buf)) {
		opbuf[0] = 0x95;
	}  else if (!strcmp("swap7", buf)) {
		opbuf[0] = 0x96;
	}  else if (!strcmp("swap8", buf)) {
		opbuf[0] = 0x97;
	}  else if (!strcmp("swap9", buf)) {
		opbuf[0] = 0x98;
	}  else if (!strcmp("swap10", buf)) {
		opbuf[0] = 0x99;
	}  else if (!strcmp("swap11", buf)) {
		opbuf[0] = 0x9a;
	}  else if (!strcmp("swap12", buf)) {
		opbuf[0] = 0x9b;
	}  else if (!strcmp("swap13", buf)) {
		opbuf[0] = 0x9c;
	}  else if (!strcmp("swap14", buf)) {
		opbuf[0] = 0x9d;
	}  else if (!strcmp("swap15", buf)) {
		opbuf[0] = 0x9e;
	}  else if (!strcmp("swap16", buf)) {
		opbuf[0] = 0x9f;
	}  else if (!strcmp("log0", buf)) {
		opbuf[0] = 0xa0;
	}  else if (!strcmp("log1", buf)) {
		opbuf[0] = 0xa1;
	}  else if (!strcmp("log2", buf)) {
		opbuf[0] = 0xa2;
	}  else if (!strcmp("log3", buf)) {
		opbuf[0] = 0xa3;
	}  else if (!strcmp("log4", buf)) {
		opbuf[0] = 0xa4;
	}  else if (!strcmp("create", buf)) {
		opbuf[0] = 0xf0;
	}  else if (!strcmp("call", buf)) {
		opbuf[0] = 0xf1;
	}  else if (!strcmp("callcode", buf)) {
		opbuf[0] = 0xf2;
	}  else if (!strcmp("return", buf)) {
		opbuf[0] = 0xf3;
	}  else if (!strcmp("delegatecall", buf)) {
		opbuf[0] = 0xf4;
	}  else if (!strcmp("create2", buf)) {
		opbuf[0] = 0xf5;
	}  else if (!strcmp("staticcall", buf)) {
		opbuf[0] = 0xfa;
	}  else if (!strcmp("revert", buf)) {
		opbuf[0] = 0xfd;
	}  else if (!strcmp("selfdestruct", buf)) {
		opbuf[0] = 0xff;
	}  else {
		len = 0;
	}
	
	memcpy(rz_strbuf_get(&op->buf), opbuf, sizeof(ut8) * len);
	return op->size = len;
}
