// SPDX-FileCopyrightText: 2023 gogo <gogo246475@gmail.com>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>

static int evmDisass(RzAsmOp *op, const ut8 *buf, int len) {
	int instruction_size = 1;
	char buf_asm[2000];
	const unsigned char out[256];
	const unsigned char opcode[256];
	switch (buf[0]) {
		case 0x00:
			rz_str_cpy(buf_asm, "STOP") break;
		case 0x01:
			rz_str_cpy(buf_asm, "ADD") break;
		case 0x02:
			rz_str_cpy(buf_asm, "MUL") break;
		case 0x03:
			rz_str_cpy(buf_asm, "SUB") break;
		case 0x04:
			rz_str_cpy(buf_asm, "DIV") break;
		case 0x05:
			rz_str_cpy(buf_asm, "SDIV") break;
		case 0x06:
			rz_str_cpy(buf_asm, "MOD") break;
		case 0x07:
			rz_str_cpy(buf_asm, "SMOD") break;
		case 0x8:
			rz_str_cpy(buf_asm, "ADDMOD") break;
		case 0x9:
			rz_str_cpy(buf_asm, "MULMOD") break;
		case 0x0a:
			rz_str_cpy(buf_asm, "EXP") break;
		case 0x0b:
			rz_str_cpy(buf_asm, "SIGNEXTEND") break;
		case 0x11:
			rz_str_cpy(buf_asm, "GT") break;
		case 0x12:
			rz_str_cpy(buf_asm, "SLT") break;
		case 0x13:
			rz_str_cpy(buf_asm, "SGT") break;
		case 0x14:
			rz_str_cpy(buf_asm, "EQ") break;
		case 0x15:
			rz_str_cpy(buf_asm, "ISZERO") break;
		case 0x16:
			rz_str_cpy(buf_asm, "AND") break;
		case 0x17:
			rz_str_cpy(buf_asm, "OR") break;
		case 0x18:
			rz_str_cpy(buf_asm, "XOR") break;
		case 0x19:
			rz_str_cpy(buf_asm, "NOT") break;
		case 0x1a:
			rz_str_cpy(buf_asm, "BYTE") break;
		case 0x1b:
			rz_str_cpy(buf_asm, "SHL") break;
		case 0x1c:
			rz_str_cpy(buf_asm, "SHR") break;
		case 0x1d:
			rz_str_cpy(buf_asm, "SAR") break;
		case 0x20:
			rz_str_cpy(buf_asm, "SHA3") break;
		case 0x30:
			rz_str_cpy(buf_asm, "ADDRESS") break;
		case 0x31:
			rz_str_cpy(buf_asm, "BALANCE") break;
		case 0x32:
			rz_str_cpy(buf_asm, "ORIGIN") break;
		case 0x33:
			rz_str_cpy(buf_asm, "CALLER") break;
		case 0x34:
			rz_str_cpy(buf_asm, "CALLVALUE") break;
		case 0x35:
			rz_str_cpy(buf_asm, "CALLDATALOAD") break;
		case 0x36:
			rz_str_cpy(buf_asm, "CALLDATASIZE") break;
		case 0x37:
			rz_str_cpy(buf_asm, "CALLDATACOPY") break;
		case 0x38:
			rz_str_cpy(buf_asm, "CODESIZE") break;
		case 0x39:
			rz_str_cpy(buf_asm, "CODECOPY") break;
		case 0x3a:
			rz_str_cpy(buf_asm, "GASPRICE") break;
		case 0x3b:
			rz_str_cpy(buf_asm, "EXTCODESIZE") break;
		case 0x3c:
			rz_str_cpy(buf_asm, "EXTCODECOPY") break;
		case 0x3d:
			rz_str_cpy(buf_asm, "RETURNDATASIZE") break;
		case 0x3e:
			rz_str_cpy(buf_asm, "RETURNDATACOPY") break;
		case 0x3f:
			rz_str_cpy(buf_asm, "EXTCODEHASH") break;
		case 0x40:
			rz_str_cpy(buf_asm, "BLOCKHASH") break;
		case 0x41:
			rz_str_cpy(buf_asm, "COINBASE") break;
		case 0x42:
			rz_str_cpy(buf_asm, "TIMESTAMP") break;
		case 0x43:
			rz_str_cpy(buf_asm, "NUMBER") break;
		case 0x44:
			rz_str_cpy(buf_asm, "DIFFICULTY") break;
		case 0x45:
			rz_str_cpy(buf_asm, "GASLIMIT") break;
		case 0x46:
			rz_str_cpy(buf_asm, "CHAINID") break;
		case 0x47:
			rz_str_cpy(buf_asm, "SELFBALANCE") break;
		case 0x48:
			rz_str_cpy(buf_asm, "BASEFEE") break;
		case 0x50:
			rz_str_cpy(buf_asm, "POP") break; 
		case 0x51:
			rz_str_cpy(buf_asm, "MLOAD") break;
		case 0x52:
			rz_str_cpy(buf_asm, "MSTORE") break;
		case 0x53:
			rz_str_cpy(buf_asm, "MSTORE8") break;
		case 0x54:
			rz_str_cpy(buf_asm, "SLOAD") break;
		case 0x55:
			rz_str_cpy(buf_asm, "SSTORE") break;
		case 0x56:
			rz_str_cpy(buf_asm, "JUMP") break;
		case 0x57:
			rz_str_cpy(buf_asm, "JUMPI") break;
		case 0x58:
			rz_str_cpy(buf_asm, "PC") break;
		case 0x59:
			rz_str_cpy(buf_asm, "MSIZE") break;
		case 0x5a:
			rz_str_cpy(buf_asm, "GAS") break;
		case 0x5b:
			rz_str_cpy(buf_asm, "JUMPDEST") break;
		case 0x60:
			instruction_size = 2;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH1 0x%s", opcode); break;
		case 0x61:
			instruction_size = 3;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH2 0x%s", opcode); break;
		case 0x62:
			instruction_size = 4;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH3 0x%s", opcode); break;
		case 0x63:
			instruction_size = 5;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH4 0x%s", opcode); break;
		case 0x64:
			instruction_size = 6;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH5 0x%s", opcode); break;
		case 0x65:
			instruction_size = 7;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH6 0x%s", opcode); break;
		case 0x66:
			instruction_size = 8;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH7 0x%s", opcode); break;
		case 0x67:
			instruction_size = 9;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH8 0x%s", opcode); break;
		case 0x68:
			instruction_size = 10;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH9 0x%s", opcode); break;
		case 0x69:
			instruction_size = 11;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH10 0x%s", opcode); break;
		case 0x6a:
			instruction_size = 12;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH11 0x%s", opcode); break;
		case 0x6b:
			instruction_size = 13;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH12 0x%s", opcode); break;
		case 0x6c:
			instruction_size = 14;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH13 0x%s", opcode); break;
		case 0x6d:
			instruction_size = 15;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH14 0x%s", opcode); break;
		case 0x6e:
			instruction_size = 16;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH15 0x%s", opcode); break;
		case 0x6f:
			instruction_size = 17;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH16 0x%s", opcode); break;
		case 0x70:
			instruction_size = 18;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH17 0x%s", opcode); break;
		case 0x71:
			instruction_size = 19;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH18 0x%s", opcode); break;
		case 0x72:
			instruction_size = 20;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH19 0x%s", opcode); break;
		case 0x73:
			instruction_size = 21;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH20 0x%s", opcode); break;
		case 0x74:
			instruction_size = 22;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH21 0x%s", opcode); break;
		case 0x75:
			instruction_size = 23;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH22 0x%s", opcode); break;
		case 0x76:
			instruction_size = 24;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH23 0x%s", opcode); break;
		case 0x77:
			instruction_size = 25;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH24 0x%s", opcode); break;
		case 0x78:
			instruction_size = 26;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH25 0x%s", opcode); break;
		case 0x79:
			instruction_size = 27;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH26 0x%s", opcode); break;
		case 0x7a:
			instruction_size = 28;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH27 0x%s", opcode); break;
		case 0x7b:
			instruction_size = 29;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH28 0x%s", opcode); break;
		case 0x7c:
			instruction_size = 30;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH29 0x%s", opcode); break;
		case 0x7d:
			instruction_size = 31;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH30 0x%s", opcode); break;
		case 0x7e:
			instruction_size = 32;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH31 0x%s", opcode); break;
		case 0x7f:
			instruction_size = 33;
			rz_hex_bin2str(buf+1, instruction_size-1, opcode);
			rz_strf(buf_asm, "PUSH32 0x%s", opcode); break;
		case 0x80:
			rz_str_cpy(buf_asm, "DUP1") break;
		case 0x81:
			rz_str_cpy(buf_asm, "DUP2") break;
		case 0x82:
			rz_str_cpy(buf_asm, "DUP3") break;
		case 0x83:
			rz_str_cpy(buf_asm, "DUP4") break;
		case 0x84:
			rz_str_cpy(buf_asm, "DUP5") break;
		case 0x85:
			rz_str_cpy(buf_asm, "DUP6") break;
		case 0x86:
			rz_str_cpy(buf_asm, "DUP7") break;
		case 0x87:
			rz_str_cpy(buf_asm, "DUP8") break;
		case 0x88:
			rz_str_cpy(buf_asm, "DUP9") break;
		case 0x89:
			rz_str_cpy(buf_asm, "DUP10") break;
		case 0x8a:
			rz_str_cpy(buf_asm, "DUP11") break;
		case 0x8b:
			rz_str_cpy(buf_asm, "DUP12") break;
		case 0x8c:
			rz_str_cpy(buf_asm, "DUP13") break;
		case 0x8d:
			rz_str_cpy(buf_asm, "DUP14") break;
		case 0x8e:
			rz_str_cpy(buf_asm, "DUP15") break;
		case 0x8f:
			rz_str_cpy(buf_asm, "DUP16") break;
		case 0x90:
			rz_str_cpy(buf_asm, "SWAP1") break;
		case 0x91:
			rz_str_cpy(buf_asm, "SWAP2") break;
		case 0x92:
			rz_str_cpy(buf_asm, "SWAP3") break;
		case 0x93:
			rz_str_cpy(buf_asm, "SWAP4") break;
		case 0x94:
			rz_str_cpy(buf_asm, "SWAP5") break;
		case 0x95:
			rz_str_cpy(buf_asm, "SWAP6") break;
		case 0x96:
			rz_str_cpy(buf_asm, "SWAP7") break;
		case 0x97:
			rz_str_cpy(buf_asm, "SWAP8") break;
		case 0x98:
			rz_str_cpy(buf_asm, "SWAP9") break;
		case 0x99:
			rz_str_cpy(buf_asm, "SWAP10") break;
		case 0x9a:
			rz_str_cpy(buf_asm, "SWAP11") break;
		case 0x9b:
			rz_str_cpy(buf_asm, "SWAP12") break;
		case 0x9c:
			rz_str_cpy(buf_asm, "SWAP13") break;
		case 0x9d:
			rz_str_cpy(buf_asm, "SWAP14") break;
		case 0x9e:
			rz_str_cpy(buf_asm, "SWAP15") break;
		case 0x9f:
			rz_str_cpy(buf_asm, "SWAP16") break;
		case 0xa0:
			rz_str_cpy(buf_asm, "LOG0") break;
		case 0xa1:
			rz_str_cpy(buf_asm, "LOG1") break;
		case 0xa2:
			rz_str_cpy(buf_asm, "LOG2") break;
		case 0xa3:
			rz_str_cpy(buf_asm, "LOG3") break;
		case 0xa4:
			rz_str_cpy(buf_asm, "LOG4") break;
		case 0xb0:
			rz_str_cpy(buf_asm, "PUSH") break; //requires arguments?
		case 0xb1:
			rz_str_cpy(buf_asm, "DUP") break; //requires arguments?
		case 0xb2:
			rz_str_cpy(buf_asm, "SWAP") break;
		case 0xf0:
			rz_str_cpy(buf_asm, "CREATE") break;
		case 0xf1:
			rz_str_cpy(buf_asm, "CALL") break; //requires arguments?
		case 0xf2:
			rz_str_cpy(buf_asm, "CALLCODE") break;
		case 0xf3:
			rz_str_cpy(buf_asm, "RETURN") break;
		case 0xf4:
			rz_str_cpy(buf_asm, "DELEGATECALL") break;
		case 0xf5:
			rz_str_cpy(buf_asm, "CREATE2") break;
		case 0xfa:
			rz_str_cpy(buf_asm, "STATICCALL") break;
		case 0xfd:
			rz_str_cpy(buf_asm, "REVERT") break;
		case 0xff:
			rz_str_cpy(buf_asm, "SELFDESTRUCT") break;
		default:
			rz_str_cpy(buf_asm, "Invalid") break;
	}
	
	rz_strbuf_set(&op->buf_asm, buf_asm);
	return instruction_size;
}
