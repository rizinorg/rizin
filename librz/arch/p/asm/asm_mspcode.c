// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

static int mspcode_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	if (l < 1) {
		return 0;
	}
	const ut8 opcode = b[0];
	op->size = 1;
	rz_asm_op_set_asm(op, "invalid");

	switch (opcode) {
	case 0x00:
		if (l < 2) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "IDE_BOL 0x%02x", b[1]);
		op->size = 2;
		break;
	case 0x02:
		if (l < 2) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "IDE_BOL 0x%02x", b[1]);
		op->size = 2;
		break;

	// Push [FC0D134] (well-known global)
	case 0x01:
		rz_asm_op_set_asm(op, "Push [FC0D134]");
		break;
	case 0x03:
		rz_asm_op_set_asm(op, "Push [FC0D134]");
		break;

	// Push arg / ptr / [SR]+arg (imm#2)
	case 0x04:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "PushArg 0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;
	case 0x05:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "PushPtr 0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;
	case 0x06:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "Push [SR]+0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;

	// Push [arg1]+imm#2 (imm#2 + imm#2)
	case 0x07:
		if (l < 5) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "Push [0x%04x]+0x%04x", rz_read_le16(b + 1), rz_read_le16(b + 3));
		op->size = 5;
		break;

	// [SR]=[arg] (imm#2)
	case 0x08:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "[SR]=[0x%04x]", rz_read_le16(b + 1));
		op->size = 3;
		break;

	// Call variants (ptr1 + imm2#2) => total 1 + 2 + 2 = 5
	case 0x0A:
		if (l < 5) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "Call 0x%04x ; chkstack 0x%04x", rz_read_le16(b + 1), rz_read_le16(b + 3));
		op->size = 5;
		break;
	case 0x0B:
		if (l < 5) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "CallPushEAX 0x%04x ; chkstack 0x%04x", rz_read_le16(b + 1), rz_read_le16(b + 3));
		op->size = 5;
		break;

	// Procedure end / exits
	case 0x13:
		rz_asm_op_set_asm(op, "EndProc");
		break;
	case 0x14:
		rz_asm_op_set_asm(op, "EndProc");
		break;
	case 0x16:
		rz_asm_op_set_asm(op, "ExitProc");
		break;
	case 0x17:
		rz_asm_op_set_asm(op, "ExitEngineGroup");
		break;
	case 0x18:
		rz_asm_op_set_asm(op, "ExitEngineGroup");
		break;

	// Push ptr (analysis treats 0x1B as push, not a branch)
	case 0x1B:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "PushPtr 0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;

	// Conditional branch: If Pop==0 / Pop!=0 / unconditional branch (imm#2)
	case 0x1C:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "IfZ +0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;
	case 0x1D:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "IfNZ +0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;
	case 0x1E:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "Jmp +0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;

	case 0x27:
		if (l > 1) {
			rz_asm_op_setf_asm(op, "PushVarError 0x80020004 ; LitI2_Byte %d", (ut8)b[1]);
			op->size = 2;
		} else {
			rz_asm_op_set_asm(op, "PushVarError 0x80020004");
		}
		break;

	// PushVarInteger imm2#2 (imm#2)
	case 0x28:
		if (l < 3) {
			return 0;
		}
		rz_asm_op_setf_asm(op, "PushVarInteger 0x%04x", rz_read_le16(b + 1));
		op->size = 3;
		break;

	// Variable-size ops: 1 + 2 + nbytes payload
	case 0x29:
	case 0x32:
	case 0x36:
		if (l < 3) {
			return 0;
		}
		{
			const ut16 nbytes = rz_read_le16(b + 1);
			const ut32 total = 1u + 2u + (ut32)nbytes;
			if (l < (int)total) {
				return 0;
			}
			rz_asm_op_setf_asm(op, "VarOp 0x%02x nbytes=%u", opcode, (unsigned)nbytes);
			op->size = (int)total;
		}
		break;

	// vbaStrCat
	case 0x2A:
		rz_asm_op_set_asm(op, "vbaStrCat");
		break;

	default:
		rz_asm_op_setf_asm(op, "db 0x%02x", opcode);
		break;
	}

	return op->size;
}

RzAsmPlugin rz_asm_plugin_mspcode = {
	.name = "mspcode",
	.arch = "mspcode",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Microsoft P-Code disassembler",
	.disassemble = &mspcode_disassemble,
};
