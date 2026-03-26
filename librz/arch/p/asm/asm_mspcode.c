// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
// not complete
static int mspcode_disassemble(const RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	if (l < 1) {
		return 0;
	}
	ut8 opcode = b[0];
	op->size = 1;
	rz_asm_op_set_asm(op, "invalid");

	switch (opcode) {
	case 0x00: rz_asm_op_set_asm(op, "Add"); break;
	case 0x01: rz_asm_op_set_asm(op, "Sub"); break;
	case 0x02: rz_asm_op_set_asm(op, "Mul"); break;
	case 0x03: rz_asm_op_set_asm(op, "Div"); break;
	case 0x04: rz_asm_op_set_asm(op, "Mod"); break;
	case 0x05: rz_asm_op_set_asm(op, "Neg"); break;
	case 0x06: rz_asm_op_set_asm(op, "Not"); break;
	case 0x07: rz_asm_op_set_asm(op, "And"); break;
	case 0x08: rz_asm_op_set_asm(op, "Or"); break;
	case 0x09: rz_asm_op_set_asm(op, "Xor"); break;
	case 0x0a: rz_asm_op_set_asm(op, "Eqv"); break;
	case 0x0b: rz_asm_op_set_asm(op, "Imp"); break;
	case 0x0c: rz_asm_op_set_asm(op, "Lt"); break;
	case 0x0d: rz_asm_op_set_asm(op, "Le"); break;
	case 0x0e: rz_asm_op_set_asm(op, "Gt"); break;
	case 0x0f: rz_asm_op_set_asm(op, "Ge"); break;
	case 0x10: rz_asm_op_set_asm(op, "Eq"); break;
	case 0x11: rz_asm_op_set_asm(op, "Ne"); break;

	case 0x27: // LitI2_Byte
		if (l > 1) {
			rz_asm_op_setf_asm(op, "LitI2_Byte %d", (char)b[1]);
			op->size = 2;
		}
		break;
	case 0xF4: // LitI2
		if (l > 2) {
			rz_asm_op_setf_asm(op, "LitI2 0x%04x", rz_read_le16(b + 1));
			op->size = 3;
		}
		break;
	case 0xF5: // LitI4
		if (l > 4) {
			rz_asm_op_setf_asm(op, "LitI4 0x%08x", rz_read_le32(b + 1));
			op->size = 5;
		}
		break;

	// Control Flow
	case 0x1B: // Branch
	case 0x1C: // BranchT
	case 0x1D: // BranchF
		if (l > 2) {
			ut16 offset = rz_read_le16(b + 1);
			const char *mnemonic = (opcode == 0x1B) ? "Branch" : (opcode == 0x1C) ? "BranchT"
											      : "BranchF";
			rz_asm_op_setf_asm(op, "%s 0x%04x", mnemonic, offset);
			op->size = 3;
		}
		break;

	case 0xFC:
		rz_asm_op_set_asm(op, "End");
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
