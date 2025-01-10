// SPDX-FileCopyrightText: 2018 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/*
	"Missing" vm ops:

	0F 01 C0 vmxoff
	0F 01 C1 vmcall
	0F 01 C2 vmlaunch
	0F 01 C3 vmresume
	0F 01 C4 vmxon
	0F 78 /r vmread r/m32,r32
	0F 79 /r vmwrite r32,r/m32
	0F C7 /6 m64 vmptrld m64
	0F C7 /7 m64 vmptrst m64
	66 0F C7 /6 m64 vmclear m64
	0F A6 /r xbts r32,r/m32
	0F A7 /r ibts r/m32,r32
	0F 37 getsec
	F0 FA clx
	F0 FB stx
	? smret
	? smcall
	? skinit
	? stgi

*/

#define VPCEXT2(y, x) ((y)[2] == (x))

static inline void decompile_vm(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	if (len > 3 && buf[0] == 0x0F && buf[1] == 0x3F && (VPCEXT2(buf, 0x01) || VPCEXT2(buf, 0x05) || VPCEXT2(buf, 0x07) || VPCEXT2(buf, 0x0D) || VPCEXT2(buf, 0x10))) {
		if (a->syntax == RZ_ASM_SYNTAX_ATT) {
			rz_asm_op_setf_asm(op, "vpcext $0x%x, $0x%x", buf[3], buf[2]);
		} else {
			rz_asm_op_setf_asm(op, "vpcext %xh, %xh", buf[2], buf[3]);
		}
		op->size = 4;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x00) {
		/* 0F C6 28 00 00 vmgetinfo */
		rz_asm_op_set_asm(op, "vmgetinfo");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x01) {
		/* 0F C6 28 00 01 vmsetinfo */
		rz_asm_op_set_asm(op, "vmsetinfo");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x02) {
		/* 0F C6 28 00 02 vmdxdsbl */
		rz_asm_op_set_asm(op, "vmdxdsbl");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x00 && buf[4] == 0x03) {
		/* 0F C6 28 00 03 vmdxenbl */
		rz_asm_op_set_asm(op, "vmdxenbl");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x00) {
		/* 0F C6 28 01 00 vmcpuid */
		rz_asm_op_set_asm(op, "vmcpuid");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x01) {
		/* 0F C6 28 01 01 vmhlt */
		rz_asm_op_set_asm(op, "vmhlt");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x01 && buf[4] == 0x02) {
		/* 0F C6 28 01 02 vmsplaf */
		rz_asm_op_set_asm(op, "vmsplaf");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x00) {
		/* 0F C6 28 02 00 vmpushfd */
		rz_asm_op_set_asm(op, "vmpushfd");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x01) {
		/* 0F C6 28 02 01 vmpopfd */
		rz_asm_op_set_asm(op, "vmpopfd");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x02) {
		/* 0F C6 28 02 02 vmcli */
		rz_asm_op_set_asm(op, "vmcli");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x03) {
		/* 0F C6 28 02 03 vmsti */
		rz_asm_op_set_asm(op, "vmsti");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x02 && buf[4] == 0x04) {
		/* 0F C6 28 02 04 vmiretd */
		rz_asm_op_set_asm(op, "vmiretd");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x00) {
		/* 0F C6 28 03 00 vmsgdt */
		rz_asm_op_set_asm(op, "vmsgdt");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x01) {
		/* 0F C6 28 03 01 vmsidt */
		rz_asm_op_set_asm(op, "vmsidt");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x02) {
		/* 0F C6 28 03 02 vmsldt */
		rz_asm_op_set_asm(op, "vmsldt");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x03 && buf[4] == 0x03) {
		/* 0F C6 28 03 03 vmstr */
		rz_asm_op_set_asm(op, "vmstr");
		op->size = 5;
	} else if (len > 4 && buf[0] == 0x0F && buf[1] == 0xC6 && buf[2] == 0x28 && buf[3] == 0x04 && buf[4] == 0x00) {
		/* 0F C6 28 04 00 vmsdte */
		rz_asm_op_set_asm(op, "vmsdte");
		op->size = 5;
	} else {
		rz_asm_op_set_asm(op, "invalid");
	}
}

#undef VPCEXT2
