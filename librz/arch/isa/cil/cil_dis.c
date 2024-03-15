// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_asm.h>
#include <rz_endian.h>
#include <rz_util/rz_strbuf.h>
#include "cil_dis.h"

/** \file
 * The read_## functions are dispatched based on the opcode `param`
 * they take the position in by pointer and can alter it,
 * and return a nonzero value if an error occurs
 *
 * The position is always the index of the next byte to read. If,
 * after incrementing by the number of bytes to be read, the index ==
 * the buffer length, the read has gone to the end of the buffer and
 * should succeed. If index > buffer length, the read is past the
 * bounds and should fail
 */

// Generate generic parameter types
#define DEF_READ_GENERIC(bytes, readtype, fmt) \
	static int read_generic##readtype(int *pos, CILOp *op, const ut8 *buf, int len) { \
		if (*pos + bytes > len) { \
			return -1; \
		} \
		rz_strbuf_appendf(&op->strbuf, fmt, rz_read_at_le##readtype(buf, *pos)); \
		*pos += bytes; \
		return 0; \
	}

DEF_READ_GENERIC(1, 8, " 0x%X")
DEF_READ_GENERIC(2, 16, " 0x%X")
DEF_READ_GENERIC(4, 32, " 0x%X")
DEF_READ_GENERIC(8, 64, " 0x%llX")

DEF_READ_GENERIC(4, _float, " %f")
DEF_READ_GENERIC(8, _double, " %f")

static int read_InlineNone(int *pos, CILOp *op, const ut8 *buf, int len) {
	return 0;
}

#define read_ShortInlineVar read_generic8
#define read_ShortInlineI   read_generic8

#define read_InlineVar read_generic16

#define read_InlineI      read_generic32
#define read_InlineSig    read_generic32
#define read_InlineType   read_generic32
#define read_InlineField  read_generic32
#define read_InlineString read_generic32
#define read_InlineTok    read_generic32

#define read_InlineI8 read_generic64

#define read_ShortInlineR read_generic_float
#define read_InlineR      read_generic_double

// Special
static int read_InlineMethod(int *pos, CILOp *op, const ut8 *buf, int len) {
	if (*pos + sizeof(ut32) > len) {
		return -1;
	}
	ut32 tok = rz_read_at_le32(buf, *pos);
	rz_strbuf_appendf(&op->strbuf, " 0x%X", tok);
	op->tok = tok;
	*pos += sizeof(ut32);
	return 0;
}

static int read_InlineBrTarget(int *pos, CILOp *op, const ut8 *buf, int len) {
	if (*pos + sizeof(st32) > len) {
		return -1;
	}
	st32 target = rz_read_at_le32(buf, *pos);
	rz_strbuf_appendf(&op->strbuf, " %d", target);
	op->target = target;
	*pos += sizeof(st32);
	return 0;
}

static int read_ShortInlineBrTarget(int *pos, CILOp *op, const ut8 *buf, int len) {
	if (*pos + sizeof(st8) > len) {
		return -1;
	}
	st8 target = rz_read_at_le8(buf, *pos);
	rz_strbuf_appendf(&op->strbuf, " %hhd", target);
	op->target = target;
	*pos += sizeof(st8);
	return 0;
}

static int read_InlineSwitch(int *pos, CILOp *op, const ut8 *buf, int len) {
	if (*pos + sizeof(ut32) > len) {
		return -1;
	}

	ut32 count = rz_read_le32(buf);
	*pos += sizeof(ut32);
	if (*pos + count * 4 > len) {
		return -1;
	}
	*pos += count * 4;
	return 0;
}

typedef struct {
	char *str;
	int (*read_param)(int *pos, CILOp *op, const ut8 *buf, int len);
	bool prefix;
} CILOpcodeReader;

/** \file
 * The opcode_readers arrays include the opcode mnemonic, the
 * appropriate parameter reader to call, and whether or not the opcode
 * is a prefix opcode
 *
 * eg. OPCODE_SINGLE(CIL_OP_NOP, "nop", InlineNone, 0x00, NEXT)
 * ->
 * CILOpcodeReader opcode_readers_single[] = {
 *   [CIL_OP_NOP] = { .str = "nop", .read_param = read_InlineNone },
 *   ...
 * }
 */
#define OPCODE_SINGLE(name, string, param, byte, control) [name] = { .str = string, .read_param = read_##param },
static const CILOpcodeReader opcode_readers_single[] = {
#include "opcodes_single.def"
	[0xFF] = { 0 }
};

#define OPCODE_DOUBLE(name, string, param, byte, control) [name] = { .str = string, .read_param = read_##param },
#define OPCODE_PREFIX(name, string, param, byte, control) [name] = { \
	.prefix = true, \
	.str = string, \
	.read_param = read_##param \
},
static const CILOpcodeReader opcode_readers_double[] = {
#include "opcodes_double.def"
#include "opcodes_prefix.def"
	[0xFF] = { 0 }
};

/**
 * \brief Disassemble a CIL buffer
 * \return 0 on success, -1 on fail
 */
int cil_dis(CILOp *op, const ut8 *buf, int len) {
	int pos = 0;
	if (pos >= len) { // pos + 1 > len
		return -1;
	}

	ut8 byte;
	rz_strbuf_init(&op->strbuf);

start: // Taken after a prefix opcode has been consumed
	byte = buf[pos++];

	CILOpcodeReader opcode_reader;
	if (byte != 0xFE) { // Single-byte
		op->byte1 = byte;
		opcode_reader = opcode_readers_single[byte];
	} else { // Double-byte
		if (pos >= len) { // pos + 1 > len
			return -1; // OOB
		}

		op->byte1 = byte;
		op->byte2 = byte = buf[pos++];
		opcode_reader = opcode_readers_double[byte];
	}

	if (!opcode_reader.str) {
		return -1; // Invalid
	}

	// Mnemonic
	if (!rz_strbuf_append(&op->strbuf, opcode_reader.str)) {
		return -1;
	}

	// Dispatch based on opcode `param`
	if (opcode_reader.read_param(&pos, op, buf, len)) {
		return -1;
	}

	if (opcode_reader.prefix) {
		if (!rz_strbuf_append(&op->strbuf, " ")) { // extra space
			return -1;
		}
		goto start; // continue
	}

	op->size = pos;
	return 0;
}
