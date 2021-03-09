// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PYC_DIS_H
#define PYC_DIS_H

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "opcode.h"

typedef enum {
	TYPE_ASCII = 'a',
	TYPE_ASCII_INTERNED = 'A',
	TYPE_BINARY_COMPLEX = 'y',
	TYPE_BINARY_FLOAT = 'g',
	TYPE_CODE_v0 = 'C',
	TYPE_CODE_v1 = 'c',
	TYPE_COMPLEX = 'x',
	TYPE_DICT = '{',
	TYPE_ELLIPSIS = '.',
	TYPE_FALSE = 'F',
	TYPE_FLOAT = 'f',
	TYPE_FROZENSET = '>',
	TYPE_INT64 = 'I',
	TYPE_INTERNED = 't',
	TYPE_INT = 'i',
	TYPE_LIST = '[',
	TYPE_LONG = 'l',
	TYPE_NONE = 'N',
	TYPE_NULL = '0',
	TYPE_REF = 'r',
	TYPE_SET = '<',
	TYPE_SHORT_ASCII_INTERNED = 'Z',
	TYPE_SHORT_ASCII = 'z',
	TYPE_SMALL_TUPLE = ')',
	TYPE_STOPITER = 'S',
	TYPE_STRINGREF = 'R',
	TYPE_STRING = 's',
	TYPE_TRUE = 'T',
	TYPE_TUPLE = '(',
	TYPE_UNICODE = 'u',
	TYPE_UNKNOWN = '?',
} pyc_marshal_type;

typedef enum {
	FLAG_REF = '\x80',
} pyc_marshal_flag;

typedef struct {
	pyc_marshal_type type;
	void *data;
} pyc_object;

typedef struct {
	ut32 argcount;
	ut32 posonlyargcount;
	ut32 kwonlyargcount;
	ut32 nlocals;
	ut32 stacksize;
	ut32 flags;
	pyc_object *code;
	pyc_object *consts;
	pyc_object *names;
	pyc_object *varnames;
	pyc_object *freevars;
	pyc_object *cellvars;
	pyc_object *filename;
	pyc_object *name;
	ut32 firstlineno;
	pyc_object *lnotab;
	st64 start_offset;
	st64 end_offset;
} pyc_code_object;

int rz_pyc_disasm(RzAsmOp *op, const ut8 *buf, RzList *cobjs, RzList *interned_table, ut64 pc, pyc_opcodes *opcodes);

#endif
