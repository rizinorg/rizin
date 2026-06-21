// SPDX-FileCopyrightText: 2016 c0riolis
// SPDX-FileCopyrightText: 2016 Tardy
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MARSHAL_H
#define MARSHAL_H

#include <rz_util.h>
#include <rz_types.h>
#include "pyc_magic.h"

#define RZ_PYC_CO_FAST_LOCAL 0x20
#define RZ_PYC_CO_FAST_CELL  0x40
#define RZ_PYC_CO_FAST_FREE  0x80

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
	TYPE_SLICE = ':',
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
	// For versions >=3.11.0
	pyc_object *localsplusnames;
	pyc_object *localspluskinds;
	pyc_object *qualname;
	pyc_object *exceptiontable;
} pyc_code_object;

typedef struct pyc_context {
	ut64 code_start_offset;
	struct pyc_version version;
	/* used from marshall.c */
	RzList /*<char *>*/ *interned_table;
	RzPVector /*<RzBinSection *>*/ *sections_cache;
	RzPVector /*<RzBinString *>*/ *strings_cache;
	RzPVector /*<RzBinSymbol *>*/ *symbols_cache;
	RzList /*<RzList<void *> *>*/ *shared;
	RzList /*<pyc_object *>*/ *refs; // If you don't have a good reason, do not change this. And also checkout !refs in get_code_object()
	ut32 magic_int;
	ut32 symbols_ordinal;
} RzBinPycObj;

bool get_sections_symbols_from_code_objects(RzBinPycObj *pyc, RzBuffer *buffer, RzPVector /*<RzBinSection *>*/ *sections, RzPVector /*<RzBinSymbol *>*/ *symbols, RzList /*<pyc_code_object *>*/ *objs, ut32 magic);
ut64 get_code_object_addr(RzBinPycObj *pyc, RzBuffer *buffer, ut32 magic);

#endif
