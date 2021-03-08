// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#include "pyc_dis.h"

static const char *cmp_op[] = { "<", "<=", "==", "!=", ">", ">=", "in", "not in", "is", "is not", "exception match", "BAD" };

static const char *parse_arg(pyc_opcode_object *op, ut32 oparg, RzList *names, RzList *consts, RzList *varnames, RzList *interned_table, RzList *freevars, RzList *cellvars, RzList *opcode_arg_fmt);

int rz_pyc_disasm(RzAsmOp *opstruct, const ut8 *code, RzList *cobjs, RzList *interned_table, ut64 pc, pyc_opcodes *ops) {
	pyc_code_object *cobj = NULL, *t = NULL;
	ut32 i = 0, oparg;
	st64 start_offset, end_offset;
	RzListIter *iter = NULL;

	rz_list_foreach (cobjs, iter, t) {
		start_offset = t->start_offset;
		end_offset = t->end_offset;
		if (start_offset <= pc && pc < end_offset) { // pc in [start_offset, end_offset)
			cobj = t;
			break;
		}
	}

	if (cobj) {
		/* TODO: adding line number and offset */
		RzList *varnames = cobj->varnames->data;
		RzList *consts = cobj->consts->data;
		RzList *names = cobj->names->data;
		RzList *freevars = cobj->freevars->data;
		RzList *cellvars = cobj->cellvars->data;

		ut8 op = code[i];
		i++;
		char *name = ops->opcodes[op].op_name;
		rz_strbuf_set(&opstruct->buf_asm, name);
		if (!name) {
			return 0;
		}
		if (op >= ops->have_argument) {
			if (ops->bits == 16) {
				oparg = code[i] + code[i + 1] * 256;
				i += 2;
			} else {
				oparg = code[i];
				i += 1;
			}
			const char *arg = parse_arg(&ops->opcodes[op], oparg, names, consts, varnames, interned_table, freevars, cellvars, ops->opcode_arg_fmt);
			if (arg != NULL) {
				rz_strbuf_appendf(&opstruct->buf_asm, "%20s", arg);
				free((char *)arg);
			}
		} else if (ops->bits == 8) {
			i += 1;
		}

		return i;
	}
	return 0;
}

static char *generic_array_obj_to_string(RzList *l);

static const char *parse_arg(pyc_opcode_object *op, ut32 oparg, RzList *names, RzList *consts, RzList *varnames, RzList *interned_table, RzList *freevars, RzList *cellvars, RzList *opcode_arg_fmt) {
	pyc_object *t = NULL;
	const char *arg = NULL;
	pyc_code_object *tmp_cobj;
	pyc_arg_fmt *fmt;
	RzListIter *i = NULL;

	// version-specific formatter for certain opcodes
	rz_list_foreach (opcode_arg_fmt, i, fmt)
		if (!strcmp(fmt->op_name, op->op_name)) {
			return fmt->formatter(oparg);
		}

	if (op->type & HASCONST) {
		t = (pyc_object *)rz_list_get_n(consts, oparg);
		if (t == NULL) {
			return NULL;
		}
		switch (t->type) {
		case TYPE_CODE_v0:
		case TYPE_CODE_v1:
			tmp_cobj = t->data;
			arg = rz_str_newf("CodeObject(%s) from %s", (char *)tmp_cobj->name->data, (char *)tmp_cobj->filename->data);
			break;
		case TYPE_TUPLE:
		case TYPE_SET:
		case TYPE_FROZENSET:
		case TYPE_LIST:
		case TYPE_SMALL_TUPLE:
			arg = generic_array_obj_to_string(t->data);
			break;
		case TYPE_STRING:
		case TYPE_INTERNED:
		case TYPE_STRINGREF:
			arg = rz_str_newf("'%s'", (char *)t->data);
			break;
		default:
			arg = rz_str_new(t->data);
		}
	}
	if (op->type & HASNAME) {
		t = (pyc_object *)rz_list_get_n(names, oparg);
		if (t == NULL) {
			return NULL;
		}
		arg = rz_str_new(t->data);
	}
	if ((op->type & HASJREL) || (op->type & HASJABS)) {
		arg = rz_str_newf("%u", oparg);
	}
	if (op->type & HASLOCAL) {
		t = (pyc_object *)rz_list_get_n(varnames, oparg);
		if (!t)
			return NULL;
		arg = rz_str_new(t->data);
	}
	if (op->type & HASCOMPARE) {
		arg = rz_str_new(cmp_op[oparg]);
	}
	if (op->type & HASFREE) {
		if (!cellvars || !freevars) {
			arg = rz_str_newf("%u", oparg);
			return arg;
		}

		if (oparg < rz_list_length(cellvars)) {
			t = (pyc_object *)rz_list_get_n(cellvars, oparg);
		} else if ((oparg - rz_list_length(cellvars)) < rz_list_length(freevars)) {
			t = (pyc_object *)rz_list_get_n(freevars, oparg);
		} else {
			arg = rz_str_newf("%u", oparg);
			return arg;
		}
		if (!t) {
			return NULL;
		}

		arg = rz_str_new(t->data);
	}
	if (op->type & HASNARGS) {
		arg = rz_str_newf("%u", oparg);
	}
	if (op->type & HASVARGS) {
		arg = rz_str_newf("%u", oparg);
	}

	return arg;
}

static char *generic_array_obj_to_string(RzList *l) {
	RzListIter *iter = NULL;
	pyc_object *e = NULL;

	RzStrBuf *rbuf = rz_strbuf_new(NULL);

	rz_list_foreach (l, iter, e) {
		rz_strbuf_append(rbuf, e->data);
		rz_strbuf_append(rbuf, ",");
	}

	char *buf = rz_strbuf_get(rbuf);

	/* remove last , */
	buf[strlen(buf) - 1] = '\0';
	char *r = rz_str_newf("(%s)", buf);

	rz_strbuf_free(rbuf);
	return r;
}
