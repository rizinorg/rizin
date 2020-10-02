/*
 * Convert from ESIL to REIL (Reverse Engineering Intermediate Language)
 * Contributor: sushant94
 */

#include <rz_anal.h>

#define REIL_TEMP_PREFIX "V"
#define REIL_REG_PREFIX "R_"
#define REGBUFSZ 32

void reil_flag_spew_inst(RzAnalEsil *esil, const char *flag);
static const char *ops[] = { FOREACHOP(REIL_OP_STRING) };

// Get size of a register.
static ut8 esil_internal_sizeof_reg(RzAnalEsil *esil, const char *r) {
	if (!esil || !esil->anal || !esil->anal->reg || !r) {
		return false;
	}
	RzRegItem *i = rz_reg_get(esil->anal->reg, r, -1);
	return i ? (ut8)i->size : 0;
}

RzAnalReilArgType reil_get_arg_type(RzAnalEsil *esil, char *s) {
	if (!strncmp (s, REIL_TEMP_PREFIX, strlen (REIL_TEMP_PREFIX))) {
		return ARG_TEMP;
	}
	int type = rz_anal_esil_get_parm_type(esil, s);
	switch (type) {
	case RZ_ANAL_ESIL_PARM_REG:
		return ARG_REG;
	case RZ_ANAL_ESIL_PARM_NUM:
		return ARG_CONST;
	default:
		return ARG_NONE;
	}
}

// Marshall the struct into a string
void reil_push_arg(RzAnalEsil *esil, RzAnalReilArg *op) {
	char *s = rz_str_newf ("%s:%d", op->name, op->size);
	rz_anal_esil_push (esil, s);
	free (s);
}

// Unmarshall the string in stack to the struct.
RzAnalReilArg *reil_pop_arg(RzAnalEsil *esil) {
	RzAnalReilArg *op;
	int i, j = 0, flag = 0, len;
	char tmp_buf[REGBUFSZ];
	char *buf = rz_anal_esil_pop(esil);
	if (!buf) {
		return NULL;
	}
	len = strlen (buf);
	op = RZ_NEW0(RzAnalReilArg);
	for (i = 0; i < len; i++) {
		if (buf[i] == ':') {
			tmp_buf[j] = '\0';
			rz_str_ncpy (op->name, tmp_buf, sizeof (op->name));
			memset (tmp_buf, 0, sizeof (tmp_buf));
			j = 0;
			flag = 1;
			continue;
		}
		// Strip all spaces
		if (buf[i] == ' ') {
			continue;
		}
		tmp_buf[j] = buf[i];
		j++;
	}
	tmp_buf[j] = '\0';

	// If we have not encountered a ':' we don't know the size yet.
	if (!flag) {
		rz_str_ncpy (op->name, tmp_buf, sizeof (op->name));
		op->type = reil_get_arg_type (esil, op->name);
		if (op->type == ARG_REG) {
			op->size = esil_internal_sizeof_reg(esil, op->name);
		} else if (op->type == ARG_CONST) {
			op->size = esil->anal->bits;
		}
		free(buf);
		return op;
	}

	op->size = strtoll(tmp_buf, NULL, 10);
	op->type = reil_get_arg_type(esil, op->name);
	free(buf);
	return op;
}

// Get the next available temp register.
void get_next_temp_reg(RzAnalEsil *esil, char *buf) {
	rz_snprintf (buf, REGBUFSZ, REIL_TEMP_PREFIX"_%02"PFMT64u,
		esil->Reil->reilNextTemp);
	esil->Reil->reilNextTemp++;
}

void reil_make_arg(RzAnalEsil *esil, RzAnalReilArg *arg, char *name) {
	if (!arg) {
		return;
	}
	RzAnalReilArgType type = reil_get_arg_type (esil, name);
	arg->size = 0;
	arg->type = type;
	rz_str_ncpy  (arg->name, name, sizeof (arg->name) - 1);
}

// Free ins and all its arguments
void reil_free_inst(RzAnalReilInst *ins) {
	if (!ins) {
		return;
	}
	if (ins->arg[0]) { RZ_FREE (ins->arg[0]); }
	if (ins->arg[1]) { RZ_FREE (ins->arg[1]); }
	if (ins->arg[2]) { RZ_FREE (ins->arg[2]); }
	RZ_FREE(ins);
}

// Automatically increments the seq_num of the instruction.
void reil_print_inst(RzAnalEsil *esil, RzAnalReilInst *ins) {
	int i;

	if (!ins || !esil) {
		return;
	}
	esil->anal->cb_printf("%04"PFMT64x".%02"PFMT64x": %8s",
		esil->Reil->addr, esil->Reil->seq_num++, ops[ins->opcode]);
	for (i = 0; i < 3; i++) {
		if (i > 0) {
			esil->anal->cb_printf (" ,");
		}
		if (!ins->arg[i]) {
			continue;
		}
		if (ins->arg[i]->type == ARG_NONE) {
			esil->anal->cb_printf ("%10s   ", ins->arg[i]->name);
			continue;
		}
		if (ins->arg[i]->type == ARG_REG) {
			char *tmp_buf = rz_str_newf ("%s%s", REIL_REG_PREFIX, ins->arg[i]->name);
			esil->anal->cb_printf ("%10s:%02d", tmp_buf, ins->arg[i]->size);
			free (tmp_buf);
			continue;
		}
		esil->anal->cb_printf ("%10s:%02d", ins->arg[i]->name, ins->arg[i]->size);
	}
	esil->anal->cb_printf("\n");
}

// Used to cast sizes during assignment. OR is used for casting.
// Pushes the new *casted* src onto stack. Warning: Frees the original src!
void reil_cast_size(RzAnalEsil *esil, RzAnalReilArg *src, RzAnalReilArg *dst) {
	char tmp_buf[REGBUFSZ];
	RzAnalReilInst *ins;

	if (!src || !dst) {
		return;
	}
	// No need to case sizes if dst and src are of same size.
	if (src->size == dst->size) {
		reil_push_arg(esil, src);
		return;
	}
	snprintf (tmp_buf, REGBUFSZ-1, "0:%d", dst->size);
	rz_anal_esil_push (esil, tmp_buf);
	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		return;
	}
	ins->opcode = REIL_OR;
	ins->arg[0] = src;
	ins->arg[1] = reil_pop_arg (esil);
	ins->arg[2] = RZ_NEW0(RzAnalReilArg);
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	if (ins->arg[2]) {
		ins->arg[2]->size = dst->size;
	}
	reil_print_inst (esil, ins);
	if (ins->arg[2]) {
		reil_push_arg (esil, ins->arg[2]);
	}
	reil_free_inst (ins);
}

// Here start translation functions!
static bool reil_eq(RzAnalEsil *esil) {
	RzAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RzAnalReilArgType src_type, dst_type;
	RzAnalReilArg *dst, *src;

	dst = reil_pop_arg (esil);
	if (!dst) {
		return false;
	}
	src = reil_pop_arg (esil);
	if (!src) {
		RZ_FREE (dst);
		return false;
	}

	src_type = src->type;
	// Check if the src is an internal var. If it is, we need to resolve it.
	if (src_type == ARG_ESIL_INTERNAL) {
		reil_flag_spew_inst (esil, src->name + 1);
		RZ_FREE (src);
		src = reil_pop_arg (esil);
	} else if (src_type == ARG_REG) {
		// No direct register to register transfer.
		ins = RZ_NEW0 (RzAnalReilInst);
		if (!ins) {
			free (src);
			free (dst);
			return false;
		}
		ins->opcode = REIL_STR;
		ins->arg[0] = src;
		ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
		if (!ins->arg[1]) {
			reil_free_inst (ins);
			return false;
		}
		ins->arg[2] = RZ_NEW0(RzAnalReilArg);
		if (!ins->arg[2]) {
			reil_free_inst (ins);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);
		reil_push_arg( esil, ins->arg[2]);
		reil_free_inst (ins);
		src = reil_pop_arg (esil);
	}

	// First, make a copy of the dst. We will need this to set the flags later on.
	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (dst);
		RZ_FREE (src);
		return false;
	}
	dst_type = dst->type;
	if (src_type != ARG_ESIL_INTERNAL && dst_type == ARG_REG) {
		ins->opcode = REIL_STR;
		ins->arg[0] = dst;
		ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
		if (!ins->arg[1]) {
			reil_free_inst (ins);
			RZ_FREE (src);
			return false;
		}
		ins->arg[2] = RZ_NEW0 (RzAnalReilArg);
		if (!ins->arg[2]) {
			reil_free_inst (ins);
			RZ_FREE (src);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);

		// Used for setting the flags
		rz_snprintf (esil->Reil->old, sizeof (esil->Reil->old) - 1, "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		rz_snprintf (esil->Reil->cur, sizeof (esil->Reil->cur) - 1, "%s:%d", dst->name,
				dst->size);
		esil->Reil->lastsz = dst->size;

		RZ_FREE (ins->arg[1]);
		RZ_FREE (ins->arg[2]);
	}

	// If we are modifying the Instruction Pointer, then we need to emit JCC instead.
	if (!strcmp(esil->Reil->pc, dst->name)) {
		ins->opcode = REIL_JCC;
		rz_anal_esil_push (esil, "1:1");
		ins->arg[0] = reil_pop_arg (esil);
		ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
		reil_make_arg (esil, ins->arg[1], " ");
		ins->arg[2] = src;
		reil_print_inst (esil, ins);
		reil_free_inst (ins);
		RZ_FREE (dst);
		return true;
	}

	reil_cast_size (esil, src, dst);
	ins->opcode = REIL_STR;
	ins->arg[0] = reil_pop_arg (esil);
	if (!ins->arg[0]) {
		RZ_FREE (dst);
		reil_free_inst (ins);
		return false;
	}

	ins->arg[2] = dst;
	ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
	reil_make_arg (esil, ins->arg[1], " ");
	reil_print_inst (esil, ins);
	reil_free_inst (ins);
	return true;
}

// General function for operations that take 2 operands
static int reil_binop(RzAnalEsil *esil, RzAnalReilOpcode opcode) {
	RzAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	ut8 dst_size;
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op1);
		RZ_FREE (op2);
		return false;
	}
	ins->opcode = opcode;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = RZ_NEW0(RzAnalReilArg);
	if (!ins->arg[2])  {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	// Choose the larger of the two sizes as the size of dst
	dst_size = ins->arg[0]->size;
	if (dst_size < ins->arg[1]->size) {
		dst_size = ins->arg[1]->size;
	}
	// REIL_LT has a dst_size of 1.
	if (opcode == REIL_LT) {
		dst_size = 1;
	}
	ins->arg[2]->size = dst_size;
	reil_print_inst(esil, ins);
	reil_push_arg(esil, ins->arg[2]);
	reil_free_inst(ins);
	return true;
}

// General function for operations which re-assign to dst. Example, addeq.
static int reil_bineqop(RzAnalEsil *esil, RzAnalReilOpcode opcode) {
	int ret = 1;
	RzAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}

	reil_push_arg(esil, op);
	ret &= reil_binop(esil, opcode);
	reil_push_arg(esil, op);
	ret &= reil_eq(esil);
	RZ_FREE(op);
	return ret;
}

static bool reil_add(RzAnalEsil *esil)     { return reil_binop (esil, REIL_ADD);   }
static bool reil_addeq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_ADD); }
static bool reil_mul(RzAnalEsil *esil)     { return reil_binop (esil, REIL_MUL);   }
static bool reil_muleq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_MUL); }
static bool reil_sub(RzAnalEsil *esil)     { return reil_binop (esil, REIL_SUB);   }
static bool reil_subeq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_SUB); }
static bool reil_div(RzAnalEsil *esil)     { return reil_binop (esil, REIL_DIV);   }
static bool reil_diveq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_DIV); }
static bool reil_xor(RzAnalEsil *esil)     { return reil_binop (esil, REIL_XOR);   }
static bool reil_xoreq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_XOR); }
static bool reil_and(RzAnalEsil *esil)     { return reil_binop (esil, REIL_AND);   }
static bool reil_andeq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_AND); }
static bool reil_or(RzAnalEsil *esil)      { return reil_binop (esil, REIL_OR);    }
static bool reil_oreq(RzAnalEsil *esil)    { return reil_bineqop (esil, REIL_OR);  }
static bool reil_lsl(RzAnalEsil *esil)     { return reil_binop (esil, REIL_SHL);   }
static bool reil_lsleq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHL); }
static bool reil_lsr(RzAnalEsil *esil)     { return reil_binop (esil, REIL_SHR);   }
static bool reil_lsreq(RzAnalEsil *esil)   { return reil_bineqop (esil, REIL_SHR); }
static bool reil_smaller(RzAnalEsil *esil) { return reil_binop (esil, REIL_LT);    }

static bool reil_cmp(RzAnalEsil *esil) {
	RzAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op1);
		RZ_FREE (op2);
		return false;
	}
	ins->opcode = REIL_EQ;
	ins->arg[0] = op2;
	ins->arg[1] = op1;
	ins->arg[2] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = 1;
	reil_print_inst (esil, ins);
	// Set vars needed to determine flags.
	rz_snprintf (esil->Reil->cur, sizeof (esil->Reil->old) - 1, "%s:%d",
			ins->arg[2]->name, ins->arg[2]->size);
	rz_snprintf (esil->Reil->old, sizeof (esil->Reil->cur) - 1, "%s:%d",
			op2->name, op2->size);
	if (rz_reg_get (esil->anal->reg, op2->name, -1)) {
		esil->Reil->lastsz = op2->size;
	} else if (rz_reg_get (esil->anal->reg, op1->name, -1)) {
		esil->Reil->lastsz = op1->size;
	}
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_smaller_equal(RzAnalEsil *esil) {
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);
	reil_smaller(esil);
	reil_push_arg(esil, op1);
	reil_push_arg(esil, op2);
	reil_cmp(esil);
	reil_or(esil);

	RZ_FREE(op1);
	RZ_FREE(op2);
	return true;
}

static bool reil_larger(RzAnalEsil *esil) {
	RzAnalReilArg *op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	RzAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}
	reil_push_arg (esil, op2);
	reil_push_arg (esil, op1);
	reil_smaller (esil);
	RZ_FREE (op1);
	RZ_FREE (op2);
	return true;
}

static bool reil_larger_equal(RzAnalEsil *esil) {
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg(esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg(esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	reil_push_arg (esil, op2);
	reil_push_arg (esil, op1);
	reil_smaller_equal (esil);
	RZ_FREE (op1);
	RZ_FREE (op2);
	return true;
}

static bool reil_dec(RzAnalEsil *esil) {
	RzAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	rz_anal_esil_pushnum (esil, 1);
	reil_push_arg (esil, op);
	reil_sub (esil);
	RZ_FREE (op);
	return true;
}

static bool reil_deceq(RzAnalEsil *esil) {
	RzAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}
	reil_push_arg (esil, op1);
	reil_dec (esil);
	reil_push_arg (esil, op1);
	reil_eq (esil);
	RZ_FREE (op1);
	return true;
}

static bool reil_inc(RzAnalEsil *esil) {
	RzAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}

	rz_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_add(esil);
	RZ_FREE(op);
	return true;
}

static bool reil_inceq(RzAnalEsil *esil) {
	RzAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	reil_push_arg (esil, op);
	reil_inc (esil);
	reil_push_arg (esil, op);
	reil_eq (esil);
	RZ_FREE (op);
	return true;
}

static bool reil_neg(RzAnalEsil *esil) {
	char tmp_buf[REGBUFSZ];
	RzAnalReilInst *ins;
	RzAnalReilArg *op = reil_pop_arg (esil);
	if (!op) {
		return false;
	}
	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op);
		return false;
	}
	ins->opcode = REIL_EQ;
	ins->arg[0] = op;
	rz_anal_esil_pushnum (esil, 0);
	ins->arg[1] = reil_pop_arg(esil);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	if (ins->arg[0]->size < ins->arg[1]->size) {
		ins->arg[1]->size = ins->arg[0]->size;
	}

	ins->arg[2]->size = 1;
	reil_print_inst (esil, ins);
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_negeq(RzAnalEsil *esil) {
	RzAnalReilArg *op = reil_pop_arg(esil);
	if (!op) {
		return false;
	}
	reil_push_arg (esil, op);
	reil_neg (esil);
	reil_push_arg (esil, op);
	reil_eq (esil);
	free (op);
	return true;
}

static bool reil_not(RzAnalEsil *esil) {
	char tmp_buf[REGBUFSZ];
	RzAnalReilInst *ins;
	RzAnalReilArg *op = reil_pop_arg (esil);
	if (!op) {
		return false;
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op);
		return false;
	}
	ins->opcode = REIL_NOT;
	ins->arg[0] = op;
	ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg (esil, ins->arg[1], " ");
	get_next_temp_reg (esil, tmp_buf);
	reil_make_arg (esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst (esil, ins);
	reil_push_arg (esil, ins->arg[2]);
	reil_free_inst (ins);
	return true;
}

static bool reil_if(RzAnalEsil *esil) {
	RzAnalReilInst *ins;
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op2);
		RZ_FREE (op1);
		return false;
	}
	ins->opcode = REIL_JCC;
	ins->arg[0] = op1;
	ins->arg[2] = op2;
	ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg (esil, ins->arg[1], " ");
	reil_print_inst (esil, ins);
	reil_free_inst (ins);
	return true;
}

static bool reil_if_end(RzAnalEsil *esil) { return true; }

static bool reil_peek(RzAnalEsil *esil) {
	RzAnalReilInst *ins;
	char tmp_buf[REGBUFSZ];
	RzAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		RZ_FREE (op1);
		return false;
	}
	ins->opcode = REIL_LDM;
	ins->arg[0] = op1;
	ins->arg[1] = RZ_NEW0(RzAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	ins->arg[2] = RZ_NEW0(RzAnalReilArg);
	if (!ins->arg[2]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg(esil, ins->arg[1], " ");
	get_next_temp_reg(esil, tmp_buf);
	reil_make_arg(esil, ins->arg[2], tmp_buf);
	ins->arg[2]->size = ins->arg[0]->size;
	reil_print_inst(esil, ins);
	reil_push_arg(esil, ins->arg[2]);
	reil_free_inst(ins);
	return true;
}

// n = 8, 4, 2, 1
static bool reil_peekn(RzAnalEsil *esil, ut8 n) {
	RzAnalReilArg *op2;
	RzAnalReilArg *op1 = reil_pop_arg (esil);
	if (!op1) {
		return false;
	}

	reil_push_arg (esil, op1);
	reil_peek (esil);
	// No need to cast if n = 0
	if (n == 0) {
		RZ_FREE (op1);
		return true;
	}

	RZ_FREE (op1);
	op1 = reil_pop_arg (esil);
	if (!op1) {
		return false;
	}

	op2 = RZ_NEW0 (RzAnalReilArg);
	if (!op2) {
		RZ_FREE (op1);
		return false;
	}
	op2->size = n * 8;
	op2->type = ARG_TEMP;
	get_next_temp_reg (esil, op2->name);
	reil_cast_size (esil, op1, op2);
	esil->Reil->lastsz = 8 * n;

	RZ_FREE (op2);
	return true;
}

static bool reil_peek1(RzAnalEsil *esil) { return reil_peekn(esil, 1); }
static bool reil_peek2(RzAnalEsil *esil) { return reil_peekn(esil, 2); }
static bool reil_peek4(RzAnalEsil *esil) { return reil_peekn(esil, 4); }
static bool reil_peek8(RzAnalEsil *esil) { return reil_peekn(esil, 8); }

// n = 8, 4, 2, 1
static bool reil_poken(RzAnalEsil *esil, ut8 n) {
	char tmp_buf[REGBUFSZ];
	RzAnalReilInst *ins;
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	if (op1->type != ARG_ESIL_INTERNAL) {
		ins = RZ_NEW0 (RzAnalReilInst);
		if (!ins) {
			RZ_FREE (op2);
			RZ_FREE (op1);
			return false;
		}
		ins->opcode = REIL_LDM;
		ins->arg[0] = op2;
		ins->arg[1] = RZ_NEW0(RzAnalReilArg);
		if (!ins->arg[1]) {
			RZ_FREE (op1);
			reil_free_inst (ins);
			return false;
		}
		ins->arg[2] = RZ_NEW0(RzAnalReilArg);
		if (!ins->arg[2]) {
			RZ_FREE (op1);
			reil_free_inst (ins);
			return false;
		}
		reil_make_arg (esil, ins->arg[1], " ");
		get_next_temp_reg (esil, tmp_buf);
		reil_make_arg (esil, ins->arg[2], tmp_buf);
		ins->arg[2]->size = ins->arg[0]->size;
		reil_print_inst (esil, ins);
		rz_snprintf (esil->Reil->old, sizeof (esil->Reil->old) - 1, "%s:%d",
				ins->arg[2]->name, ins->arg[2]->size);
		rz_snprintf (esil->Reil->cur, sizeof (esil->Reil->cur) - 1, "%s:%d",
				op2->name, op2->size);
		esil->lastsz = n * 8;
		reil_push_arg (esil, op1);
		reil_push_arg (esil, op2);
		RZ_FREE (op1);
		reil_free_inst (ins);
	} else {
		reil_flag_spew_inst (esil, op1->name + 1);
		RZ_FREE (op1);
		op1 = reil_pop_arg (esil);
		reil_push_arg (esil, op2);
		reil_push_arg (esil, op1);
		RZ_FREE (op2);
		RZ_FREE (op1);
	}

	ins = RZ_NEW0 (RzAnalReilInst);
	if (!ins) {
		return false;
	}
	ins->opcode = REIL_STM;
	ins->arg[2] = reil_pop_arg (esil);
	ins->arg[0] = reil_pop_arg (esil);
	ins->arg[1] = RZ_NEW0 (RzAnalReilArg);
	if (!ins->arg[1]) {
		reil_free_inst (ins);
		return false;
	}
	reil_make_arg(esil, ins->arg[1], " ");
	reil_print_inst(esil, ins);
	reil_free_inst(ins);
	return true;
}

static bool reil_poke(RzAnalEsil *esil) {
	return reil_poken (esil, esil->anal->bits / 8);
}

static bool reil_poke1(RzAnalEsil *esil) { return reil_poken(esil, 1); }
static bool reil_poke2(RzAnalEsil *esil) { return reil_poken(esil, 2); }
static bool reil_poke4(RzAnalEsil *esil) { return reil_poken(esil, 4); }
static bool reil_poke8(RzAnalEsil *esil) { return reil_poken(esil, 8); }

// Generic function to handle all mem_*eq_n functions. Example, mem_oreq_n
static bool reil_mem_bineq_n(RzAnalEsil *esil, RzAnalReilOpcode opcode, ut8 size) {
	int ret = 1;
	RzAnalReilArg *op2, *op1;

	op2 = reil_pop_arg (esil);
	if (!op2) {
		return false;
	}
	op1 = reil_pop_arg (esil);
	if (!op1) {
		RZ_FREE (op2);
		return false;
	}

	reil_push_arg(esil, op2);
	ret &= reil_peekn(esil, size);
	reil_push_arg(esil, op1);
	ret &= reil_binop(esil, opcode);
	reil_push_arg(esil, op2);
	ret &= reil_poken(esil, size);

	free (op2);
	free (op1);
	return ret;
}

static bool reil_mem_oreq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_OR, esil->anal->bits / 8); }
static bool reil_mem_oreq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 1); }
static bool reil_mem_oreq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 2); }
static bool reil_mem_oreq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 4); }
static bool reil_mem_oreq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_OR, 8); }

static bool reil_mem_andeq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_AND, esil->anal->bits / 8); }
static bool reil_mem_andeq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 1); }
static bool reil_mem_andeq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 2); }
static bool reil_mem_andeq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 4); }
static bool reil_mem_andeq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_AND, 8); }

static bool reil_mem_xoreq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_XOR, esil->anal->bits / 8); }
static bool reil_mem_xoreq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 1); }
static bool reil_mem_xoreq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 2); }
static bool reil_mem_xoreq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 4); }
static bool reil_mem_xoreq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_XOR, 8); }

static bool reil_mem_addeq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_ADD, esil->anal->bits / 8); }
static bool reil_mem_addeq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 1); }
static bool reil_mem_addeq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 2); }
static bool reil_mem_addeq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 4); }
static bool reil_mem_addeq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_ADD, 8); }

static bool reil_mem_subeq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_SUB, esil->anal->bits / 8); }
static bool reil_mem_subeq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 1); }
static bool reil_mem_subeq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 2); }
static bool reil_mem_subeq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 4); }
static bool reil_mem_subeq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_SUB, 8); }

static bool reil_mem_muleq(RzAnalEsil *esil)  { return reil_mem_bineq_n(esil, REIL_MUL, esil->anal->bits / 8); }
static bool reil_mem_muleq1(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 1); }
static bool reil_mem_muleq2(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 2); }
static bool reil_mem_muleq4(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 4); }
static bool reil_mem_muleq8(RzAnalEsil *esil) { return reil_mem_bineq_n(esil, REIL_MUL, 8); }

static bool reil_mem_inceq_n(RzAnalEsil *esil, ut8 size) {
	int ret = 1;
	RzAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	rz_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_bineq_n(esil, REIL_ADD, size);

	free (op1);
	return ret;
}

static bool reil_mem_inceq(RzAnalEsil *esil) {
	return reil_mem_inceq_n(esil, esil->anal->bits / 8);
}
static bool reil_mem_inceq1(RzAnalEsil *esil) { return reil_mem_inceq_n(esil, 1); }
static bool reil_mem_inceq2(RzAnalEsil *esil) { return reil_mem_inceq_n(esil, 2); }
static bool reil_mem_inceq4(RzAnalEsil *esil) { return reil_mem_inceq_n(esil, 4); }
static bool reil_mem_inceq8(RzAnalEsil *esil) { return reil_mem_inceq_n(esil, 8); }

static int reil_mem_deceq_n(RzAnalEsil *esil, ut8 size) {
	int ret = 1;
	RzAnalReilArg *op1 = reil_pop_arg(esil);
	if (!op1) {
		return false;
	}

	rz_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op1);
	ret &= reil_mem_bineq_n(esil, REIL_SUB, size);

	free (op1);
	return ret;
}

static bool reil_mem_deceq(RzAnalEsil *esil) {
	return reil_mem_deceq_n(esil, esil->anal->bits / 8);
}
static bool reil_mem_deceq1(RzAnalEsil *esil) { return reil_mem_deceq_n(esil, 1); }
static bool reil_mem_deceq2(RzAnalEsil *esil) { return reil_mem_deceq_n(esil, 2); }
static bool reil_mem_deceq4(RzAnalEsil *esil) { return reil_mem_deceq_n(esil, 4); }
static bool reil_mem_deceq8(RzAnalEsil *esil) { return reil_mem_deceq_n(esil, 8); }

// Functions to resolve internal vars.
// performs (2 << op) - 1
void reil_generate_mask(RzAnalEsil *esil) {
	rz_anal_esil_pushnum(esil, 2);
	reil_lsl(esil);
	reil_dec(esil);
}

void reil_generate_borrow_flag(RzAnalEsil *esil, ut8 bit) {
	RzAnalReilArg *op1;

	rz_anal_esil_pushnum(esil, bit);
	rz_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	rz_anal_esil_pushnum(esil, 0x3f);
	reil_add(esil);
	rz_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	// Generate the mask. 2 << bits - 1
	reil_generate_mask(esil);
	op1 = reil_pop_arg(esil);
	// old & mask
	rz_anal_esil_push(esil, esil->Reil->old);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// cur & mask
	rz_anal_esil_push(esil, esil->Reil->cur);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// Check
	reil_larger(esil);

	free (op1);
}

void reil_generate_carry_flag(RzAnalEsil *esil, ut8 bit) {
	RzAnalReilArg *op1;

	rz_anal_esil_pushnum(esil, bit);
	rz_anal_esil_pushnum(esil, 0x3f);
	reil_and(esil);
	// Generate the mask. 2 << bits - 1
	reil_generate_mask(esil);
	op1 = reil_pop_arg(esil);
	// old & mask
	rz_anal_esil_push(esil, esil->Reil->old);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// cur & mask
	rz_anal_esil_push(esil, esil->Reil->cur);
	reil_push_arg(esil, op1);
	reil_and(esil);
	// Check
	reil_smaller(esil);

	free (op1);
}

void reil_generate_partity_flag(RzAnalEsil *esil) {
	// Generation of parity flag taken from openreil README example.
	RzAnalReilArg *op;
	rz_anal_esil_push(esil, esil->Reil->cur);
	rz_anal_esil_pushnum(esil, 0xff);
	reil_and(esil);
	op = reil_pop_arg(esil);
	if (!op) {
		return;
	}

	rz_anal_esil_pushnum(esil, 7);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	rz_anal_esil_pushnum(esil, 6);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	rz_anal_esil_pushnum(esil, 5);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	rz_anal_esil_pushnum(esil, 4);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	reil_xor(esil);
	rz_anal_esil_pushnum(esil, 3);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	rz_anal_esil_pushnum(esil, 2);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_xor(esil);
	rz_anal_esil_pushnum(esil, 1);
	reil_push_arg(esil, op);
	reil_lsr(esil);
	reil_push_arg(esil, op);
	reil_xor(esil);
	reil_xor(esil);
	reil_xor(esil);
	rz_anal_esil_pushnum(esil, 1);
	reil_and(esil);
	reil_not(esil);

	free (op);
}

void reil_generate_signature(RzAnalEsil *esil) {
	if (!esil->Reil->lastsz || esil->Reil->lastsz == 0) {
		rz_anal_esil_pushnum(esil, 0);
		return;
	}

	RzAnalReilArg *op;

	rz_anal_esil_pushnum(esil, esil->Reil->lastsz - 1);
	rz_anal_esil_pushnum(esil, 1);
	reil_lsl(esil);
	rz_anal_esil_push(esil, esil->Reil->cur);
	reil_and(esil);

	op = reil_pop_arg(esil);
	if (!op) {
		return;
	}

	rz_anal_esil_pushnum(esil, esil->Reil->lastsz - 1);
	reil_push_arg(esil, op);
	reil_lsr(esil);

	free (op);
}

void reil_generate_overflow_flag(RzAnalEsil *esil) {
	if (esil->Reil->lastsz < 2) {
		rz_anal_esil_pushnum (esil, 0);
	}

	reil_generate_borrow_flag(esil, esil->Reil->lastsz);
	reil_generate_carry_flag(esil, esil->Reil->lastsz - 2);
	reil_xor(esil);
}

void reil_flag_spew_inst(RzAnalEsil *esil, const char *flag) {
	ut8 bit;
	switch (flag[0]) {
		case 'z': // zero-flag
			rz_anal_esil_push(esil, esil->Reil->cur);
			break;
		case 'b':
			bit = (ut8)rz_num_get(NULL, &flag[1]);
			reil_generate_borrow_flag(esil, bit);
			break;
		case 'c':
			bit = (ut8)rz_num_get(NULL, &flag[1]);
			reil_generate_carry_flag(esil, bit);
			break;
		case 'o':
			reil_generate_overflow_flag(esil);
			break;
		case 'p':
			reil_generate_partity_flag(esil);
			break;
		case 'r':
			rz_anal_esil_pushnum(esil, esil->anal->bits / 8);
			break;
		case 's':
			reil_generate_signature(esil);
			break;
		default:
			return;
	}

	return;
}

/* Callback hook for command_hook */
static int setup_reil_ins(RzAnalEsil *esil, const char *op) {
	esil->Reil->addr++;      // Increment the address location.
	esil->Reil->seq_num = 0; // Reset the sequencing.
	return 0;
}

RZ_API int rz_anal_esil_to_reil_setup(RzAnalEsil *esil, RzAnal *anal, int romem,
		int stats) {
	if (!esil) {
		return false;
	}
	esil->verbose = 2;
	esil->anal = anal;
	esil->trap = 0;
	esil->trap_code = 0;

	/* Set up a callback for hook_command */
	esil->cb.hook_command = setup_reil_ins;

	esil->Reil = RZ_NEW0(RzAnalReil);
	if (!esil->Reil) {
		return false;
	}
	esil->Reil->reilNextTemp = 0;
	esil->Reil->addr = -1;
	esil->Reil->seq_num = 0;
	esil->Reil->skip = 0;

	// Store the pc
	const char *name = rz_reg_get_name (esil->anal->reg, rz_reg_get_name_idx ("PC"));
	strncpy (esil->Reil->pc, name, sizeof (esil->Reil->pc) - 1);

	rz_anal_esil_mem_ro(esil, romem);

#define	OT_UNK	RZ_ANAL_ESIL_OP_TYPE_UNKNOWN
#define	OT_CTR	RZ_ANAL_ESIL_OP_TYPE_CONTROL_FLOW
#define	OT_MATH	RZ_ANAL_ESIL_OP_TYPE_MATH
#define	OT_REGW	RZ_ANAL_ESIL_OP_TYPE_REG_WRITE
#define	OT_MEMW	RZ_ANAL_ESIL_OP_TYPE_MEM_WRITE
#define	OT_MEMR	RZ_ANAL_ESIL_OP_TYPE_MEM_READ

	rz_anal_esil_set_op(esil, "=", reil_eq, 0, 2, OT_REGW);
	rz_anal_esil_set_op(esil, ":=", reil_eq, 0, 2, OT_REGW);
	rz_anal_esil_set_op(esil, "+", reil_add, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "+=", reil_addeq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "-", reil_sub, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "-=", reil_subeq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "*", reil_mul, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "*=", reil_muleq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "/", reil_div, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "/=", reil_diveq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "^", reil_xor, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "^=", reil_xoreq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "|", reil_or, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "|=", reil_oreq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "&", reil_and, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "&=", reil_andeq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "<<", reil_lsl, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "<<=", reil_lsleq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, ">>", reil_lsr, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, ">>=", reil_lsreq, 0, 2, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "++=", reil_inceq, 0, 1, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "++", reil_inc, 1, 1, OT_MATH);
	rz_anal_esil_set_op(esil, "--=", reil_deceq, 0, 1, OT_MATH | OT_REGW);
	rz_anal_esil_set_op(esil, "--", reil_dec, 1, 1, OT_MATH);
	rz_anal_esil_set_op(esil, "!", reil_neg, 1, 1, OT_MATH);
	rz_anal_esil_set_op(esil, "!=", reil_negeq, 0, 1, OT_MATH);
	rz_anal_esil_set_op(esil, "==", reil_cmp, 0, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "<", reil_smaller, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, ">", reil_larger, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "<=", reil_smaller_equal, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, ">=", reil_larger_equal, 1, 2, OT_MATH);
	rz_anal_esil_set_op(esil, "[]", reil_peek, 1, 1, OT_MEMR);
	rz_anal_esil_set_op(esil, "=[]", reil_poke, 0, 2, OT_MEMW);
	rz_anal_esil_set_op(esil, "|=[]", reil_mem_oreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "^=[]", reil_mem_xoreq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "&=[]", reil_mem_andeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "+=[]", reil_mem_addeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "-=[]", reil_mem_subeq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "*=[]", reil_mem_muleq, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "++=[]", reil_mem_inceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "--=[]", reil_mem_deceq, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "=[1]", reil_poke1, 0, 2, OT_MEMW);
	rz_anal_esil_set_op(esil, "=[2]", reil_poke2, 0, 2, OT_MEMW);
	rz_anal_esil_set_op(esil, "=[4]", reil_poke4, 0, 2, OT_MEMW);
	rz_anal_esil_set_op(esil, "=[8]", reil_poke8, 0, 2, OT_MEMW);
	rz_anal_esil_set_op(esil, "[1]", reil_peek1, 1, 1, OT_MEMR);
	rz_anal_esil_set_op(esil, "[2]", reil_peek2, 1, 1, OT_MEMR);
	rz_anal_esil_set_op(esil, "[4]", reil_peek4, 1, 1, OT_MEMR);
	rz_anal_esil_set_op(esil, "[8]", reil_peek8, 1, 1, OT_MEMR);
	rz_anal_esil_set_op(esil, "|=[1]", reil_mem_oreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "|=[2]", reil_mem_oreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "|=[4]", reil_mem_oreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "|=[8]", reil_mem_oreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "^=[1]", reil_mem_xoreq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "^=[2]", reil_mem_xoreq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "^=[4]", reil_mem_xoreq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "^=[8]", reil_mem_xoreq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "&=[1]", reil_mem_andeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "&=[2]", reil_mem_andeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "&=[4]", reil_mem_andeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "&=[8]", reil_mem_andeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "+=[1]", reil_mem_addeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "+=[2]", reil_mem_addeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "+=[4]", reil_mem_addeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "+=[8]", reil_mem_addeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "-=[1]", reil_mem_subeq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "-=[2]", reil_mem_subeq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "-=[4]", reil_mem_subeq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "-=[8]", reil_mem_subeq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "*=[1]", reil_mem_muleq1, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "*=[2]", reil_mem_muleq2, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "*=[4]", reil_mem_muleq4, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "*=[8]", reil_mem_muleq8, 0, 2, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "++=[1]", reil_mem_inceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "++=[2]", reil_mem_inceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "++=[4]", reil_mem_inceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "++=[8]", reil_mem_inceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "--=[1]", reil_mem_deceq1, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "--=[2]", reil_mem_deceq2, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "--=[4]", reil_mem_deceq4, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "--=[8]", reil_mem_deceq8, 0, 1, OT_MATH | OT_MEMR | OT_MEMW);
	rz_anal_esil_set_op(esil, "?{", reil_if, 0, 1, OT_CTR);
	rz_anal_esil_set_op(esil, "}", reil_if_end, 0, 0, OT_CTR);

	return true;
}
