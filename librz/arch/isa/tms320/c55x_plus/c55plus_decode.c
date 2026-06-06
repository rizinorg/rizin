// SPDX-FileCopyrightText: 2013-2021 th0rpe <josediazfer@yahoo.es>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rz_types.h>
#include <rz_util.h>

#include "ins.h"
#include "decode.h"
#include "hashtable.h"
#include "decode_funcs.h"

extern char *ins_str[];
extern ut32 ins_buff_len;

static ut32 get_q_bits(ut32 val, char *ins, ut32 ins_len, int *err_code) {
	ut32 res = 0;

	if (!rz_str_ncasecmp(ins, "q_MMAP", 6)) {
		res = val & 1;
	} else if (!rz_str_ncasecmp(ins, "q_LOCK", 6)) {
		res = val & 1;
	} else if (!rz_str_ncasecmp(ins, "q_LINR", 6)) {
		res = (val >> 2) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_CIRC", 6)) {
		res = (val >> 3) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_PORT_READ", 11)) {
		res = (val >> 4) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_PORT_WRITE", 12)) {
		res = (val >> 5) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_XPORT_READ", 12)) {
		res = (val >> 6) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_XPORT_WRITE", 13)) {
		res = (val >> 7) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_SAT", 5)) {
		res = (val >> 8) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_XC0", 5)) {
		res = (val >> 9) & 1;
	} else if (!rz_str_ncasecmp(ins, "q_XC1", 5)) {
		res = (val >> 10) & 1;
	} else {
		/* INVALID CONDITION */
		fprintf(stderr, "Invalid token %s\n", ins);
		*err_code = -1;
	}
	return res;
}

/*
	a2 = 0x223;
	0x800 = valor que se crea en sub_40BAE0<) con and 0xfffff800
*/
static ut32 get_ins_bits(ut32 hash_code, ut32 ins_pos, char *ins,
	ut32 ins_len, ut32 magic_value, int *err_code) {
	ut32 res = 0;
	ut8 op_b;
	ut32 len, x, i;
	char *op_str, *aux;

	if (ins[0] == 'q') {
		return get_q_bits(magic_value, ins, ins_len, err_code);
	}

	op_str = ins_str[1 + hash_code * 4];
	// printf("OPSTR => %s %d\n", ins, ins_len);

	x = 0;
	for (i = 0; i < ins_len; i++) {
		aux = strchr(&op_str[x], ins[i]);
		if (!aux) {
			aux = strchr(op_str, ins[i]);
			if (!aux) {
				fprintf(stderr, "Invalid token %s\n", ins);
				*err_code = -1;
				return 0;
			}
		}

		len = (unsigned int)(aux - op_str);
		// printf("INS_POS: %d POS: %d\n",  ins_pos, len / 8);
		op_b = get_ins_part(ins_pos + len / 8, 1);
		// printf("OPP: %x\n", op_b);

		x = len + 1;
		res = (res * 2) | ((op_b >> ((1023 - len) % 8)) & 1);
		if (!op_str[x]) {
			x = 0;
		}
	}

	return res;
}

static bool check_arg(ut32 ins_bits, int *err_code) {
	bool res = false;

	if ((ins_bits <= 31) | (ins_bits >= 128 && ins_bits < 160)) {
		res = true;
	} else if (ins_bits >= 32 && ins_bits <= 252) {
		res = false;
	} else {
		fprintf(stderr, "Invalid arg: %u\n", ins_bits);
		*err_code = -1;
	}

	return res;
}

static char *decode_regis(char *reg_arg, st32 hash_code, ut32 ins_bits,
	ut32 *ret_ins_bits, int *err_code) {
	char reg_type;
	char *res;

	reg_type = *reg_arg;
	res = NULL;

	// printf("REG_TYPE %d %d\n", reg_type, ins_bits);

	switch (reg_type) {
	case 33:
		res = get_reg_name_1((ins_bits >> 1) |
			((ins_bits & 1) << 6));
		break;
	case 100:
		if (rz_str_ncasecmp(reg_arg, "d(ALLx", 6)) {
			fprintf(stderr, "invalid register! %s\n", reg_arg);
			*err_code = -1;
			return NULL;
		}
		res = (check_arg(ins_bits, err_code) != 0 && *err_code == 0) ? rz_str_dup("dbl(") : NULL;
		if (*err_code < 0) {
			return NULL;
		}
		break;
	case 41:
		if (rz_str_ncasecmp(reg_arg, ")ALLx", 5)) {
			fprintf(stderr, "invalid register! %s\n", reg_arg);
			*err_code = -1;
			return NULL;
		}
		res = (check_arg(ins_bits, err_code) && *err_code == 0) ? rz_str_dup(")") : NULL;
		if (*err_code < 0) {
			return NULL;
		}
		break;
	case 65:
		if (!rz_str_ncasecmp(reg_arg, "ACLH", 4)) {
			res = get_reg_name_1(ins_bits + 64);
		} else if (!rz_str_ncasecmp(reg_arg, "ACxP", 4)) {
			res = get_reg_name_1(ins_bits + 1);
		} else if (!rz_str_ncasecmp(reg_arg, "ACx", 3) ||
			!rz_str_ncasecmp(reg_arg, "ADR", 3) ||
			!rz_str_ncasecmp(reg_arg, "ALL", 3) /* 430ADC */
		) {
			res = get_reg_name_1(ins_bits);
		}
		if (hash_code == 0xDF || hash_code == 0xE0) {
			*ret_ins_bits = ins_bits;
		}
		break;
	case 68:
		res = get_reg_name_1(ins_bits + 32);
		break;
	case 77:
		if (!rz_str_ncasecmp(reg_arg, "MA", 2) || !rz_str_ncasecmp(reg_arg, "MR", 2)) {
			res = get_reg_name_1(ins_bits);
		} else {
			res = get_reg_name_2(ins_bits);
		}
		break;
	case 83:
		res = get_reg_name_1(ins_bits);
		break;
	case 82:
		if (!rz_str_ncasecmp(reg_arg, "RA", 2) || !rz_str_ncasecmp(reg_arg, "RL", 2)) {
			res = get_reg_name_1(ins_bits);
		} else if (!rz_str_ncasecmp(reg_arg, "RLP", 3) || !rz_str_ncasecmp(reg_arg, "RxP", 3)) {
			res = get_reg_name_1(ins_bits + 1);
		} else if (!rz_str_ncasecmp(reg_arg, "RX", 2)) {
			res = get_reg_name_1(ins_bits);
		} else {
			res = get_reg_name_2(ins_bits);
		}
		break;
	case 84:
		res = get_reg_name_1(ins_bits + 48);
		break;
	case 87:
		if (!rz_str_ncasecmp(reg_arg, "WD", 2)) {
			res = get_reg_name_2(ins_bits);
		} else if (!rz_str_ncasecmp(reg_arg, "WA", 2)) {
			res = get_reg_name_1(ins_bits);
		} else {
			res = NULL;
		}
		break;
	case 88:
		if (!rz_str_ncasecmp(reg_arg, "XR", 2)) {
			res = get_reg_name_3(ins_bits);
		} else if (!rz_str_ncasecmp(reg_arg, "XD", 2)) {
			res = get_reg_name_2(ins_bits + 32);
		} else {
			res = NULL;
		}
		break;
	default:
		res = NULL;
		break;
	}

	return res;
}

static char *decode_ins(st32 hash_code, ut32 ins_pos, ut32 ins_off, ut32 *ins_len_dec,
	ut32 *reg_len_dec, ut32 *ret_ins_bits, ut32 magic_value, ut8 two_ins, int *err_code) {
	ut32 ins_len;
	char *ins, *pos;
	char token_aux[80];
	ut32 i, len;
	char *reg = NULL;
	char *res_decode = NULL;
	char *aux = NULL;

	// get instruction length
	ins_len = get_ins_len(get_ins_part(ins_pos + ins_off, 1));
	// get pseudo instruction
	ins = ins_str[1 + 2 + hash_code * 4];
	if (!ins /*|| ins_str[4 * hash_code] == 0*/) {
		fprintf(stderr, "Invalid instruction hash %x\n", hash_code);
		*err_code = -1;
		return NULL;
	}
	*reg_len_dec = 0;
	if (hash_code == 0x19C) {
		ut32 tok_reg_len = 0;
		res_decode = get_token_decoded(hash_code, "MMMMxxxxmm", 10, NULL, ret_ins_bits,
			&tok_reg_len, magic_value, ins_pos + ins_off, ins_len, two_ins, err_code);
		if (*err_code < 0) {
			return NULL;
		}
		*reg_len_dec += tok_reg_len;
	}

	pos = ins;
	// instruction length
	*ins_len_dec = ins_len;

	while (*pos) {
		if (*pos == '`') {
			pos++;
			aux = strchr(pos, '`');
			if (!aux || pos == aux) {
				fprintf(stderr, "Invalid instruction %s\n", ins);
				free(res_decode);
				*err_code = -1;
				return NULL;
			}
			len = (ut32)(size_t)(aux - pos);
			if (len >= 80) {
				fprintf(stderr, "Invalid length token %d\n", len);
				free(res_decode);
				*err_code = -1;
				return NULL;
			}

			memcpy(token_aux, pos, len);
			token_aux[len] = '\0';
			pos = aux;

			reg = NULL;
			for (i = 0; i < len; i++) {
				if (token_aux[i] == ',') {
					len = (unsigned int)(size_t)(&token_aux[i] - token_aux);
					reg = &token_aux[i + 1];

					break;
				}
			}

			ut32 tok_reg_len = 0;
			aux = get_token_decoded(hash_code, token_aux, len, reg, ret_ins_bits,
				&tok_reg_len, magic_value, ins_pos + ins_off, ins_len, two_ins, err_code);
			if (*err_code < 0) {
				return NULL;
			}
			/* get_token_decoded resets its ret_reg_len output to 0 on every
			 * call, so a later token would otherwise clobber the extra-byte
			 * count reported by an earlier offset operand (e.g. the
			 * MMMMxxxxmm Smem token in COPY/MOV, which is followed by more
			 * register tokens). Accumulate instead. */
			*reg_len_dec += tok_reg_len;
			res_decode = rz_str_append_owned(res_decode, aux);
		} else {
			token_aux[0] = *pos;
			token_aux[1] = '\0';
			res_decode = rz_str_append(res_decode, token_aux);
		}
		pos++;
	}

	return res_decode;
}

static bool is_hash(st32 hash_code) {
	bool ret;

	switch (hash_code) {
	case 0xE8:
	case 0xE9:
	case 0xEA:
	case 0xEC:
	case 0x1A8:
	case 0x1DC:
	case 0x1E1:
	case 0x1E2:
	case 0x1E3:
	case 0x1E4:
		ret = 1;
		break;
	default:
		ret = 0;
	}

	return ret;
}

void set_magic_value(ut32 *magic_value, st32 hash_code, int *err_code) {
	switch (hash_code) {
	case 232:
		*magic_value |= 1;
		break;
	case 424:
		*magic_value |= 2;
		break;
	case 236:
		*magic_value |= 4;
		break;
	case 233:
		*magic_value |= 0x10;
		break;
	case 234:
		*magic_value |= 0x20;
		break;
	case 483:
		*magic_value |= 0x40;
		break;
	case 484:
		*magic_value |= 0x80;
		break;
	case 476:
		*magic_value |= 0x100;
		break;
	case 481:
		*magic_value |= 0x200;
		break;
	case 482:
		*magic_value |= 0x400;
		break;
	default:
		fprintf(stderr, "invalid hash code 0x%x for magic value 0x%x\n", hash_code, *magic_value);
		*err_code = -1;
	}
}

static char *do_decode(ut32 ins_off, ut32 ins_pos, ut32 two_ins, ut32 *next_ins_pos,
	st32 *ins_hash_code, int *err_code) {
	st32 hash_code, hash_aux;
	ut32 reg_len_dec, ins_len_dec, ret_ins_bits;
	char *ins_res = NULL, *ins_aux = NULL;
	ut32 magic_value = 0x800;

	*next_ins_pos = 0;

	reg_len_dec = 0;
	ret_ins_bits = 0;
	ins_len_dec = 0;

	hash_code = get_hash_code(ins_pos + ins_off);
	if (is_hash(hash_code)) {
		hash_aux = hash_code;
		ins_off++;
		set_magic_value(&magic_value, hash_code, err_code);
		if (*err_code < 0) {
			return NULL;
		}
		hash_code = get_hash_code(ins_pos + ins_off);
		*next_ins_pos = 1;
	} else {
		hash_aux = 0x223;
	}

	if (ins_hash_code != NULL) {
		*ins_hash_code = hash_code;
	}

	if (hash_aux == 0x1E1 || hash_aux == 0x1E2) {
		ins_aux = decode_ins(hash_aux, ins_pos, ins_off, &ins_len_dec, &reg_len_dec,
			&ret_ins_bits, magic_value, two_ins, err_code);
		if (*err_code < 0) {
			return NULL;
		}
		ins_aux = rz_str_append(ins_aux, " ");
	}

	if (hash_code == 0x223) {
		char hex_buf[8];
		ins_res = rz_str_append(ins_aux, ".byte 0x");
		ins_res = rz_str_append(ins_res, rz_strf(hex_buf, "%02x", get_ins_part(ins_pos, 1) & 0xff));
		*next_ins_pos = *next_ins_pos + 1;
	} else {
		free(ins_aux);
		ins_aux = decode_ins(hash_code, ins_pos, ins_off, &ins_len_dec,
			&reg_len_dec, &ret_ins_bits, magic_value, two_ins, err_code);
		if (*err_code < 0) {
			free(ins_aux);
			return NULL;
		}
		ins_res = rz_str_append_owned(ins_aux, ins_res);
		/* ins_len_dec is the base encoding length; reg_len_dec carries the
		 * extra bytes consumed by a k16/k24 offset operand (Smem modes
		 * *arN(#K16) / *arN(#K24) / *abs16 / *(#K24)). These must be added
		 * or the decoder under-reports the size and the following bytes are
		 * re-decoded as a spurious extra instruction. */
		*next_ins_pos += ins_len_dec + reg_len_dec;
	}

	return ins_res;
}

char *c55plus_decode(ut32 ins_pos, ut32 *next_ins_pos) {
	ut8 opcode, two_ins = 0;
	ut32 next_ins1_pos, next_ins2_pos;
	st32 hash_code;
	char *ins1, *ins2, *aux, *ins_res;
	int err_code;

	if (ins_pos >= ins_buff_len) {
		return NULL;
	}
	ins_res = NULL;
	err_code = 0;

	opcode = get_ins_part(ins_pos, 1);
	if ((opcode & 0xF0) == 0x30) {
		two_ins = opcode & 0x0F;
		if (two_ins < 4) {
			two_ins += 0xF;
		}
	} else {
		two_ins = 0;
	}

	// two instruction execution?
	if (two_ins) {
		ins1 = do_decode(1, ins_pos, two_ins, &next_ins1_pos, &hash_code, &err_code);
		if (err_code < 0) {
			free(ins1);
			return NULL;
		}
		ins2 = do_decode(next_ins1_pos + 1, ins_pos, two_ins, &next_ins2_pos, NULL, &err_code);
		if (err_code < 0) {
			free(ins1);
			free(ins2);
			return NULL;
		}
		*next_ins_pos = next_ins2_pos;

		if (hash_code == 0xF0 || hash_code == 0xF1) {
			aux = rz_str_append(ins2, " || ");
			ins_res = rz_str_append_owned(aux, ins1);
		} else {
			aux = rz_str_append(ins1, " || ");
			ins_res = rz_str_append_owned(aux, ins2);
		}
		*next_ins_pos = next_ins1_pos + next_ins2_pos + 1;
		if (*next_ins_pos != two_ins) {
			// ins_res = strcat_dup(ins_res, " P-tag problem", 1);
			err_code = -1;
			free(ins_res);
			return NULL;
		}
	} else {
		ins_res = do_decode(0, ins_pos, two_ins, &next_ins1_pos, &hash_code, &err_code);
		if (err_code < 0) {
			free(ins_res);
			return NULL;
		}
		*next_ins_pos = next_ins1_pos;
	}

	return ins_res;
}

static bool is_linear_circular(ut32 ins_bits) {
	ut8 op, op2, op3;
	op = (ins_bits >> 6) | 16 * (ins_bits & 3);
	op2 = (ins_bits >> 2) & 0xF;
	op3 = op2 & 0xF;
	return (op == 26 || op == 30 || (op3 > 7 && op3 != 15));
}

static char *get_token_decoded(st32 hash_code, char *ins_token, ut32 ins_token_len,
	char *reg_arg, ut32 *ret_ins_bits, ut32 *ret_reg_len, ut32 magic_value,
	ut32 ins_pos, ut32 ins_len, ut8 two_ins, int *err_code) {
	ut32 tok_op, ins_bits;
	char *res = NULL;
	char *aux = NULL;
	ut32 ret_len = 0, flag;

	*ret_ins_bits = 0;
	*ret_reg_len = 0;

	ins_bits = get_ins_bits(hash_code, ins_pos, ins_token, ins_token_len, magic_value, err_code);
	if (*err_code < 0) {
		return NULL;
	}
	tok_op = *ins_token - 0x23;

	switch (tok_op) {
	case 30:
	case 31:
	case 32:
	case 33:
	case 43:
	case 62:
	case 63:
	case 64:
	case 65:
		if (!reg_arg || *reg_arg == '\0') {
			res = rz_str_dup("<register>");
			goto ret_decode;
		}
		res = decode_regis(reg_arg, hash_code, ins_bits, ret_ins_bits, err_code);
		if (*err_code < 0) {
			return NULL;
		}
		break;
	case 35: res = ins_bits ? rz_str_dup(" || far()") : NULL; break;
	case 36: res = ins_bits ? rz_str_dup(" || local()") : NULL; break;
	case 37: res = get_opers(ins_bits); break;
	case 38:
		res = ins_bits ? "lo" : "hi";
		res = rz_str_dup(res);
		break;
	case 39: res = get_cmp_op(ins_bits); break;
	case 40:
	case 48:
		res = rz_str_newf("#0x%x", (ins_bits << (32 - ins_token_len) >> (32 - ins_token_len)));
		break;
	case 70:
	case 72:
	case 80:
		if (reg_arg) {
			if (*reg_arg == '!') {
				res = get_reg_pair(ins_bits);
				break;
			} else if (!rz_str_ncasecmp(reg_arg, "ST", 2)) {
				res = get_status_regs_and_bits(reg_arg, ins_bits);
				break;
			}
		}
		if (hash_code == 0xDF || hash_code == 0xE0) {
			*ret_ins_bits = ins_bits;
		}
		if (!reg_arg || *reg_arg != '-') {
			res = rz_str_newf("#0x%lx", (long unsigned int)ins_bits);
		} else {
			res = rz_str_newf("-#0x%lx", (long unsigned int)ins_bits);
		}
		if (!reg_arg || *reg_arg != 'm') {
			break;
		}

		res = rz_str_append(res, ")");
		res = rz_str_prepend(res, "*(");

		if (magic_value & 0xC0) {
			res = rz_str_append(res, ")");
			res = rz_str_prepend(res, "volatile(");
		} else if (magic_value & 0x30) {
			res = rz_str_append(res, ")");
			res = rz_str_prepend(res, "port(");
		}
		break;
	case 41:
	case 73:
		if (reg_arg && *reg_arg == 'L') {
			ins_bits = ins_bits << (32 - ins_token_len) >> (32 - ins_token_len);
		}
		if (reg_arg && *reg_arg == 'i') {
			res = rz_str_dup("");
		} else {
			res = rz_str_newf("#0x%06lx", (long unsigned int)ins_bits);
		}
		break;
	case 42:
		flag = 0;
		if (reg_arg && *reg_arg == '3') {
			flag = ins_bits & 1;
			ins_bits = ins_bits >> 1;
			reg_arg++;
		}
		if (magic_value & 1) {
			aux = get_sim_reg(reg_arg, ins_bits);
		} else if (reg_arg) {
			switch (*reg_arg) {
			case 'b':
			case 'd':
				reg_arg++;
				break;
			case '!':
				// strncpy(buff_aux, reg_arg + 1, 8);
				reg_arg += 10;
				// ins_bits2 = get_ins_bits(hash_code, ins_pos, buff_aux, 8);
				break;
			}
			aux = get_AR_regs_class2(ins_bits, &ret_len, ins_len + ins_pos, 1);
		}
		if (magic_value & 1) {
			aux = rz_str_append(aux, ")");
			aux = rz_str_prepend(aux, "mmap(");
		} else if ((magic_value & 4) && is_linear_circular(ins_bits)) {
			aux = rz_str_append(aux, ")");
			aux = rz_str_prepend(aux, "linear(");
		} else if ((magic_value & 8) && is_linear_circular(ins_bits)) {
			aux = rz_str_append(aux, ")");
			aux = rz_str_prepend(aux, "circular(");
		} else if (magic_value & 2) {
			aux = rz_str_append(aux, ")");
			aux = rz_str_prepend(aux, "lock(");
		} else if (reg_arg) {
			if (((magic_value & 0x10) && strchr(reg_arg, 'r')) ||
				((magic_value & 0x20) && strchr(reg_arg, 'w'))) {

				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "port(");
			} else if (
				((magic_value & 0x40) && strchr(reg_arg, 'r')) ||
				((magic_value & 0x80000000) && strchr(reg_arg, 'w'))) {

				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "volatile(");
			}
		}

		if (flag) {
			res = rz_str_prepend(aux, "t3 = ");
		} else {
			res = aux;
			*ret_reg_len = ret_len;
		}
		break;
	case 79:
		res = get_trans_reg(ins_bits);
		if (!res) {
			*err_code = -1;
		}
		break;
	case 49:
		if (reg_arg) {
			if (*reg_arg == '1') {
				res = get_tc2_tc1(ins_bits >> 1);
			} else if (*reg_arg == '2') {
				res = get_tc2_tc1(ins_bits & 1);
			}
		} else {
			res = get_tc2_tc1(ins_bits);
		}
		if (!res) {
			*err_code = -1;
			return NULL;
		}
		break;
	case 51:
		/* V / VV template field -- Carry or TC2 (see decode_funcs.c
		 * get_tc2_or_carry comment). With a 'VV,1' suffix the high
		 * bit of the 2-bit field is consumed; with 'VV,2' the low bit.
		 * With no suffix the whole field is consumed. ROL/ROR use the
		 * paired (VV,1 ; VV,2) form. */
		if (reg_arg) {
			if (*reg_arg == '1') {
				res = get_tc2_or_carry(ins_bits >> 1);
			} else if (*reg_arg == '2') {
				res = get_tc2_or_carry(ins_bits & 1);
			}
		} else {
			res = get_tc2_or_carry(ins_bits);
		}
		if (!res) {
			*err_code = -1;
			return NULL;
		}
		break;
	case 52:
		if (ins_bits == 0) {
			break;
		}
		if (reg_arg) {
			if (*reg_arg == 'H') {
				res = "hi(";
			} else if (*reg_arg == 'L') {
				res = "lo(";
			} else if (*reg_arg == 'd') {
				res = "dbl(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else {
				res = "<W>";
			}
		} else {
			res = "<W !flags>";
		}
		res = rz_str_dup(res);
		break;
	case 53:
	case 54:
	case 55:
		flag = 0;
		if (reg_arg && *reg_arg == '3') {
			flag = ins_bits & 1;
			ins_bits = ins_bits >> 1;
			reg_arg++;
		}
		aux = get_AR_regs_class1(ins_bits);
		tok_op = ins_bits & 0xF;
		if (magic_value & 4) {
			if (tok_op <= 7 || tok_op == 0xF) {
				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "linear(");
			}
		} else if (magic_value & 8) {
			if (tok_op <= 7 || tok_op == 0xF) {
				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "circular(");
			}
		} else if (magic_value & 2) {
			aux = rz_str_append(aux, ")");
			aux = rz_str_prepend(aux, "lock(");
		} else if (reg_arg) {
			if (
				((magic_value & 0x10) && *ins_token == 'X' && strchr(reg_arg, 'r')) ||
				((magic_value & 0x20) && *ins_token == 'Y' && strchr(reg_arg, 'w'))) {

				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "port(");
			} else if (
				((magic_value & 0x40) && *ins_token == 'X' && strchr(reg_arg, 'r')) ||
				((magic_value & 0x80000000) && *ins_token == 'Y' && strchr(reg_arg, 'w'))

			) {
				aux = rz_str_append(aux, ")");
				aux = rz_str_prepend(aux, "volatile(");
			}
		}
		res = flag ? rz_str_prepend(aux, "t3 = ") : aux;
		break;
	case 0:
	case 1:
		if (!ins_bits) {
			break;
		}
		if (!reg_arg) {
			res = "U";
		} else {
			if (*reg_arg == '(') {
				res = "uns(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else {
				res = "<$/#>";
			}
		}
		res = rz_str_dup(res);
		break;
	case 2:
		if (!ins_bits) {
			break;
		}
		if (!reg_arg) {
			res = "R";
		} else {
			if (*reg_arg == '(') {
				res = "rnd(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else {
				res = "<%>";
			}
		}
		res = rz_str_dup(res);
		break;
	case 12:
		if (!ins_bits) {
			break;
		}
		if (!reg_arg) {
			res = "F";
		} else {
			if (*reg_arg == '(') {
				res = "frct(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else if (*reg_arg == 'a') {
				res = "<%>";
			} else {
				res = "</>";
			}
		}
		res = rz_str_dup(res);
		break;
	case 29:
		if (!ins_bits) {
			break;
		}
		if (!reg_arg) {
			res = "saturate";
		} else {
			if (*reg_arg == '(') {
				res = "saturate(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else {
				res = "<saturate>";
			}
		}
		res = rz_str_dup(res);
		break;
	case 16:
		res = (ins_bits != 0) ? rz_str_dup("t3 = ") : NULL;
		break;
	case 17:
		if (!ins_bits) {
			break;
		}
		if (!reg_arg) {
			res = "40";
		} else {
			if (*reg_arg == '(') {
				res = "m40(";
			} else if (*reg_arg == ')') {
				res = ")";
			} else {
				res = "<4>";
			}
		}
		res = rz_str_dup(res);
		break;
	case 78:
		if (!rz_str_ncasecmp(ins_token, "q_SAT", 5)) {
			res = ins_bits ? "s" : NULL;
		} else if (!rz_str_ncasecmp(ins_token, "q_CIRC", 6)) {
			res = ins_bits ? ".cr" : NULL;
		} else if (!rz_str_ncasecmp(ins_token, "q_LINR", 6)) {
			res = ins_bits ? ".lr" : NULL;
		} else {
			fprintf(stderr, "Invalid instruction %s\n!", ins_token);
			*err_code = -1;
			return NULL;
		}
		if (res != NULL) {
			res = rz_str_dup(res);
		}
		break;
	}

ret_decode:
	return res;
}
