// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <math.h> // required for signbit
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"
#include "rz_types.h"

#define HIGHLIGHT_SZ 1024

static const char *help_msg_greater_sign[] = {
	"Usage:", "[cmd]>[file]", "redirects console from 'cmd' output to 'file'",
	"[cmd] > [file]", "", "redirect STDOUT of 'cmd' to 'file'",
	"[cmd] > $alias", "", "save the output of the command as an alias (see $?)",
	"[cmd] H> [file]", "", "redirect html output of 'cmd' to 'file'",
	"[cmd] 2> [file]", "", "redirect STDERR of 'cmd' to 'file'",
	"[cmd] 2> /dev/null", "", "omit the STDERR output of 'cmd'",
	NULL
};

struct rz_core_var {
	const char *name;
	const char *description;
};

struct rz_core_var core_vars[] = {
	{ "$$", "here (current virtual seek)" },
	{ "$$$", "current non-temporary virtual seek" },
	{ "$?", "last comparison value" },
	{ "$B", "base address (aligned lowest map address)" },
	{ "$b", "block size" },
	{ "$c", "get terminal width in character columns" },
	{ "$Cn", "get nth call of function" },
	{ "$D", "current debug map base address %v $D @ rsp" },
	{ "$DB", "same as dbg.baddr, progam base address" },
	{ "$DD", "current debug map size" },
	{ "$Dn", "get nth data reference in function" },
	{ "$e", "1 if end of block, else 0" },
	{ "$f", "jump fail address (e.g. jz 0x10 => next instruction)" },
	{ "$F", "Same as $FB" },
	{ "$Fb", "begin of basic block" },
	{ "$FB", "begin of function" },
	{ "$Fe", "end of basic block" },
	{ "$FE", "end of function" },
	{ "$Ff", "function false destination" },
	{ "$Fi", "basic block instructions" },
	{ "$FI", "function instructions" },
	{ "$Fj", "function jump destination" },
	{ "$fl", "flag length (size) at current address (fla; pD $l @ entry0)" },
	{ "$FS", "function size (linear length)" },
	{ "$Fs", "size of the current basic block" },
	{ "$FSS", "function size (sum bb sizes)" },
	{ "$j", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)" },
	{ "$Ja", "get nth jump of function" },
	{ "$l", "opcode length" },
	{ "$M", "map address (lowest map address)" },
	{ "$m", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)" },
	{ "$MM", "map size (lowest map address)" },
	{ "$O", "cursor here (current offset pointed by the cursor)" },
	{ "$o", "here (current disk io offset)" },
	{ "$p", "getpid()" },
	{ "$P", "pid of children (only in debug)" },
	{ "$r", "get console height (in rows, see $c for columns)" },
	{ "$s", "file size" },
	{ "$S", "section offset" },
	{ "$SS", "section size" },
	{ "$v", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)" },
	{ "$w", "get word size, 4 if asm.bits=32, 8 if 64, ..." },
	{ "$Xn", "get nth xref of function" },
};

struct rz_core_var help_core_vars[] = {
	{ "flag", "offset of flag" },
	{ "${ev}", "get value of eval <config variable <ev>" },
	{ "$alias", "alias commands (simple macros, see $?)" },
	{ "$e{flag}", "end of <flag> (flag->offset + flag->size)" },
	{ "$k{kv}", "get value of an sdb query value" },
	{ "$r{reg}", "get value of named register <reg>" },
	{ "$s{flag}", "get size of <flag>" },
};

/**
 * \brief Returns all the $ variable names in a NULL-terminated arr
 */
RZ_DEPRECATE RZ_API const char **rz_core_help_vars_get(RzCore *core) {
	static const char *vars[] = {
		"$$", "$$$", "$?", "$B", "$b", "$c", "$Cn", "$D", "$DB", "$DD", "$Dn",
		"$e", "$f", "$F", "$Fb", "$FB", "$Fe", "$FE", "$Ff", "$Fi", "$FI", "$Fj",
		"$fl", "$FS", "$Fs", "$FSS", "$j", "$Ja", "$l", "$M", "$m", "$MM", "$O",
		"$o", "$p", "$P", "$r", "$s", "$S", "$SS", "$v", "$w", "$Xn", NULL
	};
	return vars;
}

RZ_DEPRECATE RZ_API void rz_core_help_vars_print(RzCore *core) {
	rz_list_rizin_vars_handler(core, 0, NULL);
}

RZ_IPI RzCmdStatus rz_list_rizin_vars_handler(RzCore *core, int argc, const char **argv) {
	const bool wideOffsets = rz_config_get_i(core->config, "scr.wideoff");
	for (int i = 0; i < RZ_ARRAY_SIZE(core_vars); i++) {
		struct rz_core_var *var = &core_vars[i];
		if (argc > 1 && strcmp(argv[1], var->name)) {
			continue;
		}
		char *pad = rz_str_pad(' ', 6 - strlen(var->name));
		if (wideOffsets) {
			rz_cons_printf("%s %s 0x%016" PFMT64x "\n", var->name, pad, rz_num_math(core->num, var->name));
		} else {
			rz_cons_printf("%s %s 0x%08" PFMT64x "\n", var->name, pad, rz_num_math(core->num, var->name));
		}
		free(pad);
	}
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief If \p pj is NULL then standard output will be displayed
 * If it's non-NULL then it's treated as a borrowed PJ and used and
 * printing will be done in JSON format and not standard one.
 * Hence the the third parameter decides in which format data will be displayed.
 *
 * \param core RzCore.
 * \param input Input mathematical expression.
 * \param pj Borrowed PJ if calculated value is to be printed in JSON format.
 * \return true on success, false otherwise.
 **/
RZ_IPI bool rz_core_cmd_calculate_expr(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input, RZ_BORROW PJ *pj) {
	rz_return_val_if_fail(core && input, false);

	char unit[8];
	char number[128], out[128] = RZ_EMPTY;

	ut64 n = rz_num_math(core->num, input);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		core->num->dbz = 0;
		return false;
	}

	/* decimal, hexa, octal */
	ut32 s, a;
	s = n >> 16 << 12;
	a = n & 0x0fff;
	rz_num_units(unit, sizeof(unit), n);

	/* binary and floating point */
	double d;
	float f;
	rz_str_bits64(out, n);
	f = d = core->num->fvalue;
	/* adjust sign for nan floats, different libcs are confused */
	if (isnan(f) && signbit(f)) {
		f = -f;
	}
	if (isnan(d) && signbit(d)) {
		d = -d;
	}

	if (pj) {
		pj_o(pj);
		if (n >> 32) {
			pj_ks(pj, "int32", rz_strf(number, "%d", (st32)(n & UT32_MAX)));
			pj_ks(pj, "uint32", rz_strf(number, "%u", (ut32)n));
		} else {
			pj_ks(pj, "int64", rz_strf(number, "%" PFMT64d, (st64)n));
			pj_ks(pj, "uint64", rz_strf(number, "%" PFMT64u, (ut64)n));
		}
		pj_ks(pj, "hex", rz_strf(number, "0x%08" PFMT64x, n));
		pj_ks(pj, "octal", rz_strf(number, "0%" PFMT64o, n));
		pj_ks(pj, "unit", unit);
		pj_ks(pj, "segment", rz_strf(number, "%04x:%04x", s, a));
		pj_ks(pj, "fvalue", rz_strf(number, "%.1lf", core->num->fvalue));
		pj_ks(pj, "float", rz_strf(number, "%ff", f));
		pj_ks(pj, "double", rz_strf(number, "%lf", d));
		pj_ks(pj, "binary", rz_strf(number, "0b%s", out));
		/* ternary */
		rz_num_to_trits(out, n);
		pj_ks(pj, "trits", rz_strf(number, "0t%s", out));

		pj_end(pj);
	} else {
		if (n >> 32) {
			rz_cons_printf("int64   %" PFMT64d "\n", (st64)n);
			rz_cons_printf("uint64  %" PFMT64u "\n", (ut64)n);
		} else {
			rz_cons_printf("int32   %d\n", (st32)n);
			rz_cons_printf("uint32  %u\n", (ut32)n);
		}
		rz_cons_printf("hex     0x%" PFMT64x "\n", n);
		rz_cons_printf("octal   0%" PFMT64o "\n", n);
		rz_cons_printf("unit    %s\n", unit);
		rz_cons_printf("segment %04x:%04x\n", s, a);
		char *asnum = rz_num_as_string(NULL, n, false);
		if (asnum) {
			rz_cons_printf("string  \"%s\"\n", asnum);
			free(asnum);
		}
		rz_cons_printf("fvalue  %.1lf\n", core->num->fvalue);
		rz_cons_printf("float   %ff\n", f);
		rz_cons_printf("double  %lf\n", d);
		rz_cons_printf("binary  0b%s\n", out);
		/* ternary*/
		rz_num_to_trits(out, n);
		rz_cons_printf("trits   0t%s\n", out);
	}

	return true;
}

RZ_IPI RzCmdStatus rz_calculate_expr_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	bool res;
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		res = rz_core_cmd_calculate_expr(core, argv[1], state->d.pj);
	} else {
		res = rz_core_cmd_calculate_expr(core, argv[1], NULL);
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_set_active_tab_zero_handler(RzCore *core, int argc, const char **argv) {
	core->curtab = 0;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_active_tab_next_handler(RzCore *core, int argc, const char **argv) {
	if (core->curtab < 0) {
		core->curtab = 0;
	}
	core->curtab++;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_generate_random_number_handler(RzCore *core, int argc, const char **argv) {
	const char *lowlimit = argv[1];
	ut64 low = rz_num_math(core->num, lowlimit);

	const char *uplimit = argv[2];
	ut64 high = rz_num_math(core->num, uplimit);

	if (low >= high) {
		RZ_LOG_ERROR("core : Invalid arguments passed to %s : low-limit shouldn't be more then high-limit\n", argv[0]);
		return RZ_CMD_STATUS_ERROR;
	}

	core->num->value = (ut64)(low + rz_num_rand64(high - low));
	rz_cons_printf("0x%" PFMT64x "\n", core->num->value);

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_binary_handler(RzCore *core, int argc, const char **argv) {
	char out[128] = RZ_EMPTY;
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_num_to_bits(out, n);
	rz_cons_printf("%sb\n", out);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_base64_encode_handler(RzCore *core, int argc, const char **argv) {
	char *buf = rz_base64_encode_dyn((ut8 *)argv[1], strlen(argv[1]));
	if (!buf) {
		RZ_LOG_ERROR("Out of memory!\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_base64_decode_handler(RzCore *core, int argc, const char **argv) {
	ut8 *buf = rz_base64_decode_dyn(argv[1], -1);
	if (!buf) {
		RZ_LOG_ERROR("Base64 string is invalid\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println((char *)buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_check_between_handler(RzCore *core, int argc, const char **argv) {
	st64 f = rz_num_math(core->num, argv[1]);
	st64 m = rz_num_math(core->num, argv[2]);
	st64 l = rz_num_math(core->num, argv[3]);
	core->num->value = RZ_BETWEEN(f, m, l);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_boundaries_prot_handler(RzCore *core, int argc, const char **argv) {
	const char *mode = rz_str_trim_head_ro(argv[1]);
	RzList *list = rz_core_get_boundaries_prot(core, -1, mode, "search");
	if (!list) {
		RZ_LOG_ERROR("Failed to get boundaries protection values in RzList\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzIOMap *map;
	rz_list_foreach (list, iter, map) {
		rz_cons_printf("0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_djb2_hash_handler(RzCore *core, int argc, const char **argv) {
	ut32 hash = (ut32)rz_str_djb2_hash(argv[1]);
	rz_cons_printf("0x%08x\n", hash);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_bitstring_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_get(core->num, argv[1]);
	char out[128] = RZ_EMPTY;
	rz_str_bits(out, (const ut8 *)&n, sizeof(n) * 8, argv[2]);
	rz_cons_println(out);

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_expr_print_octal_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_cons_printf("0%" PFMT64o "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_num_to_units_handler(RzCore *core, int argc, const char **argv) {
	char unit[8];
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_num_units(unit, sizeof(unit), n);
	rz_cons_println(unit);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_last_eval_expr_handler(RzCore *core, int argc, const char **argv) {
	rz_num_math(core->num, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%" PFMT64x "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%08" PFMT64x "\n", n); // differs from %v here 0x%08
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i1_handler(RzCore *core, int argc, const char **argv) {
	st8 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st8)(n & UT8_MAX));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i2_handler(RzCore *core, int argc, const char **argv) {
	st16 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st16)(n & UT16_MAX));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i4_handler(RzCore *core, int argc, const char **argv) {
	st32 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st32)(n & UT32_MAX));
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_show_value_i8_handler(RzCore *core, int argc, const char **argv) {
	st64 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%" PFMT64d "\n", (st64)(n & UT64_MAX));
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_show_value_int_handler(RzCore *core, int argc, const char **argv) {
	st64 n = argc < 2 ? core->num->value : rz_num_math(core->num, argv[1]);
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%" PFMT64d "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_compare_and_set_core_num_value_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = strcmp(argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_positive_handler(RzCore *core, int argc, const char **argv) {
	st64 n = (st64)core->num->value;
	if (n > 0) {
		rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_negative_handler(RzCore *core, int argc, const char **argv) {
	st64 n = (st64)core->num->value;
	if (n < 0) {
		rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_zero_handler(RzCore *core, int argc, const char **argv) {
	if (!core->num->value) {
		core->num->value = rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_nonzero_handler(RzCore *core, int argc, const char **argv) {
	if (core->num->value) {
		core->num->value = rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdDescDetail *rz_cmd_math_help_vars_details_cb(RzCore *core, int argc, const char **argv) {
	RzCmdDescDetail *details = RZ_NEWS0(RzCmdDescDetail, 2);
	if (!details) {
		return NULL;
	}
	details[0].name = (const char *)rz_str_dup("Rizin variables");
	if (!details->name) {
		goto err;
	}
	RzCmdDescDetailEntry *entries = RZ_NEWS0(RzCmdDescDetailEntry, RZ_ARRAY_SIZE(core_vars) + RZ_ARRAY_SIZE(help_core_vars) + 1);
	details[0].entries = (const RzCmdDescDetailEntry *)entries;
	if (!entries) {
		goto err;
	}
	int i;
	for (i = 0; i < RZ_ARRAY_SIZE(core_vars); i++) {
		struct rz_core_var *var = &core_vars[i];
		entries[i].text = (char *)rz_str_dup(var->name);
		entries[i].arg_str = rz_str_dup("");
		entries[i].comment = rz_str_dup(var->description);
		if (!entries[i].text || !entries[i].arg_str || !entries[i].comment) {
			goto err;
		}
	}
	for (int j = 0; j < RZ_ARRAY_SIZE(help_core_vars); j++, i++) {
		struct rz_core_var *var = &help_core_vars[j];
		entries[i].text = (char *)rz_str_dup(var->name);
		entries[i].arg_str = rz_str_dup("");
		entries[i].comment = rz_str_dup(var->description);
		if (!entries[i].text || !entries[i].arg_str || !entries[i].comment) {
			goto err;
		}
	}
	details->entries = (const RzCmdDescDetailEntry *)entries;
	return details;
err:
	rz_cmd_desc_details_free(details);
	return NULL;
}

RZ_IPI RzCmdStatus rz_calculate_string_length_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	core->num->value = strlen(argv[1]);
	if (state->mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_cons_printf("%" PFMT64d "\n", core->num->value);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_calc_expr_show_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_cons_printf("%" PFMT64x "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_ascii_to_hex_handler(RzCore *core, int argc, const char **argv) {
	const char *str = argv[1];
	int n = strlen(str);
	for (int i = 0; i < n; i++) {
		rz_cons_printf("%02x", str[i]);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_numeric_expr_to_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	int bits = rz_num_to_bits(NULL, n) / 8;
	for (int i = 0; i < bits; i++) {
		rz_cons_printf("%02x", (ut8)((n >> (i * 8)) & 0xff));
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_hex_to_ascii_handler(RzCore *core, int argc, const char **argv) {
	ut8 *out = malloc(strlen(argv[1]) + 1);
	if (out) {
		int len = rz_hex_str2bin(argv[1], out);
		if (len >= 0) {
			out[len] = 0;
			rz_cons_println((const char *)out);
		} else {
			RZ_LOG_ERROR("core: Error parsing the hexpair string\n");
		}
		free(out);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_generate_sequence_handler(RzCore *core, int argc, const char **argv) {
	ut64 from, to, step;
	from = rz_num_math(core->num, argv[1]);
	to = rz_num_math(core->num, argv[2]);
	if (argc == 4) {
		step = rz_num_math(core->num, argv[3]);
		if (step == 0) {
			step = 1;
		}
	} else {
		step = 1;
	}

	for (; from <= to; from += step)
		rz_cons_printf("%" PFMT64d " ", from);
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_phys2virt_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc == 2 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 vaddr = rz_io_p2v(core->io, n);
	if (vaddr == UT64_MAX) {
		rz_cons_printf("no map at 0x%08" PFMT64x "\n", n);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", vaddr);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_virt2phys_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc == 2 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 paddr = rz_io_v2p(core->io, n);
	if (paddr == UT64_MAX) {
		rz_cons_printf("no map at 0x%08" PFMT64x "\n", n);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", paddr);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_yank_hud_file_handler(RzCore *core, int argc, const char **argv) {
	rz_core_yank_hud_file(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

static bool get_prompt(RzCore *core, char *prompt, char *output, size_t output_sz) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return false;
	}
	rz_cons_flush();
	rz_line_set_prompt(rz_cons_singleton()->line, prompt);
	rz_cons_fgets(output, output_sz, 0, NULL);
	output[output_sz - 1] = 0;
	return true;
}

/**
 * \brief Show a prompt "highlight" and highlights the string inserted by the user
 *
 * \param core Reference to RzCore
 */
RZ_IPI void rz_core_prompt_highlight(RzCore *core) {
	char highlight_str[HIGHLIGHT_SZ];

	if (!get_prompt(core, "highlight: ", highlight_str, sizeof(highlight_str))) {
		return;
	}

	rz_cons_highlight(highlight_str);
}

static RzCmdStatus prompt_handler(RzCore *core, int argc, const char **argv, bool echo) {
	char foo[1024];

	snprintf(foo, sizeof(foo) - 1, "%s: ", argv[1]);
	if (!get_prompt(core, foo, foo, sizeof(foo))) {
		return RZ_CMD_STATUS_ERROR;
	}

	rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, foo);
	core->num->value = rz_num_math(core->num, foo);
	rz_cons_set_raw(0);
	if (echo) {
		rz_cons_printf("%s\n", foo);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_prompt_handler(RzCore *core, int argc, const char **argv) {
	return prompt_handler(core, argc, argv, false);
}

RZ_IPI RzCmdStatus rz_input_prompt_echo_handler(RzCore *core, int argc, const char **argv) {
	return prompt_handler(core, argc, argv, true);
}

static RzCmdStatus yesno_handler(RzCore *core, int argc, const char **argv, const char *yn) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_cons_yesno(0, "%s? (%s) ", argv[1], yn);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yesno_no_handler(RzCore *core, int argc, const char **argv) {
	return yesno_handler(core, argc, argv, "y/N");
}

RZ_IPI RzCmdStatus rz_input_yesno_yes_handler(RzCore *core, int argc, const char **argv) {
	return yesno_handler(core, argc, argv, "Y/n");
}

RZ_IPI RzCmdStatus rz_input_any_key_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	rz_cons_any_key(NULL);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yank_hud_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_core_yank_hud_path(core, argv[1], 0) == true;
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_msg_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	rz_cons_message(argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_conditional_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = !rz_num_conditional(core->num, argv[1]);
	rz_cons_printf("%s\n", rz_str_bool(!core->num->value));
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_get_addr_references_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	char *rstr = core->print->hasrefs(core->print->user, addr, true);
	if (!rstr) {
		RZ_LOG_ERROR("core: Cannot get refs\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(rstr);
	free(rstr);
	return RZ_CMD_STATUS_OK;
}
