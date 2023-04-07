// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <math.h> // required for signbit
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"
#include "rz_types.h"

static const char *help_msg_greater_sign[] = {
	"Usage:", "[cmd]>[file]", "redirects console from 'cmd' output to 'file'",
	"[cmd] > [file]", "", "redirect STDOUT of 'cmd' to 'file'",
	"[cmd] > $alias", "", "save the output of the command as an alias (see $?)",
	"[cmd] H> [file]", "", "redirect html output of 'cmd' to 'file'",
	"[cmd] 2> [file]", "", "redirect STDERR of 'cmd' to 'file'",
	"[cmd] 2> /dev/null", "", "omit the STDERR output of 'cmd'",
	NULL
};

/**
 * \brief Returns all the $ variable names in a NULL-terminated arr
 */
RZ_API const char **rz_core_help_vars_get(RzCore *core) {
	static const char *vars[] = {
		"$$", "$$$", "$?", "$B", "$b", "$c", "$Cn", "$D", "$DB", "$DD", "$Dn",
		"$e", "$f", "$F", "$Fb", "$FB", "$Fe", "$FE", "$Ff", "$Fi", "$FI", "$Fj",
		"$fl", "$FS", "$Fs", "$FSS", "$j", "$Ja", "$l", "$M", "$m", "$MM", "$O",
		"$o", "$p", "$P", "$r", "$s", "$S", "$SS", "$v", "$w", "$Xn", NULL
	};
	return vars;
}

RZ_API void rz_core_help_vars_print(RzCore *core) {
	int i = 0;
	const char **vars = rz_core_help_vars_get(core);
	const bool wideOffsets = rz_config_get_i(core->config, "scr.wideoff");
	while (vars[i]) {
		const char *pad = rz_str_pad(' ', 6 - strlen(vars[i]));
		if (wideOffsets) {
			rz_cons_printf("%s %s 0x%016" PFMT64x "\n", vars[i], pad, rz_num_math(core->num, vars[i]));
		} else {
			rz_cons_printf("%s %s 0x%08" PFMT64x "\n", vars[i], pad, rz_num_math(core->num, vars[i]));
		}
		i++;
	}
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
		;
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
	ut64 low = (ut32)rz_num_math(core->num, lowlimit);

	const char *uplimit = argv[2];
	ut64 high = (ut32)rz_num_math(core->num, uplimit);

	if (low >= high) {
		RZ_LOG_ERROR("core : Invalid arguments passed to %s : low-limit shouldn't be more then high-limit", argv[0]);
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
	char *buf = NULL;
	for (int i = 1; i < argc; i++) {
		const int buflen = (strlen(argv[i]) * 4) + 1;
		buf = (char *)realloc((void *)buf, buflen * sizeof(char));
		if (!buf) {
			RZ_LOG_ERROR("core: Out of memory!");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_base64_encode(buf, (const ut8 *)argv[i], strlen(argv[i]));
		rz_cons_println((const char *)buf);
	}
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_base64_decode_handler(RzCore *core, int argc, const char **argv) {
	ut8 *buf = NULL;
	for (int i = 1; i < argc; i++) {
		const int buflen = (strlen(argv[i]) * 4) + 1;
		buf = (ut8 *)realloc((void *)buf, buflen * sizeof(ut8));
		if (!buf) {
			RZ_LOG_ERROR("core: Out of memory!");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_base64_decode(buf, argv[i], -1);
		rz_cons_println((const char *)buf);
	}
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
	const char *mode = rz_str_trim_head_ro(argv[0]);
	RzList *list = rz_core_get_boundaries_prot(core, -1, mode, "search");
	if (!list) {
		RZ_LOG_ERROR("core: Failed to get boundaries protection values in RzList");
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
	for (int i = 1; i < argc; i++) {
		ut32 hash = (ut32)rz_str_djb2_hash(argv[i]);
		rz_cons_printf("0x%08x\n", hash);
	}
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
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
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
	rz_cons_printf("0x%08" PFMT64x "\n", n); // differs from ?v here 0x%08
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

RZ_IPI RzCmdStatus rz_set_core_num_value_handler(RzCore *core, int argc, const char **argv) {
	rz_num_math(core->num, argv[1]);
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

RZ_IPI RzCmdStatus rz_show_help_vars_handler(RzCore *core, int argc, const char **argv) {
	rz_core_help_vars_print(core);
	return RZ_CMD_STATUS_OK;
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

RZ_IPI RzCmdStatus rz_input_numerical_expr_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	char foo[1024];
	rz_cons_flush();
	// TODO: rz_cons_input()
	snprintf(foo, sizeof(foo) - 1, "%s: ", argv[1]);
	rz_line_set_prompt(foo);
	rz_cons_fgets(foo, sizeof(foo), 0, NULL);
	foo[sizeof(foo) - 1] = 0;
	rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, foo);
	core->num->value = rz_num_math(core->num, foo);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yesno_no_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_cons_yesno(0, "%s? (y/N)", argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yesno_yes_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_cons_yesno(0, "%s? (Y/n)", argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
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

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_positive2_handler(RzCore *core, int argc, const char **argv) {
	if (core->num->value) {
		core->num->value = rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}
