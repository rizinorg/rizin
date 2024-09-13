// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmp.h>
#include "../core_private.h"

static void rizin_compare_words(RzCore *core, ut64 of, ut64 od, int len, int ws) {
	rz_return_if_fail(core && (ws == 1 || ws == 2 || ws == 4 || ws == 8));
	int i;
	bool useColor = rz_config_get_i(core->config, "scr.color") != 0;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	ut64 v[2];
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	for (i = 0; i < len; i += ws) {
		for (size_t j = 0; j < 2; j++) {
			ut8 tmp[8] = { 0 };
			rz_io_nread_at(core->io, (j ? od : of) + i, tmp, ws);
			v[j] = rz_read_ble(tmp, big_endian, ws * 8);
		}
		char ch = (v[0] == v[1]) ? '=' : '!';
		const char *color = useColor ? ch == '=' ? "" : pal->graph_false : "";
		const char *colorEnd = useColor ? Color_RESET : "";

		if (useColor) {
			rz_cons_printf("%s0x%08" PFMT64x "  " Color_RESET, pal->offset, of + i);
		} else {
			rz_cons_printf("0x%08" PFMT64x "  ", of + i);
		}
		switch (ws) {
		case 1:
			rz_cons_printf("%s0x%02x %c 0x%02x%s\n", color,
				(ut32)(v[0] & 0xff), ch, (ut32)(v[1] & 0xff), colorEnd);
			break;
		case 2:
			rz_cons_printf("%s0x%04hx %c 0x%04hx%s\n", color,
				(ut16)v[0], ch, (ut16)v[1], colorEnd);
			break;
		case 4:
			rz_cons_printf("%s0x%08" PFMT32x " %c 0x%08" PFMT32x "%s\n", color,
				(ut32)v[0], ch, (ut32)v[1], colorEnd);
			break;
		case 8:
			rz_cons_printf("%s0x%016" PFMT64x " %c 0x%016" PFMT64x "%s\n",
				color, v[0], ch, v[1], colorEnd);
			break;
		}
	}
}

static bool rizin_compare_unified(RzCore *core, RzCompareData *cmp) {
	int i, min = 1, inc = 16;
	int headers = B_IS_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	if (headers) {
		B_UNSET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	for (i = 0; i < cmp->len; i += inc) {
		min = RZ_MIN(16, (cmp->len - i));
		if (!memcmp(cmp->data1 + i, cmp->data2 + i, min)) {
			rz_cons_printf("  ");
			rz_core_print_hexdiff(core, cmp->addr1 + i, cmp->data1 + i, cmp->addr1 + i, cmp->data1 + i, min, 0);
		} else {
			rz_cons_printf("- ");
			rz_core_print_hexdiff(core, cmp->addr1 + i, cmp->data1 + i, cmp->addr2 + i, cmp->data2 + i, min, 0);
			rz_cons_printf("+ ");
			rz_core_print_hexdiff(core, cmp->addr2 + i, cmp->data2 + i, cmp->addr1 + i, cmp->data1 + i, min, 0);
		}
	}
	if (headers) {
		B_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	return true;
}

static bool core_cmp_bits(RzCore *core, RzCompareData *cmp) {
	const bool scr_color = rz_config_get_i(core->config, "scr.color");
	int i;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	const char *color = scr_color ? pal->offset : "";
	const char *color_end = scr_color ? Color_RESET : "";
	if (rz_config_get_i(core->config, "hex.header")) {
		char *n = rz_str_newf("0x%08" PFMT64x, cmp->addr1);
		char *extra = rz_str_pad(' ', strlen(n) - 10);
		free(n);
		rz_cons_printf("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, extra, color_end);
		free(extra);
	}
	color = scr_color ? pal->graph_false : "";
	color_end = scr_color ? Color_RESET : "";

	rz_cons_printf("%s0x%08" PFMT64x "%s  ", color, cmp->addr1, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (cmp->data1[0] & 1 << i) ? 1 : 0;
		bool b1 = (cmp->data2[0] & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b0 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b0, color_end);
	}
	color = scr_color ? pal->graph_true : "";
	color_end = scr_color ? Color_RESET : "";
	rz_cons_printf("\n%s0x%08" PFMT64x "%s  ", color, cmp->addr2, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (cmp->data1[0] & 1 << i) ? 1 : 0;
		bool b1 = (cmp->data2[0] & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b1 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b1, color_end);
	}
	rz_cons_newline();

	return true;
}

// c
RZ_IPI RzCmdStatus rz_cmd_cmp_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	char *unescaped = rz_str_dup(argv[1]);
	int len = rz_str_unescape(unescaped);
	RzCompareData *cmp = rz_core_cmp_mem_data(core, core->offset, (ut8 *)unescaped, len);
	if (!cmp) {
		goto end;
	}
	int val = rz_core_cmp_print(core, cmp, state);
	ret = val != -1 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;

end:
	rz_core_cmp_free(cmp);
	free(unescaped);
	return ret;
}

// c1
RZ_IPI RzCmdStatus rz_cmd_cmp_bits_handler(RzCore *core, int argc, const char **argv) {
	RzCompareData *cmp = rz_core_cmp_mem_mem(core, core->offset, rz_num_math(core->num, argv[1]), 1);
	if (!cmp) {
		return RZ_CMD_STATUS_ERROR;
	}
	bool val = core_cmp_bits(core, cmp);
	rz_core_cmp_free(cmp);
	return val ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// ca
RZ_IPI RzCmdStatus rz_cmd_cmp_addr_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCompareData *cmp = rz_core_cmp_mem_mem(core, core->offset, rz_num_math(core->num, argv[1]), rz_num_math(core->num, argv[2]));
	if (!cmp) {
		return RZ_CMD_STATUS_ERROR;
	}
	int val = rz_core_cmp_print(core, cmp, state);
	rz_core_cmp_free(cmp);
	return val != -1 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cb
RZ_IPI RzCmdStatus rz_cmd_cmp_bytes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	ut64 sz = rz_num_math(core->num, argv[2]);
	if (sz > 8) {
		RZ_LOG_ERROR("Cannot compare more than 8 bytes. Use the c command instead.\n");
		return ret;
	}

	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	ut64 num = rz_num_math(core->num, argv[1]);
	ut8 tmp[8] = { 0 };
	rz_write_ble64(tmp, num, big_endian);
	RzCompareData *cmp = rz_core_cmp_mem_data(core, core->offset, big_endian && sz ? tmp + (8 - sz) : tmp, sz);
	if (!cmp) {
		goto end;
	}
	int val = rz_core_cmp_print(core, cmp, state);
	ret = val != -1 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;

end:
	rz_core_cmp_free(cmp);
	return ret;
}

// cc
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_block_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	bool col = core->cons->columns > 123;
	ut8 *b = malloc(core->blocksize);
	if (b) {
		memset(b, 0xff, core->blocksize);
		rz_io_nread_at(core->io, addr, b, core->blocksize);
		rz_core_print_hexdiff(core, core->offset, core->block, addr, b, core->blocksize, col);
	}
	free(b);
	return RZ_CMD_STATUS_OK;
}

// ccc
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_diff_lines_handler(RzCore *core, int argc, const char **argv) {
	ut32 oflags = core->print->flags;
	core->print->flags |= RZ_PRINT_FLAGS_DIFFOUT;
	ut64 addr = rz_num_math(core->num, argv[1]);
	bool col = core->cons->columns > 123;
	ut8 *b = malloc(core->blocksize);
	if (b) {
		memset(b, 0xff, core->blocksize);
		rz_io_nread_at(core->io, addr, b, core->blocksize);
		rz_core_print_hexdiff(core, core->offset, core->block, addr, b, core->blocksize, col);
	}
	free(b);
	core->print->flags = oflags;
	return RZ_CMD_STATUS_OK;
}

// ccd
RZ_IPI RzCmdStatus rz_cmd_cmp_disasm_handler(RzCore *core, int argc, const char **argv) {
	RzList *cmp = rz_core_cmp_disasm(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rz_core_cmp_disasm_print(core, cmp, false);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cf
RZ_IPI RzCmdStatus rz_cmd_cmp_file_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	FILE *fd = rz_sys_fopen(argv[1], "rb");
	if (!fd) {
		RZ_LOG_ERROR("Cannot open file: %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus stat = RZ_CMD_STATUS_ERROR;
	ut8 *buf = (ut8 *)malloc(core->blocksize);
	if (!buf) {
		goto return_goto;
	}
	if (fread(buf, 1, core->blocksize, fd) < 1) {
		RZ_LOG_ERROR("Cannot read file: %s\n", argv[1]);
		goto return_goto;
	}
	RzCompareData *cmp = rz_core_cmp_mem_data(core, core->offset, buf, core->blocksize);
	if (!cmp) {
		goto return_goto;
	}
	int val = rz_core_cmp_print(core, cmp, state);
	rz_core_cmp_free(cmp);
	stat = val != -1 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;

return_goto:
	free(buf);
	fclose(fd);
	return stat;
}

// cu
RZ_IPI RzCmdStatus rz_cmd_cmp_unified_handler(RzCore *core, int argc, const char **argv) {
	RzCompareData *cmp = rz_core_cmp_mem_mem(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rizin_compare_unified(core, cmp);
	rz_core_cmp_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cu1
RZ_IPI RzCmdStatus rz_cmd_cmp_unified1_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 1);
	return RZ_CMD_STATUS_OK;
}

// cu2
RZ_IPI RzCmdStatus rz_cmd_cmp_unified2_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 2);
	return RZ_CMD_STATUS_OK;
}

// cu4
RZ_IPI RzCmdStatus rz_cmd_cmp_unified4_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 4);
	return RZ_CMD_STATUS_OK;
}

// cu8
RZ_IPI RzCmdStatus rz_cmd_cmp_unified8_handler(RzCore *core, int argc, const char **argv) {
	rizin_compare_words(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize, 8);
	return RZ_CMD_STATUS_OK;
}

// cud
RZ_IPI RzCmdStatus rz_cmd_cmp_unified_disasm_handler(RzCore *core, int argc, const char **argv) {
	RzList *cmp = rz_core_cmp_disasm(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rz_core_cmp_disasm_print(core, cmp, true);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cw
RZ_IPI RzCmdStatus rz_cmd_cmp_add_memory_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_add(core, core->offset, atoi(argv[1]), argv[2]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cwl
RZ_IPI RzCmdStatus rz_cmd_cmp_list_compare_watchers_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	rz_core_cmpwatch_show(core, UT64_MAX, mode);
	return RZ_CMD_STATUS_OK;
}

// cwr
RZ_IPI RzCmdStatus rz_cmd_cmp_reset_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_revert(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cwu
RZ_IPI RzCmdStatus rz_cmd_cmp_update_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_update(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cwx
RZ_IPI RzCmdStatus rz_cmd_cmp_remove_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_del(core, core->offset) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cx
RZ_IPI RzCmdStatus rz_cmd_cmp_hexpair_string_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *input = rz_str_dup(argv[1]);
	rz_str_remove_char(input, ' ');
	unsigned char *buf;
	int ret = false;
	if (!(buf = (ut8 *)malloc(strlen(input) + 1))) {
		goto return_goto;
	}
	ret = rz_hex_bin2str(core->block, strlen(input) / 2, (char *)buf);
	for (int i = 0; i < ret * 2; i++) {
		if (input[i] == '.') {
			input[i] = buf[i];
		}
	}
	ret = rz_hex_str2bin(input, buf);
	if (ret < 1) {
		RZ_LOG_ERROR("Cannot parse hexpair\n");
		ret = false;
		goto return_goto;
	}
	RzCompareData *cmp = rz_core_cmp_mem_data(core, core->offset, buf, strlen(input) / 2);
	if (!cmp) {
		goto return_goto;
	}
	core->num->value = cmp->same ? 0 : 1;
	int val = rz_core_cmp_print(core, cmp, state);
	rz_core_cmp_free(cmp);
	ret = val != -1;

return_goto:
	free(input);
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cX
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_block_hexdiff_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	unsigned char *buf = malloc(core->blocksize);
	bool ret = false;
	if (!buf) {
		goto return_goto;
	}
	if (rz_io_nread_at(core->io, rz_num_math(core->num, argv[1]), buf, core->blocksize) == -1) {
		RZ_LOG_ERROR("Cannot read hexdump at %s\n", argv[1]);
		goto return_goto;
	}

	RzCompareData *cmp = rz_core_cmp_mem_data(core, core->offset, buf, core->blocksize);
	if (!cmp) {
		free(cmp);
		goto return_goto;
	}
	int val = rz_core_cmp_print(core, cmp, state);
	rz_core_cmp_free(cmp);
	ret = val != -1;

return_goto:
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
