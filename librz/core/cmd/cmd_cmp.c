// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_cmp.h"

static int rizin_compare_words(RzCore *core, ut64 of, ut64 od, int len, int ws) {
	int i;
	bool useColor = rz_config_get_i(core->config, "scr.color") != 0;
	utAny v0, v1;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	for (i = 0; i < len; i += ws) {
		memset(&v0, 0, sizeof(v0));
		memset(&v1, 0, sizeof(v1));
		rz_io_nread_at(core->io, of + i, (ut8 *)&v0, ws);
		rz_io_nread_at(core->io, od + i, (ut8 *)&v1, ws);
		char ch = (v0.v64 == v1.v64) ? '=' : '!';
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
				(ut32)(v0.v8 & 0xff), ch, (ut32)(v1.v8 & 0xff), colorEnd);
			break;
		case 2:
			rz_cons_printf("%s0x%04hx %c 0x%04hx%s\n", color,
				v0.v16, ch, v1.v16, colorEnd);
			break;
		case 4:
			rz_cons_printf("%s0x%08" PFMT32x " %c 0x%08" PFMT32x "%s\n", color,
				v0.v32, ch, v1.v32, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v32);
			if (v0.v32 != v1.v32) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v32);
			}
			break;
		case 8:
			rz_cons_printf("%s0x%016" PFMT64x " %c 0x%016" PFMT64x "%s\n",
				color, v0.v64, ch, v1.v64, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v64);
			if (v0.v64 != v1.v64) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v64);
			}
			break;
		}
	}
	return 0;
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
			rz_print_hexdiff(core->print, cmp->addr1 + i, cmp->data1 + i, cmp->addr1 + i, cmp->data1 + i, min, 0);
		} else {
			rz_cons_printf("- ");
			rz_print_hexdiff(core->print, cmp->addr1 + i, cmp->data1 + i, cmp->addr2 + i, cmp->data2 + i, min, 0);
			rz_cons_printf("+ ");
			rz_print_hexdiff(core->print, cmp->addr2 + i, cmp->data2 + i, cmp->addr1 + i, cmp->data1 + i, min, 0);
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
		const char *extra = rz_str_pad(' ', strlen(n) - 10);
		free(n);
		rz_cons_printf("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, extra, color_end);
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
RZ_IPI RzCmdStatus rz_cmd_cmp_string_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	char *unescaped = strdup(argv[1]);
	int len = rz_str_unescape(unescaped);
	RzCompareData *cmp = rz_cmp_mem_data(core, core->offset, (ut8 *)unescaped, len);
	if (!cmp) {
		goto end;
	}
	int val = rz_cmp_print(core, cmp, mode);
	if (val != -1) {
		core->num->value = val;
		ret = RZ_CMD_STATUS_OK;
	}

end:
	free(cmp);
	free(unescaped);
	return ret;
}

// ca
RZ_IPI RzCmdStatus rz_cmd_cmp_bits_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	RzCompareData *cmp = rz_cmp_mem_mem(core, core->offset, rz_num_math(core->num, argv[1]), 1);
	if (!cmp) {
		return ret;
	}
	ret = core_cmp_bits(core, cmp) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	free(cmp);
	return ret;
}

// cb
RZ_IPI RzCmdStatus rz_cmd_cmp_bytes_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStatus ret = RZ_CMD_STATUS_ERROR;
	ut64 sz = rz_num_math(core->num, argv[2]);
	if (sz > 8) {
		rz_cons_printf("Cannot compare more than 8 bytes. Use the c command instead.\n");
		return ret;
	}

	ut64 num = rz_num_math(core->num, argv[1]);
	ut64 mask = -1;
	mask >>= 8 - sz;
	ut64 valid_num = num & mask;
	RzCompareData *cmp = rz_cmp_mem_data(core, core->offset, (ut8 *)&valid_num, sz);
	if (!cmp) {
		goto end;
	}
	if (cmp->same) {
		core->num->value = 0;
	} else {
		core->num->value = 1;
	}

	int val = rz_cmp_print(core, cmp, RZ_OUTPUT_MODE_STANDARD);
	if (val != -1) {
		ret = RZ_CMD_STATUS_OK;
	}

end:
	free(cmp);
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
		rz_print_hexdiff(core->print, core->offset, core->block, addr, b, core->blocksize, col);
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
		rz_print_hexdiff(core->print, core->offset, core->block, addr, b, core->blocksize, col);
	}
	free(b);
	core->print->flags = oflags;
	return RZ_CMD_STATUS_OK;
}

// ccd
RZ_IPI RzCmdStatus rz_cmd_cmp_disasm_handler(RzCore *core, int argc, const char **argv) {
	RzList *cmp = rz_cmp_disasm(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rz_cmp_disasm_print(core, cmp, false);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cf
RZ_IPI RzCmdStatus rz_cmd_cmp_file_handler(RzCore *core, int argc, const char **argv) {
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
	RzCompareData *cmp = rz_cmp_mem_data(core, core->offset, buf, core->blocksize);
	if (!cmp) {
		free(cmp);
		goto return_goto;
	}
	int val = rz_cmp_print(core, cmp, RZ_OUTPUT_MODE_STANDARD);
	free(cmp);
	if (val == -1) {
		goto return_goto;
	}
	core->num->value = val;
	stat = RZ_CMD_STATUS_OK;

return_goto:
	free(buf);
	fclose(fd);
	return stat;
}

// cu
RZ_IPI RzCmdStatus rz_cmd_cmp_unified_handler(RzCore *core, int argc, const char **argv) {
	RzCompareData *cmp = rz_cmp_mem_mem(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rizin_compare_unified(core, cmp);
	free(cmp);
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
	RzList *cmp = rz_cmp_disasm(core, core->offset, rz_num_math(core->num, argv[1]), core->blocksize);
	bool ret = rz_cmp_disasm_print(core, cmp, true);
	rz_list_free(cmp);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cw
RZ_IPI RzCmdStatus rz_cmd_cmp_add_memory_watcher_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_cmpwatch_add(core, core->offset, atoi(argv[0]), argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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

// cx
RZ_IPI RzCmdStatus rz_cmd_cmp_hexpair_string_handler(RzCore *core, int argc, const char **argv) {
	RzStrBuf *concat_argv = rz_strbuf_new(NULL);
	for (int i = 0; i < argc; i++) {
		rz_strbuf_append(concat_argv, argv[i]);
	}
	char *input = rz_strbuf_drain(concat_argv);
	rz_strbuf_free(concat_argv);

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
	RzCompareData *cmp = rz_cmp_mem_data(core, core->offset, buf, core->blocksize);
	if (!cmp) {
		free(cmp);
		goto return_goto;
	}
	int val = rz_cmp_print(core, cmp, RZ_OUTPUT_MODE_STANDARD);
	free(cmp);
	if (val == -1) {
		ret = false;
		goto return_goto;
	}
	core->num->value = val;
	ret = true;

return_goto:
	free(input);
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cX
RZ_IPI RzCmdStatus rz_cmd_cmp_hex_block_hexdiff_handler(RzCore *core, int argc, const char **argv) {
	unsigned char *buf = malloc(core->blocksize);
	bool ret = false;
	if (!buf) {
		goto return_goto;
	}
	if (rz_io_nread_at(core->io, rz_num_math(core->num, argv[1]), buf, core->blocksize) == -1) {
		RZ_LOG_ERROR("Cannot read hexdump at %s\n", argv[1]);
		goto return_goto;
	}

	RzCompareData *cmp = rz_cmp_mem_data(core, core->offset, buf, core->blocksize);
	if (!cmp) {
		free(cmp);
		goto return_goto;
	}
	int val = rz_cmp_print(core, cmp, RZ_OUTPUT_MODE_STANDARD);
	free(cmp);
	if (val == -1) {
		goto return_goto;
	}
	core->num->value = val;
	ret = true;

return_goto:
	free(buf);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
