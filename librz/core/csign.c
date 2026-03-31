// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_flirt.h>

typedef struct map_string_value_t {
	const char *name;
	ut32 value;
} MapStringValue;

const MapStringValue arch_map[29] = {
	{ "x86", RZ_FLIRT_SIG_ARCH_386 },
	{ "z80", RZ_FLIRT_SIG_ARCH_Z80 },
	// { "i860", RZ_FLIRT_SIG_ARCH_I860 },
	{ "8051", RZ_FLIRT_SIG_ARCH_8051 },
	// { "tms", RZ_FLIRT_SIG_ARCH_TMS },
	{ "6502", RZ_FLIRT_SIG_ARCH_6502 },
	// { "pdp", RZ_FLIRT_SIG_ARCH_PDP },
	{ "m68k", RZ_FLIRT_SIG_ARCH_68K },
	{ "java", RZ_FLIRT_SIG_ARCH_JAVA },
	{ "m680x", RZ_FLIRT_SIG_ARCH_6800 },
	// { "st7", RZ_FLIRT_SIG_ARCH_ST7 },
	// { "mc6812", RZ_FLIRT_SIG_ARCH_MC6812 },
	{ "mips", RZ_FLIRT_SIG_ARCH_MIPS },
	{ "arm", RZ_FLIRT_SIG_ARCH_ARM },
	// { "tmsc6", RZ_FLIRT_SIG_ARCH_TMSC6 },
	{ "ppc", RZ_FLIRT_SIG_ARCH_PPC },
	// { "80196", RZ_FLIRT_SIG_ARCH_80196 },
	// { "z8", RZ_FLIRT_SIG_ARCH_Z8 },
	{ "sh", RZ_FLIRT_SIG_ARCH_SH },
	// { "net", RZ_FLIRT_SIG_ARCH_NET },
	{ "avr", RZ_FLIRT_SIG_ARCH_AVR },
	{ "h8300", RZ_FLIRT_SIG_ARCH_H8 },
	{ "pic", RZ_FLIRT_SIG_ARCH_PIC },
	{ "sparc", RZ_FLIRT_SIG_ARCH_SPARC },
	// { "alpha", RZ_FLIRT_SIG_ARCH_ALPHA },
	{ "hppa", RZ_FLIRT_SIG_ARCH_HPPA },
	// { "h8500", RZ_FLIRT_SIG_ARCH_H8500 },
	{ "tricore", RZ_FLIRT_SIG_ARCH_TRICORE },
	// { "dsp56k", RZ_FLIRT_SIG_ARCH_DSP56K },
	// { "c166", RZ_FLIRT_SIG_ARCH_C166 },
	// { "st20", RZ_FLIRT_SIG_ARCH_ST20 },
	// { "ia64", RZ_FLIRT_SIG_ARCH_IA64 },
	// { "i960", RZ_FLIRT_SIG_ARCH_I960 },
	// { "f2mc", RZ_FLIRT_SIG_ARCH_F2MC },
	// { "tms320c54", RZ_FLIRT_SIG_ARCH_TMS320C54 },
	{ "tms320", RZ_FLIRT_SIG_ARCH_TMS320C55 },
	// { "trimedia", RZ_FLIRT_SIG_ARCH_TRIMEDIA },
	// { "m32r", RZ_FLIRT_SIG_ARCH_M32R },
	// { "nec_78k0", RZ_FLIRT_SIG_ARCH_NEC_78K0 },
	// { "nec_78k0s", RZ_FLIRT_SIG_ARCH_NEC_78K0S },
	// { "m740", RZ_FLIRT_SIG_ARCH_M740 },
	// { "m7700", RZ_FLIRT_SIG_ARCH_M7700 },
	// { "st9", RZ_FLIRT_SIG_ARCH_ST9 },
	// { "fr", RZ_FLIRT_SIG_ARCH_FR },
	// { "mc6816", RZ_FLIRT_SIG_ARCH_MC6816 },
	// { "m7900", RZ_FLIRT_SIG_ARCH_M7900 },
	// { "tms320c3", RZ_FLIRT_SIG_ARCH_TMS320C3 },
	// { "kr1878", RZ_FLIRT_SIG_ARCH_KR1878 },
	// { "ad218x", RZ_FLIRT_SIG_ARCH_AD218X },
	// { "oakdsp", RZ_FLIRT_SIG_ARCH_OAKDSP },
	// { "tlcs900", RZ_FLIRT_SIG_ARCH_TLCS900 },
	// { "c39", RZ_FLIRT_SIG_ARCH_C39 },
	{ "cr16", RZ_FLIRT_SIG_ARCH_CR16 },
	// { "mn102l00", RZ_FLIRT_SIG_ARCH_MN102L00 },
	// { "tms320c1x", RZ_FLIRT_SIG_ARCH_TMS320C1X },
	{ "v850", RZ_FLIRT_SIG_ARCH_NEC_V850X },
	// { "scr_adpt", RZ_FLIRT_SIG_ARCH_SCR_ADPT },
	{ "ebc", RZ_FLIRT_SIG_ARCH_EBC },
	{ "msp430", RZ_FLIRT_SIG_ARCH_MSP430 },
	// { "spu", RZ_FLIRT_SIG_ARCH_SPU },
	{ "dalvik", RZ_FLIRT_SIG_ARCH_DALVIK },
	// { "65c816", RZ_FLIRT_SIG_ARCH_65C816 },
	// { "ad2106x", RZ_FLIRT_SIG_ARCH_AD2106X },
	{ "arc", RZ_FLIRT_SIG_ARCH_ARC },
	// { "dsp96k", RZ_FLIRT_SIG_ARCH_DSP96K },
	// { "m16c", RZ_FLIRT_SIG_ARCH_M16C },
	{ "pic", RZ_FLIRT_SIG_ARCH_PIC16 },
	{ "riscv", RZ_FLIRT_SIG_ARCH_RISCV },
	// { "rl78", RZ_FLIRT_SIG_ARCH_RL78 },
	{ "sysz", RZ_FLIRT_SIG_ARCH_S390 },
	{ "spc700", RZ_FLIRT_SIG_ARCH_SPC700 },
	// { "tms320c28", RZ_FLIRT_SIG_ARCH_TMS320C28 },
	// { "unsp", RZ_FLIRT_SIG_ARCH_UNSP },
	{ "xtensa", RZ_FLIRT_SIG_ARCH_XTENSA },
};

const MapStringValue file_map[25] = {
	{ "dos:exe:old", RZ_FLIRT_SIG_FILE_DOS_EXE_OLD },
	{ "dos:com:old", RZ_FLIRT_SIG_FILE_DOS_COM_OLD },
	{ "bin", RZ_FLIRT_SIG_FILE_BIN },
	{ "dosdrv", RZ_FLIRT_SIG_FILE_DOSDRV },
	{ "ne", RZ_FLIRT_SIG_FILE_NE },
	{ "intelhex", RZ_FLIRT_SIG_FILE_INTELHEX },
	{ "moshex", RZ_FLIRT_SIG_FILE_MOSHEX },
	{ "lx", RZ_FLIRT_SIG_FILE_LX },
	{ "le", RZ_FLIRT_SIG_FILE_LE },
	{ "nlm", RZ_FLIRT_SIG_FILE_NLM },
	{ "coff", RZ_FLIRT_SIG_FILE_COFF },
	{ "pe", RZ_FLIRT_SIG_FILE_PE },
	{ "omf", RZ_FLIRT_SIG_FILE_OMF },
	{ "srec", RZ_FLIRT_SIG_FILE_SREC },
	{ "zip", RZ_FLIRT_SIG_FILE_ZIP },
	{ "omflib", RZ_FLIRT_SIG_FILE_OMFLIB },
	{ "ar", RZ_FLIRT_SIG_FILE_AR },
	{ "loader", RZ_FLIRT_SIG_FILE_LOADER },
	{ "elf", RZ_FLIRT_SIG_FILE_ELF },
	{ "w32run", RZ_FLIRT_SIG_FILE_W32RUN },
	{ "aout", RZ_FLIRT_SIG_FILE_AOUT },
	{ "pilot", RZ_FLIRT_SIG_FILE_PILOT },
	{ "dos:exe", RZ_FLIRT_SIG_FILE_DOS_EXE },
	{ "dos:com", RZ_FLIRT_SIG_FILE_DOS_COM },
	{ "aixar", RZ_FLIRT_SIG_FILE_AIXAR },
};

const MapStringValue os_map[6] = {
	{ "msdos", RZ_FLIRT_SIG_OS_MSDOS },
	{ "win", RZ_FLIRT_SIG_OS_WIN },
	{ "os2", RZ_FLIRT_SIG_OS_OS2 },
	{ "netware", RZ_FLIRT_SIG_OS_NETWARE },
	{ "unix", RZ_FLIRT_SIG_OS_UNIX },
	{ "other", RZ_FLIRT_SIG_OS_OTHER },
};

const MapStringValue app_map[10] = {
	{ "console", RZ_FLIRT_SIG_APP_CONSOLE },
	{ "graphics", RZ_FLIRT_SIG_APP_GRAPHICS },
	{ "exe", RZ_FLIRT_SIG_APP_EXE },
	{ "dll", RZ_FLIRT_SIG_APP_DLL },
	{ "drv", RZ_FLIRT_SIG_APP_DRV },
	{ "thread:single", RZ_FLIRT_SIG_APP_SINGLE_THREADED },
	{ "thread:multi", RZ_FLIRT_SIG_APP_MULTI_THREADED },
	{ "16bit", RZ_FLIRT_SIG_APP_16_BIT },
	{ "32bit", RZ_FLIRT_SIG_APP_32_BIT },
	{ "64bit", RZ_FLIRT_SIG_APP_64_BIT },
};

/**
 * \brief Returns the FLIRT arch id from a given arch name
 * Returns RZ_FLIRT_SIG_ARCH_ANY if name is not found.
 *
 * \param  arch The arch to convert to id
 * \return      The FLIRT arch id.
 */
RZ_API ut8 rz_core_flirt_arch_from_name(RZ_NONNULL const char *arch) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(arch), RZ_FLIRT_SIG_ARCH_ANY);

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(arch_map); ++i) {
		if (strcmp(arch, arch_map[i].name)) {
			continue;
		}
		return arch_map[i].value;
	}

	return RZ_FLIRT_SIG_ARCH_ANY;
}

/**
 * \brief Returns the FLIRT arch name (string format) from a given arch id
 * Returns "unknown" if name is not found.
 *
 * \param  arch The arch to convert to string
 * \return      The FLIRT arch name.
 */
RZ_API const char *rz_core_flirt_arch_from_id(ut8 arch) {
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(arch_map); ++i) {
		if (arch != arch_map[i].value) {
			continue;
		}
		return arch_map[i].name;
	}

	return "unknown";
}

/**
 * \brief Returns the FLIRT file flags from a given list (comma spaced) of file types
 * Returns RZ_FLIRT_SIG_FILE_ALL if file_list is "any" and 0 if no valid value is not found.
 *
 * \param  file_list The file list to convert to flags
 * \return           The FLIRT file flags.
 */
RZ_API ut32 rz_core_flirt_file_from_option_list(RZ_NONNULL const char *file_list) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(file_list), 0);
	ut32 flags = 0;
	const char *tk;
	RzListIter *it;
	RzList *tokens = NULL;

	if (strstr(file_list, "all")) {
		return RZ_FLIRT_SIG_FILE_ALL;
	}

	tokens = rz_str_split_duplist(file_list, ",", true);
	if (!tokens) {
		RZ_LOG_ERROR("cannot allocate token list\n");
		return 0;
	}

	rz_list_foreach (tokens, it, tk) {
		for (ut32 i = 0; i < RZ_ARRAY_SIZE(file_map); ++i) {
			if (strcmp(tk, file_map[i].name)) {
				continue;
			}
			flags |= file_map[i].value;
		}
	}
	rz_list_free(tokens);
	return flags;
}

/**
 * \brief Returns the FLIRT file flags from a given list (comma spaced) of file types
 * Returns RZ_FLIRT_SIG_OS_ALL if file_list is "any" and 0 if no valid value is not found.
 *
 * \param  os_list The os list to convert to flags
 * \return         The FLIRT os flags.
 */
RZ_API ut16 rz_core_flirt_os_from_option_list(RZ_NONNULL const char *os_list) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(os_list), 0);
	ut32 flags = 0;
	const char *tk;
	RzListIter *it;
	RzList *tokens = NULL;

	if (strstr(os_list, "all")) {
		return RZ_FLIRT_SIG_OS_ALL;
	}

	tokens = rz_str_split_duplist(os_list, ",", true);
	if (!tokens) {
		RZ_LOG_ERROR("cannot allocate token list\n");
		return 0;
	}

	rz_list_foreach (tokens, it, tk) {
		for (ut32 i = 0; i < RZ_ARRAY_SIZE(os_map); ++i) {
			if (strcmp(tk, os_map[i].name)) {
				continue;
			}
			flags |= os_map[i].value;
		}
	}
	rz_list_free(tokens);
	return flags;
}

/**
 * \brief Returns the FLIRT file flags from a given list (comma spaced) of file types
 * Returns RZ_FLIRT_SIG_APP_ALL if file_list is "any" and 0 if no valid value is not found.
 *
 * \param  app_list The app list to convert to flags
 * \return          The FLIRT app flags.
 */
RZ_API ut16 rz_core_flirt_app_from_option_list(RZ_NONNULL const char *app_list) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(app_list), 0);
	ut32 flags = 0;
	const char *tk;
	RzListIter *it;
	RzList *tokens = NULL;

	if (strstr(app_list, "all")) {
		return RZ_FLIRT_SIG_APP_ALL;
	}

	tokens = rz_str_split_duplist(app_list, ",", true);
	if (!tokens) {
		RZ_LOG_ERROR("cannot allocate token list\n");
		return 0;
	}

	rz_list_foreach (tokens, it, tk) {
		for (ut32 i = 0; i < RZ_ARRAY_SIZE(app_map); ++i) {
			if (strcmp(tk, app_map[i].name)) {
				continue;
			}
			flags |= app_map[i].value;
		}
	}
	rz_list_free(tokens);
	return flags;
}

static void flirt_print_module(const RzFlirtModule *module) {
	RzListIter *pub_func_it, *ref_func_it, *tail_bytes_it;
	RzFlirtFunction *func, *ref_func;
	RzFlirtTailByte *tail_byte;

	rz_cons_printf("%02X %04X %04X ", module->crc_length, module->crc16, module->length);
	rz_list_foreach (module->public_functions, pub_func_it, func) {
		if (func->is_local || func->is_collision) {
			rz_cons_printf("(");
			if (func->is_local) {
				rz_cons_printf("l");
			}
			if (func->is_collision) {
				rz_cons_printf("!");
			}
			rz_cons_printf(")");
		}
		rz_cons_printf("%04X:%s", func->offset, func->name);
		if (rz_list_has_next(pub_func_it)) {
			rz_cons_printf(" ");
		}
	}
	if (module->tail_bytes) {
		rz_list_foreach (module->tail_bytes, tail_bytes_it, tail_byte) {
			rz_cons_printf(" (%04X: %02X)", tail_byte->offset, tail_byte->value);
		}
	}
	if (module->referenced_functions) {
		rz_cons_printf(" (REF ");
		rz_list_foreach (module->referenced_functions, ref_func_it, ref_func) {
			rz_cons_printf("%04X: %s", ref_func->offset, ref_func->name);
			if (rz_list_has_next(ref_func_it)) {
				rz_cons_printf(" ");
			}
		}
		rz_cons_printf(")");
	}
	rz_cons_printf("\n");
}

static void flirt_print_node_pattern(const RzFlirtNode *node) {
	for (ut32 i = 0; i < node->length; i++) {
		if (node->pattern_mask[i]) {
			rz_cons_printf("%02X", node->pattern_bytes[i]);
		} else {
			rz_cons_printf("..");
		}
	}
	rz_cons_printf(":\n");
}

static void flirt_print_indentation(int indent) {
	char *pad = rz_str_pad(' ', indent);
	rz_cons_printf("%s", pad);
	free(pad);
}

static void flirt_print_node(const RzFlirtNode *node, int indent) {
	/* Prints a signature node. The output is similar to dumpsig */
	RzListIter *child_it, *module_it;
	RzFlirtNode *child;
	RzFlirtModule *module;

	if (node->pattern_bytes) { // avoid printing the root node
		flirt_print_indentation(indent);
		flirt_print_node_pattern(node);
	}
	if (node->child_list) {
		rz_list_foreach (node->child_list, child_it, child) {
			flirt_print_node(child, indent + 1);
		}
	} else if (node->module_list) {
		ut32 i = 0;
		rz_list_foreach (node->module_list, module_it, module) {
			flirt_print_indentation(indent + 1);
			rz_cons_printf("%d. ", i);
			flirt_print_module(module);
			i++;
		}
	}
}

/**
 * \brief Dumps the contents of a FLIRT file
 *
 * \param flirt_file FLIRT file name to dump
 */
RZ_API bool rz_core_flirt_dump_file(RZ_NONNULL const char *flirt_file) {
	rz_return_val_if_fail(RZ_STR_ISNOTEMPTY(flirt_file), false);

	const char *extension = rz_str_lchr(flirt_file, '.');
	if (RZ_STR_ISEMPTY(extension) || (strcmp(extension, ".sig") != 0 && strcmp(extension, ".pat") != 0)) {
		RZ_LOG_ERROR("FLIRT: unknown extension '%s'\n", extension);
		return false;
	}

	RzFlirtInfo info = { 0 };
	RzBuffer *buffer = NULL;
	RzFlirtNode *node = NULL;

	if (!(buffer = rz_buf_new_file(flirt_file, O_RDONLY, 0))) {
		RZ_LOG_ERROR("FLIRT: cannot open %s (read mode)\n", flirt_file);
		return false;
	} else if (!strcmp(extension, ".pat")) {
		node = rz_sign_flirt_parse_string_pattern_from_buffer(buffer, RZ_FLIRT_NODE_OPTIMIZE_NORMAL, &info);
	} else {
		node = rz_sign_flirt_parse_compressed_pattern_from_buffer(buffer, RZ_FLIRT_SIG_ARCH_ANY, &info);
	}
	rz_buf_free(buffer);

	if (!node) {
		RZ_LOG_ERROR("FLIRT: we encountered an error while parsing the file. Sorry.\n");
		return false;
	}

	switch (info.type) {
	case RZ_FLIRT_FILE_TYPE_SIG:
		rz_cons_printf("SIG format\n");
		rz_cons_printf("Signature:    %s, %u modules\n", info.u.sig.name ? info.u.sig.name : "", info.u.sig.n_modules);
		rz_cons_printf("Version:      %u\n", info.u.sig.version);
		rz_cons_printf("Architecture: %u (%s)\n", info.u.sig.architecture, rz_core_flirt_arch_from_id(info.u.sig.architecture));
		break;
	case RZ_FLIRT_FILE_TYPE_PAT:
		rz_cons_printf("PAT format\n");
		rz_cons_printf("Signature:    %u modules\n", info.u.pat.n_modules);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	flirt_print_node(node, -1);
	rz_sign_flirt_node_free(node);
	rz_sign_flirt_info_fini(&info);
	return true;
}

/**
 * \brief      Generates a new FLIRT file from a given RzCore structure.
 *
 * \param  core           RzCore to use.
 * \param  output_file    Output file.
 * \param  written_nodes  When not NULL, returns the number of nodes written in the file.
 *
 * \return true on success, false on failure
 */
RZ_API bool rz_core_flirt_create_file(RZ_NONNULL RzCore *core, RZ_NONNULL const char *output_file, RZ_NULLABLE ut32 *written_nodes) {
	rz_return_val_if_fail(core && RZ_STR_ISNOTEMPTY(output_file), false);

	const char *extension = rz_str_lchr(output_file, '.');
	if (RZ_STR_ISEMPTY(extension) || (strcmp(extension, ".sig") != 0 && strcmp(extension, ".pat") != 0)) {
		RZ_LOG_ERROR("missing or unknown extension '%s'. supported only .pat and .sig\n", extension);
		return false;
	}

	ut64 optimize = rz_config_get_i(core->config, "flirt.node.optimize");
	if (optimize > RZ_FLIRT_NODE_OPTIMIZE_MAX) {
		RZ_LOG_ERROR("config 'flirt.node.optimize' is set to an invalid value.\n");
		return false;
	}

	bool ignore_unknown = rz_config_get_b(core->config, "flirt.ignore.unknown");
	RzFlirtNode *node = rz_sign_flirt_node_new(core->analysis, optimize, ignore_unknown);
	if (!node) {
		return false;
	}

	RzBuffer *buffer = rz_buf_new_file(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (!buffer) {
		RZ_LOG_ERROR("cannot create file '%s'\n", output_file);
		return false;
	}

	bool result = false;
	if (!strcmp(extension, ".pat")) {
		result = rz_sign_flirt_write_string_pattern_to_buffer(node, buffer);
	} else if (!strcmp(extension, ".sig")) {
		ut64 hdr_version = rz_config_get_i(core->config, "flirt.sig.version");
		const char *hdr_arch = rz_config_get(core->config, "asm.arch");
		const char *hdr_file = rz_config_get(core->config, "flirt.sig.file");
		const char *hdr_os = rz_config_get(core->config, "flirt.sig.os");
		const char *hdr_lib = rz_config_get(core->config, "flirt.sig.library");
		bool deflate = rz_config_get_b(core->config, "flirt.sig.deflate");
		ut8 architecture = rz_core_flirt_arch_from_name(hdr_arch);

		if (RZ_STR_ISEMPTY(hdr_lib)) {
			RZ_LOG_WARN("config 'flirt.sig.library' is empty. using default value '" RZ_FLIRT_LIBRARY_NAME_DFL "'\n");
			hdr_lib = RZ_FLIRT_LIBRARY_NAME_DFL;
		} else if (architecture >= RZ_FLIRT_SIG_ARCH_ANY) {
			RZ_LOG_ERROR("FLIRT: architecture '%s' is not supported as .sig file, we suggest to use the .pat format.\n", hdr_arch);
			RZ_LOG_ERROR("FLIRT: we suggest to open an issue to discuss with the rizin team about it.\n");
			result = false;
			goto fail;
		}

		RzFlirtCompressedOptions options = {
			.version = hdr_version,
			.arch = rz_core_flirt_arch_from_name(hdr_arch),
			.file = rz_core_flirt_file_from_option_list(hdr_file),
			.os = rz_core_flirt_os_from_option_list(hdr_os),
			.app = RZ_FLIRT_SIG_APP_ALL,
			.deflate = deflate,
			.libname = hdr_lib,
		};
		result = rz_sign_flirt_write_compressed_pattern_to_buffer(node, buffer, &options);
	}

	if (written_nodes) {
		*written_nodes = rz_sign_flirt_node_count_nodes(node);
	}

fail:
	rz_buf_free(buffer);
	rz_sign_flirt_node_free(node);
	return result;
}

/**
 * \brief converts a FLIRT file to the other format.
 *
 * \param  input_file  Input file
 * \param  output_file Output file
 * \param  optimize    Optimization value (expects an RZ_FLIRT_NODE_OPTIMIZE_* value)
 *
 * \return true on success, false on failure
 */
RZ_API bool rz_core_flirt_convert_file(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input_file, RZ_NONNULL const char *output_file) {
	rz_return_val_if_fail(core && RZ_STR_ISNOTEMPTY(input_file) && RZ_STR_ISNOTEMPTY(output_file), false);

	const char *in_extension = rz_str_lchr(input_file, '.');
	if (RZ_STR_ISEMPTY(in_extension) || (strcmp(in_extension, ".sig") != 0 && strcmp(in_extension, ".pat") != 0)) {
		RZ_LOG_ERROR("FLIRT: unknown input extension '%s'\n", in_extension);
		return false;
	}

	const char *out_extension = rz_str_lchr(output_file, '.');
	if (RZ_STR_ISEMPTY(out_extension) || (strcmp(out_extension, ".sig") != 0 && strcmp(out_extension, ".pat") != 0)) {
		RZ_LOG_ERROR("FLIRT: unknown output extension '%s'\n", out_extension);
		return false;
	}

	if (!strcmp(out_extension, in_extension)) {
		RZ_LOG_ERROR("FLIRT: cannot convert '%s' to '%s' because the format is the same\n", input_file, output_file);
		return false;
	}

	RzBuffer *buffer = NULL;
	RzFlirtNode *node = NULL;

	ut64 optimize = rz_config_get_i(core->config, "flirt.node.optimize");
	if (optimize > RZ_FLIRT_NODE_OPTIMIZE_MAX) {
		RZ_LOG_ERROR("config 'flirt.node.optimize' is set to an invalid value.\n");
		return false;
	}

	if (!(buffer = rz_buf_new_file(input_file, O_RDONLY, 0))) {
		RZ_LOG_ERROR("FLIRT: cannot open %s (read mode)\n", input_file);
		return false;
	} else if (!strcmp(in_extension, ".pat")) {
		node = rz_sign_flirt_parse_string_pattern_from_buffer(buffer, optimize, NULL);
	} else {
		node = rz_sign_flirt_parse_compressed_pattern_from_buffer(buffer, RZ_FLIRT_SIG_ARCH_ANY, NULL);
	}
	rz_buf_free(buffer);

	if (!node) {
		RZ_LOG_ERROR("FLIRT: we encountered an error while parsing the file. Sorry.\n");
		return false;
	}

	bool result = false;
	if (!(buffer = rz_buf_new_file(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644))) {
		RZ_LOG_ERROR("FLIRT: cannot open %s (write mode)\n", output_file);
		return false;
	} else if (!strcmp(out_extension, ".pat")) {
		result = rz_sign_flirt_write_string_pattern_to_buffer(node, buffer);
	} else {
		ut64 hdr_version = rz_config_get_i(core->config, "flirt.sig.version");
		const char *hdr_arch = rz_config_get(core->config, "asm.arch");
		const char *hdr_file = rz_config_get(core->config, "flirt.sig.file");
		const char *hdr_os = rz_config_get(core->config, "flirt.sig.os");
		const char *hdr_lib = rz_config_get(core->config, "flirt.sig.library");
		bool deflate = rz_config_get_b(core->config, "flirt.sig.deflate");
		ut8 architecture = rz_core_flirt_arch_from_name(hdr_arch);

		if (RZ_STR_ISEMPTY(hdr_lib)) {
			RZ_LOG_WARN("config 'flirt.sig.library' is empty. using default value '" RZ_FLIRT_LIBRARY_NAME_DFL "'\n");
			hdr_lib = RZ_FLIRT_LIBRARY_NAME_DFL;
		} else if (architecture >= RZ_FLIRT_SIG_ARCH_ANY) {
			RZ_LOG_ERROR("FLIRT: architecture '%s' is not supported as .sig file, we suggest to use the .pat format.\n", hdr_arch);
			RZ_LOG_ERROR("FLIRT: we suggest to open an issue to discuss with the rizin team about it.\n");
			result = false;
			goto fail;
		}

		RzFlirtCompressedOptions options = {
			.version = hdr_version,
			.arch = architecture,
			.file = rz_core_flirt_file_from_option_list(hdr_file),
			.os = rz_core_flirt_os_from_option_list(hdr_os),
			.app = RZ_FLIRT_SIG_APP_ALL,
			.deflate = deflate,
			.libname = hdr_lib,
		};
		result = rz_sign_flirt_write_compressed_pattern_to_buffer(node, buffer, &options);
	}

fail:
	rz_buf_free(buffer);
	rz_sign_flirt_node_free(node);
	return result;
}