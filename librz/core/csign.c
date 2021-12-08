// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_sign.h>
#include <rz_flirt.h>

typedef struct map_string_value_t {
	const char *name;
	ut32 value;
} MapStringValue;

const MapStringValue arch_map[18] = {
	{ "x86", RZ_FLIRT_SIG_ARCH_386 },
	{ "z80", RZ_FLIRT_SIG_ARCH_Z80 },
	// { "i860", RZ_FLIRT_SIG_ARCH_I860 },
	// { "8051", RZ_FLIRT_SIG_ARCH_8051 },
	// { "tms", RZ_FLIRT_SIG_ARCH_TMS },
	{ "6502", RZ_FLIRT_SIG_ARCH_6502 },
	// { "pdp", RZ_FLIRT_SIG_ARCH_PDP },
	// { "68k", RZ_FLIRT_SIG_ARCH_68K },
	{ "java", RZ_FLIRT_SIG_ARCH_JAVA },
	// { "6800", RZ_FLIRT_SIG_ARCH_6800 },
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
	// { "tms320c55", RZ_FLIRT_SIG_ARCH_TMS320C55 },
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
	// { "nec_v850x", RZ_FLIRT_SIG_ARCH_NEC_V850X },
	// { "scr_adpt", RZ_FLIRT_SIG_ARCH_SCR_ADPT },
	{ "ebc", RZ_FLIRT_SIG_ARCH_EBC },
	{ "msp430", RZ_FLIRT_SIG_ARCH_MSP430 },
	// { "spu", RZ_FLIRT_SIG_ARCH_SPU },
	{ "dalvik", RZ_FLIRT_SIG_ARCH_DALVIK },
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
		if (pub_func_it->n) {
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
			if (ref_func_it->n) {
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
	rz_cons_printf("%s", rz_str_pad(' ', indent));
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
 * \brief Dumps the contents of a RzFlirtNode
 *
 * \param node FLIRT node to dump
 */
RZ_API void rz_core_flirt_dump_node(RZ_NONNULL const RzFlirtNode *node) {
	rz_return_if_fail(node);
	flirt_print_node(node, -1);
}

/**
 * \brief Dumps the contents of a FLIRT file
 *
 * \param flirt_file FLIRT file name to dump
 */
RZ_API void rz_core_flirt_dump_file(RZ_NONNULL const char *flirt_file) {
	rz_return_if_fail(RZ_STR_ISNOTEMPTY(flirt_file));

	const char *extension = rz_str_lchr(flirt_file, '.');
	if (RZ_STR_ISEMPTY(extension) || (strcmp(extension, ".sig") != 0 && strcmp(extension, ".pac") != 0)) {
		RZ_LOG_ERROR("FLIRT: unknown extension '%s'\n", extension);
		return;
	}

	RzBuffer *buffer = NULL;
	RzFlirtNode *node = NULL;

	if (!(buffer = rz_buf_new_slurp(flirt_file))) {
		RZ_LOG_ERROR("FLIRT: Can't open %s\n", flirt_file);
		return;
	} else if (!strcmp(extension, ".pac")) {
		node = rz_sign_flirt_parse_string_pattern_from_buffer(buffer, RZ_FLIRT_NODE_OPTIMIZE_NORMAL);
	} else {
		node = rz_sign_flirt_parse_compressed_pattern_from_buffer(buffer, RZ_FLIRT_SIG_ARCH_ANY);
	}

	rz_buf_free(buffer);
	if (node) {
		rz_core_flirt_dump_node(node);
		rz_sign_flirt_node_free(node);
		return;
	} else {
		RZ_LOG_ERROR("FLIRT: We encountered an error while parsing the file. Sorry.\n");
		return;
	}
}