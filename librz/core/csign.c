// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2014-2016 jfrankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_sign.h>
#include <rz_flirt.h>

static void flirt_print_module(const RzFlirtModule *module) {
	RzListIter *pub_func_it, *ref_func_it, *tail_byte_it;
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
		rz_list_foreach (module->tail_bytes, tail_byte_it, tail_byte) {
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
		if (node->variant_bool_array[i]) {
			rz_cons_printf("..");
		} else {
			rz_cons_printf("%02X", node->pattern_bytes[i]);
		}
	}
	rz_cons_printf(":\n");
}

static void flirt_print_indentation(int indent) {
	rz_cons_printf("%s", rz_str_pad(' ', indent));
}

static void flirt_print_node(const RzFlirtNode *node, int indent) {
	/*Prints a signature node. The output is similar to dumpsig*/
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
RZ_API void rz_core_flirt_dump(RZ_NONNULL const char *flirt_file) {
	rz_return_if_fail(RZ_STR_ISNOTEMPTY(flirt_file));

	RzBuffer *buffer = NULL;
	RzFlirtNode *node = NULL;

	if (!(buffer = rz_buf_new_slurp(flirt_file))) {
		RZ_LOG_ERROR("FLIRT: Can't open %s\n", flirt_file);
		return;
	}

	node = rz_sign_flirt_parse_buffer(buffer);
	rz_buf_free(buffer);
	if (node) {
		flirt_print_node(node, -1);
		rz_sign_flirt_node_free(node);
		return;
	} else {
		RZ_LOG_ERROR("FLIRT: We encountered an error while parsing the file. Sorry.\n");
		return;
	}
}