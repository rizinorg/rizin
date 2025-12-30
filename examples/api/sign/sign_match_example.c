// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Parsing and matching a FLIRT signature
 *
 * This example demonstrates how to parse a .pat format
 * signature string and count the number of patterns/modules.
 */

#include <rz_flirt.h>
#include <rz_util.h>
#include <stdio.h>

// A simple .pat signature for testing
static const char *test_pat =
	"5589E583EC..894DF8....................C745FC00000000 00 0000 0040 :0000 test_function\n"
	"---\n";

int main(int argc, char **argv) {
	printf("=== RzSign Match Example ===\n\n");

	// Create a buffer from the test pattern
	RzBuffer *pat_buf = rz_buf_new_with_bytes((const ut8 *)test_pat, strlen(test_pat));
	if (!pat_buf) {
		fprintf(stderr, "Failed to create buffer\n");
		return 1;
	}

	printf("Parsing .pat signature:\n%s\n", test_pat);

	// Parse the pattern
	RzFlirtInfo info = { 0 };
	RzFlirtNode *node = rz_sign_flirt_parse_string_pattern_from_buffer(pat_buf, RZ_FLIRT_NODE_OPTIMIZE_NONE, &info);

	rz_buf_free(pat_buf);

	if (!node) {
		fprintf(stderr, "Failed to parse pattern\n");
		return 1;
	}

	printf("Parsing successful!\n");
	printf("File type: %s\n", info.type == RZ_FLIRT_FILE_TYPE_PAT ? "PAT" : "Unknown");
	printf("Number of modules: %u\n", info.u.pat.n_modules);

	// Count nodes
	ut32 node_count = rz_sign_flirt_node_count_nodes(node);
	printf("Total nodes in tree: %u\n", node_count);

	// Verify structure
	if (node->child_list && rz_list_length(node->child_list) > 0) {
		RzFlirtNode *child = rz_list_first_val(node->child_list);
		if (child && child->module_list && rz_list_length(child->module_list) > 0) {
			RzFlirtModule *module = rz_list_first_val(child->module_list);
			if (module && module->public_functions && rz_list_length(module->public_functions) > 0) {
				RzFlirtFunction *func = rz_list_first_val(module->public_functions);
				printf("\nFirst function in signature:\n");
				printf("  Name: %s\n", func->name);
				printf("  Offset: 0x%04x\n", func->offset);
				printf("  Is local: %s\n", func->is_local ? "yes" : "no");
			}
		}
	}

	rz_sign_flirt_info_fini(&info);
	rz_sign_flirt_node_free(node);

	printf("\n=== Done ===\n");
	return 0;
}
