// SPDX-FileCopyrightText: 2025 Maijin <Maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Example: Creating a FLIRT signature from a pattern
 *
 * This example demonstrates the structure of FLIRT nodes
 * and how to create a simple .pat signature string manually.
 */

#include <rz_flirt.h>
#include <rz_util.h>
#include <stdio.h>

int main(int argc, char **argv) {
	printf("=== RzSign Create Example ===\n\n");

	// Demonstrate how a .pat signature is structured
	printf("A .pat signature line has this format:\n");
	printf("  <pattern> <pattern_len> <crc16> <func_size> <symbols>\n\n");

	// Example: Creating a simple signature for a function
	// Pattern bytes: 55 89 E5 83 EC (push ebp; mov ebp, esp; sub esp, ...)
	// With variant bytes: 55 89 E5 83 EC .. (last byte is variable)
	const char *example_pattern = "5589E583EC..";
	const char *func_name = "my_function";
	ut8 pattern_len = 0x00;
	ut16 crc16 = 0x0000;
	ut32 func_size = 0x40; // 64 bytes

	printf("Building signature for function '%s':\n", func_name);
	printf("  Pattern bytes: 55 89 E5 83 EC ..\n");
	printf("  Pattern len:   0x%02X\n", pattern_len);
	printf("  CRC16:         0x%04X\n", crc16);
	printf("  Function size: 0x%04X (%u bytes)\n\n", func_size, func_size);

	// Generate the .pat line
	printf("Generated .pat signature:\n");
	printf("--------------------------------\n");
	printf("%s %02X %04X %04X :0000 %s\n", 
		example_pattern, pattern_len, crc16, func_size, func_name);
	printf("---\n");
	printf("--------------------------------\n\n");

	// Parse it back to verify
	const char *pat_content = "5589E583EC.. 00 0000 0040 :0000 my_function\n---\n";
	RzBuffer *buf = rz_buf_new_with_bytes((const ut8 *)pat_content, strlen(pat_content));
	if (!buf) {
		fprintf(stderr, "Failed to create buffer\n");
		return 1;
	}

	RzFlirtInfo info = { 0 };
	RzFlirtNode *node = rz_sign_flirt_parse_string_pattern_from_buffer(buf, RZ_FLIRT_NODE_OPTIMIZE_NONE, &info);
	rz_buf_free(buf);

	if (node) {
		printf("Verification: Parsed signature successfully!\n");
		printf("  File type: %s\n", info.type == RZ_FLIRT_FILE_TYPE_PAT ? "PAT" : "Unknown");
		printf("  Modules: %u\n", info.u.pat.n_modules);
		rz_sign_flirt_info_fini(&info);
		rz_sign_flirt_node_free(node);
	} else {
		fprintf(stderr, "Failed to parse signature\n");
	}

	printf("\n=== Done ===\n");
	return 0;
}
