// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_main.h>
#include <rz_prologues.h>

static void show_help(bool usage_only) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-prologues (-f <file> | -d <dir>) [options]\n");
	if (usage_only) {
		return;
	}
	const char *options[] = {
		// clang-format off
		"-f",       "file",             "Input binary file to process",
		"-d",       "dir",              "Input directory containing binaries to process (non-recursive)",
		"-o",       "file",             "Write output to file instead of stdout",
		"-j",       "",                 "Output in JSON format (default is YAML)",
		"-l",       "len",              "Prologue length in bytes (default: " RZ_STR_DEF(RZ_PROLOGUE_DEFAULT_LEN) ")",
		"-e",       "threshold",        "Entropy threshold for wildcard generalization [0.0-1.0] (default: " RZ_STR_DEF(RZ_PROLOGUE_DEFAULT_ENTROPY_THRESHOLD) ")",
		"-r",       "",                 "Output raw prologues without entropy-based generalization",
		"-t",       "",                 "Output prefix tree (trie) structure instead of prologue list",
		"-a",       "arch",             "Filter / target architecture (e.g. x86, arm)",
		"-b",       "bits",             "Filter / target bitness of arch (e.g. 16, 32, 64)",
		"-B",       "",                 "Target big-endian architecture (default: little-endian)",
		"-q",       "",                 "Quiet mode (suppress log messages)",
		"-v",       "",                 "Show version information",
		"-h",       "",                 "Show this help message",
		// clang-format on
	};

	rz_print_colored_help(options, RZ_ARRAY_SIZE(options), false);
	printf("\n" Color_CYAN "Notes:" Color_RESET "\n"
	       "  When processing a directory (-d), if architecture (-a) or bits (-b) are not\n"
	       "  specified, the tool adopts the architecture of the first valid binary to\n"
	       "  prevent mixing cross-architecture prologues.\n\n"
	       "  Generated JSON prologues (-j) can be loaded into Rizin for function analysis\n"
	       "  using the 'aapf <file>' command.\n");

	printf("\n" Color_CYAN "Examples:" Color_RESET "\n"
	       "  # Extract generalized JSON prologues from a binary\n"
	       "  rz-prologues -f input.bin -j -o output.json\n\n"
	       "  # Extract 64-bit x86 prologues from a directory in quiet mode\n"
	       "  rz-prologues -d /path/to/bins -a x86 -b 64 -jq -o x86_64.json\n\n"
	       "  # Extract raw prologues without entropy-based generalization\n"
	       "  rz-prologues -f input.bin -rj -o raw_prologues.json\n\n"
	       "  # Dump the prefix tree (trie) structure without generalization to YAML\n"
	       "  rz-prologues -f input.bin -tr -o trie.yaml\n");
}

static bool output_handler(RzStructuredData *sd, const char *output_file, bool json_mode) {
	char *output = NULL;
	if (json_mode) {
		output = rz_structured_data_to_json(sd);
	} else {
		output = rz_structured_data_to_yaml(sd);
	}
	rz_structured_data_free(sd);
	if (!output) {
		RZ_LOG_ERROR("Failed to convert structured data to %s\n", json_mode ? "JSON" : "YAML");
		return false;
	}

	if (output_file) {
		if (rz_file_exists(output_file)) {
			if (!rz_cons_yesno('n', "Output file '%s' already exists. Overwrite? (y/N) ", output_file)) {
				RZ_LOG_WARN("Output cancelled.\n");
				RZ_FREE(output);
				return false;
			}
		}
		if (!rz_file_dump(output_file, (const ut8 *)output, strlen(output), false)) {
			RZ_LOG_ERROR("Failed to write output to file '%s'\n", output_file);
			RZ_FREE(output);
			return false;
		}
	} else {
		printf("%s\n", output);
	}
	RZ_FREE(output);
	return true;
}

static bool generate_prologues(const char *input_path, bool is_dir, const char *output_file,
	bool raw, bool trie_mode, bool json_mode,
	ut64 prologue_len, double entropy_threshold, const char *arch, int bits, bool big_endian) {

	RzProloguesArchInfo arch_info = {
		.arch = arch ? rz_str_dup(arch) : NULL,
		.bits = bits > 0 ? bits : 0,
		.big_endian = big_endian
	};

	RzTrie *pg_trie = rz_prologues_trie_new();
	if (!pg_trie) {
		RZ_LOG_ERROR("Failed to create prologues trie\n");
		rz_prologues_arch_info_fini(&arch_info);
		return false;
	}

	RzBin *bin = rz_bin_new();
	if (!bin) {
		RZ_LOG_ERROR("Failed to create RzBin instance\n");
		rz_trie_free(pg_trie);
		rz_prologues_arch_info_fini(&arch_info);
		return false;
	}
	RzIO *io = rz_io_new();
	if (!io) {
		RZ_LOG_ERROR("Failed to create RzIO instance\n");
		rz_bin_free(bin);
		rz_trie_free(pg_trie);
		rz_prologues_arch_info_fini(&arch_info);
		return false;
	}
	io->ff = true;
	rz_io_bind(io, &bin->iob);

	bool ret = false;
	RzSetS *files = rz_set_s_new(HT_STR_DUP);
	if (is_dir) {
		// dir
		int res = rz_prologues_trie_feed_directory(pg_trie, bin, input_path, prologue_len,
			&arch_info, files);

		if (res < 0) {
			RZ_LOG_ERROR("Failed to feed directory '%s' into prologues trie\n", input_path);
			goto err;
		}
	} else {
		// file
		if (!rz_file_is_regular(input_path)) {
			RZ_LOG_ERROR("File does not exist, invalid path: %s\n", input_path);
			goto err;
		}

		RzBuffer *buf = rz_buf_new_file(input_path, O_RDONLY, 0);
		if (!buf) {
			RZ_LOG_WARN("Failed to open buffer for file: %s\n", input_path);
			goto err;
		}

		RzBinOptions opt;
		rz_bin_options_init(&opt, -1, 0, 0, false);
		opt.filename = input_path;
		RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
		rz_buf_free(buf);
		if (!bf) {
			RZ_LOG_WARN("Failed to parse binary for file: %s\n", input_path);
			goto err;
		}

		bool res = rz_prologues_trie_feed_binfile(pg_trie, bf, prologue_len, &arch_info, files);
		rz_bin_file_delete(bin, bf);
		if (!res) {
			RZ_LOG_ERROR("Failed to feed binfile '%s' into prologues trie\n", input_path);
			goto err;
		}
	}

	// generalize
	RzVector *prologues = NULL;
	if (raw) {
		prologues = rz_prologues_extract_raw_from_trie(pg_trie, prologue_len);
	} else {
		prologues = rz_prologues_generalize_and_extract(pg_trie, prologue_len, entropy_threshold);
	}
	if (!prologues) {
		RZ_LOG_ERROR("Failed to generalize prologues from trie\n");
		goto err;
	}
	RzStructuredData *sd = NULL;
	if (trie_mode) {
		sd = rz_prologues_trie_to_structured_data(pg_trie, prologue_len, &arch_info, files);
	} else {
		sd = rz_prologues_to_structured_data(prologues, prologue_len, &arch_info);
	}
	rz_vector_free(prologues);
	if (!sd) {
		RZ_LOG_ERROR("Failed to convert prologues to structured data\n");
		goto err;
	}

	if (!output_handler(sd, output_file, json_mode)) {
		RZ_LOG_ERROR("Failed to output prologues\n");
		goto err;
	}
	ret = true;
err:
	rz_prologues_arch_info_fini(&arch_info);
	rz_bin_free(bin);
	rz_io_free(io);
	rz_trie_free(pg_trie);
	rz_set_s_free(files);
	return ret;
}

RZ_API int rz_main_rz_prologues(int argc, const char **argv) {

	int n = RZ_DEFAULT_LOGLVL;
	char *log_level = rz_sys_getenv("RZ_LOGLEVEL");
	if (RZ_STR_ISNOTEMPTY(log_level)) {
		n = strtol(log_level, NULL, 0);
		free(log_level);
	}
	if (n >= 0 && n < RZ_LOGLVL_SIZE) {
		rz_log_set_level((RzLogLevel)n);
	}

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "hvqd:f:rjtl:e:a:b:Bo:");
	int c;

	const char *output_file = NULL;
	const char *input_path = NULL;
	bool is_dir = false;
	bool raw = false;
	bool json_mode = false;
	bool trie_mode = false;
	ut64 prologue_len = RZ_PROLOGUE_DEFAULT_LEN;
	double entropy_threshold = RZ_PROLOGUE_DEFAULT_ENTROPY_THRESHOLD;
	const char *arch = NULL;
	int bits = -1;
	bool big_endian = false;

	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'h': {
			show_help(false);
			return 0;
		}
		case 'v': {
			RzPath *sys_path = rz_path_new();
			if (!sys_path) {
				show_help(false);
				return 0;
			}
			size_t print_val = rz_main_version_print(sys_path, "rz-prologues");
			rz_path_free(sys_path);
			return print_val;
		}
		case 'q':
			rz_log_set_level(RZ_LOGLVL_NONE);
			break;
		case 'd':
			is_dir = true;
			input_path = opt.arg;
			break;
		case 'f':
			input_path = opt.arg;
			break;
		case 'a':
			arch = opt.arg;
			break;
		case 'b':
			bits = strtoll(opt.arg, NULL, 0);
			break;
		case 'B':
			big_endian = true;
			break;
		case 'r':
			raw = true;
			break;
		case 'j':
			json_mode = true;
			break;
		case 't':
			trie_mode = true;
			break;
		case 'l': {
			prologue_len = strtoull(opt.arg, NULL, 0);
			if (prologue_len == 0) {
				RZ_LOG_ERROR("Prologue length must be a positive integer.\n");
				return 1;
			}
			break;
		}
		case 'e': {
			char *end = NULL;
			entropy_threshold = strtod(opt.arg, &end);
			if (!end || *end != '\0') {
				RZ_LOG_ERROR("Entropy threshold must be a valid double value\n");
				return 1;
			}
			if (entropy_threshold < 0.0 || entropy_threshold > 1.0) {
				RZ_LOG_ERROR("Entropy threshold must be between 0.0 and 1.0\n");
				return 1;
			}
			break;
		}
		case 'o':
			output_file = opt.arg;
			break;
		default:
			break;
		}
	}

	if (!input_path) {
		RZ_LOG_ERROR("No input specified, please provide an input path to a file or directory\n");
		show_help(true);
		return 1;
	}

	if (!rz_cons_new()) {
		return 1;
	}
	rz_cons_set_interactive(true);

	if (!generate_prologues(input_path, is_dir, output_file, raw, trie_mode, json_mode, prologue_len,
		    entropy_threshold, arch, bits, big_endian)) {
		RZ_LOG_ERROR("Failed to generate prologues from input '%s'\n", input_path);
		rz_cons_free();
		return 1;
	}
	rz_cons_free();
	return 0;
}
