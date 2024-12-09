// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_list.h>
#include <rz_types_base.h>
#include "../core_private.h"

#define CMD_SEARCH_BEGIN() \
	do { \
		if (core->in_search) { \
			RZ_LOG_ERROR("core: recursive search is forbidden.\n"); \
			return RZ_CMD_STATUS_ERROR; \
		} \
		core->in_search = true; \
		bool progress = state->mode != RZ_OUTPUT_MODE_JSON && rz_config_get_b(core->config, "search.progress"); \
		rz_search_opt_set_cancel_cb(core->search_opts, cmd_search_progress_cancel, progress ? state : NULL); \
	} while (0)

#define CMD_SEARCH_END() \
	do { \
		core->in_search = false; \
		rz_search_opt_set_cancel_cb(core->search_opts, NULL, NULL); \
	} while (0)

static bool cmd_search_progress_cancel(void *user, size_t n_hits) {
	if (user) {
		// we have RzCmdStateOutput state
		rz_cons_printf("Searching... hits: %" PFMTSZu "\r", n_hits);
	}
	return rz_cons_is_breaked();
}

static void cmd_search_output_to_state(RzCmdStateOutput *state, RzSearchHit *hit, const char *flag_name) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%08" PFMT64x "\n", hit->address);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%08" PFMT64x " %" PFMTSZu " %s\n", hit->address, hit->size, flag_name);
		break;
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_kn(state->d.pj, "address", hit->address);
		pj_kn(state->d.pj, "size", hit->size);
		pj_ks(state->d.pj, "flag", flag_name);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		rz_table_add_rowf(state->d.t, "xXs", hit->address, hit->size, flag_name);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void cmd_search_call_command(RzCore *core, RzSearchHit *hit, const char *command) {
	ut64 old_offset = core->offset;
	rz_core_seek(core, hit->address, true);
	rz_core_cmd(core, command, false);
	rz_core_seek(core, old_offset, true);
}

static RzCmdStatus cmd_core_handle_search_hits(RzCore *core, RzCmdStateOutput *state, RzList *hits) {
	if (!hits) {
		core->num->value = 0;
		return RZ_CMD_STATUS_ERROR;
	}

	RzListIter *it = NULL;
	RzSearchHit *hit = NULL;
	const char *cmd_hit = NULL;
	const char *search_prefix = NULL;
	size_t counter = 0;

	cmd_hit = rz_config_get(core->config, "cmd.hit");
	search_prefix = rz_config_get(core->config, "search.prefix");
	if (RZ_STR_ISEMPTY(search_prefix)) {
		// ensure thre prefix is always set.
		search_prefix = "hit";
	}

	if (RZ_STR_ISEMPTY(cmd_hit)) {
		// setup output and flagspace
		rz_cmd_state_output_array_start(state);
		rz_cmd_state_output_set_columnsf(state, "xXs", "offset", "size", "flag");
		rz_flag_space_push(core->flags, "search");
	}

	rz_list_foreach (hits, it, hit) {
		if (RZ_STR_ISNOTEMPTY(cmd_hit)) {
			cmd_search_call_command(core, hit, cmd_hit);
			continue;
		}

		// only output & add flag when cmd.hit is not set.
		const char *meta = hit->metadata ? hit->metadata : "match";
		char *flag = rz_str_newf("%s.%s.%" PFMTSZu, search_prefix, meta, counter);
		rz_flag_set(core->flags, flag, hit->address, hit->size);
		cmd_search_output_to_state(state, hit, flag);
		free(flag);
		counter++;
	}

	if (RZ_STR_ISEMPTY(cmd_hit)) {
		// terminating output and flagspace
		rz_flag_space_pop(core->flags);
		rz_cmd_state_output_array_end(state);
	}

	// set return value to the number of hits before returning
	core->num->value = rz_list_length(hits);
	rz_list_free(hits);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_assemble_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_aes_key_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_aes_keys(core, core->search_opts);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_private_key_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_private_keys(core, core->search_opts);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_regex_raw_sensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_regex(core, core->search_opts, argv[1], false);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_regex_raw_insensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_regex(core, core->search_opts, argv[1], true);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_graph_path_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_graph_path_follow_jumps_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_hash_block_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_magic_const_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_magic(core, core->search_opts);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_entropy_section_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_reference_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

#define CMD_SEARCH_FOR_VALUE(bits) \
	do { \
		CMD_SEARCH_BEGIN(); \
		bool big_endian = rz_config_get_b(core->config, "cfg.bigendian"); \
		ut##bits value = rz_num_math(core->num, argv[1]); \
		ut8 buffer[sizeof(value)] = { 0 }; \
		rz_write_ble(buffer, value, big_endian, bits); \
		RzList *hits = rz_core_search_bytes(core, core->search_opts, buffer, NULL, sizeof(value)); \
		RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits); \
		CMD_SEARCH_END(); \
		return res; \
	} while (0)

RZ_IPI RzCmdStatus rz_cmd_value_8_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_FOR_VALUE(8);
}

RZ_IPI RzCmdStatus rz_cmd_value_16_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_FOR_VALUE(16);
}

RZ_IPI RzCmdStatus rz_cmd_value_32_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_FOR_VALUE(32);
}

RZ_IPI RzCmdStatus rz_cmd_value_64_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_FOR_VALUE(64);
}

RZ_IPI RzCmdStatus rz_cmd_hex_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	RzList *hits = rz_core_search_hex_pattern(core, core->search_opts, argv[1]);
	RzCmdStatus res = cmd_core_handle_search_hits(core, state, hits);
	CMD_SEARCH_END();
	return res;
}

static RzCmdStatus cmd_string_search_generic(RzCore *core, const char *string, const char *encoding, bool caseless, RzCmdStateOutput *state) {
	RzStrEnc expected = RZ_STRING_ENC_GUESS;
	char *search_str = rz_str_dup(string);
	if (!RZ_STR_ISEMPTY(search_str)) {
		RZ_LOG_ERROR("core: invalid string: empty string.\n");
		free(search_str);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	if (rz_str_unescape(search_str) < 1) {
		RZ_LOG_ERROR("core: invalid string: failed to unescape.\n");
		free(search_str);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	if (RZ_STR_ISNOTEMPTY(encoding)) {
		expected = rz_str_enc_string_as_type(encoding);
		if (expected == RZ_STRING_ENC_GUESS) {
			RZ_LOG_ERROR("core: invalid encoding %s.\n", encoding);
			free(search_str);
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
	}

	RzList *hits = rz_core_search_string(core, core->search_opts, search_str, expected, caseless);
	free(search_str);

	return cmd_core_handle_search_hits(core, state, hits);
}

RZ_IPI RzCmdStatus rz_cmd_string_sensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	const char *encoding = argc > 2 ? argv[2] : NULL;
	RzCmdStatus res = cmd_string_search_generic(core, argv[1], encoding, false, state);
	CMD_SEARCH_END();
	return res;
}

RZ_IPI RzCmdStatus rz_cmd_string_insensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	CMD_SEARCH_BEGIN();
	const char *encoding = argc > 2 ? argv[2] : NULL;
	RzCmdStatus res = cmd_string_search_generic(core, argv[1], encoding, true, state);
	CMD_SEARCH_END();
	return res;
}
