// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_list.h>
#include <rz_types_base.h>
#include "../core_private.h"

#include "cmd_search_rop.c"

typedef struct search_parameters {
	RzCore *core; ///< RzCore instance to use
	RzCmdStateOutput *state; ///< RzCmdStateOutput to use to print data.
	RzList /*<RzIOMap *>*/ *boundaries;
	const char *cmd_hit;
	bool inverse;
	bool aes_search;
	bool privkey_search;
} search_parameters_t;

RZ_IPI RzCmdStatus rz_cmd_info_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	if (!input) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzRopSearchContext *context = rz_core_rop_search_context_new(core, argv[1], false, RZ_ROP_GADGET_PRINT, state);
	RzCmdStatus status = rz_core_rop_gadget_info(core, context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_query_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzPVector /*<RzRopConstraint *>*/ *constraints = rop_constraint_map_parse(core, argc, argv);
	if (!constraints) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (rz_pvector_empty(constraints)) {
		rz_pvector_fini(constraints);
		return RZ_CMD_STATUS_INVALID;
	}

	RzRopSearchContext *context = rz_core_rop_search_context_new(core, argv[1], false, RZ_ROP_GADGET_PRINT, state);
	const RzCmdStatus cmd_status = rz_core_rop_search(core, context);
	rz_pvector_fini(constraints);
	rz_core_rop_search_context_free(context);
	return cmd_status;
}

RZ_IPI RzCmdStatus rz_cmd_search_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	if (!input) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, input, true, RZ_ROP_GADGET_PRINT, state);
	RzCmdStatus status = rz_core_rop_search(core, context);
	rz_core_rop_search_context_free(context);
	return status;
}

RZ_IPI RzCmdStatus rz_cmd_detail_gadget_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *input = argc > 1 ? argv[1] : "";
	RzRopSearchContext *context = rz_core_rop_search_context_new(core, input, false, RZ_ROP_GADGET_PRINT_DETAIL | RZ_ROP_GADGET_ANALYZE, state);
	RzCmdStatus status = rz_core_rop_search(core, context);
	rz_core_rop_search_context_free(context);
	return status;
}

typedef struct search_prelude_cb_ctx {
	int counter; ///< Number of preludes found
	RzCore *core; ///< RzCore to use
	int depth; ///< analysis.depth value
} search_prelude_cb_ctx_t;

static bool search_prelude_cb_hit(RzSearchKeyword *kw, void *user, ut64 addr) {
	search_prelude_cb_ctx_t *ctx = (search_prelude_cb_ctx_t *)user;
	ctx->counter++;
	rz_core_analysis_fcn(ctx->core, addr, -1, RZ_ANALYSIS_XREF_TYPE_NULL, ctx->depth);
	return true;
}

RZ_API int rz_core_search_prelude(RzCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen) {
	search_prelude_cb_ctx_t ctx = { 0 };
	ut8 *b = NULL;

	// TODO: handle sections ?
	if (from >= to) {
		RZ_LOG_ERROR("core: Invalid search range 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", from, to);
		return 0;
	}

	b = (ut8 *)malloc(core->blocksize);
	if (!b) {
		RZ_LOG_ERROR("core: failed to allocate prelude search buffer with size %u\n", core->blocksize);
		return 0;
	}

	// set RzCore.
	ctx.core = core;
	ctx.depth = rz_config_get_i(core->config, "analysis.depth");

	rz_search_reset(core->search, RZ_SEARCH_MODE_KEYWORD);
	rz_search_kw_add(core->search, rz_search_keyword_new(buf, blen, mask, mlen, NULL));
	rz_search_begin(core->search);
	rz_search_set_callback(core->search, &search_prelude_cb_hit, &ctx);
	for (ut64 at = from; at < to; at += core->blocksize) {
		if (rz_cons_is_breaked() ||
			!rz_io_is_valid_offset(core->io, at, 0)) {
			break;
		}
		if (rz_io_read_at(core->io, at, b, core->blocksize)) {
			RZ_LOG_ERROR("core: failed to read at 0x%08" PFMT64x "\n", at);
			break;
		}
		if (rz_search_update(core->search, at, b, core->blocksize) == -1) {
			RZ_LOG_ERROR("core: update read error at 0x%08" PFMT64x "\n", at);
			break;
		}
	}
	// rz_search_reset might also benifet from having an if(s->data) RZ_FREE(s->data), but im not sure.
	// add a commit that puts it in there to this PR if it wouldn't break anything. (don't have to worry about this happening again, since all searches start by resetting core->search)
	// For now we will just use rz_search_kw_reset
	rz_search_kw_reset(core->search);
	free(b);
	return ctx.counter;
}

RZ_API int rz_core_search_preludes(RzCore *core, bool log) {
	int ret = -1;
	ut64 from = UT64_MAX;
	ut64 to = UT64_MAX;
	int keyword_length = 0;
	ut8 *keyword = NULL;
	const char *prelude = rz_config_get(core->config, "analysis.prelude");
	ut64 limit = rz_config_get_i(core->config, "analysis.prelude.limit");

	RzList *list = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	RzList *arch_preludes = NULL;
	RzListIter *iter = NULL, *iter2 = NULL;
	RzIOMap *p = NULL;
	RzSearchKeyword *kw = NULL;

	if (!list) {
		return -1;
	}

	if (RZ_STR_ISNOTEMPTY(prelude)) {
		keyword = malloc(strlen(prelude) + 1);
		if (!keyword) {
			RZ_LOG_ERROR("aap: cannot allocate 'analysis.prelude' buffer\n");
			rz_list_free(list);
			return -1;
		}
		keyword_length = rz_hex_str2bin(prelude, keyword);
	} else {
		arch_preludes = rz_analysis_preludes(core->analysis);
		if (!arch_preludes) {
			rz_list_free(list);
			return -1;
		}
	}

	rz_list_foreach (list, iter, p) {
		if (!(p->perm & RZ_PERM_X)) {
			continue;
		}
		from = p->itv.addr;
		to = rz_itv_end(p->itv);
		if ((to - from) >= limit) {
			RZ_LOG_WARN("aap: search interval (from 0x%" PFMT64x
				    " to 0x%" PFMT64x ") exeeds analysis.prelude.limit (0x%" PFMT64x "), skipping it.\n",
				from, to, limit);
			continue;
		}
		if (keyword && keyword_length > 0) {
			ret = rz_core_search_prelude(core, from, to, keyword, keyword_length, NULL, 0);
		} else {
			rz_list_foreach (arch_preludes, iter2, kw) {
				ret = rz_core_search_prelude(core, from, to,
					kw->bin_keyword, kw->keyword_length,
					kw->bin_binmask, kw->binmask_length);
			}
		}
	}
	free(keyword);
	rz_list_free(list);
	rz_list_free(arch_preludes);
	return ret;
}

RZ_IPI RzCmdStatus rz_cmd_utf8_string_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *search_arg = rz_str_dup(argv[1]);
	if (!search_arg) {
		RZ_LOG_ERROR("core: invalid utf8 string: failed to unescape.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	int len = rz_str_unescape(search_arg);
	if (len < 1) {
		RZ_LOG_ERROR("core: invalid utf8 string: failed to unescape.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	RzSearchKeyword *search_kw = rz_search_keyword_new((const ut8 *)search_arg, len, NULL, 0, NULL);
	free(search_arg);
	if (!search_kw) {
		RZ_LOG_ERROR("core: failed to create new RzSearchKeyword\n");
		return RZ_CMD_STATUS_ERROR;
	}

	search_kw->icase = false;
	search_kw->type = RZ_SEARCH_KEYWORD_TYPE_STRING;
	rz_search_kw_add(core->search, search_kw);

	// setup search mode and direction
	rz_search_reset(core->search, RZ_SEARCH_MODE_KEYWORD);
	rz_search_set_backwards(core->search, false);

	search_parameters_t param = { 0 };
	param.state = state;
	// RzCmdStatus status = core_run_search(core, &param, argv[1]);
	return RZ_CMD_STATUS_ERROR; // status;
}

RZ_IPI RzCmdStatus rz_cmd_wide_string_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_utf8_string_insensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_wide_string_insensitive_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_assemble_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_cryptographic_material_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_regex_raw_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
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
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_pattern_raw_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_similarity_raw_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_entropy_section_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_reference_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_value_8_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_value_16_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_value_32_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_value_64_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_hex_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_non_matching_hex_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_size_string_search_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI int rz_cmd_search(void *data, const char *input) {
	RZ_LOG_ERROR("You should not be here via '%s'\n", input)
	return false;
}
