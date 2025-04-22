// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_cons.h>

static void rz_line_nscompletion_init(RzLineNSCompletion *c) {
	c->run = NULL;
	c->run_user = NULL;
}

static void undo_free(RzLine *line) {
	if (!line) {
		return;
	}
	rz_vector_free(line->undo_vec);
	line->undo_vec = NULL;
	line->undo_cursor = 0;
	line->undo_continue = false;
}

RZ_API RZ_OWN RzLine *rz_line_new(void) {
	RzLine *line = RZ_NEW0(RzLine);
	if (!line) {
		return NULL;
	}
	line->prompt = rz_str_dup("> ");
	line->kill_ring = rz_list_newf(free);
	line->kill_ring_ptr = -1;
#if __WINDOWS__
	line->vtmode = rz_cons_detect_vt_mode();
#else
	line->vtmode = RZ_VIRT_TERM_MODE_COMPLETE;
#endif
	if (!rz_line_dietline_init(line)) {
		RZ_LOG_ERROR("error: rz_line_dietline_init\n");
	}
	rz_line_completion_init(&line->completion, 4096);
	rz_line_nscompletion_init(&line->ns_completion);
	return line;
}

RZ_API void rz_line_free(RZ_NULLABLE RzLine *line) {
	if (!line) {
		return;
	}
	free((void *)line->prompt);
	line->prompt = NULL;
	rz_list_free(line->kill_ring);
	rz_line_hist_free(line);
	undo_free(line);
	rz_line_completion_fini(&line->completion);
	free(line);
}

RZ_API void rz_line_clipboard_push(RZ_NONNULL RzLine *line, RZ_NONNULL const char *str) {
	rz_return_if_fail(line && str);
	line->kill_ring_ptr += 1;
	rz_list_insert(line->kill_ring, line->kill_ring_ptr, rz_str_dup(str));
}

// handle const or dynamic prompts?
RZ_API void rz_line_set_prompt(RZ_NONNULL RzLine *line, RZ_NONNULL const char *prompt) {
	rz_return_if_fail(line && prompt);
	free(line->prompt);
	line->prompt = rz_str_dup(prompt);
	RzCons *cons = rz_cons_singleton();
	line->cb_fkey = cons->cb_fkey;
}

// handle const or dynamic prompts?
RZ_API RZ_OWN char *rz_line_get_prompt(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, NULL);
	return rz_str_dup(line->prompt);
}

RZ_API void rz_line_completion_init(RzLineCompletion *completion, size_t args_limit) {
	completion->run = NULL;
	completion->run_user = NULL;
	completion->args_limit = args_limit;
	rz_pvector_init(&completion->args, free);
}

RZ_API void rz_line_completion_fini(RzLineCompletion *completion) {
	rz_line_completion_clear(completion);
}

RZ_API void rz_line_completion_push(RzLineCompletion *completion, const char *str) {
	rz_return_if_fail(completion && str);
	if (completion->quit) {
		return;
	}
	if (rz_pvector_len(&completion->args) < completion->args_limit) {
		char *s = rz_str_dup(str);
		if (s) {
			rz_pvector_push(&completion->args, (void *)s);
		}
	} else {
		completion->quit = true;
		eprintf("WARNING: Maximum completion capacity reached, increase scr.maxtab");
	}
}

RZ_API void rz_line_completion_set(RzLineCompletion *completion, int argc, const char **argv) {
	rz_return_if_fail(completion && (argc >= 0));
	rz_line_completion_clear(completion);
	if (argc > completion->args_limit) {
		eprintf("WARNING: Maximum completion capacity reached, increase scr.maxtab");
	}
	size_t count = RZ_MIN(argc, completion->args_limit);
	rz_pvector_reserve(&completion->args, count);
	int i;
	for (i = 0; i < count; i++) {
		rz_line_completion_push(completion, argv[i]);
	}
}

RZ_API void rz_line_completion_clear(RzLineCompletion *completion) {
	rz_return_if_fail(completion);
	completion->quit = false;
	rz_pvector_clear(&completion->args);
}

/**
 * Create an empty completion result with no available options.
 *
 * \param start Value for \p RzLineNSCompletionResult.start
 * \param end Value for \p RzLineNSCompletionResult.end
 * \param end_string Text that should be inserted after the only option available is autocompleted. When NULL, it defaults to " " (without quotes)
 */
RZ_API RzLineNSCompletionResult *rz_line_ns_completion_result_new(size_t start, size_t end, const char *end_string) {
	RzLineNSCompletionResult *res = RZ_NEW0(RzLineNSCompletionResult);
	if (!res) {
		return NULL;
	}
	rz_pvector_init(&res->options, (RzPVectorFree)free);
	HtPPOptions opt = { 0 };
	opt.cmp = (HtPPComparator)strcmp;
	opt.hashfn = (HtPPHashFunction)sdb_hash;
	res->options_ht = ht_pp_new_opt(&opt);
	res->start = start;
	res->end = end;
	if (!end_string) {
		end_string = " ";
	}
	res->end_string = end_string;
	return res;
}

/**
 * Free a previously allocated RzLineNSCompletionResult
 */
RZ_API void rz_line_ns_completion_result_free(RzLineNSCompletionResult *res) {
	if (!res) {
		return;
	}
	ht_pp_free(res->options_ht);
	rz_pvector_fini(&res->options);
	free(res);
}

/**
 * Add a new option to the list of possible autocomplete-able values.
 */
RZ_API void rz_line_ns_completion_result_add(RzLineNSCompletionResult *res, const char *option) {
	if (ht_pp_find(res->options_ht, option, NULL)) {
		return;
	}
	char *dup = rz_str_dup(option);
	rz_pvector_push(&res->options, dup);
	ht_pp_insert(res->options_ht, dup, dup);
}

/**
 * \brief Add a new option to the list of possible autocomplete-able value if it matches the given string
 * \param option the option to be added
 * \param cur currently entered prefix
 */
RZ_API void rz_line_ns_completion_result_propose(RzLineNSCompletionResult *res, const char *option, const char *cur, size_t cur_len) {
	if (strncmp(option, cur, cur_len)) {
		return;
	}
	rz_line_ns_completion_result_add(res, option);
}

#include "dietline.c"
