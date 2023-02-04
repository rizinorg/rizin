// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_diff.h>

/** \file similarity.c
 *
 * The code uses the levenshtein distance to calculate the similarity
 * of two functions or basic blocks.
 *
 * The functions basic blocks are attached together to for a unique
 * raw blob of bytes before being used for the similarity calculation.
 *
 * If two signatures are of the same size, memcmp is used to perform
 * a fast compare which speeds up the computation and skips the levenshtein
 * distance calculation which is more expensive to perform.
 */

#define iob_read_at(addr, buf, size) (analysis->iob.read_at(analysis->iob.io, addr, buf, size))

typedef ut8 *(*AllocateBuffer)(RzAnalysis *analysis, void *data, ut8 **buffer, ut32 *buf_sz);

typedef struct shared_context_t {
	const RzList /*<void *>*/ *list_b;
	RzThreadQueue *queue;
	RzThreadQueue *matches;
	RzThreadQueue *unmatch;
	AllocateBuffer alloc;
	RzThreadLock *lock_a;
	RzThreadLock *lock_b;
	RzAnalysis *analysis_a;
	RzAnalysis *analysis_b;
} SharedContext;

static bool shared_context_init(SharedContext *context, RzAnalysis *analysis_a, RzAnalysis *analysis_b, RzList /*<void *>*/ *list_a, RzList /*<void *>*/ *list_b, AllocateBuffer alloc_cb) {
	RzThreadLock *lock_a = rz_th_lock_new(true);
	RzThreadLock *lock_b = analysis_a == analysis_b ? lock_a : rz_th_lock_new(true);
	RzThreadQueue *queue = rz_th_queue_new2(rz_list_clone(list_a));
	RzThreadQueue *matches = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	RzThreadQueue *unmatch = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!lock_a || !lock_b || !queue || !matches || !unmatch) {
		rz_th_lock_free(lock_a);
		lock_a = NULL;
		rz_th_lock_free(lock_b);
		rz_th_queue_free(queue);
		rz_th_queue_free(matches);
		rz_th_queue_free(unmatch);
		return false;
	}
	context->queue = queue;
	context->list_b = list_b;
	context->matches = matches;
	context->unmatch = unmatch;
	context->alloc = alloc_cb;
	context->lock_a = lock_a;
	context->lock_b = lock_b;
	context->analysis_a = analysis_a;
	context->analysis_b = analysis_b;
	return true;
}

static void shared_context_fini(SharedContext *context) {
	rz_th_queue_free(context->queue);
	rz_th_queue_free(context->matches);
	rz_th_queue_free(context->unmatch);
	rz_th_lock_free(context->lock_a);
	if (context->lock_a != context->lock_b) {
		rz_th_lock_free(context->lock_b);
	}
}

static bool shared_context_alloc_a(SharedContext *context, void *ptr, ut8 **buffer, ut32 *buf_sz) {
	rz_th_lock_enter(context->lock_a);
	bool res = context->alloc(context->analysis_a, ptr, buffer, buf_sz);
	rz_th_lock_leave(context->lock_a);
	return res;
}

static bool shared_context_alloc_b(SharedContext *context, void *ptr, ut8 **buffer, ut32 *buf_sz) {
	rz_th_lock_enter(context->lock_b);
	bool res = context->alloc(context->analysis_b, ptr, buffer, buf_sz);
	rz_th_lock_leave(context->lock_b);
	return res;
}

static bool basic_block_data_new(RzAnalysis *analysis, RzAnalysisBlock *bb, ut8 **buffer, ut32 *buf_sz) {
	rz_return_val_if_fail(analysis && bb && buffer && buf_sz, false);
	ut8 *data = NULL;

	if (bb->size < 1 ||
		!(data = malloc(bb->size)) ||
		!iob_read_at(bb->addr, data, bb->size)) {
		goto fail;
	}

	*buf_sz = bb->size;
	*buffer = data;
	return true;

fail:
	free(data);
	return false;
}

static bool function_data_new(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut8 **buffer, ut32 *buf_sz) {
	rz_return_val_if_fail(analysis && fcn && buffer && buf_sz, false);
	size_t size = 0, current = 0;
	ut8 *data = NULL;
	RzAnalysisBlock *bb = NULL;
	RzListIter *iter = NULL;

	rz_list_foreach (fcn->bbs, iter, bb) {
		size += bb->size;
	}

	if (size < 1 || !(data = malloc(size))) {
		goto fail;
	}

	current = 0;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->size > 0 && !iob_read_at(bb->addr, data + current, bb->size)) {
			goto fail;
		}
		current += bb->size;
	}

	*buf_sz = size;
	*buffer = data;
	return true;

fail:
	free(data);
	return false;
}

static double calculate_similarity(const ut8 *buf_a, ut32 size_a, const ut8 *buf_b, ut32 size_b) {
	if (size_a == size_b && !memcmp(buf_a, buf_b, size_b)) {
		return 1.0;
	}
	double similarity = 0.0;
	if (!rz_diff_levenshtein_distance(buf_a, size_a, buf_b, size_b, NULL, &similarity)) {
		return 0.0;
	}
	return similarity;
}

static double analysis_similarity_generic(RzAnalysis *analysis_a, void *ptr_a, RzAnalysis *analysis_b, void *ptr_b, AllocateBuffer callback_new) {
	ut8 *buf_a = NULL, *buf_b = NULL;
	ut32 size_a = 0, size_b = 0;
	double similarity = 0.0;
	bool ret = true;

	if (!callback_new(analysis_a, ptr_a, &buf_a, &size_a) ||
		!callback_new(analysis_b, ptr_b, &buf_b, &size_b)) {
		ret = false;
		goto fail;
	}

	similarity = calculate_similarity(buf_a, size_a, buf_b, size_b);

fail:
	free(buf_a);
	free(buf_b);
	return ret ? similarity : -1.0;
}

/**
 * \brief      Calculates the similarity of two basic blocks
 *
 * \param      analysis  The RzAnalysis struct to use
 * \param      bb_a      The input basic block A to compare
 * \param      bb_b      The input basic block B to compare
 *
 * \return     On success returns a value between 0.0 and 1.0, othewise negative
 */
RZ_API double rz_analysis_similarity_basic_block(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisBlock *bb_a, RZ_NONNULL RzAnalysisBlock *bb_b) {
	rz_return_val_if_fail(analysis && bb_a && bb_b, -1.0);
	return analysis_similarity_generic(analysis, bb_a, analysis, bb_b, (AllocateBuffer)basic_block_data_new);
}

/**
 * \brief      Calculates the similarity of two functions
 *
 * \param      analysis  The RzAnalysis struct to use
 * \param      fcn_a     The input function A to compare
 * \param      fcn_b     The input function B to compare
 *
 * \return     On success returns a value between 0.0 and 1.0, othewise negative
 */
RZ_API double rz_analysis_similarity_function(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn_a, RZ_NONNULL RzAnalysisFunction *fcn_b) {
	rz_return_val_if_fail(analysis && fcn_a && fcn_b, -1.0);
	return analysis_similarity_generic(analysis, fcn_a, analysis, fcn_b, (AllocateBuffer)function_data_new);
}

/**
 * \brief      Calculates the similarity of two basic blocks
 *
 * \param      analysis_a  The RzAnalysis struct for bb_a to use
 * \param      bb_a        The input basic block A to compare
 * \param      analysis_b  The RzAnalysis struct for bb_b to use
 * \param      bb_b        The input basic block B to compare
 *
 * \return     On success returns a value between 0.0 and 1.0, othewise negative
 */
RZ_API double rz_analysis_similarity_basic_block_2(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysisBlock *bb_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzAnalysisBlock *bb_b) {
	rz_return_val_if_fail(analysis_a && analysis_b && bb_a && bb_b, -1.0);
	return analysis_similarity_generic(analysis_a, bb_a, analysis_b, bb_b, (AllocateBuffer)basic_block_data_new);
}

/**
 * \brief      Calculates the similarity of two functions
 *
 * \param      analysis_a  The RzAnalysis struct for fcn_a to use
 * \param      fcn_a       The input function A to compare
 * \param      analysis_b  The RzAnalysis struct for fcn_b to use
 * \param      fcn_b       The input function B to compare
 *
 * \return     On success returns a value between 0.0 and 1.0, othewise negative
 */
RZ_API double rz_analysis_similarity_function_2(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysisFunction *fcn_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzAnalysisFunction *fcn_b) {
	rz_return_val_if_fail(analysis_a && analysis_b && fcn_a && fcn_b, -1.0);
	return analysis_similarity_generic(analysis_a, fcn_a, analysis_b, fcn_b, (AllocateBuffer)function_data_new);
}

static RZ_OWN RzAnalysisMatchPair *match_pair_new(const void *pair_a, const void *pair_b, double similarity) {
	RzAnalysisMatchPair *result = RZ_NEW0(RzAnalysisMatchPair);
	if (!result) {
		return NULL;
	}

	result->pair_a = pair_a;
	result->pair_b = pair_b;
	result->similarity = similarity;
	return result;
}

static RZ_OWN RzAnalysisMatchResult *analysis_match_result_new(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzList /*<void *>*/ *list_a, RZ_NONNULL RzList /*<void *>*/ *list_b, RzThreadFunction thread_cb, AllocateBuffer alloc_cb) {
	size_t pool_size = 1;
	RzListIter *iter;
	RzAnalysisMatchPair *pair = NULL;
	RzAnalysisMatchResult *result = NULL;
	RzList *unmatch_a = rz_list_newf((RzListFree)free);
	RzList *unmatch_b = rz_list_clone(list_b);
	RzThreadPool *pool = rz_th_pool_new(RZ_THREAD_POOL_ALL_CORES);
	SharedContext shared = { 0 };

	if (!unmatch_a || !unmatch_b || !pool || !shared_context_init(&shared, analysis_a, analysis_b, list_a, list_b, alloc_cb)) {
		RZ_LOG_ERROR("analysis_match: cannot initialize search context\n");
		goto fail;
	}

	pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("analysis_match: using %u threads\n", (ut32)pool_size);
	for (size_t i = 0; i < pool_size; ++i) {
		rz_th_pool_add_thread(pool, rz_th_new((RzThreadFunction)thread_cb, &shared));
	}

	rz_th_pool_wait(pool);

	result = RZ_NEW0(RzAnalysisMatchResult);
	if (!result) {
		goto fail;
	}

	result->matches = rz_th_queue_pop_all(shared.matches);
	result->unmatch_a = rz_th_queue_pop_all(shared.unmatch);
	result->unmatch_b = unmatch_b;

	// there is no need to sort unmatch_b because it is already sorted.
	rz_list_foreach (result->matches, iter, pair) {
		rz_list_delete_data(unmatch_b, (void *)pair->pair_b);
	}

	rz_th_pool_free(pool);
	shared_context_fini(&shared);
	return result;

fail:
	rz_th_pool_free(pool);
	shared_context_fini(&shared);
	rz_list_free(unmatch_a);
	rz_list_free(unmatch_b);
	return NULL;
}

/**
 * \brief      Frees a valid pointer to a RzAnalysisMatchResult struct
 *
 * \param[in]  RzAnalysisMatchResult  The analysis match result to be freed
 */
RZ_API void rz_analysis_match_result_free(RZ_NULLABLE RzAnalysisMatchResult *result) {
	if (!result) {
		return;
	}
	rz_list_free(result->matches);
	rz_list_free(result->unmatch_a);
	rz_list_free(result->unmatch_b);
	free(result);
}

static void *analysis_match_basic_blocks(SharedContext *shared) {
	double max_similarity = 0.0, calc_similarity = 0.0;
	const RzListIter *iter = NULL;
	RzAnalysisBlock *bb_a = NULL, *bb_b = NULL, *match = NULL;
	RzAnalysisMatchPair *pair = NULL;
	ut32 size_a = 0, size_b = 0;
	ut8 *buf_a = NULL, *buf_b = NULL;

	while ((bb_a = rz_th_queue_pop(shared->queue, false))) {
		if (!shared_context_alloc_a(shared, bb_a, &buf_a, &size_a)) {
			RZ_LOG_ERROR("analysis_match: cannot allocate buffer for block 0x%08" PFMT64x " (A)\n", bb_a->addr);
			rz_th_queue_push(shared->unmatch, bb_a, true);
			continue;
		}

		match = NULL;
		max_similarity = 0.0;
		rz_list_foreach (shared->list_b, iter, bb_b) {
			if (!shared_context_alloc_b(shared, bb_b, &buf_b, &size_b)) {
				RZ_LOG_ERROR("analysis_match: cannot allocate buffer for block 0x%08" PFMT64x " (B)\n", bb_b->addr);
				continue;
			}

			calc_similarity = calculate_similarity(buf_a, size_a, buf_b, size_b);
			free(buf_b);

			if (calc_similarity < RZ_ANALYSIS_SIMILARITY_THRESHOLD && calc_similarity <= max_similarity) {
				continue;
			}
			max_similarity = calc_similarity;
			match = bb_b;
			if (max_similarity >= 1.0) {
				break;
			}
		}
		free(buf_a);

		if (match && (pair = match_pair_new(bb_a, match, max_similarity))) {
			rz_th_queue_push(shared->matches, pair, true);
			continue;
		}
		rz_th_queue_push(shared->unmatch, bb_a, true);
	}

	return NULL;
}

/**
 * \brief      Finds matching basic blocks of 2 given functions using the same RzAnalysis core
 *
 * \param      analysis  The RzAnalysis struct to use
 * \param      fcn_a     The input function A
 * \param      fcn_b     The input function B
 *
 * \return     On success returns a valid pointer to RzAnalysisMatchResult otherwise NULL
 */
RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_basic_blocks(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn_a, RZ_NONNULL RzAnalysisFunction *fcn_b) {
	rz_return_val_if_fail(analysis && fcn_a && fcn_b, NULL);
	return analysis_match_result_new(analysis, analysis, fcn_a->bbs, fcn_b->bbs, (RzThreadFunction)analysis_match_basic_blocks, (AllocateBuffer)basic_block_data_new);
}

static bool function_name_cmp(RzAnalysisFunction *fcn_a, RzAnalysisFunction *fcn_b) {
	if (RZ_STR_ISEMPTY(fcn_b->name) ||
		!strncmp(fcn_b->name, "fcn.", strlen("fcn.")) ||
		RZ_STR_ISEMPTY(fcn_a->name) ||
		!strncmp(fcn_a->name, "fcn.", strlen("fcn."))) {
		return false;
	}

	return !strcmp(fcn_a->name, fcn_b->name);
}

static void *analysis_match_functions(SharedContext *shared) {
	double max_similarity = 0.0, calc_similarity = 0.0;
	const RzListIter *iter = NULL;
	RzAnalysisFunction *fcn_a = NULL, *fcn_b = NULL, *match = NULL;
	RzAnalysisMatchPair *pair = NULL;
	ut32 size_a = 0, size_b = 0;
	ut8 *buf_a = NULL, *buf_b = NULL;

	while ((fcn_a = rz_th_queue_pop(shared->queue, false))) {
		if (!shared_context_alloc_a(shared, fcn_a, &buf_a, &size_a)) {
			RZ_LOG_ERROR("analysis_match: cannot allocate buffer for function %s (A)\n", fcn_a->name);
			rz_th_queue_push(shared->unmatch, fcn_a, true);
			continue;
		}

		match = NULL;
		max_similarity = 0.0;
		rz_list_foreach (shared->list_b, iter, fcn_b) {
			if (!shared_context_alloc_b(shared, fcn_b, &buf_b, &size_b)) {
				RZ_LOG_ERROR("analysis_match: cannot allocate buffer for function %s (B)\n", fcn_b->name);
				continue;
			}

			calc_similarity = calculate_similarity(buf_a, size_a, buf_b, size_b);
			free(buf_b);

			if (function_name_cmp(fcn_a, fcn_b)) {
				max_similarity = calc_similarity;
				match = fcn_b;
				break;
			} else if (calc_similarity < RZ_ANALYSIS_SIMILARITY_THRESHOLD && calc_similarity <= max_similarity) {
				continue;
			}
			max_similarity = calc_similarity;
			match = fcn_b;
			if (max_similarity >= 1.0) {
				break;
			}
		}
		free(buf_a);

		if (match && (pair = match_pair_new(fcn_a, match, max_similarity))) {
			rz_th_queue_push(shared->matches, pair, true);
			continue;
		}
		rz_th_queue_push(shared->unmatch, fcn_a, true);
	}

	return NULL;
}

/**
 * \brief      Finds matching functions of 2 given lists of functions using the same RzAnalysis core
 *
 * \param      analysis  The RzAnalysis struct to use
 * \param      fcn_a     The input list A of functions
 * \param      fcn_b     The input list B of functions
 *
 * \return     On success returns a valid pointer to RzAnalysisMatchResult otherwise NULL
 */
RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_functions(RZ_NONNULL RzAnalysis *analysis, RzList /*<RzAnalysisFunction *>*/ *list_a, RzList /*<RzAnalysisFunction *>*/ *list_b) {
	rz_return_val_if_fail(analysis && list_a && list_b, NULL);
	return analysis_match_result_new(analysis, analysis, list_a, list_b, (RzThreadFunction)analysis_match_functions, (AllocateBuffer)function_data_new);
}

/**
 * \brief      Finds matching basic blocks of 2 given functions using two different RzAnalysis cores
 *
 * \param      analysis_a  The RzAnalysis struct for fcn_a to use
 * \param      fcn_a       The input function A
 * \param      analysis_b  The RzAnalysis struct for fcn_b to use
 * \param      fcn_b       The input function B
 *
 * \return     On success returns a valid pointer to RzAnalysisMatchResult otherwise NULL
 */
RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_basic_blocks_2(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysisFunction *fcn_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzAnalysisFunction *fcn_b) {
	rz_return_val_if_fail(analysis_a && analysis_b && fcn_a && fcn_b, NULL);
	return analysis_match_result_new(analysis_a, analysis_b, fcn_a->bbs, fcn_b->bbs, (RzThreadFunction)analysis_match_basic_blocks, (AllocateBuffer)basic_block_data_new);
}

/**
 * \brief      Finds matching functions of 2 given lists of functions using two different RzAnalysis cores
 *
 * \param      analysis_a  The RzAnalysis struct for list_a to use
 * \param      list_a      The input list A of functions
 * \param      analysis_b  The RzAnalysis struct for list_b to use
 * \param      list_b      The input list B of functions
 *
 * \return     On success returns a valid pointer to RzAnalysisMatchResult otherwise NULL
 */
RZ_API RZ_OWN RzAnalysisMatchResult *rz_analysis_match_functions_2(RZ_NONNULL RzAnalysis *analysis_a, RzList /*<RzAnalysisFunction *>*/ *list_a, RZ_NONNULL RzAnalysis *analysis_b, RzList /*<RzAnalysisFunction *>*/ *list_b) {
	rz_return_val_if_fail(analysis_a && analysis_b && list_a && list_b, NULL);
	return analysis_match_result_new(analysis_a, analysis_b, list_a, list_b, (RzThreadFunction)analysis_match_functions, (AllocateBuffer)function_data_new);
}
