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

typedef struct shared_context_t {
	RzList *list_b;
	RzThreadQueue *queue;
	RzThreadQueue *matches;
	RzThreadQueue *unmatch;
} SharedContext;

typedef struct signature_data_t {
	size_t size; ///< Signature size
	ut8 *data; ///< Signature bytes
	void *info; ///< Info linked to the signature (RzAnalysisBlock or RzAnalysisFunction)
} SignatureData;

typedef SignatureData *(*SignatureNewCb)(RzAnalysis *analysis, void *data);

static SignatureData *signature_data_bb_new(RzAnalysis *analysis, RzAnalysisBlock *bb) {
	rz_return_val_if_fail(analysis && bb, NULL);
	SignatureData *sim = NULL;
	ut8 *data = NULL;

	if (bb->size < 1 ||
		!(data = malloc(bb->size)) ||
		!(sim = RZ_NEW0(SignatureData)) ||
		!iob_read_at(bb->addr, data, bb->size)) {
		goto fail;
	}

	sim->size = bb->size;
	sim->data = data;
	sim->info = bb;
	return sim;

fail:
	free(data);
	free(sim);
	return NULL;
}

static SignatureData *signature_data_fcn_new(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(analysis && fcn, NULL);
	size_t size = 0, current = 0;
	ut8 *data = NULL;
	SignatureData *sim = NULL;
	RzAnalysisBlock *bb = NULL;
	RzListIter *iter = NULL;

	rz_list_foreach (fcn->bbs, iter, bb) {
		size += bb->size;
	}

	if (size < 1 || !(data = malloc(size)) || !(sim = RZ_NEW0(SignatureData))) {
		goto fail;
	}

	current = 0;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->size > 0 && !iob_read_at(bb->addr, data + current, bb->size)) {
			goto fail;
		}
		current += bb->size;
	}

	sim->size = size;
	sim->data = data;
	sim->info = fcn;
	return sim;

fail:
	free(data);
	free(sim);
	return NULL;
}

static void signature_data_free(SignatureData *sim) {
	if (!sim) {
		return;
	}
	free(sim->data);
	free(sim);
}

static RzList /*<SignatureData *>*/ *signature_data_from_list(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzList /*<void *>*/ *list_src, SignatureNewCb callback_new) {
	RzList *list = rz_list_newf((RzListFree)signature_data_free);
	if (!list) {
		RZ_LOG_ERROR("analysis: Cannot allocate RzList for basic blocks signatures\n");
		return NULL;
	}
	void *ptr;
	RzListIter *iter;
	SignatureData *sim;

	rz_list_foreach (list_src, iter, ptr) {
		sim = callback_new(analysis, ptr);
		if (!sim || !rz_list_append(list, sim)) {
			signature_data_free(sim);
			rz_list_free(list);
			return NULL;
		}
	}

	return list;
}

static bool shared_context_init(SharedContext *context, RzAnalysis *analysis_a, RzAnalysis *analysis_b, RzList /*<void *>*/ *list_a, RzList /*<void *>*/ *list_b, SignatureNewCb alloc_cb) {
	RzThreadQueue *queue = NULL;
	RzList *copy_a = signature_data_from_list(analysis_a, list_a, alloc_cb);
	RzList *copy_b = signature_data_from_list(analysis_b, list_b, alloc_cb);
	RzThreadQueue *matches = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	RzThreadQueue *unmatch = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!copy_a || !copy_b || !matches || !unmatch || !(queue = rz_th_queue_new2(copy_a))) {
		rz_list_free(copy_a);
		rz_list_free(copy_b);
		rz_th_queue_free(matches);
		rz_th_queue_free(unmatch);
		return false;
	}

	context->queue = queue;
	context->list_b = copy_b;
	context->matches = matches;
	context->unmatch = unmatch;
	return true;
}

static void shared_context_fini(SharedContext *context) {
	rz_list_free(context->list_b);
	rz_th_queue_free(context->matches);
	rz_th_queue_free(context->unmatch);
	rz_th_queue_free(context->queue);
}

#define signature_fast_compare(sim_a, sim_b) \
	(sim_a->size == sim_b->size && !memcmp(sim_a->data, sim_b->data, sim_b->size))

#define signature_levenshtein_distance(sim_a, sim_b, similarity) \
	rz_diff_levenshtein_distance(sim_a->data, sim_a->size, sim_b->data, sim_b->size, NULL, similarity)

static double calculate_similarity(SignatureData *sig_a, SignatureData *sig_b) {
	if (signature_fast_compare(sig_a, sig_b)) {
		return 1.0;
	}
	double similarity = 0.0;
	if (!signature_levenshtein_distance(sig_a, sig_b, &similarity)) {
		return 0.0;
	}
	return similarity;
}

#undef signature_fast_compare
#undef signature_levenshtein_distance

static double analysis_similarity_generic(RzAnalysis *analysis_a, void *ptr_a, RzAnalysis *analysis_b, void *ptr_b, SignatureNewCb callback_new) {
	SignatureData *sig_a = NULL, *sig_b = NULL;
	double similarity = 0.0;
	bool ret = true;

	if (!(sig_a = callback_new(analysis_a, ptr_a)) ||
		!(sig_b = callback_new(analysis_b, ptr_b))) {
		ret = false;
		goto fail;
	}

	similarity = calculate_similarity(sig_a, sig_b);

fail:
	signature_data_free(sig_a);
	signature_data_free(sig_b);
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
	return analysis_similarity_generic(analysis, bb_a, analysis, bb_b, (SignatureNewCb)signature_data_bb_new);
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
	return analysis_similarity_generic(analysis, fcn_a, analysis, fcn_b, (SignatureNewCb)signature_data_fcn_new);
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
	return analysis_similarity_generic(analysis_a, bb_a, analysis_b, bb_b, (SignatureNewCb)signature_data_bb_new);
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
	return analysis_similarity_generic(analysis_a, fcn_a, analysis_b, fcn_b, (SignatureNewCb)signature_data_fcn_new);
}

static RZ_OWN RzAnalysisMatchPair *match_pair_new(SignatureData *sig_a, SignatureData *sig_b, double similarity) {
	RzAnalysisMatchPair *result = RZ_NEW0(RzAnalysisMatchPair);
	if (!result) {
		return NULL;
	}

	result->pair_a = sig_a->info;
	result->pair_b = sig_b->info;
	result->similarity = similarity;
	return result;
}

static int comparePairAddresses(const RzAnalysisMatchPair *ma, const RzAnalysisMatchPair *mb) {
	const RzAnalysisFunction *a = ma->pair_a;
	const RzAnalysisFunction *b = mb->pair_a;
	return (a && b && a->addr && b->addr ? (a->addr > b->addr) - (a->addr < b->addr) : 0);
}

static RZ_OWN RzAnalysisMatchResult *analysis_match_result_new(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzList /*<void *>*/ *list_a, RZ_NONNULL RzList /*<void *>*/ *list_b, RzThreadFunction thread_cb, SignatureNewCb alloc_cb) {
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

	rz_list_sort(result->matches, (RzListComparator)comparePairAddresses);
	rz_list_sort(result->unmatch_a, analysis_a->columnSort);

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
	return analysis_match_result_new(analysis, analysis, fcn_a->bbs, fcn_b->bbs, (RzThreadFunction)analysis_match_basic_blocks, (SignatureNewCb)signature_data_bb_new);
}

static bool function_cmp(SignatureData *sig_a, SignatureData *sig_b) {
	RzAnalysisFunction *fcn_a = sig_a->info;
	RzAnalysisFunction *fcn_b = sig_b->info;
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
	SignatureData *sig_a, *sig_b, *match = NULL;
	RzAnalysisMatchPair *pair = NULL;

	while ((sig_a = rz_th_queue_pop(shared->queue, false))) {
		match = NULL;
		max_similarity = 0.0;
		rz_list_foreach (shared->list_b, iter, sig_b) {
			calc_similarity = calculate_similarity(sig_a, sig_b);

			if (function_cmp(sig_a, sig_b)) {
				max_similarity = calc_similarity;
				match = sig_b;
				break;
			} else if (calc_similarity < RZ_ANALYSIS_SIMILARITY_THRESHOLD && calc_similarity <= max_similarity) {
				continue;
			}
			max_similarity = calc_similarity;
			match = sig_b;
			if (max_similarity >= 1.0) {
				break;
			}
		}

		if (match && (pair = match_pair_new(sig_a, match, max_similarity))) {
			rz_th_queue_push(shared->matches, pair, true);
			continue;
		}
		rz_th_queue_push(shared->unmatch, sig_a->info, true);
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
	return analysis_match_result_new(analysis, analysis, list_a, list_b, (RzThreadFunction)analysis_match_functions, (SignatureNewCb)signature_data_fcn_new);
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
	return analysis_match_result_new(analysis_a, analysis_b, fcn_a->bbs, fcn_b->bbs, (RzThreadFunction)analysis_match_basic_blocks, (SignatureNewCb)signature_data_bb_new);
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
	return analysis_match_result_new(analysis_a, analysis_b, list_a, list_b, (RzThreadFunction)analysis_match_functions, (SignatureNewCb)signature_data_fcn_new);
}
