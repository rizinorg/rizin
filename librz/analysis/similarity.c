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

typedef struct signature_data_t {
	size_t size; ///< Signature size
	ut8 *data; ///< Signature bytes
	void *info; ///< Info linked to the signature (RzAnalysisBlock or RzAnalysisFunction)
} SignatureData;

typedef SignatureData *(*SignatureDataCb)(RzAnalysis *analysis, void *data);
typedef bool (*SignatureMetaCompare)(void *a, void *b);

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

#define signature_fast_compare(sim_a, sim_b) \
	(sim_a->size == sim_b->size && !memcmp(sim_a->data, sim_b->data, sim_b->size))

#define signature_levenshtein_distance(sim_a, sim_b, similarity) \
	rz_diff_levenshtein_distance(sim_a->data, sim_a->size, sim_b->data, sim_b->size, NULL, &similarity)

static double analysis_similarity_generic(RzAnalysis *analysis_a, void *ptr_a, RzAnalysis *analysis_b, void *ptr_b, SignatureDataCb callback_new) {
	SignatureData *sim_a = NULL, *sim_b = NULL;
	double similarity = 0.0;
	bool ret = true;

	sim_a = callback_new(analysis_a, ptr_a);
	sim_b = callback_new(analysis_b, ptr_b);
	if (!sim_a || !sim_b) {
		ret = false;
		goto fail;
	}

	if (signature_fast_compare(sim_a, sim_b)) {
		similarity = 1.0;
	} else {
		ret = signature_levenshtein_distance(sim_a, sim_b, similarity);
	}

fail:
	signature_data_free(sim_a);
	signature_data_free(sim_b);
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
	return analysis_similarity_generic(analysis, bb_a, analysis, bb_b, (SignatureDataCb)signature_data_bb_new);
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
	return analysis_similarity_generic(analysis, fcn_a, analysis, fcn_b, (SignatureDataCb)signature_data_fcn_new);
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
	return analysis_similarity_generic(analysis_a, bb_a, analysis_b, bb_b, (SignatureDataCb)signature_data_bb_new);
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
	return analysis_similarity_generic(analysis_a, fcn_a, analysis_b, fcn_b, (SignatureDataCb)signature_data_fcn_new);
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

static RzList /*<SignatureData *>*/ *signature_data_from_list(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzList /*<void *>*/ *list_src, SignatureDataCb callback_new) {
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

static RZ_OWN RzAnalysisMatchResult *analysis_match_result_new(RZ_NONNULL RzAnalysis *analysis_a, RZ_NONNULL RzAnalysis *analysis_b, RZ_NONNULL RzList /*<void *>*/ *list_a, RZ_NONNULL RzList /*<void *>*/ *list_b, SignatureMetaCompare callback_cmp, SignatureDataCb callback_new) {
	RzAnalysisMatchResult *result = NULL;

	RzList *matches = rz_list_newf((RzListFree)free);
	RzList *unmatch_a = rz_list_newf((RzListFree)free);
	RzList *unmatch_b = rz_list_newf((RzListFree)free);
	RzList *sims_a = signature_data_from_list(analysis_a, list_a, callback_new);
	RzList *sims_b = signature_data_from_list(analysis_b, list_b, callback_new);
	if (!matches || !unmatch_a || !unmatch_b || !sims_a || !sims_b) {
		goto fail;
	}

	RzAnalysisMatchPair *pair = NULL;
	SignatureData *sim_a = NULL, *sim_b = NULL;
	RzListIter *it_a = NULL, *it_b = NULL, *match_b = NULL;
	double max_similarity = 0.0, calc_similarity = 0.0;

	if (callback_cmp) {
		// Sometimes we can pre-match the data by name etc, so we can make the list smaller.
		it_a = sims_a->head;
		while (it_a) {
			sim_a = rz_list_iter_get_data(it_a);
			match_b = NULL;
			max_similarity = 0.0;
			rz_list_foreach (sims_b, it_b, sim_b) {
				if (!callback_cmp(sim_a->info, sim_b->info)) {
					continue;
				}

				if (signature_fast_compare(sim_a, sim_b)) {
					max_similarity = 1.0;
				} else {
					signature_levenshtein_distance(sim_a, sim_b, max_similarity);
				}

				match_b = it_b;
				break;
			}

			if (!match_b) {
				it_a = rz_list_iter_get_next(it_a);
				continue;
			}

			sim_b = rz_list_iter_get_data(match_b);
			pair = match_pair_new(sim_a->info, sim_b->info, max_similarity);
			if (!pair || !rz_list_append(matches, pair)) {
				free(pair);
				goto fail;
			}

			rz_list_delete(sims_b, match_b);
			RzListIter *it_del = it_a;
			it_a = it_del->p;
			rz_list_delete(sims_a, it_del);

			if (!it_a) {
				// if we delete the first element
				// we need to fetch the new first
				// iter
				it_a = sims_a->head;
			} else {
				it_a = rz_list_iter_get_next(it_a);
			}
		}
	}

	rz_list_foreach (sims_a, it_a, sim_a) {
		match_b = NULL;
		max_similarity = 0.0;
		rz_list_foreach (sims_b, it_b, sim_b) {
			if (signature_fast_compare(sim_a, sim_b)) {
				max_similarity = 1.0;
				match_b = it_b;
				break;
			}

			calc_similarity = 0.0;
			signature_levenshtein_distance(sim_a, sim_b, calc_similarity);
			if (calc_similarity <= max_similarity) {
				continue;
			}
			max_similarity = calc_similarity;
			match_b = it_b;
			if (max_similarity >= 1.0) {
				break;
			}
		}

		if (!match_b || max_similarity < RZ_ANALYSIS_SIMILARITY_THRESHOLD) {
			if (!rz_list_append(unmatch_a, sim_a->info)) {
				goto fail;
			}
			continue;
		}

		sim_b = rz_list_iter_get_data(match_b);
		pair = match_pair_new(sim_a->info, sim_b->info, max_similarity);
		if (!pair || !rz_list_append(matches, pair)) {
			free(pair);
			goto fail;
		}
		rz_list_delete(sims_b, match_b);
	}

	rz_list_foreach (sims_b, it_b, sim_b) {
		if (!rz_list_append(unmatch_b, sim_b->info)) {
			goto fail;
		}
	}

	result = RZ_NEW0(RzAnalysisMatchResult);
	if (!result) {
		goto fail;
	}

	result->matches = matches;
	result->unmatch_a = unmatch_a;
	result->unmatch_b = unmatch_b;

	rz_list_free(sims_a);
	rz_list_free(sims_b);
	return result;

fail:
	rz_list_free(matches);
	rz_list_free(unmatch_a);
	rz_list_free(unmatch_b);
	rz_list_free(sims_a);
	rz_list_free(sims_b);
	return NULL;
}

#undef signature_fast_compare
#undef signature_levenshtein_distance

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
	return analysis_match_result_new(analysis, analysis, fcn_a->bbs, fcn_b->bbs, NULL, (SignatureDataCb)signature_data_bb_new);
}

static bool function_cmp(RzAnalysisFunction *fcn_a, RzAnalysisFunction *fcn_b) {
	if (RZ_STR_ISEMPTY(fcn_a->name) ||
		RZ_STR_ISEMPTY(fcn_b->name) ||
		!strncmp(fcn_a->name, "fcn.", strlen("fcn.")) ||
		!strncmp(fcn_b->name, "fcn.", strlen("fcn."))) {
		return false;
	}

	return !strcmp(fcn_a->name, fcn_b->name);
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
	return analysis_match_result_new(analysis, analysis, list_a, list_b, (SignatureMetaCompare)function_cmp, (SignatureDataCb)signature_data_fcn_new);
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
	return analysis_match_result_new(analysis_a, analysis_b, fcn_a->bbs, fcn_b->bbs, NULL, (SignatureDataCb)signature_data_bb_new);
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
	return analysis_match_result_new(analysis_a, analysis_b, list_a, list_b, (SignatureMetaCompare)function_cmp, (SignatureDataCb)signature_data_fcn_new);
}
