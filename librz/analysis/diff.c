// SPDX-FileCopyrightText: 2010-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_diff.h>

RZ_API RzAnalysisDiff *rz_analysis_diff_new(void) {
	RzAnalysisDiff *diff = RZ_NEW0(RzAnalysisDiff);
	if (diff) {
		diff->type = RZ_ANALYSIS_DIFF_TYPE_NULL;
		diff->addr = UT64_MAX;
		diff->dist = 0;
		diff->name = NULL;
		diff->size = 0;
	}
	return diff;
}

RZ_API void *rz_analysis_diff_free(RzAnalysisDiff *diff) {
	if (diff && diff->name) {
		RZ_FREE(diff->name);
	}
	free(diff);
	return NULL;
}

/* 0-1 */
RZ_API void rz_analysis_diff_setup(RzAnalysis *analysis, int doops, double thbb, double thfcn) {
	if (doops >= 0) {
		analysis->diff_ops = doops;
	}
	analysis->diff_thbb = (thbb >= 0) ? thbb : RZ_ANALYSIS_THRESHOLDBB;
	analysis->diff_thfcn = (thfcn >= 0) ? thfcn : RZ_ANALYSIS_THRESHOLDFCN;
}

/* 0-100 */
RZ_API void rz_analysis_diff_setup_i(RzAnalysis *analysis, int doops, int thbb, int thfcn) {
	if (doops >= 0) {
		analysis->diff_ops = doops;
	}
	analysis->diff_thbb = (thbb >= 0) ? ((double)thbb) / 100 : RZ_ANALYSIS_THRESHOLDBB;
	analysis->diff_thfcn = (thfcn >= 0) ? ((double)thfcn) / 100 : RZ_ANALYSIS_THRESHOLDFCN;
}

// Fingerprint function basic block
RZ_API int rz_analysis_diff_fingerprint_bb(RzAnalysis *analysis, RzAnalysisBlock *bb) {
	RzAnalysisOp *op;
	ut8 *buf;
	int oplen, idx = 0;

	if (!analysis) {
		return -1;
	}
	if (analysis->cur && analysis->cur->fingerprint_bb) {
		return (analysis->cur->fingerprint_bb(analysis, bb));
	}
	if (!(bb->fingerprint = malloc(1 + bb->size))) {
		return -1;
	}
	if (!(buf = malloc(bb->size + 1))) {
		free(bb->fingerprint);
		return -1;
	}
	if (analysis->iob.read_at(analysis->iob.io, bb->addr, buf, bb->size)) {
		memcpy(bb->fingerprint, buf, bb->size);
		if (analysis->diff_ops) { // diff using only the opcode
			if (!(op = rz_analysis_op_new())) {
				free(bb->fingerprint);
				free(buf);
				return -1;
			}
			while (idx < bb->size) {
				if ((oplen = rz_analysis_op(analysis, op, 0, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_BASIC)) < 1) {
					break;
				}
				if (op->nopcode != 0) {
					memset(bb->fingerprint + idx + op->nopcode, 0, oplen - op->nopcode);
				}
				idx += oplen;
			}
			free(op);
		}
	}
	free(buf);
	return bb->size;
}

RZ_API size_t rz_analysis_diff_fingerprint_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *iter;

	if (analysis && analysis->cur && analysis->cur->fingerprint_fcn) {
		return (analysis->cur->fingerprint_fcn(analysis, fcn));
	}

	fcn->fingerprint = NULL;
	fcn->fingerprint_size = 0;
	rz_list_foreach (fcn->bbs, iter, bb) {
		fcn->fingerprint_size += bb->size;
		fcn->fingerprint = realloc(fcn->fingerprint, fcn->fingerprint_size + 1);
		if (!fcn->fingerprint) {
			return 0;
		}
		memcpy(fcn->fingerprint + fcn->fingerprint_size - bb->size, bb->fingerprint, bb->size);
	}
	return fcn->fingerprint_size;
}

RZ_API bool rz_analysis_diff_bb(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisFunction *fcn2) {
	RzAnalysisBlock *bb, *bb2, *mbb, *mbb2;
	RzListIter *iter, *iter2;
	double t, ot;

	if (!analysis || !fcn || !fcn2) {
		return false;
	}
	if (analysis->cur && analysis->cur->diff_bb) {
		return (analysis->cur->diff_bb(analysis, fcn, fcn2));
	}
	fcn->diff->type = fcn2->diff->type = RZ_ANALYSIS_DIFF_TYPE_MATCH;
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->diff && bb->diff->type != RZ_ANALYSIS_DIFF_TYPE_NULL) {
			continue;
		}
		ot = 0;
		mbb = mbb2 = NULL;
		rz_list_foreach (fcn2->bbs, iter2, bb2) {
			if (!bb2->diff || bb2->diff->type == RZ_ANALYSIS_DIFF_TYPE_NULL) {
				rz_diff_levenstein_distance(bb->fingerprint, bb->size, bb2->fingerprint, bb2->size, NULL, &t);
				if (t > analysis->diff_thbb && t > ot) {
					ot = t;
					mbb = bb;
					mbb2 = bb2;
					if (t == 1) {
						break;
					}
				}
			}
		}
		if (mbb && mbb2) {
			if (!mbb->diff) {
				mbb->diff = rz_analysis_diff_new();
			}
			if (!mbb2->diff) {
				mbb2->diff = rz_analysis_diff_new();
			}
			if (!mbb->diff || !mbb2->diff) {
				return false;
			}
			if (ot == 1 || t > analysis->diff_thfcn) {
				mbb->diff->type = mbb2->diff->type = RZ_ANALYSIS_DIFF_TYPE_MATCH;
			} else {
				mbb->diff->type = mbb2->diff->type =
					fcn->diff->type = fcn2->diff->type =
						RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
			}
			mbb->diff->dist = mbb2->diff->dist = ot;
			RZ_FREE(mbb->fingerprint);
			RZ_FREE(mbb2->fingerprint);
			mbb->diff->addr = mbb2->addr;
			mbb2->diff->addr = mbb->addr;
			mbb->diff->size = mbb2->size;
			mbb2->diff->size = mbb->size;
		} else {
			fcn->diff->type = fcn2->diff->type = (fcn->diff->dist >= RZ_ANALYSIS_DIFF_THRESHOLD)
				? RZ_ANALYSIS_DIFF_TYPE_MATCH
				: RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
		}
	}
	return true;
}

RZ_API int rz_analysis_diff_fcn(RzAnalysis *analysis, RzList *fcns1, RzList *fcns2) {
	RzAnalysisFunction *fcn, *fcn2, *mfcn, *mfcn2;
	RzListIter *iter, *iter2;
	double t, ot, sizes_div;

	if (!analysis) {
		return false;
	}
	if (analysis->cur && analysis->cur->diff_fcn) {
		return (analysis->cur->diff_fcn(analysis, fcns1, fcns2));
	}
	/* Compare functions with the same name */
	rz_list_foreach (fcns1, iter, fcn) {
		rz_list_foreach (fcns2, iter2, fcn2) {
			if (fcn->name && fcn2->name && strcmp(fcn->name, fcn2->name)) {
				continue;
			}
			rz_diff_levenstein_distance(fcn->fingerprint, fcn->fingerprint_size,
				fcn2->fingerprint, fcn2->fingerprint_size, NULL, &t);
			/* Set flag in matched functions */
			fcn->diff->type = fcn2->diff->type = (t >= RZ_ANALYSIS_DIFF_THRESHOLD)
				? RZ_ANALYSIS_DIFF_TYPE_MATCH
				: RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
			fcn->diff->dist = fcn2->diff->dist = t;
			RZ_FREE(fcn->fingerprint);
			RZ_FREE(fcn2->fingerprint);
			fcn->diff->addr = fcn2->addr;
			fcn2->diff->addr = fcn->addr;
			fcn->diff->size = fcn2->fingerprint_size;
			fcn2->diff->size = fcn->fingerprint_size;
			RZ_FREE(fcn->diff->name);
			if (fcn2->name) {
				fcn->diff->name = strdup(fcn2->name);
			}
			RZ_FREE(fcn2->diff->name);
			if (fcn->name) {
				fcn2->diff->name = strdup(fcn->name);
			}
			rz_analysis_diff_bb(analysis, fcn, fcn2);
			break;
		}
	}
	/* Compare remaining functions */
	rz_list_foreach (fcns1, iter, fcn) {
		if (fcn->diff->type != RZ_ANALYSIS_DIFF_TYPE_NULL) {
			continue;
		} else if (!fcn->fingerprint_size) {
			continue;
		} else if (fcn->type != RZ_ANALYSIS_FCN_TYPE_FCN && fcn->type != RZ_ANALYSIS_FCN_TYPE_SYM) {
			continue;
		}
		ot = 0.0;
		mfcn = mfcn2 = NULL;
		rz_list_foreach (fcns2, iter2, fcn2) {
			if (fcn2->diff->type != RZ_ANALYSIS_DIFF_TYPE_NULL) {
				continue;
			} else if (!fcn2->fingerprint_size) {
				continue;
			} else if (fcn2->type != RZ_ANALYSIS_FCN_TYPE_FCN && fcn2->type != RZ_ANALYSIS_FCN_TYPE_SYM) {
				continue;
			}
			if (fcn->fingerprint_size > fcn2->fingerprint_size) {
				sizes_div = fcn2->fingerprint_size;
				sizes_div /= fcn->fingerprint_size;
			} else {
				sizes_div = fcn->fingerprint_size;
				sizes_div /= fcn2->fingerprint_size;
			}
			if (sizes_div < RZ_ANALYSIS_DIFF_THRESHOLD) {
				continue;
			}
			rz_diff_levenstein_distance(fcn->fingerprint, fcn->fingerprint_size, fcn2->fingerprint, fcn2->fingerprint_size, NULL, &t);
			if (t > ot) {
				ot = t;
				mfcn = fcn;
				mfcn2 = fcn2;
				if (ot >= RZ_ANALYSIS_DIFF_THRESHOLD) {
					break;
				}
			}
		}
		if (mfcn && mfcn2) {
			mfcn->diff->dist = mfcn2->diff->dist = ot;
			/* Set flag in matched functions */
			mfcn->diff->type = mfcn2->diff->type = (ot > RZ_ANALYSIS_DIFF_THRESHOLD)
				? RZ_ANALYSIS_DIFF_TYPE_MATCH
				: RZ_ANALYSIS_DIFF_TYPE_UNMATCH;
			RZ_FREE(mfcn->fingerprint);
			RZ_FREE(mfcn2->fingerprint);
			mfcn->diff->addr = mfcn2->addr;
			mfcn2->diff->addr = mfcn->addr;
			mfcn->diff->size = mfcn2->fingerprint_size;
			mfcn2->diff->size = mfcn->fingerprint_size;
			RZ_FREE(mfcn->diff->name);
			if (mfcn2->name) {
				mfcn->diff->name = strdup(mfcn2->name);
			}
			RZ_FREE(mfcn2->diff->name);
			if (mfcn->name) {
				mfcn2->diff->name = strdup(mfcn->name);
			}
			rz_analysis_diff_bb(analysis, mfcn, mfcn2);
		}
	}
	return true;
}

RZ_API int rz_analysis_diff_eval(RzAnalysis *analysis) {
	if (analysis && analysis->cur && analysis->cur->diff_eval) {
		return (analysis->cur->diff_eval(analysis));
	}
	return true; // XXX: shouldn't this be false?
}
