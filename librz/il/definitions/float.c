// SPDX-FileCopyrightText: 2023 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file this file contains some float function used in rzil fbasic theory
 * To avoid conflict during developing, I put some float operation here at first
 * Some of them should be moved to rz_util/float in the future and resolve conflict to merge
 */
#include <rz_il/definitions/float.h>

/**
 * create a float by specifying `format` and `bitv`
 * BAP ref : ('r, 's) format Float.t Value.sort -> 's bitv -> ('r, 's) format float
 * \param format format of float, see RzFloatFormat enum
 * \param bv bitvector representation of float
 * \return float instance
 */
RZ_API RZ_OWN RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail((format != RZ_FLOAT_UNK) && bv, NULL);

	ut32 len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	if (len != bv->len) {
		RZ_LOG_ERROR("The size of the float :%d does not match the size of the bitvector :%d.\n", len, bv->len);
		return NULL;
	}

	RzFloat *f = RZ_NEW0(RzFloat);
	if (!f) {
		return NULL;
	}

	RzBitVector *dup_bv = rz_bv_dup(bv);
	if (!dup_bv) {
		free(f);
		return NULL;
	}

	f->s = dup_bv;
	f->r = format;

	return f;
}

/**
 * convert rmode into const string for exporting info
 * \param mode round mode
 * \return round mode string
 */
RZ_API const char *rz_il_float_stringify_rmode(RzFloatRMode mode) {
	switch (mode) {
	case RZ_FLOAT_RMODE_RNA:
		return "rna";
	case RZ_FLOAT_RMODE_RNE:
		return "rne";
	case RZ_FLOAT_RMODE_RTN:
		return "rtn";
	case RZ_FLOAT_RMODE_RTZ:
		return "rtz";
	case RZ_FLOAT_RMODE_RTP:
		return "rtp";
	default:
		return "unk_round";
	}
}

/**
 * convert format to human readable string
 * \param format float format
 * \return float format string
 */
RZ_API const char *rz_il_float_stringify_format(RzFloatFormat format) {
	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return "ieee754-bin32";
	case RZ_FLOAT_IEEE754_BIN_64:
		return "ieee754-bin64";
	case RZ_FLOAT_IEEE754_BIN_80:
		return "ieee754-bin80";
	case RZ_FLOAT_IEEE754_DEC_64:
		return "ieee754-dec64";
	case RZ_FLOAT_IEEE754_DEC_128:
		return "ieee754-dec128";
	default:
		return "unk_format";
	}
}
