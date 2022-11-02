#include <rz_il/definitions/float.h>

RZ_API RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail((format != RZ_FLOAT_UNK) && bv, NULL);
	// Task :
	// 1. dup bv to make float
	// 2. make sure bv length is equal with what `format` defined
	// TODO : should we support cast here ?
	//	interpret 31-bit vector as IEEE-BIN64 etc.

	ut32 len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	if (len != bv->len) {
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

	f->s = bv;
	f->r = format;

	return f;
}
