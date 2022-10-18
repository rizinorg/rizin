// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include <rz_util.h>

#if __WINDOWS__
#define CASTLDBL (double)
#else
#define CASTLDBL
#endif

// TODO: add support for 80bit floating point value

// long double = 128 bit
RZ_API double rz_reg_get_double(RzReg *reg, RzRegItem *item) {
	RzRegSet *regset;
	int off;
	double ret = 0.0;
	if (!reg || !item) {
		return ret;
	}
	off = BITS2BYTES(item->offset);
	regset = &reg->regset[item->arena];
	switch (item->size) {
	case 64:
		if (regset->arena->size - off - 1 >= 0) {
			ret = rz_read_at_ble_double(regset->arena->bytes, off, reg->big_endian);
		}
		break;
	default:
		RZ_LOG_ERROR("rz_reg_set_double: Bit size %d not supported\n", item->size);
		break;
	}
	return ret;
}

RZ_API bool rz_reg_set_double(RzReg *reg, RzRegItem *item, double value) {
	ut8 src[8];

	if (!item) {
		RZ_LOG_ERROR("rz_reg_set_value: item is NULL\n");
		return false;
	}
	switch (item->size) {
	case 64:
		rz_write_ble_double(src, value, reg->big_endian);
		break;
	default:
		RZ_LOG_ERROR("rz_reg_set_double: Bit size %d not supported\n", item->size);
		return false;
	}
	if (reg->regset[item->arena].arena->size - BITS2BYTES(item->offset) - BITS2BYTES(item->size) >= 0) {
		rz_mem_copybits(reg->regset[item->arena].arena->bytes +
				BITS2BYTES(item->offset),
			src, item->size);
		return true;
	}
	RZ_LOG_ERROR("rz_reg_set_value: Cannot set %s to %lf\n", item->name, value);
	return false;
}

// long double = 80 bit
RZ_API long double rz_reg_get_longdouble(RzReg *reg, RzRegItem *item) {
	RzRegSet *regset;
	long double vld = 0.0f;
	int off;
	long double ret = 0.0f;
	if (!reg || !item) {
		return 0LL;
	}
	off = BITS2BYTES(item->offset);
	regset = &reg->regset[item->arena];
	switch (item->size) {
	case 80:
	case 96:
	case 128:
	case 256:
		if (regset->arena->size - off - 1 >= 0) {
			memcpy(&vld, regset->arena->bytes + off, sizeof(long double));
			ret = vld;
		}
		break;
	default:
		eprintf("rz_reg_get_longdouble: Bit size %d not supported\n", item->size);
		return 0.0f;
	}
	return ret;
}

RZ_API bool rz_reg_set_longdouble(RzReg *reg, RzRegItem *item, long double value) {
	ut8 *src = NULL;

	if (!item) {
		eprintf("rz_reg_set_value: item is NULL\n");
		return false;
	}
	switch (item->size) {
	case 80:
	case 96:
	case 128:
		// FIXME: endian
		src = (ut8 *)&value;
		break;
	default:
		eprintf("rz_reg_set_longdouble: Bit size %d not supported\n", item->size);
		return false;
	}
	if (reg->regset[item->arena].arena->size - BITS2BYTES(item->offset) - BITS2BYTES(item->size) >= 0) {
		rz_mem_copybits(reg->regset[item->arena].arena->bytes +
				BITS2BYTES(item->offset),
			src, item->size);
		return true;
	}

	eprintf("rz_reg_set_value: Cannot set %s to %" LDBLFMT "\n", item->name, CASTLDBL value);
	return false;
}

/* floating point . deprecate maybe? */
RZ_API float rz_reg_get_float(RzReg *reg, RzRegItem *item) {
	// TODO
	return 0.0f;
}

RZ_API bool rz_reg_set_float(RzReg *reg, RzRegItem *item, float value) {
	return false;
}
