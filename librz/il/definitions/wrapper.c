// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "wrapper.h"
BitVector val_cast_to_bitv(RzILVal val) {
	BitVector ret;
	ret = val->data.bv;
	free(val);
	return ret;
}

RzILVal bitv_cast_to_val(BitVector bv) {
	RzILVal ret = rz_il_new_value();
	ret->type = RZIL_VAR_TYPE_BV;
	ret->data.bv = bv;
	return ret;
}

Bool val_cast_to_bool(RzILVal val) {
	Bool ret;
	ret = val->data.b;
	return ret;
}

RzILVal bool_cast_to_val(Bool b) {
	RzILVal ret = rz_il_new_value();
	ret->type = RZIL_VAR_TYPE_BOOL;
	ret->data.b = b;
	return ret;
}
