// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/value.h>

/**
 * New an empty value
 * \return val RzILVal, pointer to this value
 */
RZ_API RzILVal *rz_il_new_value(void) {
	RzILVal *ret;
	ret = (RzILVal *)malloc(sizeof(struct rz_il_val_t));
	if (!ret) {
		return NULL;
	}
	memset(ret, 0, sizeof(struct rz_il_val_t));
	ret->type = RZIL_VAR_TYPE_UNK;
	return ret;
}

/**
 * Clone an RzILVal
 * \param val RzILVal, pointer to the value you want to dump
 * \return dump RzILVal, pointer to the dumped value
 */
RZ_API RzILVal *rz_il_dup_value(RzILVal *val) {
	RzILVal *ret = rz_il_new_value();
	ret->type = val->type;

	if (ret->type == RZIL_VAR_TYPE_BOOL) {
		ret->data.b = rz_il_new_bool(val->data.b->b);
	}

	if (ret->type == RZIL_VAR_TYPE_BV) {
		ret->data.bv = rz_il_bv_dup(val->data.bv);
	}

	if (ret->type == RZIL_VAR_TYPE_UNK) {
		ret->data.b = NULL;
		ret->data.bv = NULL;
	}

	return ret;
}

/**
 * New an empty temporary value
 * \return temp RzILTemp, pointer to the new temporary value
 */
RZ_API RzILTemp rz_il_new_temp(void) {
	RzILTemp temp = RZ_NEW0(struct rz_il_tempv_t);
	if (!temp) {
		return NULL;
	}
	temp->data = NULL;
	temp->type = RZIL_TEMP_EMPTY;
	return temp;
}

/**
 * Free a temporary value
 * \param temp RzILTemp, pointer to the temporary value you want to free
 */
RZ_API void rz_il_free_temp(RzILTemp temp) {
	free(temp);
}

/**
 * Free a RzILVal value
 * \param val RzILVal, pointer to the RzILVal instance
 */
RZ_API void rz_il_free_value(RzILVal *val) {
	if (!val) {
		return;
	}

	RZIL_VAR_TYPE type = val->type;
	switch (type) {
	case RZIL_VAR_TYPE_BOOL:
		rz_il_free_bool(val->data.b);
		break;
	case RZIL_VAR_TYPE_BV:
		rz_il_bv_free(val->data.bv);
		break;
	case RZIL_VAR_TYPE_UNK:
	default:
		break;
	}

	free(val);
}
