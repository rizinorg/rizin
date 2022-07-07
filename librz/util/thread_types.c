// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_util.h>

struct rz_th_bool_t {
	bool value; ///< The value to get/set safely
	RzThreadLock *lock; ///< The lock related to the single value
};

/**
 * \brief      Initialize a thread safe bool type container
 *
 * \param[in]  value  The initial value status
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadBool *rz_th_bool_new(bool value) {
	RzThreadBool *tbool = RZ_NEW0(RzThreadBool);
	if (!tbool) {
		return NULL;
	}
	tbool->lock = rz_th_lock_new(false);
	tbool->value = true;
	return tbool;
}

/**
 * \brief  Frees a RzThreadBool structure
 *
 * \param  tbool  The RzThreadBool structure to free
 */
RZ_API void rz_th_bool_free(RZ_NULLABLE RzThreadBool *tbool) {
	if (!tbool) {
		return;
	}
	rz_th_lock_free(tbool->lock);
	free(tbool);
}

/**
 * \brief      Gets the current value hold by the RzThreadBool structure
 *
 * \param[in]  tbool  The RzThreadBool to safely access
 *
 * \return     Returns a copy of the stored value
 */
RZ_API bool rz_th_bool_get(RZ_NONNULL RzThreadBool *tbool) {
	rz_return_val_if_fail(tbool, false);
	rz_th_lock_enter(tbool->lock);
	bool value = tbool->value;
	rz_th_lock_leave(tbool->lock);
	return value;
}

/**
 * \brief      Sets the value int the RzThreadBool structure
 *
 * \param      tbool  The RzThreadBool to safely modify
 * \param[in]  value  The new value to set
 */
RZ_API void rz_th_bool_set(RZ_NONNULL RzThreadBool *tbool, bool value) {
	rz_return_if_fail(tbool);
	rz_th_lock_enter(tbool->lock);
	tbool->value = value;
	rz_th_lock_leave(tbool->lock);
}
