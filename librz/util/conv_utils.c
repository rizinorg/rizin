// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

/**
 * \brief      Clones a RzPVector but returns it as a RzList
 *
 * \param[in]  pvec  The RzPVector to clone.
 *
 * \return     On success a valid pointer is returned, otherwise NULL.
 */
RZ_API RZ_OWN RzList /*<void *>*/ *rz_util_copy_pvector_as_list(RZ_NONNULL const RzPVector /*<void *>*/ *pvec) {
	rz_return_val_if_fail(pvec, NULL);

	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (pvec, it) {
		rz_list_append(list, *it);
	}
	return list;
}

/**
 * \brief      Clones a RzList but returns it as a RzPVector
 *
 * \param[in]  list  The RzList to clone.
 *
 * \return     On success a valid pointer is returned, otherwise NULL.
 */
RZ_API RZ_OWN RzPVector /*<void *>*/ *rz_util_copy_list_as_pvector(RZ_NONNULL const RzList /*<void *>*/ *list) {
	rz_return_val_if_fail(list, NULL);

	size_t pvec_size = rz_list_length(list);
	RzPVector *pvec = rz_pvector_new_with_len(NULL, pvec_size);
	if (!pvec) {
		return NULL;
	}

	RzListIter *it;
	void *ptr;
	size_t i = 0;
	rz_list_foreach (list, it, ptr) {
		rz_pvector_set(pvec, i, ptr);
		i++;
	}
	return pvec;
}
