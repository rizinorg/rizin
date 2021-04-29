// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API bool rz_calculate_luhn_value(const char *data, ut64 *result) {
	rz_return_val_if_fail(data && result, false);
	ssize_t size = strlen(data);
	if (size < 1) {
		return false;
	}

	int digit;
	ut64 sum = 0;
	bool parity = false;
	for (ssize_t i = size - 1; i >= 0; --i) {
		if (!IS_DIGIT(data[i])) {
			return false;
		}

		digit = data[i] - '0';
		if (parity) {
			digit *= 2;
		}
		digit = (digit / 10) + (digit % 10);
		sum += digit;
		parity = !parity;
	}

	*result = sum % 10;
	return true;
}
