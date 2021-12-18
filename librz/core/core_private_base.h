// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CORE_PRIVATE_BASE_H
#define RZ_CORE_PRIVATE_BASE_H

#define RZ_CORE_BASE_ADDRESS_ALIGN   0x0000000000010000ull
#define RZ_CORE_BASE_ADDRESS_DEFAULT 0x0000000008000000ull
#define RZ_CORE_BASE_ADDRESS_DEX     0x0000000000200000ull

#define rz_core_align_base_address(x) \
	do { \
		if ((x) & (RZ_CORE_BASE_ADDRESS_ALIGN - 1)) { \
			(x) += RZ_CORE_BASE_ADDRESS_ALIGN; \
			(x) &= ~(RZ_CORE_BASE_ADDRESS_ALIGN - 1); \
		} \
	} while (0)

#endif /* RZ_CORE_PRIVATE_BASE_H */
