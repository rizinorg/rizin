// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2019 00rsiere <00rsiere@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DRX_H
#define RZ_DRX_H

enum {
	DRX_API_LIST = 0,
	DRX_API_GET_BP = 1,
	DRX_API_SET_BP = 2,
	DRX_API_REMOVE_BP = 3,
};

#if __i386__ || __x86_64__
#define NUM_DRX_REGISTERS 8
#endif

#endif
