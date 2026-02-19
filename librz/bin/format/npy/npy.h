// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_NPY_H
#define RZ_NPY_H

#define NPY_ARRAY_MAX_DIMENSIONS 8
#define NPY_ARRAY_MAGIC_LENGTH   6
#define NPY_ARRAY_MAGIC_STRING   "\x93NUMPY"

typedef struct {
	char descr[32];
	bool fortran_order;
	ut64 ndim;
	ut64 shape[NPY_ARRAY_MAX_DIMENSIONS];
	ut64 elem_size;
} NPYheader;

#endif /* RZ_NPY_H */