// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2016 Jeffrey Crowell <crowell@bu.edu>
// SPDX-FileCopyrightText: 2016 Álvaro Felipe Melchor <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STACK_H
#define RZ_STACK_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RzStackFree)(void *ptr);

typedef struct rz_stack_t {
	void **elems;
	unsigned int n_elems;
	int top;
	RzStackFree free;
} RzStack;

RZ_API RzStack *rz_stack_new(ut32 n);
RZ_API void rz_stack_free(RzStack *s);
RZ_API bool rz_stack_is_empty(RzStack *s);
RZ_API RzStack *rz_stack_newf(ut32 n, RzStackFree f);
RZ_API bool rz_stack_push(RzStack *s, void *el);
RZ_API void *rz_stack_pop(RzStack *s);
RZ_API size_t rz_stack_size(RzStack *s);
RZ_API void *rz_stack_peek(RzStack *s);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STACK_H
