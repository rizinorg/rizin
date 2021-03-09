// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RzStack *rz_stack_new(ut32 n) {
	RzStack *s = RZ_NEW0(RzStack);
	if (!s) {
		return NULL;
	}
	s->elems = RZ_NEWS0(void *, n);
	if (!s->elems) {
		free(s);
		return NULL;
	}
	s->n_elems = n;
	s->top = -1;
	return s;
}

RZ_API RzStack *rz_stack_newf(ut32 n, RzStackFree f) {
	RzStack *s = rz_stack_new(n);
	if (s) {
		s->free = f;
	}
	return s;
}

RZ_API void rz_stack_free(RzStack *s) {
	if (s) {
		if (s->free) {
			int i;
			for (i = 0; i <= s->top; i++) {
				s->free(s->elems[i]);
			}
		}
		free(s->elems);
		free(s);
	}
}

RZ_API bool rz_stack_push(RzStack *s, void *el) {
	if (s->top == s->n_elems - 1) {
		/* reallocate the stack */
		s->n_elems *= 2;
		void **elems = realloc(s->elems, s->n_elems * sizeof(void *));
		if (!elems) {
			return false;
		}
		s->elems = elems;
	}

	s->top++;
	s->elems[s->top] = el;
	return true;
}

//the caller should be take care of the object returned
RZ_API void *rz_stack_pop(RzStack *s) {
	if (s->top == -1) {
		return NULL;
	}
	void *res = s->elems[s->top];
	s->top--;
	return res;
}

RZ_API bool rz_stack_is_empty(RzStack *s) {
	return s->top == -1;
}

RZ_API size_t rz_stack_size(RzStack *s) {
	return (size_t)(s->top + 1);
}

RZ_API void *rz_stack_peek(RzStack *s) {
	return rz_stack_is_empty(s) ? NULL : s->elems[s->top];
}
