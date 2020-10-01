/* radare - LGPL - Copyright 2007-2020 - ret2libc */

#include <rz_util.h>

RZ_API RStack *rz_stack_new(ut32 n) {
	RStack *s = R_NEW0 (RStack);
	if (!s) {
		return NULL;
	}
	s->elems = R_NEWS0 (void *, n);
	if (!s->elems) {
		free (s);
		return NULL;
	}
	s->n_elems = n;
	s->top = -1;
	return s;
}

RZ_API RStack *rz_stack_newf(ut32 n, RStackFree f) {
	RStack *s = rz_stack_new (n);
	if (s) {
		s->free = f;
	}
	return s;
}

RZ_API void rz_stack_free(RStack *s) {
	if (s) {
		if (s->free) {
			int i;
			for (i = 0; i <= s->top; i++) {
				s->free (s->elems[i]);
			}
		}
		free (s->elems);
		free (s);
	}
}

RZ_API bool rz_stack_push(RStack *s, void *el) {
	if (s->top == s->n_elems - 1) {
		/* reallocate the stack */
		s->n_elems *= 2;
		void **elems = realloc (s->elems, s->n_elems * sizeof (void *));
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
RZ_API void *rz_stack_pop(RStack *s) {
	if (s->top == -1) {
		return NULL;
	}
	void *res = s->elems[s->top];
	s->top--;
	return res;
}

RZ_API bool rz_stack_is_empty(RStack *s) {
	return s->top == -1;
}

RZ_API size_t rz_stack_size(RStack *s) {
	return (size_t)(s->top + 1);
}

RZ_API void *rz_stack_peek(RStack *s) {
	return rz_stack_is_empty (s)? NULL: s->elems[s->top];
}
