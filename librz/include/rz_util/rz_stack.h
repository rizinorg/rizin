#ifndef R_STACK_H
#define R_STACK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RStackFree)(void *ptr);

typedef struct rz_stack_t {
	void **elems;
	unsigned int n_elems;
	int top;
	RStackFree free;
} RStack;

RZ_API RStack *rz_stack_new(ut32 n);
RZ_API void rz_stack_free(RStack *s);
RZ_API bool rz_stack_is_empty(RStack *s);
RZ_API RStack *rz_stack_newf(ut32 n, RStackFree f);
RZ_API bool rz_stack_push(RStack *s, void *el);
RZ_API void *rz_stack_pop(RStack *s);
RZ_API size_t rz_stack_size(RStack *s);
RZ_API void *rz_stack_peek(RStack *s);

#ifdef __cplusplus
}
#endif

#endif //  R_STACK_H
