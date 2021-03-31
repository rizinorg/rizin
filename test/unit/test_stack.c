// SPDX-FileCopyrightText: 2016 Jeffrey Crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

// Test that popping from an empty stack works.
bool test_rz_stack_pop_empty(void) {
	RzStack *stack = rz_stack_new(10);
	void *elem = rz_stack_pop(stack);
	mu_assert_eq((int)(intptr_t)elem, 0, "pop empty stack");
	rz_stack_free(stack);
	mu_end;
}

// Test that we can retrieve an item pushed onto a stack.
bool test_rz_stack_push_pop(void) {
	RzStack *stack = rz_stack_new(10);
	rz_stack_push(stack, (void *)(intptr_t)0x1337);
	void *elem = rz_stack_pop(stack);
	mu_assert_eq((int)(intptr_t)elem, 0x1337, "push pop stack");
	rz_stack_free(stack);
	mu_end;
}

// Test that the FIFO behavior is done.
bool test_rz_stack_push_pop_multi(void) {
	RzStack *stack = rz_stack_new(10);
	rz_stack_push(stack, (void *)(intptr_t)0x1337);
	rz_stack_push(stack, (void *)(intptr_t)0x8888);
	void *elem = rz_stack_pop(stack);
	mu_assert_eq((int)(intptr_t)elem, 0x8888, "push pop stack");
	elem = rz_stack_pop(stack);
	mu_assert_eq((int)(intptr_t)elem, 0x1337, "push pop stack");
	rz_stack_free(stack);
	mu_end;
}

// Test that stack size grows when more than the allowable number are pushed on.
bool test_rz_stack_grow(void) {
	RzStack *stack = rz_stack_new(2);
	mu_assert_eq(stack->n_elems, 2, "normal stack size");
	rz_stack_push(stack, (void *)(intptr_t)0x1337);
	rz_stack_push(stack, (void *)(intptr_t)0x8888);
	rz_stack_push(stack, (void *)(intptr_t)0xB00B5);
	mu_assert_eq(stack->n_elems, 4, "stack grew!");
	rz_stack_free(stack);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_stack_pop_empty);
	mu_run_test(test_rz_stack_push_pop);
	mu_run_test(test_rz_stack_push_pop_multi);
	mu_run_test(test_rz_stack_grow);
	return tests_passed != tests_run;
}

mu_main(all_tests)