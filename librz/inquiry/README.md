<!-- SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re> -->
<!-- SPDX-License-Identifier: LGPL-3.0-only -->

# RzInquiry Module

Module implementing basic and advanced binary analysis.

## Interpreter Notes

Ideas for optimization (do not implement any of these without profiling first):
* evaluation (`eval_pure` in `interpreter.c` and possibly also `eval_effect`)
  often temporarily allocates temporary abstract values if there is more than
  one operand in an op.
  E.g. for `(add x y)`, the output RzAbstractVal can be reused to evaluate `x`
  into first, but `y` is allocated dynamically on the heap.
  Because the size of dynamic values depends on the plugin, we can't use
  regular stack memory. However we could build our own stack to the side and
  re-use allocations that way.
  For example an `RzVector` where the element size is given by the plugin.
* In evaluation of an op, one could often short-circuit if one operand is
  already known to be top.
  E.g. for `(add x y)` with constant/top abstraction, if `x` evaluates to top,
  we don't have to evaluate `y` anymore because the result will be top anyway.
  However, this may not always be the case, e.g. for `(logand x y)`, if `x` is
  top, `y` may evaluate to 0 and the result will be a constant again. And if
  the plugin defines a more fine-grained abstraction then even more cases will
  result in non-top results.
  So the plugin must decide whether to short-circuit or not. It has to be
  profiled if the cost of asking the plugin all the time is really compensated
  by avoided evalutations in practical code.
