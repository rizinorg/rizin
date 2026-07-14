<!-- SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re> -->
<!-- SPDX-License-Identifier: LGPL-3.0-only -->

# RzInquiry Module

Module implementing basic and advanced binary analysis.

## TODO

* Add final pass for analysis and integrate xrefs and other yield info in result

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

## Multiple entrypoints in one block

Code:
```
B> fallthrough
   fallthrough
A> fallthrough
   jmp
```

B and A are in-edges. When interpreting, we first only get the full IL blocks
where B extends until the jmp and A does not know there may be instructions
before.
Desired outcome is to have blocks like this without overlap:

```
------------------
| B> fallthrough |
|    fallthrough |
------------------
        |
------------------
| A> fallthrough |
|    jmp         |
------------------
```

rot127 solved it by just interpreting the IL blocks as they come and at the end
reducing the overlapping blocks.

thestr4ng3r's approach is to handle the reduction as part of the interpreter loop:

Case 1:
  A was already discovered.
  B is discovered later.
  => It must extend only until the start of A.

Case 2:
  B was already discovered.
  A is discovered later.
  => B must be split.

Special cases:
Jump into the middle of an instruction. In such cases, overlaps between blocks
are permitted. Perhaps when an instruction meets again with one from another
block, this should be merged.

### Call detection issues

Call detection is based on a store of the block end addr before the jump.
Consider the following ARMv4 code for an indirect call (blx was introduced in ARMv5):

```
A> mov lr, pc
B> mov pc, r0
C> ...
```

both A and B are block entries.

1. If A is discovered before B, the call is recognized and C is also added as a fallthrough entry.
2. If B is discovered before A, the call is not recognized because A and B are two separate blocks already.

The ideal outcome is probably that this is **not** recognized as a call since
it is unlikely to be meant to be one in this pattern, but this is not practical
as explained in detail in the section below.
Since for this special case, we will not decide whether the jump is a call, we
have to simply interpret it as both a call and a direct jump.

Idea: have some flags per block, something like:
- Fallthrough
- Stores bb-end, WARNING: bb-end must be detected from the IL cache block that definitely ends with an explicit jmp

#### Detailed reasoning why avoiding call detection is not possible

Consider patterns like this, where there is an in-edge to A and to B.

```
A>    mov lr, pc
B>    jmp 1324
C>    ...
```

For all such patterns across an entire interpretation, we now want to **not**
consider the jmp as a call, but only because of the in-edge B. However:

* To make the decision whether a block from entry A is calling, it is necessary
  to know that there is no entry B into the block splitting pc storage and
  jump.
* This is only possible to know once a fixpoint has been reached already. But
  reaching the final fixpoint also depends on whether A is calling, so there is
  a circular dependency.

One might try to approach this by postponing adding any successor states of A
if it is detected that it might be calling, then loop until a temporary
fixpoint is reached, then continue from A, again postponing deciding on
successors of potentially calling blocks and do this until a final fixpoint has
been reached.
But if wethen  detect an edge B, we have violated our condition that we want
this pattern to always not be recognized as calling. But if from this we might
rewind and conclude that A is not calling, that edge B would disappear, so A
should be calling again and it is a circular dependency again.

We could weaken our initial condition to allow for A to be calling while B is
there if B is detected only because of A later on, but then consider this
example:

```
A>    mov lr, pc
B>    jmp 1234
C>    jmp B'
...
A'>   mov lr, pc
B'>   jmp 4321
C'>   jmp B
```

There is no unique solution for minimizing calling blocks with edges into them
anymore. Either A is considered calling and A' is not, or the other way around.

In conclusion, it is impossible to guarantee that blocks that have a
call-splitting in-edge are never treated as calling, and it is also impossible
to minimize the number of such occurrences deterministically (avoiding
arbitrary heuristics).
And even if we tried to minimize these cases and use some heuristics to decide
between multiple solutions, the added complexity to the algorithm would likely
be justified by how little practical usefulness this has.
