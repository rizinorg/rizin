RzIL
====

RzIL is the new intermediate language in Rizin, primarily intended for
representing the semantics of machine code. It is designed as a clone of BAP's
[Core Theory](http://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/),
with minor deviations where necessary.

Background
----------

RzIL was introduced as a consequence of dissatisfaction with certain properties
of ESIL, in particular its highly ambiguous and weak typing, requiring [major
hacks](https://github.com/rizinorg/rizin/blob/2e065789a70edd20909aadcdf7f9c45b9af699fb/librz/analysis/esil/esil.c#L1025-L1032),
for example to determine the bit-width of a value required for further
calculations.

At this point, two options to proceed were to either enhance ESIL and
redesign some aspects of it, such as introducing static typing, or starting
from scratch with a new language, preferably reusing an already existing
field-tested one. It was decided for the latter approach, and the language was
chosen to be BAP Core Theory. The initial implementation was then carried out as
part of the Rizin Summer of Code 2021 by heersin.

Language Design
---------------

An expression, or "op", in RzIL forms a tree, optionally composed from multiple
sub-ops. All these ops are statically typed and are divided into pure ops and
effects at the highest level.

### Pure Ops

As the name suggests, pure ops, stored by `RzILOpPure`, are computations that
are free from side-effects and evaluate to a single value. The types of values
supported at the moment are booleans and bitvectors.

### Effect Ops and State

As the counterpart to pure ops, effects stored by `RzILOpEffect` express
transitions from one virtual machine state to another. The state of the RzIL vm
consists of variables, binding values to names, and memories, which are arrays
of bitvectors indexed by bitvectors. An example of an effect op is `set n x`,
which sets the value of the variable `n` to the value that the pure expression
`x` evaluates to. The `seq` op allows composing a sequence of multiple effects
to be executed after each other, `branch` introduces conditional execution and
`repeat` enables looping.

Deviations from Core Theory
---------------------------

Core Theory is very tightly integrated into the BAP ecosystem and while
theoretically being reusable outside as-is, has certain properties that do not
translate well to our C implementation, which is where some deliberate
deviations were made.
The following paragraphs dive deeply into certain implementation details of BAP,
in order to distinguish them from RzIL, so basic knowledge of OCaml or other
ML-like languages is required. This chapter may not be relevant to users only
interested in RzIL.

### Typing

BAP makes heavy use of OCaml's strong type system to ensure well-typedness also
on the IL level. In particular, any Core Theory expression that is well-typed in
OCaml is automatically well-typed on the level of the IL.

As a specific example, BAP uses the OCaml type `'s bitv` to express pure
bitvector ops, where the size of the bitvector is statically given by the type
variable `'s`. This ensures for example that the op `add : 's bitv -> 's bitv ->
's bitv` will only be able to take bitvectors of identical size as operands and
return a bitvector of the same size as well. At the same time, it is possible to
have polymorphic ops such as the if-then-else `ite : bool -> 'a pure -> 'a pure
-> 'a pure` which can operate on both `bool` and `'s bitv` values (`bool` is an
alias for `Bool.t pure` and `'s bitv` is an alias for `'s Bitv.t pure`).

Replicating all of this is close to impossible using C's type system, so RzIL
partially relies on dynamic typing on C level, while still keeping static typing
on IL level. In C, RzIL statically separates `RzILOpPure` and `RzILOpEffect`,
but goes no further than that. The typedefs `RzILOpBitVector` and `RzILOpBool`
are mere aliases of `RzILOpPure` to indicate which type is meant whenever it is
known in the code. Further splitting is not possible while keeping ops like
`ite` polymorphic.

So far, this is only an implementation detail, but does not actually affect the
language itself. However, as there are also certain limitations of OCaml's type
system, our dynamic typing does open up other possibilities.

For instance, the `append` op is used for appending two bitvectors of arbitrary
sizes. Intuitively, the result's size would be the operands' numbers of bits
added together, motivating a signature that would look somewhat like this:
`append : 'b bitv -> 'c bitv -> ('b + 'c) bitv`. This however is simply not
possible in OCaml, so BAP resorts to specify the result size explicitly as an
argument and defines `append`'s semantics to apply an extra cast after
appending: `append : 'a Bitv.t Value.sort -> 'b bitv -> 'c bitv -> 'a bitv`.
This solves the problem of typing, but makes the op's semantics somewhat
more complicated.

In contrast, RzIL's `append` always has the resulting size as the sum of the
operand sizes, simplifying the semantics.

### Variables

Core Theory has three kinds of variables, which are categorized by the
definition of their [identifier
type](https://github.com/BinaryAnalysisPlatform/bap/blob/92d67c83fe0988b8a25bf563bdf33a9594db3e54/lib/bap_core_theory/bap_core_theory_var.ml#L20-L23):

```ocaml
type ident =
  | Var of {num : Int63.t (* ... *)}
  | Let of {num : Int63.t}
  | Reg of {name : String.Caseless.t (* ... *)}
```

`Reg` vars, identified by a string, which usually correspond to physical
registers of the emulated architecture, exist in the same way in RzIL as "global
variables". They are defined as part of the vm setup and their scope is
infinite.

`Let` vars, which are immutable variables occuring as part of the pure `let` op,
are implemented in a very similar way too. The only difference is that RzIL
again uses string identifiers instead of integers. Their scope is naturally
limited to the body of the `let` expression. As part of the RzIL vm, these
variables are called "local pure variables".

`Var` vars in Core Theory are so-called virtual variables, used mostly for
temporary scratch locations. Their scope is unlimited, but when an instruction
is lifted to Core Theory as part of the BAP Knowledge Base (this is
approximately a very innovative kind of database),
[fresh](https://github.com/BinaryAnalysisPlatform/bap/blob/92d67c83fe0988b8a25bf563bdf33a9594db3e54/lib/bap_core_theory/bap_core_theory_var.ml#L99-L101)
temporary variables are always chosen with a globally unique identifier, thus
automatically distinguishing temporary variables from multiple lifted
instructions. Without the Knowledge Base concept, this approach does not work
for RzIL. Instead, it has "local variables", which are defined simply by the
occurences of `set` ops for their names. Their scope is generally limited to a
single lifted instruction. Even though they are defined implcitly by `set` ops,
they are still typed statically and code with multiple `set` ops assigning
values of different types to the same identifier is considered invalid.

### Omitted Ops

Not every single Core Theory op has been implemented in RzIL so far. Some may be
implemented later when needed, others do not exist as "real" ops, but only have
a constructor function, composing it from other ops, like the current
implementation of [`unsigned`](https://github.com/rizinorg/rizin/blob/4487d7e1ac8ec0346f0f0b6f14dfdc7d5e424b34/librz/il/il_opcodes.c#L306-L309).
And some may be omitted completely, such as
[`concat`](http://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/Theory/module-type-Basic/index.html#val-concat),
as list operands would be rather awkward to handle in C.

Execution of real machine code
------------------------------

The bare IL described above is located in the `il` module. It comes with a
reference interpreter implemented as `RzILVM`, which may be used to evaluate
arbitrary pure and effect ops on a state of variables and memories. At this
point the IL does not have any connection to real architectures yet.

The `analysis` module then bridges exactly this gap. It provides the extended
`RzAnalysisILVM`, which directly builds on top of `RzILVM`, but adds the
connection to `RzIO` for memories, binding of IL variables to machine registers
and other related aspects.

An `RzAnalysisPlugin`, which is used to disassemble instructions of a specific
architecture, may also implement lifting from its raw machine code to RzIL in
its `op` callback.
In addition, it declaratively describes any architecture-specific info about
the global context in which this lifted code is meant to be executed by
implementing the `il_config` callback.
