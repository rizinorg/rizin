RzNum to RzIL lift: a reference by example
==========================================

`rz_il_lift_num()` (and the `RzCore` wrapper `rz_core_il_lift()`) turn an
RzNum expression into an `RzILOpPure` - the same pure-op value the rest
of RzIL is built from. This document shows, by example, exactly what the
lift produces for every feature of the expression language.

Each example is written as

    <expression>                => <lifted RzILOpPure, stringified>

where the right-hand side is the *exact* Unicode form the `pLf` command
prints, emitted by the RzIL exporter itself. A lifted expression and a
hand-written RzIL fragment of the same shape are therefore byte-for-byte
identical. Examples are evaluated with no *host bindings* - that is, no
program is supplying values for flags, registers, or memory, so a bare
identifier reads as zero. The *structure* of the lift is what matters
here; with a real host those lookups return real values, so the embedded
constants change while the structure stays the same. (What a host
binding is, and how a program supplies one, is covered in
`doc/math.md`.)


The one idea: lift or ground
----------------------------

Two terms run through this whole document, so here they are up front.
When the lifter meets an operator it does one of two things:

  * It **lifts structurally** (often shortened to "lifts") - the
    operator has a direct RzIL pure-op, so it stays in the output *as
    that operator* (`add`, `shiftl`, `ite`, ...) and the lifter recurses
    into its operands. "Structural" just means the shape is kept: `1 + 2`
    becomes `(0x1₆₄ + 0x2₆₄)`, still visibly an addition.
  * It is **grounded** - the operator has no RzIL counterpart, so the
    sub-expression is *evaluated to a constant* and that constant takes
    its place. `2 ** 8` becomes `0x100₆₄`, a plain number; the `**` is
    gone.

Grounding is always *local*: only the piece that lacks a pure-op
collapses, and the rest lifts as usual. One grounded function call
inside an arithmetic tree leaves the arithmetic intact - `min(5, 10) + 1`
is `(0x5₆₄ + 0x1₆₄)`, not a single folded constant. The "Quick
reference" at the end lists which operators land in which bucket.


Reading the output notation
---------------------------

The exporter's notation is compact; once these conventions are clear,
every example below reads at a glance:

  * **Subscript = bit width.** `0x1₆₄` is a 64-bit constant, `0x5₈` an
    8-bit one. A plain literal is 64-bit; a width suffix (`5u8`) sets it.
  * **Glyphs stand in for the pure-op** (full table below): `≪` / `≫`
    are the shifts, `≡` / `≦` the comparisons, `↠` the ternary, `−`
    unary minus, `~ & | ⊕` the bitwise ops.
  * **A shift carries a third operand, its fill bit:** `⊥` (false) for a
    logical `<<` / `>>`, `↑x` (the shifted value's top bit) for an
    arithmetic `sar`.
  * **Floats wear an `.f` suffix and a leading `rne` rounding-mode
    prefix:** `(rne 0x….f₆₄ + 0x….f₆₄)`.
  * **Parentheses mirror the parse exactly,** so precedence and
    associativity are visible directly in the shape.

Where a glyph would be ambiguous, or the exporter emits none, the ASCII
equivalent is given alongside.


Operator glyphs at a glance
---------------------------

| RzNum operator       | RzIL pure-op           | Unicode | ASCII   |
|----------------------|------------------------|---------|---------|
| `+` `-` `*`          | `add` `sub` `mul`      | `+` `-` `*` | `+` `-` `*` |
| `/` `%`              | `div` `mod`            | `/` `%` | `/` `%` |
| `sdiv` `smod`        | `sdiv` `smod`          | `/⁺` `%⁺` | `/+` `%+` |
| `&` `\|` `^`         | `logand` `logor` `logxor` | `&` `\|` `⊕` | `&` `\|` `^` |
| `<<` `>>` (logical)  | `shiftl` `shiftr`      | `≪` `≫` | `<<` `>>` |
| `sar` (arithmetic)   | `shiftr`, sign fill    | `≫` | `>>` |
| `==`                 | `eq`                   | `≡` | `==` |
| `<=` (unsigned)      | `ule`                  | `≦` | `<=` |
| `~`                  | `lognot`               | `~` | `~` |
| unary `-`            | `neg`                  | `−` | `-` |
| `? :` (ternary)      | `ite`                  | `↠` | `->` |

`<`, `>`, `>=`, `!=` and the rotates `<<<` / `>>>` have no single
RzIL pure-op glyph in the Unicode exporter, so they are grounded;
see the dedicated section further down.


Numeric literals and widths
---------------------------

A plain integer literal becomes a 64-bit bit-vector constant, with
the width written as a subscript:

    1 + 2                       => (0x1₆₄ + 0x2₆₄)
    0x10 - 0x05                 => (0x10₆₄ - 0x5₆₄)
    -5                          => −0x5₆₄
    +5                          => 0x5₆₄

A width-suffixed literal keeps its width, and the lift propagates
the per-operand width into the output:

    5u8 + 3u8                   => (0x5₈ + 0x3₈)
    0xffu16 & 0x0fu16           => (0xff₁₆ & 0xf₁₆)
    1u32 << 4u32                => (0x1₃₂ ≪ 0x4₃₂ ⊥)

Widths are not capped at 64 bits; a `u128` literal lifts to a 128-bit
constant just the same:

    1u128 << 4u128              => (0x1₁₂₈ ≪ 0x4₁₂₈ ⊥)

Operands of different widths each lift at their own width. The result
would still need a width cast to typecheck as RzIL, but the lift stays
faithful to what was written:

    5u8 + 1u16                  => (0x5₈ + 0x1₁₆)
    5 + 3u8                     => (0x5₆₄ + 0x3₈)

There is no implicit cast either way. Mixing bit-vector widths lifts
each operand at its own width (above); mixing an integer with a float
grounds instead (see Floats below). The evaluator-side rule is spelled
out under "Result kinds" in `doc/math.md`.


Arithmetic and bitwise
----------------------

Precedence and associativity are preserved by the lift, so the
parenthesisation in the output reflects the parse exactly:

    1 + 2 * 3                   => (0x1₆₄ + (0x2₆₄ * 0x3₆₄))
    (1 + 2) * 3                 => ((0x1₆₄ + 0x2₆₄) * 0x3₆₄)
    -(1 + 2)                    => −(0x1₆₄ + 0x2₆₄)

Bitwise operators map directly:

    0xff & 0x0f                 => (0xff₆₄ & 0xf₆₄)
    0xa | 0x5                   => (0xa₆₄ | 0x5₆₄)
    0xa ^ 0x5                   => (0xa₆₄ ⊕ 0x5₆₄)
    ~0xff                       => ~0xff₆₄

Shifts lift structurally. RzIL's shift carries an explicit fill bit as
a third operand; a logical `<<` / `>>` fills with `⊥` (false):

    1 << 4                      => (0x1₆₄ ≪ 0x4₆₄ ⊥)
    0x100 >> 4                  => (0x100₆₄ ≫ 0x4₆₄ ⊥)

Division and modulo, signed and unsigned:

    10 / 3                      => (0xa₆₄ / 0x3₆₄)
    10 % 3                      => (0xa₆₄ % 0x3₆₄)
    10 sdiv 3                   => (0xa₆₄ /⁺ 0x3₆₄)
    10 smod 3                   => (0xa₆₄ %⁺ 0x3₆₄)
    256 sar 2                   => (0x100₆₄ ≫ 0x2₆₄ ↑0x100₆₄)

`sar` (arithmetic right shift) is the same `shiftr` op with the shifted
value's top bit `↑x` as the fill, so the sign is propagated instead of
zero-filled.

The signed family also lifts structurally on bit-vectors, carrying
the declared width through:

    0xffu8 sdiv 2u8             => (0xff₈ /⁺ 0x2₈)
    0xfeu8 sar 1u8              => (0xfe₈ ≫ 0x1₈ ↑0xfe₈)


Comparisons
-----------

`==` and `<=` (unsigned) have direct RzIL pure-ops and lift
structurally:

    1 == 1                      => (0x1₆₄ ≡ 0x1₆₄)
    5 <= 10                     => (0x5₆₄ ≦ 0xa₆₄)

`<`, `>`, `>=`, `!=` compose from `eq`, `ule` and `lognot` in RzIL
proper but have no single glyph the Unicode exporter emits, so the
lift evaluates them to a one-bit ut64 constant rather than building
the composite. The truth value still survives - it just arrives as
a literal:

    5 < 10                      => 0x1₆₄
    5 > 3                       => 0x1₆₄
    5 >= 4                      => 0x1₆₄
    5 != 6                      => 0x1₆₄

The same is true for `!`:

    !5                          => 0x0₆₄
    !0                          => 0x1₆₄
    !(5 > 3)                    => 0x0₆₄


The ternary `c ? a : b` (RzIL `ite`)
------------------------------------

The conditional is the one control-flow construct in the language
that has a direct RzIL pure-op, so the whole construct lifts
structurally and *both* branches survive into the output. The
exporter's notation is `(cond ↠ then else)`:

    1 ? 10 : 20                 => (0x1₆₄ ↠ 0xa₆₄ 0x14₆₄)

A condition that itself lifts (`==`, `≦`) stays structural, so the
shape of the decision is preserved end-to-end. With a condition
that has to be grounded (`>`, `<`, ...), only the condition
collapses; the surrounding `ite` is still there:

    len(0xffu16) == 16 ? 0xaa : 0xbb
                                => ((0x10₆₄ ≡ 0x10₆₄) ↠ 0xaa₆₄ 0xbb₆₄)
    5 > 3 ? 100 : 200           => (0x1₆₄ ↠ 0x64₆₄ 0xc8₆₄)
    double(10) > 15 ? 1 : 0     => (0x1₆₄ ↠ 0x1₆₄ 0x0₆₄)

The branches can be arbitrary sub-expressions and lift in full:

    1 ? 2 + 3 : 4 * 5           => (0x1₆₄ ↠ (0x2₆₄ + 0x3₆₄) (0x4₆₄ * 0x5₆₄))
    x > 0 ? x + 1 : x - 1       => (0x0₆₄ ↠ (0x0₆₄ + 0x1₆₄) (0x0₆₄ - 0x1₆₄))

Right-associativity threads naturally into nested `ite`s:

    a ? b : c ? d : e           => (0x0₆₄ ↠ 0x0₆₄ (0x0₆₄ ↠ 0x0₆₄ 0x0₆₄))
    a > 10 ? b : a > 5 ? c : a > 0 ? d : e
                                => (0x0₆₄ ↠ 0x0₆₄ (0x0₆₄ ↠ 0x0₆₄ (0x0₆₄ ↠ 0x0₆₄ 0x0₆₄)))

And the ternary composes with the rest of the language:

    (x > 0 ? x : -x) + 1        => ((0x0₆₄ ↠ 0x0₆₄ −0x0₆₄) + 0x1₆₄)


Compositions and depth
----------------------

There is no depth limit beyond the evaluator's node budget; the lift
preserves whatever the parse tree gives it. Examples worth seeing
in their full shape:

    (1 + 2) * (3 + 4) - (5 << 1)
                                => (((0x1₆₄ + 0x2₆₄) * (0x3₆₄ + 0x4₆₄)) - (0x5₆₄ ≪ 0x1₆₄ ⊥))

    (0xff & 0xf0) | (0x0f << 4)
                                => ((0xff₆₄ & 0xf0₆₄) | (0xf₆₄ ≪ 0x4₆₄ ⊥))

    ((a + b) * 2) sar 1         => (((0x0₆₄ + 0x0₆₄) * 0x2₆₄) ≫ 0x1₆₄ ↑((0x0₆₄ + 0x0₆₄) * 0x2₆₄))


Identifiers, host variables, assignment
---------------------------------------

A bare identifier is resolved by the host - in rizin's `%` that means
the flag and register tables - when a host is present; with none it
reads as zero. Either way the lift embeds the resolved value as a
constant, so the variable name does not survive into RzIL:

    a + b                       => (0x0₆₄ + 0x0₆₄)
    x = 5                       => 0x5₆₄

The zeros above are just the no-host default. In a real session the
host supplies values: if the register `rax` holds `0x1000` and the flag
`main` sits at `0x400500`, the same lift embeds those instead -

    rax + main                  => (0x1000₆₄ + 0x400500₆₄)

An assignment expression has the value of its right-hand side and
lifts to that value. The binding side effect itself has no RzIL
counterpart in this lift - the rest of the expression (or a later
statement, see below) reads the bound value at lift time and embeds
it directly:

    a = 1; b = 2; a + b * 3     => 0x7₆₄

A binding that is fully known at lift time collapses the expression
that uses it - even a ternary, because its condition then evaluates to a
constant the lift can fold away:

    x = 5; x > 3 ? x : 0        => 0x5₆₄
    a = 5; b = 10; a < b ? a : b
                                => 0x5₆₄

The ternary's structure survives only when the condition is something
the lift *cannot* see through - an unbound host variable, say - so the
decision genuinely has to be deferred to run time:

    x > 0 ? x + 1 : x - 1       => (0x0₆₄ ↠ (0x0₆₄ + 0x1₆₄) (0x0₆₄ - 0x1₆₄))


Statement sequencing
--------------------

A `;`-separated sequence has no RzIL pure-op form, so it is grounded
to its final value. Earlier bindings are honoured during that
grounding:

    1 + 2; 3 + 4                => 0x7₆₄
    a = 1; b = 2; a + b * 3     => 0x7₆₄


Functions, both built-in and host-registered
--------------------------------------------

Function calls are grounded to a constant - none of the built-ins
(`min`, `max`, `abs`, `popcount`, `len`, and the Unicode aliases) has
a direct RzIL pure-op:

    min(5, 10)                  => 0x5₆₄
    max(min(3,7), 5)            => 0x5₆₄
    popcount(0xff)              => 0x8₆₄
    len(0xffu16)                => 0x10₆₄
    len("ABCD")                 => 0x20₆₄

Grounding happens per call, so a built-in is reduced to a constant
*and then* the surrounding operators lift around it:

    min(5,10) + max(1,2)        => (0x5₆₄ + 0x2₆₄)
    len(0xffu16) * 8            => (0x10₆₄ * 0x8₆₄)

The same applies to host-registered functions through
`RzNumFuncRegistry` (see "Host-registered functions" in `doc/math.md`
for how a program registers one). With a registry that defines
`double(n) -> 2n`:

    double(21) + 1              => (0x2a₆₄ + 0x1₆₄)
    double(10) > 15 ? 1 : 0     => (0x1₆₄ ↠ 0x1₆₄ 0x0₆₄)

A Unicode-named function is lifted the same way:

    минимум(7, 3)               => 0x3₆₄

A host function that fails to ground (typically because no
appropriate callback is supplied at lift time) produces a clear
error:

    crc(0, 4)
        cannot ground sub-expression: unknown function: crc


Typed-address dereferences
--------------------------

A typed read such as `addr:le32` / `:be64` / `:s32` / `:f32` behaves
one of two ways. When an IO layer is present - evaluating through `%`
in a session with bytes mapped at `addr` - it reads memory, and the
value read is grounded into the output. With no IO layer - the plain
lift API, or an address with nothing mapped - the suffix is parsed but
the address itself passes through unchanged. Either way the result is a
single grounded constant; whether there is data at `0x1000` only
changes *which* constant it is:

    0x1000:le32                 => 0x1000₆₄
    0x1000:s32                  => 0x1000₆₄
    0x1000:f32                  => 0x1000₆₄
    0x1000:128                  => 0x1000₆₄
    0x1000:f128                 => 0x1000₆₄

(Those are the no-IO pass-through values; with bytes mapped they would
be the decoded reads instead.) A `:128` or `:f128` read produces a
width-128 bit-vector when IO is present. `:f128` returns the raw 128
bits, not a decoded quad-precision float - RzNum's float type is always
a 64-bit double.

When combined with structural operators:

    0:le32 + 1                  => (0x0₆₄ + 0x1₆₄)


Power, log, rotates
-------------------

`**`, `log` and the bitwise rotates `<<<` / `>>>` have no direct
RzIL pure-op in the bit-vector sort and are grounded:

    2 ** 8                      => 0x100₆₄
    16 log 2                    => 0x0₆₄
    1 <<< 4                     => 0x10₆₄
    1 >>> 4                     => 0x1000000000000000₆₄

The bit-vector versions ground the same way, but the constants
carry their declared width:

    0x12u8 <<< 4                => 0x21₈
    2u8 ** 4u8                  => 0x10₈
    2u32 log 8u32               => 0x3₃₂

Grounding evaluates `**` and `log` the way the evaluator does, in
`double` precision. A small power is exact, but a power whose result is
too large for a `double` collapses to zero or infinity. So the lift
does *not* preserve an exact big-number power: when `**` sits inside an
enclosing operator, the grounded value is a truncated ut64:

    2 ** 100                    => 0x0₆₄
    (2 ** 100) + 1              => (0x0₆₄ + 0x1₆₄)
    (2 ** 100) - (2 ** 99)      => (0x0₆₄ - 0x0₆₄)

For an exact big-number power, evaluate the expression directly
through `rz_num_math_value`; this is a documented limit of the lift,
not of the evaluator.


Floats
------

A numeric literal containing a `.` or scientific-notation exponent
is lifted as an IEEE-754 double-precision constant - "0x<bits>.f64"
in the RzIL exporter's notation, where `<bits>` is the bit-vector
representation of the value. Float-pure arithmetic (both operands
float) lifts to the RzIL float-binop form, with the leading
rounding-mode prefix that distinguishes the float family from the
bit-vector family:

    1.5 + 2.5                   => (rne 0x3ff8000000000000.f₆₄ + 0x4004000000000000.f₆₄)
    1.0 / 2.0                   => (rne 0x3ff0000000000000.f₆₄ / 0x4000000000000000.f₆₄)
    3.14 * 2.0                  => (rne 0x40091eb851eb851f.f₆₄ * 0x4000000000000000.f₆₄)

The rounding mode is always `rne` (round-nearest-even, IEEE-754's
default); RzNum has no syntax for choosing one. Every RzNum float is a
64-bit double, so both operands are always `.f₆₄`; the language has no
32-bit float *value* (even a `:f32` memory read is widened to a
double).

Mixed integer / float arithmetic is grounded rather than fabricating
an implicit cast the user did not write:

    1 + 2.5                     => 0x3₆₄
    3.14 * 2                    => 0x6₆₄

For a float-conditioned ternary, RzIL's `ite` needs a Bool, but a
float is not one. The lift bridges this in two steps. First it turns
the float condition `f` into the Bool `f ≡ 0` (this is `is_fzero`).
That test is inverted, though: `f ≡ 0` is true exactly when `f` is
zero - the case where the evaluator takes the *else* branch. So,
second, the lift swaps the two branches, and the form reads
`(f ≡ 0 ↠ else then)`. The two inversions cancel, reproducing the
evaluator's rule that a non-zero float is true:

    0.5 ? 7 : 8                 => (0x3fe0000000000000.f₆₄ ≡ 0 ↠ 0x8₆₄ 0x7₆₄)
    0.0 ? 7 : 8                 => (0x0.f₆₄ ≡ 0 ↠ 0x8₆₄ 0x7₆₄)

So under the lift `0.5` picks the `7` branch and `0.0` picks the
`8` branch, matching the evaluator.

When both branches are float as well, the branches lift in their
own float form:

    0.5 ? 1.5 : 2.5             => (0x3fe0000000000000.f₆₄ ≡ 0 ↠ 0x4004000000000000.f₆₄ 0x3ff8000000000000.f₆₄)

The typed-read `:fN` suffix is still grounded by the lift, because
the kind it produces depends on whether an IO callback is wired at
read time. Mixing `addr:f32` with a float literal therefore grounds
the whole expression rather than emitting a half-typed structural
form.


Quick reference: what lifts, what grounds
-----------------------------------------

Lifts structurally:
  * arithmetic `+ - * / %`, signed `sdiv smod sar`;
  * bitwise `& | ^ ~`;
  * shifts `<< >>`;
  * unary `- +`;
  * comparisons `==` and `<=`;
  * ternary `? :` (`ite`), with `is_fzero` wrapping when the condition
    is a float;
  * float-pure arithmetic `+ - * /` (rendered with the `rne` rmode
    prefix and `.f₆₄` operand suffixes);
  * float literals (rendered as `0x<bits>.f₆₄`).

Always grounded to a constant (because RzIL has no matching
bit-vector pure-op in the Unicode exporter, or no pure-op at all):
  * comparisons `< > >= !=`, logical `!`;
  * power `**`, logarithm `log`;
  * rotates `<<<` `>>>`;
  * mixed integer-and-float arithmetic (no implicit cast is invented);
  * float modulo `%` (no direct RzIL pure-op in the exporter for
    `fmod`);
  * `len`, `popcount`, `min`, `max`, `abs`, and any host-registered
    function;
  * typed-address dereferences `addr:T`;
  * `;`-separated sequences.

Where a sub-expression has to be grounded, only that sub-expression
collapses - the structure around it lifts as usual, so a single
non-structural piece does not destroy the surrounding form.
