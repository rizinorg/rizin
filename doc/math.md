RzNum Expression Language
=========================

The `RzNum` evaluator parses and computes mathematical expressions
used throughout Rizin. Every place that accepts a numeric argument
(`%`, `rz-ax`, the `?v` command, flag offsets, seek targets, ...)
funnels through the same grammar and the same evaluator.

This document describes the surface language as users see it.
For consumers of the C API see the doxygen comments on
`rz_num_math_value()`, `rz_num_math_value_ex()`, `rz_core_math()`,
and the helpers `rz_num_value_to_ut64()` / `rz_num_value_print()`.


Numeric literals
----------------

| Form                           | Meaning                          | Example      |
|--------------------------------|----------------------------------|--------------|
| `123`                          | decimal                          | `42`         |
| `0x1a` / `0X1A`                | hexadecimal                      | `0xdeadbeef` |
| `0b1010` / `0B1010`            | binary                           | `0b101010`   |
| `0o17` / `0O17`                | octal                            | `0o755`      |
| `0t102` / `0T102`              | ternary (base 3)                 | `0t1102`     |
| `3.14`                         | decimal float                    | `1.5`        |
| `1.5e3`                        | decimal float with exponent      | `1.0e-3`     |
| `0x1p10`                       | hex float (binary exponent)      | `0x1p-4`     |

A literal in any base may be followed by an IEC byte unit suffix to
multiply by the matching power of two:

| Suffix              | Multiplier  |
|---------------------|-------------|
| `KiB`               | 1024        |
| `KB`                | 1000        |
| `MiB` / `MB`        | 1024^2 / 1000^2 |
| `GiB` / `GB`        | 1024^3 / 1000^3 |
| `TiB` / `TB`        | 1024^4 / 1000^4 |
| `PiB` / `PB`        | 1024^5 / 1000^5 |
| `EiB` / `EB`        | 1024^6 / 1000^6 |

Examples: `4KiB`, `2MiB`, `1.5GB`. Float values accept units too.

A literal that does not fit in a 64-bit unsigned integer is
automatically promoted to an arbitrary-precision big number (kind
`RZ_NUM_KIND_BIG`). This works for every supported base, not just
hexadecimal:

    % 0x10000000000000000              -> bignum 0x10000000000000000
    % 99999999999999999999999999       -> bignum 0x52b7d2dcc80cd2e3ffffffff
    % 0b100000000000000000000000000000000000000000000000000000000000000000
                                       -> bignum 0x20000000000000000

When arithmetic on a big number produces a result that fits back
inside `ut64`, the value is demoted automatically.

A literal followed by a `u` plus a bit-width - `u8`, `u16`, `u32`,
`u64`, `u128` - is a fixed-width *bit-vector* (kind
`RZ_NUM_KIND_BITVECTOR`). Bit-vectors do modular arithmetic at their
width, so they overflow by wrapping rather than promoting:

    % 5u8                  -> width 8,  0x05
    % 200u8 + 100u8        -> width 8,  0x2c   (300 mod 256)
    % 0xffu8 + 1u8         -> width 8,  0x00   (wraps)
    % 10u16 * 10u16        -> width 16, 0x0064

A bare letter run with no width (`5u`, `10ul`, `3.0f`) is
informational only and does not change the kind. See the
"Bit-vectors" section below for the operations defined on them.


Identifiers
-----------

A bare identifier is looked up as a variable through the host's
`RzNum` callback. In the shell this is the flag table: typing
`% entry0` evaluates to the address of `entry0`. Unknown
identifiers resolve to zero (matching the legacy behaviour).

Identifier characters are everything that is not a control
character, whitespace, operator, bracket, quote, comma, semicolon,
backslash, dollar sign, or a digit (as the first character). This
includes any non-ASCII Unicode letter; identifiers may be written
in any script.

### Reserved words

These seven words are operator keywords and cannot be assigned to. Each
is meaningful only in its operator position:

| Word(s)               | Operator position                          |
|-----------------------|--------------------------------------------|
| `mod`, `log`          | binary operator: `x mod y`, `x log y`      |
| `sdiv`, `smod`, `sar` | signed operator: `x sdiv y`, `x sar y`     |
| `le`, `be`            | endianness in a typed read: `0x1000:le32`  |

Every other identifier, in any script, is a free variable name.


Special variables
-----------------

`$`-prefixed names are a closed set drawn from the canonical list
used by the `%v` (legacy `?v`) command:

    $$    current offset                $$$  alias for $$
    $b    block size                    $B   block size in bytes
    $F    function start at $$          $Ff  function end at $$
    $Fj   function jump at $$           $Fb  function basic block at $$
    $FB   function basic block end      $Fi  next instruction
    $FS   function size                 $fl  flag size at $$
    $S    section start                 $SS  section size
    $D    debug map start               $DB  debug map end
    $DD   debug map size                $DS  debug map permissions
    $c    column / cursor               $Cn  comment by index
    $alias  alias map                   $e   end of execution
    $f    fail-jump address             $j   true-jump address
    $Ja   analysis jump address
    $l    last instruction length       $M   map count
    $MM   address space size            $m   memory size
    $O    current opcode address        $o   opcode size
    $p    PID                           $P   parent PID
    $r    return value register         $s   stack pointer
    $v    value                         $w   word size

An unknown `$`-name is a parse error (since the rule is a closed
list), not an evaluator error.


Variable bindings
-----------------

`x = y` and `let x = y` bind the identifier `x` to the value of `y`
and evaluate to that value. The two forms are identical; `let` is an
optional keyword with no separate scoping. The binding is visible to
the rest of the current expression, so a later part can read it back:

    (x = 7) + x              -> 14
    (a = 2) * (a + 1)        -> 6
    (c = 1) + (c = 9) + c    -> 19    (reassignment updates the binding)

A local binding shadows a host variable (flag / special variable)
of the same name. Bound values keep their kind, so a bound big
number stays exact. The reserved words (see the Reserved words table
above) cannot be assigned.

With the statement separator `;` (see below) bindings can be
introduced and reused without the parenthesis trick:

    let radius = 5; let area = radius * radius; area    -> 25
    bla = crc(0, 4); 0:be32 + bla

Persistence across evaluations is opt-in. By default a binding lives
for a single evaluation. If the caller supplies a persistent variable
store (`RzNumMathOptions.vars`, created with `rz_num_value_store_new()`),
bindings written by one evaluation remain visible to later ones that
share the store. The `%` shell command uses such a store, so a
variable bound in one `%` invocation is visible to the next:

    [0x0]> % bla = crc(0, 4)
    [0x0]> % 0:be32 + bla     <- 'bla' still bound here


Statement sequencing
--------------------

Several expressions can be chained with `;`. Each is evaluated in
order (so bindings made by earlier statements are visible to later
ones) and the value of the whole is the value of the last statement.
A trailing `;` is allowed.

    1 + 2; 3 + 4             -> 7
    x = 10; y = 20; x + y    -> 30
    a = 3; b = a * a; a + b  -> 12
    a = 3; b = a * a; a + b; -> 12   (a trailing ; is allowed)


Operators
---------

In order from highest precedence to lowest. All operators are
left-associative except exponentiation, which is right-associative.

    Unary prefix:    +x   -x   !x   ~x   ++x   --x
    Exponent:        x ** y    (right-associative)
    Mul-class:       x * y    x / y    x % y    x mod y
                     x sdiv y    x smod y    (signed division / remainder)
    Add-class:       x + y    x - y
    Shifts:          x << y   x >> y   x <<< y   x >>> y   x sar y
                     (<<< and >>> are bitwise rotates on the low 64 bits;
                      sar is the sign-propagating arithmetic shift right)
    Bitwise AND:     x & y
    Bitwise XOR:     x ^ y
    Bitwise OR:      x | y
    Comparison:      x < y    x <= y   x > y    x >= y
    Equality:        x == y   x != y
    Conditional:     c ? a : b    (ternary, right-associative)
    Logarithm:       x log y      (computes log_x(y))
    Assignment:      x = y    let x = y    (binds x, evaluates to y)

Notes:

- Division and modulo with a zero right-hand side raise
  `RZ_NUM_ERR_DIV_ZERO` (for both the unsigned `/` `%` and the signed
  `sdiv` `smod`).
- `sdiv`, `smod` and `sar` interpret their operands as two's-complement
  signed 64-bit values. `/`, `%` and `>>` are unsigned. For example
  `-5 sdiv 2` is `-2` while `0xfffffffffffffffb / 2` is a large
  positive number; `0xffffffffffffff00 sar 4` sign-extends to
  `0xfffffffffffffff0` whereas `>> 4` does not.
- Rotations `<<<` and `>>>` on a `ut64` or big number rotate a 64-bit
  projection of the operand (a big number has no width-independent
  rotate). On a *bit-vector* they rotate within that value's own width
  instead - see the Bit-vectors section.
- `**` and `log` are computed in `double`. An integer `**` with a small
  exponent is still exact (it promotes to a big number); otherwise the
  result is a `float`. For an exact bignum power use repeated
  multiplication.
- `~` (bitwise NOT) on a big number projects to `ut64` first, since
  the complement of an arbitrary-precision integer is not defined
  without a fixed width.
- The ternary `c ? a : b` is right-associative, so
  `a ? b : c ? d : e` parses as `a ? b : (c ? d : e)`. It
  short-circuits: only the taken branch is evaluated, so
  `b != 0 ? a / b : 0` is safe even when `b` is zero. The
  condition's truthiness is per-kind - non-zero ut64/big/bit-vector
  is true; a float is tested as a float, so `0.5 ? a : b` is `a`
  but `0.0 ? a : b` is `b`. The selected branch keeps its own kind,
  including bit-vectors and big numbers. The ternary is also the one
  control-flow construct that lifts structurally to RzIL, mapping
  directly onto `ite`.

Comparisons and equality return `1` (true) or `0` (false) as a
`ut64`.


Typed address syntax
--------------------

A literal address can be followed by a colon and a typed suffix
describing the read width, signedness, endianness, and whether the
bytes are an integer or a float:

    0x1000:le32     read a 32-bit little-endian unsigned word
    0x1000:be64     read a 64-bit big-endian unsigned word
    0x1000:8        read 8 bits (1 byte), native endianness
    0x1000:s32      read a 32-bit SIGNED word (sign-extended)
    0x1000:lef32    read a 32-bit little-endian IEEE-754 float
    0x1000:f16      read a native-endian half-precision float
    0x1000:f64      read a double-precision float
    0x1000:128      read a 128-bit value, returns a bit-vector
    0x1000:f128     read a 128-bit IEEE-754 quad, raw bits as a bit-vector

The suffix grammar is `[le|be]? [s]? width` for integers (`width`
one of 8/16/32/64/128) or `[le|be]? f (16|32|64|128)` for floats.
An `s` marks a signed integer read (the value is sign-extended to
the result); an `f` marks an IEEE-754 float read.

The result kind follows the requested width:

  * widths up to 64 bits return a `ut64` (integer) or `double`
    (float); the float decoder handles f16 / f32 / f64 directly;
  * 128-bit reads (`:128` and `:f128`) return a width-128
    bit-vector. Two underlying 64-bit reads are stitched into the
    bit-vector in the requested endianness, so `:128` and `:f128`
    both preserve every bit. RzNum's float kind itself is
    double-precision, so `:f128` does NOT decode to a native
    quad-precision float; the bit-vector carries the raw 128-bit
    IEEE-754 pattern and the host can inspect it, compare two
    quad values bit-for-bit, or feed it to a host function that
    knows how to print quad-precision.

When evaluated through `rz_core_math()` (which backs the `%` shell
command) the suffix dereferences against the active IO layer:

    [0x0]> % 0:le32          (on an ELF)
    hex     0x464c457f       <- little-endian read of 7f 45 4c 46
    [0x0]> % 0:s32           <- same bytes, interpreted signed
    [0x0]> % 0:lef32         <- same bytes, interpreted as a float
    [0x0]> % 0:128           <- 16 bytes as a width-128 bit-vector

When evaluated through the bare `rz_num_math_value()` API with no
IO-read callback wired in, the suffix is parsed but the literal
address is returned unchanged (parity across every width).


String-as-bytes literal
-----------------------

A double-quoted string is interpreted as a sequence of bytes packed
little-endian (first byte is the least-significant) into a bit-vector
whose width is `8 * byte-count`. Supported escapes: `\\`, `\"`, `\n`,
`\t`, `\r`, `\0`, `\xHH`.

    "AB"        -> 0x4241        bit-vector, width 16 ('A' in the low byte)
    "ABCD"      -> 0x44434241    bit-vector, width 32
    "\x01\xff"  -> 0xff01        bit-vector, width 16

The bytes are taken verbatim, so a string written in any script is
packed as its raw UTF-8 source bytes. Because the result is a
bit-vector that carries its width, the byte count is recoverable with
`len` (see below):

    len("ABCD")        -> 32     (bits)
    len("ABCD") / 8    -> 4      (bytes)
    len("ABCDEFGHIJ")  -> 80     (a 10-byte string is fine)
    len("Ω")           -> 16     ("Ω" is two UTF-8 bytes)

Arithmetic on a string value follows bit-vector rules at that width,
so `"AB" + 1` is `0x4242` (it wraps within 16 bits). An empty string
`""` is the zero-width edge case and evaluates to a `ut64` `0`.


Built-in functions
------------------

| Function                       | Arity | Description                            |
|--------------------------------|-------|----------------------------------------|
| `min(a, b)`                    | 2     | smaller operand, kind-preserving       |
| `max(a, b)`                    | 2     | larger operand, kind-preserving        |
| `abs(x)`                       | 1     | absolute value                         |
| `popcount(x)`                  | 1     | number of set bits (works on bignums)  |
| `len(x)`                       | 1     | length in BITS of a bit-vector / big / ut64 (a string literal is a bit-vector, so `len(s)/8` is its byte count) |
| `минимум(a, b)`                | 2     | alias for `min` (Russian)              |
| `максимум(a, b)`               | 2     | alias for `max` (Russian)              |
| `最小(a, b)` / `最大(a, b)`    | 2     | aliases for `min` / `max` (Chinese/Japanese) |
| `دالة(x)`                      | 1     | alias for `abs` (Arabic)               |
| `Σ(x)`                         | 1     | alias for `popcount` (Greek sigma)     |

`len` gives a single, bit-keyed notion of length across the
integer-ish kinds: a bit-vector reports its declared width, a big
number its exact significant bit width, a `ut64` its significant
bit width (`len(0)` is 0). Since a string-as-bytes literal is a
bit-vector of `8 * byte-count` bits, `len("ABCD")` is 32 and
`len("ABCD") / 8` is the byte count 4. `len` on a float is a type
error.

The Russian aliases exist as a runnable demonstration that
identifier handling is Unicode-clean end to end; new natural-
language aliases land in `librz/util/num/evaluator.c`
without grammar changes.

`**` computes an exact integer power when both operands are
integers and the exponent is a non-negative integer no larger than
4096; the result promotes to a big number when it exceeds `ut64`.
Otherwise (float operand, negative or oversized exponent) it falls
through to a `double` computation.

    % 2 ** 64        ->  decimal 18446744073709551616  (exact)
    % 2 ** 0.5       ->  float   1.41421                (double path)

Host-registered functions
--------------------------

A host can register additional functions through the C API without
modifying the grammar or the evaluator. The function appears in the
expression language exactly like a built-in; registered names take
precedence over the built-in table, so a host may also shadow one.

Through `rz_core_math()` (which backs the `%` shell command) Rizin
registers a set of functions that read bytes through the active IO
layer (bounded to 64 KiB per call) and compute over them:

| Function                  | Arity | Result | Description                              |
|---------------------------|-------|--------|------------------------------------------|
| `md5(addr, n)`            | 2     | bignum | MD5 digest                               |
| `sha1(addr, n)`           | 2     | bignum | SHA-1 digest                             |
| `sha256(addr, n)`         | 2     | bignum | SHA-256 digest                           |
| `sha384(addr, n)`         | 2     | bignum | SHA-384 digest                           |
| `sha512(addr, n)`         | 2     | bignum | SHA-512 digest                           |
| `adler32(addr, n)`        | 2     | ut64   | Adler-32 checksum                        |
| `xxhash(addr, n)`         | 2     | ut64   | xxHash32                                 |
| `hash(addr, n)`           | 2     | bignum | alias for `sha256`                       |
| `crc(addr, n [, width])`  | 2-3   | ut64   | CRC; width 8/16/32/64, default 32        |
| `crc8/crc16/crc32/crc64`  | 2     | ut64   | explicit CRC-width aliases               |
| `entropy(addr, n)`        | 2     | float  | Shannon entropy, 0.0 - 8.0               |
| `temperature(addr, n)`    | 2     | float  | information temperature                  |

The CRC family deliberately lives behind one `crc()` name with an
optional width parameter rather than separate per-width entry
points:

    % crc(0, 16)         # CRC-32 (default)
    % crc(0, 16, 16)     # CRC-16
    % crc(0, 16, 64)     # CRC-64

Digest results are returned as big numbers laid out big-endian so
the hex form matches the `ph <algo>` command:

    [0x0]> % sha256(0, 16)
    decimal 72468553576780861412383346668577895435178167241169020037740589910276139146126
    hex     0xa037bf6e958bd6b2fdcc4a95c7dc6f7735730ae33d20819a056a5da050d05b8e
    width   256 bits (approx)

To register your own function, create a registry, add entries, and
pass it through `RzNumMathOptions.funcs`:

    RzNumFuncRegistry *reg = rz_num_func_registry_new();
    rz_num_func_registry_add(reg, "myfn", 1, my_callback, my_userdata);
    RzNumMathOptions opt = { .funcs = reg };
    rz_num_math_value_ex(num, expr, &opt, &out, &err);
    rz_num_func_registry_free(reg);

`rz_num_func_registry_add(reg, name, arity, fn, user)`:

  * `name` is copied as UTF-8, so a function may be registered under
    any identifier the grammar accepts - including a non-ASCII
    (Unicode) name. For example a function registered as `минимум`,
    `合计`, or `δ` is then callable by that exact name:

        rz_num_func_registry_add(reg, "сумма", -1, sum_cb, NULL);
        // expression:  сумма(1, 2, 3)   ->  6

  * `arity` is the exact number of arguments the function requires,
    or `-1` for a variadic function that accepts any number of
    arguments. A call whose argument count does not match a
    non-negative `arity` fails with `RZ_NUM_ERR_NOT_IMPLEMENTED`
    before the callback runs. There is no upper bound on the number
    of arguments a variadic function may receive:

        rz_num_func_registry_add(reg, "сумма", -1, sum_cb, NULL);
        // сумма(1,2,3,4,5,6,7,8,9,10)   ->  55

  * registered names are consulted *before* the built-in table, so a
    registration shadows a built-in of the same name. This is how a
    host can, for instance, replace the 2-argument built-in `min`
    with a variadic one.

The callback has the signature:

    void my_callback(void *user, const RzNumValue *args, int argc,
                     RzNumCallbackResult *out);

It receives the opaque `user` pointer from registration, the
already-evaluated `args` (each carrying its own kind) with their
count `argc`, and fills an `RzNumCallbackResult` with a kind, a
payload, and an `ok` flag. Setting `ok` to false makes the
expression fail with `RZ_NUM_ERR_UNCOMPUTABLE`. A big-number or
bit-vector payload transfers ownership to the evaluator.


Result kinds
------------

Every evaluation produces an `RzNumValue` carrying a *kind* and a
payload:

| Kind                       | Payload     | Produced by                       |
|----------------------------|-------------|-----------------------------------|
| `RZ_NUM_KIND_UT64`         | `ut64 n`    | integer literals, comparisons, ...|
| `RZ_NUM_KIND_FLOAT`        | `double d`  | float literals, `**`, `log`       |
| `RZ_NUM_KIND_BIG`          | `RzNumBig*` | overflowing integer literals      |
| `RZ_NUM_KIND_BITVECTOR`    | `RzBitVector*` | width-suffixed literals (`5u8`)   |

When a sub-expression mixes kinds, the more general kind wins:

    ut64 + ut64       -> ut64
    ut64 + big        -> big   (or demoted ut64 if the result fits)
    ut64 + float      -> float
    big  + float      -> float (big projected to double)

There is no cast operator and no implicit C-style cast, so a mixed
expression never *fails* for want of a cast - it promotes by the rule
above. Mixing bit-vector *widths* is the one case that does not
promote: the operand width is kept and the other side is taken modulo
that width (see Bit-vectors). To pin a value to a specific width or
kind, write the literal you want (`5u32` for a 32-bit bit-vector) or
read it through a typed address.

The `%` shell command and `rz-ax` use the result kind to choose an
output layout (multi-base table for `ut64`, decimal scientific +
hex bit pattern for `float`, exact decimal + hex + bit-width for
`big`, and width + hex + binary for a bit-vector).


Bit-vectors
-----------

A width-suffixed literal (`5u8`, `0xffu16`, `0x123456789abcu64`)
evaluates to a bit-vector of exactly that width. Unlike `ut64` and
`big`, a bit-vector never changes width during arithmetic: every
operation is computed modulo `2^width`, so results wrap instead of
promoting.

Operations defined on bit-vectors:

| Operators                | Result      | Notes                            |
|--------------------------|-------------|----------------------------------|
| `+` `-` `*` `/` `%`      | bit-vector  | modular at the operand width; `/` or `%` by zero is `RZ_NUM_ERR_DIV_ZERO` |
| `sdiv` `smod` `sar`      | bit-vector  | two's-complement signed at the operand width; zero divisor is `RZ_NUM_ERR_DIV_ZERO` |
| `&` `\|` `^`             | bit-vector  | bitwise                          |
| `<<` `>>`                | bit-vector  | shift by the low bits of the right operand |
| `<<<` `>>>`              | bit-vector  | rotate within the operand width (bits that fall off one end wrap to the other); the rotate amount is taken modulo W |
| `**`                     | bit-vector  | exponentiation by squaring, modular at the operand width (so `2u8 ** 8u8` wraps to `0`); the exponent must fit a `ut64` |
| `log`                    | bit-vector  | `log_a(b)`, computed in `double` internally but returned as a bit-vector at the operand width, not as a float |
| `==` `!=` `<` `<=` `>` `>=` | `ut64` 0/1 | unsigned comparison              |

The signed family (`sdiv`/`smod`/`sar`) lifts structurally to RzIL's
signed operators (`/⁺`, `%⁺`, `≫⁺`); rotates, `**`, and `log` have no
direct RzIL pure-op for bit-vectors, so the lift grounds them to a
constant - the evaluator's result is correct, only the symbolic form
is collapsed.

When a bit-vector is combined with a plain `ut64`, the bit-vector's
width wins and the integer is taken modulo that width:

    % 5u8 + 3              -> width 8,  0x08
    % 0xffu8 + 1u8         -> width 8,  0x00   (wraps)
    % 1u8 << 4u8           -> width 8,  0x10
    % 10u8 / 3u8           -> width 8,  0x03

A bit-vector projects to a `ut64` (via `rz_num_value_to_ut64()` or
the legacy `rz_num_math_ut64()`) by taking its low 64 bits.


### Unicode rendering

When the shell is in UTF-8 mode (`scr.utf8=true`), the `%` command
folds the bit-width into the value rows of a bit-vector as a Unicode
subscript - the same notation RzIL uses for bit-vector constants in
its Unicode export - and drops the `0b` prefix from the binary row.
With `scr.utf8=false` the plain ASCII layout is used instead, the
same way `plf` shows the ASCII layout that `pLf` renders in Unicode.

    [0x0]> e scr.utf8=false
    [0x0]> % 200u8 + 100u8
    hex     0x2c
    binary  0b00101100
    width   8 bits

    [0x0]> e scr.utf8=true
    [0x0]> % 200u8 + 100u8
    hex     0x2c₈
    binary  00101100₈
    width   8 bits

The value rows come first and the width row last in both modes. The
renderer is reachable from C as `rz_num_value_print_ex()` with
`RzNumPrintOptions.utf8` set; `rz_num_value_print()` is the ASCII
default.


Relationship to RzIL
--------------------

RzNum's bit-vector kind and RzIL both build on the same `RzBitVector`
primitive, so the two systems already share a value representation.
The Unicode bit-vector form above is deliberately the same notation
RzIL emits (see `il_export_string_unicode.c`). Keeping the output
visually consistent means a bit-vector printed by `%` reads the same
as one inside a `pLf` listing.

The operator-to-glyph mapping - which RzNum operator becomes which
RzIL pure-op and Unicode symbol - lives in `doc/math-il-lift.md`, so it
is maintained in one place. Two things tie the systems together:

  * **A shared bit-vector formatter.** The subscript-width rendering
    used here and the bit-vector case in RzIL's Unicode exporter are
    backed by the same RzUtil helpers, `rz_bv_width_subscript()` and
    `rz_bv_as_unicode_string()`, so the two renderings cannot drift
    apart.
  * **Lifting to RzIL.** `rz_num_il_lift()` (core wrapper
    `rz_core_il_lift()`) turns an expression into the matching
    `RzILOpPure`, rendered in the form `pLf` prints. Operators with a
    direct pure-op survive as structure; the rest are evaluated to a
    constant first:

        1 + 2 * 3      ->  (0x1₆₄ + (0x2₆₄ * 0x3₆₄))
        5u8 + 3u8      ->  (0x5₈ + 0x3₈)
        min(5, 3) + 1  ->  (0x3₆₄ + 0x1₆₄)   (min evaluated first)
        2 ** 8         ->  0x100₆₄           (** evaluated)

    Arithmetic, bitwise, the shifts, the signed `sdiv`/`smod`/`sar`,
    `==`/`<=`, the ternary (onto `ite`), and float-pure arithmetic lift
    structurally - the ternary is the one control-flow construct that
    survives into symbolic execution. Functions, the typed-address
    dereference, host variables, `**`/`log`, the rotates, mixed
    integer-and-float arithmetic, and `;`-sequences are the cases
    evaluated to a constant.

For an exhaustive set of worked examples - simple operators, deeply
nested expressions, the ternary lifting onto RzIL `ite`, host-
registered functions, and every case where the lift has to ground a
sub-expression - see `doc/math-il-lift.md`.


Error categories
----------------

Each evaluation either succeeds (`RZ_NUM_ERR_OK`) or fails with
exactly one category:

| Category                            | When                                       |
|-------------------------------------|--------------------------------------------|
| `RZ_NUM_ERR_PARSE`                  | unbalanced parens, unknown special var, ...|
| `RZ_NUM_ERR_EMPTY`                  | input is empty or whitespace only          |
| `RZ_NUM_ERR_RESERVED_WORD`          | bare `mod` / `log` / `le` / `be`           |
| `RZ_NUM_ERR_UNDEFINED_VAR`          | host callback rejected a known $-variable  |
| `RZ_NUM_ERR_DIV_ZERO`               | `/` or `%` by zero                         |
| `RZ_NUM_ERR_OVERFLOW`               | reserved for future fixed-width literals   |
| `RZ_NUM_ERR_TYPE_MISMATCH`          | reserved                                   |
| `RZ_NUM_ERR_TIMEOUT`                | wall-clock budget exceeded                 |
| `RZ_NUM_ERR_UNCOMPUTABLE`           | `log` of non-positive, failed function or IO read |
| `RZ_NUM_ERR_NOT_IMPLEMENTED`        | unknown function, unhandled node           |
| `RZ_NUM_ERR_OUT_OF_MEMORY`          | allocation failed                          |

Human-readable names for each category are returned by
`rz_num_error_name()`.


Timeouts
--------

`rz_num_math_value_ex()` accepts an `RzNumMathOptions` struct with
a `timeout_ms` field. The evaluator checks the monotonic clock
every 256 AST nodes; if the budget is exceeded the result carries
`RZ_NUM_ERR_TIMEOUT`. The default (and the value used by
`rz_num_math_value`, `rz_num_math_ut64`, `rz-ax`, and `%`) is
zero = unlimited. Set a positive value when feeding untrusted
input or when an interactive prompt must remain responsive.


Examples at the shell
---------------------

    > % 1 + 2 * 3
    int32   7
    uint32  7
    hex     0x7
    octal   07
    unit    7
    segment 0000:0007
    binary  0b00000111
    trits   0t21

    > % 0xff & 0x0f
    int32   15
    uint32  15
    hex     0xf
    ...

    > % 0xffffffffffffffff + 1
    int32   0
    ...
    (ut64 + ut64 wraps; write an explicit bignum literal for
     arbitrary precision)

    > % 0x10000000000000000
    decimal 18446744073709551616
    hex     0x10000000000000000
    width   68 bits (approx)

    > % 2 ** 100
    decimal 1267650600228229401496703205376
    hex     0x100000000000000000000000000
    width   104 bits (approx)

    > % 3.14159 ** 2
    float   9.8696
    scifmt  9.8696044010893580
    hex     0x4023bd3b7c6aaa1c

    > % min(0x100, max(0x50, 0x80))
    int32   128
    ...

    > % минимум(0x100, 0x200)
    int32   256
    ...

    > % 0:le32                 (on a loaded ELF)
    hex     0x464c457f         <- dereferences 7f 45 4c 46

    > % sha256(0, 16)
    decimal 72468553576780861412383346668577895435178167241169020037740589910276139146126
    hex     0xa037bf6e958bd6b2fdcc4a95c7dc6f7735730ae33d20819a056a5da050d05b8e
    width   256 bits (approx)

    > %j 0x10000000000000000
    {"value":"0x10000000000000000","kind":"big"}

    > % 200u8 + 100u8         (8-bit modular arithmetic)
    hex     0x2c
    binary  0b00101100
    width   8 bits
