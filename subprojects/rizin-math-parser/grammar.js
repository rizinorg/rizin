// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

const identifier_start = /[^\p{Control}\s+\-*\/%^#&~!|<>=(){}\[\];:,\\'"\d$]/u;
const identifier_continue = /[^\p{Control}\s+\-*\/%^#&~!|<>=(){}\[\];:,\\'"]*/u;

const unit_names = ["KiB", "KB", "MiB", "MB", "GiB", "GB", "TiB", "TB", "PiB", "PB", "EiB", "EB"];

module.exports = grammar({
  name: "rznum",

  // Declaring a "word" rule activates tree-sitter's keyword
  // extraction. At lex time the lexer greedily matches the longest
  // identifier-shaped run; the result is then matched against the
  // grammar's literal-string tokens. If the parser's current state
  // accepts the keyword (e.g. "let" at the start of a let_assignment),
  // the keyword token type is emitted; otherwise tree-sitter falls
  // back to emitting $._word, which the parser can then accept as
  // a variable.
  //
  // The practical effect: `let` is always reserved (no production
  // accepts a variable at expression start), while `mod`, `log`,
  // `le` and `be` are only reserved in their positional contexts
  // (infix between expressions, or as part of an address suffix).
  // A bare `mod` or `log` therefore parses as a variable; the
  // evaluator (see librz/util/num/evaluator.c) checks
  // for these reserved names and raises an error rather than
  // silently resolving them through the variable callback.
  word: ($) => $._word,

  // After a `number_value`, a following ':' may begin a typed-read
  // suffix (address_typed) or be the ternary's else-separator. Let the
  // parser use lookahead to decide based on whether a valid width
  // follows.
  conflicts: ($) => [[$.number, $.address_typed]],

  precedences: () => [
    [
      "unitary",
      "exponent",
      "multiplication",
      "addition",
      "shift",
      "bitwise_and",
      "bitwise_xor",
      "bitwise_or",
      "comparison",
      "equality",
      "conditional",
      "let_assignment",
      "assignment",
    ],
  ],

  rules: {
    // A program is one or more expressions separated by ';'. The
    // value of the whole program is the value of the last expression;
    // earlier ones are evaluated for their side effects (variable
    // bindings). A trailing ';' is allowed.
    expression: ($) => seq($._expression, repeat(seq(";", $._expression)), optional(";")),

    _expression: ($) =>
      choice(
        $.number,
        $.address_typed,
        $.string_bytes,
        $.special_variable,
        $.variable,
        $.function,
        $.let_assignment,
        $.assignment,
        $.increment,
        $.decrement,
        $.unary_plus,
        $.unary_minus,
        $.sum,
        $.subtraction,
        $.product,
        $.division,
        $.signed_division,
        $.modulo,
        $.signed_modulo,
        $.exponent,
        $.logarithm,
        $.logical_negation,
        $.logical_not,
        $.logical_and,
        $.logical_or,
        $.logical_xor,
        $.logical_shl,
        $.logical_shr,
        $.arith_shr,
        $.logical_rol,
        $.logical_ror,
        $.less_than,
        $.less_equal,
        $.greater_than,
        $.greater_equal,
        $.equal,
        $.not_equal,
        $.conditional,
        $.parenthesized_expression,
      ),

    let_assignment: ($) =>
      prec.right("let_assignment", seq("let", field("left", $.variable), "=", field("right", $._expression))),

    assignment: ($) => prec.right("assignment", seq(field("left", $.variable), "=", field("right", $._expression))),

    increment: ($) => prec.right("unitary", seq("++", field("right", $._expression))),

    decrement: ($) => prec.right("unitary", seq("--", field("right", $._expression))),

    unary_plus: ($) => prec.right("unitary", seq("+", field("right", $._expression))),

    unary_minus: ($) => prec.right("unitary", seq("-", field("right", $._expression))),

    logical_negation: ($) => prec.right("unitary", seq("~", field("right", $._expression))),

    logical_not: ($) => prec.right("unitary", seq("!", field("right", $._expression))),

    sum: ($) => prec.left("addition", seq(field("left", $._expression), "+", field("right", $._expression))),

    subtraction: ($) => prec.left("addition", seq(field("left", $._expression), "-", field("right", $._expression))),

    product: ($) => prec.left("multiplication", seq(field("left", $._expression), "*", field("right", $._expression))),

    division: ($) => prec.left("multiplication", seq(field("left", $._expression), "/", field("right", $._expression))),

    // Signed (two's-complement) division and remainder. Word
    // operators, lexed like `mod` / `log`; reservation is enforced in
    // the evaluator. Mirror RzIL's sdiv / smod.
    signed_division: ($) =>
      prec.left("multiplication", seq(field("left", $._expression), "sdiv", field("right", $._expression))),

    modulo: ($) =>
      prec.left("multiplication", seq(field("left", $._expression), choice("mod", "%"), field("right", $._expression))),

    signed_modulo: ($) =>
      prec.left("multiplication", seq(field("left", $._expression), "smod", field("right", $._expression))),

    exponent: ($) => prec.right("exponent", seq(field("base", $._expression), "**", field("exponent", $._expression))),

    logarithm: ($) =>
      prec.right("exponent", seq(field("base", $._expression), "log", field("exponent", $._expression))),

    logical_shl: ($) => prec.left("shift", seq(field("left", $._expression), "<<", field("right", $._expression))),

    logical_shr: ($) => prec.left("shift", seq(field("left", $._expression), ">>", field("right", $._expression))),

    // Arithmetic (sign-propagating) shift right. Word operator `sar`,
    // mirroring RzIL's shiftr with a sign fill.
    arith_shr: ($) => prec.left("shift", seq(field("left", $._expression), "sar", field("right", $._expression))),

    logical_rol: ($) => prec.left("shift", seq(field("left", $._expression), "<<<", field("right", $._expression))),

    logical_ror: ($) => prec.left("shift", seq(field("left", $._expression), ">>>", field("right", $._expression))),

    logical_and: ($) => prec.left("bitwise_and", seq(field("left", $._expression), "&", field("right", $._expression))),

    logical_xor: ($) => prec.left("bitwise_xor", seq(field("left", $._expression), "^", field("right", $._expression))),

    logical_or: ($) => prec.left("bitwise_or", seq(field("left", $._expression), "|", field("right", $._expression))),

    less_than: ($) => prec.left("comparison", seq(field("left", $._expression), "<", field("right", $._expression))),

    less_equal: ($) => prec.left("comparison", seq(field("left", $._expression), "<=", field("right", $._expression))),

    greater_than: ($) => prec.left("comparison", seq(field("left", $._expression), ">", field("right", $._expression))),

    greater_equal: ($) =>
      prec.left("comparison", seq(field("left", $._expression), ">=", field("right", $._expression))),

    equal: ($) => prec.left("equality", seq(field("left", $._expression), "==", field("right", $._expression))),

    not_equal: ($) => prec.left("equality", seq(field("left", $._expression), "!=", field("right", $._expression))),

    // C-style ternary: cond ? then : else. Right-associative so that
    // a ? b : c ? d : e parses as a ? b : (c ? d : e). The condition
    // is truthy when non-zero; only the taken branch is evaluated.
    conditional: ($) =>
      prec.right(
        "conditional",
        seq(
          field("condition", $._expression),
          "?",
          field("consequence", $._expression),
          ":",
          field("alternative", $._expression),
        ),
      ),

    function: ($) => seq($.function_name, $.argument_list),

    argument_list: ($) => seq("(", commaSep($.argument), ")"),

    argument: ($) => $._expression,

    parenthesized_expression: ($) => seq("(", $._expression, ")"),

    // ---- numeric literals -----------------------------------------
    //
    // Unsigned only: a leading sign is parsed as the unary_plus /
    // unary_minus operator above.
    number_value: () => {
      const bin = /[0-1]/;
      const tern = /[0-2]/;
      const oct = /[0-7]/;
      const dec = /[0-9]/;
      const hex = /[0-9a-fA-F]/;
      const binDigits = repeat1(bin);
      const ternDigits = repeat1(tern);
      const octDigits = repeat1(oct);
      const decDigits = repeat1(dec);
      const hexDigits = repeat1(hex);
      return token(
        seq(
          choice(
            seq(
              choice(
                decDigits,
                seq("0b", binDigits),
                seq("0t", ternDigits),
                seq("0o", octDigits),
                seq("0x", hexDigits),
              ),
              optional(seq(".", optional(hexDigits))),
            ),
            seq(".", decDigits),
          ),
          optional(seq(/[eEpP]/, optional(/[-+]/), hexDigits)),
        ),
      );
    },

    // Number suffix: a contiguous run of u/l/U/L/f/F optionally
    // followed by a bit-width (8/16/32/64/128). A run with a width,
    // e.g. "u8" / "u16" / "u32" / "u64" / "u128", denotes a
    // fixed-width bit-vector literal; a bare run of letters keeps the
    // old informational meaning. Defining it as a token means it
    // competes with the identifier lexer as a whole word; the parser
    // only accepts it in the trailing position of a `number`, so it
    // does not shadow user identifiers like `lower` or `frob`.
    number_suffix: () => token(seq(repeat1(/[ulUFLf]/), optional(choice("8", "16", "32", "64", "128")))),

    // Number unit: a single token equal to one of the SI / IEC
    // suffix strings, lexed greedily.
    number_unit: () => token(choice(...unit_names)),

    number: ($) => seq($.number_value, optional(choice($.number_suffix, $.number_unit))),

    // ---- address with explicit width and endianness ---------------
    // ---- typed-address dereference --------------------------------
    //   0x1234:le32        little-endian unsigned 32-bit
    //   0xDEADBEEF:be64    big-endian unsigned 64-bit
    //   0x1000:8           native-endian unsigned 8-bit
    //   0x1000:s32         native-endian SIGNED 32-bit
    //   0x1000:lef32       little-endian 32-bit FLOAT
    //   0x1000:f16         native-endian half-precision float
    //
    // The tail is one token so it does not interact with the
    // identifier lexer. It is:
    //   [le|be]? [s]? (8|16|32|64|128)        integer read
    //   [le|be]? f     (16|32|64)             float read
    // 's' marks a signed integer read; 'f' a float read (half /
    // single / double).
    // The trailing ':' of a typed read can collide with the ternary's
    // else-separator after a numeric literal (`c ? 0x10 : 0` vs
    // `0x10:le32`). The two are disambiguated by lookahead - declared
    // as a conflict below - so `address_typed` is chosen only when a
    // valid width actually follows the colon.
    address_typed: ($) => seq($.number_value, ":", $.address_width),
    address_width: () =>
      token(
        seq(
          optional(choice("le", "be")),
          choice(seq(optional("s"), choice("8", "16", "32", "64", "128")), seq("f", choice("16", "32", "64", "128"))),
        ),
      ),

    // ---- string-as-bytes literal ----------------------------------
    string_bytes: () => token(seq('"', repeat(choice(/[^"\\\n]/, /\\./)), '"')),

    // ---- special (Rizin) variables --------------------------------
    special_variable: () =>
      token(
        choice(
          "$$$",
          "$$",
          "$alias",
          "$b",
          "$B",
          "$c",
          "$Cn",
          "$D",
          "$DB",
          "$DD",
          "$DS",
          "$e",
          "$f",
          "$F",
          "$Fb",
          "$FB",
          "$Fi",
          "$FS",
          "$Ff",
          "$Fj",
          "$fl",
          "$j",
          "$Ja",
          "$l",
          "$M",
          "$MM",
          "$m",
          "$O",
          "$o",
          "$p",
          "$P",
          "$r",
          "$s",
          "$S",
          "$SS",
          "$v",
          "$w",
        ),
      ),

    // The word lexer used by the `word: ($) => $._word` directive.
    //
    // Tree-sitter's keyword extraction emits the literal-token type
    // (e.g. `"mod"`) instead of `_word` when the matched identifier
    // equals a keyword used elsewhere in the grammar AND the parser
    // accepts that keyword at the current parse state. When the
    // parser does NOT accept the keyword - for example, a bare
    // `mod` in expression-leaf position - tree-sitter falls back to
    // emitting `_word`, which lets the bare keyword parse as a
    // variable.
    //
    // This grammar accepts that fallback at parse time; reservation
    // is enforced at evaluator level (see rz_num_math_value()),
    // which raises an error if a variable's name equals one of the
    // reserved words. The `let` keyword is the exception: because
    // it always appears at the start of an expression, the parser
    // never accepts a variable in its place, so a bare `let` is a
    // syntax error.
    _word: () => token(seq(identifier_start, identifier_continue)),
    variable: ($) => $._word,
    function_name: ($) => $._word,
  },
});

function commaSep(rule) {
  return optional(commaSep1(rule));
}

function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
