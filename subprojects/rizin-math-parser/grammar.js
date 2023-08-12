const identifier_start = /[^\p{Control}\s+\-*/%^#&~|<>=(){}\[\];:,\\'"\d]/;
const identifier_continue = /[^\p{Control}\s+\-*/%^#&~|<>=(){}\[\];:,\\'"]*/;
const unit = choice(
  "KiB",
  "KB",
  "MiB",
  "MB",
  "GiB",
  "GB",
  "TiB",
  "TB",
  "EiB",
  "EB",
);

module.exports = grammar({
  name: "rznum",

  inline: ($) => [$._variable, $._argument_name, $._function_name],

  precedences: (_) => [
    [
      "unitary",
      "exponent",
      "multiplication",
      "addition",
      "logical",
      "let_assignment",
      "assignment",
    ],
  ],

  rules: {
    expression: ($) => $._expression,
    _expression: ($) =>
      choice(
        $.number,
        $.variable,
        $.function,
        $.let_assignment,
        $.assignment,
        $.increment,
        $.decrement,
        $.sum,
        $.subtraction,
        $.product,
        $.division,
        $.modulo,
        $.division,
        $.exponent,
        $.logarithm,
        $.logical_negation,
        $.logical_and,
        $.logical_or,
        $.logical_xor,
        $.logical_shl,
        $.logical_shr,
        $.logical_rol,
        $.logical_ror,
        $._parenthesized_expression,
      ),

    let_assignment: ($) =>
      prec.left(
        "let_assignment",
        seq(
          "let",
          field("left", $._expression),
          "=",
          field("right", $._expression),
        ),
      ),

    assignment: ($) =>
      prec.left(
        "assignment",
        seq(field("left", $._expression), "=", field("right", $._expression)),
      ),

    increment: ($) =>
      prec.left("unitary", seq("++", field("left", $._expression))),

    decrement: ($) =>
      prec.left("unitary", seq("--", field("left", $._expression))),

    sum: ($) =>
      prec.left(
        "addition",
        seq(field("left", $._expression), "+", field("right", $._expression)),
      ),

    subtraction: ($) =>
      prec.left(
        "addition",
        seq(field("left", $._expression), "-", field("right", $._expression)),
      ),

    product: ($) =>
      prec.left(
        "multiplication",
        seq(field("left", $._expression), "*", field("right", $._expression)),
      ),

    division: ($) =>
      prec.left(
        "multiplication",
        seq(field("left", $._expression), "/", field("right", $._expression)),
      ),

    modulo: ($) =>
      prec.left(
        "multiplication",
        seq(
          field("left", $._expression),
          choice("mod", "%"),
          field("right", $._expression),
        ),
      ),

    exponent: ($) =>
      prec.left(
        "exponent",
        seq(
          field("base", $._expression),
          "**",
          field("exponent", $._expression),
        ),
      ),

    logarithm: ($) =>
      prec.left(
        "exponent",
        seq(
          field("base", $._expression),
          "log",
          field("exponent", $._expression),
        ),
      ),

    logical_negation: ($) =>
      prec.left("unitary", seq("~", field("right", $._expression))),

    logical_and: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), "&", field("right", $._expression)),
      ),

    logical_or: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), "|", field("right", $._expression)),
      ),

    logical_xor: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), "^", field("right", $._expression)),
      ),

    logical_shl: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), "<<", field("right", $._expression)),
      ),

    logical_shr: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), ">>", field("right", $._expression)),
      ),

    logical_rol: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), "<<<", field("right", $._expression)),
      ),

    logical_ror: ($) =>
      prec.left(
        "logical",
        seq(field("left", $._expression), ">>>", field("right", $._expression)),
      ),

    function: ($) => seq($.function_name, $.argument_list),

    argument_list: ($) => seq("(", commaSep($.argument_name), ")"),

    _parenthesized_expression: ($) => seq("(", $._expression, ")"),

    number_value: ($) => {
      const bin = /[0-1]/;
      const ternary = /[0-2]/;
      const octal = /[0-7]/;
      const decimal = /[0-9]/;
      const hex = /[0-9a-fA-F]/;
      const binDigits = repeat1(bin);
      const ternaryDigits = repeat1(ternary);
      const octalDigits = repeat1(octal);
      const decimalDigits = repeat1(decimal);
      const hexDigits = repeat1(hex);
      return token(
        seq(
          optional(/[-\+]/),
          optional(choice("0x", "0b", "0o", "0t")),
          choice(
            seq(
              choice(
                decimalDigits,
                seq("0b", binDigits),
                seq("0t", ternaryDigits),
                seq("0x", hexDigits),
                seq("0o", octalDigits),
              ),
              optional(seq(".", optional(hexDigits))),
            ),
            seq(".", decimalDigits),
          ),
          optional(seq(/[eEpP]/, optional(seq(optional(/[-\+]/), hexDigits)))),
        ),
      );
    },

    number_suffix: (_) => repeat1(choice("u", "l", "U", "L", "f", "F")),
    number_unit: (_) => unit,

    number: ($) =>
      seq($.number_value, optional(choice($.number_suffix, $.number_unit))),

    variable: (_) => token(seq(identifier_start, identifier_continue)),
    argument_name: (_) => token(seq(identifier_start, identifier_continue)),
    function_name: (_) => token(seq(identifier_start, identifier_continue)),
  },
});

/**
 * Creates a rule to optionally match one or more of the rules separated by a comma
 *
 * @param {Rule} rule
 *
 * @return {ChoiceRule}
 *
 */
function commaSep(rule) {
  return optional(commaSep1(rule));
}

/**
 * Creates a rule to match one or more of the rules separated by a comma
 *
 * @param {Rule} rule
 *
 * @return {SeqRule}
 *
 */
function commaSep1(rule) {
  return seq(rule, repeat(seq(",", rule)));
}
