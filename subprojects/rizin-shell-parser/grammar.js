// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

const SPECIAL_CHARACTERS = ["\\s", "@", "|", "#", '"', "'", ">", ";", "$", "`", "~", "\\", ",", "(", ")"];
const SPEC_SPECIAL_CHARACTERS = ["\\s", "@", "|", "#", '"', "'", ">", ";", "$", "`", "~", "\\", ",", "(", ")", ":"];

const SPECIAL_CHARACTERS_EQUAL = SPECIAL_CHARACTERS.concat(["="]);
const SPECIAL_CHARACTERS_COMMA = SPECIAL_CHARACTERS.concat([","]);

const ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\$\{[^\r\n $}]+\}/,
  /\\./,
);
const SPEC_ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...SPEC_SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\$\{[^\r\n $}]+\}/,
  /\\./,
);

module.exports = grammar({
  name: "rzcmd",

  extras: ($) => [$._comment, /[ \t]*/],

  externals: ($) => [$._cmd_identifier, $._help_stmt, $.file_descriptor, $._eq_sep_concat, $._concat, $._spec_sep],

  inline: ($) => [$.stmt_delimiter, $.stmt_delimiter_singleline],

  rules: {
    statements: ($) =>
      choice(
        seq(),
        seq(repeat($.stmt_delimiter)),
        seq(repeat($.stmt_delimiter), $._statement, repeat(seq($.stmt_delimiter, optional($._statement)))),
      ),
    _statements_singleline: ($) =>
      prec(
        1,
        seq(
          repeat($.stmt_delimiter_singleline),
          $._statement,
          repeat(seq($.stmt_delimiter_singleline, optional($._statement))),
        ),
      ),

    _statement: ($) => choice($.redirect_stmt, $._simple_stmt),

    _simple_stmt: ($) =>
      choice(
        $.help_stmt,
        $.repeat_stmt,
        $.arged_stmt,
        $.macro_stmt,
        $.tmp_stmt,
        $._iter_stmt,
        $._pipe_stmt,
        $.grep_stmt,
      ),

    tmp_stmt: ($) => prec.right(seq($._simple_stmt, repeat1($._tmp_op))),

    _tmp_op: ($) =>
      choice(
        $.tmp_seek_op,
        $.tmp_blksz_op,
        $.tmp_fromto_op,
        $.tmp_arch_op,
        $.tmp_bits_op,
        $.tmp_nthi_op,
        $.tmp_eval_op,
        $.tmp_fs_op,
        $.tmp_reli_op,
        $.tmp_kuery_op,
        $.tmp_fd_op,
        $.tmp_reg_op,
        $.tmp_file_op,
        $.tmp_string_op,
        $.tmp_value_op,
        $.tmp_hex_op,
      ),

    _iter_stmt: ($) =>
      choice(
        $.iter_file_lines_stmt,
        $.iter_offsets_stmt,
        $.iter_offsetssizes_stmt,
        $.iter_hit_stmt,
        $.iter_interpret_stmt,
        $.iter_interpret_offsetssizes_stmt,
        $.iter_comment_stmt,
        $.iter_dbta_stmt,
        $.iter_dbtb_stmt,
        $.iter_dbts_stmt,
        $.iter_threads_stmt,
        $.iter_bbs_stmt,
        $.iter_instrs_stmt,
        $.iter_import_stmt,
        $.iter_sections_stmt,
        $.iter_segments_stmt,
        $.iter_symbol_stmt,
        $.iter_string_stmt,
        $.iter_flags_stmt,
        $.iter_function_stmt,
        $.iter_iomap_stmt,
        $.iter_dbgmap_stmt,
        $.iter_register_stmt,
        $.iter_step_stmt,
      ),

    _pipe_stmt: ($) => choice($.html_disable_stmt, $.html_enable_stmt, $.pipe_stmt),

    grep_stmt: ($) => seq(field("command", $._simple_stmt), "~", field("specifier", $.grep_specifier)),
    // FIXME: improve parser for grep specifier
    // grep_specifier_identifier also includes ~ because r2 does not support nested grep statements yet
    grep_specifier_identifier: ($) => token(seq(repeat1(choice(/[^\n\r;#@>|`$()]+/, /\\./, /\$[^(\r\n;#>|`]/)))),
    grep_specifier: ($) =>
      prec.left(
        choice(
          seq(
            repeat1(choice($.grep_specifier_identifier, $.cmd_substitution_arg)),
            optional(alias(/[$]+/, $.grep_specifier_identifier)),
          ),
          alias(/[$]+/, $.grep_specifier_identifier),
        ),
      ),

    html_disable_stmt: ($) => prec.right(1, seq(field("command", $._simple_stmt), "|")),
    html_enable_stmt: ($) => prec.right(1, seq(field("command", $._simple_stmt), "|H")),
    pipe_stmt: ($) => seq($._simple_stmt, "|", $.args),
    pipe_second_stmt: ($) => /[^|\r\n;]+/,

    iter_file_lines_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@.", $.arg)),
    iter_offsets_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@=", optional($.args))),
    iter_offsetssizes_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@@=", optional($.args))),
    iter_hit_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@", $._concat, alias($._search_stmt, $.arged_stmt))),
    iter_interpret_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@c:", $._simple_stmt)),
    iter_interpret_offsetssizes_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@@c:", $._simple_stmt)),
    iter_comment_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@C", optional(seq(":", $.arg)))),
    iter_dbta_stmt: ($) => prec.right(1, seq($._simple_stmt, choice("@@dbt", "@@dbta"))),
    iter_dbtb_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@dbtb")),
    iter_dbts_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@dbts")),
    iter_threads_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@t")),
    iter_bbs_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@b")),
    iter_instrs_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@i")),
    iter_import_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@ii")),
    iter_sections_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@iS")),
    iter_segments_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@iSS")),
    iter_symbol_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@is")),
    iter_string_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@iz")),
    iter_flags_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@f", optional(seq(":", $.arg)))),
    iter_function_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@F", optional(seq(":", $.arg)))),
    iter_iomap_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@om")),
    iter_dbgmap_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@dm")),
    iter_register_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@r")),
    iter_step_stmt: ($) => prec.right(1, seq($._simple_stmt, "@@s:", $.args)),

    // tmp changes statements
    tmp_seek_op: ($) => seq("@ ", $.args),
    tmp_blksz_op: ($) => seq("@!", $.args),
    tmp_fromto_op: ($) => seq("@(", $.args, ")"),
    tmp_arch_op: ($) => seq("@a:", $.arg),
    tmp_bits_op: ($) => seq("@b:", $.args),
    tmp_nthi_op: ($) => seq("@B:", $.arg),
    tmp_eval_op: ($) => seq("@e:", alias($.tmp_eval_args, $.args)),
    tmp_fs_op: ($) => seq("@F:", $.arg),
    tmp_reli_op: ($) => seq("@i:", $.args),
    tmp_kuery_op: ($) => seq("@k:", $.arg),
    tmp_fd_op: ($) => seq("@o:", $.args),
    tmp_reg_op: ($) => seq("@r:", $.arg),
    tmp_file_op: ($) => seq("@f:", $.arg),
    tmp_string_op: ($) => seq("@s:", $.arg),
    tmp_value_op: ($) => seq("@v:", $.arg),
    tmp_hex_op: ($) => seq("@x:", $.arg),

    // basic statements
    help_stmt: ($) =>
      prec.left(
        1,
        choice(
          field("command", alias($.question_mark_identifier, $.cmd_identifier)),
          field("command", alias(choice("?**", "?**e", "?***"), $.cmd_identifier)),
          field("command", alias($._help_stmt, $.cmd_identifier)),
        ),
      ),
    macro_body: ($) => seq(";", $._statement, repeat(seq(";", $._statement))),
    macro_name: ($) => /[A-Za-z0-9_\-\.]+/,
    macro_content: ($) =>
      prec(1, seq(field("name", $.macro_name), field("args", optional($.args)), field("body", $.macro_body))),
    macro_call: ($) => seq("(", field("argv", optional($.args)), ")"),
    macro_stmt: ($) =>
      seq(field("command", alias("(", $.cmd_identifier)), $._concat, $.macro_content, ")", optional($.macro_call)),
    arged_stmt: ($) =>
      choice(
        $._simple_arged_stmt,
        $._pointer_arged_stmt,
        $._macro_arged_stmt,
        $._alias_arged_stmt,
        $._system_stmt,
        $._interpret_stmt,
        $._env_stmt,
        $._last_stmt,
        $._simple_arged_stmt_question,
      ),

    _macro_arged_stmt: ($) =>
      choice(
        field("command", alias(choice("(", "(-*", "(*"), $.cmd_identifier)),
        seq(field("command", alias("(-", $.cmd_identifier)), field("args", $.args)),
      ),
    _alias_arged_stmt: ($) =>
      prec.left(
        1,
        choice(
          field("command", alias(choice("$*", "$**"), $.cmd_identifier)),
          seq(field("command", alias("$", $.cmd_identifier)), optional(field("args", $.args))),
        ),
      ),
    _simple_arged_stmt_question: ($) =>
      prec.left(1, seq(field("command", alias($._help_stmt, $.cmd_identifier)), field("args", $.args))),

    _simple_arged_stmt: ($) => prec.left(1, seq(field("command", $.cmd_identifier), field("args", optional($.args)))),
    _search_stmt: ($) =>
      prec.left(
        1,
        seq(field("command", alias(/\/[A-Za-z0-9+!\/*]*/, $.cmd_identifier)), field("args", optional($.args))),
      ),
    _pointer_arged_stmt: ($) =>
      prec.left(
        1,
        seq(
          field("command", alias($.pointer_identifier, $.cmd_identifier)),
          field("args", alias($.eq_sep_args, $.args)),
        ),
      ),
    _system_stmt: ($) => prec.left(1, seq(field("command", $.system_identifier), optional(field("args", $.args)))),
    _interpret_stmt: ($) =>
      prec.left(
        1,
        choice(
          seq(field("command", alias(".", $.cmd_identifier)), field("args", $._simple_stmt)),
          seq(
            field("command", alias(/\.[\.:\-*]+/, $.cmd_identifier)),
            optional(seq(/[ ]+/, field("args", optional($.args)))),
          ),
          seq(field("command", alias(/\.[ ]+/, $.cmd_identifier)), field("args", optional($.args))),
          seq(field("command", alias(/\.\.?\(/, $.cmd_identifier)), field("args", optional($.args)), ")"),
          seq(field("command", alias($._interpret_search_identifier, $.cmd_identifier)), field("args", $.args)),
          prec.right(1, seq(field("args", $._simple_stmt), field("command", "|."))),
        ),
      ),
    _interpret_search_identifier: ($) => "./",
    _env_stmt: ($) =>
      prec.left(
        seq(
          field("command", alias($._env_stmt_identifier, $.cmd_identifier)),
          optional(seq(/[ ]+/, field("args", optional(alias($.eq_sep_args, $.args))))),
        ),
      ),
    _env_stmt_identifier: ($) => "env",
    _last_stmt: ($) => seq(field("command", alias($.last_stmt_identifier, $.cmd_identifier))),

    last_stmt_identifier: ($) => choice(".", "..."),
    interpret_arg: ($) => $._any_stmt,
    system_identifier: ($) => /![\*!-=]*/,
    question_mark_identifier: ($) => "?",

    repeat_stmt: ($) =>
      prec.left(1, seq(field("arg", alias($._dec_number, $.number)), field("command", $._simple_stmt))),

    pointer_identifier: ($) => "*",
    eq_sep_args: ($) => seq(alias($._eq_sep_key, $.arg), optional(seq("=", alias($._eq_sep_val, $.arg)))),

    redirect_stmt: ($) =>
      prec.right(
        2,
        seq(field("command", $._simple_stmt), field("redirect_operator", $._redirect_operator), field("arg", $.arg)),
      ),
    _redirect_operator: ($) =>
      choice($.fdn_redirect_operator, $.fdn_append_operator, $.html_redirect_operator, $.html_append_operator),
    fdn_redirect_operator: ($) => seq(optional($.file_descriptor), ">"),
    fdn_append_operator: ($) => seq(optional($.file_descriptor), ">>"),
    html_redirect_operator: ($) => "H>",
    html_append_operator: ($) => "H>>",

    _arg_with_paren: ($) => seq(alias("(", $.arg_identifier), $.args, alias(")", $.arg_identifier)),
    _arg: ($) =>
      choice(
        $.arg_identifier,
        $.double_quoted_arg,
        $.single_quoted_arg,
        $.cmd_substitution_arg,
        alias($._arg_with_paren, $.args),
        alias(",", $.arg_identifier),
      ),
    arg: ($) => choice($._arg, $.concatenation),
    args: ($) => prec.left(repeat1($.arg)),
    // TODO: this should accept a quoted_arg and a cmd_substitution_arg as well
    tmp_eval_args: ($) => prec.left(seq(alias($.tmp_eval_arg, $.arg), repeat(seq(",", alias($.tmp_eval_arg, $.arg))))),
    tmp_eval_arg: ($) => alias(repeat1(noneOf(...SPECIAL_CHARACTERS_COMMA)), $.arg_identifier),

    _eq_sep_key_single: ($) =>
      choice(
        alias($._eq_sep_key_identifier, $.arg_identifier),
        $.double_quoted_arg,
        $.single_quoted_arg,
        $.cmd_substitution_arg,
      ),
    _eq_sep_key_concatenation: ($) =>
      prec.left(seq($._eq_sep_key_single, repeat1(seq($._eq_sep_concat, $._eq_sep_key_single)))),
    _eq_sep_key: ($) => choice($._eq_sep_key_single, alias($._eq_sep_key_concatenation, $.concatenation)),
    _eq_sep_key_identifier: ($) =>
      token(
        repeat1(
          choice(
            repeat1(noneOf(...SPECIAL_CHARACTERS_EQUAL)),
            /\$[^({]/,
            /\$\{[^\r\n $}]+\}/,
            escape(...SPECIAL_CHARACTERS_EQUAL),
          ),
        ),
      ),
    _eq_sep_val_concatenation: ($) => prec.left(1, seq($.arg, repeat1(seq($._eq_sep_concat, $.arg)))),
    _eq_sep_val: ($) => choice($._arg, alias($._eq_sep_val_concatenation, $.concatenation)),
    _any_stmt: ($) => /[^\r\n;~|]+/,

    arg_identifier: ($) => argIdentifier(ARG_IDENTIFIER_BASE),
    spec_arg_identifier: ($) => argIdentifier(SPEC_ARG_IDENTIFIER_BASE),

    double_quoted_arg: ($) =>
      seq(
        '"',
        repeat(choice(token.immediate(prec(1, /[^\\"\n$`]+/)), /\$[^("]?/, /\\[\\"\n$`]?/, $.cmd_substitution_arg)),
        '"',
      ),
    single_quoted_arg: ($) => seq("'", repeat(choice(token.immediate(prec(1, /[^\\'\n]+/)), /\\[\\'\n]?/)), "'"),
    cmd_substitution_arg: ($) =>
      choice(seq("$(", $._statements_singleline, ")"), prec(1, seq("`", $._statements_singleline, "`"))),
    concatenation: ($) => prec(-1, seq($._arg, repeat1(prec(-1, seq($._concat, $._arg))))),

    _dec_number: ($) => choice(/[1-9][0-9]*/, /[0-9][0-9]+/),
    _comment: ($) => /#[^\r\n]*/,

    stmt_delimiter: ($) => choice("\n", "\r", $.stmt_delimiter_singleline),
    stmt_delimiter_singleline: ($) => ";",

    specifiers: ($) => repeat1(seq($._spec_sep, $._concat, alias($.spec_arg_identifier, $.arg_identifier))),
    cmd_identifier: ($) => seq(field("id", $._cmd_identifier), field("extra", optional($.specifiers))),
  },
});

function noneOf(...characters) {
  const negatedString = characters.map((c) => (c == "\\" ? "\\\\" : c)).join("");
  return new RegExp("[^" + negatedString + "]");
}

function argIdentifier(baseCharacters) {
  return choice(token(repeat1(baseCharacters)), "$");
}
