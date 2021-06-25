// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

const SPECIAL_CHARACTERS = ["\\s", "@", "|", "#", '"', "'", ">", ";", "$", "`", "~", "\\", ",", "(", ")"];
const SPEC_SPECIAL_CHARACTERS = ["\\s", "@", "|", "#", '"', "'", ">", ";", "$", "`", "~", "\\", ",", "(", ")", ":"];

const PF_SPECIAL_CHARACTERS = ["\\s", "@", "|", "#", '"', "'", ">", ";", "$", "`", "~", "\\", "(", ")"];

const PF_DOT_SPECIAL_CHARACTERS = PF_SPECIAL_CHARACTERS.concat([".", "="]);
const SPECIAL_CHARACTERS_EQUAL = SPECIAL_CHARACTERS.concat(["="]);
const SPECIAL_CHARACTERS_COMMA = SPECIAL_CHARACTERS.concat([","]);

const ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\${[^\r\n $}]+}/,
  /\\./
);
const SPEC_ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...SPEC_SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\${[^\r\n $}]+}/,
  /\\./
);
const PF_DOT_ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...PF_DOT_SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\${[^\r\n $}]+}/,
  /\\./
);
const PF_ARG_IDENTIFIER_BASE = choice(
  repeat1(noneOf(...PF_SPECIAL_CHARACTERS)),
  "$$$",
  "$$",
  /\$[^\s@|#"'>;`~\\({) ]/,
  /\${[^\r\n $}]+}/,
  /\\./
);

module.exports = grammar({
  name: "rzcmd",

  extras: ($) => [$._comment, /[ \t]*/],

  externals: ($) => [
    $._cmd_identifier,
    $._help_stmt,
    $.file_descriptor,
    $._eq_sep_concat,
    $._concat,
    $._concat_pf_dot,
    $._spec_sep,
  ],

  inline: ($) => [$.stmt_delimiter, $.stmt_delimiter_singleline, $._comment],

  rules: {
    statements: ($) =>
      choice(
        seq(),
        seq(repeat($.stmt_delimiter)),
        seq(repeat($.stmt_delimiter), $._statement, repeat(seq($.stmt_delimiter, optional($._statement))))
      ),
    _statements_singleline: ($) =>
      prec(
        1,
        seq(
          repeat($.stmt_delimiter_singleline),
          $._statement,
          repeat(seq($.stmt_delimiter_singleline, optional($._statement)))
        )
      ),

    _statement: ($) => choice($.redirect_stmt, $._simple_stmt),

    legacy_quoted_stmt: ($) => seq('"', field("string", token(prec(-1, /([^"\\]|\\(.|\n))+/))), '"'),

    _simple_stmt: ($) =>
      choice(
        $.help_stmt,
        $.repeat_stmt,
        $.arged_stmt,
        $.number_stmt,
        $._tmp_stmt,
        $._iter_stmt,
        $._pipe_stmt,
        $.grep_stmt,
        $.legacy_quoted_stmt,
        $._pf_stmts
      ),

    _tmp_stmt: ($) =>
      choice(
        $.tmp_seek_stmt,
        $.tmp_blksz_stmt,
        $.tmp_fromto_stmt,
        $.tmp_arch_stmt,
        $.tmp_bits_stmt,
        $.tmp_nthi_stmt,
        $.tmp_eval_stmt,
        $.tmp_fs_stmt,
        $.tmp_reli_stmt,
        $.tmp_kuery_stmt,
        $.tmp_fd_stmt,
        $.tmp_reg_stmt,
        $.tmp_file_stmt,
        $.tmp_string_stmt,
        $.tmp_value_stmt,
        $.tmp_hex_stmt
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
        $.iter_step_stmt
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
            optional(alias(/[$]+/, $.grep_specifier_identifier))
          ),
          alias(/[$]+/, $.grep_specifier_identifier)
        )
      ),

    html_disable_stmt: ($) => prec.right(1, seq(field("command", $._simple_stmt), "|")),
    html_enable_stmt: ($) => prec.right(1, seq(field("command", $._simple_stmt), "|H")),
    pipe_stmt: $ => seq($._simple_stmt, '|', $.args),
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
    tmp_seek_stmt: ($) => prec.right(1, seq($._simple_stmt, "@", $.args)),
    tmp_blksz_stmt: ($) => prec.right(1, seq($._simple_stmt, "@!", $.args)),
    tmp_fromto_stmt: ($) => prec.right(1, seq($._simple_stmt, "@(", $.args, ")")),
    tmp_arch_stmt: ($) => prec.right(1, seq($._simple_stmt, "@a:", $.arg)),
    tmp_bits_stmt: ($) => prec.right(1, seq($._simple_stmt, "@b:", $.args)),
    tmp_nthi_stmt: ($) => prec.right(1, seq($._simple_stmt, "@B:", $.arg)),
    tmp_eval_stmt: ($) => prec.right(1, seq($._simple_stmt, "@e:", $.tmp_eval_args)),
    tmp_fs_stmt: ($) => prec.right(1, seq($._simple_stmt, "@F:", $.arg)),
    tmp_reli_stmt: ($) => prec.right(1, seq($._simple_stmt, "@i:", $.args)),
    tmp_kuery_stmt: ($) => prec.right(1, seq($._simple_stmt, "@k:", $.arg)),
    tmp_fd_stmt: ($) => prec.right(1, seq($._simple_stmt, "@o:", $.args)),
    tmp_reg_stmt: ($) => prec.right(1, seq($._simple_stmt, "@r:", $.arg)),
    tmp_file_stmt: ($) => prec.right(1, seq($._simple_stmt, "@f:", $.arg)),
    tmp_string_stmt: ($) => prec.right(1, seq($._simple_stmt, "@s:", $.arg)),
    tmp_value_stmt: ($) => prec.right(1, seq($._simple_stmt, "@v:", $.arg)),
    tmp_hex_stmt: ($) => prec.right(1, seq($._simple_stmt, "@x:", $.arg)),

    // basic statements
    number_stmt: ($) => choice($._dec_number, "0", /(0x[0-9A-Fa-f]+|0b[0-1]+)/),
    help_stmt: ($) =>
      prec.left(
        1,
        choice(
          field("command", alias($.question_mark_identifier, $.cmd_identifier)),
          field("command", alias($._help_stmt, $.cmd_identifier))
        )
      ),
    arged_stmt: ($) =>
      choice(
        $._simple_arged_stmt,
        $._math_arged_stmt,
        $._pointer_arged_stmt,
        $._macro_arged_stmt,
        $._system_stmt,
        $._interpret_stmt,
        $._env_stmt,
        $._pf_arged_stmt,
        $._last_stmt,
        $._simple_arged_stmt_question
      ),

    _simple_arged_stmt_question: ($) =>
      prec.left(1, seq(field("command", alias($._help_stmt, $.cmd_identifier)), field("args", $.args))),

    _simple_arged_stmt: ($) => prec.left(1, seq(field("command", $.cmd_identifier), field("args", optional($.args)))),
    _search_stmt: ($) =>
      prec.left(
        1,
        seq(field("command", alias(/\/[A-Za-z0-9+!\/*]*/, $.cmd_identifier)), field("args", optional($.args)))
      ),
    _math_arged_stmt: ($) =>
      prec.left(1, seq(field("command", alias($.question_mark_identifier, $.cmd_identifier)), field("args", $.args))),
    _pointer_arged_stmt: ($) =>
      prec.left(
        1,
        seq(
          field("command", alias($.pointer_identifier, $.cmd_identifier)),
          field("args", alias($.eq_sep_args, $.args))
        )
      ),
    _macro_arged_stmt: ($) =>
      prec.left(
        1,
        seq(field("command", alias($.macro_identifier, $.cmd_identifier)), field("args", optional($.macro_args)))
      ),
    _system_stmt: ($) => prec.left(1, seq(field("command", $.system_identifier), optional(field("args", $.args)))),
    _interpret_stmt: ($) =>
      prec.left(
        1,
        choice(
          seq(field("command", alias(".", $.cmd_identifier)), field("args", $._simple_stmt)),
          seq(field("command", alias(/\.[\.:\-*]+/, $.cmd_identifier)), /[ ]+/, field("args", optional($.args))),
          seq(field("command", alias(/\.[ ]+/, $.cmd_identifier)), field("args", optional($.args))),
          seq(field("command", alias(".!", $.cmd_identifier)), field("args", $.interpret_arg)),
          seq(field("command", alias(".(", $.cmd_identifier)), field("args", $.macro_call_content)),
          seq(field("command", alias($._interpret_search_identifier, $.cmd_identifier)), field("args", $.args)),
          prec.right(1, seq(field("args", $._simple_stmt), field("command", "|.")))
        )
      ),
    _interpret_search_identifier: ($) => seq("./"),
    _pf_arged_stmt: ($) =>
      choice(
        seq(field("command", alias($.pf_dot_cmd_identifier, $.cmd_identifier))),
        seq(field("command", alias("pfo", $.cmd_identifier)), field("args", $.args))
      ),
    _pf_stmts: ($) =>
      prec.left(
        1,
        choice(
          // pf fmt, pf* fmt_name|fmt, pfc fmt_name|fmt, pfd.fmt_name, pfj fmt_name|fmt, pfq fmt, pfs.struct_name, pfs format
          alias($.pf_cmd, $.arged_stmt),
          // pf.fmt_name.field_name, pf.fmt_name.field_name[i], pf.fmt_name.field_name=33, pfv.fmt_name[.field]
          alias($.pf_dot_cmd, $.arged_stmt),
          // pf.name [0|cnt]fmt
          alias($.pf_new_cmd, $.arged_stmt),
          // Cf [sz] [fmt]
          alias($.Cf_cmd, $.arged_stmt)
          // pf., pfo fdf_name: will be handled as regular arged_stmt
        )
      ),
    Cf_cmd: ($) =>
      prec.left(
        seq(field("command", alias("Cf", $.cmd_identifier)), optional(field("args", alias($._Cf_args, $.args))))
      ),
    _Cf_args: ($) => seq($.arg, $.pf_args),
    pf_dot_cmd_identifier: ($) => "pf.",
    pf_dot_full_cmd_identifier: ($) => /pf[*cjqsv]\./,
    pf_new_cmd: ($) =>
      seq(
        field("command", alias($.pf_dot_cmd_identifier, $.cmd_identifier)),
        $._concat_pf_dot,
        field("args", $.pf_new_args)
      ),
    pf_dot_cmd: ($) =>
      prec.left(
        1,
        seq(
          field("command", alias(choice($.pf_dot_cmd_identifier, $.pf_dot_full_cmd_identifier), $.cmd_identifier)),
          $._concat_pf_dot,
          field("args", $.pf_dot_cmd_args)
        )
      ),
    pf_cmd: ($) => seq(field("command", alias(/pf[*cjqs]?/, $.cmd_identifier)), field("args", $.pf_args)),
    pf_new_args: ($) => seq(alias($.pf_dot_arg, $.pf_arg), $.pf_args),
    pf_dot_cmd_args: ($) =>
      seq(alias($.pf_dot_args, $.pf_args), optional(seq(alias("=", $.pf_arg_identifier), $.pf_args))),
    _pf_dot_arg_identifier: ($) => argIdentifier(PF_DOT_ARG_IDENTIFIER_BASE),
    _pf_arg_parentheses: ($) => seq(alias("(", $.pf_arg_identifier), $.pf_args, alias(")", $.pf_arg_identifier)),
    pf_arg_identifier: ($) => argIdentifier(PF_ARG_IDENTIFIER_BASE),
    _pf_arg: ($) => choice($.pf_arg_identifier, $._pf_arg_parentheses, $.cmd_substitution_arg),
    _pf_dot_arg: ($) => choice(alias($._pf_dot_arg_identifier, $.pf_arg_identifier), $.cmd_substitution_arg),
    pf_concatenation: ($) => prec(-1, seq($._pf_arg, repeat1(prec(-1, seq($._concat, $._pf_arg))))),
    pf_dot_concatenation: ($) => prec(-1, seq($._pf_dot_arg, repeat1(prec(-1, seq($._concat_pf_dot, $._pf_dot_arg))))),
    pf_arg: ($) => choice($._pf_arg, $.pf_concatenation),
    pf_dot_arg: ($) => choice($._pf_dot_arg, alias($.pf_dot_concatenation, $.pf_concatenation)),
    pf_args: ($) => prec.left(repeat1($.pf_arg)),
    pf_dot_args: ($) =>
      prec.left(
        1,
        seq(
          alias($.pf_dot_arg, $.pf_arg),
          repeat(seq($._concat_pf_dot, ".", $._concat_pf_dot, alias($.pf_dot_arg, $.pf_arg)))
        )
      ),
    _env_stmt: ($) =>
      prec.left(
        seq(
          field("command", alias($._env_stmt_identifier, $.cmd_identifier)),
          field("args", optional(alias($.eq_sep_args, $.args)))
        )
      ),
    _env_stmt_identifier: ($) => choice("%", "env"),
    _last_stmt: ($) => seq(field("command", alias($.last_stmt_identifier, $.cmd_identifier))),

    last_stmt_identifier: ($) => choice(".", "..."),
    interpret_arg: ($) => $._any_stmt,
    system_identifier: ($) => /![\*!-=]*/,
    question_mark_identifier: ($) => "?",

    repeat_stmt: ($) =>
      prec.left(1, seq(field("arg", alias($._dec_number, $.number)), field("command", $._simple_stmt))),

    pointer_identifier: ($) => "*",
    eq_sep_args: ($) => seq(alias($._eq_sep_key, $.arg), optional(seq("=", alias($._eq_sep_val, $.arg)))),
    macro_identifier: ($) => /\([-\*]?/,
    macro_call_content: ($) => prec.left(seq(optional($.args), ")")),
    macro_call_full_content: ($) => seq("(", $.macro_call_content),
    macro_content: ($) =>
      prec(
        1,
        seq(
          field("name", $.arg),
          optional($.args),
          optional(seq(";", $._statement, repeat(seq(";", $._statement)))),
          ")"
        )
      ),
    macro_args: ($) => seq($.macro_content, optional(seq(optional($.macro_call_full_content)))),

    redirect_stmt: ($) =>
      prec.right(
        2,
        seq(field("command", $._simple_stmt), field("redirect_operator", $._redirect_operator), field("arg", $.arg))
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
        alias(",", $.arg_identifier)
      ),
    arg: ($) => choice($._arg, $.concatenation),
    args: ($) => prec.left(repeat1($.arg)),
    // TODO: this should accept a quoted_arg and a cmd_substitution_arg as well
    tmp_eval_args: ($) => prec.left(seq($.tmp_eval_arg, repeat(seq(",", $.tmp_eval_arg)))),
    tmp_eval_arg: ($) => repeat1(noneOf(...SPECIAL_CHARACTERS_COMMA)),

    _eq_sep_key_single: ($) =>
      choice(
        alias($._eq_sep_key_identifier, $.arg_identifier),
        $.double_quoted_arg,
        $.single_quoted_arg,
        $.cmd_substitution_arg
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
            /\${[^\r\n $}]+}/,
            escape(...SPECIAL_CHARACTERS_EQUAL)
          )
        )
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
        '"'
      ),
    single_quoted_arg: ($) => seq("'", repeat(choice(token.immediate(prec(1, /[^\\'\n]+/)), /\\[\\'\n]?/)), "'"),
    cmd_substitution_arg: ($) =>
      choice(seq("$(", $._statements_singleline, ")"), prec(1, seq("`", $._statements_singleline, "`"))),
    concatenation: ($) => prec(-1, seq($._arg, repeat1(prec(-1, seq($._concat, $._arg))))),

    _dec_number: ($) => choice(/[1-9][0-9]*/, /[0-9][0-9]+/),
    _comment: ($) => token(choice(/#[^\r\n]*/)),

    stmt_delimiter: ($) => choice("\n", "\r", $.stmt_delimiter_singleline),
    stmt_delimiter_singleline: ($) => choice(";"),

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
