#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 65
#define LARGE_STATE_COUNT 2
#define SYMBOL_COUNT 74
#define ALIAS_COUNT 0
#define TOKEN_COUNT 42
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 4
#define MAX_ALIAS_SEQUENCE_LENGTH 4
#define PRODUCTION_ID_COUNT 6

enum {
  anon_sym_let = 1,
  anon_sym_EQ = 2,
  anon_sym_PLUS_PLUS = 3,
  anon_sym_DASH_DASH = 4,
  anon_sym_PLUS = 5,
  anon_sym_DASH = 6,
  anon_sym_STAR = 7,
  anon_sym_SLASH = 8,
  anon_sym_mod = 9,
  anon_sym_PERCENT = 10,
  anon_sym_STAR_STAR = 11,
  anon_sym_log = 12,
  anon_sym_TILDE = 13,
  anon_sym_AMP = 14,
  anon_sym_PIPE = 15,
  anon_sym_CARET = 16,
  anon_sym_LT_LT = 17,
  anon_sym_GT_GT = 18,
  anon_sym_LT_LT_LT = 19,
  anon_sym_GT_GT_GT = 20,
  anon_sym_LPAREN = 21,
  anon_sym_COMMA = 22,
  anon_sym_RPAREN = 23,
  sym_number_value = 24,
  anon_sym_u = 25,
  anon_sym_l = 26,
  anon_sym_U = 27,
  anon_sym_L = 28,
  anon_sym_f = 29,
  anon_sym_F = 30,
  anon_sym_KiB = 31,
  anon_sym_KB = 32,
  anon_sym_MiB = 33,
  anon_sym_MB = 34,
  anon_sym_GiB = 35,
  anon_sym_GB = 36,
  anon_sym_TiB = 37,
  anon_sym_TB = 38,
  anon_sym_EiB = 39,
  anon_sym_EB = 40,
  aux_sym_variable_token1 = 41,
  sym_expression = 42,
  sym__expression = 43,
  sym_let_assignment = 44,
  sym_assignment = 45,
  sym_increment = 46,
  sym_decrement = 47,
  sym_sum = 48,
  sym_subtraction = 49,
  sym_product = 50,
  sym_division = 51,
  sym_modulo = 52,
  sym_exponent = 53,
  sym_logarithm = 54,
  sym_logical_negation = 55,
  sym_logical_and = 56,
  sym_logical_or = 57,
  sym_logical_xor = 58,
  sym_logical_shl = 59,
  sym_logical_shr = 60,
  sym_logical_rol = 61,
  sym_logical_ror = 62,
  sym_function = 63,
  sym_argument_list = 64,
  sym__parenthesized_expression = 65,
  sym_number_suffix = 66,
  sym_number_unit = 67,
  sym_number = 68,
  sym_variable = 69,
  sym_argument_name = 70,
  sym_function_name = 71,
  aux_sym_argument_list_repeat1 = 72,
  aux_sym_number_suffix_repeat1 = 73,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_let] = "let",
  [anon_sym_EQ] = "=",
  [anon_sym_PLUS_PLUS] = "++",
  [anon_sym_DASH_DASH] = "--",
  [anon_sym_PLUS] = "+",
  [anon_sym_DASH] = "-",
  [anon_sym_STAR] = "*",
  [anon_sym_SLASH] = "/",
  [anon_sym_mod] = "mod",
  [anon_sym_PERCENT] = "%",
  [anon_sym_STAR_STAR] = "**",
  [anon_sym_log] = "log",
  [anon_sym_TILDE] = "~",
  [anon_sym_AMP] = "&",
  [anon_sym_PIPE] = "|",
  [anon_sym_CARET] = "^",
  [anon_sym_LT_LT] = "<<",
  [anon_sym_GT_GT] = ">>",
  [anon_sym_LT_LT_LT] = "<<<",
  [anon_sym_GT_GT_GT] = ">>>",
  [anon_sym_LPAREN] = "(",
  [anon_sym_COMMA] = ",",
  [anon_sym_RPAREN] = ")",
  [sym_number_value] = "number_value",
  [anon_sym_u] = "u",
  [anon_sym_l] = "l",
  [anon_sym_U] = "U",
  [anon_sym_L] = "L",
  [anon_sym_f] = "f",
  [anon_sym_F] = "F",
  [anon_sym_KiB] = "KiB",
  [anon_sym_KB] = "KB",
  [anon_sym_MiB] = "MiB",
  [anon_sym_MB] = "MB",
  [anon_sym_GiB] = "GiB",
  [anon_sym_GB] = "GB",
  [anon_sym_TiB] = "TiB",
  [anon_sym_TB] = "TB",
  [anon_sym_EiB] = "EiB",
  [anon_sym_EB] = "EB",
  [aux_sym_variable_token1] = "variable_token1",
  [sym_expression] = "expression",
  [sym__expression] = "_expression",
  [sym_let_assignment] = "let_assignment",
  [sym_assignment] = "assignment",
  [sym_increment] = "increment",
  [sym_decrement] = "decrement",
  [sym_sum] = "sum",
  [sym_subtraction] = "subtraction",
  [sym_product] = "product",
  [sym_division] = "division",
  [sym_modulo] = "modulo",
  [sym_exponent] = "exponent",
  [sym_logarithm] = "logarithm",
  [sym_logical_negation] = "logical_negation",
  [sym_logical_and] = "logical_and",
  [sym_logical_or] = "logical_or",
  [sym_logical_xor] = "logical_xor",
  [sym_logical_shl] = "logical_shl",
  [sym_logical_shr] = "logical_shr",
  [sym_logical_rol] = "logical_rol",
  [sym_logical_ror] = "logical_ror",
  [sym_function] = "function",
  [sym_argument_list] = "argument_list",
  [sym__parenthesized_expression] = "_parenthesized_expression",
  [sym_number_suffix] = "number_suffix",
  [sym_number_unit] = "number_unit",
  [sym_number] = "number",
  [sym_variable] = "variable",
  [sym_argument_name] = "argument_name",
  [sym_function_name] = "function_name",
  [aux_sym_argument_list_repeat1] = "argument_list_repeat1",
  [aux_sym_number_suffix_repeat1] = "number_suffix_repeat1",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [anon_sym_let] = anon_sym_let,
  [anon_sym_EQ] = anon_sym_EQ,
  [anon_sym_PLUS_PLUS] = anon_sym_PLUS_PLUS,
  [anon_sym_DASH_DASH] = anon_sym_DASH_DASH,
  [anon_sym_PLUS] = anon_sym_PLUS,
  [anon_sym_DASH] = anon_sym_DASH,
  [anon_sym_STAR] = anon_sym_STAR,
  [anon_sym_SLASH] = anon_sym_SLASH,
  [anon_sym_mod] = anon_sym_mod,
  [anon_sym_PERCENT] = anon_sym_PERCENT,
  [anon_sym_STAR_STAR] = anon_sym_STAR_STAR,
  [anon_sym_log] = anon_sym_log,
  [anon_sym_TILDE] = anon_sym_TILDE,
  [anon_sym_AMP] = anon_sym_AMP,
  [anon_sym_PIPE] = anon_sym_PIPE,
  [anon_sym_CARET] = anon_sym_CARET,
  [anon_sym_LT_LT] = anon_sym_LT_LT,
  [anon_sym_GT_GT] = anon_sym_GT_GT,
  [anon_sym_LT_LT_LT] = anon_sym_LT_LT_LT,
  [anon_sym_GT_GT_GT] = anon_sym_GT_GT_GT,
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_COMMA] = anon_sym_COMMA,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [sym_number_value] = sym_number_value,
  [anon_sym_u] = anon_sym_u,
  [anon_sym_l] = anon_sym_l,
  [anon_sym_U] = anon_sym_U,
  [anon_sym_L] = anon_sym_L,
  [anon_sym_f] = anon_sym_f,
  [anon_sym_F] = anon_sym_F,
  [anon_sym_KiB] = anon_sym_KiB,
  [anon_sym_KB] = anon_sym_KB,
  [anon_sym_MiB] = anon_sym_MiB,
  [anon_sym_MB] = anon_sym_MB,
  [anon_sym_GiB] = anon_sym_GiB,
  [anon_sym_GB] = anon_sym_GB,
  [anon_sym_TiB] = anon_sym_TiB,
  [anon_sym_TB] = anon_sym_TB,
  [anon_sym_EiB] = anon_sym_EiB,
  [anon_sym_EB] = anon_sym_EB,
  [aux_sym_variable_token1] = aux_sym_variable_token1,
  [sym_expression] = sym_expression,
  [sym__expression] = sym__expression,
  [sym_let_assignment] = sym_let_assignment,
  [sym_assignment] = sym_assignment,
  [sym_increment] = sym_increment,
  [sym_decrement] = sym_decrement,
  [sym_sum] = sym_sum,
  [sym_subtraction] = sym_subtraction,
  [sym_product] = sym_product,
  [sym_division] = sym_division,
  [sym_modulo] = sym_modulo,
  [sym_exponent] = sym_exponent,
  [sym_logarithm] = sym_logarithm,
  [sym_logical_negation] = sym_logical_negation,
  [sym_logical_and] = sym_logical_and,
  [sym_logical_or] = sym_logical_or,
  [sym_logical_xor] = sym_logical_xor,
  [sym_logical_shl] = sym_logical_shl,
  [sym_logical_shr] = sym_logical_shr,
  [sym_logical_rol] = sym_logical_rol,
  [sym_logical_ror] = sym_logical_ror,
  [sym_function] = sym_function,
  [sym_argument_list] = sym_argument_list,
  [sym__parenthesized_expression] = sym__parenthesized_expression,
  [sym_number_suffix] = sym_number_suffix,
  [sym_number_unit] = sym_number_unit,
  [sym_number] = sym_number,
  [sym_variable] = sym_variable,
  [sym_argument_name] = sym_argument_name,
  [sym_function_name] = sym_function_name,
  [aux_sym_argument_list_repeat1] = aux_sym_argument_list_repeat1,
  [aux_sym_number_suffix_repeat1] = aux_sym_number_suffix_repeat1,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
    .named = true,
  },
  [anon_sym_let] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_EQ] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PLUS_PLUS] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_DASH_DASH] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PLUS] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_DASH] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_STAR] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_SLASH] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_mod] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PERCENT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_STAR_STAR] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_log] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_TILDE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_AMP] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_PIPE] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_CARET] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT_LT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT_LT_LT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GT_GT_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_COMMA] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
    .visible = true,
    .named = false,
  },
  [sym_number_value] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_u] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_l] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_U] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_L] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_f] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_F] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_KiB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_KB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_MiB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_MB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GiB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_GB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_TiB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_TB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_EiB] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_EB] = {
    .visible = true,
    .named = false,
  },
  [aux_sym_variable_token1] = {
    .visible = false,
    .named = false,
  },
  [sym_expression] = {
    .visible = true,
    .named = true,
  },
  [sym__expression] = {
    .visible = false,
    .named = true,
  },
  [sym_let_assignment] = {
    .visible = true,
    .named = true,
  },
  [sym_assignment] = {
    .visible = true,
    .named = true,
  },
  [sym_increment] = {
    .visible = true,
    .named = true,
  },
  [sym_decrement] = {
    .visible = true,
    .named = true,
  },
  [sym_sum] = {
    .visible = true,
    .named = true,
  },
  [sym_subtraction] = {
    .visible = true,
    .named = true,
  },
  [sym_product] = {
    .visible = true,
    .named = true,
  },
  [sym_division] = {
    .visible = true,
    .named = true,
  },
  [sym_modulo] = {
    .visible = true,
    .named = true,
  },
  [sym_exponent] = {
    .visible = true,
    .named = true,
  },
  [sym_logarithm] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_negation] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_and] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_or] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_xor] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_shl] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_shr] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_rol] = {
    .visible = true,
    .named = true,
  },
  [sym_logical_ror] = {
    .visible = true,
    .named = true,
  },
  [sym_function] = {
    .visible = true,
    .named = true,
  },
  [sym_argument_list] = {
    .visible = true,
    .named = true,
  },
  [sym__parenthesized_expression] = {
    .visible = false,
    .named = true,
  },
  [sym_number_suffix] = {
    .visible = true,
    .named = true,
  },
  [sym_number_unit] = {
    .visible = true,
    .named = true,
  },
  [sym_number] = {
    .visible = true,
    .named = true,
  },
  [sym_variable] = {
    .visible = true,
    .named = true,
  },
  [sym_argument_name] = {
    .visible = true,
    .named = true,
  },
  [sym_function_name] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_argument_list_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_number_suffix_repeat1] = {
    .visible = false,
    .named = false,
  },
};

enum {
  field_base = 1,
  field_exponent = 2,
  field_left = 3,
  field_right = 4,
};

static const char * const ts_field_names[] = {
  [0] = NULL,
  [field_base] = "base",
  [field_exponent] = "exponent",
  [field_left] = "left",
  [field_right] = "right",
};

static const TSFieldMapSlice ts_field_map_slices[PRODUCTION_ID_COUNT] = {
  [1] = {.index = 0, .length = 1},
  [2] = {.index = 1, .length = 1},
  [3] = {.index = 2, .length = 2},
  [4] = {.index = 4, .length = 2},
  [5] = {.index = 6, .length = 2},
};

static const TSFieldMapEntry ts_field_map_entries[] = {
  [0] =
    {field_left, 1},
  [1] =
    {field_right, 1},
  [2] =
    {field_left, 0},
    {field_right, 2},
  [4] =
    {field_base, 0},
    {field_exponent, 2},
  [6] =
    {field_left, 1},
    {field_right, 3},
};

static const TSSymbol ts_alias_sequences[PRODUCTION_ID_COUNT][MAX_ALIAS_SEQUENCE_LENGTH] = {
  [0] = {0},
};

static const uint16_t ts_non_terminal_alias_map[] = {
  0,
};

static const TSStateId ts_primary_state_ids[STATE_COUNT] = {
  [0] = 0,
  [1] = 1,
  [2] = 2,
  [3] = 3,
  [4] = 4,
  [5] = 5,
  [6] = 6,
  [7] = 7,
  [8] = 8,
  [9] = 9,
  [10] = 10,
  [11] = 11,
  [12] = 12,
  [13] = 13,
  [14] = 14,
  [15] = 15,
  [16] = 16,
  [17] = 17,
  [18] = 18,
  [19] = 19,
  [20] = 20,
  [21] = 21,
  [22] = 22,
  [23] = 23,
  [24] = 24,
  [25] = 25,
  [26] = 26,
  [27] = 27,
  [28] = 28,
  [29] = 29,
  [30] = 30,
  [31] = 31,
  [32] = 32,
  [33] = 33,
  [34] = 34,
  [35] = 35,
  [36] = 36,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 43,
  [44] = 44,
  [45] = 45,
  [46] = 46,
  [47] = 47,
  [48] = 48,
  [49] = 49,
  [50] = 50,
  [51] = 51,
  [52] = 52,
  [53] = 53,
  [54] = 54,
  [55] = 55,
  [56] = 56,
  [57] = 57,
  [58] = 58,
  [59] = 59,
  [60] = 60,
  [61] = 61,
  [62] = 62,
  [63] = 63,
  [64] = 64,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(32);
      if (lookahead == '%') ADVANCE(43);
      if (lookahead == '&') ADVANCE(47);
      if (lookahead == '(') ADVANCE(54);
      if (lookahead == ')') ADVANCE(56);
      if (lookahead == '*') ADVANCE(40);
      if (lookahead == '+') ADVANCE(38);
      if (lookahead == ',') ADVANCE(55);
      if (lookahead == '-') ADVANCE(39);
      if (lookahead == '/') ADVANCE(41);
      if (lookahead == '<') ADVANCE(9);
      if (lookahead == '=') ADVANCE(35);
      if (lookahead == '>') ADVANCE(10);
      if (lookahead == 'E') ADVANCE(11);
      if (lookahead == 'F') ADVANCE(87);
      if (lookahead == 'G') ADVANCE(12);
      if (lookahead == 'K') ADVANCE(13);
      if (lookahead == 'L') ADVANCE(85);
      if (lookahead == 'M') ADVANCE(14);
      if (lookahead == 'T') ADVANCE(15);
      if (lookahead == 'U') ADVANCE(84);
      if (lookahead == '^') ADVANCE(49);
      if (lookahead == 'f') ADVANCE(86);
      if (lookahead == 'l') ADVANCE(82);
      if (lookahead == 'm') ADVANCE(23);
      if (lookahead == 'u') ADVANCE(81);
      if (lookahead == '|') ADVANCE(48);
      if (lookahead == '~') ADVANCE(46);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      END_STATE();
    case 1:
      if (lookahead == '(') ADVANCE(54);
      if (lookahead == '+') ADVANCE(3);
      if (lookahead == '-') ADVANCE(4);
      if (lookahead == '.') ADVANCE(100);
      if (lookahead == '0') ADVANCE(57);
      if (lookahead == 'l') ADVANCE(98);
      if (lookahead == '~') ADVANCE(46);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('1' <= lookahead && lookahead <= '9')) ADVANCE(72);
      if (lookahead != 0 &&
          lookahead > 31 &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 2:
      if (lookahead == ')') ADVANCE(56);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (lookahead != 0 &&
          lookahead > 31 &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          (lookahead < '/' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 3:
      if (lookahead == '+') ADVANCE(36);
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(57);
      if (('1' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 4:
      if (lookahead == '-') ADVANCE(37);
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(57);
      if (('1' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 5:
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(58);
      if (lookahead == '1') ADVANCE(66);
      if (('2' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 6:
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(59);
      if (lookahead == '8' ||
          lookahead == '9') ADVANCE(72);
      if (('1' <= lookahead && lookahead <= '7')) ADVANCE(68);
      END_STATE();
    case 7:
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(60);
      if (lookahead == '1' ||
          lookahead == '2') ADVANCE(69);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 8:
      if (lookahead == '.') ADVANCE(28);
      if (lookahead == '0') ADVANCE(61);
      if (('1' <= lookahead && lookahead <= '9')) ADVANCE(64);
      if (('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      END_STATE();
    case 9:
      if (lookahead == '<') ADVANCE(50);
      END_STATE();
    case 10:
      if (lookahead == '>') ADVANCE(51);
      END_STATE();
    case 11:
      if (lookahead == 'B') ADVANCE(97);
      if (lookahead == 'i') ADVANCE(16);
      END_STATE();
    case 12:
      if (lookahead == 'B') ADVANCE(93);
      if (lookahead == 'i') ADVANCE(17);
      END_STATE();
    case 13:
      if (lookahead == 'B') ADVANCE(89);
      if (lookahead == 'i') ADVANCE(18);
      END_STATE();
    case 14:
      if (lookahead == 'B') ADVANCE(91);
      if (lookahead == 'i') ADVANCE(19);
      END_STATE();
    case 15:
      if (lookahead == 'B') ADVANCE(95);
      if (lookahead == 'i') ADVANCE(20);
      END_STATE();
    case 16:
      if (lookahead == 'B') ADVANCE(96);
      END_STATE();
    case 17:
      if (lookahead == 'B') ADVANCE(92);
      END_STATE();
    case 18:
      if (lookahead == 'B') ADVANCE(88);
      END_STATE();
    case 19:
      if (lookahead == 'B') ADVANCE(90);
      END_STATE();
    case 20:
      if (lookahead == 'B') ADVANCE(94);
      END_STATE();
    case 21:
      if (lookahead == 'd') ADVANCE(42);
      END_STATE();
    case 22:
      if (lookahead == 'g') ADVANCE(45);
      END_STATE();
    case 23:
      if (lookahead == 'o') ADVANCE(21);
      END_STATE();
    case 24:
      if (lookahead == 't') ADVANCE(33);
      END_STATE();
    case 25:
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(67);
      END_STATE();
    case 26:
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(70);
      END_STATE();
    case 27:
      if (('0' <= lookahead && lookahead <= '7')) ADVANCE(71);
      END_STATE();
    case 28:
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(77);
      END_STATE();
    case 29:
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      END_STATE();
    case 30:
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(79);
      END_STATE();
    case 31:
      if (eof) ADVANCE(32);
      if (lookahead == '%') ADVANCE(43);
      if (lookahead == '&') ADVANCE(47);
      if (lookahead == ')') ADVANCE(56);
      if (lookahead == '*') ADVANCE(40);
      if (lookahead == '+') ADVANCE(38);
      if (lookahead == '-') ADVANCE(39);
      if (lookahead == '/') ADVANCE(41);
      if (lookahead == '<') ADVANCE(9);
      if (lookahead == '=') ADVANCE(35);
      if (lookahead == '>') ADVANCE(10);
      if (lookahead == 'E') ADVANCE(11);
      if (lookahead == 'F') ADVANCE(87);
      if (lookahead == 'G') ADVANCE(12);
      if (lookahead == 'K') ADVANCE(13);
      if (lookahead == 'L') ADVANCE(85);
      if (lookahead == 'M') ADVANCE(14);
      if (lookahead == 'T') ADVANCE(15);
      if (lookahead == 'U') ADVANCE(84);
      if (lookahead == '^') ADVANCE(49);
      if (lookahead == 'f') ADVANCE(86);
      if (lookahead == 'l') ADVANCE(83);
      if (lookahead == 'm') ADVANCE(23);
      if (lookahead == 'u') ADVANCE(81);
      if (lookahead == '|') ADVANCE(48);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(31)
      END_STATE();
    case 32:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 33:
      ACCEPT_TOKEN(anon_sym_let);
      END_STATE();
    case 34:
      ACCEPT_TOKEN(anon_sym_let);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          lookahead != '/' &&
          (lookahead < ':' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 35:
      ACCEPT_TOKEN(anon_sym_EQ);
      END_STATE();
    case 36:
      ACCEPT_TOKEN(anon_sym_PLUS_PLUS);
      END_STATE();
    case 37:
      ACCEPT_TOKEN(anon_sym_DASH_DASH);
      END_STATE();
    case 38:
      ACCEPT_TOKEN(anon_sym_PLUS);
      END_STATE();
    case 39:
      ACCEPT_TOKEN(anon_sym_DASH);
      END_STATE();
    case 40:
      ACCEPT_TOKEN(anon_sym_STAR);
      if (lookahead == '*') ADVANCE(44);
      END_STATE();
    case 41:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 42:
      ACCEPT_TOKEN(anon_sym_mod);
      END_STATE();
    case 43:
      ACCEPT_TOKEN(anon_sym_PERCENT);
      END_STATE();
    case 44:
      ACCEPT_TOKEN(anon_sym_STAR_STAR);
      END_STATE();
    case 45:
      ACCEPT_TOKEN(anon_sym_log);
      END_STATE();
    case 46:
      ACCEPT_TOKEN(anon_sym_TILDE);
      END_STATE();
    case 47:
      ACCEPT_TOKEN(anon_sym_AMP);
      END_STATE();
    case 48:
      ACCEPT_TOKEN(anon_sym_PIPE);
      END_STATE();
    case 49:
      ACCEPT_TOKEN(anon_sym_CARET);
      END_STATE();
    case 50:
      ACCEPT_TOKEN(anon_sym_LT_LT);
      if (lookahead == '<') ADVANCE(52);
      END_STATE();
    case 51:
      ACCEPT_TOKEN(anon_sym_GT_GT);
      if (lookahead == '>') ADVANCE(53);
      END_STATE();
    case 52:
      ACCEPT_TOKEN(anon_sym_LT_LT_LT);
      END_STATE();
    case 53:
      ACCEPT_TOKEN(anon_sym_GT_GT_GT);
      END_STATE();
    case 54:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 55:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 56:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 57:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'b') ADVANCE(5);
      if (lookahead == 'o') ADVANCE(6);
      if (lookahead == 't') ADVANCE(7);
      if (lookahead == 'x') ADVANCE(8);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 58:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'b') ADVANCE(25);
      if (lookahead == 'o') ADVANCE(27);
      if (lookahead == 't') ADVANCE(26);
      if (lookahead == 'x') ADVANCE(29);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(66);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('2' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 59:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'b') ADVANCE(25);
      if (lookahead == 'o') ADVANCE(27);
      if (lookahead == 't') ADVANCE(26);
      if (lookahead == 'x') ADVANCE(29);
      if (lookahead == '8' ||
          lookahead == '9') ADVANCE(72);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '7')) ADVANCE(68);
      END_STATE();
    case 60:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'b') ADVANCE(25);
      if (lookahead == 'o') ADVANCE(27);
      if (lookahead == 't') ADVANCE(26);
      if (lookahead == 'x') ADVANCE(29);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(69);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 61:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'b') ADVANCE(63);
      if (lookahead == 'o') ADVANCE(27);
      if (lookahead == 't') ADVANCE(26);
      if (lookahead == 'x') ADVANCE(29);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(62);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(64);
      END_STATE();
    case 62:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == '+' ||
          lookahead == '-') ADVANCE(30);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(62);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      END_STATE();
    case 63:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(62);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(63);
      if (('2' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      END_STATE();
    case 64:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(62);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(64);
      END_STATE();
    case 65:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(62);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(65);
      END_STATE();
    case 66:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(66);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('2' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 67:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == '0' ||
          lookahead == '1') ADVANCE(67);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      END_STATE();
    case 68:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == '8' ||
          lookahead == '9') ADVANCE(72);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '7')) ADVANCE(68);
      END_STATE();
    case 69:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(69);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('3' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 70:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (('0' <= lookahead && lookahead <= '2')) ADVANCE(70);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      END_STATE();
    case 71:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '7')) ADVANCE(71);
      END_STATE();
    case 72:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '.') ADVANCE(76);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(72);
      END_STATE();
    case 73:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '+' ||
          lookahead == '-') ADVANCE(30);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(73);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(76);
      END_STATE();
    case 74:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '+' ||
          lookahead == '-') ADVANCE(30);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(79);
      END_STATE();
    case 75:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == '+' ||
          lookahead == '-') ADVANCE(30);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(80);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || ',' < lookahead) &&
          (lookahead < '/' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 76:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == 'E' ||
          lookahead == 'e') ADVANCE(73);
      if (lookahead == 'P' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(76);
      END_STATE();
    case 77:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(74);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(77);
      END_STATE();
    case 78:
      ACCEPT_TOKEN(sym_number_value);
      if (lookahead == 'E' ||
          lookahead == 'P' ||
          lookahead == 'e' ||
          lookahead == 'p') ADVANCE(75);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(78);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          (lookahead < '/' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 79:
      ACCEPT_TOKEN(sym_number_value);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(79);
      END_STATE();
    case 80:
      ACCEPT_TOKEN(sym_number_value);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'F') ||
          ('a' <= lookahead && lookahead <= 'f')) ADVANCE(80);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          (lookahead < '/' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 81:
      ACCEPT_TOKEN(anon_sym_u);
      END_STATE();
    case 82:
      ACCEPT_TOKEN(anon_sym_l);
      if (lookahead == 'e') ADVANCE(24);
      if (lookahead == 'o') ADVANCE(22);
      END_STATE();
    case 83:
      ACCEPT_TOKEN(anon_sym_l);
      if (lookahead == 'o') ADVANCE(22);
      END_STATE();
    case 84:
      ACCEPT_TOKEN(anon_sym_U);
      END_STATE();
    case 85:
      ACCEPT_TOKEN(anon_sym_L);
      END_STATE();
    case 86:
      ACCEPT_TOKEN(anon_sym_f);
      END_STATE();
    case 87:
      ACCEPT_TOKEN(anon_sym_F);
      END_STATE();
    case 88:
      ACCEPT_TOKEN(anon_sym_KiB);
      END_STATE();
    case 89:
      ACCEPT_TOKEN(anon_sym_KB);
      END_STATE();
    case 90:
      ACCEPT_TOKEN(anon_sym_MiB);
      END_STATE();
    case 91:
      ACCEPT_TOKEN(anon_sym_MB);
      END_STATE();
    case 92:
      ACCEPT_TOKEN(anon_sym_GiB);
      END_STATE();
    case 93:
      ACCEPT_TOKEN(anon_sym_GB);
      END_STATE();
    case 94:
      ACCEPT_TOKEN(anon_sym_TiB);
      END_STATE();
    case 95:
      ACCEPT_TOKEN(anon_sym_TB);
      END_STATE();
    case 96:
      ACCEPT_TOKEN(anon_sym_EiB);
      END_STATE();
    case 97:
      ACCEPT_TOKEN(anon_sym_EB);
      END_STATE();
    case 98:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (lookahead == 'e') ADVANCE(99);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          lookahead != '/' &&
          (lookahead < ':' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 99:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (lookahead == 't') ADVANCE(34);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          lookahead != '/' &&
          (lookahead < ':' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 100:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(78);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          (lookahead < '/' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    case 101:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (lookahead != 0 &&
          lookahead > ' ' &&
          lookahead != '"' &&
          lookahead != '#' &&
          (lookahead < '%' || '-' < lookahead) &&
          lookahead != '/' &&
          (lookahead < ':' || '>' < lookahead) &&
          (lookahead < '[' || '^' < lookahead) &&
          (lookahead < '{' || 159 < lookahead)) ADVANCE(101);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 1},
  [2] = {.lex_state = 31},
  [3] = {.lex_state = 1},
  [4] = {.lex_state = 1},
  [5] = {.lex_state = 1},
  [6] = {.lex_state = 1},
  [7] = {.lex_state = 1},
  [8] = {.lex_state = 1},
  [9] = {.lex_state = 1},
  [10] = {.lex_state = 1},
  [11] = {.lex_state = 1},
  [12] = {.lex_state = 1},
  [13] = {.lex_state = 1},
  [14] = {.lex_state = 1},
  [15] = {.lex_state = 1},
  [16] = {.lex_state = 1},
  [17] = {.lex_state = 1},
  [18] = {.lex_state = 1},
  [19] = {.lex_state = 1},
  [20] = {.lex_state = 1},
  [21] = {.lex_state = 1},
  [22] = {.lex_state = 1},
  [23] = {.lex_state = 1},
  [24] = {.lex_state = 31},
  [25] = {.lex_state = 31},
  [26] = {.lex_state = 0},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 0},
  [29] = {.lex_state = 0},
  [30] = {.lex_state = 0},
  [31] = {.lex_state = 0},
  [32] = {.lex_state = 0},
  [33] = {.lex_state = 0},
  [34] = {.lex_state = 0},
  [35] = {.lex_state = 0},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 0},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 0},
  [52] = {.lex_state = 0},
  [53] = {.lex_state = 0},
  [54] = {.lex_state = 0},
  [55] = {.lex_state = 0},
  [56] = {.lex_state = 0},
  [57] = {.lex_state = 2},
  [58] = {.lex_state = 0},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 0},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 2},
  [63] = {.lex_state = 0},
  [64] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_let] = ACTIONS(1),
    [anon_sym_EQ] = ACTIONS(1),
    [anon_sym_PLUS] = ACTIONS(1),
    [anon_sym_DASH] = ACTIONS(1),
    [anon_sym_STAR] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [anon_sym_mod] = ACTIONS(1),
    [anon_sym_PERCENT] = ACTIONS(1),
    [anon_sym_STAR_STAR] = ACTIONS(1),
    [anon_sym_log] = ACTIONS(1),
    [anon_sym_TILDE] = ACTIONS(1),
    [anon_sym_AMP] = ACTIONS(1),
    [anon_sym_PIPE] = ACTIONS(1),
    [anon_sym_CARET] = ACTIONS(1),
    [anon_sym_LT_LT] = ACTIONS(1),
    [anon_sym_GT_GT] = ACTIONS(1),
    [anon_sym_LT_LT_LT] = ACTIONS(1),
    [anon_sym_GT_GT_GT] = ACTIONS(1),
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_COMMA] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [anon_sym_u] = ACTIONS(1),
    [anon_sym_l] = ACTIONS(1),
    [anon_sym_U] = ACTIONS(1),
    [anon_sym_L] = ACTIONS(1),
    [anon_sym_f] = ACTIONS(1),
    [anon_sym_F] = ACTIONS(1),
    [anon_sym_KiB] = ACTIONS(1),
    [anon_sym_KB] = ACTIONS(1),
    [anon_sym_MiB] = ACTIONS(1),
    [anon_sym_MB] = ACTIONS(1),
    [anon_sym_GiB] = ACTIONS(1),
    [anon_sym_GB] = ACTIONS(1),
    [anon_sym_TiB] = ACTIONS(1),
    [anon_sym_TB] = ACTIONS(1),
    [anon_sym_EiB] = ACTIONS(1),
    [anon_sym_EB] = ACTIONS(1),
  },
  [1] = {
    [sym_expression] = STATE(64),
    [sym__expression] = STATE(53),
    [sym_let_assignment] = STATE(53),
    [sym_assignment] = STATE(53),
    [sym_increment] = STATE(53),
    [sym_decrement] = STATE(53),
    [sym_sum] = STATE(53),
    [sym_subtraction] = STATE(53),
    [sym_product] = STATE(53),
    [sym_division] = STATE(53),
    [sym_modulo] = STATE(53),
    [sym_exponent] = STATE(53),
    [sym_logarithm] = STATE(53),
    [sym_logical_negation] = STATE(53),
    [sym_logical_and] = STATE(53),
    [sym_logical_or] = STATE(53),
    [sym_logical_xor] = STATE(53),
    [sym_logical_shl] = STATE(53),
    [sym_logical_shr] = STATE(53),
    [sym_logical_rol] = STATE(53),
    [sym_logical_ror] = STATE(53),
    [sym_function] = STATE(53),
    [sym__parenthesized_expression] = STATE(53),
    [sym_number] = STATE(53),
    [sym_variable] = STATE(53),
    [sym_function_name] = STATE(60),
    [anon_sym_let] = ACTIONS(3),
    [anon_sym_PLUS_PLUS] = ACTIONS(5),
    [anon_sym_DASH_DASH] = ACTIONS(7),
    [anon_sym_TILDE] = ACTIONS(9),
    [anon_sym_LPAREN] = ACTIONS(11),
    [sym_number_value] = ACTIONS(13),
    [aux_sym_variable_token1] = ACTIONS(15),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 7,
    ACTIONS(23), 1,
      anon_sym_l,
    STATE(25), 1,
      aux_sym_number_suffix_repeat1,
    STATE(29), 2,
      sym_number_suffix,
      sym_number_unit,
    ACTIONS(19), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(21), 5,
      anon_sym_u,
      anon_sym_U,
      anon_sym_L,
      anon_sym_f,
      anon_sym_F,
    ACTIONS(25), 10,
      anon_sym_KiB,
      anon_sym_KB,
      anon_sym_MiB,
      anon_sym_MB,
      anon_sym_GiB,
      anon_sym_GB,
      anon_sym_TiB,
      anon_sym_TB,
      anon_sym_EiB,
      anon_sym_EB,
    ACTIONS(17), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [52] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(39), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [103] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(45), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [154] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(32), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [205] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(31), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [256] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(54), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [307] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(46), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [358] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(33), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [409] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(35), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [460] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(37), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [511] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(47), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [562] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(52), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [613] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(51), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [664] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(50), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [715] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(49), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [766] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(55), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [817] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(48), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [868] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(40), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [919] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(41), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [970] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(42), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [1021] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(43), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [1072] = 9,
    ACTIONS(3), 1,
      anon_sym_let,
    ACTIONS(5), 1,
      anon_sym_PLUS_PLUS,
    ACTIONS(7), 1,
      anon_sym_DASH_DASH,
    ACTIONS(9), 1,
      anon_sym_TILDE,
    ACTIONS(11), 1,
      anon_sym_LPAREN,
    ACTIONS(13), 1,
      sym_number_value,
    ACTIONS(15), 1,
      aux_sym_variable_token1,
    STATE(60), 1,
      sym_function_name,
    STATE(44), 24,
      sym__expression,
      sym_let_assignment,
      sym_assignment,
      sym_increment,
      sym_decrement,
      sym_sum,
      sym_subtraction,
      sym_product,
      sym_division,
      sym_modulo,
      sym_exponent,
      sym_logarithm,
      sym_logical_negation,
      sym_logical_and,
      sym_logical_or,
      sym_logical_xor,
      sym_logical_shl,
      sym_logical_shr,
      sym_logical_rol,
      sym_logical_ror,
      sym_function,
      sym__parenthesized_expression,
      sym_number,
      sym_variable,
  [1123] = 5,
    ACTIONS(34), 1,
      anon_sym_l,
    STATE(24), 1,
      aux_sym_number_suffix_repeat1,
    ACTIONS(29), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(31), 5,
      anon_sym_u,
      anon_sym_U,
      anon_sym_L,
      anon_sym_f,
      anon_sym_F,
    ACTIONS(27), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1159] = 5,
    ACTIONS(43), 1,
      anon_sym_l,
    STATE(24), 1,
      aux_sym_number_suffix_repeat1,
    ACTIONS(39), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(41), 5,
      anon_sym_u,
      anon_sym_U,
      anon_sym_L,
      anon_sym_f,
      anon_sym_F,
    ACTIONS(37), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1195] = 3,
    ACTIONS(49), 1,
      anon_sym_LPAREN,
    ACTIONS(47), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(45), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1221] = 2,
    ACTIONS(53), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(51), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1244] = 2,
    ACTIONS(57), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(55), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1267] = 2,
    ACTIONS(61), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(59), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1290] = 2,
    ACTIONS(65), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(63), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1313] = 2,
    ACTIONS(69), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(67), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1336] = 2,
    ACTIONS(73), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(71), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1359] = 2,
    ACTIONS(77), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(75), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1382] = 2,
    ACTIONS(81), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(79), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1405] = 15,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(99), 1,
      anon_sym_AMP,
    ACTIONS(101), 1,
      anon_sym_PIPE,
    ACTIONS(103), 1,
      anon_sym_CARET,
    ACTIONS(105), 1,
      anon_sym_LT_LT,
    ACTIONS(107), 1,
      anon_sym_GT_GT,
    ACTIONS(109), 1,
      anon_sym_LT_LT_LT,
    ACTIONS(111), 1,
      anon_sym_GT_GT_GT,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(83), 3,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_RPAREN,
  [1454] = 2,
    ACTIONS(115), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(113), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1477] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(119), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(117), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1514] = 2,
    ACTIONS(123), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(121), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1537] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(127), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(125), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1574] = 15,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(99), 1,
      anon_sym_AMP,
    ACTIONS(101), 1,
      anon_sym_PIPE,
    ACTIONS(103), 1,
      anon_sym_CARET,
    ACTIONS(105), 1,
      anon_sym_LT_LT,
    ACTIONS(107), 1,
      anon_sym_GT_GT,
    ACTIONS(109), 1,
      anon_sym_LT_LT_LT,
    ACTIONS(111), 1,
      anon_sym_GT_GT_GT,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(129), 3,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_RPAREN,
  [1623] = 7,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(133), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(131), 10,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1656] = 7,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(137), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(135), 10,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1689] = 4,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(141), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(139), 13,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1716] = 4,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(145), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(143), 13,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1743] = 4,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(149), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(147), 13,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1770] = 2,
    ACTIONS(153), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(151), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1793] = 2,
    ACTIONS(157), 3,
      anon_sym_STAR,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(155), 15,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_PLUS,
      anon_sym_DASH,
      anon_sym_SLASH,
      anon_sym_mod,
      anon_sym_PERCENT,
      anon_sym_STAR_STAR,
      anon_sym_log,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1816] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(161), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(159), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1853] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(165), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(163), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1890] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(169), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(167), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1927] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(173), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(171), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [1964] = 9,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
    ACTIONS(177), 2,
      anon_sym_LT_LT,
      anon_sym_GT_GT,
    ACTIONS(175), 8,
      ts_builtin_sym_end,
      anon_sym_EQ,
      anon_sym_AMP,
      anon_sym_PIPE,
      anon_sym_CARET,
      anon_sym_LT_LT_LT,
      anon_sym_GT_GT_GT,
      anon_sym_RPAREN,
  [2001] = 16,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(99), 1,
      anon_sym_AMP,
    ACTIONS(101), 1,
      anon_sym_PIPE,
    ACTIONS(103), 1,
      anon_sym_CARET,
    ACTIONS(105), 1,
      anon_sym_LT_LT,
    ACTIONS(107), 1,
      anon_sym_GT_GT,
    ACTIONS(109), 1,
      anon_sym_LT_LT_LT,
    ACTIONS(111), 1,
      anon_sym_GT_GT_GT,
    ACTIONS(179), 1,
      ts_builtin_sym_end,
    ACTIONS(181), 1,
      anon_sym_EQ,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
  [2051] = 16,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(99), 1,
      anon_sym_AMP,
    ACTIONS(101), 1,
      anon_sym_PIPE,
    ACTIONS(103), 1,
      anon_sym_CARET,
    ACTIONS(105), 1,
      anon_sym_LT_LT,
    ACTIONS(107), 1,
      anon_sym_GT_GT,
    ACTIONS(109), 1,
      anon_sym_LT_LT_LT,
    ACTIONS(111), 1,
      anon_sym_GT_GT_GT,
    ACTIONS(181), 1,
      anon_sym_EQ,
    ACTIONS(183), 1,
      anon_sym_RPAREN,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
  [2101] = 15,
    ACTIONS(85), 1,
      anon_sym_PLUS,
    ACTIONS(87), 1,
      anon_sym_DASH,
    ACTIONS(89), 1,
      anon_sym_STAR,
    ACTIONS(91), 1,
      anon_sym_SLASH,
    ACTIONS(95), 1,
      anon_sym_STAR_STAR,
    ACTIONS(97), 1,
      anon_sym_log,
    ACTIONS(99), 1,
      anon_sym_AMP,
    ACTIONS(101), 1,
      anon_sym_PIPE,
    ACTIONS(103), 1,
      anon_sym_CARET,
    ACTIONS(105), 1,
      anon_sym_LT_LT,
    ACTIONS(107), 1,
      anon_sym_GT_GT,
    ACTIONS(109), 1,
      anon_sym_LT_LT_LT,
    ACTIONS(111), 1,
      anon_sym_GT_GT_GT,
    ACTIONS(185), 1,
      anon_sym_EQ,
    ACTIONS(93), 2,
      anon_sym_mod,
      anon_sym_PERCENT,
  [2148] = 3,
    ACTIONS(187), 1,
      anon_sym_COMMA,
    ACTIONS(189), 1,
      anon_sym_RPAREN,
    STATE(58), 1,
      aux_sym_argument_list_repeat1,
  [2158] = 3,
    ACTIONS(191), 1,
      anon_sym_RPAREN,
    ACTIONS(193), 1,
      aux_sym_variable_token1,
    STATE(56), 1,
      sym_argument_name,
  [2168] = 3,
    ACTIONS(187), 1,
      anon_sym_COMMA,
    ACTIONS(195), 1,
      anon_sym_RPAREN,
    STATE(59), 1,
      aux_sym_argument_list_repeat1,
  [2178] = 3,
    ACTIONS(197), 1,
      anon_sym_COMMA,
    ACTIONS(200), 1,
      anon_sym_RPAREN,
    STATE(59), 1,
      aux_sym_argument_list_repeat1,
  [2188] = 2,
    ACTIONS(202), 1,
      anon_sym_LPAREN,
    STATE(36), 1,
      sym_argument_list,
  [2195] = 1,
    ACTIONS(204), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [2200] = 2,
    ACTIONS(193), 1,
      aux_sym_variable_token1,
    STATE(63), 1,
      sym_argument_name,
  [2207] = 1,
    ACTIONS(200), 2,
      anon_sym_COMMA,
      anon_sym_RPAREN,
  [2212] = 1,
    ACTIONS(206), 1,
      ts_builtin_sym_end,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(2)] = 0,
  [SMALL_STATE(3)] = 52,
  [SMALL_STATE(4)] = 103,
  [SMALL_STATE(5)] = 154,
  [SMALL_STATE(6)] = 205,
  [SMALL_STATE(7)] = 256,
  [SMALL_STATE(8)] = 307,
  [SMALL_STATE(9)] = 358,
  [SMALL_STATE(10)] = 409,
  [SMALL_STATE(11)] = 460,
  [SMALL_STATE(12)] = 511,
  [SMALL_STATE(13)] = 562,
  [SMALL_STATE(14)] = 613,
  [SMALL_STATE(15)] = 664,
  [SMALL_STATE(16)] = 715,
  [SMALL_STATE(17)] = 766,
  [SMALL_STATE(18)] = 817,
  [SMALL_STATE(19)] = 868,
  [SMALL_STATE(20)] = 919,
  [SMALL_STATE(21)] = 970,
  [SMALL_STATE(22)] = 1021,
  [SMALL_STATE(23)] = 1072,
  [SMALL_STATE(24)] = 1123,
  [SMALL_STATE(25)] = 1159,
  [SMALL_STATE(26)] = 1195,
  [SMALL_STATE(27)] = 1221,
  [SMALL_STATE(28)] = 1244,
  [SMALL_STATE(29)] = 1267,
  [SMALL_STATE(30)] = 1290,
  [SMALL_STATE(31)] = 1313,
  [SMALL_STATE(32)] = 1336,
  [SMALL_STATE(33)] = 1359,
  [SMALL_STATE(34)] = 1382,
  [SMALL_STATE(35)] = 1405,
  [SMALL_STATE(36)] = 1454,
  [SMALL_STATE(37)] = 1477,
  [SMALL_STATE(38)] = 1514,
  [SMALL_STATE(39)] = 1537,
  [SMALL_STATE(40)] = 1574,
  [SMALL_STATE(41)] = 1623,
  [SMALL_STATE(42)] = 1656,
  [SMALL_STATE(43)] = 1689,
  [SMALL_STATE(44)] = 1716,
  [SMALL_STATE(45)] = 1743,
  [SMALL_STATE(46)] = 1770,
  [SMALL_STATE(47)] = 1793,
  [SMALL_STATE(48)] = 1816,
  [SMALL_STATE(49)] = 1853,
  [SMALL_STATE(50)] = 1890,
  [SMALL_STATE(51)] = 1927,
  [SMALL_STATE(52)] = 1964,
  [SMALL_STATE(53)] = 2001,
  [SMALL_STATE(54)] = 2051,
  [SMALL_STATE(55)] = 2101,
  [SMALL_STATE(56)] = 2148,
  [SMALL_STATE(57)] = 2158,
  [SMALL_STATE(58)] = 2168,
  [SMALL_STATE(59)] = 2178,
  [SMALL_STATE(60)] = 2188,
  [SMALL_STATE(61)] = 2195,
  [SMALL_STATE(62)] = 2200,
  [SMALL_STATE(63)] = 2207,
  [SMALL_STATE(64)] = 2212,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = false}}, SHIFT(17),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [7] = {.entry = {.count = 1, .reusable = true}}, SHIFT(5),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(2),
  [15] = {.entry = {.count = 1, .reusable = false}}, SHIFT(26),
  [17] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number, 1),
  [19] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number, 1),
  [21] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [23] = {.entry = {.count = 1, .reusable = false}}, SHIFT(25),
  [25] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [27] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_number_suffix_repeat1, 2),
  [29] = {.entry = {.count = 1, .reusable = false}}, REDUCE(aux_sym_number_suffix_repeat1, 2),
  [31] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_number_suffix_repeat1, 2), SHIFT_REPEAT(24),
  [34] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_number_suffix_repeat1, 2), SHIFT_REPEAT(24),
  [37] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_suffix, 1),
  [39] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_suffix, 1),
  [41] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [43] = {.entry = {.count = 1, .reusable = false}}, SHIFT(24),
  [45] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_variable, 1),
  [47] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_variable, 1),
  [49] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_function_name, 1),
  [51] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number_unit, 1),
  [53] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number_unit, 1),
  [55] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_argument_list, 2),
  [57] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_argument_list, 2),
  [59] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_number, 2),
  [61] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_number, 2),
  [63] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_argument_list, 4),
  [65] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_argument_list, 4),
  [67] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_negation, 2, .production_id = 2),
  [69] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_negation, 2, .production_id = 2),
  [71] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_decrement, 2, .production_id = 1),
  [73] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_decrement, 2, .production_id = 1),
  [75] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_increment, 2, .production_id = 1),
  [77] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_increment, 2, .production_id = 1),
  [79] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_argument_list, 3),
  [81] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_argument_list, 3),
  [83] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_let_assignment, 4, .production_id = 5),
  [85] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [87] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [89] = {.entry = {.count = 1, .reusable = false}}, SHIFT(22),
  [91] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [93] = {.entry = {.count = 1, .reusable = true}}, SHIFT(4),
  [95] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [97] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [99] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [101] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [103] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [105] = {.entry = {.count = 1, .reusable = false}}, SHIFT(14),
  [107] = {.entry = {.count = 1, .reusable = false}}, SHIFT(13),
  [109] = {.entry = {.count = 1, .reusable = true}}, SHIFT(3),
  [111] = {.entry = {.count = 1, .reusable = true}}, SHIFT(11),
  [113] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_function, 2),
  [115] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_function, 2),
  [117] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_ror, 3, .production_id = 3),
  [119] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_ror, 3, .production_id = 3),
  [121] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym__parenthesized_expression, 3),
  [123] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym__parenthesized_expression, 3),
  [125] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_rol, 3, .production_id = 3),
  [127] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_rol, 3, .production_id = 3),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_assignment, 3, .production_id = 3),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_sum, 3, .production_id = 3),
  [133] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_sum, 3, .production_id = 3),
  [135] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_subtraction, 3, .production_id = 3),
  [137] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_subtraction, 3, .production_id = 3),
  [139] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_product, 3, .production_id = 3),
  [141] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_product, 3, .production_id = 3),
  [143] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_division, 3, .production_id = 3),
  [145] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_division, 3, .production_id = 3),
  [147] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_modulo, 3, .production_id = 3),
  [149] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_modulo, 3, .production_id = 3),
  [151] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_exponent, 3, .production_id = 4),
  [153] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_exponent, 3, .production_id = 4),
  [155] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logarithm, 3, .production_id = 4),
  [157] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logarithm, 3, .production_id = 4),
  [159] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_and, 3, .production_id = 3),
  [161] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_and, 3, .production_id = 3),
  [163] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_or, 3, .production_id = 3),
  [165] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_or, 3, .production_id = 3),
  [167] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_xor, 3, .production_id = 3),
  [169] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_xor, 3, .production_id = 3),
  [171] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_shl, 3, .production_id = 3),
  [173] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_shl, 3, .production_id = 3),
  [175] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_logical_shr, 3, .production_id = 3),
  [177] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_logical_shr, 3, .production_id = 3),
  [179] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_expression, 1),
  [181] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [183] = {.entry = {.count = 1, .reusable = true}}, SHIFT(38),
  [185] = {.entry = {.count = 1, .reusable = true}}, SHIFT(10),
  [187] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [191] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [193] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [195] = {.entry = {.count = 1, .reusable = true}}, SHIFT(30),
  [197] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_argument_list_repeat1, 2), SHIFT_REPEAT(62),
  [200] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_argument_list_repeat1, 2),
  [202] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [204] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_argument_name, 1),
  [206] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef _WIN32
#define extern __declspec(dllexport)
#endif

extern const TSLanguage *tree_sitter_rznum(void) {
  static const TSLanguage language = {
    .version = LANGUAGE_VERSION,
    .symbol_count = SYMBOL_COUNT,
    .alias_count = ALIAS_COUNT,
    .token_count = TOKEN_COUNT,
    .external_token_count = EXTERNAL_TOKEN_COUNT,
    .state_count = STATE_COUNT,
    .large_state_count = LARGE_STATE_COUNT,
    .production_id_count = PRODUCTION_ID_COUNT,
    .field_count = FIELD_COUNT,
    .max_alias_sequence_length = MAX_ALIAS_SEQUENCE_LENGTH,
    .parse_table = &ts_parse_table[0][0],
    .small_parse_table = ts_small_parse_table,
    .small_parse_table_map = ts_small_parse_table_map,
    .parse_actions = ts_parse_actions,
    .symbol_names = ts_symbol_names,
    .field_names = ts_field_names,
    .field_map_slices = ts_field_map_slices,
    .field_map_entries = ts_field_map_entries,
    .symbol_metadata = ts_symbol_metadata,
    .public_symbol_map = ts_symbol_map,
    .alias_map = ts_non_terminal_alias_map,
    .alias_sequences = &ts_alias_sequences[0][0],
    .lex_modes = ts_lex_modes,
    .lex_fn = ts_lex,
    .primary_state_ids = ts_primary_state_ids,
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
