// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

#include "parse_helper.h"

static RzList /*<char *>*/ *luac_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar luac_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("move", "1 := 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadi", "1 := 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadf", "1 := (lua_Number)2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadk", "1 := K[2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadkx", "1 := K[extra arg]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadfalse", "1 := false"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lfalseskip", "1 := false; pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadtrue", "1 := true"),
	RZ_PSEUDO_DEFINE_GRAMMAR("loadnil", "r[1], r[1+#1], ..., r[1+2] := nil"),
	RZ_PSEUDO_DEFINE_GRAMMAR("getupval", "1 := UpValue[2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("setupval", "UpValue[2] := 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("gettabup", "1 := UpValue[2][K[3]:shortstring]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("gettable", "1 := r[2][r[3]]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("geti", "1 := r[2][3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("getfield", "1 := 2[K[3]:shortstring]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("settabup", "UpValue[1][K[2]:shortstring] := RK(3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("settable", "r[1][r[2]] := RK(3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("seti", "r[1][2] := RK(3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("setfield", "1[K[2]:shortstring] := RK(3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("newtable", "1 := {} (size = 2,3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("self", "2 := 1 (self), 3 := 2[3]"), // r3=r1 (self), r2=r1['batch_deposit']
	RZ_PSEUDO_DEFINE_GRAMMAR("addi", "1 := 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addk", "1 := 2 + K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subk", "1 := 2 - K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mulk", "1 := 2 * K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("modk", "1 := 2 % K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("powk", "1 := 2 ^ K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("divk", "1 := 2 / K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("idivk", "1 := 2 // K[3]:number"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bandk", "1 := 2 & K[3]:integer"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bork", "1 := 2 & K[3]:integer"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bxork", "1 := 2 & K[3]:integer"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shri", "1 := 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shli", "1 := 3 << 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 := 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 := 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul", "1 := 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mod", "1 := 2 % 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pow", "1 := 2 ^ 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div", "1 := 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("idiv", "1 := 2 // 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("band", "1 := 2 & 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bor", "1 := 2 | 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bxor", "1 := 2 ~ 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl", "1 := 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr", "1 := 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mmbin", "call 3 metamethod over 1 and 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mmbini", "call 3 metamethod over 1 and 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mmbink", "call 3 metamethod over 1 and K[2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("unm", "1 := -2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bnot", "1 := ~2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("not", "1 := not 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("len", "1 := #R[2] (length operator)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("concat", "1 := 1..2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("close", "close all upvalues >= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tbc", "mark variable 1 \"to be closed\""),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto pc + 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eq", "if ((1 == 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lt", "if ((1 < 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("le", "if ((1 <= 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eqk", "if ((1 == K[2]) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eqi", "if ((1 == 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lti", "if ((1 < 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lei", "if ((1 <= 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ti", "if ((1 > 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("gei", "if ((1 >= 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("gti", "if ((1 > 2) ~= k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("test", "if (1 != k) then pc++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("testset", "if (not 2 == k) then pc++ else 1 := 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("call", "call 1; (2 in; 2 out)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tailcall", "return 1(R[1+#1], ... ,R[1+2-#1])"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return", "return 1, ... ,r[2+3-#2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return0", "return;"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return1", "return#1 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("forloop", "update counters; if loop continues then pc-=2;"),
	RZ_PSEUDO_DEFINE_GRAMMAR("forprep", "<check values and prepare counters>; if not to run then pc+=2+#1;"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tforprep", "create upvalue for r[1 + #3]; pc+=2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tforcall", "r[1+#4], ... ,r[1+#3+2] := 1(r[1+#1], r[1+#2]);"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tforloop", "if r[1+#2] ~= nil then { 1=r[1+#2]; pc -= 2 }"),
	RZ_PSEUDO_DEFINE_GRAMMAR("setlist", "1[3+i] := r[1+i], #1 <= i <= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("closure", "1 := closure(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vararg", "1, r[..+#1], ..., r[..+2-#2] = vararg"),
	RZ_PSEUDO_DEFINE_GRAMMAR("varargprep", "varargs, 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("extraarg", "extra (larger) argument for previous opcode (1)"),
};

static const RzPseudoConfig luac_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(luac_lexicon, 4, luac_tokenize);

RzList /*<char *>*/ *luac_tokenize(const char *assembly, size_t length) {
	char *buf = NULL;
	RzList /*<char *>*/ *tokens = NULL;

	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	tokens = rz_str_split_duplist(buf, " ", true);
	free(buf);
	if (!tokens) {
		return NULL;
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&luac_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_luac_pseudo = {
	.name = "luac.pseudo",
	.desc = "luac pseudo syntax",
	.parse = parse,
};
