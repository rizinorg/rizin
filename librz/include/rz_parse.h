// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2018 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PARSE_H
#define RZ_PARSE_H

#include <rz_types.h>
#include <rz_flag.h>
#include <rz_analysis.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_parse);

typedef RzList *(*RzAnalysisVarList)(RzAnalysisFunction *fcn, int kind);

typedef struct rz_parse_t {
	void *user;
	RzSpace *flagspace;
	RzSpace *notin_flagspace;
	bool pseudo;
	bool subreg; // replace registers with their respective alias/role name (rdi=A0, ...)
	bool subrel; // replace rip relative expressions in instruction
	bool subtail; // replace any immediate relative to current address with .. prefix syntax
	bool localvar_only; // if true use only the local variable name (e.g. [local_10h] instead of [ebp + local10h])
	ut64 subrel_addr;
	int maxflagnamelen;
	int minval;
	char *retleave_asm;
	struct rz_parse_plugin_t *cur;
	// RzAnalysis *analysis; // weak analysis ref XXX do not use. use analb.anal
	RzList *parsers;
	RzAnalysisVarList varlist;
	st64 (*get_ptr_at)(RzAnalysisFunction *fcn, st64 delta, ut64 addr);
	const char *(*get_reg_at)(RzAnalysisFunction *fcn, st64 delta, ut64 addr);
	char *(*get_op_ireg)(void *user, ut64 addr);
	RzAnalysisBind analb;
	RzFlagGetAtAddr flag_get; // XXX
	RzAnalysisLabelAt label_get;
} RzParse;

typedef struct rz_parse_plugin_t {
	char *name;
	char *desc;
	bool (*init)(RzParse *p, void *user);
	int (*fini)(RzParse *p, void *user);
	int (*parse)(RzParse *p, const char *data, char *str);
	bool (*assemble)(RzParse *p, char *data, char *str);
	int (*filter)(RzParse *p, ut64 addr, RzFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*subvar)(RzParse *p, RzAnalysisFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
	int (*replace)(int argc, const char *argv[], char *newstr);
} RzParsePlugin;

#ifdef RZ_API

/* lifecycle */
RZ_API struct rz_parse_t *rz_parse_new(void);
RZ_API void rz_parse_free(RzParse *p);

/* plugins */
RZ_API void rz_parse_set_user_ptr(RzParse *p, void *user);
RZ_API bool rz_parse_add(RzParse *p, RzParsePlugin *foo);
RZ_API bool rz_parse_use(RzParse *p, const char *name);

/* action */
RZ_API bool rz_parse_parse(RzParse *p, const char *data, char *str);
RZ_API bool rz_parse_assemble(RzParse *p, char *data, char *str); // XXX deprecate, unused and probably useless, related to write-hack
RZ_API bool rz_parse_filter(RzParse *p, ut64 addr, RzFlag *f, RzAnalysisHint *hint, char *data, char *str, int len, bool big_endian);
RZ_API bool rz_parse_subvar(RzParse *p, RzAnalysisFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
RZ_API char *rz_parse_immtrim(char *opstr);

/* c */
// why we have analysis scoped things in rparse
RZ_API char *rz_parse_c_string(RzAnalysis *analysis, const char *code, char **error_msg);
RZ_API char *rz_parse_c_file(RzAnalysis *analysis, const char *path, const char *dir, char **error_msg);
RZ_API void rz_parse_c_reset(RzParse *p);

/* ctype */
// Parses strings like "const char * [0x42] const * [23]" to RzParseCTypeType

typedef struct rz_parse_ctype_t RzParseCType;

typedef enum {
	RZ_PARSE_CTYPE_TYPE_KIND_IDENTIFIER,
	RZ_PARSE_CTYPE_TYPE_KIND_POINTER,
	RZ_PARSE_CTYPE_TYPE_KIND_ARRAY
} RzParseCTypeTypeKind;

typedef enum {
	RZ_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED,
	RZ_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT,
	RZ_PARSE_CTYPE_IDENTIFIER_KIND_UNION,
	RZ_PARSE_CTYPE_IDENTIFIER_KIND_ENUM
} RzParseCTypeTypeIdentifierKind;

typedef struct rz_parse_ctype_type_t RzParseCTypeType;
struct rz_parse_ctype_type_t {
	RzParseCTypeTypeKind kind;
	union {
		struct {
			RzParseCTypeTypeIdentifierKind kind;
			char *name;
			bool is_const;
		} identifier;
		struct {
			RzParseCTypeType *type;
			bool is_const;
		} pointer;
		struct {
			RzParseCTypeType *type;
			ut64 count;
		} array;
	};
};

RZ_API RzParseCType *rz_parse_ctype_new(void);
RZ_API void rz_parse_ctype_free(RzParseCType *ctype);
RZ_API RzParseCTypeType *rz_parse_ctype_parse(RzParseCType *ctype, const char *str, char **error);
RZ_API void rz_parse_ctype_type_free(RzParseCTypeType *type);

/* plugin pointers */
extern RzParsePlugin rz_parse_plugin_6502_pseudo;
extern RzParsePlugin rz_parse_plugin_arm_pseudo;
extern RzParsePlugin rz_parse_plugin_att2intel;
extern RzParsePlugin rz_parse_plugin_avr_pseudo;
extern RzParsePlugin rz_parse_plugin_chip8_pseudo;
extern RzParsePlugin rz_parse_plugin_dalvik_pseudo;
extern RzParsePlugin rz_parse_plugin_dummy;
extern RzParsePlugin rz_parse_plugin_m68k_pseudo;
extern RzParsePlugin rz_parse_plugin_mips_pseudo;
extern RzParsePlugin rz_parse_plugin_ppc_pseudo;
extern RzParsePlugin rz_parse_plugin_sh_pseudo;
extern RzParsePlugin rz_parse_plugin_wasm_pseudo;
extern RzParsePlugin rz_parse_plugin_riscv_pseudo;
extern RzParsePlugin rz_parse_plugin_x86_pseudo;
extern RzParsePlugin rz_parse_plugin_z80_pseudo;
extern RzParsePlugin rz_parse_plugin_tms320_pseudo;
extern RzParsePlugin rz_parse_plugin_v850_pseudo;
#endif

#ifdef __cplusplus
}
#endif

#endif
