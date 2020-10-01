/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#ifndef R2_PARSE_H
#define R2_PARSE_H

#include <rz_types.h>
#include <rz_flag.h>
#include <rz_anal.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(rz_parse);

typedef RzList* (*RzAnalVarList)(RzAnalFunction *fcn, int kind);

typedef struct rz_parse_t {
	void *user;
	RSpace *flagspace;
	RSpace *notin_flagspace;
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
	// RzAnal *anal; // weak anal ref XXX do not use. use analb.anal
	RzList *parsers;
	RzAnalVarList varlist;
	st64 (*get_ptr_at)(RzAnalFunction *fcn, st64 delta, ut64 addr);
	const char *(*get_reg_at)(RzAnalFunction *fcn, st64 delta, ut64 addr);
	char* (*get_op_ireg)(void *user, ut64 addr);
	RzAnalBind analb;
	RzFlagGetAtAddr flag_get; // XXX
	RzAnalLabelAt label_get;
} RzParse;

typedef struct rz_parse_plugin_t {
	char *name;
	char *desc;
	bool (*init)(RzParse *p, void *user);
	int (*fini)(RzParse *p, void *user);
	int (*parse)(RzParse *p, const char *data, char *str);
	bool (*assemble)(RzParse *p, char *data, char *str);
	int (*filter)(RzParse *p, ut64 addr, RzFlag *f, char *data, char *str, int len, bool big_endian);
	bool (*subvar)(RzParse *p, RzAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
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
RZ_API bool rz_parse_filter(RzParse *p, ut64 addr, RzFlag *f, RzAnalHint *hint, char *data, char *str, int len, bool big_endian);
RZ_API bool rz_parse_subvar(RzParse *p, RzAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len);
RZ_API char *rz_parse_immtrim(char *opstr);

/* c */
// why we have anal scoped things in rparse
RZ_API char *rz_parse_c_string(RzAnal *anal, const char *code, char **error_msg);
RZ_API char *rz_parse_c_file(RzAnal *anal, const char *path, const char *dir, char **error_msg);
RZ_API void rz_parse_c_reset(RzParse *p);

/* ctype */
// Parses strings like "const char * [0x42] const * [23]" to RzParseCTypeType

typedef struct rz_parse_ctype_t RzParseCType;

typedef enum {
	R_PARSE_CTYPE_TYPE_KIND_IDENTIFIER,
	R_PARSE_CTYPE_TYPE_KIND_POINTER,
	R_PARSE_CTYPE_TYPE_KIND_ARRAY
} RzParseCTypeTypeKind;

typedef enum {
	R_PARSE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED,
	R_PARSE_CTYPE_IDENTIFIER_KIND_STRUCT,
	R_PARSE_CTYPE_IDENTIFIER_KIND_UNION,
	R_PARSE_CTYPE_IDENTIFIER_KIND_ENUM
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
extern RzParsePlugin rz_parse_plugin_x86_pseudo;
extern RzParsePlugin rz_parse_plugin_z80_pseudo;
extern RzParsePlugin rz_parse_plugin_tms320_pseudo;
extern RzParsePlugin rz_parse_plugin_v850_pseudo;
#endif

#ifdef __cplusplus
}
#endif

#endif
