// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct {
	size_t unions;
	size_t structs;
	size_t enums;
	size_t callables;
} CParserAnonymousTypesState;

typedef struct {
	bool verbose;
	HtSP *types;
	HtSP *callables;
	HtSP *forward;
	RzStrBuf *errors;
	RzStrBuf *warnings;
	RzStrBuf *debug;
	CParserAnonymousTypesState anon;
} CParserState;

typedef struct {
	RzBaseType *btype;
	RzType *type;
} ParserTypePair;

CParserState *c_parser_state_new(HtSP *base_types, HtSP *callable_types);
void c_parser_state_free(CParserState *state);

int parse_type_nodes_save(CParserState *state, TSNode node, const char *text);
int parse_type_node_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, bool is_const);
int parse_declaration_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair);
int parse_type_descriptor_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair);
int parse_type_declarator_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair, char **identifier);
int parse_type_abstract_declarator_node(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair);

void parser_debug(CParserState *state, const char *fmt, ...);
void parser_error(CParserState *state, const char *fmt, ...);
void parser_warning(CParserState *state, const char *fmt, ...);

// Types storage API

RzBaseType *c_parser_base_type_find(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_base_type_is_forward_definition(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_base_type_exists(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_base_type_store(CParserState *state, RZ_NONNULL const char *name, ParserTypePair *tpair);
bool c_parser_forward_definition_store(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_forward_definition_remove(CParserState *state, RZ_NONNULL const char *name);

RzCallable *c_parser_callable_type_find(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_callable_type_exists(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_callable_type_store(CParserState *state, RZ_NONNULL const char *name, RZ_NONNULL RzType *type);

RZ_OWN ParserTypePair *c_parser_new_unspecified_naked_type(CParserState *state, RZ_NONNULL const char *name, bool is_const);

RZ_OWN ParserTypePair *c_parser_new_primitive_type(CParserState *state, RZ_NONNULL const char *name, bool is_const);
RZ_OWN ParserTypePair *c_parser_get_primitive_type(CParserState *state, RZ_NONNULL const char *name, bool is_const);

RZ_OWN ParserTypePair *c_parser_new_structure_naked_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_structure_type(CParserState *state, RZ_NONNULL const char *name, size_t members_count);
RZ_OWN ParserTypePair *c_parser_get_structure_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_structure_forward_definition(CParserState *state, RZ_NONNULL const char *name);

RZ_OWN ParserTypePair *c_parser_new_union_naked_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_union_type(CParserState *state, RZ_NONNULL const char *name, size_t members_count);
RZ_OWN ParserTypePair *c_parser_get_union_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_union_forward_definition(CParserState *state, RZ_NONNULL const char *name);

RZ_OWN ParserTypePair *c_parser_new_enum_naked_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_enum_type(CParserState *state, RZ_NONNULL const char *name, size_t cases_count);
RZ_OWN ParserTypePair *c_parser_get_enum_type(CParserState *state, RZ_NONNULL const char *name);
RZ_OWN ParserTypePair *c_parser_new_enum_forward_definition(CParserState *state, RZ_NONNULL const char *name);

RZ_OWN ParserTypePair *c_parser_new_typedef(CParserState *state, RZ_NONNULL const char *name, RZ_NONNULL const char *base);
RZ_OWN ParserTypePair *c_parser_get_typedef(CParserState *state, RZ_NONNULL const char *name);

RZ_OWN RzType *c_parser_new_naked_callable(CParserState *state);
RZ_OWN RzType *c_parser_new_callable(CParserState *state, RZ_NONNULL const char *name);
bool c_parser_new_callable_argument(CParserState *state, RZ_NONNULL RzCallable *callable, RZ_NONNULL const char *name, RZ_OWN RZ_NONNULL RzType *type);

// ParserTypePair wrapper helpers
RZ_OWN ParserTypePair *c_parser_type_wrap_to_pointer(CParserState *state, ParserTypePair *tpair, bool is_const);
RZ_OWN ParserTypePair *c_parser_type_wrap_to_array(CParserState *state, ParserTypePair *tpair, size_t size);
bool c_parser_pointer_set_subtype(CParserState *state, RZ_BORROW ParserTypePair *tpair, RZ_OWN ParserTypePair *subpair);
bool c_parser_array_set_subtype(CParserState *state, RZ_BORROW ParserTypePair *tpair, RZ_OWN ParserTypePair *subpair);

// Generators of the anonymous type names
RZ_OWN char *c_parser_new_anonymous_structure_name(CParserState *state);
RZ_OWN char *c_parser_new_anonymous_union_name(CParserState *state);
RZ_OWN char *c_parser_new_anonymous_enum_name(CParserState *state);
RZ_OWN char *c_parser_new_anonymous_callable_name(CParserState *state);
