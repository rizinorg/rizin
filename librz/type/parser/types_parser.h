// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct {
	bool verbose;
	HtPP *types;
	RzStrBuf *errors;
	RzStrBuf *warnings;
	RzStrBuf *debug;
} CParserState;

typedef struct {
	RzBaseType *btype;
	RzType *type;
} ParserTypePair;

CParserState *c_parser_state_new();
void c_parser_state_free(CParserState *state);

int parse_type_nodes_save(CParserState *state, TSNode node, const char *text);
int parse_type_node_single(CParserState *state, TSNode node, const char *text, ParserTypePair **tpair);

void parser_debug(CParserState *state, const char *fmt, ...);
void parser_error(CParserState *state, const char *fmt, ...);
void parser_warning(CParserState *state, const char *fmt, ...);

// Types storage API

RZ_OWN ParserTypePair *c_parser_new_structure(CParserState *state, const char *name, size_t members_count);
RZ_OWN ParserTypePair *c_parser_new_union(CParserState *state, const char *name, size_t members_count);
RZ_OWN ParserTypePair *c_parser_new_enum(CParserState *state, const char *name, size_t cases_count);
RZ_OWN ParserTypePair *c_parser_new_typedef(CParserState *state, const char *name);

int c_parser_store_type(CParserState *state, const char *name, ParserTypePair *tpair);
