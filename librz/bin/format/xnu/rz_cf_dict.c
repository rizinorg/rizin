// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <stdlib.h>
#include <rz_util.h>
#include <rz_list.h>

#include <yxml.h>
#include "rz_cf_dict.h"

#define XMLBUFSIZE 4096

typedef enum {
	RZ_CF_STATE_ROOT,
	RZ_CF_STATE_IN_DICT,
	RZ_CF_STATE_IN_ARRAY,
	RZ_CF_STATE_IN_KEY,
	RZ_CF_STATE_IN_SCALAR,
	RZ_CF_STATE_IN_IGNORE,
} RCFParsePhase;

typedef struct _RCFParseState {
	RCFParsePhase phase;
	char *key;
	RCFValueType value_type;
	RCFValueDict *dict;
	RCFValueArray *array;
} RCFParseState;

static RCFParseState *rz_cf_parse_state_new(RCFParsePhase phase);
static void rz_cf_parse_state_free(RCFParseState *state);

static RCFKeyValue *rz_cf_key_value_new(char *key, RCFValue *value);
static void rz_cf_key_value_free(RCFKeyValue *key_value);

static RCFValueDict *rz_cf_value_dict_new(void);
static void rz_cf_value_dict_add(RCFValueDict *dict, RCFKeyValue *key_value);
static void rz_cf_value_dict_print(RCFValueDict *dict);

static RCFValueArray *rz_cf_value_array_new(void);
static void rz_cf_value_array_free(RCFValueArray *array);
static void rz_cf_value_array_add(RCFValueArray *array, RCFValue *value);
static void rz_cf_value_array_print(RCFValueArray *dict);

static RCFValueString *rz_cf_value_string_new(char *string);
static void rz_cf_value_string_free(RCFValueString *string);
static void rz_cf_value_string_print(RCFValueString *string);

static RCFValueInteger *rz_cf_value_integer_new(char *string);
static void rz_cf_value_integer_free(RCFValueInteger *integer);
static void rz_cf_value_integer_print(RCFValueInteger *integer);

static RCFValueData *rz_cf_value_data_new(char *string);
static void rz_cf_value_data_free(RCFValueData *data);
static void rz_cf_value_data_print(RCFValueData *data);

static RCFValueNULL *rz_cf_value_null_new(void);
static void rz_cf_value_null_free(RCFValueNULL *null);
static void rz_cf_value_null_print(RCFValueNULL *null);

static RCFValueBool *rz_cf_value_bool_new(bool value);
static void rz_cf_value_bool_free(RCFValueBool *bool_value);
static void rz_cf_value_bool_print(RCFValueBool *bool_value);

static void rz_cf_value_free(RCFValue *value);

RCFValueDict *rz_cf_value_dict_parse(RzBuffer *file_buf, ut64 offset, ut64 size, int options) {
	RCFValueDict *result = NULL;
	yxml_t x;
	int i, depth = 0;
	char *content = NULL;

	void *xml_buf = malloc(XMLBUFSIZE);
	if (!xml_buf) {
		return NULL;
	}

	yxml_init(&x, xml_buf, XMLBUFSIZE);

	RzList *stack = rz_list_newf((RzListFree)&rz_cf_parse_state_free);
	if (!stack) {
		goto beach;
	}

	rz_list_push(stack, rz_cf_parse_state_new(RZ_CF_STATE_ROOT));

	for (i = 0; i < size; i++) {
		ut8 doc = 0;
		rz_buf_read_at(file_buf, offset + i, &doc, 1);
		if (!doc) {
			break;
		}

		yxml_ret_t r = yxml_parse(&x, doc);
		if (r < 0) {
			eprintf("Parsing error at :%" PRIu32 ":%" PRIu64 " byte offset %" PRIu64 "\n",
				x.line, x.byte, x.total);
			goto beach;
		}

		switch (r) {
		case YXML_ELEMSTART: {
			RCFParseState *state = (RCFParseState *)rz_list_get_top(stack);
			RCFParseState *next_state = NULL;

			if (!strcmp(x.elem, "dict")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_DICT);
				if (!next_state) {
					goto beach;
				}
				next_state->dict = rz_cf_value_dict_new();
			} else if (!strcmp(x.elem, "array")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_ARRAY);
				if (!next_state) {
					goto beach;
				}
				next_state->array = rz_cf_value_array_new();
			} else if (!strcmp(x.elem, "key") && state->phase == RZ_CF_STATE_IN_DICT) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_KEY);
				if (!next_state) {
					goto beach;
				}
				next_state->dict = state->dict;
			} else if (!strcmp(x.elem, "string")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = RZ_CF_STRING;
			} else if (!strcmp(x.elem, "integer")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = RZ_CF_INTEGER;
			} else if (!strcmp(x.elem, "data")) {
				if (options & RZ_CF_OPTION_SKIP_NSDATA) {
					next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_IGNORE);
				} else {
					next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_SCALAR);
					if (!next_state) {
						goto beach;
					}
					next_state->value_type = RZ_CF_DATA;
				}
			} else if (!strcmp(x.elem, "true")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = RZ_CF_TRUE;
			} else if (!strcmp(x.elem, "false")) {
				next_state = rz_cf_parse_state_new(RZ_CF_STATE_IN_SCALAR);
				if (!next_state) {
					goto beach;
				}
				next_state->value_type = RZ_CF_FALSE;
			}

			if (next_state) {
				rz_list_push(stack, next_state);
			} else {
				eprintf("Missing next state for elem: %s phase: %d\n", x.elem, state->phase);
				break;
			}
			depth++;

			break;
		}
		case YXML_ELEMEND: {
			RCFParseState *state = (RCFParseState *)rz_list_pop(stack);
			RCFParseState *next_state = (RCFParseState *)rz_list_get_top(stack);
			if (!state || !next_state) {
				goto beach;
			}

			if (next_state->phase == RZ_CF_STATE_ROOT) {
				if (state->phase == RZ_CF_STATE_IN_DICT) {
					result = state->dict;
					rz_cf_parse_state_free(state);
					break;
				} else {
					eprintf("Root element is not a dict\n");
					goto beach;
				}
			}

			if (next_state->phase == RZ_CF_STATE_IN_DICT && state->phase == RZ_CF_STATE_IN_KEY) {
				if (!content) {
					eprintf("NULL key not supported");
					goto beach;
				}
				next_state->key = content;
			}

			if (state->phase != RZ_CF_STATE_IN_KEY) {
				RCFValue *value = NULL;

				switch (state->phase) {
				case RZ_CF_STATE_IN_DICT:
					value = (RCFValue *)state->dict;
					break;
				case RZ_CF_STATE_IN_ARRAY:
					value = (RCFValue *)state->array;
					break;
				case RZ_CF_STATE_IN_SCALAR:
					if (!content && state->value_type != RZ_CF_FALSE && state->value_type != RZ_CF_TRUE) {
						value = (RCFValue *)rz_cf_value_null_new();
					} else {
						switch (state->value_type) {
						case RZ_CF_STRING:
							value = (RCFValue *)rz_cf_value_string_new(content);
							break;
						case RZ_CF_INTEGER:
							value = (RCFValue *)rz_cf_value_integer_new(content);
							RZ_FREE(content);
							break;
						case RZ_CF_DATA:
							value = (RCFValue *)rz_cf_value_data_new(content);
							RZ_FREE(content);
							break;
						case RZ_CF_TRUE:
							value = (RCFValue *)rz_cf_value_bool_new(true);
							break;
						case RZ_CF_FALSE:
							value = (RCFValue *)rz_cf_value_bool_new(false);
							break;
						default:
							break;
						}
					}
					break;
				default:
					break;
				}

				if (next_state->phase == RZ_CF_STATE_IN_DICT) {
					if (value) {
						RCFKeyValue *key_value = rz_cf_key_value_new(next_state->key, value);
						rz_cf_value_dict_add(next_state->dict, key_value);
					} else if (state->phase != RZ_CF_STATE_IN_IGNORE) {
						eprintf("Missing value for key %s\n", next_state->key);
						rz_cf_value_free((RCFValue *)value);
						goto beach;
					}
				} else if (next_state->phase == RZ_CF_STATE_IN_ARRAY) {
					if (value) {
						rz_cf_value_array_add(next_state->array, value);
					} else if (state->phase != RZ_CF_STATE_IN_IGNORE) {
						eprintf("Missing value for array\n");
						rz_cf_value_free((RCFValue *)value);
						goto beach;
					}
				}
			}

			depth--;
			content = NULL;
			rz_cf_parse_state_free(state);
			break;
		}
		case YXML_CONTENT: {
			RCFParseState *state = (RCFParseState *)rz_list_get_top(stack);
			if (state->phase == RZ_CF_STATE_IN_IGNORE) {
				break;
			}
			if (!content) {
				content = rz_str_new(x.data);
			} else {
				content = rz_str_append(content, x.data);
			}
			break;
		}
		default:
			break;
		}

		if (result) {
			break;
		}
	}

	yxml_ret_t r = yxml_eof(&x);
	if (r < 0) {
		eprintf("Invalid xml\n");
	}

beach:
	RZ_FREE(xml_buf);
	if (stack) {
		rz_list_free(stack);
	}

	return result;
}

static RCFParseState *rz_cf_parse_state_new(RCFParsePhase phase) {
	RCFParseState *state = RZ_NEW0(RCFParseState);
	if (state) {
		state->phase = phase;
	}
	return state;
}

static void rz_cf_parse_state_free(RCFParseState *state) {
	if (state) {
		RZ_FREE(state);
	}
}

static RCFKeyValue *rz_cf_key_value_new(char *key, RCFValue *value) {
	RCFKeyValue *key_value = RZ_NEW0(RCFKeyValue);
	if (!key_value) {
		return NULL;
	}

	key_value->key = key;
	key_value->value = value;

	return key_value;
}

static void rz_cf_key_value_free(RCFKeyValue *key_value) {
	if (!key_value) {
		return;
	}

	if (key_value->key) {
		RZ_FREE(key_value->key);
	}
	if (key_value->value) {
		rz_cf_value_free(key_value->value);
		key_value->value = NULL;
	}

	RZ_FREE(key_value);
}

static RCFValueDict *rz_cf_value_dict_new(void) {
	RCFValueDict *dict = RZ_NEW0(RCFValueDict);
	if (!dict) {
		return NULL;
	}

	dict->type = RZ_CF_DICT;
	dict->pairs = rz_list_newf((RzListFree)&rz_cf_key_value_free);

	return dict;
}

void rz_cf_value_dict_free(RCFValueDict *dict) {
	rz_return_if_fail(dict);

	if (dict->pairs) {
		rz_list_free(dict->pairs);
		dict->pairs = NULL;
	}
	dict->type = RZ_CF_INVALID;
	RZ_FREE(dict);
}

static void rz_cf_value_dict_add(RCFValueDict *dict, RCFKeyValue *key_value) {
	if (!dict || !dict->pairs) {
		return;
	}

	rz_list_push(dict->pairs, key_value);
}

static void rz_cf_value_dict_print(RCFValueDict *dict) {
	RzListIter *iter;
	RCFKeyValue *key_value;
	int length = rz_list_length(dict->pairs);
	int i = 0;
	printf("{");
	rz_list_foreach (dict->pairs, iter, key_value) {
		printf("\"%s\":", key_value->key);
		rz_cf_value_print(key_value->value);
		if (i++ < length - 1) {
			printf(",");
		}
	}
	printf("}");
}

static RCFValueArray *rz_cf_value_array_new(void) {
	RCFValueArray *array = RZ_NEW0(RCFValueArray);
	if (!array) {
		return NULL;
	}

	array->type = RZ_CF_ARRAY;
	array->values = rz_list_newf((RzListFree)&rz_cf_value_free);

	return array;
}

static void rz_cf_value_array_free(RCFValueArray *array) {
	if (!array) {
		return;
	}

	if (array->values) {
		rz_list_free(array->values);
		array->values = NULL;
	}

	array->type = RZ_CF_INVALID;
	RZ_FREE(array);
}

static void rz_cf_value_array_add(RCFValueArray *array, RCFValue *value) {
	if (!array || !array->values) {
		return;
	}

	rz_list_push(array->values, value);
}

static void rz_cf_value_array_print(RCFValueArray *array) {
	RzListIter *iter;
	RCFValue *value;
	int length = rz_list_length(array->values);
	int i = 0;
	printf("[");
	rz_list_foreach (array->values, iter, value) {
		rz_cf_value_print(value);
		if (i++ < length - 1) {
			printf(",");
		}
	}
	printf("]");
}

static RCFValueString *rz_cf_value_string_new(char *string) {
	RCFValueString *value_string = RZ_NEW0(RCFValueString);
	if (!value_string) {
		return NULL;
	}

	value_string->type = RZ_CF_STRING;
	value_string->value = string;

	return value_string;
}

static void rz_cf_value_string_free(RCFValueString *string) {
	if (!string) {
		return;
	}

	if (string->value) {
		RZ_FREE(string->value);
	}

	string->type = RZ_CF_INVALID;
	RZ_FREE(string);
}

static void rz_cf_value_string_print(RCFValueString *string) {
	char *escaped = strdup(string->value);
	escaped = rz_str_replace(escaped, "\"", "\\\"", 1);
	printf("\"%s\"", escaped);
	RZ_FREE(escaped);
}

static RCFValueInteger *rz_cf_value_integer_new(char *string) {
	RCFValueInteger *integer = RZ_NEW0(RCFValueInteger);
	if (!integer) {
		return NULL;
	}

	integer->type = RZ_CF_INTEGER;
	integer->value = rz_num_get(NULL, string);

	return integer;
}

static void rz_cf_value_integer_free(RCFValueInteger *integer) {
	if (!integer) {
		return;
	}

	integer->type = RZ_CF_INVALID;
	RZ_FREE(integer);
}

static void rz_cf_value_integer_print(RCFValueInteger *integer) {
	printf("%llu", integer->value);
}

static RCFValueData *rz_cf_value_data_new(char *string) {
	RCFValueData *data = RZ_NEW0(RCFValueData);
	if (!data) {
		return NULL;
	}

	const int len = strlen(string);
	const int out_len = len / 4 * 3 + 1;
	ut8 *out = calloc(sizeof(ut8), out_len);
	if (!out) {
		RZ_FREE(data);
		return NULL;
	}
	rz_base64_decode(out, string, len);

	data->type = RZ_CF_DATA;
	data->value = rz_buf_new_with_pointers(out, out_len, true);

	return data;
}

static void rz_cf_value_data_free(RCFValueData *data) {
	if (!data) {
		return;
	}

	data->type = RZ_CF_INVALID;
	if (data->value) {
		rz_buf_free(data->value);
		data->value = NULL;
	}

	RZ_FREE(data);
}

static void rz_cf_value_data_print(RCFValueData *data) {
	printf("\"...\"");
}

static RCFValueNULL *rz_cf_value_null_new(void) {
	RCFValueNULL *null = RZ_NEW0(RCFValueNULL);
	if (!null) {
		return NULL;
	}

	null->type = RZ_CF_NULL;

	return null;
}

static void rz_cf_value_null_free(RCFValueNULL *null) {
	if (!null) {
		return;
	}

	null->type = RZ_CF_INVALID;
	RZ_FREE(null);
}

static void rz_cf_value_null_print(RCFValueNULL *null) {
	printf("null");
}

static RCFValueBool *rz_cf_value_bool_new(bool value) {
	RCFValueBool *bool_value = RZ_NEW0(RCFValueBool);
	if (!bool_value) {
		return NULL;
	}

	bool_value->type = value ? RZ_CF_TRUE : RZ_CF_FALSE;
	return bool_value;
}

static void rz_cf_value_bool_free(RCFValueBool *bool_value) {
	if (bool_value) {
		bool_value->type = RZ_CF_INVALID;
		RZ_FREE(bool_value);
	}
}

static void rz_cf_value_bool_print(RCFValueBool *bool_value) {
	if (bool_value->type == RZ_CF_TRUE) {
		printf("true");
	} else {
		printf("false");
	}
}
static void rz_cf_value_free(RCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case RZ_CF_DICT:
		rz_cf_value_dict_free((RCFValueDict *)value);
		break;
	case RZ_CF_ARRAY:
		rz_cf_value_array_free((RCFValueArray *)value);
		break;
	case RZ_CF_STRING:
		rz_cf_value_string_free((RCFValueString *)value);
		break;
	case RZ_CF_INTEGER:
		rz_cf_value_integer_free((RCFValueInteger *)value);
		break;
	case RZ_CF_DATA:
		rz_cf_value_data_free((RCFValueData *)value);
		break;
	case RZ_CF_NULL:
		rz_cf_value_null_free((RCFValueNULL *)value);
		break;
	case RZ_CF_TRUE:
	case RZ_CF_FALSE:
		rz_cf_value_bool_free((RCFValueBool *)value);
		break;
	default:
		break;
	}
}

void rz_cf_value_print(RCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case RZ_CF_DICT:
		rz_cf_value_dict_print((RCFValueDict *)value);
		break;
	case RZ_CF_ARRAY:
		rz_cf_value_array_print((RCFValueArray *)value);
		break;
	case RZ_CF_STRING:
		rz_cf_value_string_print((RCFValueString *)value);
		break;
	case RZ_CF_INTEGER:
		rz_cf_value_integer_print((RCFValueInteger *)value);
		break;
	case RZ_CF_DATA:
		rz_cf_value_data_print((RCFValueData *)value);
		break;
	case RZ_CF_NULL:
		rz_cf_value_null_print((RCFValueNULL *)value);
		break;
	case RZ_CF_TRUE:
	case RZ_CF_FALSE:
		rz_cf_value_bool_print((RCFValueBool *)value);
		break;
	default:
		break;
	}
}
