// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2023 Siguza <siguza@siguza.net>
// SPDX-FileCopyrightText: 2019 Francesco Tamagni <mrmacete@protonmail.ch>
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
	RZ_CF_STATE_IN_ATTR_ID,
	RZ_CF_STATE_IN_ATTR_IDREF
} RzCFParsePhase;

typedef enum {
	RZ_CF_ID_STATE_NONE,
	RZ_CF_ID_STATE_SET,
	RZ_CF_ID_STATE_REF,
} RzCFIDState;

typedef struct rz_cf_parse_state {
	RzCFParsePhase phase;
	RzCFIDState idstate;
	ut32 id;
	char *key;
	RzCFValueType value_type;
	RzCFValueDict *dict;
	RzCFValueArray *array;
} RzCFParseState;

static RzCFParseState *rz_cf_parse_state_new(RzCFParsePhase phase);
static void rz_cf_parse_state_free(RzCFParseState *state);

static RzCFKeyValue *rz_cf_key_value_new(char *key, RzCFValue *value);
static void rz_cf_key_value_free(RzCFKeyValue *key_value);

static RzCFValueDict *rz_cf_value_dict_new(void);
static void rz_cf_value_dict_add(RzCFValueDict *dict, RzCFKeyValue *key_value);
static void rz_cf_value_dict_print(RzCFValueDict *dict);

static RzCFValueArray *rz_cf_value_array_new(void);
static void rz_cf_value_array_free(RzCFValueArray *array);
static void rz_cf_value_array_add(RzCFValueArray *array, RzCFValue *value);
static void rz_cf_value_array_print(RzCFValueArray *dict);

static RzCFValueString *rz_cf_value_string_new(char *string);
static void rz_cf_value_string_free(RzCFValueString *string);
static void rz_cf_value_string_print(RzCFValueString *string);

static RzCFValueInteger *rz_cf_value_integer_new(char *string);
static void rz_cf_value_integer_free(RzCFValueInteger *integer);
static void rz_cf_value_integer_print(RzCFValueInteger *integer);

static RzCFValueData *rz_cf_value_data_new(char *string);
static void rz_cf_value_data_free(RzCFValueData *data);
static void rz_cf_value_data_print(RzCFValueData *data);

static RzCFValueNULL *rz_cf_value_null_new(void);
static void rz_cf_value_null_free(RzCFValueNULL *null);
static void rz_cf_value_null_print(RzCFValueNULL *null);

static RzCFValueBool *rz_cf_value_bool_new(bool value);
static void rz_cf_value_bool_free(RzCFValueBool *bool_value);
static void rz_cf_value_bool_print(RzCFValueBool *bool_value);

static RzCFValue *rz_cf_value_clone(RzCFValue *value);
static void rz_cf_value_free(RzCFValue *value);

RZ_API RzCFValueDict *rz_cf_value_dict_parse(RzBuffer *file_buf, ut64 offset, ut64 size, int options) {
	RzList *idlist = NULL;
	RzCFValueDict *result = NULL;
	yxml_t x;
	int i;
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

	if (options & RZ_CF_OPTION_SUPPORT_IDREF) {
		idlist = rz_list_new();
		if (!idlist) {
			goto beach;
		}
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
			RZ_LOG_ERROR("Parsing error at :%" PRIu32 ":%" PRIu64 " byte offset %" PRIu64 "\n",
				x.line, x.byte, x.total);
			goto beach;
		}

		switch (r) {
		case YXML_ELEMSTART: {
			RzCFParseState *state = (RzCFParseState *)rz_list_last(stack);
			RzCFParseState *next_state = NULL;

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
				RZ_LOG_ERROR("Missing next state for elem: %s phase: %d\n", x.elem, state->phase);
				break;
			}
			break;
		}
		case YXML_ELEMEND: {
			RzCFParseState *state = (RzCFParseState *)rz_list_pop(stack);
			RzCFParseState *next_state = (RzCFParseState *)rz_list_last(stack);
			if (!state || !next_state) {
				goto beach;
			}

			if (next_state->phase == RZ_CF_STATE_ROOT) {
				if (state->phase == RZ_CF_STATE_IN_DICT) {
					result = state->dict;
					rz_cf_parse_state_free(state);
					break;
				} else {
					RZ_LOG_ERROR("Root element is not a dict\n");
					goto beach;
				}
			}

			if (next_state->phase == RZ_CF_STATE_IN_DICT && state->phase == RZ_CF_STATE_IN_KEY) {
				if (!content) {
					RZ_LOG_ERROR("NULL key is not supported\n");
					goto beach;
				}
				next_state->key = content;
			}

			if (state->phase != RZ_CF_STATE_IN_KEY) {
				RzCFValue *value = NULL;

				if (idlist && state->idstate == RZ_CF_ID_STATE_REF) {
					value = rz_list_get_n(idlist, (int)state->id);
					if (!value) {
						RZ_LOG_ERROR("Missing value for IDREF %" PFMT32u "\n", state->id);
						goto beach;
					}
					if (state->phase == RZ_CF_STATE_IN_DICT) {
						if (rz_list_length(state->dict->pairs) != 0) {
							RZ_LOG_ERROR("Dict with IDREF already has elements\n");
							goto beach;
						}
						rz_cf_value_dict_free(state->dict);
						state->dict = NULL;
					} else if (state->phase == RZ_CF_STATE_IN_ARRAY) {
						if (rz_list_length(state->dict->pairs) != 0) {
							RZ_LOG_ERROR("Array with IDREF already has elements\n");
							goto beach;
						}
						rz_cf_value_array_free(state->array);
						state->array = NULL;
					} else if (state->phase == RZ_CF_STATE_IN_SCALAR && content) {
						RZ_LOG_ERROR("Element with IDREF already has content\n");
						goto beach;
					}
					value = rz_cf_value_clone(value);
					if (!value) {
						goto beach;
					}
				} else {
					switch (state->phase) {
					case RZ_CF_STATE_IN_DICT:
						value = (RzCFValue *)state->dict;
						break;
					case RZ_CF_STATE_IN_ARRAY:
						value = (RzCFValue *)state->array;
						break;
					case RZ_CF_STATE_IN_SCALAR:
						if (!content && state->value_type != RZ_CF_FALSE && state->value_type != RZ_CF_TRUE) {
							value = (RzCFValue *)rz_cf_value_null_new();
						} else {
							switch (state->value_type) {
							case RZ_CF_STRING:
								value = (RzCFValue *)rz_cf_value_string_new(content);
								break;
							case RZ_CF_INTEGER:
								value = (RzCFValue *)rz_cf_value_integer_new(content);
								RZ_FREE(content);
								break;
							case RZ_CF_DATA:
								value = (RzCFValue *)rz_cf_value_data_new(content);
								RZ_FREE(content);
								break;
							case RZ_CF_TRUE:
								value = (RzCFValue *)rz_cf_value_bool_new(true);
								break;
							case RZ_CF_FALSE:
								value = (RzCFValue *)rz_cf_value_bool_new(false);
								break;
							default:
								break;
							}
						}
						break;
					default:
						break;
					}

					if (idlist && state->idstate == RZ_CF_ID_STATE_SET) {
						if (value) {
							rz_list_insert(idlist, state->id, value);
						} else {
							RZ_LOG_WARN("Missing value for ID %" PFMT32u "\n", state->id);
						}
					}
				}

				if (next_state->phase == RZ_CF_STATE_IN_DICT) {
					if (value) {
						RzCFKeyValue *key_value = rz_cf_key_value_new(next_state->key, value);
						rz_cf_value_dict_add(next_state->dict, key_value);
					} else if (state->phase != RZ_CF_STATE_IN_IGNORE) {
						RZ_LOG_ERROR("Missing value for key %s\n", next_state->key);
						rz_cf_value_free((RzCFValue *)value);
						goto beach;
					}
				} else if (next_state->phase == RZ_CF_STATE_IN_ARRAY) {
					if (value) {
						rz_cf_value_array_add(next_state->array, value);
					} else if (state->phase != RZ_CF_STATE_IN_IGNORE) {
						RZ_LOG_ERROR("Missing value for array\n");
						rz_cf_value_free((RzCFValue *)value);
						goto beach;
					}
				}
			}

			content = NULL;
			rz_cf_parse_state_free(state);
			break;
		}
		case YXML_CONTENT: {
			RzCFParseState *state = (RzCFParseState *)rz_list_last(stack);
			if (state->phase == RZ_CF_STATE_IN_IGNORE) {
				break;
			}
			if (!content) {
				content = rz_str_dup(x.data);
			} else {
				content = rz_str_append(content, x.data);
			}
			break;
		}
		case YXML_ATTRSTART: {
			if (idlist) {
				RzCFParseState *state = (RzCFParseState *)rz_list_last(stack);
				if (state->phase != RZ_CF_STATE_IN_DICT && state->phase != RZ_CF_STATE_IN_ARRAY && state->phase != RZ_CF_STATE_IN_SCALAR) {
					break;
				}
				RzCFParsePhase next_phase;
				if (!strcmp(x.attr, "ID")) {
					next_phase = RZ_CF_STATE_IN_ATTR_ID;
				} else if (!strcmp(x.attr, "IDREF")) {
					next_phase = RZ_CF_STATE_IN_ATTR_IDREF;
				} else {
					break;
				}
				if (state->idstate != RZ_CF_ID_STATE_NONE) {
					RZ_LOG_ERROR("Cannot have ID and IDREF on the same element");
					goto beach;
				}
				RzCFParseState *next_state = rz_cf_parse_state_new(next_phase);
				if (!next_state) {
					goto beach;
				}
				rz_list_push(stack, next_state);
			}
			break;
		}
		case YXML_ATTRVAL: {
			if (idlist) {
				RzCFParseState *state = (RzCFParseState *)rz_list_last(stack);
				if (state->phase != RZ_CF_STATE_IN_ATTR_ID && state->phase != RZ_CF_STATE_IN_ATTR_IDREF) {
					break;
				}
				content = rz_str_append(content, x.data);
			}
			break;
		}
		case YXML_ATTREND: {
			if (idlist) {
				RzCFParseState *state = (RzCFParseState *)rz_list_last(stack);
				if (state->phase != RZ_CF_STATE_IN_ATTR_ID && state->phase != RZ_CF_STATE_IN_ATTR_IDREF) {
					break;
				}
				rz_list_pop(stack);
				RzCFParseState *next_state = (RzCFParseState *)rz_list_last(stack);
				next_state->id = (ut32)rz_num_get(NULL, content);
				next_state->idstate = state->phase == RZ_CF_STATE_IN_ATTR_ID ? RZ_CF_ID_STATE_SET : RZ_CF_ID_STATE_REF;
				RZ_FREE(content);
				content = NULL;
				rz_cf_parse_state_free(state);
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
		RZ_LOG_ERROR("Invalid xml\n");
	}

beach:
	RZ_FREE(xml_buf);
	rz_list_free(stack);
	rz_list_free(idlist);
	free(content);

	return result;
}

static RzCFParseState *rz_cf_parse_state_new(RzCFParsePhase phase) {
	RzCFParseState *state = RZ_NEW0(RzCFParseState);
	if (state) {
		state->phase = phase;
	}
	return state;
}

static void rz_cf_parse_state_free(RzCFParseState *state) {
	if (state) {
		RZ_FREE(state);
	}
}

static RzCFKeyValue *rz_cf_key_value_new(char *key, RzCFValue *value) {
	RzCFKeyValue *key_value = RZ_NEW0(RzCFKeyValue);
	if (!key_value) {
		return NULL;
	}

	key_value->key = key;
	key_value->value = value;

	return key_value;
}

static void rz_cf_key_value_free(RzCFKeyValue *key_value) {
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

static RzCFValueDict *rz_cf_value_dict_new(void) {
	RzCFValueDict *dict = RZ_NEW0(RzCFValueDict);
	if (!dict) {
		return NULL;
	}

	dict->type = RZ_CF_DICT;
	dict->pairs = rz_list_newf((RzListFree)&rz_cf_key_value_free);

	return dict;
}

RZ_API void rz_cf_value_dict_free(RzCFValueDict *dict) {
	rz_return_if_fail(dict);

	if (dict->pairs) {
		rz_list_free(dict->pairs);
		dict->pairs = NULL;
	}
	dict->type = RZ_CF_INVALID;
	RZ_FREE(dict);
}

static void rz_cf_value_dict_add(RzCFValueDict *dict, RzCFKeyValue *key_value) {
	if (!dict || !dict->pairs) {
		return;
	}

	rz_list_push(dict->pairs, key_value);
}

static void rz_cf_value_dict_print(RzCFValueDict *dict) {
	RzListIter *iter;
	RzCFKeyValue *key_value;
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

static RzCFValueArray *rz_cf_value_array_new(void) {
	RzCFValueArray *array = RZ_NEW0(RzCFValueArray);
	if (!array) {
		return NULL;
	}

	array->type = RZ_CF_ARRAY;
	array->values = rz_list_newf((RzListFree)&rz_cf_value_free);

	return array;
}

static void rz_cf_value_array_free(RzCFValueArray *array) {
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

static void rz_cf_value_array_add(RzCFValueArray *array, RzCFValue *value) {
	if (!array || !array->values) {
		return;
	}

	rz_list_push(array->values, value);
}

static void rz_cf_value_array_print(RzCFValueArray *array) {
	RzListIter *iter;
	RzCFValue *value;
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

static RzCFValueString *rz_cf_value_string_new(char *string) {
	RzCFValueString *value_string = RZ_NEW0(RzCFValueString);
	if (!value_string) {
		return NULL;
	}

	value_string->type = RZ_CF_STRING;
	value_string->value = string;

	return value_string;
}

static void rz_cf_value_string_free(RzCFValueString *string) {
	if (!string) {
		return;
	}

	if (string->value) {
		RZ_FREE(string->value);
	}

	string->type = RZ_CF_INVALID;
	RZ_FREE(string);
}

static void rz_cf_value_string_print(RzCFValueString *string) {
	char *escaped = strdup(string->value);
	escaped = rz_str_replace(escaped, "\"", "\\\"", 1);
	printf("\"%s\"", escaped);
	RZ_FREE(escaped);
}

static RzCFValueInteger *rz_cf_value_integer_new(char *string) {
	RzCFValueInteger *integer = RZ_NEW0(RzCFValueInteger);
	if (!integer) {
		return NULL;
	}

	integer->type = RZ_CF_INTEGER;
	integer->value = rz_num_get(NULL, string);

	return integer;
}

static void rz_cf_value_integer_free(RzCFValueInteger *integer) {
	if (!integer) {
		return;
	}

	integer->type = RZ_CF_INVALID;
	RZ_FREE(integer);
}

static void rz_cf_value_integer_print(RzCFValueInteger *integer) {
	printf("%llu", integer->value);
}

static RzCFValueData *rz_cf_value_data_new(char *string) {
	RzCFValueData *data = RZ_NEW0(RzCFValueData);
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

static void rz_cf_value_data_free(RzCFValueData *data) {
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

static void rz_cf_value_data_print(RzCFValueData *data) {
	printf("\"...\"");
}

static RzCFValueNULL *rz_cf_value_null_new(void) {
	RzCFValueNULL *null = RZ_NEW0(RzCFValueNULL);
	if (!null) {
		return NULL;
	}

	null->type = RZ_CF_NULL;

	return null;
}

static void rz_cf_value_null_free(RzCFValueNULL *null) {
	if (!null) {
		return;
	}

	null->type = RZ_CF_INVALID;
	RZ_FREE(null);
}

static void rz_cf_value_null_print(RzCFValueNULL *null) {
	printf("null");
}

static RzCFValueBool *rz_cf_value_bool_new(bool value) {
	RzCFValueBool *bool_value = RZ_NEW0(RzCFValueBool);
	if (!bool_value) {
		return NULL;
	}

	bool_value->type = value ? RZ_CF_TRUE : RZ_CF_FALSE;
	return bool_value;
}

static void rz_cf_value_bool_free(RzCFValueBool *bool_value) {
	if (bool_value) {
		bool_value->type = RZ_CF_INVALID;
		RZ_FREE(bool_value);
	}
}

static void rz_cf_value_bool_print(RzCFValueBool *bool_value) {
	if (bool_value->type == RZ_CF_TRUE) {
		printf("true");
	} else {
		printf("false");
	}
}

static RzCFValue *rz_cf_value_clone(RzCFValue *value) {
	if (!value) {
		return NULL;
	}

	RzCFValue *copy = NULL;

	switch (value->type) {
	case RZ_CF_DICT: {
		RzCFValueDict *dict = rz_cf_value_dict_new();
		if (dict) {
			copy = (RzCFValue *)dict;
			RzListIter *iter;
			RzCFKeyValue *item;
			rz_list_foreach (((RzCFValueDict *)value)->pairs, iter, item) {
				char *key = rz_str_dup(item->key);
				if (key) {
					RzCFValue *clone = rz_cf_value_clone(item->value);
					if (clone) {
						RzCFKeyValue *pair = rz_cf_key_value_new(key, clone);
						if (pair) {
							rz_cf_value_dict_add(dict, pair);
						}
						rz_cf_value_free(clone);
					}
					RZ_FREE(key);
				}
				rz_cf_value_dict_free(dict);
				copy = NULL;
				break;
			}
		}
		break;
	}
	case RZ_CF_ARRAY: {
		RzCFValueArray *array = rz_cf_value_array_new();
		if (array) {
			copy = (RzCFValue *)array;
			RzListIter *iter;
			RzCFValue *item;
			rz_list_foreach (((RzCFValueArray *)value)->values, iter, item) {
				RzCFValue *clone = rz_cf_value_clone(item);
				if (clone) {
					rz_cf_value_array_add(array, clone);
					continue;
				}
				rz_cf_value_array_free(array);
				copy = NULL;
				break;
			}
		}
		break;
	}
	case RZ_CF_STRING: {
		RzCFValueString *string = RZ_NEW0(RzCFValueString);
		if (string) {
			string->value = rz_str_dup(((RzCFValueString *)value)->value);
			if (string->value) {
				copy = (RzCFValue *)string;
			} else {
				RZ_FREE(string);
			}
		}
		break;
	}
	case RZ_CF_INTEGER: {
		RzCFValueInteger *integer = RZ_NEW0(RzCFValueInteger);
		if (integer) {
			integer->value = ((RzCFValueInteger *)value)->value;
			copy = (RzCFValue *)integer;
		}
		break;
	}
	case RZ_CF_DATA: {
		RzCFValueData *data = RZ_NEW0(RzCFValueData);
		if (data) {
			data->value = rz_buf_new_with_buf(((RzCFValueData *)value)->value);
			if (data->value) {
				copy = (RzCFValue *)data;
			} else {
				RZ_FREE(data);
			}
		}
		break;
	}
	case RZ_CF_NULL:
		copy = (RzCFValue *)(RZ_NEW0(RzCFValueNULL));
		break;
	case RZ_CF_TRUE:
	case RZ_CF_FALSE:
		copy = (RzCFValue *)(RZ_NEW0(RzCFValueBool));
		break;
	default:
		break;
	}

	if (copy) {
		copy->type = value->type;
	}

	return copy;
}

static void rz_cf_value_free(RzCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case RZ_CF_DICT:
		rz_cf_value_dict_free((RzCFValueDict *)value);
		break;
	case RZ_CF_ARRAY:
		rz_cf_value_array_free((RzCFValueArray *)value);
		break;
	case RZ_CF_STRING:
		rz_cf_value_string_free((RzCFValueString *)value);
		break;
	case RZ_CF_INTEGER:
		rz_cf_value_integer_free((RzCFValueInteger *)value);
		break;
	case RZ_CF_DATA:
		rz_cf_value_data_free((RzCFValueData *)value);
		break;
	case RZ_CF_NULL:
		rz_cf_value_null_free((RzCFValueNULL *)value);
		break;
	case RZ_CF_TRUE:
	case RZ_CF_FALSE:
		rz_cf_value_bool_free((RzCFValueBool *)value);
		break;
	default:
		break;
	}
}

RZ_API void rz_cf_value_print(RzCFValue *value) {
	if (!value) {
		return;
	}

	switch (value->type) {
	case RZ_CF_DICT:
		rz_cf_value_dict_print((RzCFValueDict *)value);
		break;
	case RZ_CF_ARRAY:
		rz_cf_value_array_print((RzCFValueArray *)value);
		break;
	case RZ_CF_STRING:
		rz_cf_value_string_print((RzCFValueString *)value);
		break;
	case RZ_CF_INTEGER:
		rz_cf_value_integer_print((RzCFValueInteger *)value);
		break;
	case RZ_CF_DATA:
		rz_cf_value_data_print((RzCFValueData *)value);
		break;
	case RZ_CF_NULL:
		rz_cf_value_null_print((RzCFValueNULL *)value);
		break;
	case RZ_CF_TRUE:
	case RZ_CF_FALSE:
		rz_cf_value_bool_print((RzCFValueBool *)value);
		break;
	default:
		break;
	}
}
