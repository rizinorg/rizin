
#ifndef RZ_SERIALIZE_UTIL_H
#define RZ_SERIALIZE_UTIL_H

#include <rz_util/rz_str.h>

#define SERIALIZE_ERR(...) do { if(res) { rz_list_push (res, rz_str_newf (__VA_ARGS__)); } } while(0)

// Hashtable-based key parser to prevent strcmp chains
typedef HtPP KeyParser;

static inline KeyParser *key_parser_new(void) {
	return ht_pp_new0 ();
}

static inline void key_parser_free(KeyParser *parser) {
	ht_pp_free (parser);
}

static inline void key_parser_add(KeyParser *parser, const char *key, int val) {
	ht_pp_insert (parser, key, (void *)(size_t)val);
}

#define KEY_PARSER_UNKNOWN -1

#define KEY_PARSER_SWITCH(parser, key) \
	bool key_parser_found = false; \
	int key_parser_v = (int)(size_t)ht_pp_find (parser, key, &key_parser_found); \
	if (!key_parser_found) { \
		key_parser_v = KEY_PARSER_UNKNOWN; \
	} \
	switch (key_parser_v)

#define KEY_PARSER_JSON(parser, json, child, body) \
	if(json->type == RZ_JSON_OBJECT) { \
		for(RJson *child = json->children.first; child; child = child->next) { \
			KEY_PARSER_SWITCH (parser, child->key) { body } \
		} \
	}

#define SUB_DO(ns, call, rip) \
	subdb = sdb_ns (db, ns, false); \
	if (!subdb) { \
		SERIALIZE_ERR ("missing " ns " namespace"); \
		rip \
	} \
	if (!(call)) { \
		rip \
	} \

#endif //RZ_SERIALIZE_UTIL_H
