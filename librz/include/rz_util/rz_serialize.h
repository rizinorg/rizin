// SPDX-FileCopyrightText: Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SERIALIZE_H
#define RZ_SERIALIZE_H

#include <rz_util/rz_json.h>
#include <rz_util/ht_sp.h>
#include <rz_list.h>

/**
 * \brief Detailed info about a (de)serialization result
 *
 * This is currently just a list of strings which may be warnings
 * or detailed error messages.
 */
typedef RzList RzSerializeResultInfo;

static inline RzSerializeResultInfo *rz_serialize_result_info_new(void) {
	return rz_list_newf(free);
}

static inline void rz_serialize_result_info_free(RzSerializeResultInfo *info) {
	rz_list_free(info);
}

// Common helpers for writing (de)serialization code

/**
 * \brief Push an error to the local RzSerializeResultInfo
 * \res RzSerializeInfoResult *
 * \param ... printf-style arguments to be pushed as the error to res
 */
#define RZ_SERIALIZE_ERR(res, ...) \
	do { \
		if (res) { \
			rz_list_push(res, rz_str_newf(__VA_ARGS__)); \
		} \
	} while (0)

/**
 * \brief Hashtable-based key parser to prevent strcmp chains
 *
 * This enables string values to be used in a switch/case-like
 * fashion.
 */
typedef HtSP RzKeyParser;

static inline RzKeyParser *rz_key_parser_new(void) {
	return ht_sp_new(HT_STR_DUP, NULL, NULL);
}

static inline void rz_key_parser_free(RzKeyParser *parser) {
	ht_sp_free(parser);
}

static inline void rz_key_parser_add(RzKeyParser *parser, const char *key, int val) {
	ht_sp_insert(parser, key, (void *)(size_t)val);
}

#define RZ_KEY_PARSER_UNKNOWN -1

/**
 * \brief switch-like macro over RzKeyParser values
 * \param parser RzKeyParser *
 * \param key const char *
 */
#define RZ_KEY_PARSER_SWITCH(parser, key) \
	bool key_parser_found = false; \
	int key_parser_v = (int)(size_t)ht_sp_find(parser, key, &key_parser_found); \
	if (!key_parser_found) { \
		key_parser_v = RZ_KEY_PARSER_UNKNOWN; \
	} \
	switch (key_parser_v)

/**
 * \brief Iterate over all keys in a json object and call RZ_KEY_PARSER_SWITCH on each
 * \param parser RzKeyParser *
 * \param json RzJson *
 * \param child var name for the `RzJson *child`
 * \param body code block with cases
 */
#define RZ_KEY_PARSER_JSON(parser, json, child, body) \
	if (json->type == RZ_JSON_OBJECT) { \
		for (RzJson *child = json->children.first; child; child = child->next) { \
			RZ_KEY_PARSER_SWITCH(parser, child->key) { \
				body \
			} \
		} \
	}

/**
 * \brief Get an sdb sub-namespace or fail
 * \param db Sdb * the Sdb from which to take the sub-namespace
 * \param subdb Sdb * where to put the sub-namespace
 * \param res RzSerializeResult * where to push an error on failure
 * \param ns const char *
 * \param rip code to execute if the function failed
 *
 * Example:
 *
 *     Sdb *subdb;
 *     RZ_SERIALIZE_SUB(db, subdb, res, "files", return false;)
 *     // do something with subdb
 *
 */
#define RZ_SERIALIZE_SUB(db, subdb, res, ns, rip) \
	do { \
		subdb = sdb_ns(db, ns, false); \
		if (!subdb) { \
			RZ_SERIALIZE_ERR(res, "missing " ns " namespace"); \
			rip \
		} \
	} while (0)

/**
 * \brief Get an sdb sub-namespace and evaluate `call` or fail
 * \param db Sdb * the Sdb from which to take the sub-namespace
 * \param subdb Sdb * where to put the sub-namespace
 * \param res RzSerializeResult * where to push an error on failure
 * \param ns const char *
 * \param call function call
 * \param rip code to execute if the function failed
 *
 * Example:
 *
 *     Sdb *subdb;
 *     RZ_SERIALIZE_SUB_DO(db, subdb, res, "files",
 *         rz_serialize_io_files_load(subdb, io, res), return false;)
 *
 */
#define RZ_SERIALIZE_SUB_DO(db, subdb, res, ns, call, rip) \
	RZ_SERIALIZE_SUB(db, subdb, res, ns, rip); \
	if (!(call)) { \
		rip \
	}

#endif // RZ_SERIALIZE_H
