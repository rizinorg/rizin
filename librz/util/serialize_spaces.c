
#include <rz_util/rz_serialize.h>
#include <rz_util/rz_spaces.h>

#include "../util/serialize_helper.h"

/*
 * SDB Format:
 *
 * /
 *   name=<spaces name>
 *   spacestack=[<space name>,<space name>,<space name>, <current>] (json)
 *   /spaces
 *     <space name>="s"
 *     ...
 */

#define KEY_NAME "name"
#define KEY_SPACESTACK "spacestack"
#define KEY_SPACES "spaces"

RZ_API void rz_serialize_spaces_save(RZ_NONNULL Sdb *db, RZ_NONNULL RSpaces *spaces) {
	sdb_set (db, KEY_NAME, spaces->name, 0);

	PJ *j = pj_new ();
	if(!j) {
		return;
	}
	pj_a (j);
	RzListIter *iter;
	char *spacename;
	rz_list_foreach (spaces->spacestack, iter, spacename) {
		pj_s (j, spacename);
	}
	pj_s (j, spaces->current ? spaces->current->name : "*"); // push current manually, will be popped on load
	pj_end (j);
	sdb_set (db, KEY_SPACESTACK, pj_string (j), 0);
	pj_free (j);

	Sdb *db_spaces = sdb_ns (db, KEY_SPACES, true);
	RBIter rbiter;
	RSpace *space;
	rz_rbtree_foreach (spaces->spaces, rbiter, space, RSpace, rb) {
		sdb_set (db_spaces, space->name, "s", 0);
	}
}

static bool foreach_space_cb(void *user, const char *k, const char *v) {
	RSpaces *spaces = user;
	rz_spaces_add (spaces, k);
	return true;
}

RZ_API bool rz_serialize_spaces_load(RZ_NONNULL Sdb *db, RZ_NONNULL RSpaces *spaces, bool load_name, RZ_NULLABLE RSerializeResultInfo *res) {
	if (load_name) {
		char *old_name = (char *)spaces->name;
		spaces->name = sdb_get (db, KEY_NAME, NULL);
		if (!spaces->name) {
			spaces->name = old_name;
			SERIALIZE_ERR ("failed to get spaces name from db");
			return false;
		}
		free (old_name);
	}

	rz_spaces_purge (spaces);

	Sdb *db_spaces = sdb_ns (db, KEY_SPACES, false);
	if (!db_spaces) {
		SERIALIZE_ERR ("failed to get spaces sub-namespace");
		return false;
	}
	sdb_foreach (db_spaces, foreach_space_cb, spaces);

	char *stack_json_str = sdb_get (db, KEY_SPACESTACK, NULL);
	if (!stack_json_str) {
		SERIALIZE_ERR ("spacestack is missing");
		return false;
	}

	bool ret = true;
	RJson *stack_json = rz_json_parse (stack_json_str);
	if (!stack_json) {
		SERIALIZE_ERR ("failed to parse stackspace json");
		ret = false;
		goto beach;
	}
	if (stack_json->type != RZ_JSON_ARRAY) {
		SERIALIZE_ERR ("stackspace json is not an array");
		ret = false;
		goto beach;
	}
	RJson *stack_element;
	for (stack_element = stack_json->children.first; stack_element; stack_element = stack_element->next) {
		if (stack_element->type != RZ_JSON_STRING) {
			SERIALIZE_ERR ("stackspace element is not a string");
			ret = false;
			goto beach;
		}
		RSpace *space = rz_spaces_get (spaces, stack_element->str_value);
		rz_list_append (spaces->spacestack, space ? space->name : "*");
	}

	rz_spaces_pop (spaces); // current is the top stack element, pop it

beach:
	rz_json_free (stack_json);
	free (stack_json_str);
	return ret;
}
