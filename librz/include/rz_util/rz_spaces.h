#ifndef RZ_SPACES_H
#define RZ_SPACES_H

#define RZ_SPACES_MAX 512

#include "rz_util.h"
#include "rz_serialize.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RzSpaces represents a set of Spaces.
 * A Space is used to group similar objects and it can have a name. Name
 * "*"/""/NULL is reserved to indicate "all spaces".
 *
 * You can have groups of "meta" (e.g. bin meta, format meta, etc.), groups of
 * zign info, groups of flags, etc.
 *
 * It is possible to hook into the RzSpaces functions by using RzEvent.
 * RZ_SPACE_EVENT_COUNT: called when you need to count how many elements there are in a given RzSpace
 * RZ_SPACE_EVENT_RENAME: called when renaming a RzSpace with an oldname to a newname
 * RZ_SPACE_EVENT_UNSET: called when deleting a RzSpace with a given name
 */

typedef struct rz_space_t {
	char *name;
	RBNode rb;
} RzSpace;

typedef enum {
	RZ_SPACE_EVENT_COUNT = 1,
	RZ_SPACE_EVENT_RENAME,
	RZ_SPACE_EVENT_UNSET,
} RzSpaceEventType;

typedef struct rz_space_event_t {
	union {
		struct {
			const RzSpace *space;
		} count;
		struct {
			const RzSpace *space;
		} unset;
		struct {
			const RzSpace *space;
			const char *oldname;
			const char *newname;
		} rename;
	} data;
	int res;
} RzSpaceEvent;

typedef struct rz_spaces_t {
	const char *name;
	RzSpace *current;
	RBTree spaces;
	RzList *spacestack;
	RzEvent *event;
} RzSpaces;

// Create a new RzSpaces with the given name
RZ_API RzSpaces *rz_spaces_new(const char *name);
// Initialize an existing RzSpaces with the given name
RZ_API bool rz_spaces_init(RzSpaces *sp, const char *name);
// Finalize an existing RzSpaces
RZ_API void rz_spaces_fini(RzSpaces *sp);
// Finalize and free an existing RzSpaces
RZ_API void rz_spaces_free(RzSpaces *sp);
// Delete all spaces
RZ_API void rz_spaces_purge(RzSpaces *sp);
// Get the RzSpace with the given name
RZ_API RzSpace *rz_spaces_get(RzSpaces *sp, const char *name);
// Add a new RzSpace if one does not already exist, otherwise return the existing one
RZ_API RzSpace *rz_spaces_add(RzSpaces *sp, const char *name);
// Add and select a new RzSpace if one does not already exist, otherwise return and select the existing one
RZ_API RzSpace *rz_spaces_set(RzSpaces *sp, const char *name);
// Remove the RzSpace with the given name or all of them if name is NULL
RZ_API bool rz_spaces_unset(RzSpaces *sp, const char *name);
// Change the name of RzSpace with oname to nname
RZ_API bool rz_spaces_rename(RzSpaces *sp, const char *oname, const char *nname);
// Count the elements that belong to the RzSpace with the given name
RZ_API int rz_spaces_count(RzSpaces *sp, const char *name);
// Add/Select the RzSpace with the given name and save the current one in the history
RZ_API bool rz_spaces_push(RzSpaces *sp, const char *name);
// Select the RzSpace that was set before the current one
RZ_API bool rz_spaces_pop(RzSpaces *sp);

static inline RzSpace *rz_spaces_current(RzSpaces *sp) {
	return sp->current;
}

static inline const char *rz_spaces_current_name(RzSpaces *sp) {
	return sp->current ? sp->current->name : "*";
}

static inline bool rz_spaces_is_empty(RzSpaces *sp) {
	RBIter it = rz_rbtree_first(sp->spaces);
	return it.len == 0;
}

typedef RBIter RzSpaceIter;
#define rz_spaces_foreach(sp, it, s) \
	rz_rbtree_foreach ((sp)->spaces, (it), (s), RzSpace, rb)

/* serialize */

RZ_API void rz_serialize_spaces_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzSpaces *spaces);
/**
 * @param load_name whether to overwrite the name in spaces with the value from db
 */
RZ_API bool rz_serialize_spaces_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzSpaces *spaces, bool load_name, RZ_NULLABLE RzSerializeResultInfo *res);

#ifdef __cplusplus
}
#endif

#endif //  RZ_SPACES_H
