/* rizin - LGPL - Copyright 2020 - thestr4ng3r */

#ifndef RZ_SERIALIZE_H
#define RZ_SERIALIZE_H

#include <rz_util/rz_json.h>
#include <rz_list.h>

typedef RzList RzSerializeResultInfo;
static inline RzSerializeResultInfo *rz_serialize_result_info_new(void) {
	return rz_list_newf(free);
}
static inline void rz_serialize_result_info_free(RzSerializeResultInfo *info) {
	rz_list_free(info);
}

#endif //RZ_SERIALIZE_H
