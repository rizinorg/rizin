/* rizin - LGPL - Copyright 2020 - thestr4ng3r */

#ifndef RZ_SERIALIZE_H
#define RZ_SERIALIZE_H

#include <rz_util/rz_json.h>
#include <rz_list.h>

typedef RzList RSerializeResultInfo;
static inline RSerializeResultInfo *rz_serialize_result_info_new(void) { return rz_list_newf (free); }
static inline void rz_serialize_result_info_free(RSerializeResultInfo *info) { rz_list_free (info); }

#endif //RZ_SERIALIZE_H
