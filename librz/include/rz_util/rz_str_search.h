#ifndef RZ_STR_SEARCH_H
#define RZ_STR_SEARCH_H

#include <rz_bin.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_scan_strings(RzList *list, RzBuffer *buf_to_scan,
	const ut64 from, const ut64 to, int min_str_length, int type);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_SEARCH_H
