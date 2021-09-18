#ifndef RZ_STR_SEARCH_H
#define RZ_STR_SEARCH_H

#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_buf.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represent a detected string.
 */
typedef struct {
	char *string; ///< Pointer to the string
	ut64 addr; ///< Address of the string in the RzBuffer
	ut32 size; ///< Size of buffer containing the string in bytes
	ut32 length; ///< Length of string in chars
	RzStrEnc type; ///< String type
} RzDetectedString;

/**
 * Defines the search parameters for rz_scan_strings
 */
typedef struct {
	size_t buf_size; ///< Maximum size of a detected string
	size_t max_uni_blocks; ///< Maximum number of unicode blocks
	size_t min_str_length; ///< Minimum string length
	bool prefer_big_endian; //< True if the preferred endianess for UTF strings is big-endian
} RzUtilStrScanOptions;

RZ_API void rz_detected_string_free(RzDetectedString *str);

RZ_API int rz_scan_strings(RzBuffer *buf_to_scan, RzList *list, const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_SEARCH_H
