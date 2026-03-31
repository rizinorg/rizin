#ifndef RZ_STR_SEARCH_H
#define RZ_STR_SEARCH_H

#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_regex.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represent a detected string.
 */
typedef struct {
	char *string; ///< The detected string. Note that this one is always in UTF-8. No matter what the ecoding is in memory.
	RzRegexMulti *regex; ///< Regex matching the string. If set, the string member is the pattern.
	ut64 addr; ///< Address/offset of the string in the RzBuffer
	ut32 size; ///< Size of buffer containing the string in bytes
	ut32 length; ///< Length of string in chars
	RzStrEnc encoding; ///< String encoding in memory.
	size_t alignment; ///< The address alignment a matched string must have. If search.align is set, both must match.
	/**
	 * \brief Maps UTF-8 code point offsets to their memory offset.
	 * This is necessary if the string's character width in memory doesn't match UTF-8 character width.
	 * E.g. the in memory string is IBM270 (Japanese) and has a character width of 1 bytes.
	 * But the decoded string above is always UTF-8 and has a character width of 1-4 bytes.
	 *
	 * It is NULL if the string encoding in memory is UTF-8 or ASCII.
	 */
	ut64 *byte_mem_map;
} RzDetectedString;

/**
 * Defines the search parameters for rz_scan_strings
 */
typedef struct {
	size_t max_str_length; ///< Maximum size of a detected string.
	size_t min_str_length; ///< Minimum string length
	bool prefer_big_endian; ///< True if the preferred endianess for UTF strings is big-endian
	bool check_ascii_freq; ///< If true, perform check on ASCII frequencies when looking for false positives
} RzUtilStrScanOptions;

RZ_API void rz_detected_string_free(RzDetectedString *str);

RZ_API bool rz_scan_strings_single_raw(RZ_NONNULL const ut8 *buf, ut64 size, RZ_NONNULL const RzUtilStrScanOptions *opt, RzStrEnc type, RZ_NONNULL RzDetectedString **output);
RZ_API int rz_scan_strings_raw(RZ_NONNULL const ut8 *buf, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type);
RZ_API int rz_scan_strings(RZ_NONNULL RzBuffer *buf_to_scan, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type);
RZ_API int rz_scan_strings_whole_buf(RZ_NONNULL const RzBuffer *buf_to_scan, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt, RzStrEnc type);

#ifdef __cplusplus
}
#endif

#endif // RZ_STR_SEARCH_H
