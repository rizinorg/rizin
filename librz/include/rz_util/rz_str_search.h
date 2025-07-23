#ifndef RZ_STR_SEARCH_H
#define RZ_STR_SEARCH_H

#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/ht_uu.h>
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
	RzStrEnc type; ///< String encoding in memory.
	size_t alignment; ///< The address alignment a matched string must have. If search.align is set, both must match.
} RzDetectedString;

/**
 * \brief Flags to allow undefined unicode code points during string scanning.
 */
typedef enum {
	RZ_STR_SCAN_ONLY_DEFINED = 0,
	RZ_STR_SCAN_UTF8_UNDEF = 1,
	RZ_STR_SCAN_UTF16_UNDEF = 2,
	RZ_STR_SCAN_UTF32_UNDEF = 4,
	RZ_STR_SCAN_UTF_UNDEF = RZ_STR_SCAN_UTF8_UNDEF | RZ_STR_SCAN_UTF16_UNDEF | RZ_STR_SCAN_UTF32_UNDEF,
} RzStrScanAllowedUndef;

/**
 * Defines the search parameters for rz_scan_strings
 */
typedef struct {
	size_t max_str_length; ///< Maximum size of a detected string.
	size_t min_str_length; ///< Minimum string length
	bool prefer_big_endian; ///< True if the preferred endianess for UTF strings is big-endian
	bool check_ascii_freq; ///< If true, perform check on ASCII frequencies when looking for false positives
	/**
	 * \brief Flags for allowing undefined code points during scanning.
	 * If set the scan accepts code points in strings even
	 * if they are undefined by unicode standards.
	 * This can improve performance, because checking code point definitons
	 * has a runtime complexity of O(log n): n = number of undefined ranges.
	 *
	 * NOTE: "Undefined" is not the same as an invalid decode.
	 * The scanner won't add bytes to the string if they don't decode at all.
	 * Or if they decode to a surrogate.
	 *
	 * This is relevant for UTF-16 and UTF-32.
	 * Because they always decode to some code code.
	 * Allowing undefined code points for them, will effectively allow any
	 * byte pattern into the string, *except* surrogates.
	 */
	RzStrScanAllowedUndef allow_undefined;
	/**
	 * \brief Map UTF-8 byte offsets to memory offsets.
	 * The string scan function always returns UTF-8 strings.
	 * Independent what encoding the strings have in memory.
	 * Sometimes it is necessary to know the offsets of the real encoding.
	 * This maps an UTF-8 code point offset to the original code point offset in memory.
	 * The keys are ut64 values. With the upper 32bits holding the index into the
	 * "detected string list" returned by rz_scan_strings_whole_buf().
	 * The lower 32bits are the offset into the UTF-8 string.
	 * The value is the offset into the memory. Relevant to the buffer
	 * The string was found in.
	 *
	 * Example:
	 *
	 * Buffer (UTF-16): 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00, 0x42, 0x00, 0x42
	 * Found strings (UTF-8): [ "AA", "BB" ]
	 * Map: {
	 *   0x0000000000000000: 0,
	 *   0x0000000000000001: 2,
	 *   0x0000000100000000: 6,
	 *   0x0000000100000001: 8
	 * }
	 */
	RZ_NULLABLE HtUU *utf8_to_mem_offset_map;
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
