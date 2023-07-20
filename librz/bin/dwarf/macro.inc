// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define OK_None \
	do { \
		*out = NULL; \
		return true; \
	} while (0)

#define RET_VAL_IF_FAIL(x, val) \
	do { \
		if (!(x)) { \
			return (val); \
		} \
	} while (0)

#define RET_FALSE_IF_FAIL(x) RET_VAL_IF_FAIL(x, false)
#define RET_NULL_IF_FAIL(x)  RET_VAL_IF_FAIL(x, NULL)
#define GOTO_IF_FAIL(x, label) \
	do { \
		if (!(x)) { \
			goto label; \
		} \
	} while (0)

#define UX_WRAP(out, x, wrap) \
	switch ((x)) { \
	case 1: \
		wrap(rz_buf_read8(buffer, (ut8 *)&(out))); \
		break; \
	case 2: \
		wrap(rz_buf_read_ble16(buffer, (ut16 *)&(out), big_endian)); \
		break; \
	case 4: \
		wrap(rz_buf_read_ble32(buffer, (ut32 *)&(out), big_endian)); \
		break; \
	case 8: \
		wrap(rz_buf_read_ble64(buffer, (ut64 *)&(out), big_endian)); \
		break; \
	default: \
		RZ_LOG_ERROR("DWARF: Unexpected pointer size: %u\n", (unsigned)(x)); \
		return false; \
	}

#define UX_WRAP1(out, x, wrap, ...) \
	switch ((x)) { \
	case 1: \
		wrap(rz_buf_read8(buffer, (ut8 *)&(out)), __VA_ARGS__); \
		break; \
	case 2: \
		wrap(rz_buf_read_ble16(buffer, (ut16 *)&(out), big_endian), __VA_ARGS__); \
		break; \
	case 4: \
		wrap(rz_buf_read_ble32(buffer, (ut32 *)&(out), big_endian), __VA_ARGS__); \
		break; \
	case 8: \
		wrap(rz_buf_read_ble64(buffer, (ut64 *)&(out), big_endian), __VA_ARGS__); \
		break; \
	default: \
		RZ_LOG_ERROR("DWARF: Unexpected pointer size: %u\n", (unsigned)(x)); \
		return false; \
	}

static inline char *buf_get_string(RzBuffer *buffer) {
	st64 offset = (st64)rz_buf_tell(buffer);
	RET_NULL_IF_FAIL(offset != -1);
	char *x = rz_buf_get_string(buffer, offset);
	RET_NULL_IF_FAIL(x);
	ut64 len = strlen(x) + 1;
	rz_buf_seek(buffer, (st64)len, SEEK_CUR);
	if (len <= 1) {
		free(x);
		return NULL;
	}
	return x;
}

#define U8_WARP(out, warp)     warp(rz_buf_read8(buffer, (ut8 *)&(out)))
#define U16_WARP(out, warp)    warp(rz_buf_read_ble16(buffer, (ut16 *)&(out), big_endian))
#define U32_WARP(out, warp)    warp(rz_buf_read_ble32(buffer, (ut32 *)&(out), big_endian))
#define U64_WARP(out, warp)    warp(rz_buf_read_ble64(buffer, (ut64 *)&(out), big_endian))
#define U128_WARP(out, warp)   warp(rz_buf_read_ble128(buffer, (ut128 *)&(out), big_endian))
#define ULE128_WARP(out, warp) warp(rz_buf_uleb128(buffer, (ut64 *)&(out)) > 0)
#define SLE128_WARP(out, warp) warp(rz_buf_sleb128(buffer, (st64 *)&(out)) > 0)

#define U8_WARP1(out, warp, ...)     warp(rz_buf_read8(buffer, (ut8 *)&(out)), __VA_ARGS__)
#define U16_WARP1(out, warp, ...)    warp(rz_buf_read_ble16(buffer, (ut16 *)&(out), big_endian), __VA_ARGS__)
#define U32_WARP1(out, warp, ...)    warp(rz_buf_read_ble32(buffer, (ut32 *)&(out), big_endian), __VA_ARGS__)
#define U64_WARP1(out, warp, ...)    warp(rz_buf_read_ble64(buffer, (ut64 *)&(out), big_endian), __VA_ARGS__)
#define U128_WARP1(out, warp, ...)   warp(rz_buf_read_ble128(buffer, (ut128 *)&(out), big_endian), __VA_ARGS__)
#define ULE128_WARP1(out, warp, ...) warp(rz_buf_uleb128(buffer, (ut64 *)&(out)) > 0, __VA_ARGS__)
#define SLE128_WARP1(out, warp, ...) warp(rz_buf_sleb128(buffer, (st64 *)&(out)) > 0, __VA_ARGS__)

#define U8_OR_RET_NULL(out)     U8_WARP(out, RET_NULL_IF_FAIL)
#define U16_OR_RET_NULL(out)    U16_WARP(out, RET_NULL_IF_FAIL)
#define U32_OR_RET_NULL(out)    U32_WARP(out, RET_NULL_IF_FAIL)
#define U64_OR_RET_NULL(out)    U64_WARP(out, RET_NULL_IF_FAIL)
#define U128_OR_RET_NULL(out)   U128_WARP(out, RET_NULL_IF_FAIL)
#define UX_OR_RET_NULL(out, x)  UX_WRAP(out, x, RET_NULL_IF_FAIL)
#define ULE128_OR_RET_NULL(out) ULE128_WARP(out, RET_NULL_IF_FAIL)
#define SLE128_OR_RET_NULL(out) SLE128_WARP(out, RET_NULL_IF_FAIL)

#define U8_OR_RET_FALSE(out)     U8_WARP(out, RET_FALSE_IF_FAIL)
#define U16_OR_RET_FALSE(out)    U16_WARP(out, RET_FALSE_IF_FAIL)
#define U32_OR_RET_FALSE(out)    U32_WARP(out, RET_FALSE_IF_FAIL)
#define U64_OR_RET_FALSE(out)    U64_WARP(out, RET_FALSE_IF_FAIL)
#define U128_OR_RET_FALSE(out)   U128_WARP(out, RET_FALSE_IF_FAIL)
#define UX_OR_RET_FALSE(out, x)  UX_WRAP(out, x, RET_FALSE_IF_FAIL)
#define ULE128_OR_RET_FALSE(out) ULE128_WARP(out, RET_FALSE_IF_FAIL)
#define SLE128_OR_RET_FALSE(out) SLE128_WARP(out, RET_FALSE_IF_FAIL)

#define U8_OR_GOTO(out, label)     U8_WARP1(out, GOTO_IF_FAIL, label)
#define U16_OR_GOTO(out, label)    U16_WARP1(out, GOTO_IF_FAIL, label)
#define U32_OR_GOTO(out, label)    U32_WARP1(out, GOTO_IF_FAIL, label)
#define U64_OR_GOTO(out, label)    U64_WARP1(out, GOTO_IF_FAIL, label)
#define U128_OR_GOTO(out, label)   U128_WARP1(out, GOTO_IF_FAIL, label)
#define UX_OR_GOTO(out, x, label)  UX_WRAP1(out, x, GOTO_IF_FAIL, label)
#define ULE128_OR_GOTO(out, label) ULE128_WARP1(out, GOTO_IF_FAIL, label)
#define SLE128_OR_GOTO(out, label) SLE128_WARP1(out, GOTO_IF_FAIL, label)