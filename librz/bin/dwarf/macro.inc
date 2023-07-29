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

#define ERR_IF_FAIL(x) GOTO_IF_FAIL(x, err)

#define WRAP_F(X, F, out, wrap) \
	do { \
		X temp = { 0 }; \
		wrap(F); \
		out = temp; \
	} while (0)

#define WRAP_VA_F(X, F, out, wrap, ...) \
	do { \
		X temp = { 0 }; \
		wrap(F, __VA_ARGS__); \
		out = temp; \
	} while (0)

#define WRAP_U(X, out, wrap)           WRAP_F(ut##X, rz_buf_read_ble##X(buffer, &temp, big_endian), out, wrap)
#define WRAP_VA_U(X, out, wrap, ...)   WRAP_VA_F(ut##X, rz_buf_read_ble##X(buffer, &temp, big_endian), out, wrap, __VA_ARGS__)
#define WRAP_U8(out, wrap)             WRAP_F(ut8, rz_buf_read8(buffer, &temp), out, wrap)
#define WRAP_VA_U8(out, wrap, ...)     WRAP_VA_F(ut8, rz_buf_read8(buffer, &temp), out, wrap, __VA_ARGS__)
#define WRAP_ULE128(out, wrap)         WRAP_F(ut64, rz_buf_uleb128(buffer, &temp) > 0, out, wrap)
#define WRAP_VA_ULE128(out, wrap, ...) WRAP_VA_F(ut64, rz_buf_uleb128(buffer, &temp) > 0, out, wrap, __VA_ARGS__)
#define WRAP_SLE128(out, wrap)         WRAP_F(st64, rz_buf_sleb128(buffer, &temp) > 0, out, wrap)
#define WRAP_VA_SLE128(out, wrap, ...) WRAP_VA_F(st64, rz_buf_sleb128(buffer, &temp) > 0, out, wrap, __VA_ARGS__)

#define WRAP_UX(X, out, wrap) \
	switch ((X)) { \
	case 1: WRAP_U8(out, wrap); break; \
	case 2: WRAP_U(16, out, wrap); break; \
	case 4: WRAP_U(32, out, wrap); break; \
	case 8: WRAP_U(64, out, wrap); break; \
	default: RZ_LOG_ERROR("DWARF: Unexpected pointer size: %u\n", (unsigned)(X)); return false; \
	}

#define WRAP_VA_UX(X, out, wrap, ...) \
	switch ((X)) { \
	case 1: WRAP_VA_U8(out, wrap, __VA_ARGS__); break; \
	case 2: WRAP_VA_U(16, out, wrap, __VA_ARGS__); break; \
	case 4: WRAP_VA_U(32, out, wrap, __VA_ARGS__); break; \
	case 8: WRAP_VA_U(64, out, wrap, __VA_ARGS__); break; \
	default: RZ_LOG_ERROR("DWARF: Unexpected pointer size: %u\n", (unsigned)(X)); return false; \
	}

#define U8_OR_RET_NULL(out)     WRAP_U8(out, RET_NULL_IF_FAIL)
#define U_OR_RET_NULL(X, out)   WRAP_U(X, out, RET_NULL_IF_FAIL)
#define UX_OR_RET_NULL(X, out)  WRAP_UX(X, out, RET_NULL_IF_FAIL)
#define ULE128_OR_RET_NULL(out) WRAP_ULE128(out, RET_NULL_IF_FAIL)
#define SLE128_OR_RET_NULL(out) WRAP_SLE128(out, RET_NULL_IF_FAIL)

#define U8_OR_RET_FALSE(out)     WRAP_U8(out, RET_FALSE_IF_FAIL)
#define U_OR_RET_FALSE(X, out)   WRAP_U(X, out, RET_FALSE_IF_FAIL)
#define UX_OR_RET_FALSE(X, out)  WRAP_UX(X, out, RET_FALSE_IF_FAIL)
#define ULE128_OR_RET_FALSE(out) WRAP_ULE128(out, RET_FALSE_IF_FAIL)
#define SLE128_OR_RET_FALSE(out) WRAP_SLE128(out, RET_FALSE_IF_FAIL)

#define U8_OR_GOTO(out, label)     WRAP_VA_U8(out, GOTO_IF_FAIL, label)
#define U_OR_GOTO(X, out, label)   WRAP_VA_U(X, out, GOTO_IF_FAIL, label)
#define UX_OR_GOTO(X, out, label)  WRAP_VA_UX(X, out, GOTO_IF_FAIL, label)
#define ULE128_OR_GOTO(out, label) WRAP_VA_ULE128(out, GOTO_IF_FAIL, label)
#define SLE128_OR_GOTO(out, label) WRAP_VA_SLE128(out, GOTO_IF_FAIL, label)

#define U_ADDR_SIZE_OR_RET_FALSE(out) WRAP_UX(encoding->address_size, out, RET_FALSE_IF_FAIL)
