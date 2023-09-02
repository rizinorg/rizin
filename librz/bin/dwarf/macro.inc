// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define MEM_ZERO(T, x)       rz_mem_memzero((x), sizeof(T))
#define MEM_CPY(T, dst, src) rz_mem_copy((dst), sizeof(T), (src), sizeof(T))

#define OK_None \
	do { \
		*out = NULL; \
		return true; \
	} while (0)

#define OK_OR(x, E) \
	do { \
		if (!(x)) { \
			E; \
		} \
	} while (0)

#define OK_OR_ERR(x, E) \
	do { \
		if (!(x)) { \
			E; \
			goto err; \
		} \
	} while (0)

#define AND_DO(x, E) \
	do { \
		if ((x)) { \
			E; \
		} \
	} while (0)

#define RET_FALSE_IF_FAIL(x)   OK_OR(x, return false)
#define RET_NULL_IF_FAIL(x)    OK_OR(x, return NULL)
#define GOTO_IF_FAIL(x, label) OK_OR(x, goto label)
#define ERR_IF_FAIL(x)         OK_OR(x, goto err)

#define READ_OR(TT, T, out, F, E) \
	do { \
		TT temp = { 0 }; \
		if (!F) { \
			E; \
		} \
		(out) = (T)temp; \
	} while (0)

#define READ8_OR(T, out, E)       READ_OR(ut8, T, out, rz_buf_read8(buffer, &temp), E)
#define READ_T_OR(bit, T, out, E) READ_OR(ut##bit, T, out, rz_buf_read_ble##bit(buffer, &temp, big_endian), E)
#define READ_UT_OR(bit, out, E)   READ_OR(ut##bit, ut##bit, out, rz_buf_read_ble##bit(buffer, &temp, big_endian), E)

#define ULE128_OR(T, out, E) READ_OR(ut64, T, out, (rz_buf_uleb128(buffer, &temp) > 0), E)
#define SLE128_OR(T, out, E) READ_OR(st64, T, out, (rz_buf_sleb128(buffer, &temp) > 0), E)

#define UX_OR(bit, out, E) \
	switch ((bit)) { \
	case 1: READ8_OR(ut8, out, E); break; \
	case 2: READ_UT_OR(16, out, E); break; \
	case 4: READ_UT_OR(32, out, E); break; \
	case 8: READ_UT_OR(64, out, E); break; \
	default: RZ_LOG_ERROR("DWARF: Unexpected pointer size: %u\n", (unsigned)(bit)); return false; \
	}

#define U8_OR_RET_FALSE(out)     READ8_OR(ut8, out, return false)
#define U_OR_RET_FALSE(X, out)   READ_UT_OR(X, out, return false)
#define UX_OR_RET_FALSE(X, out)  UX_OR(X, out, return false)
#define ULE128_OR_RET_FALSE(out) ULE128_OR(ut64, out, return false)
#define SLE128_OR_RET_FALSE(out) SLE128_OR(st64, out, return false)

#define U8_OR_GOTO(out, label)     READ8_OR(ut8, out, goto label)
#define U_OR_GOTO(X, out, label)   READ_UT_OR(X, out, goto label)
#define UX_OR_GOTO(X, out, label)  UX_OR(X, out, goto label)
#define ULE128_OR_GOTO(out, label) ULE128_OR(ut64, out, goto label)
#define SLE128_OR_GOTO(out, label) SLE128_OR(st64, out, goto label)

#define U_ADDR_SIZE_OR_RET_FALSE(out) UX_OR(encoding->address_size, out, return false)

#define Ht_FREE_IMPL(V, T, f) \
	static void Ht##V##_##T##_free(Ht##V##Kv *kv) { \
		f(kv->value); \
	}
