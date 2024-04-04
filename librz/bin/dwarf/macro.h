// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define MEM_ZERO(T, x)       rz_mem_memzero((x), sizeof(T))
#define MEM_CPY(T, dst, src) rz_mem_copy((dst), sizeof(T), (src), sizeof(T))

#define OK_OR(x, E) \
	if (!(x)) { \
		E; \
	}

#define OK_OR_ERR(x, E) \
	if (!(x)) { \
		E; \
		goto err; \
	}

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

#define READ8_OR(T, out, E)       READ_OR(ut8, T, out, R_read8(R, &temp), E)
#define READS8_OR(T, out, E)      READ_OR(ut8, st8, out, R_read8(R, &temp), E)
#define READ24_OR(T, out, E)      READ_OR(ut32, T, out, R_read24(R, &temp), E)
#define READ_T_OR(bit, T, out, E) READ_OR(ut##bit, T, out, R_read##bit(R, &temp), E)
#define READ_UT_OR(bit, out, E)   READ_OR(ut##bit, ut##bit, out, R_read##bit(R, &temp), E)
#define ULE128_OR(T, out, E)      READ_OR(ut64, T, out, R_read_ule128(R, &temp), E)
#define SLE128_OR(T, out, E)      READ_OR(st64, T, out, R_read_sle128(R, &temp), E)

#define U8_OR_RET_FALSE(out)     READ8_OR(ut8, out, return false)
#define U_OR_RET_FALSE(X, out)   READ_UT_OR(X, out, return false)
#define ULE128_OR_RET_FALSE(out) ULE128_OR(ut64, out, return false)
#define SLE128_OR_RET_FALSE(out) SLE128_OR(st64, out, return false)

#define U8_OR_GOTO(out, label)     READ8_OR(ut8, out, goto label)
#define U_OR_GOTO(X, out, label)   READ_UT_OR(X, out, goto label)
#define ULE128_OR_GOTO(out, label) ULE128_OR(ut64, out, goto label)
#define SLE128_OR_GOTO(out, label) SLE128_OR(st64, out, goto label)

#define Ht_FREE_IMPL(V, T, f) \
	static void Ht##V##_##T##_free(Ht##V##Kv *kv, RZ_UNUSED void *user) { \
		f(kv->value); \
	}

#define RZ_VECTOR_FINI_T(T, f) \
	static void RzVector_##T##_fini(void *v, void *u) { \
		f(v); \
	}
