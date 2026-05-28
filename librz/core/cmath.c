// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Core-aware front end to the RzNum expression evaluator.
 *
 * Stitches rz_num_math_value_ex() (in librz_util) to RzCore's
 * context:
 *
 *   - the per-core num callback that resolves flags / special
 *     variables is already wired up in core.c, so passing core->num
 *     through covers identifier resolution;
 *   - an IO-read callback backs the `:le32` / `:be64` / `:N`
 *     typed-address dereference syntax, reading through core->io;
 *   - a registry of core-specific functions (hash / crc / entropy /
 *     temperature) is supplied, backed by RzHash and RzIO.
 *
 * The registry and the IO callback are passed to the evaluator
 * through RzNumMathOptions; librz_util has no compile-time knowledge
 * of RzIO or RzHash.
 */

#include <rz_core.h>
#include <rz_hash.h>
#include <rz_util/rz_num.h>

// --- IO-read callback for typed-address dereference -----------------

// Raw-bytes reader backing RzNum's typed-address syntax (and shareable
// verbatim with rz_pf's RzPfReadAtCb, which has the same signature -
// see <rz_pf.h>). All byte assembly, endian swap, sign-extension and
// IEEE-754 decoding live in the evaluator; this callback just hands
// back the requested bytes from RzIO.
static int core_io_read(void *user, ut64 addr, ut8 *buf, int len) {
	RzCore *core = (RzCore *)user;
	if (!core || !core->io || len < 1) {
		return 0;
	}
	return rz_io_nread_at(core->io, addr, buf, len);
}

// --- sha256(addr, len): hash len bytes at addr ----------------------

// Read up to 64 KiB at addr into a freshly-allocated buffer. Returns
// NULL (and leaves *out failed) on any problem. The 64 KiB bound
// keeps a stray expression from asking the core to slurp gigabytes.
static ut8 *core_read_block(RzCore *core, ut64 addr, ut64 len) {
	if (!core || !core->io || len == 0 || len > 0x10000) {
		return NULL;
	}
	ut8 *buf = malloc(len);
	if (!buf) {
		return NULL;
	}
	if (rz_io_nread_at(core->io, addr, buf, len) < 1) {
		free(buf);
		return NULL;
	}
	return buf;
}

// Turn a big-endian byte buffer into an RzNumValue: a bignum when it
// exceeds 8 bytes, otherwise a plain ut64. Consumes nothing; the
// caller still owns `digest`.
static void bytes_to_result(const ut8 *digest, ut32 n, RzNumCallbackResult *out) {
	if (n == 0) {
		out->ok = false;
		return;
	}
	if (n <= 8) {
		ut64 v = 0;
		for (ut32 i = 0; i < n; i++) {
			v = (v << 8) | digest[i];
		}
		out->ok = true;
		out->kind = RZ_NUM_KIND_UT64;
		out->val.n = v;
		return;
	}
	RzNumBig *big = rz_big_new();
	RzNumBig *shift = rz_big_new();
	RzNumBig *byte = rz_big_new();
	if (!big || !shift || !byte) {
		rz_big_free(big);
		rz_big_free(shift);
		rz_big_free(byte);
		out->ok = false;
		return;
	}
	rz_big_from_int(big, 0);
	rz_big_from_int(shift, 256);
	for (ut32 i = 0; i < n; i++) {
		RzNumBig *tmp = rz_big_new();
		if (!tmp) {
			rz_big_free(big);
			rz_big_free(shift);
			rz_big_free(byte);
			out->ok = false;
			return;
		}
		rz_big_mul(tmp, big, shift);
		rz_big_from_int(byte, digest[i]);
		rz_big_add(big, tmp, byte);
		rz_big_free(tmp);
	}
	rz_big_free(shift);
	rz_big_free(byte);
	out->ok = true;
	out->kind = RZ_NUM_KIND_BIG;
	out->val.big = big;
}

// Generic "hash bytes with the named algorithm" worker shared by all
// the digest-family functions. argc must be 2 (addr, len).
static void core_hash_named(RzCore *core, const char *algo,
	const RzNumValue *args, int argc, RzNumCallbackResult *out) {
	out->ok = false;
	if (!core || !core->hash || argc != 2) {
		return;
	}
	ut64 addr = args[0].val.n;
	ut64 len = args[1].val.n;
	ut8 *buf = core_read_block(core, addr, len);
	if (!buf) {
		return;
	}
	RzHashSize digest_size = 0;
	ut8 *digest = rz_hash_cfg_calculate_small_block(core->hash, algo,
		buf, len, &digest_size);
	free(buf);
	if (!digest || digest_size == 0) {
		free(digest);
		return;
	}
	bytes_to_result(digest, digest_size, out);
	free(digest);
}

// One thin trampoline per digest family. The algorithm name is the
// fixed string each passes to core_hash_named().
#define DIGEST_FN(fnname, algo) \
	static void fnname(void *user, const RzNumValue *args, int argc, RzNumCallbackResult *out) { \
		core_hash_named((RzCore *)user, algo, args, argc, out); \
	}

DIGEST_FN(core_fn_md5, "md5")
DIGEST_FN(core_fn_sha1, "sha1")
DIGEST_FN(core_fn_sha256, "sha256")
DIGEST_FN(core_fn_sha384, "sha384")
DIGEST_FN(core_fn_sha512, "sha512")
DIGEST_FN(core_fn_crc32, "crc32")
DIGEST_FN(core_fn_crc16, "crc16")
DIGEST_FN(core_fn_crc8, "crc8smbus")
DIGEST_FN(core_fn_crc64, "crc64")
DIGEST_FN(core_fn_adler32, "adler32")
DIGEST_FN(core_fn_xxhash, "xxhash32")

// crc(addr, len [, width]) -> CRC of the given width (8/16/32/64),
// defaulting to CRC-32. The optional third argument is the
// requested CRC width in bits; this is the "optional parameter for
// the exact algorithm" rather than separate crc8/crc16/... names.
static void core_fn_crc(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	out->ok = false;
	if (argc != 2 && argc != 3) {
		return;
	}
	const char *algo = "crc32";
	if (argc == 3) {
		switch (args[2].val.n) {
		case 8: algo = "crc8smbus"; break;
		case 16: algo = "crc16"; break;
		case 32: algo = "crc32"; break;
		case 64: algo = "crc64"; break;
		default: return; // unsupported width
		}
	}
	core_hash_named((RzCore *)user, algo, args, 2, out);
}

// hash(addr, len) is an alias for sha256 - a sensible default digest.
static void core_fn_hash(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	core_hash_named((RzCore *)user, "sha256", args, argc, out);
}

// entropy(addr, len) and temperature(addr, len) return doubles.
static void core_fn_entropy(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	RzCore *core = (RzCore *)user;
	out->ok = false;
	if (argc != 2) {
		return;
	}
	ut8 *buf = core_read_block(core, args[0].val.n, args[1].val.n);
	if (!buf) {
		return;
	}
	double e = rz_hash_entropy(buf, args[1].val.n);
	free(buf);
	out->ok = true;
	out->kind = RZ_NUM_KIND_FLOAT;
	out->val.d = e;
}

static void core_fn_temperature(void *user, const RzNumValue *args, int argc,
	RzNumCallbackResult *out) {
	RzCore *core = (RzCore *)user;
	out->ok = false;
	if (argc != 2) {
		return;
	}
	ut8 *buf = core_read_block(core, args[0].val.n, args[1].val.n);
	if (!buf) {
		return;
	}
	double t = rz_hash_temperature(buf, args[1].val.n);
	free(buf);
	out->ok = true;
	out->kind = RZ_NUM_KIND_FLOAT;
	out->val.d = t;
}

// Build the per-call function registry. Returns NULL if no functions
// could be registered (the caller treats that as "no extra
// functions", not as an error).
static RzNumFuncRegistry *core_build_registry(RzCore *core) {
	RzNumFuncRegistry *reg = rz_num_func_registry_new();
	if (!reg) {
		return NULL;
	}
	// Digest families: <fn>(addr, len) -> digest as bignum/ut64.
	rz_num_func_registry_add(reg, "md5", 2, core_fn_md5, core);
	rz_num_func_registry_add(reg, "sha1", 2, core_fn_sha1, core);
	rz_num_func_registry_add(reg, "sha256", 2, core_fn_sha256, core);
	rz_num_func_registry_add(reg, "sha384", 2, core_fn_sha384, core);
	rz_num_func_registry_add(reg, "sha512", 2, core_fn_sha512, core);
	rz_num_func_registry_add(reg, "adler32", 2, core_fn_adler32, core);
	rz_num_func_registry_add(reg, "xxhash", 2, core_fn_xxhash, core);
	rz_num_func_registry_add(reg, "hash", 2, core_fn_hash, core);
	// CRC: unified crc(addr, len [, width]); the family aliases stay
	// available for callers who prefer the explicit name.
	rz_num_func_registry_add(reg, "crc", -1, core_fn_crc, core);
	rz_num_func_registry_add(reg, "crc8", 2, core_fn_crc8, core);
	rz_num_func_registry_add(reg, "crc16", 2, core_fn_crc16, core);
	rz_num_func_registry_add(reg, "crc32", 2, core_fn_crc32, core);
	rz_num_func_registry_add(reg, "crc64", 2, core_fn_crc64, core);
	// Statistical measures: <fn>(addr, len) -> float.
	rz_num_func_registry_add(reg, "entropy", 2, core_fn_entropy, core);
	rz_num_func_registry_add(reg, "temperature", 2, core_fn_temperature, core);
	return reg;
}

/**
 * \brief Context-aware expression evaluator built on rz_num_math_value_ex().
 *
 * Resolves identifiers against the current core (flags, the special
 * variables $$, $$$, $b, $B, $F, ..., built-in and unicode-aliased
 * math functions) and evaluates bignum / float / bit-vector arithmetic.
 * The address-typed suffix (`0x1000:le32`) is read through core->io.
 *
 * \param core      Core whose context (flags, offset, block size,
 *                  core->num callback) backs the evaluation. Must be non-NULL.
 * \param expr      Expression to evaluate. Must be non-NULL.
 * \param options   Optional options (timeout). NULL selects defaults.
 * \param out_value Out-parameter receiving the value; finalise it with
 *                  rz_num_value_fini() when done. Must be non-NULL.
 * \param error_msg Optional out-pointer for a caller-owned diagnostic.
 * \return true on success, false on parse or evaluation error.
 */
RZ_API bool rz_core_math(RZ_NONNULL RzCore *core, RZ_NONNULL const char *expr,
	RZ_NULLABLE const RzCoreMathOptions *options,
	RZ_OUT RZ_NONNULL RzNumValue *out_value,
	RZ_OUT RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(core && expr && out_value, false);

	RzNumFuncRegistry *reg = core_build_registry(core);
	// `x = expr` bindings persist for the life of the core via a store
	// hung off core->num, created on first use, freed in rz_num_free().
	if (core->num && !core->num->expr_vars) {
		core->num->expr_vars = rz_num_value_store_new();
	}
	RzNumMathOptions opt = {
		.timeout_ms = options ? options->timeout_ms : 0,
		.funcs = reg,
		.io_read = core_io_read,
		.io_read_user = core,
		.vars = core->num ? core->num->expr_vars : NULL,
	};

	bool ok = rz_num_math_value_ex(core->num, expr, &opt, out_value, error_msg);
	rz_num_func_registry_free(reg);

	// Mirror the legacy num->value / num->fvalue so consumers reading
	// them observe the same state rz_num_math() would have left.
	if (ok && core->num) {
		core->num->value = rz_num_value_to_ut64(out_value);
		core->num->fvalue = rz_num_value_to_double(out_value);
	}
	return ok;
}

/**
 * \brief Convenience wrapper around rz_core_math() returning a ut64.
 *
 * Mirrors rz_num_math_ut64(): FLOAT truncates, BIG narrows to the low
 * 64 bits. Errors return 0 (core->num->dbz is still set on a trapped
 * divide-by-zero); the diagnostic is left for the caller to surface.
 *
 * \param core Core backing the evaluation. Must be non-NULL.
 * \param expr Expression to evaluate. Must be non-NULL.
 * \return The ut64 projection of the result, or 0 on error.
 */
RZ_API ut64 rz_core_math_ut64(RZ_NONNULL RzCore *core, RZ_NONNULL const char *expr) {
	rz_return_val_if_fail(core && expr, 0);
	RzNumValue v;
	rz_num_value_init(&v);
	char *err = NULL;
	if (!rz_core_math(core, expr, NULL, &v, &err)) {
		free(err);
		rz_num_value_fini(&v);
		return 0;
	}
	free(err);
	ut64 ret = rz_num_value_to_ut64(&v);
	rz_num_value_fini(&v);
	return ret;
}

/**
 * \brief Lift an expression to its RzIL pure-expression form in core context.
 *
 * Thin wrapper over rz_il_lift_num() supplying the core's function
 * registry and IO-read callback, so any function call, typed-address
 * dereference, or host variable is grounded to the same concrete value
 * the % command would compute. The result is a typed RzILOpPure tree; a
 * caller wanting the pLf text form passes it to
 * rz_il_op_pure_stringify_unicode().
 *
 * \param core      Core context. Must be non-NULL.
 * \param expr      Expression to lift. Must be non-NULL.
 * \param error_msg Optional out-pointer for a caller-owned diagnostic.
 * \return The lifted RzILOpPure (caller-owned), or NULL on error.
 */
RZ_API RZ_OWN RzILOpPure *rz_core_il_lift(RZ_NONNULL RzCore *core, RZ_NONNULL const char *expr,
	RZ_OUT RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(core && expr, NULL);
	RzNumFuncRegistry *reg = core_build_registry(core);
	RzNumMathOptions opt = {
		.funcs = reg,
		.io_read = core_io_read,
		.io_read_user = core,
	};
	RzILOpPure *out = rz_il_lift_num(core->num, expr, &opt, error_msg);
	rz_num_func_registry_free(reg);
	return out;
}
