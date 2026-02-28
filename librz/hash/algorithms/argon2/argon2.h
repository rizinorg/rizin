// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef ARGON2_H
#define ARGON2_H

#include <rz_types.h>
#include <rz_util.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* Symbols visibility control */
#ifdef A2_VISCTL
#define ARGON2_PUBLIC __attribute__((visibility("default")))
#define ARGON2_LOCAL  __attribute__((visibility("hidden")))
#elif defined(_MSC_VER)
#define ARGON2_PUBLIC __declspec(dllexport)
#define ARGON2_LOCAL
#else
#define ARGON2_PUBLIC
#define ARGON2_LOCAL
#endif

/*
 * Argon2 input parameter restrictions
 */

/* Minimum and maximum number of lanes (degree of parallelism) */
#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)

/* Minimum and maximum number of threads */
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)

/* Number of synchronization points between lanes per pass */
#define ARGON2_SYNC_POINTS UINT32_C(4)

/* Minimum and maximum digest size in bytes */
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)

/* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS) /* 2 blocks per slice */

#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
/* Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
#define ARGON2_MAX_MEMORY_BITS \
	ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2_MAX_MEMORY \
	ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)

/* Minimum and maximum number of passes */
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)

/* Minimum and maximum password length in bytes */
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum associated data length in bytes */
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum salt length in bytes */
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)

/* Minimum and maximum key length in bytes */
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)

/* Flags to determine which fields are securely wiped (default = no wipe). */
#define ARGON2_DEFAULT_FLAGS       UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET   (UINT32_C(1) << 1)

/* Global flag to determine if we are wiping internal memory buffers. This flag
 * is defined in argon2.c and defaults to 1 (wipe internal memory).
 */
extern int FLAG_clear_internal_memory;

/* Argon2 error codes */
typedef enum {
	ARGON2_OK = 0,
	ARGON2_OUTPUT_PTR_NULL = -1,
	ARGON2_OUTPUT_TOO_SHORT = -2,
	ARGON2_OUTPUT_TOO_LONG = -3,
	ARGON2_PWD_TOO_SHORT = -4,
	ARGON2_PWD_TOO_LONG = -5,
	ARGON2_SALT_TOO_SHORT = -6,
	ARGON2_SALT_TOO_LONG = -7,
	ARGON2_AD_TOO_SHORT = -8,
	ARGON2_AD_TOO_LONG = -9,
	ARGON2_SECRET_TOO_SHORT = -10,
	ARGON2_SECRET_TOO_LONG = -11,
	ARGON2_TIME_TOO_SMALL = -12,
	ARGON2_TIME_TOO_LARGE = -13,
	ARGON2_MEMORY_TOO_LITTLE = -14,
	ARGON2_MEMORY_TOO_MUCH = -15,
	ARGON2_LANES_TOO_FEW = -16,
	ARGON2_LANES_TOO_MANY = -17,
	ARGON2_PWD_PTR_MISMATCH = -18, /* NULL pointer with non-zero length */
	ARGON2_SALT_PTR_MISMATCH = -19, /* NULL pointer with non-zero length */
	ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL pointer with non-zero length */
	ARGON2_AD_PTR_MISMATCH = -21, /* NULL pointer with non-zero length */
	ARGON2_MEMORY_ALLOCATION_ERROR = -22,
	ARGON2_FREE_MEMORY_CBK_NULL = -23,
	ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,
	ARGON2_INCORRECT_PARAMETER = -25,
	ARGON2_INCORRECT_TYPE = -26,
	ARGON2_OUT_PTR_MISMATCH = -27,
	ARGON2_THREADS_TOO_FEW = -28,
	ARGON2_THREADS_TOO_MANY = -29,
	ARGON2_MISSING_ARGS = -30,
	ARGON2_ENCODING_FAIL = -31,
	ARGON2_DECODING_FAIL = -32,
	ARGON2_THREAD_FAIL = -33,
	ARGON2_DECODING_LENGTH_FAIL = -34,
	ARGON2_VERIFY_MISMATCH = -35
} argon2_error_codes;

typedef enum {
	ARGON2_BLOCK_SIZE = 1024,
	ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8,
	ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16,
	ARGON2_HWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 32,
	ARGON2_512BIT_WORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 64,
	ARGON2_ADDRESSES_IN_BLOCK = 128,
	ARGON2_PREHASH_DIGEST_LENGTH = 64,
	ARGON2_PREHASH_SEED_LENGTH = 72
} argon2_core_constants;

/* Argon2 variants — declared early so structs below can reference it */
typedef enum {
	Argon2_d = 0,
	Argon2_i = 1,
	Argon2_id = 2
} argon2_type;

/* Supported versions */
typedef enum {
	ARGON2_VERSION_10 = 0x10,
	ARGON2_VERSION_13 = 0x13,
	ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
} argon2_version;

/*
 * Structure for the (1KB) memory block implemented as 128 64-bit words.
 * Memory blocks can be copied, XORed. Internal words can be accessed by []
 * (no bounds checking).
 */
typedef struct block_ {
	ut64 v[ARGON2_QWORDS_IN_BLOCK];
} block;

/* Initialize each byte of the block with @in */
void init_block_value(block *b, ut8 in);

/* Copy block @src to block @dst */
void copy_block(block *dst, const block *src);

/* XOR @src onto @dst bytewise */
void xor_block(block *dst, const block *src);

/* External memory allocator callbacks */
typedef int (*allocate_fptr)(ut8 **memory, size_t size);
typedef void (*deallocate_fptr)(ut8 *memory, size_t size);

/* Argon2 execution context */
typedef struct {
	ut8 *out; /* output array */
	ut32 outlen; /* digest length */

	ut8 *pwd; /* password array */
	ut32 pwdlen; /* password length */

	ut8 *salt; /* salt array */
	ut32 saltlen; /* salt length */

	ut8 *secret; /* key array */
	ut32 secretlen; /* key length */

	ut8 *ad; /* associated data array */
	ut32 adlen; /* associated data length */

	ut32 t_cost; /* number of passes */
	ut32 m_cost; /* amount of memory requested (KB) */
	ut32 lanes; /* number of lanes */
	ut32 threads; /* maximum number of threads */

	ut32 version; /* version number */

	allocate_fptr allocate_cbk; /* pointer to memory allocator */
	deallocate_fptr free_cbk; /* pointer to memory deallocator */

	ut32 flags; /* array of bool options */
} argon2_context;

typedef struct {
	block *memory; /* Memory pointer */
	ut32 version;
	ut32 passes; /* Number of passes */
	ut32 memory_blocks; /* Number of blocks in memory */
	ut32 segment_length;
	ut32 lane_length;
	ut32 lanes;
	ut32 threads;
	argon2_type type;
	argon2_context *context_ptr; /* Points back to original context */
} argon2_instance_t;

typedef struct {
	ut32 pass;
	ut32 lane;
	ut8 slice;
	ut32 index;
} argon2_position_t;

typedef struct {
	argon2_instance_t *instance_ptr;
	argon2_position_t pos;
} argon2_thread_data;

/* Convert argon2_type to string (returns NULL if type is invalid) */
const char *argon2_type2string(argon2_type type, int uppercase);

/* Core Argon2 function using a context structure */
int argon2_ctx(argon2_context *context, argon2_type type);

/**
 * Argon2 password hashing API (Argon2i, Argon2d, Argon2id).
 *
 * These functions compute a password hash using the given parameters.
 * They can produce:
 *   - an encoded string (for storage), or
 *   - a raw binary hash.
 *
 * PARAMETERS
 *
 * @param t_cost        Number of iterations (time cost).
 * @param m_cost        Memory usage in kibibytes (KiB).
 * @param parallelism   Number of lanes/threads.
 * @param pwd           Pointer to the password buffer (not null-terminated).
 * @param pwdlen        Password length in bytes.
 * @param salt          Pointer to the salt buffer.
 * @param saltlen       Salt length in bytes.
 * @param hash          Output buffer for raw binary hash (*_hash_raw variants).
 * @param hashlen       Desired length of the hash in bytes.
 * @param encoded       Output buffer for encoded hash string (*_hash_encoded variants).
 * @param encodedlen    Size of the encoded output buffer.
 * @param type          Argon2 variant — used only in argon2_hash().
 * @param version       Argon2 version  — used only in argon2_hash().
 *
 * RETURN VALUE
 *
 *     Returns ARGON2_OK on success, otherwise a negative error code.
 */

/* Argon2i */
int argon2i_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen);

int argon2i_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen);

/* Argon2d */
int argon2d_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen);

int argon2d_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen);

/* Argon2id */
int argon2id_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen);

int argon2id_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen);

/* Generic */
int argon2_hash(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen,
	char *encoded, size_t encodedlen,
	argon2_type type, ut32 version);

/**
 * Verifies a password against an encoded string.
 * Returns ARGON2_OK on match, ARGON2_VERIFY_MISMATCH on failure.
 */
int argon2i_verify(const char *encoded, const void *pwd, size_t pwdlen);
int argon2d_verify(const char *encoded, const void *pwd, size_t pwdlen);
int argon2id_verify(const char *encoded, const void *pwd, size_t pwdlen);
int argon2_verify(const char *encoded, const void *pwd, size_t pwdlen, argon2_type type);

/**
 * Executes the Argon2 algorithm based on the chosen variant.
 * @param  context  Pointer to the Argon2 context containing parameters and buffers.
 * @return ARGON2_OK on success, a non-zero error code otherwise.
 */
int argon2d_ctx(argon2_context *context);
int argon2i_ctx(argon2_context *context);
int argon2id_ctx(argon2_context *context);

/**
 * Verify a password hash directly via context for a specific Argon2 variant.
 * Use argon2_verify_ctx() for a generic interface where type is passed as argument.
 */
int argon2d_verify_ctx(argon2_context *context, const char *hash);
int argon2i_verify_ctx(argon2_context *context, const char *hash);
int argon2id_verify_ctx(argon2_context *context, const char *hash);
int argon2_verify_ctx(argon2_context *context, const char *hash, argon2_type type);

/* Returns a human-readable string for the given Argon2 error code. */
const char *argon2_error_message(int error_code);

/**
 * Returns the encoded hash length for the given input parameters.
 * @param t_cost      Number of iterations
 * @param m_cost      Memory usage in kibibytes
 * @param parallelism Number of threads / lanes
 * @param saltlen     Salt size in bytes
 * @param hashlen     Hash size in bytes
 * @param type        The argon2_type to compute the encoded length for
 * @return            The encoded hash length in bytes
 */
size_t argon2_encodedlen(ut32 t_cost, ut32 m_cost, ut32 parallelism, ut32 saltlen, ut32 hashlen, argon2_type type);

/* Allocates num * size bytes using the allocator from context.
 * Returns ARGON2_OK on success.
 */
int allocate_memory(const argon2_context *context, ut8 **memory, size_t num, size_t size);

/* Frees num * size bytes using context's deallocator.
 * Securely wipes memory before freeing.
 */
void free_memory(const argon2_context *context, ut8 *memory, size_t num, size_t size);

/* Wipes memory only if the clear flag is enabled. */
void clear_internal_memory(void *v, size_t n);

/* Computes the index of the reference block using
 * a pseudo-random value and lane rules.
 */
ut32 index_alpha(const argon2_instance_t *instance, const argon2_position_t *position, ut32 pseudo_rand, int same_lane);

/* Validates all parameters in the context.
 * Returns ARGON2_OK if valid.
 */
int validate_inputs(const argon2_context *context);

/* Hashes all inputs into blockhash. */
void initial_hash(ut8 *blockhash, argon2_context *context, argon2_type type);

/* Initializes the first two blocks in each lane. */
void fill_first_blocks(ut8 *blockhash, const argon2_instance_t *instance);

/* Allocates memory, hashes inputs, and initializes the first blocks.
 * Returns ARGON2_OK on success.
 */
int initialize(argon2_instance_t *instance, argon2_context *context);

/* Combines final blocks from all lanes, produces the output hash,
 * and frees memory.
 */
void finalize(const argon2_context *context, argon2_instance_t *instance);

/* Fills one segment of memory using previous blocks (possibly from other lanes). */
void fill_segment(const argon2_instance_t *instance, argon2_position_t position);

/* Repeatedly fills all memory blocks for the configured number of passes. */
int fill_memory_blocks(argon2_instance_t *instance);

#if defined(__cplusplus)
}
#endif

#endif /* ARGON2_H */