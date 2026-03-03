// SPDX-FileCopyrightText: 2012 Samuel Neves <sneves@dei.uc.pt>
// SPDX-License-Identifier: CC0

#ifndef BLAKE2_IMPL_H
#define BLAKE2_IMPL_H

#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util/rz_mem.h>

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define BLAKE2_INLINE __inline
  #elif defined(__GNUC__)
    #define BLAKE2_INLINE __inline__
  #else
    #define BLAKE2_INLINE
  #endif
#else
  #define BLAKE2_INLINE inline
#endif

/* Static assert compatibility */
#if defined(_MSC_VER) && !defined(__cplusplus)
  #define BLAKE2_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
  #define BLAKE2_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum {
  BLAKE2S_BLOCKBYTES    = 64,
  BLAKE2S_OUTBYTES      = 32,
  BLAKE2S_KEYBYTES      = 32,
  BLAKE2S_SALTBYTES     = 8,
  BLAKE2S_PERSONALBYTES = 8
} blake2s_constant;

typedef enum {
  BLAKE2B_BLOCKBYTES    = 128,
  BLAKE2B_OUTBYTES      = 64,
  BLAKE2B_KEYBYTES      = 64,
  BLAKE2B_SALTBYTES     = 16,
  BLAKE2B_PERSONALBYTES = 16
} blake2b_constant;

typedef struct {
  ut32   h[8];
  ut32   t[2];
  ut32   f[2];
  ut8    buf[BLAKE2S_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
  ut8    last_node;
} blake2s_state;

typedef struct {
  ut64   h[8];
  ut64   t[2];
  ut64   f[2];
  ut8    buf[BLAKE2B_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
  ut8    last_node;
} blake2b_state;

typedef struct {
  blake2s_state S[8][1];
  blake2s_state R[1];
  ut8           buf[8 * BLAKE2S_BLOCKBYTES];
  size_t        buflen;
  size_t        outlen;
} blake2sp_state;

typedef struct {
  blake2b_state S[4][1];
  blake2b_state R[1];
  ut8           buf[4 * BLAKE2B_BLOCKBYTES];
  size_t        buflen;
  size_t        outlen;
} blake2bp_state;

RZ_PACKED(struct blake2s_param_ {
  ut8  digest_length;
  ut8  key_length;
  ut8  fanout;
  ut8  depth;
  ut32 leaf_length;
  ut32 node_offset;
  ut16 xof_length;
  ut8  node_depth;
  ut8  inner_length;
  /* ut8 reserved[0]; */
  ut8  salt[BLAKE2S_SALTBYTES];
  ut8  personal[BLAKE2S_PERSONALBYTES];
});
typedef struct blake2s_param_ blake2s_param;

RZ_PACKED(struct blake2b_param_ {
  ut8  digest_length;
  ut8  key_length;
  ut8  fanout;
  ut8  depth;
  ut32 leaf_length;
  ut32 node_offset;
  ut32 xof_length;
  ut8  node_depth;
  ut8  inner_length;
  ut8  reserved[14];
  ut8  salt[BLAKE2B_SALTBYTES];
  ut8  personal[BLAKE2B_PERSONALBYTES];
});
typedef struct blake2b_param_ blake2b_param;

typedef struct {
  blake2s_state S[1];
  blake2s_param P[1];
} blake2xs_state;

typedef struct {
  blake2b_state S[1];
  blake2b_param P[1];
} blake2xb_state;

BLAKE2_STATIC_ASSERT(sizeof(blake2s_param) == BLAKE2S_OUTBYTES, "blake2s_param must be exactly 32 bytes (padded struct detected)");
BLAKE2_STATIC_ASSERT(sizeof(blake2b_param) == BLAKE2B_OUTBYTES, "blake2b_param must be exactly 64 bytes (padded struct detected)");

/* Streaming API */

int blake2s_init(blake2s_state *S, size_t outlen);
int blake2s_init_key(blake2s_state *S, size_t outlen, const void *key, size_t keylen);
int blake2s_init_param(blake2s_state *S, const blake2s_param *P);
int blake2s_update(blake2s_state *S, const void *in, size_t inlen);
int blake2s_final(blake2s_state *S, void *out, size_t outlen);

int blake2b_init(blake2b_state *S, size_t outlen);
int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen);
int blake2b_init_param(blake2b_state *S, const blake2b_param *P);
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

int blake2sp_init(blake2sp_state *S, size_t outlen);
int blake2sp_init_key(blake2sp_state *S, size_t outlen, const void *key, size_t keylen);
int blake2sp_update(blake2sp_state *S, const void *in, size_t inlen);
int blake2sp_final(blake2sp_state *S, void *out, size_t outlen);

int blake2bp_init(blake2bp_state *S, size_t outlen);
int blake2bp_init_key(blake2bp_state *S, size_t outlen, const void *key, size_t keylen);
int blake2bp_update(blake2bp_state *S, const void *in, size_t inlen);
int blake2bp_final(blake2bp_state *S, void *out, size_t outlen);

int blake2xs_init(blake2xs_state *S, size_t outlen);
int blake2xs_init_key(blake2xs_state *S, size_t outlen, const void *key, size_t keylen);
int blake2xs_update(blake2xs_state *S, const void *in, size_t inlen);
int blake2xs_final(blake2xs_state *S, void *out, size_t outlen);

int blake2xb_init(blake2xb_state *S, size_t outlen);
int blake2xb_init_key(blake2xb_state *S, size_t outlen, const void *key, size_t keylen);
int blake2xb_update(blake2xb_state *S, const void *in, size_t inlen);
int blake2xb_final(blake2xb_state *S, void *out, size_t outlen);

/* Simple API */

int blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2sp(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2bp(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2xs(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2xb(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);
int blake2(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen);

static BLAKE2_INLINE ut16 load16(const void *src) {
  return rz_read_le16(src);
}

static BLAKE2_INLINE ut32 load32(const void *src) {
  return rz_read_le32(src);
}

static BLAKE2_INLINE ut64 load64(const void *src) {
  return rz_read_le64(src);
}

static BLAKE2_INLINE void store16(void *dst, ut16 w) {
  rz_write_le16(dst, w);
}

static BLAKE2_INLINE void store32(void *dst, ut32 w) {
  rz_write_le32(dst, w);
}

static BLAKE2_INLINE void store64(void *dst, ut64 w) {
  rz_write_le64(dst, w);
}

static BLAKE2_INLINE ut64 load48(const void *src) {
  const ut8 *p = (const ut8 *)src;
  return ((ut64)p[0]      ) |
         ((ut64)p[1] <<  8) |
         ((ut64)p[2] << 16) |
         ((ut64)p[3] << 24) |
         ((ut64)p[4] << 32) |
         ((ut64)p[5] << 40);
}

static BLAKE2_INLINE void store48(void *dst, ut64 w) {
  ut8 *p = (ut8 *)dst;
  p[0] = (ut8)(w      );
  p[1] = (ut8)(w >>  8);
  p[2] = (ut8)(w >> 16);
  p[3] = (ut8)(w >> 24);
  p[4] = (ut8)(w >> 32);
  p[5] = (ut8)(w >> 40);
}

static BLAKE2_INLINE ut32 rotr32(const ut32 w, const unsigned c) {
  return (w >> c) | (w << (32u - (c & 31u)));
}

static BLAKE2_INLINE ut64 rotr64(const ut64 w, const unsigned c) {
  return (w >> c) | (w << (64u - (c & 63u)));
}

static BLAKE2_INLINE void secure_zero_memory(void *v, size_t n) {
  rz_mem_memzero(v, n);
}

#if defined(__cplusplus)
}
#endif

#endif /* BLAKE2_IMPL_H */