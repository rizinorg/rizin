#ifndef RZ_HASH_H
#define RZ_HASH_H

#include "rz_types.h"
#include "rz_util/rz_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_hash);

#if HAVE_LIB_SSL
#include <openssl/sha.h>
#include <openssl/md5.h>
typedef MD5_CTX RZ_MD5_CTX;
typedef SHA_CTX RZ_SHA_CTX;
typedef SHA256_CTX RZ_SHA256_CTX;
typedef SHA512_CTX RZ_SHA384_CTX;
typedef SHA512_CTX RZ_SHA512_CTX;
#define SHA256_BLOCK_LENGTH SHA256_CBLOCK
#define SHA384_BLOCK_LENGTH SHA384_CBLOCK
#define SHA512_BLOCK_LENGTH SHA512_CBLOCK
#else
#define MD5_CTX RZ_MD5_CTX

/* hashing */
typedef struct {
	ut32 state[4];
	ut32 count[2];
	ut8 buffer[64];
} RZ_MD5_CTX;

typedef struct {
	ut32 H[5];
	ut32 W[80];
	int lenW;
	ut32 sizeHi, sizeLo;
} RZ_SHA_CTX;

#define SHA256_BLOCK_LENGTH 64
typedef struct _SHA256_CTX {
	ut32 state[8];
	ut64 bitcount;
	ut8 buffer[SHA256_BLOCK_LENGTH];
} RZ_SHA256_CTX;

#define SHA384_BLOCK_LENGTH 128
#define SHA512_BLOCK_LENGTH 128
typedef struct _SHA512_CTX {
	ut64 state[8];
	ut64 bitcount[2];
	ut8 buffer[SHA512_BLOCK_LENGTH];
} RZ_SHA512_CTX;
typedef RZ_SHA512_CTX RZ_SHA384_CTX;
#endif

/*
 * Since we have not enough space in bitmask, you may do fine
 * selection of required hash functions by the followed macros.
 *
 * TODO: subject to place in config
 */
//#define RZ_HAVE_CRC8_EXTRA 1
#define RZ_HAVE_CRC15_EXTRA 1
//#define RZ_HAVE_CRC16_EXTRA 1
#define RZ_HAVE_CRC24       1
#define RZ_HAVE_CRC32_EXTRA 1
#define RZ_HAVE_CRC64       1
#define RZ_HAVE_CRC64_EXTRA 1

/* select CRC-digest intergal holder */
#if RZ_HAVE_CRC64 || RZ_HAVE_CRC64_EXTRA
typedef ut64 utcrc;
#define PFMTCRCx PFMT64x
#else
typedef ut32 utcrc;
#define PFMTCRCx PFMT32x
#endif
#define UTCRC_C(x) ((utcrc)(x))

RZ_API ut8 rz_hash_fletcher8(const ut8 *d, size_t length);
RZ_API ut16 rz_hash_fletcher16(const ut8 *data, size_t len);
RZ_API ut32 rz_hash_fletcher32(const ut8 *data, size_t len);
RZ_API ut64 rz_hash_fletcher64(const ut8 *addr, size_t len);

typedef struct {
	utcrc crc;
	ut32 size;
	int reflect;
	utcrc poly;
	utcrc xout;
} RZ_CRC_CTX;

enum CRC_PRESETS {
	CRC_PRESET_8_SMBUS = 0,
#if RZ_HAVE_CRC8_EXTRA
	CRC_PRESET_CRC8_CDMA2000,
	CRC_PRESET_CRC8_DARC,
	CRC_PRESET_CRC8_DVB_S2,
	CRC_PRESET_CRC8_EBU,
	CRC_PRESET_CRC8_ICODE,
	CRC_PRESET_CRC8_ITU,
	CRC_PRESET_CRC8_MAXIM,
	CRC_PRESET_CRC8_ROHC,
	CRC_PRESET_CRC8_WCDMA,
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
	CRC_PRESET_15_CAN,
#endif /* RZ_HAVCE_CRC15_EXTRA */

	CRC_PRESET_16,
	CRC_PRESET_16_CITT,
	CRC_PRESET_16_USB,
	CRC_PRESET_16_HDLC,
#if RZ_HAVE_CRC16_EXTRA
	CRC_PRESET_CRC16_AUG_CCITT,
	CRC_PRESET_CRC16_BUYPASS,
	CRC_PRESET_CRC16_CDMA2000,
	CRC_PRESET_CRC16_DDS110,
	CRC_PRESET_CRC16_DECT_R,
	CRC_PRESET_CRC16_DECT_X,
	CRC_PRESET_CRC16_DNP,
	CRC_PRESET_CRC16_EN13757,
	CRC_PRESET_CRC16_GENIBUS,
	CRC_PRESET_CRC16_MAXIM,
	CRC_PRESET_CRC16_MCRF4XX,
	CRC_PRESET_CRC16_RIELLO,
	CRC_PRESET_CRC16_T10_DIF,
	CRC_PRESET_CRC16_TELEDISK,
	CRC_PRESET_CRC16_TMS37157,
	CRC_PRESET_CRCA,
	CRC_PRESET_CRC16_KERMIT,
	CRC_PRESET_CRC16_MODBUS,
	CRC_PRESET_CRC16_X25,
	CRC_PRESET_CRC16_XMODEM,
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
	CRC_PRESET_24,
#endif /* #if RZ_HAVE_CRC24 */

	CRC_PRESET_32,
	CRC_PRESET_32_ECMA_267,
	CRC_PRESET_32C,
#if RZ_HAVE_CRC32_EXTRA
	CRC_PRESET_CRC32_BZIP2,
	CRC_PRESET_CRC32D,
	CRC_PRESET_CRC32_MPEG2,
	CRC_PRESET_CRC32_POSIX,
	CRC_PRESET_CRC32Q,
	CRC_PRESET_CRC32_JAMCRC,
	CRC_PRESET_CRC32_XFER,
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
	CRC_PRESET_CRC64,
#endif /* RZ_HAVE_CRC64 */

#if RZ_HAVE_CRC64_EXTRA
	CRC_PRESET_CRC64_ECMA182,
	CRC_PRESET_CRC64_WE,
	CRC_PRESET_CRC64_XZ,
	CRC_PRESET_CRC64_ISO,
#endif /* #if RZ_HAVE_CRC64_EXTRA */

	CRC_PRESET_SIZE
};

/* Fix names conflict with ruby bindings */
#define RzHash struct rz_hash_t

struct rz_hash_t {
	RZ_MD5_CTX md5;
	RZ_SHA_CTX sha1;
	RZ_SHA256_CTX sha256;
	RZ_SHA384_CTX sha384;
	RZ_SHA512_CTX sha512;
	bool rst;
	double entropy;
	ut8 RZ_ALIGNED(8) digest[128];
};

typedef struct rz_hash_seed_t {
	int prefix;
	ut8 *buf;
	int len;
} RzHashSeed;

#define RZ_HASH_SIZE_CRC8_SMBUS 1
#if RZ_HAVE_CRC8_EXTRA
#define RZ_HASH_SIZE_CRC8_CDMA2000 1
#define RZ_HASH_SIZE_CRC8_DARC     1
#define RZ_HASH_SIZE_CRC8_DVB_S2   1
#define RZ_HASH_SIZE_CRC8_EBU      1
#define RZ_HASH_SIZE_CRC8_ICODE    1
#define RZ_HASH_SIZE_CRC8_ITU      1
#define RZ_HASH_SIZE_CRC8_MAXIM    1
#define RZ_HASH_SIZE_CRC8_ROHC     1
#define RZ_HASH_SIZE_CRC8_WCDMA    1
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
#define RZ_HASH_SIZE_CRC15_CAN 2
#endif /* #if RZ_HAVE_CRC15_EXTRA */

#define RZ_HASH_SIZE_CRC16      2
#define RZ_HASH_SIZE_CRC16_HDLC 2
#define RZ_HASH_SIZE_CRC16_USB  2
#define RZ_HASH_SIZE_CRC16_CITT 2
#if RZ_HAVE_CRC16_EXTRA
#define RZ_HASH_SIZE_CRC16_AUG_CCITT 2
#define RZ_HASH_SIZE_CRC16_BUYPASS   2
#define RZ_HASH_SIZE_CRC16_CDMA2000  2
#define RZ_HASH_SIZE_CRC16_DDS110    2
#define RZ_HASH_SIZE_CRC16_DECT_R    2
#define RZ_HASH_SIZE_CRC16_DECT_X    2
#define RZ_HASH_SIZE_CRC16_DNP       2
#define RZ_HASH_SIZE_CRC16_EN13757   2
#define RZ_HASH_SIZE_CRC16_GENIBUS   2
#define RZ_HASH_SIZE_CRC16_MAXIM     2
#define RZ_HASH_SIZE_CRC16_MCRF4XX   2
#define RZ_HASH_SIZE_CRC16_RIELLO    2
#define RZ_HASH_SIZE_CRC16_T10_DIF   2
#define RZ_HASH_SIZE_CRC16_TELEDISK  2
#define RZ_HASH_SIZE_CRC16_TMS37157  2
#define RZ_HASH_SIZE_CRCA            2
#define RZ_HASH_SIZE_CRC16_KERMIT    2
#define RZ_HASH_SIZE_CRC16_MODBUS    2
#define RZ_HASH_SIZE_CRC16_X25       2
#define RZ_HASH_SIZE_CRC16_XMODEM    2
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
#define RZ_HASH_SIZE_CRC24 3
#endif /* #if RZ_HAVE_CRC24 */

#define RZ_HASH_SIZE_CRC32          4
#define RZ_HASH_SIZE_CRC32C         4
#define RZ_HASH_SIZE_CRC32_ECMA_267 4
#if RZ_HAVE_CRC32_EXTRA
#define RZ_HASH_SIZE_CRC32_BZIP2  4
#define RZ_HASH_SIZE_CRC32D       4
#define RZ_HASH_SIZE_CRC32_MPEG2  4
#define RZ_HASH_SIZE_CRC32_POSIX  4
#define RZ_HASH_SIZE_CRC32Q       4
#define RZ_HASH_SIZE_CRC32_JAMCRC 4
#define RZ_HASH_SIZE_CRC32_XFER   4
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
#define RZ_HASH_SIZE_CRC64 8
#endif /* #if RZ_HAVE_CRC64 */
#if RZ_HAVE_CRC64_EXTRA
#define RZ_HASH_SIZE_CRC64_ECMA182 8
#define RZ_HASH_SIZE_CRC64_WE      8
#define RZ_HASH_SIZE_CRC64_XZ      8
#define RZ_HASH_SIZE_CRC64_ISO     8
#endif /* #if RZ_HAVE_CRC64_EXTRA */

#define RZ_HASH_SIZE_XXHASH  4
#define RZ_HASH_SIZE_MD4     16
#define RZ_HASH_SIZE_MD5     16
#define RZ_HASH_SIZE_SHA1    20
#define RZ_HASH_SIZE_SHA256  32
#define RZ_HASH_SIZE_SHA384  48
#define RZ_HASH_SIZE_SHA512  64
#define RZ_HASH_SIZE_ADLER32 4
/* entropy is double !! size 0 for test in rz_hash_to_string */
#define RZ_HASH_SIZE_ENTROPY    0
#define RZ_HASH_SIZE_PCPRINT    1
#define RZ_HASH_SIZE_MOD255     1
#define RZ_HASH_SIZE_PARITY     1
#define RZ_HASH_SIZE_XOR        1
#define RZ_HASH_SIZE_XORPAIR    2
#define RZ_HASH_SIZE_HAMDIST    1
#define RZ_HASH_SIZE_LUHN       1
#define RZ_HASH_SIZE_FLETCHER8  1
#define RZ_HASH_SIZE_FLETCHER16 2
#define RZ_HASH_SIZE_FLETCHER32 4
#define RZ_HASH_SIZE_FLETCHER64 8

#define RZ_HASH_NBITS (8 * sizeof(ut64))

enum HASH_INDICES {
	RZ_HASH_IDX_MD5 = 0,
	RZ_HASH_IDX_SHA1,
	RZ_HASH_IDX_SHA256,
	RZ_HASH_IDX_SHA384,
	RZ_HASH_IDX_SHA512,
	RZ_HASH_IDX_MD4,
	RZ_HASH_IDX_XOR,
	RZ_HASH_IDX_XORPAIR,
	RZ_HASH_IDX_PARITY,
	RZ_HASH_IDX_ENTROPY,
	RZ_HASH_IDX_HAMDIST,
	RZ_HASH_IDX_PCPRINT,
	RZ_HASH_IDX_MOD255,
	RZ_HASH_IDX_XXHASH,
	RZ_HASH_IDX_ADLER32,
	RZ_HASH_IDX_BASE64,
	RZ_HASH_IDX_BASE91,
	RZ_HASH_IDX_PUNYCODE,
	RZ_HASH_IDX_LUHN,

	RZ_HASH_IDX_CRC8_SMBUS,
#if RZ_HAVE_CRC8_EXTRA
	RZ_HASH_IDX_CRC8_CDMA2000,
	RZ_HASH_IDX_CRC8_DARC,
	RZ_HASH_IDX_CRC8_DVB_S2,
	RZ_HASH_IDX_CRC8_EBU,
	RZ_HASH_IDX_CRC8_ICODE,
	RZ_HASH_IDX_CRC8_ITU,
	RZ_HASH_IDX_CRC8_MAXIM,
	RZ_HASH_IDX_CRC8_ROHC,
	RZ_HASH_IDX_CRC8_WCDMA,
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
	RZ_HASH_IDX_CRC15_CAN,
#endif /* #if RZ_HAVE_CRC15_EXTRA */

	RZ_HASH_IDX_CRC16,
	RZ_HASH_IDX_CRC16_HDLC,
	RZ_HASH_IDX_CRC16_USB,
	RZ_HASH_IDX_CRC16_CITT,
#if RZ_HAVE_CRC16_EXTRA
	RZ_HASH_IDX_CRC16_AUG_CCITT,
	RZ_HASH_IDX_CRC16_BUYPASS,
	RZ_HASH_IDX_CRC16_CDMA2000,
	RZ_HASH_IDX_CRC16_DDS110,
	RZ_HASH_IDX_CRC16_DECT_R,
	RZ_HASH_IDX_CRC16_DECT_X,
	RZ_HASH_IDX_CRC16_DNP,
	RZ_HASH_IDX_CRC16_EN13757,
	RZ_HASH_IDX_CRC16_GENIBUS,
	RZ_HASH_IDX_CRC16_MAXIM,
	RZ_HASH_IDX_CRC16_MCRF4XX,
	RZ_HASH_IDX_CRC16_RIELLO,
	RZ_HASH_IDX_CRC16_T10_DIF,
	RZ_HASH_IDX_CRC16_TELEDISK,
	RZ_HASH_IDX_CRC16_TMS37157,
	RZ_HASH_IDX_CRCA,
	RZ_HASH_IDX_CRC16_KERMIT,
	RZ_HASH_IDX_CRC16_MODBUS,
	RZ_HASH_IDX_CRC16_X25,
	RZ_HASH_IDX_CRC16_XMODEM,
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
	RZ_HASH_IDX_CRC24,
#endif /* #if RZ_HAVE_CRC24 */

	RZ_HASH_IDX_CRC32,
	RZ_HASH_IDX_CRC32C,
	RZ_HASH_IDX_CRC32_ECMA_267,
#if RZ_HAVE_CRC32_EXTRA
	RZ_HASH_IDX_CRC32_BZIP2,
	RZ_HASH_IDX_CRC32D,
	RZ_HASH_IDX_CRC32_MPEG2,
	RZ_HASH_IDX_CRC32_POSIX,
	RZ_HASH_IDX_CRC32Q,
	RZ_HASH_IDX_CRC32_JAMCRC,
	RZ_HASH_IDX_CRC32_XFER,
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
	RZ_HASH_IDX_CRC64,
#endif /* #if RZ_HAVE_CRC64 */
#if RZ_HAVE_CRC64_EXTRA
	RZ_HASH_IDX_CRC64_ECMA182,
	RZ_HASH_IDX_CRC64_WE,
	RZ_HASH_IDX_CRC64_XZ,
	RZ_HASH_IDX_CRC64_ISO,
#endif /* #if RZ_HAVE_CRC64_EXTRA */

	RZ_HASH_IDX_FLETCHER8,
	RZ_HASH_IDX_FLETCHER16,
	RZ_HASH_IDX_FLETCHER32,
	RZ_HASH_IDX_FLETCHER64,
	RZ_HASH_NUM_INDICES
};

#define RZ_HASH_NONE       0
#define RZ_HASH_MD5        (1ULL << RZ_HASH_IDX_MD5)
#define RZ_HASH_SHA1       (1ULL << RZ_HASH_IDX_SHA1)
#define RZ_HASH_SHA256     (1ULL << RZ_HASH_IDX_SHA256)
#define RZ_HASH_SHA384     (1ULL << RZ_HASH_IDX_SHA384)
#define RZ_HASH_SHA512     (1ULL << RZ_HASH_IDX_SHA512)
#define RZ_HASH_MD4        (1ULL << RZ_HASH_IDX_MD4)
#define RZ_HASH_XOR        (1ULL << RZ_HASH_IDX_XOR)
#define RZ_HASH_XORPAIR    (1ULL << RZ_HASH_IDX_XORPAIR)
#define RZ_HASH_PARITY     (1ULL << RZ_HASH_IDX_PARITY)
#define RZ_HASH_ENTROPY    (1ULL << RZ_HASH_IDX_ENTROPY)
#define RZ_HASH_HAMDIST    (1ULL << RZ_HASH_IDX_HAMDIST)
#define RZ_HASH_PCPRINT    (1ULL << RZ_HASH_IDX_PCPRINT)
#define RZ_HASH_MOD255     (1ULL << RZ_HASH_IDX_MOD255)
#define RZ_HASH_XXHASH     (1ULL << RZ_HASH_IDX_XXHASH)
#define RZ_HASH_ADLER32    (1ULL << RZ_HASH_IDX_ADLER32)
#define RZ_HASH_BASE64     (1ULL << RZ_HASH_IDX_BASE64)
#define RZ_HASH_BASE91     (1ULL << RZ_HASH_IDX_BASE91)
#define RZ_HASH_PUNYCODE   (1ULL << RZ_HASH_IDX_PUNYCODE)
#define RZ_HASH_LUHN       (1ULL << RZ_HASH_IDX_LUHN)
#define RZ_HASH_FLETCHER8  (1ULL << RZ_HASH_IDX_FLETCHER8)
#define RZ_HASH_FLETCHER16 (1ULL << RZ_HASH_IDX_FLETCHER16)
#define RZ_HASH_FLETCHER32 (1ULL << RZ_HASH_IDX_FLETCHER32)
#define RZ_HASH_FLETCHER64 (1ULL << RZ_HASH_IDX_FLETCHER64)

#define RZ_HASH_CRC8_SMBUS (1ULL << RZ_HASH_IDX_CRC8_SMBUS)
#if RZ_HAVE_CRC8_EXTRA
#define RZ_HASH_CRC8_CDMA2000 (1ULL << RZ_HASH_IDX_CRC8_CDMA2000)
#define RZ_HASH_CRC8_DARC     (1ULL << RZ_HASH_IDX_CRC8_DARC)
#define RZ_HASH_CRC8_DVB_S2   (1ULL << RZ_HASH_IDX_CRC8_DVB_S2)
#define RZ_HASH_CRC8_EBU      (1ULL << RZ_HASH_IDX_CRC8_EBU)
#define RZ_HASH_CRC8_ICODE    (1ULL << RZ_HASH_IDX_CRC8_ICODE)
#define RZ_HASH_CRC8_ITU      (1ULL << RZ_HASH_IDX_CRC8_ITU)
#define RZ_HASH_CRC8_MAXIM    (1ULL << RZ_HASH_IDX_CRC8_MAXIM)
#define RZ_HASH_CRC8_ROHC     (1ULL << RZ_HASH_IDX_CRC8_ROHC)
#define RZ_HASH_CRC8_WCDMA    (1ULL << RZ_HASH_IDX_CRC8_WCDMA)
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
#define RZ_HASH_CRC15_CAN (1ULL << RZ_HASH_IDX_CRC15_CAN)
#endif /* #if RZ_HAVE_CRC15_EXTRA */

#define RZ_HASH_CRC16      (1ULL << RZ_HASH_IDX_CRC16)
#define RZ_HASH_CRC16_HDLC (1ULL << RZ_HASH_IDX_CRC16_HDLC)
#define RZ_HASH_CRC16_USB  (1ULL << RZ_HASH_IDX_CRC16_USB)
#define RZ_HASH_CRC16_CITT (1ULL << RZ_HASH_IDX_CRC16_CITT)
#if RZ_HAVE_CRC16_EXTRA
#define RZ_HASH_CRC16_AUG_CCITT (1ULL << RZ_HASH_IDX_CRC16_AUG_CCITT)
#define RZ_HASH_CRC16_BUYPASS   (1ULL << RZ_HASH_IDX_CRC16_BUYPASS)
#define RZ_HASH_CRC16_CDMA2000  (1ULL << RZ_HASH_IDX_CRC16_CDMA2000)
#define RZ_HASH_CRC16_DDS110    (1ULL << RZ_HASH_IDX_CRC16_DDS110)
#define RZ_HASH_CRC16_DECT_R    (1ULL << RZ_HASH_IDX_CRC16_DECT_R)
#define RZ_HASH_CRC16_DECT_X    (1ULL << RZ_HASH_IDX_CRC16_DECT_X)
#define RZ_HASH_CRC16_DNP       (1ULL << RZ_HASH_IDX_CRC16_DNP)
#define RZ_HASH_CRC16_EN13757   (1ULL << RZ_HASH_IDX_CRC16_EN13757)
#define RZ_HASH_CRC16_GENIBUS   (1ULL << RZ_HASH_IDX_CRC16_GENIBUS)
#define RZ_HASH_CRC16_MAXIM     (1ULL << RZ_HASH_IDX_CRC16_MAXIM)
#define RZ_HASH_CRC16_MCRF4XX   (1ULL << RZ_HASH_IDX_CRC16_MCRF4XX)
#define RZ_HASH_CRC16_RIELLO    (1ULL << RZ_HASH_IDX_CRC16_RIELLO)
#define RZ_HASH_CRC16_T10_DIF   (1ULL << RZ_HASH_IDX_CRC16_T10_DIF)
#define RZ_HASH_CRC16_TELEDISK  (1ULL << RZ_HASH_IDX_CRC16_TELEDISK)
#define RZ_HASH_CRC16_TMS37157  (1ULL << RZ_HASH_IDX_CRC16_TMS37157)
#define RZ_HASH_CRCA            (1ULL << RZ_HASH_IDX_CRCA)
#define RZ_HASH_CRC16_KERMIT    (1ULL << RZ_HASH_IDX_CRC16_KERMIT)
#define RZ_HASH_CRC16_MODBUS    (1ULL << RZ_HASH_IDX_CRC16_MODBUS)
#define RZ_HASH_CRC16_X25       (1ULL << RZ_HASH_IDX_CRC16_X25)
#define RZ_HASH_CRC16_XMODEM    (1ULL << RZ_HASH_IDX_CRC16_XMODEM)
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
#define RZ_HASH_CRC24 (1ULL << RZ_HASH_IDX_CRC24)
#endif /* #if RZ_HAVE_CRC24 */

#define RZ_HASH_CRC32          (1ULL << RZ_HASH_IDX_CRC32)
#define RZ_HASH_CRC32C         (1ULL << RZ_HASH_IDX_CRC32C)
#define RZ_HASH_CRC32_ECMA_267 (1ULL << RZ_HASH_IDX_CRC32_ECMA_267)
#if RZ_HAVE_CRC32_EXTRA
#define RZ_HASH_CRC32_BZIP2  (1ULL << RZ_HASH_IDX_CRC32_BZIP2)
#define RZ_HASH_CRC32D       (1ULL << RZ_HASH_IDX_CRC32D)
#define RZ_HASH_CRC32_MPEG2  (1ULL << RZ_HASH_IDX_CRC32_MPEG2)
#define RZ_HASH_CRC32_POSIX  (1ULL << RZ_HASH_IDX_CRC32_POSIX)
#define RZ_HASH_CRC32Q       (1ULL << RZ_HASH_IDX_CRC32Q)
#define RZ_HASH_CRC32_JAMCRC (1ULL << RZ_HASH_IDX_CRC32_JAMCRC)
#define RZ_HASH_CRC32_XFER   (1ULL << RZ_HASH_IDX_CRC32_XFER)
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
#define RZ_HASH_CRC64 (1ULL << RZ_HASH_IDX_CRC64)
#endif /* #if RZ_HAVE_CRC64 */
#if RZ_HAVE_CRC64_EXTRA
#define RZ_HASH_CRC64_ECMA182 (1ULL << RZ_HASH_IDX_CRC64_ECMA182)
#define RZ_HASH_CRC64_WE      (1ULL << RZ_HASH_IDX_CRC64_WE)
#define RZ_HASH_CRC64_XZ      (1ULL << RZ_HASH_IDX_CRC64_XZ)
#define RZ_HASH_CRC64_ISO     (1ULL << RZ_HASH_IDX_CRC64_ISO)
#endif /* #if RZ_HAVE_CRC64 */

#define RZ_HASH_ALL ((1ULL << RZ_MIN(63, RZ_HASH_NUM_INDICES)) - 1)

#ifdef RZ_API
/* OO */
RZ_API RzHash *rz_hash_new(bool rst, ut64 flags);
RZ_API void rz_hash_free(RzHash *ctx);

/* methods */
RZ_API ut8 *rz_hash_do_md4(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_md5(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_sha1(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_sha256(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_sha384(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_sha512(RzHash *ctx, const ut8 *input, int len);
RZ_API ut8 *rz_hash_do_hmac_sha256(RzHash *ctx, const ut8 *input, int len, const ut8 *key, int klen);

RZ_API char *rz_hash_to_string(RzHash *ctx, const char *name, const ut8 *data, int len);

/* static methods */
RZ_API const char *rz_hash_name(ut64 bit);
RZ_API ut64 rz_hash_name_to_bits(const char *name);
RZ_API int rz_hash_size(ut64 bit);
RZ_API int rz_hash_calculate(RzHash *ctx, ut64 algobit, const ut8 *input, int len);

/* checksums */
/* XXX : crc16 should use 0 as arg0 by default */
/* static methods */
RZ_API ut8 rz_hash_deviation(const ut8 *b, ut64 len);
RZ_API ut32 rz_hash_adler32(const ut8 *buf, int len);
RZ_API ut32 rz_hash_xxhash(const ut8 *buf, ut64 len);
RZ_API ut8 rz_hash_xor(const ut8 *b, ut64 len);
RZ_API ut16 rz_hash_xorpair(const ut8 *a, ut64 len);
RZ_API int rz_hash_parity(const ut8 *buf, ut64 len);
RZ_API ut8 rz_hash_mod255(const ut8 *b, ut64 len);
RZ_API ut64 rz_hash_luhn(const ut8 *buf, ut64 len);
RZ_API utcrc rz_hash_crc_preset(const ut8 *data, ut32 size, enum CRC_PRESETS preset);

/* analysis */
RZ_API ut8 rz_hash_hamdist(const ut8 *buf, int len);
RZ_API double rz_hash_entropy(const ut8 *data, ut64 len);
RZ_API double rz_hash_entropy_fraction(const ut8 *data, ut64 len);
RZ_API int rz_hash_pcprint(const ut8 *buffer, ut64 len);

/* lifecycle */
RZ_API void rz_hash_do_begin(RzHash *ctx, ut64 flags);
RZ_API void rz_hash_do_end(RzHash *ctx, ut64 flags);
RZ_API void rz_hash_do_spice(RzHash *ctx, ut64 algo, int loops, RzHashSeed *seed);
#endif

#ifdef __cplusplus
}
#endif

#endif
