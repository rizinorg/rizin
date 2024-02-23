/** \internal
 * \file
 * \brief Utilities for values represented in various endian orders.
 */
#ifndef RZ_ENDIAN_H
#define RZ_ENDIAN_H

#include <rz_types.h>
#include <rz_userconf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Endian agnostic functions working on single byte. */

/**
 * \brief Read the first byte from \p src.
 * \param src The pointer from which a byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_ble8(const void *src) {
	if (!src) {
		return UT8_MAX;
	}
	return *(const ut8 *)src;
}

/**
 * \brief Read the first byte from \p src at \p offset.
 * \param src The pointer from which a byte is read.
 * \param offset The offset at which the byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_at_ble8(const void *src, size_t offset) {
	if (!src) {
		return UT8_MAX;
	}
	return rz_read_ble8(((const ut8 *)src) + offset);
}

/**
 * \brief Write a byte to \p dest.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 */
static inline void rz_write_ble8(void *dest, ut8 val) {
	*(ut8 *)dest = val;
}

/**
 * \brief Write a byte to \p dest at \p offset.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 * \param offset The offset at which the byte is written.
 */
static inline void rz_write_at_ble8(void *dest, ut8 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_ble8(d, val);
}

/* Big Endian functions. */

/**
 * \brief Read the first byte from \p src.
 * \param src The pointer from which a byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_be8(const void *src) {
	return rz_read_ble8(src);
}

/**
 * \brief Read the first byte from \p src at \p offset.
 * \param src The pointer from which a byte is read.
 * \param offset The offset at which the byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_at_be8(const void *src, size_t offset) {
	return rz_read_at_ble8(src, offset);
}

/**
 * \brief Write a byte to \p dest.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 */
static inline void rz_write_be8(void *dest, ut8 val) {
	rz_write_ble8(dest, val);
}

/**
 * \brief Write a byte to \p dest at \p offset.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 * \param offset The offset at which the byte is written.
 */
static inline void rz_write_at_be8(void *dest, ut8 val, size_t offset) {
	rz_write_at_ble8(dest, val, offset);
}

/**
 * \brief Read a 16-bit value from \p src in big-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_be16(const void *src) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut16)s[0]) << 8) | (((ut16)s[1]) << 0);
}

/**
 * \brief Read a 16-bit value from \p src at \p offset in big-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_at_be16(const void *src, size_t offset) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be16(s);
}

/**
 * \brief Write a 16-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 */
static inline void rz_write_be16(void *dest, ut16 val) {
	rz_write_be8(dest, val >> 8);
	rz_write_at_be8(dest, (ut8)val, sizeof(ut8));
}

/**
 * \brief Write a 16-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be16(void *dest, ut16 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be16(d, val);
}

/**
 * \brief Read a 24-bit value from \p src in big-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_be24(const void *src) {
	if (!src) {
		return UT32_MAX;
	}
	return rz_read_be8(src) << 16 | rz_read_be8((const ut8 *)src + 1) << 8 |
		rz_read_be8((const ut8 *)src + 2);
}

/**
 * \brief Read a 24-bit value from \p src at \p offset in big-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_be24(const void *src, size_t offset) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be24(s);
}

/**
 * \brief Write a 24-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 */
static inline void rz_write_be24(void *dest, ut32 val) {
	ut8 *_dest = (ut8 *)dest;
	rz_write_be8(_dest++, val >> 16);
	rz_write_be8(_dest++, val >> 8);
	rz_write_be8(_dest, val);
}

/**
 * \brief Write a 24-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be24(void *dest, ut32 val, size_t offset) {
	ut8 *_dest = (ut8 *)dest + offset;
	rz_write_be24(_dest, val);
}

/**
 * \brief Read a 32-bit value from \p src in big-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_be32(const void *src) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut32)s[0]) << 24) | (((ut32)s[1]) << 16) |
		(((ut32)s[2]) << 8) | (((ut32)s[3]) << 0);
}

/**
 * \brief Read a 32-bit value from \p src at \p offset in big-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_be32(const void *src, size_t offset) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be32(s);
}

/**
 * \brief Write a 32-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 */
static inline void rz_write_be32(void *dest, ut32 val) {
	rz_write_be16(dest, val >> 16);
	rz_write_at_be16(dest, val, sizeof(ut16));
}

/**
 * \brief Write a 32-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be32(void *dest, ut32 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be32(d, val);
}

/**
 * \brief Read a 64-bit value from \p src in big-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_be64(const void *src) {
	if (!src) {
		return UT64_MAX;
	}
	ut64 val = ((ut64)(rz_read_be32(src))) << 32;
	val |= rz_read_at_be32(src, sizeof(ut32));
	return val;
}

/**
 * \brief Read a 64-bit value from \p src at \p offset in big-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_at_be64(const void *src, size_t offset) {
	if (!src) {
		return UT64_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be64(s);
}

/**
 * \brief Write a 64-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 */
static inline void rz_write_be64(void *dest, ut64 val) {
	rz_write_be32(dest, val >> 32);
	rz_write_at_be32(dest, (ut32)val, sizeof(ut32));
}

/**
 * \brief Write a 64-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be64(void *dest, ut64 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be64(d, val);
}

/**
 * \brief Read a 128-bit value from \p src in big-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then the maximum 128-bit value is
 * returned.
 */
static inline ut128 rz_read_be128(const void *src) {
	ut128 val;
	if (!src) {
		val.High = UT64_MAX;
		val.Low = UT64_MAX;
		return val;
	}
	val.High = rz_read_be64(src);
	val.Low = rz_read_at_be64(src, sizeof(ut64));
	return val;
}

/**
 * \brief Read a 128-bit value from \p src at \p offset in big-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then the maximum 128-bit value is
 * returned.
 */
static inline ut128 rz_read_at_be128(const void *src, size_t offset) {
	if (!src) {
		ut128 val;
		val.High = UT64_MAX;
		val.Low = UT64_MAX;
		return val;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be128(s);
}

/**
 * \brief Write a 128-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 */
static inline void rz_write_be128(void *dest, ut128 val) {
	rz_write_be64(dest, val.High);
	rz_write_at_be64(dest, val.Low, sizeof(ut64));
}

/**
 * \brief Write a 128-bit value to \p dest in big-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be128(void *dest, ut128 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be128(d, val);
}

/**
 * \brief Interpret a 32-bit value read in big-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in big-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_be_float(const void *src) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.bits = rz_read_be32(src);
	return p.flt;
}

/**
 * \brief Interpret a 32-bit value read in big-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in big-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_at_be_float(const void *src, size_t offset) {
	if (!src) {
		return rz_read_be_float(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be_float(s);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in big-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_be_float(void *dest, float val) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.flt = val;
	rz_write_be32(dest, p.bits);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in big-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be_float(void *dest, float val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be_float(d, val);
}

/**
 * \brief Interpret a 64-bit value read in big-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in big-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_be_double(const void *src) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.bits = rz_read_be64(src);
	return p.dbl;
}

/**
 * \brief Interpret a 64-bit value read in big-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in big-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_at_be_double(const void *src, size_t offset) {
	if (!src) {
		return rz_read_be_double(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_be_double(s);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in big-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_be_double(void *dest, double val) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.dbl = val;
	rz_write_be64(dest, p.bits);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in big-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_be_double(void *dest, double val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_be_double(d, val);
}

/* Little Endian functions. */

/**
 * \brief Read the first byte from \p src.
 * \param src The pointer from which a byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_le8(const void *src) {
	return rz_read_ble8(src);
}

/**
 * \brief Read the first byte from \p src at \p offset.
 * \param src The pointer from which a byte is read.
 * \param offset The offset at which the byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_at_le8(const void *src, size_t offset) {
	return rz_read_at_ble8(src, offset);
}

/**
 * \brief Write a byte to \p dest.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 */
static inline void rz_write_le8(void *dest, ut8 val) {
	rz_write_ble8(dest, val);
}

/**
 * \brief Write a byte to \p dest at \p offset.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 * \param offset The offset at which the byte is written.
 */
static inline void rz_write_at_le8(void *dest, ut8 val, size_t offset) {
	rz_write_at_ble8(dest, val, offset);
}

/**
 * \brief Read a 16-bit value from \p src in little-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_le16(const void *src) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut16)s[1]) << 8) | (((ut16)s[0]) << 0);
}

/**
 * \brief Read a 16-bit value from \p src at \p offset in little-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_at_le16(const void *src, size_t offset) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_le16(s);
}

/**
 * \brief Write a 16-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 */
static inline void rz_write_le16(void *dest, ut16 val) {
	rz_write_le8(dest, (ut8)val);
	rz_write_at_le8(dest, val >> 8, sizeof(ut8));
}

/**
 * \brief Write a 16-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le16(void *dest, ut16 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_le16(d, val);
}

/**
 * \brief Read a 24-bit value from \p src in little-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_le24(const void *src) {
	if (!src) {
		return UT32_MAX;
	}
	return rz_read_at_le8(src, 0) | rz_read_at_le8(src, 1) << 8 |
		rz_read_at_le8(src, 2) << 16;
}

/**
 * \brief Read a 24-bit value from \p src at \p offset in little-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_le24(const void *src, size_t offset) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_le24(s);
}

/**
 * \brief Write a 24-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 */
static inline void rz_write_le24(void *dest, ut32 val) {
	ut8 *_dest = (ut8 *)dest;
	rz_write_le8(_dest++, val);
	rz_write_le8(_dest++, val >> 8);
	rz_write_le8(_dest, val >> 16);
}

/**
 * \brief Write a 24-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le24(void *dest, ut32 val, size_t offset) {
	ut8 *_dest = (ut8 *)dest + offset;
	rz_write_le24(_dest, val);
}

/**
 * \brief Read a 32-bit value from \p src in little-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_le32(const void *src) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut32)s[3]) << 24) | (((ut32)s[2]) << 16) |
		(((ut32)s[1]) << 8) | (((ut32)s[0]) << 0);
}

/**
 * \brief Read a 32-bit value from \p src at \p offset in little-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_le32(const void *src, size_t offset) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_le32(s);
}

/**
 * \brief Write a 32-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 */
static inline void rz_write_le32(void *dest, ut32 val) {
	rz_write_le16(dest, val);
	rz_write_at_le16(dest, val >> 16, sizeof(ut16));
}

/**
 * \brief Write a 32-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le32(void *dest, ut32 val, size_t offset) {
	ut8 *d = ((ut8 *)dest) + offset;
	rz_write_le32(d, val);
}

/**
 * \brief Read a 64-bit value from \p src in little-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_le64(const void *src) {
	if (!src) {
		return UT64_MAX;
	}
	ut64 val = ((ut64)(rz_read_at_le32(src, sizeof(ut32)))) << 32;
	val |= rz_read_le32(src);
	return val;
}

/**
 * \brief Read a 64-bit value from \p src at \p offset in little-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_at_le64(const void *src, size_t offset) {
	if (!src) {
		return UT64_MAX;
	}
	const ut8 *s = ((const ut8 *)src) + offset;
	return rz_read_le64(s);
}

/**
 * \brief Write a 64-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 */
static inline void rz_write_le64(void *dest, ut64 val) {
	rz_write_le32(dest, (ut32)val);
	rz_write_at_le32(dest, val >> 32, sizeof(ut32));
}

/**
 * \brief Write a 64-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le64(void *dest, ut64 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_le64(d, val);
}

/**
 * \brief Read a 128-bit value from \p src in little-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then the maximum 128-bit value is
 * returned.
 */
static inline ut128 rz_read_le128(const void *src) {
	ut128 val;
	if (!src) {
		val.High = UT64_MAX;
		val.Low = UT64_MAX;
		return val;
	}
	val.High = rz_read_at_le64(src, sizeof(ut64));
	val.Low = rz_read_le64(src);
	return val;
}

/**
 * \brief Read a 128-bit value from \p src at \p offset in little-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then the maximum 128-bit value is
 * returned.
 */
static inline ut128 rz_read_at_le128(const void *src, size_t offset) {
	if (!src) {
		ut128 val;
		val.High = UT64_MAX;
		val.Low = UT64_MAX;
		return val;
	}
	const ut8 *s = ((const ut8 *)src) + offset;
	return rz_read_le128(s);
}

/**
 * \brief Write a 128-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 */
static inline void rz_write_le128(void *dest, ut128 val) {
	rz_write_le64(dest, val.Low);
	rz_write_at_le64(dest, val.High, sizeof(ut64));
}

/**
 * \brief Write a 128-bit value to \p dest in little-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le128(void *dest, ut128 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_le128(d, val);
}

/**
 * \brief Interpret a 32-bit value read in little-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in little-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_le_float(const void *src) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.bits = rz_read_le32(src);
	return p.flt;
}

/**
 * \brief Interpret a 32-bit value read in little-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in little-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_at_le_float(const void *src, size_t offset) {
	if (!src) {
		return rz_read_le_float(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_le_float(s);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in little-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_le_float(void *dest, float val) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.flt = val;
	rz_write_le32(dest, p.bits);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in little-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le_float(void *dest, float val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_le_float(d, val);
}

/**
 * \brief Interpret a 64-bit value read in little-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in little-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_le_double(const void *src) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.bits = rz_read_le64(src);
	return p.dbl;
}

/**
 * \brief Interpret a 64-bit value read in little-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in little-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_at_le_double(const void *src, size_t offset) {
	if (!src) {
		return rz_read_le_double(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_le_double(s);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in little-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_le_double(void *dest, double val) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.dbl = val;
	rz_write_le64(dest, p.bits);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in little-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_le_double(void *dest, double val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_le_double(d, val);
}

/* Middle Endian functions. */

/**
 * \brief Read the first byte from \p src.
 * \param src The pointer from which a byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_me8(const void *src) {
	return rz_read_ble8(src);
}

/**
 * \brief Read the first byte from \p src at \p offset.
 * \param src The pointer from which a byte is read.
 * \param offset The offset at which the byte is read.
 * \return The read byte value.
 * \attention If \p src is \c NULL then \c UT8_MAX is returned.
 */
static inline ut8 rz_read_at_me8(const void *src, size_t offset) {
	return rz_read_at_ble8(src, offset);
}

/**
 * \brief Write a byte to \p dest.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 */
static inline void rz_write_me8(void *dest, ut8 val) {
	rz_write_ble8(dest, val);
}

/**
 * \brief Write a byte to \p dest at \p offset.
 * \param[out] dest The pointer to which a byte is written.
 * \param val The written byte value.
 * \param offset The offset at which the byte is written.
 */
static inline void rz_write_at_me8(void *dest, ut8 val, size_t offset) {
	rz_write_at_ble8(dest, val, offset);
}

/**
 * \brief Read a 16-bit value from \p src in middle-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_me16(const void *src) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut16)s[0]) << 8) | (((ut16)s[1]) << 0);
}

/**
 * \brief Read a 16-bit value from \p src at \p offset in middle-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_at_me16(const void *src, size_t offset) {
	if (!src) {
		return UT16_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_me16(s);
}

/**
 * \brief Write a 16-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 */
static inline void rz_write_me16(void *dest, ut16 val) {
	rz_write_me8(dest, val >> 8);
	rz_write_at_me8(dest, (ut8)val, sizeof(ut8));
}

/**
 * \brief Write a 16-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_me16(void *dest, ut16 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_me16(d, val);
}

/**
 * \brief Read a 32-bit value from \p src in middle-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_me32(const void *src) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src;
	return (((ut32)s[2]) << 24) | (((ut32)s[3]) << 16) |
		(((ut32)s[0]) << 8) | (((ut32)s[1]) << 0);
}

/**
 * \brief Read a 32-bit value from \p src at \p offset in middle-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_me32(const void *src, size_t offset) {
	if (!src) {
		return UT32_MAX;
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_me32(s);
}

/**
 * \brief Write a 32-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 */
static inline void rz_write_me32(void *dest, ut32 val) {
	rz_write_me16(dest, val);
	rz_write_at_me16(dest, val >> 16, sizeof(ut16));
}

/**
 * \brief Write a 32-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_me32(void *dest, ut32 val, size_t offset) {
	ut8 *d = ((ut8 *)dest) + offset;
	rz_write_me32(d, val);
}

/**
 * \brief Read a 64-bit value from \p src in middle-endian order.
 * \param src The pointer from which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_me64(const void *src) {
	if (!src) {
		return UT64_MAX;
	}
	ut64 val = ((ut64)(rz_read_at_me32(src, sizeof(ut32)))) << 32;
	val |= rz_read_me32(src);
	return val;
}

/**
 * \brief Read a 64-bit value from \p src at \p offset in middle-endian order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 */
static inline ut64 rz_read_at_me64(const void *src, size_t offset) {
	if (!src) {
		return UT64_MAX;
	}
	const ut8 *s = ((const ut8 *)src) + offset;
	return rz_read_me64(s);
}

/**
 * \brief Write a 64-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 */
static inline void rz_write_me64(void *dest, ut64 val) {
	rz_write_me32(dest, (ut32)val);
	rz_write_at_me32(dest, val >> 32, sizeof(ut32));
}

/**
 * \brief Write a 64-bit value to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_me64(void *dest, ut64 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_me64(d, val);
}

/**
 * \brief Interpret a 32-bit value read in middle-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in middle-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_me_float(const void *src) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.bits = rz_read_me32(src);
	return p.flt;
}

/**
 * \brief Interpret a 32-bit value read in middle-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in middle-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline float rz_read_at_me_float(const void *src, size_t offset) {
	if (!src) {
		return rz_read_me_float(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_me_float(s);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_me_float(void *dest, float val) {
	union {
		ut32 bits;
		float flt;
	} p;
	p.flt = val;
	rz_write_me32(dest, p.bits);
}

/**
 * \brief Write a 32-bit floating-point to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_me_float(void *dest, float val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_me_float(d, val);
}

/**
 * \brief Interpret a 64-bit value read in middle-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in middle-endian order from.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_me_double(const void *src) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.bits = rz_read_me64(src);
	return p.dbl;
}

/**
 * \brief Interpret a 64-bit value read in middle-endian order as floating-point.
 * \param src The buffer to read the unsigned integer in middle-endian order from.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 */
static inline double rz_read_at_me_double(const void *src, size_t offset) {
	if (!src) {
		return rz_read_me_double(NULL);
	}
	const ut8 *s = (const ut8 *)src + offset;
	return rz_read_me_double(s);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 */
static inline void rz_write_me_double(void *dest, double val) {
	union {
		ut64 bits;
		double dbl;
	} p;
	p.dbl = val;
	rz_write_me64(dest, p.bits);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in middle-endian order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param offset The offset at which the value is written.
 */
static inline void rz_write_at_me_double(void *dest, double val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	rz_write_me_double(d, val);
}

/* Helper functions */

/**
 * \brief Read a 16-bit value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 */
static inline ut16 rz_read_ble16(const void *src, bool big_endian) {
	return big_endian ? rz_read_be16(src) : rz_read_le16(src);
}

/**
 * \brief Read a 24-bit value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 */
static inline ut32 rz_read_ble24(const void *src, bool big_endian) {
	return big_endian ? rz_read_be24(src) : rz_read_le24(src);
}

/**
 * \brief Read a 32-bit value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 */
static inline ut32 rz_read_ble32(const void *src, bool big_endian) {
	return big_endian ? rz_read_be32(src) : rz_read_le32(src);
}

/**
 * \brief Read a 64-bit value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT64_MAX is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 */
static inline ut64 rz_read_ble64(const void *src, bool big_endian) {
	return big_endian ? rz_read_be64(src) : rz_read_le64(src);
}

/**
 * \brief Read a 128-bit value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then the maximum 128-bit value is
 * returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 */
static inline ut128 rz_read_ble128(const void *src, bool big_endian) {
	return big_endian ? rz_read_be128(src) : rz_read_le128(src);
}

/**
 * \brief Interpret a 32-bit value read in specified order as floating-point.
 * \param src The buffer to read the unsigned integer in specified order from.
 * \param big_endian The choice of endianness.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then a floating-point value in big-endian order is
 * read. Otherwise, if \p big_endian is \c false, an floating-point
 * value in little-endian order is read.
 */
static inline float rz_read_ble_float(const void *src, bool big_endian) {
	return big_endian ? rz_read_be_float(src) : rz_read_le_float(src);
}

/**
 * \brief Interpret a 64-bit value read in specified order as floating-point.
 * \param src The buffer to read the unsigned integer in specified order from.
 * \param big_endian The choice of endianness.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then a floating-point value in big-endian order is
 * read. Otherwise, if \p big_endian is \c false, an floating-point
 * value in little-endian order is read.
 */
static inline double rz_read_ble_double(const void *src, bool big_endian) {
	return big_endian ? rz_read_be_double(src) : rz_read_le_double(src);
}

/**
 * \brief Read a 16-bit value from \p src at \p offset in specified order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 16-bit value.
 * \attention If \p src is \c NULL then \c UT16_MAX is returned.
 */
static inline ut16 rz_read_at_ble16(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be16(src, offset) : rz_read_at_le16(src, offset);
}

/**
 * \brief Read a 24-bit value from \p src at \p offset in specified order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 24-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_ble24(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be24(src, offset) : rz_read_at_le24(src, offset);
}

/**
 * \brief Read a 32-bit value from \p src at \p offset in specified order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 32-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut32 rz_read_at_ble32(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be32(src, offset) : rz_read_at_le32(src, offset);
}

/**
 * \brief Read a 64-bit value from \p src at \p offset in specified order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 64-bit value.
 * \attention If \p src is \c NULL then \c UT32_MAX is returned.
 */
static inline ut64 rz_read_at_ble64(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be64(src, offset) : rz_read_at_le64(src, offset);
}

/**
 * \brief Read a 128-bit value from \p src at \p offset in specified order.
 * \param src The pointer from which the value is read.
 * \param offset The offset at which the value is read.
 * \param big_endian The choice of endianness.
 * \return The read 128-bit value.
 * \attention If \p src is \c NULL then \c UT128_MAX is returned.
 */
static inline ut128 rz_read_at_ble128(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be128(src, offset) : rz_read_at_le128(src, offset);
}

/**
 * \brief Interpret a 32-bit value read in specified order as floating-point.
 * \param src The buffer to read the unsigned integer in specified order from.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 32-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then a floating-point value in big-endian order is
 * read. Otherwise, if \p big_endian is \c false, an floating-point
 * value in little-endian order is read.
 */
static inline float rz_read_at_ble_float(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be_float(src, offset) : rz_read_at_le_float(src, offset);
}

/**
 * \brief Interpret a 64-bit value read in specified order as floating-point.
 * \param src The buffer to read the unsigned integer in specified order from.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is read.
 * \return The floating-point value with representation equal to that
 *  of the unsigned 64-bit value read from \p src.
 * \attention \c NaN payloads might not be preserved.
 * \attention If \p src is \c NULL then \c NaN is returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then a floating-point value in big-endian order is
 * read. Otherwise, if \p big_endian is \c false, an floating-point
 * value in little-endian order is read.
 */
static inline double rz_read_at_ble_double(const void *src, size_t offset, bool big_endian) {
	return big_endian ? rz_read_at_be_double(src, offset) : rz_read_at_le_double(src, offset);
}

/**
 * \brief Read an integer value from \p src in specified order.
 * \param src The pointer from which the value is read.
 * \param big_endian The choice of endianness.
 * \param size The size of the representation in bits.
 * \return The read integer value.
 * \retval UT64_MAX If the \p size parameter is not 8, 16, 32, or 64.
 * \attention If \p src is \c NULL and \p size is a valid size, the
 * appropriate maximum unsigned integer value for that size is
 * returned.
 *
 * The value is read according to \p big_endian. If \p big_endian is
 * \c true, then an integer in big-endian order is read. Otherwise, if
 * \p big_endian is \c false, an integer in little-endian order is
 * read.
 *
 * The number of bits read is according to \p size. The valid choices
 * are \c 8, \c 16, \c 32, or \c 64.
 */
static inline ut64 rz_read_ble(const void *src, bool big_endian, int size) {
	switch (size) {
	case 8:
		return rz_read_ble8(src);
	case 16:
		return rz_read_ble16(src, big_endian);
	case 32:
		return rz_read_ble32(src, big_endian);
	case 64:
		return rz_read_ble64(src, big_endian);
	default:
		return UT64_MAX;
	}
}

/**
 * \brief Write a 16-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_ble16(void *dest, ut16 val, bool big_endian) {
	big_endian ? rz_write_be16(dest, val) : rz_write_le16(dest, val);
}

/**
 * \brief Write a 24-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_ble24(void *dest, ut32 val, bool big_endian) {
	big_endian ? rz_write_be24(dest, val) : rz_write_le24(dest, val);
}

/**
 * \brief Write a 32-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_ble32(void *dest, ut32 val, bool big_endian) {
	big_endian ? rz_write_be32(dest, val) : rz_write_le32(dest, val);
}

/**
 * \brief Write a 64-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_ble64(void *dest, ut64 val, bool big_endian) {
	big_endian ? rz_write_be64(dest, val) : rz_write_le64(dest, val);
}

/**
 * \brief Write a 128-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_ble128(void *dest, ut128 val, bool big_endian) {
	big_endian ? rz_write_be128(dest, val) : rz_write_le128(dest, val);
}

/**
 * \brief Write an integer value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written integer value.
 * \param big_endian The choice of endianness.
 * \param size The size of the representation in bits.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 *
 * The number of bits written is according to \p size. The valid choices
 * are \c 8, \c 16, \c 32, or \c 64. No action is taken otherwise.
 */
static inline void rz_write_ble(void *dst, ut64 val, bool big_endian, int size) {
	switch (size) {
	case 8:
		((ut8 *)dst)[0] = (ut8)val;
		break;
	case 16:
		rz_write_ble16(dst, (ut16)val, big_endian);
		break;
	case 24:
		rz_write_ble24(dst, (ut32)val, big_endian);
		break;
	case 32:
		rz_write_ble32(dst, (ut32)val, big_endian);
		break;
	case 64:
		rz_write_ble64(dst, val, big_endian);
		break;
	default:
		break;
	}
}

/**
 * \brief Write a 32-bit floating-point to \p dest in specified order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then a floating-point value in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, a floating-point
 * value in little-endian order is written.
 */
static inline void rz_write_ble_float(void *src, float val, bool big_endian) {
	big_endian ? rz_write_be_float(src, val) : rz_write_le_float(src, val);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in specified order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param big_endian The choice of endianness.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then a floating-point value in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, a floating-point
 * value in little-endian order is written.
 */
static inline void rz_write_ble_double(void *src, double val, bool big_endian) {
	big_endian ? rz_write_be_double(src, val) : rz_write_le_double(src, val);
}

/**
 * \brief Write a 16-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 16-bit value.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_at_ble16(void *dest, ut16 val, bool big_endian, size_t offset) {
	if (big_endian) {
		rz_write_at_be16(dest, val, offset);
	} else {
		rz_write_at_le16(dest, val, offset);
	}
}

/**
 * \brief Write a 24-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 24-bit value.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_at_ble24(void *dest, ut32 val, bool big_endian, size_t offset) {
	if (big_endian) {
		rz_write_at_be24(dest, val, offset);
	} else {
		rz_write_at_le24(dest, val, offset);
	}
}

/**
 * \brief Write a 32-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 32-bit value.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_at_ble32(void *dest, ut32 val, bool big_endian, size_t offset) {
	if (big_endian) {
		rz_write_at_be32(dest, val, offset);
	} else {
		rz_write_at_le32(dest, val, offset);
	}
}

/**
 * \brief Write a 64-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 64-bit value.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_at_ble64(void *dest, ut64 val, bool big_endian, size_t offset) {
	if (big_endian) {
		rz_write_at_be64(dest, val, offset);
	} else {
		rz_write_at_le64(dest, val, offset);
	}
}

/**
 * \brief Write a 128-bit value to \p dest in specified order.
 * \param[out] dest The pointer to which the value is written.
 * \param val The written 128-bit value.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then an integer in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, an integer in
 * little-endian order is written.
 */
static inline void rz_write_at_ble128(void *dest, ut128 val, bool big_endian, size_t offset) {
	if (big_endian) {
		rz_write_at_be128(dest, val, offset);
	} else {
		rz_write_at_le128(dest, val, offset);
	}
}

/**
 * \brief Write a 32-bit floating-point to \p dest in specified order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then a floating-point value in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, a floating-point
 * value in little-endian order is written.
 */
static inline void rz_write_at_ble_float(void *src, float val, bool big_endian) {
	big_endian ? rz_write_be_float(src, val) : rz_write_le_float(src, val);
}

/**
 * \brief Write a 64-bit floating-point to \p dest in specified order.
 * \param[out] dest The pointer to which the floating-point value is written.
 * \param val The floating-point value to be written.
 * \param big_endian The choice of endianness.
 * \param offset The offset at which the value is written.
 *
 * The value is written according to \p big_endian. If \p big_endian
 * is \c true, then a floating-point value in big-endian order is
 * written. Otherwise, if \p big_endian is \c false, a floating-point
 * value in little-endian order is written.
 */
static inline void rz_write_at_ble_double(void *src, double val, bool big_endian) {
	big_endian ? rz_write_be_double(src, val) : rz_write_le_double(src, val);
}

/*swap*/

/* Use compiler intrinsics if present */

/**
 * \def rz_swap_ut16
 * \brief Reverse the order of bytes of the 16-bit representation.
 * \parameter x The 16-bit value to operate upon.
 *
 * # Example
 *
 * \code{.c}
 * ut16 x = 0xAABB;
 * ut16 result = 0xBBAA;
 * assert(rz_swap_ut16(x) == result);
 * \endcode
 */
#if HAVE___BUILTIN_BSWAP16
#define rz_swap_ut16 __builtin_bswap16
#else
static inline ut16 rz_swap_ut16(ut16 val) {
	return (val << 8) | (val >> 8);
}
#endif

/**
 * \def rz_swap_ut32
 * \brief Reverse the order of bytes of the 32-bit representation.
 * \parameter x The 32-bit value to operate upon.
 *
 * # Example
 *
 * \code{.c}
 * ut32 x = 0xAABBCCDD;
 * ut32 result = 0xDDCCBBAA;
 * assert(rz_swap_ut32(x) == result);
 * \endcode
 */
#if HAVE___BUILTIN_BSWAP32
#define rz_swap_ut32 __builtin_bswap32
#else
static inline ut32 rz_swap_ut32(ut32 val) {
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}
#endif

/**
 * \def rz_swap_ut64
 * \brief Reverse the order of bytes of the 64-bit representation.
 * \parameter x The 64-bit value to operate upon.
 *
 * # Example
 *
 * \code{.c}
 * ut64 x = 0xAABBCCDD11223344;
 * ut64 result = 0x44332211DDCCBBAA;
 * assert(rz_swap_ut64(x) == result);
 * \endcode
 */
#if HAVE___BUILTIN_BSWAP64
#define rz_swap_ut64 __builtin_bswap64
#else
static inline ut64 rz_swap_ut64(ut64 val) {
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}
#endif

/* Some "secured" functions, to do basic operation (mul, sub, add...) on integers */

/**
 * \brief Add two 64-bit unsigned integers unless the result overflows.
 * \param[out] r The result of addition or \c 0 if overflow.
 * \param a, b The unsigned integers to add.
 * \return Return 0 if the addition would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 */
static inline int UT64_ADD(ut64 *r, ut64 a, ut64 b) {
	if (UT64_MAX - a < b) {
		return 0;
	}
	if (r) {
		*r = a + b;
	}
	return 1;
}

/**
 * \brief Multiply two 64-bit unsigned integers unless the result overflows.
 * \param[out] r The result of multiplication or \c 0 if overflow.
 * \param a, b The unsigned integers to multiply.
 * \return Return 0 if the multiplication would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 * \attention The return value of \c 0 signifies overflow if and only
 * if both \p a and \p b are non-zero. Otherwise, it is the result of
 * multiplication, and no overflow has occurred.
 */
static inline int UT64_MUL(ut64 *r, ut64 a, ut64 b) {
	if (a && UT64_MAX / a < b) {
		return 0;
	}
	if (r) {
		*r = a * b;
	}
	return 1;
}

/**
 * \brief Subtract two 64-bit unsigned integers unless the result underflows.
 * \param[out] r The difference or \c 0 if underflow.
 * \param a The subtrahend.
 * \param b The minuend.
 * \return Return 0 if the subtraction would result in underflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting underflow.
 */
static inline int UT64_SUB(ut64 *r, ut64 a, ut64 b) {
	if (b > a) {
		return 0;
	}
	if (r) {
		*r = a - b;
	}
	return 1;
}

/**
 * \brief Add two 32-bit unsigned integers unless the result overflows.
 * \param[out] r The result of addition or \c 0 if overflow.
 * \param a, b The unsigned integers to add.
 * \return Return 0 if the addition would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 */
static inline int UT32_ADD(ut32 *r, ut32 a, ut32 b) {
	if (UT32_MAX - a < b) {
		return 0;
	}
	if (r) {
		*r = a + b;
	}
	return 1;
}

/**
 * \brief Multiply two 32-bit unsigned integers unless the result overflows.
 * \param[out] r The result of multiplication or \c 0 if overflow.
 * \param a, b The unsigned integers to multiply.
 * \return Return 0 if the multiplication would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 * \attention The return value of \c 0 signifies overflow if and only
 * if both \p a and \p b are non-zero. Otherwise, it is the result of
 * multiplication, and no overflow has occurred.
 */
static inline int UT32_MUL(ut32 *r, ut32 a, ut32 b) {
	if (a && UT32_MAX / a < b) {
		return 0;
	}
	if (r) {
		*r = a * b;
	}
	return 1;
}

/**
 * \brief Subtract two 32-bit unsigned integers unless the result underflows.
 * \param[out] r The difference or \c 0 if underflow.
 * \param a The subtrahend.
 * \param b The minuend.
 * \return Return 0 if the subtraction would result in underflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting underflow.
 */
static inline int UT32_SUB(ut32 *r, ut32 a, ut32 b) {
	if (b > a) {
		return 0;
	}
	if (r) {
		*r = a - b;
	}
	return 1;
}

/**
 * \brief Add two 16-bit unsigned integers unless the result overflows.
 * \param[out] r The result of addition or \c 0 if overflow.
 * \param a, b The unsigned integers to add.
 * \return Return 0 if the addition would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 */
static inline int UT16_ADD(ut16 *r, ut16 a, ut16 b) {
	if (UT16_MAX - a < b) {
		return 0;
	}
	if (r) {
		*r = a + b;
	}
	return 1;
}

/**
 * \brief Multiply two 16-bit unsigned integers unless the result overflows.
 * \param[out] r The result of multiplication or \c 0 if overflow.
 * \param a, b The unsigned integers to multiply.
 * \return Return 0 if the multiplication would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 * \attention The return value of \c 0 signifies overflow if and only
 * if both \p a and \p b are non-zero. Otherwise, it is the result of
 * multiplication, and no overflow has occurred.
 */
static inline int UT16_MUL(ut16 *r, ut16 a, ut16 b) {
	if (a && UT16_MAX / a < b) {
		return 0;
	}
	if (r) {
		*r = a * b;
	}
	return 1;
}

/**
 * \brief Subtract two 16-bit unsigned integers unless the result underflows.
 * \param[out] r The difference or \c 0 if underflow.
 * \param a The subtrahend.
 * \param b The minuend.
 * \return Return 0 if the subtraction would result in underflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting underflow.
 */
static inline int UT16_SUB(ut16 *r, ut16 a, ut16 b) {
	if (b > a) {
		return 0;
	}
	if (r) {
		*r = a - b;
	}
	return 1;
}

/**
 * \brief Add two 8-bit unsigned integers unless the result overflows.
 * \param[out] r The result of addition or \c 0 if overflow.
 * \param a, b The unsigned integers to add.
 * \return Return 0 if the addition would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 */
static inline int UT8_ADD(ut8 *r, ut8 a, ut8 b) {
	if (UT8_MAX - a < b) {
		return 0;
	}
	if (r) {
		*r = a + b;
	}
	return 1;
}

/**
 * \brief Multiply two 8-bit unsigned integers unless the result overflows.
 * \param[out] r The result of multiplication or \c 0 if overflow.
 * \param a, b The unsigned integers to multiply.
 * \return Return 0 if the multiplication would result in overflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting overflow.
 * \attention The return value of \c 0 signifies overflow if and only
 * if both \p a and \p b are non-zero. Otherwise, it is the result of
 * multiplication, and no overflow has occurred.
 */
static inline int UT8_MUL(ut8 *r, ut8 a, ut8 b) {
	if (a && UT8_MAX / a < b) {
		return 0;
	}
	if (r) {
		*r = a * b;
	}
	return 1;
}

/**
 * \brief Subtract two 8-bit unsigned integers unless the result underflows.
 * \param[out] r The difference or \c 0 if underflow.
 * \param a The subtrahend.
 * \param b The minuend.
 * \return Return 0 if the subtraction would result in underflow or 1
 * otherwise.
 * \attention If \p r is \c NULL then it is ignored, but the return
 * value is still useful for detecting underflow.
 */
static inline int UT8_SUB(ut8 *r, ut8 a, ut8 b) {
	if (b > a) {
		return 0;
	}
	if (r) {
		*r = a - b;
	}
	return 1;
}

#ifdef __cplusplus
}
#endif

#endif
