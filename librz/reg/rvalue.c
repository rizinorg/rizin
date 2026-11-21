// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include <rz_util.h>

/**
 * \brief      Read the value of the given register as a bit vector
 *
 * \param      reg   The register profile
 * \param      item  The register item
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzBitVector *rz_reg_get_bv(RZ_NONNULL RzReg *reg, RZ_NONNULL RzRegItem *item) {
	rz_return_val_if_fail(reg && item, NULL);
	if (item->offset < 0) {
		return rz_bv_new_zero(item->size);
	}
	RzRegSet *regset = &reg->regset[item->arena];
	if (item->size == 1 && (item->offset % 8)) {
		// a single-bit, non-byte-aligned register (e.g. a status-word flag) is
		// stored at a fixed physical bit position, independent of endianness.
		RzBitVector *bv = rz_bv_new(1);
		if (!bv) {
			return NULL;
		}
		bool bit = (regset->arena->bytes[item->offset / 8] >> (item->offset % 8)) & 1;
		rz_bv_set(bv, 0, bit);
		return bv;
	}
	if (reg->big_endian) {
		return rz_bv_new_from_bytes_be(regset->arena->bytes, item->offset, item->size);
	} else {
		return rz_bv_new_from_bytes_le(regset->arena->bytes, item->offset, item->size);
	}
}

/**
 * \brief      Gets the register value based on the given register item
 *
 * \param      reg   The register profile
 * \param      item  The register item
 *
 * \return     Value stored in the register
 */
RZ_API ut64 rz_reg_get_value(RZ_NONNULL RzReg *reg, RZ_NONNULL RzRegItem *item) {
	rz_return_val_if_fail(reg && item, 0);
	if (item->offset < 0 || item->size <= 0) {
		return 0ll;
	}
	RzRegArena *arena = reg->regset[item->arena].arena;
	if (arena && arena->bytes) {
		ut32 byte_off = (ut32)item->offset >> 3;
		ut32 bit_off = (ut32)item->offset & 7;
		ut32 nbytes = ((ut32)item->size + bit_off + 7) >> 3;
		if (byte_off + nbytes <= (ut32)arena->size) {
			if (item->size == 1 && bit_off) {
				return (arena->bytes[byte_off] >> bit_off) & 1;
			}
			if (!bit_off && item->size <= 64) {
				const ut8 *buf = arena->bytes + byte_off;
				if (!reg->big_endian) {
					switch (item->size) {
					case 8:
						return buf[0];
					case 16:
						return rz_read_le16(buf);
					case 32:
						return rz_read_le32(buf);
					case 64:
						return rz_read_le64(buf);
					default: {
						ut64 val = 0;
						for (ut32 i = 0; i < nbytes; i++) {
							val |= (ut64)buf[i] << (i * 8);
						}
						return val & (UT64_MAX >> (64 - item->size));
					}
					}
				} else if (!(item->size & 7)) {
					switch (item->size) {
					case 8:
						return buf[0];
					case 16:
						return rz_read_be16(buf);
					case 32:
						return rz_read_be32(buf);
					case 64:
						return rz_read_be64(buf);
					default: {
						ut64 val = 0;
						for (ut32 i = 0; i < nbytes; i++) {
							val = (val << 8) | buf[i];
						}
						return val;
					}
					}
				}
			}
		}
	}
	RzBitVector *bv = rz_reg_get_bv(reg, item);
	if (!bv) {
		return 0;
	}
	ut64 value = rz_bv_to_ut64(bv);
	rz_bv_free(bv);
	return value;
}

/**
 * \brief      Gets the register value based on the given register role
 *
 * \param      reg   The register profile
 * \param      item  The register item
 *
 * \return     Value stored in the register
 */
RZ_API ut64 rz_reg_get_value_by_role(RZ_NONNULL RzReg *reg, RzRegisterId role) {
	rz_return_val_if_fail(reg, 0);
	RzRegItem *ri = rz_reg_get_by_role(reg, role);
	if (!ri) {
		return 0;
	}
	return rz_reg_get_value(reg, ri);
}

static bool reg_set_value(RzReg *reg, RzRegItem *item, ut64 value) {
	RzRegArena *arena = reg->regset[item->arena].arena;
	if (!arena) {
		return false;
	}
	switch (item->size) {
	case 4: {
		// Example: 4bit Register is located at bit 1 of a byte.
		// Example byte = 0b101xxxx1
		// 'xxxx' are the bits where the new 'value' is set.

		ut8 *buf = reg->regset[item->arena].arena->bytes + (item->offset / 8);
		ut8 reg_byte = buf[0];
		// Number of bits we have to shift the bits of the new value so they align with the 'xxxx' (in example: 1).
		ut8 shift = item->offset % 8;
		ut8 mask_xxxx = 0xf << shift;
		ut8 xxxx = (value & 0xf) << shift;
		ut8 new_val = (reg_byte & ~mask_xxxx) | xxxx;
		rz_mem_copybits(buf, &new_val, 8); // Write byte back.
		return true;
	}
	case 1:
		if (value) {
			ut8 *buf = arena->bytes + (item->offset / 8);
			int bit = (item->offset % 8);
			ut8 mask = (1 << bit);
			buf[0] = (buf[0] & (0xff ^ mask)) | mask;
		} else {
			int idx = item->offset / 8;
			if (idx + item->size > arena->size) {
				RZ_LOG_ERROR("reg: index (%d) exceeds arena size (%d)\n", idx + item->size, arena->size);
				return false;
			}
			ut8 *buf = arena->bytes + idx;
			int bit = item->offset % 8;
			ut8 mask = 0xff ^ (1 << bit);
			buf[0] = (buf[0] & mask) | 0;
		}
		return true;
	default:
		RZ_LOG_ERROR("reg: bit size %d not supported\n", item->size);
		return false;
	}
}

/**
 * \brief      Set the value of the given register from the given bit vector
 *
 * \param      reg   The register profile
 * \param      item  The register item
 * \param[in]  bv    The bitvector to set
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_reg_set_bv(RZ_NONNULL RzReg *reg, RZ_NONNULL RzRegItem *item, RZ_NONNULL const RzBitVector *bv) {
	rz_return_val_if_fail(reg && item && bv, false);
	if (rz_reg_is_readonly(reg, item) || item->offset < 0) {
		return true;
	}
	if (rz_bv_len(bv) != item->size) {
		return false;
	}
	if (item->offset % 8) {
		// TODO: this needs a bit offset arg in rz_bv_set_to_bytes_be()
		if (item->size == 1) {
			// workaround for flags edge-case while the offset mentioned above is not implemented yet
			return reg_set_value(reg, item, rz_bv_to_ut64(bv));
		}
		RZ_LOG_ERROR("reg: failed to set bitvector for non-byte-aligned regs (not yet supported).\n");
		return false;
	}

	RzRegSet *regset = &reg->regset[item->arena];
	int boff = item->offset / 8;
	if (reg->big_endian) {
		rz_bv_set_to_bytes_be(bv, regset->arena->bytes + boff);
	} else {
		rz_bv_set_to_bytes_le(bv, regset->arena->bytes + boff);
	}
	return true;
}

/**
 * \brief      Sets the register value based on the given register item and value
 *
 * \param      reg    The register profile
 * \param      item   The register item
 * \param      value  The value to set
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_reg_set_value(RZ_NONNULL RzReg *reg, RZ_NONNULL RzRegItem *item, ut64 value) {
	rz_return_val_if_fail(reg && item, false);
	if (rz_reg_is_readonly(reg, item) || item->offset < 0) {
		return true;
	}
	if (item->size <= 0) {
		RZ_LOG_ERROR("reg: failed to allocate RzBitVector for register write\n");
		return false;
	}
	if (item->offset & 7) {
		if (item->size == 1) {
			return reg_set_value(reg, item, value & 1);
		}
		RZ_LOG_ERROR("reg: failed to set bitvector for non-byte-aligned regs (not yet supported).\n");
		return false;
	}
	if (item->size <= 64) {
		RzRegArena *arena = reg->regset[item->arena].arena;
		ut32 byte_off = (ut32)item->offset >> 3;
		ut32 nbytes = ((ut32)item->size + 7) >> 3;
		if (arena && arena->bytes && byte_off + nbytes <= (ut32)arena->size) {
			ut8 *buf = arena->bytes + byte_off;
			ut64 masked = item->size == 64 ? value : (value & (UT64_MAX >> (64 - item->size)));
			if (!reg->big_endian) {
				switch (item->size) {
				case 8:
					buf[0] = (ut8)masked;
					return true;
				case 16:
					rz_write_le16(buf, (ut16)masked);
					return true;
				case 32:
					rz_write_le32(buf, (ut32)masked);
					return true;
				case 64:
					rz_write_le64(buf, masked);
					return true;
				default:
					for (ut32 i = 0; i < nbytes; i++) {
						if (i + 1 == nbytes && (item->size & 7)) {
							buf[i] &= (ut8)((0xff << (item->size & 7)) & 0xff);
							buf[i] |= (ut8)(masked & 0xff);
						} else {
							buf[i] = (ut8)(masked & 0xff);
						}
						masked >>= 8;
					}
					return true;
				}
			} else if (!(item->size & 7)) {
				switch (item->size) {
				case 8:
					buf[0] = (ut8)masked;
					return true;
				case 16:
					rz_write_be16(buf, (ut16)masked);
					return true;
				case 32:
					rz_write_be32(buf, (ut32)masked);
					return true;
				case 64:
					rz_write_be64(buf, masked);
					return true;
				default:
					for (ut32 i = nbytes - 1; i > 0; i--) {
						buf[i] = (ut8)(masked & 0xff);
						masked >>= 8;
					}
					buf[0] = (ut8)(masked & 0xff);
					return true;
				}
			}
		}
	}

	RzBitVector *bv = rz_bv_new_from_ut64(item->size, value);
	if (!bv) {
		RZ_LOG_ERROR("reg: failed to allocate RzBitVector for register write\n");
		return false;
	}

	bool res = rz_reg_set_bv(reg, item, bv);
	rz_bv_free(bv);
	return res;
}

/**
 * \brief      Sets the register value based on the given register role and value
 *
 * \param      reg    The register profile
 * \param      role   The register role
 * \param      value  The value to set
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_reg_set_value_by_role(RZ_NONNULL RzReg *reg, RzRegisterId role, ut64 value) {
	rz_return_val_if_fail(reg, false);
	RzRegItem *ri = rz_reg_get_by_role(reg, role);
	if (!ri) {
		return false;
	}
	return ri ? rz_reg_set_value(reg, ri, value) : false;
}
