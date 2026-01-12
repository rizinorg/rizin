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
	if (item->offset < 0) {
		return 0ll;
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
	// TODO use mapping from RzRegisterId to RzRegItem (via RzRegSet)
	return rz_reg_get_value(reg, rz_reg_get(reg, rz_reg_get_name(reg, role), -1));
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
	// TODO use mapping from RzRegisterId to RzRegItem (via RzRegSet)
	const char *name = rz_reg_get_name(reg, role);
	if (!name) {
		return false;
	}
	RzRegItem *r = rz_reg_get(reg, name, -1);
	return r ? rz_reg_set_value(reg, r, value) : false;
}
