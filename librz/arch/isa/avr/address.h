// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_AVR_ADDRESS_H
#define RZ_AVR_ADDRESS_H

#include <rz_util/rz_str.h>

#define AVR_MIN_FLASH_SIZE 0x1000

static inline ut64 avr_pc_mask(const char *cpu) {
	static const struct {
		const char *name;
		ut8 byte_address_bits;
	} models[] = {
		{ "ATmega8", 13 },
		{ "ATmega16", 14 },
		{ "ATmega48", 12 },
		{ "ATmega88", 13 },
		{ "ATmega168", 14 },
		{ "ATmega328p", 15 },
		{ "ATmega32u4", 15 },
		{ "ATmega640", 16 },
		{ "ATmega1280", 17 },
		{ "ATmega1281", 17 },
		{ "ATmega2560", 18 },
		{ "ATmega2561", 18 },
		{ "ATTiny48", 12 },
		{ "ATTiny88", 13 },
		{ "ATxmega128a4u", 18 },
	};
	if (cpu) {
		for (size_t i = 0; i < RZ_ARRAY_SIZE(models); i++) {
			if (!rz_str_casecmp(cpu, models[i].name)) {
				return (1ULL << models[i].byte_address_bits) - 1;
			}
		}
	}
	return UT64_MAX;
}

// The encoded displacement is in words relative to the following instruction.
static inline st16 avr_relative_offset(ut16 field, unsigned bits) {
	int sign = 1 << (bits - 1);
	return 2 * (1 + ((int)(field ^ sign) - sign));
}

static inline ut64 avr_wrap_target(ut64 pc, ut64 target, ut64 mask) {
	return (pc & ~mask) | (target & mask);
}

static inline ut64 avr_relative_target(ut64 pc, st16 offset, const char *cpu) {
	ut64 target = pc + offset;
	if ((pc ^ target) < AVR_MIN_FLASH_SIZE) {
		return target;
	}
	return avr_wrap_target(pc, target, avr_pc_mask(cpu));
}

#endif
