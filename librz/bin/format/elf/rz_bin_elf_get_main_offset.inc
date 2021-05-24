// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static ut64 get_main_offset_from_symbol(ELFOBJ *bin) {
	RzBinElfSymbol *symbol = Elf_(rz_bin_elf_get_symbols)(bin);

	if (!symbol) {
		return UT64_MAX;
	}

	for (size_t i = 0; !symbol[i].last; i++) {
		if (!strcmp(symbol[i].name, "main")) {
			return symbol[i].offset;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_linux_64_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	/* linux64 pie main -- probably buggy in some cases */
	int bo = 29; // Begin offset may vary depending on the entry prelude
	// endbr64 - fedora bins have this
	if (buf[0] == 0xf3 && buf[1] == 0x0f && buf[2] == 0x1e && buf[3] == 0xfa) {
		// Change begin offset if binary starts with 'endbr64'
		bo = 33;
	}
	if (buf[bo] == 0x48) {
		ut8 ch = buf[bo + 1];
		if (ch == 0x8d) { // lea rdi, qword [rip-0x21c4]
			ut8 *p = buf + bo + 3;
			st32 maindelta = (st32)rz_read_le32(p);
			ut64 vmain = (ut64)(entry + bo + maindelta) + 7;
			ut64 ventry = Elf_(rz_bin_elf_p2v_new)(bin, entry);
			if (vmain >> 16 == ventry >> 16) {
				return (ut64)vmain;
			}
		} else if (0xc7) { // mov rdi, 0xADDR
			ut8 *p = buf + bo + 3;
			return (ut64)(ut32)rz_read_le32(p);
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_x86_non_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// X86-NONPIE
#if RZ_BIN_ELF64
	if (!memcmp(buf, "\x49\x89\xd9", 3) && buf[156] == 0xe8) { // openbsd
		return rz_read_le32(buf + 157) + entry + 156 + 5;
	}
	if (!memcmp(buf + 29, "\x48\xc7\xc7", 3)) { // linux
		ut64 addr = (ut64)rz_read_le32(buf + 29 + 3);
		return Elf_(rz_bin_elf_v2p_new)(bin, addr);
	}
#else
	if (buf[23] == '\x68') {
		ut64 addr = (ut64)rz_read_le32(buf + 23 + 1);
		return Elf_(rz_bin_elf_v2p_new)(bin, addr);
	}
#endif

	return UT64_MAX;
}

static ut64 get_main_offset_x86_pie(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// X86-PIE
	if (buf[0x00] == 0x48 && buf[0x1e] == 0x8d && buf[0x11] == 0xe8) {
		ut32 *pmain = (ut32 *)(buf + 0x30);
		ut64 vmain = Elf_(rz_bin_elf_p2v_new)(bin, (ut64)*pmain);
		ut64 ventry = Elf_(rz_bin_elf_p2v_new)(bin, entry);
		if (vmain >> 16 == ventry >> 16) {
			return vmain;
		}
	}
	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp(buf, "\x31\xed\x49\x89", 4)) { // linux
			ut64 maddr, baddr;
			ut8 n32s[sizeof(ut32)] = { 0 };
			maddr = entry + 0x24 + rz_read_le32(buf + 0x20);
			if (rz_buf_read_at(bin->b, maddr, n32s, sizeof(ut32)) == -1) {
				return 0;
			}
			maddr = (ut64)rz_read_le32(&n32s[0]);
			baddr = (bin->ehdr.e_entry >> 16) << 16;
			if (bin->phdr) {
				baddr = Elf_(rz_bin_elf_get_baddr)(bin);
			}
			maddr += baddr;
			return maddr;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_x86_gcc(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (buf[0] != 0xe8 && memcmp(buf + 5, "\x50\xe8\x00\x00\x00\x00\xb8\x01\x00\x00\x00\x53", 12)) {
		return UT64_MAX;
	}

	size_t SIZEOF_CALL = 5;
	ut64 rel_addr = (ut64)(buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24));
	ut64 addr = Elf_(rz_bin_elf_p2v_new)(bin, entry + SIZEOF_CALL);
	addr += rel_addr;
	return Elf_(rz_bin_elf_v2p_new)(bin, addr);
}

static ut64 get_main_offset_mips(ELFOBJ *bin, ut64 entry, ut8 *buf, size_t size) {
	/* get .got, calculate offset of main symbol */
	if (memcmp(buf, "\x21\x00\xe0\x03\x01\x00\x11\x04", 8)) {
		return UT64_MAX;
	}

	/*
	   assuming the startup code looks like
	   got = gp-0x7ff0
	   got[index__libc_start_main] ( got[index_main] );

	   looking for the instruction generating the first argument to find main
	   lw a0, offset(gp)
	   */

	if (bin->dyn_info.dt_pltgot == RZ_BIN_ELF_ADDR_MAX) {
		return 0;
	}

	ut64 got_offset = Elf_(rz_bin_elf_v2p_new)(bin, bin->dyn_info.dt_pltgot);
	ut64 gp = got_offset + 0x7ff0;

	for (size_t i = 0; i < size; i += 4) {
		const ut32 instr = rz_read_le32(buf + i);
		if ((instr & 0xffff0000) == 0x8f840000) { // lw a0, offset(gp)
			const short delta = instr & 0x0000ffff;
			rz_buf_read_at(bin->b, /* got_entry_offset = */ gp + delta, buf, 4);
			return Elf_(rz_bin_elf_v2p_new)(bin, rz_read_le32(buf));
		}
	}

	return 0;
}

static ut64 get_main_offset_arm_glibc_thumb(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	size_t delta = 0;

	if (!memcmp(buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x02\xbc\x6a\x46", 11)) {
		/* newer versions of gcc use push/pop */
		delta = 0x28;
	} else if (!memcmp(buf, "\xf0\x00\x0b\x4f\xf0\x00\x0e\x5d\xf8\x04\x1b", 11)) {
		/* older versions of gcc (4.5.x) use ldr/str */
		delta = 0x30;
	}

	if (delta) {
		ut64 pa = Elf_(rz_bin_elf_v2p)(bin, rz_read_le32(buf + delta - 1) & ~1);
		if (pa < rz_buf_size(bin->b)) {
			return pa;
		}
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm_glibc_non_thumb(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (!memcmp(buf, "\x00\xb0\xa0\xe3\x00\xe0\xa0\xe3", 8)) {
		return Elf_(rz_bin_elf_v2p)(bin, rz_read_le32(buf + 0x34) & ~1);
	}

	if (!memcmp(buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
		return Elf_(rz_bin_elf_v2p)(bin, rz_read_le32(buf + 0x30) & ~1);
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm_glibc(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	// ARM Glibc
	if (entry & 1) {
		return get_main_offset_arm_glibc_thumb(bin, entry, buf);
	} else {
		return get_main_offset_arm_glibc_non_thumb(bin, entry, buf);
	}

	return UT64_MAX;
}

static ut64 get_main_offset_arm64(ELFOBJ *bin, ut64 entry, ut8 *buf) {
	if (buf[0x18 + 3] != 0x58 || buf[0x2f] != 0x00) {
		return UT64_MAX;
	}

	ut64 entry_vaddr = Elf_(rz_bin_elf_p2v)(bin, entry);
	ut64 main_addr = rz_read_le32(buf + 0x30);

	if (main_addr >> 16 == entry_vaddr >> 16) {
		return Elf_(rz_bin_elf_v2p)(bin, main_addr);
	}

	return UT64_MAX;
}

/**
 * \brief Compute the main offset of the binary
 * \param elf binary
 * \return the main offset
 *
 * ...
 */
ut64 Elf_(rz_bin_elf_get_main_offset)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);

	ut8 buf[256];
	ut64 entry = Elf_(rz_bin_elf_get_entry_offset)(bin);
	ut64 main_addr;

	if (entry == UT64_MAX || entry > bin->size || (entry + sizeof(buf)) > bin->size) {
		return UT64_MAX;
	}

	if (rz_buf_read_at(bin->b, entry, buf, sizeof(buf)) < 0) {
		return UT64_MAX;
	}

	main_addr = get_main_offset_arm64(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_arm_glibc(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_mips(bin, entry, buf, RZ_ARRAY_SIZE(buf));
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_gcc(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_x86_non_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	main_addr = get_main_offset_linux_64_pie(bin, entry, buf);
	if (main_addr != UT64_MAX) {
		return main_addr;
	}

	return get_main_offset_from_symbol(bin);
}
