// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2017-2019 usrshare
// SPDX-FileCopyrightText: 2015 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file bin_ninsnes.c
 *
 *  This plugin parses Nintendo SNES ROM (sfc).
 *
 *  The SNES rom files has a Cartridge header at
 *  - LoROM:   0x007fc0
 *  - HiROM:   0x00ffc0
 *  - ExHiROM: 0x40ffc0
 *
 *  This header is then composed of:
 *
 *  offset | size | description
 *  0x7fc0 | 21   | Cartridge title (uppercase ASCII, with spaces for unused bytes)
 *  0x7fd5 | 1    | ROM speed and memory map mode (0 LoROM, 1 HiROM, 5 ExHiROM)
 *  0x7fd6 | 1    | cartridge_type (Indicates if a cartridge contains extra RAM, a battery, and/or a coprocessor)
 *  0x7fd7 | 1    | ROM size: 1<<N kilobytes, rounded up (so 8=256KB, 12=4096KB and so on)
 *  0x7fd8 | 1    | RAM size: 1<<N kilobytes (so 1=2KB, 5=32KB, and so on)
 *  0x7fd9 | 1    | Country (Implies NTSC/PAL)
 *  0x7fda | 1    | Developer ID
 *  0x7fdb | 1    | ROM version (0 = first)
 *  0x7fdc | 2    | Checksum complement (Checksum ^ $FFFF)
 *  0x7fde | 2    | Checksum
 *  0x7fe0 | 32   | Interrupt vectors
 *
 *	References:
 *	- https://snes.nesdev.org/wiki/ROM_file_formats
 *	- https://snes.nesdev.org/wiki/Memory_map
 *	- https://en.wikibooks.org/wiki/Super_NES_Programming/SNES_memory_map
 *	- https://problemkaputt.de/fullsnes.htm
 */

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_endian.h>

// Some rom has an offset of +512 bytes because
// the rom dumeper added this header.
#define SNES_ROM_DUMPER_HEADER 512

#define SNES_ROM_MIN_SIZE 512 // Bytes
#define SNES_ROM_MAX_SIZE (14 * 1024 * 1024) // 14 Mb

#define SNES_ROM_HEADER_LOROM   0x007fc0
#define SNES_ROM_HEADER_HIROM   0x00ffc0
#define SNES_ROM_HEADER_EXHIROM 0x40ffc0

#define SNES_ROM_GAME_TITLE_SIZE 21

#define SNES_ROM_SPEED_MASK    (0x10)
#define SNES_ROM_MAP_MODE_MASK (0x0f)

typedef enum snes_rom_map_mode {
	SNES_ROM_MODE_LOROM_32K = 0, // LoROM_32K Banks (LoROM)
	SNES_ROM_MODE_HIROM_64K = 1, // HiROM_64K Banks (HiROM)
	SNES_ROM_MODE_LOROM_32K_S_DD1 = 2, // LoROM_32K Banks + S-DD1 (mappable) "Super MMC"
	SNES_ROM_MODE_LOROM_32K_SA_1 = 3, // LoROM_32K Banks + SA-1 (mappable) "Emulates Super MMC"
	SNES_ROM_MODE_EXTHIROM_64K = 5, // HiROM_64K Banks (ExtHiROM)
	SNES_ROM_MODE_HIROM_64K_SPC7110 = 0xa, // HiROM/64K Banks + SPC7110
} SNESRomMapMode;

#define SNES_VADDR_TO_BANK(x) ((x) >> 16)
#define SNES_BANK_TO_VADDR(x) ((x) << 16)
#define SNES_BANK_SIZE        0x10000

#define SNES_LOROM_ROM_SIZE    0x08000
#define SNES_LOROM_MIRROR_SIZE 0x08000

#define SNES_HIROM_ROM_SIZE    SNES_BANK_SIZE
#define SNES_HIROM_MIRROR_SIZE 0x08000

#define SNES_LOWRAM_BANK_SIZE     0x2000
#define SNES_IO_BANK_SIZE         0x4000
#define SNES_SRAM_BANK_SIZE       0x8000
#define SNES_WRAM_BANK_SIZE       SNES_BANK_SIZE
#define SNES_LOROM_WRAM_BANK_SIZE SNES_BANK_SIZE
#define SNES_HIROM_WRAM_BANK_SIZE 0x2000

typedef struct snes_rom_cpu_vectors {
	ut32 unused0; // Zero filled vector (or ID "XBOO") for WRAM-Boot compatible files
	ut16 native_cop; // COP vector (65C816 mode) COP opcode
	ut16 native_br; // BRK vector (65C816 mode) BRK opcode
	ut16 native_abort; // ABORT vector (65C816 mode) not used in SNES
	ut16 native_nmi; // NMI vector (65C816 mode) SNES V-Blank Interrupt
	ut16 unused1; // Unused
	ut16 native_irq; // IRQ vector (65C816 mode) SNES H/V-Timer or External Interrupt
	ut32 unused2; // Unused
	ut16 emu_cop; // COP vector (6502 mode)
	ut16 unused3; // Unused
	ut16 emu_abort; // ABORT vector (6502 mode) not used in SNES
	ut16 emu_nmi; // NMI vector (6502 mode)
	ut16 reset; // RESET vector (6502 mode) CPU is always in 6502 mode on RESET
	ut16 emu_irq; // IRQ/BRK vector (6502 mode)
} SNESCpuVectors;

typedef struct snes_mode {
	bool is_valid;
	bool fast_rom;
	SNESRomMapMode map;
} SNESMode;

typedef struct snes_rom {
	ut32 skip_offset; ///< The number of bytes to skip, when the rom has the dumper header.
	ut8 coprocessor; ///< Used only when cartridge_type is $Fx and is located on byte before the game_title.
	char game_title[SNES_ROM_GAME_TITLE_SIZE]; ///< Cartridge title, uppercase ASCII, unused bytes are spaces (0x20)
	SNESMode mode; ///< ROM speed and memory map mode (LoROM/HiROM/ExHiROM)
	ut8 cartridge_type; ///< Cartridge type (Indicates if a cartridge has RAM, battery, coprocessor)
	ut8 rom_size; ///< ROM size: 1<<N kilobytes, rounded up (so 8=256KB, 12=4096KB and so on)
	ut8 sram_size; ///< RAM size: 1<<N kilobytes (so 1=2KB, 5=32KB, and so on)
	ut8 country; ///< Country (Implies NTSC/PAL)
	ut8 developer_id; ///< Developer ID
	ut8 rom_version; ///< ROM version (0 = first)
	ut16 checksum_compl; ///< Checksum complement (~Checksum)
	ut16 checksum; ///< Checksum
	SNESCpuVectors vectors;
} SNESRom;

typedef struct snes_search_offset {
	SNESRomMapMode map_mode;
	ut32 offset;
	ut32 skip_offset;
} SNESSearchOffset;

static const SNESSearchOffset snes_offsets[] = {
	{ SNES_ROM_MODE_LOROM_32K, SNES_ROM_HEADER_LOROM, SNES_ROM_DUMPER_HEADER },
	{ SNES_ROM_MODE_HIROM_64K, SNES_ROM_HEADER_HIROM, SNES_ROM_DUMPER_HEADER },
	{ SNES_ROM_MODE_LOROM_32K_S_DD1, SNES_ROM_HEADER_LOROM, SNES_ROM_DUMPER_HEADER },
	{ SNES_ROM_MODE_LOROM_32K_SA_1, SNES_ROM_HEADER_LOROM, SNES_ROM_DUMPER_HEADER },
	{ SNES_ROM_MODE_EXTHIROM_64K, SNES_ROM_HEADER_EXHIROM, SNES_ROM_DUMPER_HEADER },
	{ SNES_ROM_MODE_HIROM_64K_SPC7110, SNES_ROM_HEADER_EXHIROM, SNES_ROM_DUMPER_HEADER },
	/* without header offset */
	{ SNES_ROM_MODE_LOROM_32K, SNES_ROM_HEADER_LOROM, 0 },
	{ SNES_ROM_MODE_HIROM_64K, SNES_ROM_HEADER_HIROM, 0 },
	{ SNES_ROM_MODE_LOROM_32K_S_DD1, SNES_ROM_HEADER_LOROM, 0 },
	{ SNES_ROM_MODE_LOROM_32K_SA_1, SNES_ROM_HEADER_LOROM, 0 },
	{ SNES_ROM_MODE_EXTHIROM_64K, SNES_ROM_HEADER_EXHIROM, 0 },
	{ SNES_ROM_MODE_HIROM_64K_SPC7110, SNES_ROM_HEADER_EXHIROM, 0 },
};

static bool snes_parse_rom(RzBuffer *b, ut32 address, ut32 skip, SNESRom *rom) {
	// we also read the coprocessor byte
	ut64 offset = address + skip - 1;
	rom->skip_offset = skip;
	ut8 mode = 0;

	if (rz_buf_read_ble8_offset(b, &offset, &rom->coprocessor, false) &&
		rz_buf_read_offset(b, &offset, (ut8 *)rom->game_title, sizeof(rom->game_title)) &&
		rz_buf_read_ble8_offset(b, &offset, &mode, false) && // decoded later
		rz_buf_read_ble8_offset(b, &offset, &rom->cartridge_type, false) &&
		rz_buf_read_ble8_offset(b, &offset, &rom->rom_size, false) &&
		rz_buf_read_ble8_offset(b, &offset, &rom->sram_size, false) &&
		rz_buf_read_ble8_offset(b, &offset, &rom->country, false) &&
		rz_buf_read_ble8_offset(b, &offset, &rom->developer_id, false) &&
		rz_buf_read_ble8_offset(b, &offset, &rom->rom_version, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->checksum_compl, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->checksum, false) &&
		rz_buf_read_ble32_offset(b, &offset, &rom->vectors.unused0, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.native_cop, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.native_br, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.native_abort, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.native_nmi, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.unused1, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.native_irq, false) &&
		rz_buf_read_ble32_offset(b, &offset, &rom->vectors.unused2, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.emu_cop, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.unused3, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.emu_abort, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.emu_nmi, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.reset, false) &&
		rz_buf_read_ble16_offset(b, &offset, &rom->vectors.emu_irq, false)) {
		// successful read.

		// decode mode into SNESMap
		// bits 7-6 must be zero and bit 5 must be 1
		rom->mode.is_valid = !(mode & 0xc0) && (mode & 0x20);
		rom->mode.fast_rom = mode & SNES_ROM_SPEED_MASK;
		rom->mode.map = mode & SNES_ROM_MAP_MODE_MASK;
		return true;
	}
	return false;
}

static bool snes_is_header_at(RzBuffer *b, SNESRom *rom, const SNESSearchOffset *sso, size_t file_size) {
	if (!snes_parse_rom(b, sso->offset, sso->skip_offset, rom)) {
		return false;
	}

	// the header can be validated in many ways.
	// first we validate there is a title
	bool null_found = false;
	for (size_t i = 0; i < sizeof(rom->game_title); ++i) {
		// it should be all uppercase but we accept also lowercase.
		const char ch = rom->game_title[i];
		if (!ch) {
			// special case where some games may have null delimited string.
			null_found = true;
		} else if (null_found && ch) {
			return false;
		} else if (!IS_PRINTABLE(ch)) {
			return false;
		}
	}

	// ROM-hacks or homebrews often omit checksums
	if (rom->checksum == (ut16)~rom->checksum_compl) {
		return true;
	}

	// the reset vector cannot be less that 0x8000
	if (rom->vectors.reset < 0x8000) {
		return false;
	}

	// the rom size header value cannot be 0
	if (!rom->rom_size) {
		return false;
	}

	// Expected size in Kbytes
	size_t file_kb = file_size / 1024;
	size_t lower_size = 1ull << (rom->rom_size - 1);
	size_t higher_size = 1ull << (rom->rom_size + 1);

	// Ensure size is always between the boundaries.
	if (!(file_kb >= lower_size && file_kb <= higher_size)) {
		return false;
	}

	// we ignore the speed bit.
	return rom->mode.is_valid && sso->map_mode == rom->mode.map;
}

static bool snes_find_header(RzBuffer *b, SNESRom *rom) {
	size_t file_size = rz_buf_size(b);
	if (file_size < SNES_ROM_MIN_SIZE || file_size > SNES_ROM_MAX_SIZE) {
		return false;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(snes_offsets); ++i) {
		if (snes_is_header_at(b, rom, &snes_offsets[i], file_size)) {
			return true;
		}
	}
	return false;
}

static bool snes_check_buffer(RzBuffer *b) {
	SNESRom rom = { 0 };
	return snes_find_header(b, &rom);
}

static bool snes_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	SNESRom *rom = RZ_NEW0(SNESRom);
	if (!rom || !snes_find_header(bf->buf, rom)) {
		free(rom);
		return false;
	}

	obj->bin_obj = rom;
	return true;
}

static RzBinInfo *snes_info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}

	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Super NES / Super Famicom");
	ret->os = rz_str_dup("snes");
	ret->arch = rz_str_dup("snes");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static bool snes_add_symbol(RzPVector /*<RzBinSymbol *>*/ *ret, const SNESRom *rom, const char *name, ut64 vaddr, size_t size) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		return false;
	}
	sym->name = rz_str_dup(name);
	sym->vaddr = vaddr;
	sym->size = size;
	sym->ordinal = 0;

	// In LoROM bank 0 is mapped at 0x80:8000, but mirrored at 0x00:8000
	// In HiROM bank 0 is mapped at 0xC0:0000, but mirrored at 0x00:8000
	// In ExHiROM bank 0 is mapped at 0xC0:0000, but mirrored at 0x00:8000
	// the rom may have the dumper header, we need to add the skip_offset
	sym->paddr = rom->skip_offset + (vaddr - 0x8000);

	rz_pvector_push(ret, sym);
	return true;
}

static RzPVector /*<RzBinSymbol *>*/ *snes_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	const SNESRom *rom = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	if (!snes_add_symbol(ret, rom, "cop_vector_native", rom->vectors.native_cop, 0) ||
		!snes_add_symbol(ret, rom, "br_vector_native", rom->vectors.native_br, 0) ||
		!snes_add_symbol(ret, rom, "abort_vector_native", rom->vectors.native_abort, 0) ||
		!snes_add_symbol(ret, rom, "nmi_vector_native", rom->vectors.native_nmi, 0) ||
		!snes_add_symbol(ret, rom, "irq_vector_native", rom->vectors.native_irq, 0) ||
		!snes_add_symbol(ret, rom, "cop_vector_emulator", rom->vectors.emu_cop, 0) ||
		!snes_add_symbol(ret, rom, "abort_vector_emulator", rom->vectors.emu_abort, 0) ||
		!snes_add_symbol(ret, rom, "nmi_vector_emulator", rom->vectors.emu_nmi, 0) ||
		!snes_add_symbol(ret, rom, "reset_vector_emulator", rom->vectors.reset, 0) ||
		!snes_add_symbol(ret, rom, "irq_vector_emulator", rom->vectors.emu_irq, 0)) {
		rz_pvector_free(ret);
		return NULL;
	}
	return ret;
}

static bool snes_add_section(RzPVector /*<RzBinSection *>*/ *ret, char *name, ut64 paddr, size_t size, ut64 vaddr, size_t vsize) {
	RzBinSection *sect = RZ_NEW0(RzBinSection);
	if (!sect) {
		free(name);
		return false;
	}

	sect->name = name;
	sect->paddr = paddr;
	sect->size = size;
	sect->vaddr = vaddr;
	sect->vsize = vsize;
	sect->perm = RZ_PERM_RX;

	rz_pvector_push(ret, sect);
	return true;
}

static RzPVector /*<RzBinSection *>*/ *snes_lorom_to_sections(const SNESRom *rom, const ut32 file_size) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// LoROM sections:
	// starts at bank 0x80, for each bank the rom always is
	// mapped from 0x8000 and has a size of 0x8000

	ut64 vaddr = SNES_BANK_TO_VADDR(0x80) + 0x8000;
	for (ut32 offset = 0; offset < file_size;) {
		ut32 bank_id = SNES_VADDR_TO_BANK(vaddr);
		ut64 paddr = rom->skip_offset + offset;

		size_t psize = SNES_LOROM_ROM_SIZE;
		if ((offset + psize) > file_size) {
			psize = file_size - offset;
		}

		char *name = rz_str_newf("rom_%02x", bank_id);
		if (!snes_add_section(ret, name, paddr, psize, vaddr, SNES_LOROM_ROM_SIZE)) {
			rz_pvector_free(ret);
			return NULL;
		}
		offset += SNES_LOROM_ROM_SIZE;
		vaddr += SNES_BANK_SIZE;
	}

	// mirror is mapped from bank 0x00-0x7D always at offset 0x8000
	vaddr = 0x8000;
	for (ut32 offset = 0; offset < file_size;) {
		ut32 bank_id = SNES_VADDR_TO_BANK(vaddr);
		ut64 paddr = rom->skip_offset + offset;

		size_t psize = SNES_LOROM_MIRROR_SIZE;
		if ((offset + psize) > file_size) {
			psize = file_size - offset;
		}

		char *name = rz_str_newf("mirror_%02x", bank_id);
		if (!snes_add_section(ret, name, paddr, psize, vaddr, SNES_LOROM_MIRROR_SIZE)) {
			rz_pvector_free(ret);
			return NULL;
		}
		offset += SNES_LOROM_MIRROR_SIZE;
		vaddr += SNES_BANK_SIZE;
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *snes_hirom_to_sections(const SNESRom *rom, const ut32 file_size) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// HiROM sections:
	// starts at bank 0xC0, for each bank the rom always is
	// mapped from 0x0000 and has a size of 0x10000

	ut64 vaddr = SNES_BANK_TO_VADDR(0xC0);
	for (ut32 offset = 0; offset < file_size;) {
		ut32 bank_id = SNES_VADDR_TO_BANK(vaddr);

		char *name = rz_str_newf("rom_%02x", bank_id);
		ut64 paddr = rom->skip_offset + offset;

		size_t psize = SNES_HIROM_ROM_SIZE;
		if ((offset + psize) > file_size) {
			psize = file_size - offset;
		}
		if (!snes_add_section(ret, name, paddr, psize, vaddr, SNES_HIROM_ROM_SIZE)) {
			rz_pvector_free(ret);
			return NULL;
		}
		offset += SNES_HIROM_ROM_SIZE;
		vaddr += SNES_BANK_SIZE;
	}

	// mirror is mapped from bank 0x00-0x3F and 0x80-0xBF
	// banks 0x00-0x3F only have 0x0000-0x7fff at 0x8000 offset
	vaddr = 0x8000;
	for (ut32 offset = 0; offset < file_size;) {
		ut32 bank_id = SNES_VADDR_TO_BANK(vaddr);
		ut64 paddr = rom->skip_offset + offset;

		size_t psize = SNES_HIROM_MIRROR_SIZE;
		if ((offset + psize) > file_size) {
			psize = file_size - offset;
		}

		char *name = rz_str_newf("mirror_%02x", bank_id);
		if (!snes_add_section(ret, name, paddr, psize, vaddr, SNES_HIROM_MIRROR_SIZE)) {
			rz_pvector_free(ret);
			return NULL;
		}
		offset += SNES_BANK_SIZE;
		vaddr += SNES_BANK_SIZE;
	}

	// banks 0x80-0xBF only have 0x8000-0xffff at 0x8000 offset
	vaddr = SNES_BANK_TO_VADDR(0x80) + 0x8000;
	for (ut32 offset = 0x8000; offset < file_size;) {
		ut32 bank_id = SNES_VADDR_TO_BANK(vaddr);
		ut64 paddr = rom->skip_offset + offset;

		size_t psize = SNES_HIROM_MIRROR_SIZE;
		if ((offset + psize) > file_size) {
			psize = file_size - offset;
		}

		char *name = rz_str_newf("mirror_%02x", bank_id);
		if (!snes_add_section(ret, name, paddr, psize, vaddr, SNES_HIROM_MIRROR_SIZE)) {
			rz_pvector_free(ret);
			return NULL;
		}
		offset += SNES_BANK_SIZE;
		vaddr += SNES_BANK_SIZE;
	}

	return ret;
}

static RzPVector /*<RzBinSection *>*/ *snes_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);

	size_t file_size = rz_buf_size(bf->buf);
	const SNESRom *rom = bf->o->bin_obj;

	switch (rom->mode.map) {
	case SNES_ROM_MODE_LOROM_32K:
		/* fall-thru */
	case SNES_ROM_MODE_LOROM_32K_S_DD1:
		/* fall-thru */
	case SNES_ROM_MODE_LOROM_32K_SA_1:
		return snes_lorom_to_sections(rom, file_size);
	case SNES_ROM_MODE_HIROM_64K_SPC7110:
		/* fall-thru */
	case SNES_ROM_MODE_HIROM_64K:
		return snes_hirom_to_sections(rom, file_size);
	case SNES_ROM_MODE_EXTHIROM_64K:
		RZ_LOG_ERROR("SNES: ExtHiROM 64K not supported\n");
		return NULL;
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static RzBinMem *snes_memory_new(char *name, ut64 address, size_t size) {
	RzBinMem *mem = RZ_NEW0(RzBinMem);
	if (!mem) {
		return NULL;
	}
	mem->name = name;
	mem->addr = address;
	mem->size = size;
	mem->perms = RZ_PERM_RWX;
	return mem;
}

static bool snes_add_memory_bank(RzPVector /*<RzBinMem *>*/ *ret, const char *name, ut64 address, ut64 mirror, size_t size) {
	ut32 bank_id = SNES_VADDR_TO_BANK(address);
	char *mem_name = rz_str_newf("%s_%02x", name, bank_id);
	RzBinMem *mem = snes_memory_new(mem_name, address, size);
	if (!mem) {
		return false;
	}

	if (mirror == UT64_MAX) {
		rz_pvector_push(ret, mem);
		return true;
	}

	mem->mirrors = rz_pvector_new(rz_bin_mem_free);
	if (!mem->mirrors) {
		rz_bin_mem_free(mem);
		return false;
	}

	bank_id = SNES_VADDR_TO_BANK(mirror);
	mem_name = rz_str_newf("%s_%02x", name, bank_id);
	RzBinMem *mirror_region = snes_memory_new(mem_name, mirror, size);
	if (!mirror_region) {
		rz_bin_mem_free(mem);
		return false;
	}

	rz_pvector_push(mem->mirrors, mirror_region);
	rz_pvector_push(ret, mem);
	return true;
}

static RzPVector /*<RzBinMem *>*/ *snes_lorom_memory(void) {
	RzPVector *memory_map = rz_pvector_new(rz_bin_mem_free);
	if (!memory_map) {
		return NULL;
	}

	// Mirror region is always the lower banks.
	for (size_t bank_id = 0x00; bank_id < 0x40; ++bank_id) {
		ut64 mirror = SNES_BANK_TO_VADDR(bank_id);
		ut64 original = SNES_BANK_TO_VADDR(0x80 + bank_id);
		// lowRAM starts always at 0x0000 and ends at 0x2000 for each bank
		if (!snes_add_memory_bank(memory_map, "LowRAM", original, mirror, SNES_LOWRAM_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}

		// I/O starts always at 0x2000 and ends at 0x6000 for each bank
		if (!snes_add_memory_bank(memory_map, "IO", original + 0x2000, mirror + 0x2000, SNES_IO_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}

		// ROM mirror is at offset 0x8000
		if (!snes_add_memory_bank(memory_map, "ROM", original + 0x8000, mirror + 0x8000, SNES_LOROM_ROM_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	// Mirror region is always the lower banks.
	for (size_t bank_id = 0x40; bank_id < 0x70; ++bank_id) {
		// ROM mirror is at offset 0x8000
		ut64 mirror = SNES_BANK_TO_VADDR(bank_id) + 0x8000;
		ut64 original = SNES_BANK_TO_VADDR(0x80 + bank_id) + 0x8000;
		if (!snes_add_memory_bank(memory_map, "ROM", original, mirror, SNES_LOROM_ROM_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	// LoROM SRAM is at 0x0000-0x8000 in banks 0x70-0x7D
	for (size_t bank_id = 0x70; bank_id < 0x7e; ++bank_id) {
		ut64 address = SNES_BANK_TO_VADDR(bank_id);
		if (!snes_add_memory_bank(memory_map, "SRAM", address, UT64_MAX, SNES_LOROM_WRAM_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}

		// ROM mirror is at offset 0x8000
		ut64 original = SNES_BANK_TO_VADDR(0x80 + bank_id) + 0x8000;
		address += 0x8000;
		if (!snes_add_memory_bank(memory_map, "ROM", original, address, SNES_LOROM_ROM_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	// LoROM WRAM is at 0x0000-0x10000 in banks 0x7E-0x7F
	for (size_t bank_id = 0x7e; bank_id < 0x80; ++bank_id) {
		ut64 address = SNES_BANK_TO_VADDR(bank_id);
		if (!snes_add_memory_bank(memory_map, "WRAM", address, UT64_MAX, SNES_WRAM_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	return memory_map;
}

static RzPVector /*<RzBinMem *>*/ *snes_hirom_memory(void) {
	RzPVector *memory_map = rz_pvector_new(rz_bin_mem_free);
	if (!memory_map) {
		rz_warn_if_reached();
		return NULL;
	}

	// Mirror region is always the lower banks.
	for (size_t bank_id = 0x00; bank_id < 0x40; ++bank_id) {
		ut64 mirror = SNES_BANK_TO_VADDR(bank_id);
		ut64 original = SNES_BANK_TO_VADDR(0x80 + bank_id);
		// lowRAM starts always at 0x0000 and ends at 0x2000 for each bank
		if (!snes_add_memory_bank(memory_map, "LowRAM", original, mirror, SNES_LOWRAM_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}

		// I/O starts always at 0x2000 and ends at 0x6000 for each bank
		if (!snes_add_memory_bank(memory_map, "IO", original + 0x2000, mirror + 0x2000, SNES_IO_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}

		if (bank_id > 0x2f) {
			// HiROM SRAM starts always at 0x6000 and ends at 0x8000 for bank 0x30-0x3F
			if (!snes_add_memory_bank(memory_map, "SRAM", original + 0x6000, UT64_MAX, SNES_HIROM_WRAM_BANK_SIZE)) {
				rz_warn_if_reached();
				rz_pvector_free(memory_map);
				return NULL;
			}
		}

		// ROM mirror is at offset 0x8000
		// banks 0x00-0x3F only have 0x0000-0x7fff at 0x8000 offset
		original = SNES_BANK_TO_VADDR(0xC0 + bank_id);
		if (!snes_add_memory_bank(memory_map, "ROM", original, mirror + 0x8000, SNES_HIROM_MIRROR_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	// LoROM WRAM is at 0x0000-0x10000 in banks 0x7E-0x7F
	for (size_t bank_id = 0x7e; bank_id < 0x80; ++bank_id) {
		ut64 address = SNES_BANK_TO_VADDR(bank_id);
		if (!snes_add_memory_bank(memory_map, "WRAM", address, UT64_MAX, SNES_WRAM_BANK_SIZE)) {
			rz_warn_if_reached();
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	// HiROM mirror is at offset 0x8000 in banks 0x80-0xBF
	// banks 0x80-0xBF only have 0x8000-0x10000 of banks 0xC0-0xFF
	for (size_t bank_id = 0x80; bank_id < 0xC0; ++bank_id) {
		ut64 mirror = SNES_BANK_TO_VADDR(bank_id) + 0x8000;
		ut64 original = SNES_BANK_TO_VADDR(0xC0 + bank_id) + 0x8000;
		if (!snes_add_memory_bank(memory_map, "ROM", original, mirror, SNES_HIROM_MIRROR_SIZE)) {
			rz_pvector_free(memory_map);
			return NULL;
		}
	}

	return memory_map;
}

static int snes_memory_compare(const RzBinMem *a, const RzBinMem *b, void *user) {
	if (b->addr > a->addr) {
		return -1;
	} else if (b->addr < a->addr) {
		return 1;
	}
	return 0;
}

static RzPVector /*<RzBinMem *>*/ *snes_memory(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	const SNESRom *rom = bf->o->bin_obj;
	RzPVector /*<RzBinMem *>*/ *memory_map = NULL;

	switch (rom->mode.map) {
	case SNES_ROM_MODE_LOROM_32K:
		/* fall-thru */
	case SNES_ROM_MODE_LOROM_32K_S_DD1:
		/* fall-thru */
	case SNES_ROM_MODE_LOROM_32K_SA_1:
		memory_map = snes_lorom_memory();
		break;
	case SNES_ROM_MODE_HIROM_64K_SPC7110:
		/* fall-thru */
	case SNES_ROM_MODE_HIROM_64K:
		memory_map = snes_hirom_memory();
		break;
	case SNES_ROM_MODE_EXTHIROM_64K:
		RZ_LOG_ERROR("SNES: ExtHiROM 64K not supported\n");
		return NULL;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	// sort before doing anything.
	rz_pvector_sort(memory_map, (RzPVectorComparator)snes_memory_compare, NULL);

	return memory_map;
}

static RzBinAddr *snes_bin_addr_new(const SNESRom *rom, RzBinSpecialSymbol type, ut64 vaddr) {
	RzBinAddr *ba = RZ_NEW0(RzBinAddr);
	if (!ba) {
		return NULL;
	}
	ba->type = type;
	ba->vaddr = ba->hvaddr = vaddr;

	// SNES jumps to ROM mirror somewhere in bank 0
	// In LoROM bank 0 is mapped at 0x80:8000, but mirrored at 0x00:8000
	// In HiROM bank 0 is mapped at 0xC0:0000, but mirrored at 0x00:8000
	// In ExHiROM bank 0 is mapped at 0xC0:0000, but mirrored at 0x00:8000
	// the rom may have the dumper header, we need to add the skip_offset
	ba->paddr = rom->skip_offset + (vaddr - 0x8000);
	ba->hpaddr = ba->paddr;
	return ba;
}

static RzPVector /*<RzBinAddr *>*/ *snes_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	const SNESRom *rom = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *ptr = snes_bin_addr_new(rom, RZ_BIN_SPECIAL_SYMBOL_ENTRY, rom->vectors.reset);
	if (!ptr) {
		rz_pvector_free(ret);
		return NULL;
	}
	rz_pvector_push(ret, ptr);
	return ret;
}

static char *snes_rom_get_map_mode(const SNESRom *rom) {
	switch (rom->mode.map) {
	case SNES_ROM_MODE_LOROM_32K:
		return rz_str_dup("LoROM 32K Banks (LoROM)");
	case SNES_ROM_MODE_HIROM_64K:
		return rz_str_dup("HiROM 64K Banks (HiROM)");
	case SNES_ROM_MODE_LOROM_32K_S_DD1:
		return rz_str_dup("LoROM 32K Banks + S-DD1 (LoROM Super MMC)");
	case SNES_ROM_MODE_LOROM_32K_SA_1:
		return rz_str_dup("LoROM 32K Banks + SA-1 (LoROM Emulates Super MMC)");
	case SNES_ROM_MODE_EXTHIROM_64K:
		return rz_str_dup("HiROM 64K Banks (ExtHiROM)");
	case SNES_ROM_MODE_HIROM_64K_SPC7110:
		return rz_str_dup("HiROM 64K Banks + SPC7110 (HiROM)");
	default:
		return rz_str_newf("unknown %u", (ut32)rom->mode.map);
	}
}

static const char *snes_rom_get_cartridge_type_base(const SNESRom *rom) {
	ut8 base = rom->cartridge_type & 0x0f;
	switch (base) {
	case 0x0:
		if (rz_str_ncasecmp(rom->game_title, "042J", 4)) {
			return "ROM+SGB2";
		}
		return "ROM";
	case 0x1: return "ROM+RAM";
	case 0x2:
		if (!rz_str_ncasecmp(rom->game_title, "XBAND", 4)) {
			return "ROM+RAM+Batt+XBandModem";
		} else if (!rz_str_ncasecmp(rom->game_title, "MENU", 4)) {
			return "ROM+RAM+Batt+NintendoPower";
		}
		return "ROM+RAM+Battery";
	case 0x3: return "ROM";
	case 0x4: return "ROM+RAM";
	case 0x5: return "ROM+RAM+Battery";
	case 0x6: return "ROM+Battery";
	case 0x9: return "ROM+RAM+Battery+RTC-4513";
	case 0xa: return "ROM+RAM+Battery+GSU1";
	default:
		rz_warn_if_reached();
		return "ROM";
	}
}

static const char *snes_rom_get_custom_coprocessor(const SNESRom *rom) {
	switch (rom->coprocessor) {
	case 0x00: return "SPC7110";
	case 0x01: return "ST010/ST011";
	case 0x02: return "ST018";
	case 0x10: return "CX4";
	default:
		rz_warn_if_reached();
		return "Unknown";
	}
}

static const char *snes_rom_get_cartridge_type_coprocessor(const SNESRom *rom) {
	ut8 cop = rom->cartridge_type >> 4;
	switch (cop) {
	case 0x0: {
		if (rom->cartridge_type == 0 ||
			rom->cartridge_type == 1 ||
			rom->cartridge_type == 2) {
			// no coprocessor
			return NULL;
		}
		return "DSP"; // (DSP1,DSP1A,DSP1B,DSP2,DSP3,DSP4)
	}
	case 0x1: return "GSU"; // (MarioChip1,GSU1,GSU2,GSU2-SP1)
	case 0x2: return "OBC1";
	case 0x3: return "SA-1";
	case 0x4: return "S-DD1";
	case 0x5: return "S-RTC";
	case 0xe: {
		if (rom->cartridge_type == 0xe3) {
			return "Super Gameboy";
		} else if (rom->cartridge_type == 0xe5) {
			return "Satellaview";
		}
		return "Other";
	}
	case 0xF:
		return snes_rom_get_custom_coprocessor(rom);
	default:
		rz_warn_if_reached();
		return "Coprocessor";
	}
}

static char *snes_rom_get_cartridge_type(const SNESRom *rom) {
	const char *cop = snes_rom_get_cartridge_type_coprocessor(rom);
	const char *base = snes_rom_get_cartridge_type_base(rom);
	if (!cop) {
		return rz_str_dup(base);
	}
	return rz_str_newf("%s+%s", base, cop);
}

static char *snes_rom_get_rom_size(const SNESRom *rom) {
	ut32 size = 1u << rom->rom_size;
	if (rom->rom_size > 10) {
		return rz_str_newf("%u MB", size);
	}
	return rz_str_newf("%u KB", size);
}

static char *snes_rom_get_sram_size(const SNESRom *rom) {
	if (!rom->sram_size) {
		return NULL;
	}

	ut32 size = 1u << rom->sram_size;
	if (rom->sram_size > 10) {
		return rz_str_newf("%u MB", size);
	}
	return rz_str_newf("%u KB", size);
}

static const char *snes_rom_get_country(const SNESRom *rom) {
	switch (rom->country) {
	case 0x00: return "Japan (NTSC)";
	case 0x01: return "USA and Canada (NTSC)";
	case 0x02: return "Europe, Oceania, Asia (PAL)";
	case 0x03: return "Sweden, Scandinavia (PAL)";
	case 0x04: return "Finland (PAL)";
	case 0x05: return "Denmark (PAL)";
	case 0x06: return "France (SECAM, PAL-like 50Hz)";
	case 0x07: return "Holland (PAL)";
	case 0x08: return "Spain (PAL)";
	case 0x09: return "Germany, Austria, Switz (PAL)";
	case 0x0A: return "Italy (PAL)";
	case 0x0B: return "China, Hong Kong (PAL)";
	case 0x0C: return "Indonesia (PAL)";
	case 0x0D: return "South Korea (NTSC)";
	case 0x0E: return "Common";
	case 0x0F: return "Canada (NTSC)";
	case 0x10: return "Brazil (PAL-M, NTSC-like 60Hz)";
	case 0x11: return "Australia (PAL)";
	default: return "Other";
	}
}

static char *snes_rom_get_developer(const SNESRom *rom) {
	switch (rom->developer_id) {
	case 0x00: return rz_str_dup("None/Homebrew");
	case 0x01: return rz_str_dup("Nintendo");
	default: return rz_str_newf("unknown 0x%02x", (ut32)rom->developer_id);
	}
}

static RzStructuredData *snes_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	const SNESRom *rom = bf->o->bin_obj;

	char *game_title = rz_str_ndup(rom->game_title, sizeof(rom->game_title));
	char *map_mode = snes_rom_get_map_mode(rom);
	char *cartridge_type = snes_rom_get_cartridge_type(rom);
	char *size = NULL;
	char *developer_id = snes_rom_get_developer(rom);

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *rom_data = rz_structured_data_map_add_map(info, "snes_rom");
	if (!rom_data) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string(rom_data, "game_title", game_title);
	rz_structured_data_map_add_string(rom_data, "speed", rom->mode.fast_rom ? "fast" : "slow");
	rz_structured_data_map_add_string(rom_data, "map_mode", map_mode);
	rz_structured_data_map_add_string(rom_data, "cartridge", cartridge_type);

	size = snes_rom_get_rom_size(rom);
	rz_structured_data_map_add_string(rom_data, "size", size);
	RZ_FREE(size);

	if ((size = snes_rom_get_sram_size(rom))) {
		rz_structured_data_map_add_string(rom_data, "sram_size", size);
		RZ_FREE(size);
	}

	rz_structured_data_map_add_string(rom_data, "country", snes_rom_get_country(rom));
	rz_structured_data_map_add_string(rom_data, "developer", developer_id);
	rz_structured_data_map_add_unsigned(rom_data, "version", rom->rom_version, true);
	rz_structured_data_map_add_unsigned(rom_data, "checksum", rom->checksum, true);
	rz_structured_data_map_add_unsigned(rom_data, "checksum_compl", rom->checksum_compl, true);

	RzStructuredData *vectors = rz_structured_data_map_add_map(rom_data, "vectors");
	if (!vectors) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *native = rz_structured_data_map_add_map(vectors, "native");
	if (!native) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(native, "unused0", rom->vectors.unused0, true);
	rz_structured_data_map_add_unsigned(native, "cop", rom->vectors.native_cop, true);
	rz_structured_data_map_add_unsigned(native, "br", rom->vectors.native_br, true);
	rz_structured_data_map_add_unsigned(native, "abort", rom->vectors.native_abort, true);
	rz_structured_data_map_add_unsigned(native, "nmi", rom->vectors.native_nmi, true);
	rz_structured_data_map_add_unsigned(native, "unused1", rom->vectors.unused1, true);
	rz_structured_data_map_add_unsigned(native, "irq", rom->vectors.native_irq, true);

	RzStructuredData *emulator = rz_structured_data_map_add_map(vectors, "emulator");
	if (!emulator) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(emulator, "unused2", rom->vectors.unused2, true);
	rz_structured_data_map_add_unsigned(emulator, "cop", rom->vectors.emu_cop, true);
	rz_structured_data_map_add_unsigned(emulator, "unused3", rom->vectors.unused3, true);
	rz_structured_data_map_add_unsigned(emulator, "abort", rom->vectors.emu_abort, true);
	rz_structured_data_map_add_unsigned(emulator, "nmi", rom->vectors.emu_nmi, true);
	rz_structured_data_map_add_unsigned(emulator, "reset", rom->vectors.reset, true);
	rz_structured_data_map_add_unsigned(emulator, "irq", rom->vectors.emu_irq, true);

	free(developer_id);
	free(cartridge_type);
	free(map_mode);
	free(game_title);
	return info;
}

RzBinPlugin rz_bin_plugin_sfc = {
	.name = "sfc",
	.desc = "Super NES / Super Famicom ROM",
	.license = "LGPL3",
	.author = "usrshare",
	.load_buffer = &snes_load_buffer,
	.check_buffer = &snes_check_buffer,
	.bin_structure = &snes_structure,
	.entries = &snes_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = snes_sections,
	.symbols = &snes_symbols,
	.info = &snes_info,
	.mem = &snes_memory,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_sfc,
	.version = RZ_VERSION
};
#endif
