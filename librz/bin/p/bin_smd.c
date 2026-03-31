// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

/**
 * \file bin_smd.c
 *
 * Implements the parser for the Super Magic Drive (SEGA Genesis / MegaDrive) ROM
 */

#define SMD_VECTORS_OFFSET 0
#define SMD_VECTORS_SIZE   0x100
#define SMD_HEADER_OFFSET  0x100
#define SMD_HEADER_SIZE    0x100
#define SMD_TEXT_OFFSET    0x200

enum smd_vectors_e {
	SMD_VECTOR_SSP = 0,
	SMD_VECTOR_RESET,
	SMD_VECTOR_BUSERR,
	SMD_VECTOR_ADRERR,
	SMD_VECTOR_INVOPCODE,
	SMD_VECTOR_DIVBY0,
	SMD_VECTOR_CHECK,
	SMD_VECTOR_TRAPV,
	SMD_VECTOR_GPF,
	SMD_VECTOR_TRACE,
	SMD_VECTOR_RESERV_0,
	SMD_VECTOR_RESERV_1,
	SMD_VECTOR_RESERV_2,
	SMD_VECTOR_RESERV_3,
	SMD_VECTOR_RESERV_4,
	SMD_VECTOR_BADINT,
	SMD_VECTOR_RESERV_10,
	SMD_VECTOR_RESERV_11,
	SMD_VECTOR_RESERV_12,
	SMD_VECTOR_RESERV_13,
	SMD_VECTOR_RESERV_14,
	SMD_VECTOR_RESERV_15,
	SMD_VECTOR_RESERV_16,
	SMD_VECTOR_RESERV_17,
	SMD_VECTOR_BADIRQ,
	SMD_VECTOR_IRQ_1,
	SMD_VECTOR_EXT,
	SMD_VECTOR_IRQ_3,
	SMD_VECTOR_HBLANK,
	SMD_VECTOR_IRQ_5,
	SMD_VECTOR_VBLANK,
	SMD_VECTOR_IRQ_7,
	SMD_VECTOR_TRAP0,
	SMD_VECTOR_TRAP1,
	SMD_VECTOR_TRAP2,
	SMD_VECTOR_TRAP3,
	SMD_VECTOR_TRAP4,
	SMD_VECTOR_TRAP5,
	SMD_VECTOR_TRAP6,
	SMD_VECTOR_TRAP7,
	SMD_VECTOR_TRAP8,
	SMD_VECTOR_TRAP9,
	SMD_VECTOR_TRAP10,
	SMD_VECTOR_TRAP11,
	SMD_VECTOR_TRAP12,
	SMD_VECTOR_TRAP13,
	SMD_VECTOR_TRAP14,
	SMD_VECTOR_TRAP15,
	SMD_VECTOR_RESERV_30,
	SMD_VECTOR_RESERV_31,
	SMD_VECTOR_RESERV_32,
	SMD_VECTOR_RESERV_33,
	SMD_VECTOR_RESERV_34,
	SMD_VECTOR_RESERV_35,
	SMD_VECTOR_RESERV_36,
	SMD_VECTOR_RESERV_37,
	SMD_VECTOR_RESERV_38,
	SMD_VECTOR_RESERV_39,
	SMD_VECTOR_RESERV_3A,
	SMD_VECTOR_RESERV_3B,
	SMD_VECTOR_RESERV_3C,
	SMD_VECTOR_RESERV_3D,
	SMD_VECTOR_RESERV_3E,
	SMD_VECTOR_RESERV_3F,
	/// end
	SMD_VECTORS_ENUM_MAX // 64
};

typedef struct smd_s {
	ut32 vectors[SMD_VECTORS_ENUM_MAX];
	char System[16];
	char Publisher[16];
	char DomesticTitle[48];
	char ExportTitle[48];
	char SerialNumber[14];
	ut16 CheckSum;
	char Peripherials[16];
	ut32 RomStart;
	ut32 RomEnd;
	ut32 RamStart;
	ut32 RamEnd;
	ut8 SramCode[12];
	ut8 ModemCode[12];
	ut8 Reserved[40];
	char CountryCode[16];
} smd_t;

const char *vectors_names[SMD_VECTORS_ENUM_MAX] = {
	// clang-format off
	"SSP", "Reset", "BusErr", "AdrErr", "InvOpCode", "DivBy0", "Check",
	"TrapV", "GPF", "Trace", "Reserv0", "Reserv1", "Reserv2", "Reserv3", "Reserv4",
	"BadInt", "Reserv10", "Reserv11", "Reserv12", "Reserv13", "Reserv14", "Reserv15",
	"Reserv16", "Reserv17", "BadIRQ", "IRQ1", "EXT", "IRQ3", "HBLANK", "IRQ5",
	"VBLANK", "IRQ7", "Trap0", "Trap1", "Trap2", "Trap3", "Trap4", "Trap5", "Trap6",
	"Trap7", "Trap8", "Trap9", "Trap10", "Trap11", "Trap12", "Trap13", "Trap14",
	"Trap15", "Reserv30", "Reserv31", "Reserv32", "Reserv33", "Reserv34", "Reserv35",
	"Reserv36", "Reserv37", "Reserv38", "Reserv39", "Reserv3A", "Reserv3B", "Reserv3C",
	"Reserv3D", "Reserv3E", "Reserv3F",
	// clang-format on
};

static bool smd_parse_vectors(RzBuffer *buf, ut64 *off, smd_t *hdr) {
	for (size_t i = 0; i < SMD_VECTORS_ENUM_MAX; ++i) {
		if (!rz_buf_read_be32_offset(buf, off, &hdr->vectors[i])) {
			return false;
		}
	}
	return true;
}

static bool smd_parse_header(RzBuffer *buf, ut64 off, smd_t *hdr) {
	return smd_parse_vectors(buf, &off, hdr) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->System, sizeof(hdr->System)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->Publisher, sizeof(hdr->Publisher)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->DomesticTitle, sizeof(hdr->DomesticTitle)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->ExportTitle, sizeof(hdr->ExportTitle)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->SerialNumber, sizeof(hdr->SerialNumber)) &&
		rz_buf_read_be16_offset(buf, &off, &hdr->CheckSum) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->Peripherials, sizeof(hdr->Peripherials)) &&
		rz_buf_read_be32_offset(buf, &off, &hdr->RomStart) &&
		rz_buf_read_be32_offset(buf, &off, &hdr->RomEnd) &&
		rz_buf_read_be32_offset(buf, &off, &hdr->RamStart) &&
		rz_buf_read_be32_offset(buf, &off, &hdr->RamEnd) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->SramCode, sizeof(hdr->SramCode)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->ModemCode, sizeof(hdr->ModemCode)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->Reserved, sizeof(hdr->Reserved)) &&
		rz_buf_read_offset(buf, &off, (ut8 *)hdr->CountryCode, sizeof(hdr->CountryCode));
}

static bool smd_check_buffer(RzBuffer *b) {
	ut8 buf[4] = { 0 };
	if (rz_buf_size(b) <= 0x190 ||
		rz_buf_read_at(b, SMD_HEADER_OFFSET, buf, sizeof(buf)) != sizeof(buf)) {
		return false;
	}

	return !memcmp(buf, "SEGA", 4);
}

static bool smd_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	smd_t *hdr = RZ_NEW0(smd_t);
	if (!hdr) {
		return false;
	}

	if (!smd_parse_header(buf, SMD_VECTORS_OFFSET, hdr)) {
		free(hdr);
		return false;
	}

	obj->bin_obj = hdr;
	return true;
}

static void smd_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}

	RZ_FREE(bf->o->bin_obj);
}

static ut64 smd_baddr(RzBinFile *bf) {
	return 0;
}

static RzBinInfo *smd_info(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const smd_t *hdr = bf->o->bin_obj;

	RzBinInfo *ret = NULL;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("ROM");
	ret->machine = rz_str_dup("Sega Megadrive");
	ret->bclass = rz_str_ndup(hdr->System, sizeof(hdr->System));
	ret->os = rz_str_dup("smd");
	ret->arch = rz_str_dup("m68k");
	ret->bits = 32;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

static void smd_add_symbol(RzPVector /*<RzBinSymbol *>*/ *ret, const char *name, ut64 addr, size_t size, size_t ordinal) {
	RzBinSymbol *ptr = RZ_NEW0(RzBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = rz_str_dup(name);
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = ordinal;
	rz_pvector_push(ret, ptr);
}

static RzPVector /*<RzBinSymbol *>*/ *smd_symbols(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	const smd_t *hdr = bf->o->bin_obj;
	RzPVector *ret = NULL;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}

	for (size_t i = 0; i < SMD_VECTORS_ENUM_MAX; i++) {
		if (!hdr->vectors[i]) {
			continue;
		}

		smd_add_symbol(ret, vectors_names[i], hdr->vectors[i], sizeof(ut32), i);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *smd_sections(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const smd_t *hdr = bf->o->bin_obj;
	RzPVector *ret = NULL;

	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	RzBinSection *ptr;
	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup(".vectors");
	ptr->paddr = ptr->vaddr = SMD_VECTORS_OFFSET;
	ptr->size = ptr->vsize = SMD_VECTORS_SIZE;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup(".header");
	ptr->paddr = ptr->vaddr = SMD_HEADER_OFFSET;
	ptr->size = ptr->vsize = SMD_HEADER_SIZE;
	ptr->perm = RZ_PERM_R;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup(".text");
	ptr->paddr = SMD_TEXT_OFFSET;
	ptr->vaddr = SMD_TEXT_OFFSET + hdr->RomStart;
	ptr->size = ptr->vsize = hdr->RomEnd - hdr->RomStart;
	ptr->perm = RZ_PERM_RX;
	rz_pvector_push(ret, ptr);

	if (!(ptr = RZ_NEW0(RzBinSection))) {
		return ret;
	}
	ptr->name = rz_str_dup(".ram");
	ptr->paddr = UT64_MAX;
	ptr->size = 0;
	ptr->vaddr = hdr->RamStart;
	ptr->vsize = (hdr->RamEnd - hdr->RamStart) - SMD_TEXT_OFFSET;
	ptr->perm = RZ_PERM_RWX;
	rz_pvector_push(ret, ptr);

	return ret;
}

// Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
static RzPVector /*<RzBinAddr *>*/ *smd_entries(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	const smd_t *hdr = bf->o->bin_obj;

	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}

	ptr->paddr = ptr->vaddr = hdr->vectors[SMD_VECTOR_RESET];
	rz_pvector_push(ret, ptr);
	return ret;
}

static RzPVector /*<RzBinString *>*/ *smd_strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	// we only search strings with a minimum length of 10 bytes.
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.min_length = 10;
	return rz_bin_file_strings(bf, &opt);
}

static void smd_vectors_structure(const smd_t *hdr, RzStructuredData *parent) {
	RzStructuredData *vecs = rz_structured_data_map_add_map(parent, "vectors");
	if (!vecs) {
		return;
	}

	for (size_t i = 0; i < SMD_VECTORS_ENUM_MAX; i++) {
		if (!hdr->vectors[i]) {
			continue;
		}

		rz_structured_data_map_add_unsigned(vecs, vectors_names[i], hdr->vectors[i], true);
	}
}

static void smd_header_structure(const smd_t *hdr, RzStructuredData *parent) {
	RzStructuredData *header = rz_structured_data_map_add_map(parent, "header");
	if (!header) {
		return;
	}

	rz_structured_data_map_add_string_n(header, "System", hdr->System, sizeof(hdr->System));
	rz_structured_data_map_add_string_n(header, "Publisher", hdr->Publisher, sizeof(hdr->Publisher));
	rz_structured_data_map_add_string_n(header, "DomesticTitle", hdr->DomesticTitle, sizeof(hdr->DomesticTitle));
	rz_structured_data_map_add_string_n(header, "ExportTitle", hdr->ExportTitle, sizeof(hdr->ExportTitle));
	rz_structured_data_map_add_string_n(header, "SerialNumber", hdr->SerialNumber, sizeof(hdr->SerialNumber));
	rz_structured_data_map_add_unsigned(header, "CheckSum", hdr->CheckSum, true);
	rz_structured_data_map_add_string_n(header, "Peripherials", hdr->Peripherials, sizeof(hdr->Peripherials));
	rz_structured_data_map_add_unsigned(header, "RomStart", hdr->RomStart, true);
	rz_structured_data_map_add_unsigned(header, "RomEnd", hdr->RomEnd, true);
	rz_structured_data_map_add_unsigned(header, "RamStart", hdr->RamStart, true);
	rz_structured_data_map_add_unsigned(header, "RamEnd", hdr->RamEnd, true);
	rz_structured_data_map_add_bytes(header, "SramCode", hdr->SramCode, sizeof(hdr->SramCode), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(header, "ModemCode", hdr->ModemCode, sizeof(hdr->ModemCode), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(header, "Reserved", hdr->Reserved, sizeof(hdr->Reserved), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_string_n(header, "CountryCode", hdr->CountryCode, sizeof(hdr->CountryCode));
}

static RzStructuredData *smd_structure(RzBinFile *bf) {
	const smd_t *hdr = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "smd");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	smd_vectors_structure(hdr, root);
	smd_header_structure(hdr, root);

	return info;
}
RzBinPlugin rz_bin_plugin_smd = {
	.name = "smd",
	.desc = "SEGA Genesis / MegaDrive ROM",
	.license = "LGPL3",
	.author = "pancake",
	.load_buffer = &smd_load_buffer,
	.check_buffer = &smd_check_buffer,
	.baddr = &smd_baddr,
	.entries = &smd_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &smd_sections,
	.symbols = &smd_symbols,
	.strings = &smd_strings,
	.info = &smd_info,
	.destroy = &smd_destroy,
	.bin_structure = &smd_structure,
	.strfilter = 'U'
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_smd,
	.version = RZ_VERSION
};
#endif
