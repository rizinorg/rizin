// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_endian.h>
#include "../../librz/bin/format/pe/pe.h"
#include "minunit.h"

#define PE_TEST_IMAGE_SIZE 0x600

static void build_synthetic_pe32(ut8 *buf, size_t size, ut16 characteristics) {
	memset(buf, 0, size);

	// DOS header: "MZ" magic and e_lfanew -> 0x40
	rz_write_at_le16(buf, 0x5a4d, 0x00);
	rz_write_at_le32(buf, 0x40, 0x3c);

	// NT signature ("PE\0\0") and COFF file header at 0x40
	rz_write_at_le32(buf, 0x00004550, 0x40);
	rz_write_at_le16(buf, PE_IMAGE_FILE_MACHINE_I386, 0x44);
	rz_write_at_le16(buf, 2, 0x46); // NumberOfSections
	rz_write_at_le16(buf, 0x00e0, 0x54); // SizeOfOptionalHeader
	rz_write_at_le16(buf, characteristics, 0x56);

	// Optional header (PE32) at 0x58
	rz_write_at_le16(buf, PE_IMAGE_FILE_TYPE_PE32, 0x58);
	rz_write_at_le32(buf, 0x200, 0x5c); // SizeOfCode
	rz_write_at_le32(buf, 0x200, 0x60); // SizeOfInitializedData
	rz_write_at_le32(buf, 0x1000, 0x68); // AddressOfEntryPoint
	rz_write_at_le32(buf, 0x1000, 0x6c); // BaseOfCode
	rz_write_at_le32(buf, 0x2000, 0x70); // BaseOfData
	rz_write_at_le32(buf, 0x00400000, 0x74); // ImageBase
	rz_write_at_le32(buf, 0x1000, 0x78); // SectionAlignment
	rz_write_at_le32(buf, 0x200, 0x7c); // FileAlignment
	rz_write_at_le16(buf, 4, 0x88); // MajorSubsystemVersion
	rz_write_at_le32(buf, 0x3000, 0x90); // SizeOfImage
	rz_write_at_le32(buf, 0x200, 0x94); // SizeOfHeaders
	rz_write_at_le16(buf, PE_IMAGE_SUBSYSTEM_WINDOWS_CUI, 0x9c);
	rz_write_at_le32(buf, PE_IMAGE_DIRECTORY_ENTRIES, 0xb4);
	// DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_BASERELOC] at 0xb8 + 5 * 8 = 0xe0
	rz_write_at_le32(buf, 0x2000, 0xe0);
	rz_write_at_le32(buf, 12, 0xe4);

	// Section 0: .text at 0x138 (RVA 0x1000, raw offset 0x200)
	memcpy(buf + 0x138, ".text", 5);
	rz_write_at_le32(buf, 0x100, 0x140); // VirtualSize
	rz_write_at_le32(buf, 0x1000, 0x144); // VirtualAddress
	rz_write_at_le32(buf, 0x200, 0x148); // SizeOfRawData
	rz_write_at_le32(buf, 0x200, 0x14c); // PointerToRawData
	rz_write_at_le32(buf,
		IMAGE_SCN_CNT_CODE | PE_IMAGE_SCN_MEM_EXECUTE | PE_IMAGE_SCN_MEM_READ,
		0x15c);

	// Section 1: .reloc at 0x160 (RVA 0x2000, raw offset 0x400)
	memcpy(buf + 0x160, ".reloc", 6);
	rz_write_at_le32(buf, 12, 0x168); // VirtualSize
	rz_write_at_le32(buf, 0x2000, 0x16c); // VirtualAddress
	rz_write_at_le32(buf, 0x200, 0x170); // SizeOfRawData
	rz_write_at_le32(buf, 0x400, 0x174); // PointerToRawData
	rz_write_at_le32(buf,
		IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | PE_IMAGE_SCN_MEM_READ,
		0x184);

	// .text body at 0x200: ret
	buf[0x200] = 0xc3;

	// .reloc block at 0x400: PageRVA = 0x1000, SizeOfBlock = 12, two HIGHLOW entries
	rz_write_at_le32(buf, 0x1000, 0x400);
	rz_write_at_le32(buf, 12, 0x404);
	rz_write_at_le16(buf, (PE_IMAGE_REL_BASED_HIGHLOW << 12) | 0x010, 0x408);
	rz_write_at_le16(buf, (PE_IMAGE_REL_BASED_HIGHLOW << 12) | 0x024, 0x40a);
}

static bool open_pe_bytes(const ut8 *bytes, size_t size, ut64 filter_rules,
	RzIO **io_out, RzBin **bin_out, RzBuffer **buf_out, RzBinFile **bf_out) {
	RzIO *io = rz_io_new();
	RzBin *bin = rz_bin_new();
	RzBuffer *buf = rz_buf_new_with_bytes(bytes, size);
	if (!io || !bin || !buf) {
		rz_buf_free(buf);
		rz_bin_free(bin);
		rz_io_free(io);
		return false;
	}
	rz_io_bind(io, &bin->iob);
	rz_bin_load_filter(bin, filter_rules);
	RzBinOptions bopt = { 0 };
	rz_bin_options_init(&bopt, 0, 0, 0, false);
	bopt.filename = "synthetic_pe32.exe";
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &bopt);
	if (!bf) {
		rz_buf_free(buf);
		rz_bin_free(bin);
		rz_io_free(io);
		return false;
	}
	*io_out = io;
	*bin_out = bin;
	*buf_out = buf;
	*bf_out = bf;
	return true;
}

bool test_pe_relocs_repeated_call(void) {
	ut8 image[PE_TEST_IMAGE_SIZE];
	build_synthetic_pe32(image, sizeof(image), 0x0102);

	RzIO *io = NULL;
	RzBin *bin = NULL;
	RzBuffer *buf = NULL;
	RzBinFile *bf = NULL;
	mu_assert_true(open_pe_bytes(image, sizeof(image), UT64_MAX, &io, &bin, &buf, &bf),
		"open synthetic PE32");
	mu_assert_notnull(bf->o, "bin object");
	mu_assert_notnull(bf->o->plugin, "bin plugin");
	mu_assert_notnull(bf->o->plugin->relocs, "pe relocs callback");

	RzPVector *first = bf->o->plugin->relocs(bf);
	mu_assert_notnull(first, "first relocs call non-NULL");
	mu_assert_eq(rz_pvector_len(first), 2, "expected 2 relocs on first call");

	RzPVector *second = bf->o->plugin->relocs(bf);
	mu_assert_notnull(second, "second relocs call non-NULL (no UAF)");
	mu_assert_eq(rz_pvector_len(second), 2, "expected 2 relocs on second call");

	static const ut64 exp_vaddrs[2] = { 0x1010, 0x1024 };
	static const ut64 exp_paddrs[2] = { 0x210, 0x224 };
	static const char *const exp_names[2] = { "pe_00001010", "pe_00001024" };

	for (size_t i = 0; i < 2; i++) {
		const RzBinReloc *r1 = rz_pvector_at(first, i);
		const RzBinReloc *r2 = rz_pvector_at(second, i);
		mu_assert_notnull(r1, "first reloc element");
		mu_assert_notnull(r2, "second reloc element");
		mu_assert_eq(r1->vaddr, exp_vaddrs[i], "expected reloc vaddr");
		mu_assert_eq(r1->paddr, exp_paddrs[i], "expected reloc paddr");
		mu_assert_eq(r1->type, PE_IMAGE_REL_BASED_HIGHLOW, "expected HIGHLOW type");
		mu_assert_eq(r2->vaddr, r1->vaddr, "matching vaddr across repeated calls");
		mu_assert_eq(r2->paddr, r1->paddr, "matching paddr across repeated calls");
		mu_assert_eq(r2->type, r1->type, "matching type across repeated calls");
		mu_assert_notnull(r1->symbol, "first reloc symbol");
		mu_assert_notnull(r2->symbol, "second reloc symbol");
		mu_assert_streq(r1->symbol->name, exp_names[i], "expected reloc symbol name");
		mu_assert_streq(r2->symbol->name, r1->symbol->name, "matching reloc symbol name");
	}

	rz_pvector_free(first);
	rz_pvector_free(second);
	rz_buf_free(buf);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_pe_relocs_unqueried_no_leak(void) {
	ut8 image[PE_TEST_IMAGE_SIZE];
	build_synthetic_pe32(image, sizeof(image), 0x0102);

	RzIO *io = NULL;
	RzBin *bin = NULL;
	RzBuffer *buf = NULL;
	RzBinFile *bf = NULL;
	mu_assert_true(open_pe_bytes(image, sizeof(image), 0, &io, &bin, &buf, &bf),
		"open synthetic PE32 with filter_rules=0");
	mu_assert_notnull(bf->o, "bin object");
	mu_assert_notnull(bf->o->bin_obj, "pe bin_obj");
	mu_assert_notnull(bf->o->relocs, "relocs storage");
	mu_assert_eq(bf->o->relocs->relocs_count, 0, "relocs skipped when filter_rules=0");

	const RzBinPEObj *pe = bf->o->bin_obj;
	mu_assert_notnull(pe->relocs, "bin->relocs initialized during load");
	mu_assert_eq(rz_vector_len(pe->relocs), 2, "expected 2 raw PE reloc entries");

	rz_buf_free(buf);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_pe_stripped_relocs(void) {
	ut8 image[PE_TEST_IMAGE_SIZE];
	build_synthetic_pe32(image, sizeof(image), 0x0102 | PE_IMAGE_FILE_RELOCS_STRIPPED);

	RzIO *io = NULL;
	RzBin *bin = NULL;
	RzBuffer *buf = NULL;
	RzBinFile *bf = NULL;
	mu_assert_true(open_pe_bytes(image, sizeof(image), UT64_MAX, &io, &bin, &buf, &bf),
		"open reloc-stripped synthetic PE32");
	mu_assert_notnull(bf->o, "bin object");
	mu_assert_notnull(bf->o->bin_obj, "pe bin_obj");
	mu_assert_notnull(bf->o->plugin, "bin plugin");
	mu_assert_notnull(bf->o->plugin->relocs, "pe relocs callback");

	const RzBinPEObj *pe = bf->o->bin_obj;
	mu_assert_null(pe->relocs, "bin->relocs NULL for stripped PE");
	mu_assert_null(bf->o->plugin->relocs(bf), "relocs() returns NULL for stripped PE");

	rz_buf_free(buf);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_pe_relocs_repeated_call);
	mu_run_test(test_pe_relocs_unqueried_no_leak);
	mu_run_test(test_pe_stripped_relocs);
	return tests_passed != tests_run;
}

mu_main(all_tests)
