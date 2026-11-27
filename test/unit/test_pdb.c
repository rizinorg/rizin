// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_pdb.h>
#include <rz_endian.h>
#include "minunit.h"

// Regression cluster for the PDB TPI NULL-data crash.
//
// A malformed TPI type record whose leaf is a known aggregate (LF_STRUCTURE,
// LF_UNION, LF_ENUM, ...) but whose body is too short makes the per-leaf
// parser (class_parse / union_parse / enum_parse) fail and return NULL. Such a
// record used to be stored with its known kind and data == NULL, and the public
// accessors then dereferenced data by kind and crashed.
//
// These tests build exactly that degenerate record by hand and assert every
// public accessor handles it gracefully instead of dereferencing NULL.

static RzPdbTpiType make_null_data_type(RzPDBTpiKind kind, ut16 leaf) {
	RzPdbTpiType t = { 0 };
	t.index = 0x1000;
	t.leaf = leaf;
	t.kind = kind;
	t.data = NULL;
	return t;
}

bool test_pdb_is_fwdref_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505 /* LF_STRUCTURE */);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506 /* LF_UNION */);
	RzPdbTpiType e = make_null_data_type(TpiKind_ENUM, 0x1507 /* LF_ENUM */);
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&c), "CLASS with NULL data must not be a fwdref");
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&u), "UNION with NULL data must not be a fwdref");
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&e), "ENUM with NULL data must not be a fwdref");
	mu_end;
}

bool test_pdb_get_type_members_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506);
	RzPdbTpiType e = make_null_data_type(TpiKind_ENUM, 0x1507);
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &c), "CLASS with NULL data has no members");
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &u), "UNION with NULL data has no members");
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &e), "ENUM with NULL data has no members");
	mu_end;
}

bool test_pdb_get_type_val_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506);
	// Must return the neutral value rather than dereferencing NULL data.
	mu_assert_eq(rz_bin_pdb_get_type_val(&c), 0, "CLASS with NULL data must yield 0");
	mu_assert_eq(rz_bin_pdb_get_type_val(&u), 0, "UNION with NULL data must yield 0");
	mu_end;
}

bool test_pdb_get_type_name_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	mu_assert_null(rz_bin_pdb_get_type_name(&c), "CLASS with NULL data has no name");
	mu_end;
}

bool test_pdb_msf_dir_overflow(void) {
	// 256 streams of size 0x04000000 with block_size=16 wraps ut32 total_blocks * 4 to 0.
	static const char magic[32] = "Microsoft C/C++ MSF 7.00\r\n\x1a"
				      "DS\0\0";
	const ut32 bs = 16;
	const ut32 nstreams = 256;
	const ut32 msd_size = 4 + nstreams * 4;
	const ut32 dir_blks = (msd_size + bs - 1) / bs;
	const ut32 total_blks = 90;
	ut8 raw[90 * 16] = { 0 };

	memcpy(raw, magic, 32);
	rz_write_le32(raw + 32, bs);
	rz_write_le32(raw + 36, 1);
	rz_write_le32(raw + 40, total_blks);
	rz_write_le32(raw + 44, msd_size);
	rz_write_le32(raw + 48, 0);
	rz_write_le32(raw + 52, 4);
	for (ut32 i = 0; i < dir_blks; i++) {
		rz_write_le32(raw + bs * 4 + i * 4, 21 + i);
	}
	rz_write_le32(raw + bs * 21, nstreams);
	for (ut32 i = 0; i < nstreams; i++) {
		rz_write_le32(raw + bs * 21 + 4 + i * 4, 0x04000000);
	}

	RzBuffer *buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "create pdb buffer");
	RzPdb *pdb = rz_bin_pdb_parse_from_buf(buf);
	mu_assert_null(pdb, "overflowing MSF stream directory must fail cleanly");

	// Stream count exceeding num_directory_bytes must also fail cleanly before allocation.
	rz_write_le32(raw + bs * 21, 0x10000);
	buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "create oversized stream count pdb buffer");
	pdb = rz_bin_pdb_parse_from_buf(buf);
	mu_assert_null(pdb, "oversized MSF NumStreams must fail cleanly");
	mu_end;
}

bool test_pdb_invalid_stream_block_map(void) {
	// Stream 1 references an out-of-range block index inside pdb7_extract_streams(),
	// leaving trailing stream slots NULL so rz_pvector_free() exercises msf_stream_free(NULL).
	static const char magic[32] = "Microsoft C/C++ MSF 7.00\r\n\x1a"
				      "DS\0\0";
	const ut32 bs = 128;
	const ut32 total_blks = 8;
	const ut32 nstreams = 4;
	const ut32 msd_size = 4 + nstreams * 4 + 2 * 4;
	ut8 raw[8 * 128] = { 0 };

	memcpy(raw, magic, 32);
	rz_write_le32(raw + 32, bs);
	rz_write_le32(raw + 36, 1);
	rz_write_le32(raw + 40, total_blks);
	rz_write_le32(raw + 44, msd_size);
	rz_write_le32(raw + 48, 0);
	rz_write_le32(raw + 52, 2); // block_map_addr = block 2

	rz_write_le32(raw + bs * 2, 3); // directory block -> block 3

	ut8 *dir = raw + bs * 3;
	rz_write_le32(dir + 0, nstreams);
	rz_write_le32(dir + 4, 0); // stream 0: 0 bytes (populated before failure)
	rz_write_le32(dir + 8, 28); // stream 1: 1 block (invalid block_idx triggers failure)
	rz_write_le32(dir + 12, 28); // stream 2: 1 block (remains NULL in streams pvector)
	rz_write_le32(dir + 16, 0); // stream 3: 0 bytes (remains NULL in streams pvector)
	rz_write_le32(dir + 20, total_blks); // OOB block_idx for stream 1
	rz_write_le32(dir + 24, 4); // block_idx for stream 2

	RzBuffer *buf = rz_buf_new_with_bytes(raw, sizeof(raw));
	mu_assert_notnull(buf, "create invalid stream block map pdb buffer");
	RzPdb *pdb = rz_bin_pdb_parse_from_buf(buf);
	mu_assert_null(pdb, "out-of-range stream block index must fail cleanly");
	mu_end;
}

static RzBuffer *make_synthetic_pdb_buf(const ut8 *omap_data, ut32 omap_sz, const ut8 *pe_data, ut32 pe_sz) {
	static const char magic[32] = "Microsoft C/C++ MSF 7.00\r\n\x1a"
				      "DS\0\0";
	const ut32 bs = 128;
	const ut32 total_blks = 16;
	ut8 raw[16 * 128] = { 0 };

	// Streams: 0=root(0B), 1=PDB(28B, blk 4), 2=TPI(56B, blk 5), 3=DBI(86B, blk 6),
	//          4=OMAP(omap_sz, blk 7 if >0), 5=PE(pe_sz, blk 8 if >0)
	ut32 sizes[6] = { 0, 28, 56, 86, omap_sz, pe_sz };
	ut32 blks[6] = { 0, 4, 5, 6, 7, 8 };
	ut32 nblks = 0;
	for (ut32 i = 0; i < 6; i++) {
		if (sizes[i] > 0) {
			nblks++;
		}
	}
	const ut32 msd_size = 4 + 6 * 4 + nblks * 4;

	memcpy(raw, magic, 32);
	rz_write_le32(raw + 32, bs);
	rz_write_le32(raw + 36, 1);
	rz_write_le32(raw + 40, total_blks);
	rz_write_le32(raw + 44, msd_size);
	rz_write_le32(raw + 48, 0);
	rz_write_le32(raw + 52, 2); // block_map_addr = block 2

	// Block 2: directory block map -> block 3
	rz_write_le32(raw + bs * 2, 3);

	// Block 3: MSF stream directory
	ut8 *dir = raw + bs * 3;
	rz_write_le32(dir, 6);
	ut32 off = 4;
	for (ut32 i = 0; i < 6; i++) {
		rz_write_le32(dir + off, sizes[i]);
		off += 4;
	}
	for (ut32 i = 0; i < 6; i++) {
		if (sizes[i] > 0) {
			rz_write_le32(dir + off, blks[i]);
			off += 4;
		}
	}

	// Block 4: Stream 1 (PDB header, VC70 = 20000404)
	rz_write_le32(raw + bs * 4, 20000404);

	// Block 5: Stream 2 (TPI header: HeaderSize=56, TypeIndexBegin=0x1000, TypeIndexEnd=0x1000)
	ut8 *tpi = raw + bs * 5;
	rz_write_le32(tpi + 4, 56);
	rz_write_le32(tpi + 8, 0x1000);
	rz_write_le32(tpi + 12, 0x1000);

	// Block 6: Stream 3 (DBI 64B header + 22B dbg_hdr)
	ut8 *dbi = raw + bs * 6;
	rz_write_le16(dbi + 20, 0xffff); // sym_record_stream = none
	ut8 *dbg_hdr = dbi + 64;
	for (ut32 i = 0; i < 11; i++) {
		rz_write_le16(dbg_hdr + i * 2, 0xffff);
	}
	if (omap_sz > 0) {
		rz_write_le16(dbg_hdr + 3 * 2, 4); // sn_omap_to_src = stream 4
	}
	if (pe_sz > 0) {
		rz_write_le16(dbg_hdr + 5 * 2, 5); // sn_section_hdr = stream 5
	}

	if (omap_data && omap_sz > 0 && omap_sz <= bs) {
		memcpy(raw + bs * 7, omap_data, omap_sz);
	}
	if (pe_data && pe_sz > 0 && pe_sz <= bs) {
		memcpy(raw + bs * 8, pe_data, pe_sz);
	}

	return rz_buf_new_with_bytes(raw, sizeof(raw));
}

bool test_pdb_omap_and_pe_streams(void) {
	// Valid OMAP + PE stream: exercise pdb_omap_remap() allocating froms and omap_stream_free() freeing it.
	ut8 valid_omap[16] = { 0 };
	rz_write_le32(valid_omap + 0, 0x1000);
	rz_write_le32(valid_omap + 4, 0x2000);
	rz_write_le32(valid_omap + 8, 0x2000);
	rz_write_le32(valid_omap + 12, 0x3000);

	ut8 valid_pe[40] = { 0 };
	memcpy(valid_pe, ".text\0\0\0", 8);
	rz_write_le32(valid_pe + 12, 0x1000); // virtual_address

	RzBuffer *buf = make_synthetic_pdb_buf(valid_omap, sizeof(valid_omap), valid_pe, sizeof(valid_pe));
	mu_assert_notnull(buf, "create valid omap+pe pdb buffer");
	RzPdb *pdb = rz_bin_pdb_parse_from_buf(buf);
	mu_assert_notnull(pdb, "parse valid synthetic pdb");
	PDBSectionOffset sec_off = { .section_index = 1, .offset = 0 };
	(void)rz_bin_pdb_to_rva(pdb, &sec_off);
	rz_bin_pdb_free(pdb);

	// Truncated OMAP stream (4 bytes < 8-byte OmapEntry) must fail cleanly without double-free.
	ut8 trunc_omap[4] = { 0x01, 0x02, 0x03, 0x04 };
	buf = make_synthetic_pdb_buf(trunc_omap, sizeof(trunc_omap), NULL, 0);
	mu_assert_notnull(buf, "create truncated omap pdb buffer");
	mu_assert_null(rz_bin_pdb_parse_from_buf(buf), "truncated omap stream fails cleanly");

	// Truncated PE stream (16 bytes < 40-byte PeImageSectionHeader) must fail cleanly without double-free.
	ut8 trunc_pe[16] = { 0 };
	buf = make_synthetic_pdb_buf(NULL, 0, trunc_pe, sizeof(trunc_pe));
	mu_assert_notnull(buf, "create truncated pe pdb buffer");
	mu_assert_null(rz_bin_pdb_parse_from_buf(buf), "truncated pe stream fails cleanly");

	mu_end;
}

int all_tests(void) {
	mu_run_test(test_pdb_is_fwdref_null_data);
	mu_run_test(test_pdb_get_type_members_null_data);
	mu_run_test(test_pdb_get_type_val_null_data);
	mu_run_test(test_pdb_get_type_name_null_data);
	mu_run_test(test_pdb_msf_dir_overflow);
	mu_run_test(test_pdb_invalid_stream_block_map);
	mu_run_test(test_pdb_omap_and_pe_streams);
	return tests_passed != tests_run;
}

mu_main(all_tests)
