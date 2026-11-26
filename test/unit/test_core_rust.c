// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_endian.h>
#include "minunit.h"

static void build_rust_pe64(ut8 *buf, size_t size, const char *data_sec_name, ut32 data_sec_sz) {
	memset(buf, 0, size);
	const ut64 image_base = 0x140000000ULL;
	ut32 data_vsize = RZ_ROUND(data_sec_sz, 0x1000);

	// DOS header
	rz_write_at_le16(buf, 0x5a4d, 0x00);
	rz_write_at_le32(buf, 0x40, 0x3c);

	// NT + COFF header (AMD64, 2 sections, PE32+ optional header 0xf0)
	rz_write_at_le32(buf, 0x00004550, 0x40);
	rz_write_at_le16(buf, 0x8664, 0x44);
	rz_write_at_le16(buf, 2, 0x46);
	rz_write_at_le16(buf, 0x00f0, 0x54);
	rz_write_at_le16(buf, 0x0022, 0x56);

	// Optional header (PE32+)
	rz_write_at_le16(buf, 0x020b, 0x58);
	rz_write_at_le32(buf, 0x200, 0x5c);
	rz_write_at_le32(buf, data_sec_sz, 0x60);
	rz_write_at_le32(buf, 0x1000, 0x68);
	rz_write_at_le32(buf, 0x1000, 0x6c);
	rz_write_at_le64(buf, image_base, 0x70);
	rz_write_at_le32(buf, 0x1000, 0x78);
	rz_write_at_le32(buf, 0x200, 0x7c);
	rz_write_at_le16(buf, 6, 0x88);
	rz_write_at_le32(buf, 0x2000 + data_vsize, 0x90);
	rz_write_at_le32(buf, 0x200, 0x94);
	rz_write_at_le16(buf, 3, 0x9c);
	rz_write_at_le32(buf, 16, 0xc4);

	// Section 0: .text (RVA 0x1000, raw 0x200, RX)
	memcpy(buf + 0x148, ".text", 5);
	rz_write_at_le32(buf, 0x200, 0x150);
	rz_write_at_le32(buf, 0x1000, 0x154);
	rz_write_at_le32(buf, 0x200, 0x158);
	rz_write_at_le32(buf, 0x200, 0x15c);
	rz_write_at_le32(buf, 0x60000020, 0x16c);

	// Section 1: data_sec_name (RVA 0x2000, raw 0x400, R)
	size_t nlen = RZ_MIN(strlen(data_sec_name), (size_t)8);
	memcpy(buf + 0x170, data_sec_name, nlen);
	rz_write_at_le32(buf, data_sec_sz, 0x178);
	rz_write_at_le32(buf, 0x2000, 0x17c);
	rz_write_at_le32(buf, data_sec_sz, 0x180);
	rz_write_at_le32(buf, 0x400, 0x184);
	rz_write_at_le32(buf, 0x40000040, 0x194);
}

static RzCore *open_synthetic_bin(const ut8 *buf, size_t size, ut64 image_base) {
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	char *uri = rz_str_newf("malloc://0x%" PFMT64x, (ut64)size);
	RzCoreFile *f = uri ? rz_core_file_open(core, uri, RZ_PERM_RW, 0) : NULL;
	free(uri);
	if (!f || rz_io_fd_write_at(core->io, f->fd, 0, buf, size) != (int)size ||
		!rz_core_bin_load(core, NULL, image_base)) {
		rz_core_free(core);
		return NULL;
	}
	return core;
}

static void emit_x64_lea_rip(ut8 *buf, size_t file_off, ut64 pc, ut8 rex, ut8 modrm_reg, ut64 target) {
	buf[file_off] = rex;
	buf[file_off + 1] = 0x8d;
	buf[file_off + 2] = (ut8)((modrm_reg << 3) | 0x05);
	st32 disp = (st32)((st64)target - (st64)(pc + 7));
	rz_write_at_le32(buf, (ut32)disp, file_off + 3);
}

bool test_rust_strings_panic_locations_and_main(void) {
	const ut64 base = 0x140000000ULL;
	ut8 img[0x800];
	build_rust_pe64(img, sizeof(img), ".rdata", 0x400);

	// Contiguous non-NUL-terminated Rust strings glued back-to-back in .rdata at RVA 0x2000:
	// [0x2000..0x2015] "https://example.invalid" (23)
	// [0x2017..0x2027] "X-Agent-Token: 1" (16)
	// [0x2027..0x2032] "src/main.rs" (11)
	// [0x2032..0x2079] "/home/u/.cargo/registry/src/index.crates.io-6f17/chacha20-0.9.1/src/lib.rs" (74)
	// [0x207c..0x2095] "/library/core/src/panicking.rs" (30)
	// [0x209a..0x20ab] "static_table_item" (17)
	const char *s1 = "https://example.invalid";
	const char *s2 = "X-Agent-Token: 1";
	const char *s_user = "src/main.rs";
	const char *s_crate = "/home/u/.cargo/registry/src/index.crates.io-6f17/chacha20-0.9.1/src/lib.rs";
	const char *s_std = "/library/core/src/panicking.rs";
	const char *s_static = "static_table_item";

	const ut64 off_s1 = 0x00;
	const ut64 off_s2 = off_s1 + strlen(s1); // directly concatenated, NO NUL!
	const ut64 off_user = off_s2 + strlen(s2); // directly concatenated, NO NUL!
	const ut64 off_crate = off_user + strlen(s_user);
	const ut64 off_std = off_crate + strlen(s_crate);
	const ut64 off_static = off_std + strlen(s_std);

	memcpy(img + 0x400 + off_s1, s1, strlen(s1));
	memcpy(img + 0x400 + off_s2, s2, strlen(s2));
	memcpy(img + 0x400 + off_user, s_user, strlen(s_user));
	memcpy(img + 0x400 + off_crate, s_crate, strlen(s_crate));
	memcpy(img + 0x400 + off_std, s_std, strlen(s_std));
	memcpy(img + 0x400 + off_static, s_static, strlen(s_static));

	// Panic Location #1 (user code) at RVA 0x2100 (raw 0x500)
	rz_write_at_le64(img, base + 0x2000 + off_user, 0x500);
	rz_write_at_le64(img, strlen(s_user), 0x508);
	rz_write_at_le32(img, 42, 0x510);
	rz_write_at_le32(img, 13, 0x514);

	// Panic Location #2 (crate) at RVA 0x2118 (raw 0x518)
	rz_write_at_le64(img, base + 0x2000 + off_crate, 0x518);
	rz_write_at_le64(img, strlen(s_crate), 0x520);
	rz_write_at_le32(img, 108, 0x528);
	rz_write_at_le32(img, 5, 0x52c);

	// Panic Location #3 (stdlib) at RVA 0x2130 (raw 0x530)
	rz_write_at_le64(img, base + 0x2000 + off_std, 0x530);
	rz_write_at_le64(img, strlen(s_std), 0x538);
	rz_write_at_le32(img, 211, 0x540);
	rz_write_at_le32(img, 9, 0x544);

	// Static &str slice (ptr, len) at RVA 0x2150 (raw 0x550)
	rz_write_at_le64(img, base + 0x2000 + off_static, 0x550);
	rz_write_at_le64(img, strlen(s_static), 0x558);

	// Base relocations for the 4 pointers above at RVA 0x2200 (raw 0x600)
	rz_write_at_le32(img, 0x2200, 0xf0);
	rz_write_at_le32(img, 16, 0xf4);
	rz_write_at_le32(img, 0x2000, 0x600);
	rz_write_at_le32(img, 16, 0x604);
	rz_write_at_le16(img, (10 << 12) | 0x100, 0x608);
	rz_write_at_le16(img, (10 << 12) | 0x118, 0x60a);
	rz_write_at_le16(img, (10 << 12) | 0x130, 0x60c);
	rz_write_at_le16(img, (10 << 12) | 0x150, 0x60e);

	// .text at RVA 0x1000 (raw 0x200):
	// 0x1000: Rust main wrapper -> lea rcx, [user_main=0x1060]; call lang_start=0x10c0; ret
	emit_x64_lea_rip(img, 0x200, base + 0x1000, 0x48, 1, base + 0x1060);
	img[0x207] = 0xe8;
	rz_write_at_le32(img, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(base + 0x100c)), 0x208);
	img[0x20c] = 0xc3;

	// 0x1060: user_main:
	//   lea rcx, [s1]; mov edx, strlen(s1); call 0x10c0
	//   lea r8, [loc_user];
	//   lea rax, [s2]; mov [rsp+0x20], rax; mov qword [rsp+0x28], strlen(s2); ret
	size_t o = 0x260;
	ut64 pc = base + 0x1060;
	emit_x64_lea_rip(img, o, pc, 0x48, 1, base + 0x2000 + off_s1);
	o += 7;
	pc += 7;
	img[o++] = 0xba; // mov edx, imm32
	rz_write_at_le32(img, (ut32)strlen(s1), o);
	o += 4;
	pc += 5;
	// Reference panic::Location #1 via lea r8, [0x140002100]
	ut64 panic_ref_pc = pc;
	emit_x64_lea_rip(img, o, pc, 0x4c, 0, base + 0x2100);
	o += 7;
	pc += 7;
	// Stack-stored &str pair: lea rax, [s2]; mov [rsp+0x20], rax; mov qword [rsp+0x28], len(s2)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, base + 0x2000 + off_s2);
	o += 7;
	pc += 7;
	// 48 89 44 24 20 -> mov [rsp + 0x20], rax
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x20;
	// 48 c7 44 24 28 <imm32> -> mov qword [rsp + 0x28], strlen(s2)
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x28;
	rz_write_at_le32(img, (ut32)strlen(s2), o);
	o += 4;
	img[o++] = 0xc3;

	// 0x10c0: lang_start stub
	img[0x2c0] = 0xc3;

	RzCore *core = open_synthetic_bin(img, sizeof(img), base);
	mu_assert_notnull(core, "open synthetic Rust PE64");
	rz_flag_set(core->flags, "main", base + 0x1000, 1);

	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover rust metadata");

	mu_assert_eq(info->main_addr, base + 0x1060, "recovered sym.rust.main");
	mu_assert_eq(info->lang_start_addr, base + 0x10c0, "recovered sym.rust.lang_start");
	mu_assert_notnull(rz_flag_get(core->flags, "sym.rust.main"), "sym.rust.main flag set");

	mu_assert_eq(rz_pvector_len(info->panic_locs), 3, "recovered 3 panic::Location structs");
	mu_assert_eq(rz_pvector_len(info->crates), 1, "recovered 1 Cargo crate");
	mu_assert_streq((const char *)rz_pvector_at(info->crates, 0), "chacha20-0.9.1", "crate name");
	mu_assert_eq(rz_pvector_len(info->user_files), 1, "recovered 1 user .rs file");
	mu_assert_streq((const char *)rz_pvector_at(info->user_files, 0), "src/main.rs", "user file");

	// Verify contiguous non-NUL strings were un-blobbed to exact lengths
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinString *bs1 = rz_bin_object_get_string_at(obj, base + 0x2000 + off_s1, true);
	mu_assert_notnull(bs1, "code reg-pair string s1 recovered");
	mu_assert_streq(bs1->string, s1, "s1 exact un-blobbed text");
	mu_assert_eq(bs1->size, strlen(s1), "s1 exact length");

	RzBinString *bs2 = rz_bin_object_get_string_at(obj, base + 0x2000 + off_s2, true);
	mu_assert_notnull(bs2, "code stack-pair string s2 recovered");
	mu_assert_streq(bs2->string, s2, "s2 exact un-blobbed text");
	mu_assert_eq(bs2->size, strlen(s2), "s2 exact length");

	RzBinString *bs_static = rz_bin_object_get_string_at(obj, base + 0x2000 + off_static, true);
	mu_assert_notnull(bs_static, "static &str table entry recovered");
	mu_assert_streq(bs_static->string, s_static, "static string exact text");

	// Verify panic::Location reference got comment + data xref at panic_ref_pc
	const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, panic_ref_pc);
	mu_assert_notnull(cmt, "panic::Location ref comment set");
	mu_assert_streq(cmt, "rust panic: src/main.rs:42:13", "exact panic location comment");

	// Verify CLI command aalrj produces valid JSON
	char *json_out = rz_core_cmd_str(core, "aalrj");
	mu_assert_notnull(json_out, "aalrj output");
	mu_assert_true(strstr(json_out, "\"chacha20-0.9.1\"") != NULL, "aalrj contains crate");
	mu_assert_true(strstr(json_out, "\"src/main.rs\"") != NULL, "aalrj contains user file");
	free(json_out);

	rz_core_rust_info_free(info);
	rz_core_free(core);
	mu_end;
}

bool test_rust_renamed_section_and_invalid_utf8(void) {
	const ut64 base = 0x140000000ULL;
	ut8 img[0x700];
	build_rust_pe64(img, sizeof(img), ".57743", 0x300);

	// Valid user .rs path + invalid UTF-8 bytes inside renamed section
	const char *s_user = "src/crypto.rs";
	memcpy(img + 0x400, s_user, strlen(s_user));
	// Invalid UTF-8 (0xff 0xfe 0x80 0x00 ...) at RVA 0x2040 (raw 0x440)
	img[0x440] = 0xff;
	img[0x441] = 0xfe;
	img[0x442] = 0x80;
	img[0x443] = 0x81;
	img[0x444] = 0x41;
	img[0x445] = 0x42;

	// Panic Location at RVA 0x2100 (raw 0x500)
	rz_write_at_le64(img, base + 0x2000, 0x500);
	rz_write_at_le64(img, strlen(s_user), 0x508);
	rz_write_at_le32(img, 77, 0x510);
	rz_write_at_le32(img, 3, 0x514);

	// Static pair pointing to invalid UTF-8 at RVA 0x2120 (raw 0x520) -> must be rejected
	rz_write_at_le64(img, base + 0x2040, 0x520);
	rz_write_at_le64(img, 6, 0x528);

	RzCore *core = open_synthetic_bin(img, sizeof(img), base);
	mu_assert_notnull(core, "open renamed-section Rust PE64");

	ut32 n = rz_core_analysis_resolve_rust_strings(core);
	mu_assert_eq(n, 1, "recovered only valid .rs string in renamed section");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	mu_assert_null(rz_bin_object_get_string_at(obj, base + 0x2040, true),
		"invalid UTF-8 pair rejected");

	rz_core_free(core);
	mu_end;
}

bool test_rust_inlined_lang_start_and_vendor_crates(void) {
	const ut64 base = 0x140000000ULL;
	ut8 img[0x800];
	build_rust_pe64(img, sizeof(img), ".rdata", 0x400);

	// Vendor & remapped crate paths plus stdlib panic_abort
	const char *p_vendor = "/rust/deps\\rustc-demangle-0.1.26\\src\\lib.rs";
	const char *p_remap = "/cargo/registry/25cdd57fae9f0462\\hashbrown-0.17.1\\src\\raw.rs";
	const char *p_abort = "library\\panic_abort\\src\\lib.rs";
	const char *p_user = "src\\agent.rs";
	ut64 o1 = 0x00;
	ut64 o2 = o1 + strlen(p_vendor);
	ut64 o3 = o2 + strlen(p_remap);
	ut64 o4 = o3 + strlen(p_abort);
	memcpy(img + 0x400 + o1, p_vendor, strlen(p_vendor));
	memcpy(img + 0x400 + o2, p_remap, strlen(p_remap));
	memcpy(img + 0x400 + o3, p_abort, strlen(p_abort));
	memcpy(img + 0x400 + o4, p_user, strlen(p_user));

	// Four panic::Location entries starting at RVA 0x2100 (raw 0x500)
	rz_write_at_le64(img, base + 0x2000 + o1, 0x500);
	rz_write_at_le64(img, strlen(p_vendor), 0x508);
	rz_write_at_le32(img, 10, 0x510);
	rz_write_at_le32(img, 2, 0x514);

	rz_write_at_le64(img, base + 0x2000 + o2, 0x518);
	rz_write_at_le64(img, strlen(p_remap), 0x520);
	rz_write_at_le32(img, 20, 0x528);
	rz_write_at_le32(img, 4, 0x52c);

	rz_write_at_le64(img, base + 0x2000 + o3, 0x530);
	rz_write_at_le64(img, strlen(p_abort), 0x538);
	rz_write_at_le32(img, 30, 0x540);
	rz_write_at_le32(img, 6, 0x544);

	rz_write_at_le64(img, base + 0x2000 + o4, 0x548);
	rz_write_at_le64(img, strlen(p_user), 0x550);
	rz_write_at_le32(img, 40, 0x558);
	rz_write_at_le32(img, 8, 0x55c);

	// Inlined std::rt::lang_start_internal wrapper at RVA 0x1000 (raw 0x200):
	//   lea rax, [user_main=0x1080]
	//   mov [rsp+0x30], rax
	//   lea rdx, [vtable=0x2200]
	//   lea rcx, [rsp+0x30]
	//   call lang_start_internal=0x10c0
	//   ret
	size_t o = 0x200;
	ut64 pc = base + 0x1000;
	emit_x64_lea_rip(img, o, pc, 0x48, 0, base + 0x1080);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x30;
	pc += 5;
	emit_x64_lea_rip(img, o, pc, 0x48, 2, base + 0x2200);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x8d;
	img[o++] = 0x4c;
	img[o++] = 0x24;
	img[o++] = 0x30;
	pc += 5;
	img[o++] = 0xe8;
	rz_write_at_le32(img, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(pc + 5)), o);
	o += 4;
	img[o++] = 0xc3;
	img[0x280] = 0xc3;
	img[0x2c0] = 0xc3;

	RzCore *core = open_synthetic_bin(img, sizeof(img), base);
	mu_assert_notnull(core, "open inlined lang_start PE64");
	rz_flag_set(core->flags, "main", base + 0x1000, 1);

	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover inlined lang_start metadata");
	mu_assert_eq(info->main_addr, base + 0x1080, "inlined lang_start_internal recovers user main");
	mu_assert_eq(info->lang_start_addr, base + 0x10c0, "inlined lang_start_internal target");
	mu_assert_eq(rz_pvector_len(info->crates), 2, "vendor and remapped crates extracted");
	mu_assert_streq((const char *)rz_pvector_at(info->crates, 0), "hashbrown-0.17.1", "remapped crate");
	mu_assert_streq((const char *)rz_pvector_at(info->crates, 1), "rustc-demangle-0.1.26", "vendor crate");
	mu_assert_eq(rz_pvector_len(info->user_files), 1, "only true user file remains");
	mu_assert_streq((const char *)rz_pvector_at(info->user_files, 0), "src\\agent.rs", "true user file");

	// Also exercise standard mode output of aalr
	char *std_out = rz_core_cmd_str(core, "aalr");
	mu_assert_notnull(std_out, "aalr standard output");
	mu_assert_true(strstr(std_out, "sym.rust.main") != NULL, "aalr output mentions sym.rust.main");
	free(std_out);

	rz_core_rust_info_free(info);
	rz_core_free(core);
	mu_end;
}

static void emit_arm64_adrp(ut8 *buf, size_t off, ut64 pc, ut32 rd, ut64 target) {
	st64 delta = ((st64)(target & ~0xfffULL) - (st64)(pc & ~0xfffULL)) >> 12;
	ut32 imm21 = (ut32)delta & 0x1fffffU;
	ut32 insn = 0x90000000U | ((imm21 & 3U) << 29) | (((imm21 >> 2) & 0x7ffffU) << 5) | (rd & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_adr(ut8 *buf, size_t off, ut64 pc, ut32 rd, ut64 target) {
	st64 delta = (st64)target - (st64)pc;
	ut32 imm21 = (ut32)delta & 0x1fffffU;
	ut32 insn = 0x10000000U | ((imm21 & 3U) << 29) | (((imm21 >> 2) & 0x7ffffU) << 5) | (rd & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_add_imm(ut8 *buf, size_t off, ut32 rd, ut32 rn, ut32 imm12) {
	ut32 insn = 0x91000000U | ((imm12 & 0xfffU) << 10) | ((rn & 31U) << 5) | (rd & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_movz(ut8 *buf, size_t off, ut32 rd, ut32 imm16) {
	ut32 insn = 0xd2800000U | ((imm16 & 0xffffU) << 5) | (rd & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_str_sp(ut8 *buf, size_t off, ut32 rt, ut32 sp_off) {
	ut32 insn = 0xf90003e0U | (((sp_off / 8U) & 0xfffU) << 10) | (rt & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_bl(ut8 *buf, size_t off, ut64 pc, ut64 target) {
	st64 delta = ((st64)target - (st64)pc) >> 2;
	ut32 insn = 0x94000000U | ((ut32)delta & 0x03ffffffU);
	rz_write_at_le32(buf, insn, off);
}

bool test_rust_analyzed_x64_fcns_and_chunk_boundary(void) {
	const ut64 base = 0x140000000ULL;
	const size_t img_sz = 0x11400;
	ut8 *img = calloc(1, img_sz);
	mu_assert_notnull(img, "alloc 64 KiB boundary PE64");
	build_rust_pe64(img, img_sz, ".rdata", 0x11000);

	const char *s_code = "analyzed_bb_string";
	const char *s_edge = "chunk_edge_static";
	const char *s_loc = "src/boundary.rs";
	const ut64 off_code = 0x00;
	const ut64 off_edge = 0x20;
	const ut64 off_loc = 0x40;
	memcpy(img + 0x400 + off_code, s_code, strlen(s_code));
	memcpy(img + 0x400 + off_edge, s_edge, strlen(s_edge));
	memcpy(img + 0x400 + off_loc, s_loc, strlen(s_loc));

	// Place a static &str at 65504 (0xffe0) immediately followed by a
	// core::panic::Location at 65520 (0xfff0) straddling the 65536 chunk edge.
	const size_t raw_edge_pair = 0x400 + 0xffe0;
	rz_write_at_le64(img, base + 0x2000 + off_edge, raw_edge_pair);
	rz_write_at_le64(img, strlen(s_edge), raw_edge_pair + 8);

	const size_t raw_straddle_loc = 0x400 + 0xfff0;
	rz_write_at_le64(img, base + 0x2000 + off_loc, raw_straddle_loc);
	rz_write_at_le64(img, strlen(s_loc), raw_straddle_loc + 8);
	rz_write_at_le32(img, 99, raw_straddle_loc + 16);
	rz_write_at_le32(img, 7, raw_straddle_loc + 20);

	// .text function at RVA 0x1000 (>= 52 bytes so analyzed BB path covers >= 10% of .text):
	size_t o = 0x200;
	ut64 pc = base + 0x1000;
	emit_x64_lea_rip(img, o, pc, 0x48, 1, base + 0x2000 + off_code); // lea rcx, [s_code]
	o += 7;
	pc += 7;
	img[o++] = 0x31; // xor eax, eax (clobber tracking)
	img[o++] = 0xc0;
	img[o++] = 0xba; // mov edx, strlen(s_code)
	rz_write_at_le32(img, (ut32)strlen(s_code), o);
	o += 4;
	img[o++] = 0x48; // mov rax, [rsp + 0x10] (mem load clobber)
	img[o++] = 0x8b;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x10;
	img[o++] = 0x48; // mov rdx, rcx (reg-to-reg propagation)
	img[o++] = 0x8b;
	img[o++] = 0xd1;
	memset(img + o, 0x90, 40);
	o += 40;
	img[o++] = 0xc3;

	RzCore *core = open_synthetic_bin(img, img_sz, base);
	free(img);
	mu_assert_notnull(core, "open chunk-boundary PE64");

	rz_core_analysis_fcn(core, base + 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover metadata across chunk boundary");

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinString *bs_code = rz_bin_object_get_string_at(obj, base + 0x2000 + off_code, true);
	mu_assert_notnull(bs_code, "analyzed BB path recovered s_code");
	mu_assert_streq(bs_code->string, s_code, "analyzed BB s_code text");

	RzBinString *bs_edge = rz_bin_object_get_string_at(obj, base + 0x2000 + off_edge, true);
	mu_assert_notnull(bs_edge, "chunk-edge static &str recovered");
	mu_assert_streq(bs_edge->string, s_edge, "chunk-edge static &str text");

	mu_assert_eq(rz_pvector_len(info->panic_locs), 1, "chunk-straddling panic::Location recovered");
	RzCoreRustPanicLoc *loc = rz_pvector_at(info->panic_locs, 0);
	mu_assert_streq(loc->file, s_loc, "straddling panic::Location file");
	mu_assert_eq(loc->line, 99, "straddling panic::Location line");
	mu_assert_eq(loc->col, 7, "straddling panic::Location col");

	rz_core_rust_info_free(info);
	rz_core_free(core);
	mu_end;
}

static void build_rust_arm64_elf64(ut8 *buf, size_t size) {
	memset(buf, 0, size);
	// ELF64 little-endian AArch64 executable header
	memcpy(buf, "\x7f"
		    "ELF",
		4);
	buf[4] = 2; // ELFCLASS64
	buf[5] = 1; // ELFDATA2LSB
	buf[6] = 1; // EV_CURRENT
	rz_write_at_le16(buf, 2, 0x10); // ET_EXEC
	rz_write_at_le16(buf, 183, 0x12); // EM_AARCH64
	rz_write_at_le32(buf, 1, 0x14);
	rz_write_at_le64(buf, 0x402020ULL, 0x18); // e_entry
	rz_write_at_le64(buf, 0x40ULL, 0x20); // e_phoff
	rz_write_at_le64(buf, 0x200ULL, 0x28); // e_shoff
	rz_write_at_le16(buf, 64, 0x34); // e_ehsize
	rz_write_at_le16(buf, 56, 0x36); // e_phentsize
	rz_write_at_le16(buf, 2, 0x38); // e_phnum
	rz_write_at_le16(buf, 64, 0x3a); // e_shentsize
	rz_write_at_le16(buf, 4, 0x3c); // e_shnum
	rz_write_at_le16(buf, 3, 0x3e); // e_shstrndx

	// PT_LOAD 0: .rodata (R) at 0x401000, file offset 0x1000, size 0x1000
	rz_write_at_le32(buf, 1, 0x40);
	rz_write_at_le32(buf, 4, 0x44);
	rz_write_at_le64(buf, 0x1000ULL, 0x48);
	rz_write_at_le64(buf, 0x401000ULL, 0x50);
	rz_write_at_le64(buf, 0x401000ULL, 0x58);
	rz_write_at_le64(buf, 0x1000ULL, 0x60);
	rz_write_at_le64(buf, 0x1000ULL, 0x68);
	rz_write_at_le64(buf, 0x1000ULL, 0x70);

	// PT_LOAD 1: .text (RX) at 0x402000, file offset 0x2000, size 0x1000
	rz_write_at_le32(buf, 1, 0x78);
	rz_write_at_le32(buf, 5, 0x7c);
	rz_write_at_le64(buf, 0x2000ULL, 0x80);
	rz_write_at_le64(buf, 0x402000ULL, 0x88);
	rz_write_at_le64(buf, 0x402000ULL, 0x90);
	rz_write_at_le64(buf, 0x1000ULL, 0x98);
	rz_write_at_le64(buf, 0x1000ULL, 0xa0);
	rz_write_at_le64(buf, 0x1000ULL, 0xa8);

	// .shstrtab at 0x100
	const char shstrtab[] = "\0.rodata\0.text\0.shstrtab\0";
	memcpy(buf + 0x100, shstrtab, sizeof(shstrtab));

	// Section 1: .rodata
	rz_write_at_le32(buf, 1, 0x240);
	rz_write_at_le32(buf, 1, 0x244); // SHT_PROGBITS
	rz_write_at_le64(buf, 2, 0x248); // SHF_ALLOC
	rz_write_at_le64(buf, 0x401000ULL, 0x250);
	rz_write_at_le64(buf, 0x1000ULL, 0x258);
	rz_write_at_le64(buf, 0x1000ULL, 0x260);
	rz_write_at_le64(buf, 8, 0x270);

	// Section 2: .text
	rz_write_at_le32(buf, 9, 0x280);
	rz_write_at_le32(buf, 1, 0x284); // SHT_PROGBITS
	rz_write_at_le64(buf, 6, 0x288); // SHF_ALLOC | SHF_EXECINSTR
	rz_write_at_le64(buf, 0x402000ULL, 0x290);
	rz_write_at_le64(buf, 0x2000ULL, 0x298);
	rz_write_at_le64(buf, 0x1000ULL, 0x2a0);
	rz_write_at_le64(buf, 4, 0x2b0);

	// Section 3: .shstrtab
	rz_write_at_le32(buf, 15, 0x2c0);
	rz_write_at_le32(buf, 3, 0x2c4); // SHT_STRTAB
	rz_write_at_le64(buf, 0x100ULL, 0x2d8);
	rz_write_at_le64(buf, sizeof(shstrtab), 0x2e0);
	rz_write_at_le64(buf, 1, 0x2f0);
}

bool test_rust_arm64_strings_and_main(void) {
	ut8 *img = calloc(1, 0x3000);
	mu_assert_notnull(img, "alloc ARM64 ELF64");
	build_rust_arm64_elf64(img, 0x3000);

	const ut64 rodata_va = 0x401000ULL;
	const ut64 text_va = 0x402000ULL;

	// Contiguous non-NUL strings in .rodata (placed BELOW .text to test negative ADRP/ADR offsets)
	const char *s1 = "arm64_adrp_str";
	const char *s2 = "arm64_stack_str";
	const char *s3 = "arm64_adr_str";
	const char *s_loc = "src/arm64.rs";
	const ut64 o1 = 0;
	const ut64 o2 = o1 + strlen(s1);
	const ut64 o3 = o2 + strlen(s2);
	const ut64 o_loc = o3 + strlen(s3);
	memcpy(img + 0x1000 + o1, s1, strlen(s1));
	memcpy(img + 0x1000 + o2, s2, strlen(s2));
	memcpy(img + 0x1000 + o3, s3, strlen(s3));
	memcpy(img + 0x1000 + o_loc, s_loc, strlen(s_loc));

	// Panic Location at 0x401100 (file 0x1100)
	rz_write_at_le64(img, rodata_va + o_loc, 0x1100);
	rz_write_at_le64(img, strlen(s_loc), 0x1108);
	rz_write_at_le32(img, 55, 0x1110);
	rz_write_at_le32(img, 9, 0x1114);

	// 0x402000: lang_start stub (ret)
	rz_write_at_le32(img, 0xd65f03c0U, 0x2000);

	// 0x402020: main wrapper -> adrp x0, 0x402000; add x0, x0, #0x60; bl 0x402000 (negative imm26); ret
	emit_arm64_adrp(img, 0x2020, text_va + 0x20, 0, text_va + 0x60);
	emit_arm64_add_imm(img, 0x2024, 0, 0, 0x60);
	emit_arm64_bl(img, 0x2028, text_va + 0x28, text_va + 0x00);
	rz_write_at_le32(img, 0xd65f03c0U, 0x202c);

	// 0x402060: user_main exercising negative ADRP, MOVZ, STR [sp, #off], negative ADR, panic ref
	size_t foff = 0x2060;
	ut64 pc = text_va + 0x60;
	// (x0, x1) reg pair via negative ADRP + ADD + MOVZ
	emit_arm64_adrp(img, foff, pc, 0, rodata_va + o1);
	foff += 4;
	pc += 4;
	emit_arm64_add_imm(img, foff, 0, 0, (ut32)o1);
	foff += 4;
	pc += 4;
	emit_arm64_movz(img, foff, 1, (ut32)strlen(s1));
	foff += 4;
	pc += 4;
	// Stack pair via x8/x9 (not a reg pair) + STR [sp, #0x10] / [sp, #0x18]
	emit_arm64_adrp(img, foff, pc, 8, rodata_va + o2);
	foff += 4;
	pc += 4;
	emit_arm64_add_imm(img, foff, 8, 8, (ut32)o2);
	foff += 4;
	pc += 4;
	emit_arm64_movz(img, foff, 9, (ut32)strlen(s2));
	foff += 4;
	pc += 4;
	emit_arm64_str_sp(img, foff, 8, 0x10);
	foff += 4;
	pc += 4;
	emit_arm64_str_sp(img, foff, 9, 0x18);
	foff += 4;
	pc += 4;
	// Negative ADR with pre-loaded length in x3 (pair x2, x3)
	emit_arm64_movz(img, foff, 3, (ut32)strlen(s3));
	foff += 4;
	pc += 4;
	emit_arm64_adr(img, foff, pc, 2, rodata_va + o3);
	foff += 4;
	pc += 4;
	// Reference panic::Location at 0x401100
	ut64 panic_ref_pc = pc;
	emit_arm64_adrp(img, foff, pc, 4, rodata_va + 0x100);
	foff += 4;
	pc += 4;
	emit_arm64_add_imm(img, foff, 4, 4, 0x100);
	foff += 4;
	rz_write_at_le32(img, 0xd65f03c0U, foff);

	RzCore *core = open_synthetic_bin(img, 0x3000, UT64_MAX);
	free(img);
	mu_assert_notnull(core, "open synthetic ARM64 ELF64");
	rz_flag_set(core->flags, "main", text_va + 0x20, 1);

	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover ARM64 Rust metadata");

	mu_assert_eq(info->main_addr, text_va + 0x60, "ARM64 recovered sym.rust.main");
	mu_assert_eq(info->lang_start_addr, text_va + 0x00, "ARM64 recovered sym.rust.lang_start");

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinString *bs1 = rz_bin_object_get_string_at(obj, rodata_va + o1, true);
	mu_assert_notnull(bs1, "ARM64 ADRP+ADD+MOVZ string recovered");
	mu_assert_streq(bs1->string, s1, "ARM64 s1 text");

	RzBinString *bs2 = rz_bin_object_get_string_at(obj, rodata_va + o2, true);
	mu_assert_notnull(bs2, "ARM64 STR [sp] stack-pair string recovered");
	mu_assert_streq(bs2->string, s2, "ARM64 s2 text");

	RzBinString *bs3 = rz_bin_object_get_string_at(obj, rodata_va + o3, true);
	mu_assert_notnull(bs3, "ARM64 ADR string recovered");
	mu_assert_streq(bs3->string, s3, "ARM64 s3 text");

	const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, panic_ref_pc);
	mu_assert_notnull(cmt, "ARM64 panic::Location comment set");
	mu_assert_streq(cmt, "rust panic: src/arm64.rs:55:9", "ARM64 panic comment text");

	rz_core_rust_info_free(info);
	rz_core_free(core);
	mu_end;
}

static void emit_arm64_add_imm_shift(ut8 *buf, size_t off, ut32 rd, ut32 rn, ut32 imm12) {
	ut32 insn = 0x91400000U | ((imm12 & 0xfffU) << 10) | ((rn & 31U) << 5) | (rd & 31U);
	rz_write_at_le32(buf, insn, off);
}

static void emit_arm64_b(ut8 *buf, size_t off, ut64 pc, ut64 target) {
	st64 delta = ((st64)target - (st64)pc) >> 2;
	ut32 insn = 0x14000000U | ((ut32)delta & 0x03ffffffU);
	rz_write_at_le32(buf, insn, off);
}

static void emit_elf64_shdr(ut8 *buf, size_t off, ut32 name, ut32 type, ut64 flags,
	ut64 addr, ut64 foff, ut64 size, ut32 link, ut32 info, ut64 align, ut64 entsize) {
	rz_write_at_le32(buf, name, off + 0x00);
	rz_write_at_le32(buf, type, off + 0x04);
	rz_write_at_le64(buf, flags, off + 0x08);
	rz_write_at_le64(buf, addr, off + 0x10);
	rz_write_at_le64(buf, foff, off + 0x18);
	rz_write_at_le64(buf, size, off + 0x20);
	rz_write_at_le32(buf, link, off + 0x28);
	rz_write_at_le32(buf, info, off + 0x2c);
	rz_write_at_le64(buf, align, off + 0x30);
	rz_write_at_le64(buf, entsize, off + 0x38);
}

static void emit_elf64_phdr(ut8 *buf, size_t off, ut32 type, ut32 flags,
	ut64 foff, ut64 vaddr, ut64 sz) {
	rz_write_at_le32(buf, type, off + 0x00);
	rz_write_at_le32(buf, flags, off + 0x04);
	rz_write_at_le64(buf, foff, off + 0x08);
	rz_write_at_le64(buf, vaddr, off + 0x10);
	rz_write_at_le64(buf, vaddr, off + 0x18);
	rz_write_at_le64(buf, sz, off + 0x20);
	rz_write_at_le64(buf, sz, off + 0x28);
	rz_write_at_le64(buf, 0x1000ULL, off + 0x30);
}

static void write_elf64_ehdr(ut8 *buf, ut16 machine, ut64 entry, ut64 phoff, ut64 shoff,
	ut16 phnum, ut16 shnum, ut16 shstrndx) {
	memcpy(buf, "\x7f"
		    "ELF",
		4);
	buf[4] = 2; // ELFCLASS64
	buf[5] = 1; // ELFDATA2LSB
	buf[6] = 1; // EV_CURRENT
	rz_write_at_le16(buf, 2, 0x10); // ET_EXEC
	rz_write_at_le16(buf, machine, 0x12);
	rz_write_at_le32(buf, 1, 0x14);
	rz_write_at_le64(buf, entry, 0x18);
	rz_write_at_le64(buf, phoff, 0x20);
	rz_write_at_le64(buf, shoff, 0x28);
	rz_write_at_le16(buf, 64, 0x34);
	rz_write_at_le16(buf, 56, 0x36);
	rz_write_at_le16(buf, phnum, 0x38);
	rz_write_at_le16(buf, 64, 0x3a);
	rz_write_at_le16(buf, shnum, 0x3c);
	rz_write_at_le16(buf, shstrndx, 0x3e);
}

bool test_rust_elf64_x64_relocs_sysv_and_cli(void) {
	// ELF64 x86-64 with .rodata, .data.rel.ro, .data.rel.ro.local, __const, __cstring,
	// .data, __data, .text, .rela.dyn, and non-PIE _start -> main detection.
	const size_t img_sz = 0x5000;
	ut8 *img = calloc(1, img_sz);
	mu_assert_notnull(img, "alloc ELF64 x86-64");
	if (!img) {
		return false;
	}

	const ut64 data_va = 0x401000ULL;
	const ut64 text_va = 0x403000ULL;
	const char shstrtab[] =
		"\0.rodata\0.data.rel.ro\0.data.rel.ro.local\0__const\0__cstring\0.data\0__data\0.text\0.rela.dyn\0.shstrtab\0";
	// Offsets into shstrtab:
	// 1: .rodata
	// 9: .data.rel.ro
	// 22: .data.rel.ro.local
	// 41: __const
	// 49: __cstring
	// 59: .data
	// 65: __data
	// 72: .text
	// 78: .rela.dyn
	// 88: .shstrtab
	memcpy(img + 0x100, shstrtab, sizeof(shstrtab));

	// 11 sections total (0=NULL, 1..9, 10=.shstrtab), shoff=0x200
	write_elf64_ehdr(img, 62 /* EM_X86_64 */, text_va + 0x200, 0x40, 0x200, 2, 11, 10);
	emit_elf64_phdr(img, 0x40, 1, 6, 0x1000, data_va, 0x2000);
	emit_elf64_phdr(img, 0x78, 1, 5, 0x3000, text_va, 0x1000);

	// Data sections spanning 0x401000..0x402c00
	emit_elf64_shdr(img, 0x240, 1, 1, 2, data_va + 0x000, 0x1000, 0x400, 0, 0, 8, 0); // .rodata
	emit_elf64_shdr(img, 0x280, 9, 1, 3, data_va + 0x400, 0x1400, 0x400, 0, 0, 8, 0); // .data.rel.ro
	emit_elf64_shdr(img, 0x2c0, 22, 1, 3, data_va + 0x800, 0x1800, 0x400, 0, 0, 8, 0); // .data.rel.ro.local
	emit_elf64_shdr(img, 0x300, 41, 1, 2, data_va + 0xc00, 0x1c00, 0x400, 0, 0, 8, 0); // __const
	emit_elf64_shdr(img, 0x340, 49, 1, 2, data_va + 0x1000, 0x2000, 0x400, 0, 0, 8, 0); // __cstring
	emit_elf64_shdr(img, 0x380, 59, 1, 3, data_va + 0x1400, 0x2400, 0x400, 0, 0, 8, 0); // .data
	emit_elf64_shdr(img, 0x3c0, 65, 1, 3, data_va + 0x1800, 0x2800, 0x400, 0, 0, 8, 0); // __data
	emit_elf64_shdr(img, 0x400, 72, 1, 6, text_va, 0x3000, 0x1000, 0, 0, 16, 0); // .text
	emit_elf64_shdr(img, 0x440, 78, 4 /* SHT_RELA */, 2, 0x404000, 0x4000, 24 * 5, 0, 0, 8, 24); // .rela.dyn
	emit_elf64_shdr(img, 0x480, 88, 3, 0, 0, 0x100, sizeof(shstrtab), 0, 0, 1, 0); // .shstrtab

	const char *s_reloc = "elf_reloc_ok";
	const char *s_unreloc = "elf_no_reloc_skip";
	const char *s_dbl = "elf_double_reloc";
	const char *s_user = "src/elf_sysv.rs";
	memcpy(img + 0x1000, s_reloc, strlen(s_reloc));
	memcpy(img + 0x1040, s_unreloc, strlen(s_unreloc));
	memcpy(img + 0x1080, s_dbl, strlen(s_dbl));
	memcpy(img + 0x10c0, s_user, strlen(s_user));

	// In .data.rel.ro (0x401400, file 0x1400):
	// 1) Relocated panic::Location at 0x401400
	rz_write_at_le64(img, data_va + 0x0c0, 0x1400);
	rz_write_at_le64(img, strlen(s_user), 0x1408);
	rz_write_at_le32(img, 12, 0x1410);
	rz_write_at_le32(img, 4, 0x1414);
	// 2) Relocated static &str at 0x401420
	rz_write_at_le64(img, data_va + 0x000, 0x1420);
	rz_write_at_le64(img, strlen(s_reloc), 0x1428);
	// 3) Unrelocated static &str at 0x401440 (must be skipped because has_relocs == true)
	rz_write_at_le64(img, data_va + 0x040, 0x1440);
	rz_write_at_le64(img, strlen(s_unreloc), 0x1448);
	// 4) Double-relocated pair at 0x401460 (reloc on BOTH ptr and len -> skipped)
	rz_write_at_le64(img, data_va + 0x080, 0x1460);
	rz_write_at_le64(img, strlen(s_dbl), 0x1468);

	// .rela.dyn at file 0x4000: 5 Elf64_Rela entries (type 8 = R_X86_64_RELATIVE)
	// Entry 0: reloc in .text (not in data_ranges -> detect_data_relocs skips it first)
	rz_write_at_le64(img, text_va + 0x500, 0x4000);
	rz_write_at_le64(img, 8, 0x4008);
	// Entry 1: reloc for panic::Location at 0x401400
	rz_write_at_le64(img, data_va + 0x400, 0x4018);
	rz_write_at_le64(img, 8, 0x4020);
	// Entry 2: reloc for static &str at 0x401420
	rz_write_at_le64(img, data_va + 0x420, 0x4030);
	rz_write_at_le64(img, 8, 0x4038);
	// Entry 3 & 4: double reloc at 0x401460 and 0x401468
	rz_write_at_le64(img, data_va + 0x460, 0x4048);
	rz_write_at_le64(img, 8, 0x4050);
	rz_write_at_le64(img, data_va + 0x468, 0x4060);
	rz_write_at_le64(img, 8, 0x4068);

	// .text at file 0x3000 (VA 0x403000):
	// 0x403000: SysV main wrapper (direct tail JMP): lea rdi, [user_main=0x403080]; jmp lang_start=0x4030c0
	emit_x64_lea_rip(img, 0x3000, text_va + 0x00, 0x48, 7, text_va + 0x80);
	img[0x3007] = 0xe9; // tail jmp rel32
	rz_write_at_le32(img, (ut32)(st32)((st64)(text_va + 0xc0) - (st64)(text_va + 0x0c)), 0x3008);

	// 0x403040: SysV inlined lang_start_internal wrapper using rbp + rsi vtable + rdi fat-ptr
	size_t o = 0x3040;
	ut64 pc = text_va + 0x40;
	emit_x64_lea_rip(img, o, pc, 0x48, 0, text_va + 0x80); // lea rax, [user_main]
	o += 7;
	pc += 7;
	img[o++] = 0x48; // mov [rbp - 0x10], rax
	img[o++] = 0x89;
	img[o++] = 0x45;
	img[o++] = 0xf0;
	pc += 4;
	emit_x64_lea_rip(img, o, pc, 0x48, 3, data_va + 0x800); // lea rbx, [data] (non-vtable reg)
	o += 7;
	pc += 7;
	emit_x64_lea_rip(img, o, pc, 0x48, 6, data_va + 0x800); // lea rsi, [vtable]
	o += 7;
	pc += 7;
	img[o++] = 0x48; // lea rax, [rbp - 0x10] (non-arg0 dst_reg)
	img[o++] = 0x8d;
	img[o++] = 0x45;
	img[o++] = 0xf0;
	pc += 4;
	img[o++] = 0x48; // lea rdi, [rbp - 0x10]
	img[o++] = 0x8d;
	img[o++] = 0x7d;
	img[o++] = 0xf0;
	pc += 4;
	img[o++] = 0xe8; // call lang_start_internal=0x4030c0
	rz_write_at_le32(img, (ut32)(st32)((st64)(text_va + 0xc0) - (st64)(pc + 5)), o);
	o += 4;
	img[o++] = 0xc3;

	// 0x403100: SysV variant using Win64-style rdx vtable + rcx fat-ptr fallback
	size_t o3 = 0x3100;
	ut64 pc3 = text_va + 0x100;
	emit_x64_lea_rip(img, o3, pc3, 0x48, 0, text_va + 0x80); // lea rax, [user_main]
	o3 += 7;
	pc3 += 7;
	img[o3++] = 0x48; // mov [rbp - 0x10], rax
	img[o3++] = 0x89;
	img[o3++] = 0x45;
	img[o3++] = 0xf0;
	pc3 += 4;
	emit_x64_lea_rip(img, o3, pc3, 0x48, 2, data_va + 0x800); // lea rdx, [vtable]
	o3 += 7;
	pc3 += 7;
	img[o3++] = 0x48; // lea rcx, [rbp - 0x10]
	img[o3++] = 0x8d;
	img[o3++] = 0x4d;
	img[o3++] = 0xf0;
	pc3 += 4;
	img[o3++] = 0xe8; // call lang_start_internal=0x4030c0
	rz_write_at_le32(img, (ut32)(st32)((st64)(text_va + 0xc0) - (st64)(pc3 + 5)), o3);
	o3 += 4;
	img[o3++] = 0xc3;

	// 0x403080: user_main stub, 0x4030c0: lang_start stub
	img[0x3080] = 0xc3;
	img[0x30c0] = 0xc3;

	// 0x403200: _start stub matching get_main_offset_x86_non_pie (offset +29: 48 c7 c7 <le32 main>)
	memset(img + 0x3200, 0x90, 29);
	img[0x3200 + 29] = 0x48;
	img[0x3200 + 30] = 0xc7;
	img[0x3200 + 31] = 0xc7;
	rz_write_at_le32(img, (ut32)(text_va + 0x00), 0x3200 + 32);
	img[0x3200 + 36] = 0xc3;

	RzCore *core = open_synthetic_bin(img, img_sz, UT64_MAX);
	mu_assert_notnull(core, "open ELF64 x86-64");

	// First pass: RZ_BIN_SPECIAL_SYMBOL_MAIN resolves 0x403000 (SysV lea rdi + tail jmp)
	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover ELF64 x86-64 metadata");
	mu_assert_eq(info->main_addr, text_va + 0x80, "ELF64 SysV direct wrapper recovers main");
	mu_assert_eq(info->lang_start_addr, text_va + 0xc0, "ELF64 SysV tail jmp recovers lang_start");
	mu_assert_eq(rz_pvector_len(info->panic_locs), 1, "ELF64 reloc panic::Location");

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	mu_assert_notnull(rz_bin_object_get_string_at(obj, data_va + 0x000, true), "relocated static &str recovered");
	mu_assert_null(rz_bin_object_get_string_at(obj, data_va + 0x040, true), "unrelocated pair skipped");
	mu_assert_null(rz_bin_object_get_string_at(obj, data_va + 0x080, true), "double-reloc pair skipped");
	rz_core_rust_info_free(info);

	// Second pass on same core: exercises existing string same-size fast-path, old_str flag replacement,
	// and already-existing sym.rust.main / sym.rust.lang_start flags.
	RzCoreRustInfo *info2 = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info2, "second pass on same ELF64 core");
	mu_assert_eq(info2->main_addr, text_va + 0x80, "second pass main unchanged");
	rz_core_rust_info_free(info2);
	rz_core_free(core);

	// Third pass: wipe _start pattern so special symbol main is absent and fall back to sym.main
	// pointing at the SysV inlined lang_start_internal wrapper (0x403040).
	memset(img + 0x3200, 0x90, 40);
	RzCore *core2 = open_synthetic_bin(img, img_sz, UT64_MAX);
	free(img);
	mu_assert_notnull(core2, "open ELF64 x86-64 for sym.main fallback");
	rz_flag_set(core2->flags, "sym.main", text_va + 0x40, 1);

	RzCoreRustInfo *info3 = rz_core_analysis_recover_rust_metadata(core2);
	mu_assert_notnull(info3, "recover SysV inlined lang_start via sym.main");
	mu_assert_eq(info3->main_addr, text_va + 0x80, "SysV inlined lang_start recovers main");
	mu_assert_eq(info3->lang_start_addr, text_va + 0xc0, "SysV inlined lang_start target");
	rz_core_rust_info_free(info3);

	// Fourth pass: SysV fallback using rdx vtable + rcx fat-ptr at 0x403100
	rz_flag_unset_name(core2->flags, "sym.main");
	rz_flag_set(core2->flags, "sym.main", text_va + 0x100, 1);
	RzCoreRustInfo *info4 = rz_core_analysis_recover_rust_metadata(core2);
	mu_assert_notnull(info4, "recover SysV rdx/rcx fallback wrapper");
	mu_assert_eq(info4->main_addr, text_va + 0x80, "SysV rdx/rcx wrapper recovers main");
	rz_core_rust_info_free(info4);
	rz_core_free(core2);
	mu_end;
}

bool test_rust_utf8_flags_paths_crates_and_stdlib(void) {
	const ut64 base = 0x140000000ULL;
	const size_t img_sz = 0x2400;
	ut8 *img = calloc(1, img_sz);
	mu_assert_notnull(img, "alloc UTF-8/crates/stdlib PE64");
	if (!img) {
		return false;
	}
	build_rust_pe64(img, img_sz, ".rdata", 0x2000);

	// 1. Place strings starting at raw 0x400 (RVA 0x2000)
	size_t soff = 0;
	// Valid string with \t \n \r space digits upper lower _ / \ . : and valid UTF-8 multibyte
	const char *s_valid = "ok\t\n\r 09AZaz_/\\.:caf\xc3\xa9";
	ut64 va_valid = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, s_valid, strlen(s_valid));
	soff += strlen(s_valid) + 1;

	// Long string (> 512 bytes) to trigger ensure_str_buf reallocation
	ut64 va_long = base + 0x2000 + soff;
	const size_t long_len = 600;
	for (size_t k = 0; k < long_len; k++) {
		img[0x400 + soff + k] = (ut8)('a' + (k % 26));
	}
	soff += long_len + 1;

	// Duplicate text at two distinct addresses to trigger flag name clash suffix
	const char *s_dup = "clashing_rust_str";
	ut64 va_dup1 = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, s_dup, strlen(s_dup));
	soff += strlen(s_dup) + 1;
	ut64 va_dup2 = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, s_dup, strlen(s_dup));
	soff += strlen(s_dup) + 1;

	// Symbol-blocked string glued directly after non-sym.-flagged string (NO NUL between them!)
	// so RzBin only sees the blob starting at va_nonsym and va_sym_blk stays absent when skipped.
	const char *s_nonsym = "allowed_with_other_flag";
	const char *s_sym_blk = "blocked_by_sym_flag";
	ut64 va_nonsym = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, s_nonsym, strlen(s_nonsym));
	soff += strlen(s_nonsym);
	ut64 va_sym_blk = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, s_sym_blk, strlen(s_sym_blk));
	soff += strlen(s_sym_blk) + 1;

	// Invalid UTF-8 / control / printable-count / strict_unreloc candidates
	ut64 va_nul = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "ab\0zz_bad", 9);
	soff += 10;
	ut64 va_ctrl = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "ab\x01zz_bad", 9);
	soff += 10;
	ut64 va_del = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "ab\x7fzz_bad", 9);
	soff += 10;
	ut64 va_c1 = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "ab\xc2\x85zz_bad", 10);
	soff += 11;
	// Glue printable-but-rejected candidates behind a prefix with no NUL so RzBin's
	// NUL-string scanner does not pre-register strings at their exact offsets.
	memcpy(img + 0x400 + soff, "PFX:", 4);
	soff += 4;
	ut64 va_few = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "   a   ", 7);
	soff += 7;
	ut64 va_same = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "aaaaaaaa", 8);
	soff += 8;
	ut64 va_punct = base + 0x2000 + soff;
	memcpy(img + 0x400 + soff, "!@#$%^&*()", 10);
	soff += 11;

	// All stdlib paths (24 forms), all cargo crate prefixes (9 forms) + edge cases,
	// bare valid/invalid filenames, forbidden chars, control chars, and duplicate user/crate.
	const char *panic_paths[] = {
		// Bare valid filename (no separator, includes upper/lower/digit/_/-/.)
		"main.09-A_.rs",
		// Duplicate user path & duplicate crate path
		"main.09-A_.rs",
		// Invalid paths (must be rejected as panic::Location)
		"bad name.rs",
		"src/\x01z.rs",
		"src/\x7fz.rs",
		"src/a\"b.rs",
		"src/a*b.rs",
		"src/a?b.rs",
		"src/a<b.rs",
		"src/a>b.rs",
		"src/a|b.rs",
		"src/a;b.rs",
		".rs",
		// All 24 stdlib patterns
		"/library/core/src/a.rs",
		"\\library\\core\\src\\a.rs",
		"/library/std/src/a.rs",
		"\\library\\std\\src\\a.rs",
		"/library/alloc/src/a.rs",
		"\\library\\alloc\\src\\a.rs",
		"/library/panic_unwind/src/a.rs",
		"\\library\\panic_unwind\\src\\a.rs",
		"/rustc/hash/a.rs",
		"\\rustc\\hash\\a.rs",
		"library/core/a.rs",
		"library\\core\\a.rs",
		"library/std/a.rs",
		"library\\std\\a.rs",
		"library/alloc/a.rs",
		"library\\alloc\\a.rs",
		"library/panic_abort/a.rs",
		"library\\panic_abort\\a.rs",
		"core/src/a.rs",
		"core\\src\\a.rs",
		"std/src/a.rs",
		"std\\src\\a.rs",
		"alloc/src/a.rs",
		"alloc\\src\\a.rs",
		// All 9 Cargo crate patterns + duplicate + edge cases
		"registry/src/idx/crate_a/a.rs",
		"registry\\src\\idx\\crate_b\\a.rs",
		"registry\\src\\idx\\crate_b\\b.rs",
		"/cargo/registry/idx/crate_c/a.rs",
		"\\cargo\\registry\\idx\\crate_d\\a.rs",
		"/rust/deps/crate_e/a.rs",
		"/rust/deps\\crate_f\\a.rs",
		"\\rust\\deps\\crate_g\\a.rs",
		".cargo/git/checkouts/crate_h/a.rs",
		".cargo\\git\\checkouts\\crate_i\\a.rs",
		// Crate edge cases: missing index sep, no trailing sep (strlen fallback), empty crate, >128 crate
		"registry/src/no_index.rs",
		"registry/src/idx/tail.rs",
		"registry/src/idx//empty.rs",
	};

	char long_crate_path[180];
	memcpy(long_crate_path, "registry/src/idx/", 17);
	memset(long_crate_path + 17, 'x', 130);
	memcpy(long_crate_path + 147, "/a.rs", 6);

	ut64 path_vas[64] = { 0 };
	size_t path_lens[64] = { 0 };
	size_t npaths = RZ_ARRAY_SIZE(panic_paths);
	for (size_t i = 0; i < npaths; i++) {
		path_vas[i] = base + 0x2000 + soff;
		path_lens[i] = strlen(panic_paths[i]);
		memcpy(img + 0x400 + soff, panic_paths[i], path_lens[i]);
		soff += path_lens[i] + 1;
	}
	path_vas[npaths] = base + 0x2000 + soff;
	path_lens[npaths] = strlen(long_crate_path);
	memcpy(img + 0x400 + soff, long_crate_path, path_lens[npaths]);
	soff += path_lens[npaths] + 1;
	npaths++;

	// Place structs starting at RVA 0x3000 (raw 0x1400)
	size_t tab_off = 0x1400;
	ut64 first_loc_va = base + 0x2000 + (tab_off - 0x400);
	for (size_t i = 0; i < npaths; i++) {
		rz_write_at_le64(img, path_vas[i], tab_off);
		rz_write_at_le64(img, path_lens[i], tab_off + 8);
		rz_write_at_le32(img, (ut32)(10 + i), tab_off + 16);
		rz_write_at_le32(img, 2, tab_off + 20);
		tab_off += 24;
	}
	// Bad line/col panic::Location candidates (line=0, line>max, col=0, col>max)
	ut32 bad_lc[4][2] = { { 0, 1 }, { 600000, 1 }, { 10, 0 }, { 10, 5000 } };
	for (size_t i = 0; i < 4; i++) {
		rz_write_at_le64(img, path_vas[0], tab_off);
		rz_write_at_le64(img, path_lens[0], tab_off + 8);
		rz_write_at_le32(img, bad_lc[i][0], tab_off + 16);
		rz_write_at_le32(img, bad_lc[i][1], tab_off + 20);
		tab_off += 24;
	}

	// Static &str entries for UTF-8, long, dup, symbol-blocked, invalid, and OOB/overflow cases
	struct {
		ut64 ptr;
		ut64 len;
	} static_pairs[] = {
		{ va_valid, strlen(s_valid) },
		{ va_valid, strlen(s_valid) }, // duplicate str_addr -> seen_strings hit
		{ va_long, long_len },
		{ va_dup1, strlen(s_dup) },
		{ va_dup2, strlen(s_dup) },
		{ va_sym_blk, strlen(s_sym_blk) },
		{ va_nonsym, strlen(s_nonsym) },
		{ va_nul, 9 },
		{ va_ctrl, 9 },
		{ va_del, 9 },
		{ va_c1, 10 },
		{ va_few, 7 },
		{ va_same, 8 },
		{ va_punct, 10 },
		{ 0, 10 }, // range_contains addr == 0
		{ UT64_MAX, 10 }, // range_contains addr == UT64_MAX
		{ UT64_MAX - 8, 32 }, // range_contains len > UT64_MAX - addr
		{ va_valid, 5000 }, // > RUST_MAX_STRING_SIZE
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(static_pairs); i++) {
		rz_write_at_le64(img, static_pairs[i].ptr, tab_off);
		rz_write_at_le64(img, static_pairs[i].len, tab_off + 8);
		tab_off += 16;
	}

	// Code at .text 0x1000 referencing first_loc_va twice (pre-existing xref at SAME pc -> seen_loc_xrefs dup)
	ut64 dup_ref_pc = base + 0x1000;
	emit_x64_lea_rip(img, 0x200, dup_ref_pc, 0x48, 0, first_loc_va);
	img[0x207] = 0xc3;

	// Run #1 without relocs (strict_unreloc = true -> tests all_same and punct rejections!)
	RzCore *core = open_synthetic_bin(img, img_sz, base);
	mu_assert_notnull(core, "open UTF-8/crates/stdlib PE64");
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_SYMBOLS);
	rz_flag_set(core->flags, "sym.blocked_str", va_sym_blk, 8);
	rz_flag_set(core->flags, "other.allowed_str", va_nonsym, 8);
	rz_flag_space_pop(core->flags);
	// Pre-existing xref to first_loc_va at dup_ref_pc exercises both existing-xref annotation and seen_loc_xrefs dedup
	rz_analysis_xrefs_set(core->analysis, dup_ref_pc, first_loc_va, RZ_ANALYSIS_XREF_TYPE_DATA);

	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover UTF-8/crates/stdlib metadata");
	mu_assert_eq(rz_pvector_len(info->crates), 10, "9 crate patterns + tail.rs extracted");
	// Valid bare filename + 3 malformed-crate paths still valid as user files
	mu_assert_true(rz_pvector_len(info->user_files) >= 1, "bare filename main_09-A.rs recovered");

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	mu_assert_notnull(rz_bin_object_get_string_at(obj, va_valid, true), "valid multibyte/tab/nl string recovered");
	mu_assert_notnull(rz_bin_object_get_string_at(obj, va_long, true), "600-byte string recovered");
	mu_assert_notnull(rz_bin_object_get_string_at(obj, va_dup1, true), "dup1 recovered");
	mu_assert_notnull(rz_bin_object_get_string_at(obj, va_dup2, true), "dup2 recovered with clash suffix");
	mu_assert_null(rz_meta_get_at(core->analysis, va_sym_blk, RZ_META_TYPE_STRING, NULL), "sym.-flagged string skipped");
	mu_assert_notnull(rz_bin_object_get_string_at(obj, va_nonsym, true), "non-sym.-flagged string recovered");
	mu_assert_null(rz_meta_get_at(core->analysis, va_nul, RZ_META_TYPE_STRING, NULL), "NUL string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_ctrl, RZ_META_TYPE_STRING, NULL), "ctrl string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_del, RZ_META_TYPE_STRING, NULL), "DEL string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_c1, RZ_META_TYPE_STRING, NULL), "C1 control string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_few, RZ_META_TYPE_STRING, NULL), "<2 printable string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_same, RZ_META_TYPE_STRING, NULL), "all-same unreloc string rejected");
	mu_assert_null(rz_meta_get_at(core->analysis, va_punct, RZ_META_TYPE_STRING, NULL), "punct-only unreloc string rejected");

	const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, dup_ref_pc);
	mu_assert_notnull(cmt, "pre-existing xref comment set");
	mu_assert_streq(cmt, "rust panic: main.09-A_.rs:10:2", "pre-existing xref panic comment");

	rz_core_rust_info_free(info);
	rz_core_free(core);

	// Run #2: Add PE base relocations containing IMAGE_REL_BASED_ABSOLUTE (type == 0) padding
	// at BOTH an unrelated address and a standalone panic::Location address (0x3018) so
	// rust_addr_has_reloc skips type == 0 via continue, plus a real DIR64 entry at 0x3000.
	rz_write_at_le32(img, 0x3e00, 0xf0); // BaseReloc DataDir RVA = 0x3e00 (raw 0x2200)
	rz_write_at_le32(img, 28, 0xf4);
	// Block 0 (12 bytes): page 0x1000 (.text, not in data_ranges) + type 0 padding
	rz_write_at_le32(img, 0x1000, 0x2200);
	rz_write_at_le32(img, 12, 0x2204);
	rz_write_at_le16(img, (10 << 12) | 0x000, 0x2208);
	rz_write_at_le16(img, 0x0000, 0x220a); // type 0 padding
	// Block 1 (16 bytes): page 0x3000 with real DIR64 at 0x000 and standalone type 0 at 0x018
	rz_write_at_le32(img, 0x3000, 0x220c);
	rz_write_at_le32(img, 16, 0x2210);
	rz_write_at_le16(img, (10 << 12) | 0x000, 0x2214); // real DIR64 at 0x3000
	rz_write_at_le16(img, (0 << 12) | 0x018, 0x2216); // standalone type 0 at 0x3018
	rz_write_at_le16(img, 0x0000, 0x2218);
	rz_write_at_le16(img, 0x0000, 0x221a);

	RzCore *core_rel = open_synthetic_bin(img, img_sz, base);
	free(img);
	mu_assert_notnull(core_rel, "open PE64 with type-0 reloc padding");
	RzCoreRustInfo *info_rel = rz_core_analysis_recover_rust_metadata(core_rel);
	mu_assert_notnull(info_rel, "recover metadata with type-0 PE reloc");
	mu_assert_eq(rz_pvector_len(info_rel->panic_locs), 1, "only relocated entry 0 recovered");
	rz_core_rust_info_free(info_rel);
	rz_core_free(core_rel);
	mu_end;
}

bool test_rust_x64_all_reg_pairs_stack_slots_and_fast_scanner(void) {
	const ut64 base = 0x140000000ULL;
	// Part A: Analyzed x86-64 functions exercising every register pair, stack slot mode/eviction,
	// clobbers, resets, panic::Location inside analyzed BB, and ninstr==0 fallback block.
	const size_t img_a_sz = 0x1400;
	ut8 *img = calloc(1, img_a_sz);
	mu_assert_notnull(img, "alloc x64 analyzed PE64");
	if (!img) {
		return false;
	}
	build_rust_pe64(img, img_a_sz, ".rdata", 0x800);
	// Expand .text raw/vsize to 0x800 (RVA 0x1000, raw 0x200) and move .rdata to raw 0xa00
	rz_write_at_le32(img, 0x800, 0x5c);
	rz_write_at_le32(img, 0x800, 0x150);
	rz_write_at_le32(img, 0x800, 0x158);
	rz_write_at_le32(img, 0xa00, 0x184);

	const char *strs[15] = {
		"pair_rcx_rdx",
		"pair_rdx_r8_",
		"pair_r8_r9__",
		"pair_rdi_rsi",
		"pair_rsi_rdx",
		"pair_rdx_rcx",
		"pair_rcx_r8_",
		"pair_rax_rdx",
		"stk_rbp_d8__",
		"stk_rbp_d32_",
		"stk_rsp_d0__",
		"stk_rsp_d32_",
		"stk_reg_imm_",
		"ninstr0_str_",
		"src/x64_bb.rs",
	};
	ut64 sva[15];
	size_t soff = 0;
	for (size_t i = 0; i < 15; i++) {
		sva[i] = base + 0x2000 + soff;
		memcpy(img + 0xa00 + soff, strs[i], strlen(strs[i]));
		soff += strlen(strs[i]); // contiguous non-NUL!
	}
	// Panic Location at RVA 0x2400 (raw 0xe00)
	ut64 loc_va = base + 0x2400;
	rz_write_at_le64(img, sva[14], 0xe00);
	rz_write_at_le64(img, strlen(strs[14]), 0xe08);
	rz_write_at_le32(img, 33, 0xe10);
	rz_write_at_le32(img, 5, 0xe14);

	size_t o = 0x200;
	ut64 pc = base + 0x1000;

	// All 8 register pairs + MOV r64, imm32 (48/49 c7) + MOV r8d..r15d (41 b8..) + non-pair + invalid lengths
	// 0: (rcx=1, rdx=2) via 48 c7 c2 (mov rdx, sign-ext imm32 > 0)
	emit_x64_lea_rip(img, o, pc, 0x48, 1, sva[0]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0xc2;
	rz_write_at_le32(img, (ut32)strlen(strs[0]), o);
	o += 4;
	pc += 7;
	// 1: (rdx=2, r8=8) via 41 b8 (mov r8d, imm32)
	emit_x64_lea_rip(img, o, pc, 0x48, 2, sva[1]);
	o += 7;
	pc += 7;
	img[o++] = 0x41;
	img[o++] = 0xb8;
	rz_write_at_le32(img, (ut32)strlen(strs[1]), o);
	o += 4;
	pc += 6;
	// 2: (r8=8, r9=9) via 4c 8d + 41 b9
	emit_x64_lea_rip(img, o, pc, 0x4c, 0, sva[2]);
	o += 7;
	pc += 7;
	img[o++] = 0x41;
	img[o++] = 0xb9;
	rz_write_at_le32(img, (ut32)strlen(strs[2]), o);
	o += 4;
	pc += 6;
	// 3: (rdi=7, rsi=6)
	emit_x64_lea_rip(img, o, pc, 0x48, 7, sva[3]);
	o += 7;
	pc += 7;
	img[o++] = 0xbe;
	rz_write_at_le32(img, (ut32)strlen(strs[3]), o);
	o += 4;
	pc += 5;
	// 4: (rsi=6, rdx=2)
	emit_x64_lea_rip(img, o, pc, 0x48, 6, sva[4]);
	o += 7;
	pc += 7;
	img[o++] = 0xba;
	rz_write_at_le32(img, (ut32)strlen(strs[4]), o);
	o += 4;
	pc += 5;
	// 5: (rdx=2, rcx=1)
	emit_x64_lea_rip(img, o, pc, 0x48, 2, sva[5]);
	o += 7;
	pc += 7;
	img[o++] = 0xb9;
	rz_write_at_le32(img, (ut32)strlen(strs[5]), o);
	o += 4;
	pc += 5;
	// 6: (rcx=1, r8=8) via 49 c7 c0 (mov r8, imm32)
	emit_x64_lea_rip(img, o, pc, 0x48, 1, sva[6]);
	o += 7;
	pc += 7;
	img[o++] = 0x49;
	img[o++] = 0xc7;
	img[o++] = 0xc0;
	rz_write_at_le32(img, (ut32)strlen(strs[6]), o);
	o += 4;
	pc += 7;
	// 7: (rax=0, rdx=2)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[7]);
	o += 7;
	pc += 7;
	img[o++] = 0xba;
	rz_write_at_le32(img, (ut32)strlen(strs[7]), o);
	o += 4;
	pc += 5;

	// Negative/too-small/too-large imms, non-pair, non-data LEA, panic::Location ref inside analyzed BB
	ut64 bb_panic_pc = pc;
	emit_x64_lea_rip(img, o, pc, 0x4c, 0, loc_va); // lea r8, [loc_va]
	o += 7;
	pc += 7;
	emit_x64_lea_rip(img, o, pc, 0x48, 0, base + 0x1000); // lea rax, [.text] (non-data)
	o += 7;
	pc += 7;
	img[o++] = 0x49; // mov r8, -1 (simm <= 0)
	img[o++] = 0xc7;
	img[o++] = 0xc0;
	rz_write_at_le32(img, 0xffffffffU, o);
	o += 4;
	pc += 7;
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[0]); // lea rax, [sva[0]]
	o += 7;
	pc += 7;
	img[o++] = 0xbb; // mov ebx, 12 (non-pair (0, 3))
	rz_write_at_le32(img, 12, o);
	o += 4;
	pc += 5;
	img[o++] = 0xba; // mov edx, 2 (< RUST_MIN_CODE_STR_LEN)
	rz_write_at_le32(img, 2, o);
	o += 4;
	pc += 5;
	img[o++] = 0xba; // mov edx, 5000 (> RUST_MAX_STRING_SIZE)
	rz_write_at_le32(img, 5000, o);
	o += 4;
	pc += 5;

	// Clobbers: xor eax, ebx (reg!=rm), xor r8, r8 (REX reg==rm), xor rax, rbx (REX reg!=rm),
	// mov r8, [rsp+0x10], mov r9, r8
	img[o++] = 0x33;
	img[o++] = 0xc3;
	pc += 2;
	img[o++] = 0x4d;
	img[o++] = 0x31;
	img[o++] = 0xc0;
	pc += 3;
	img[o++] = 0x48;
	img[o++] = 0x33;
	img[o++] = 0xc3;
	pc += 3;
	img[o++] = 0x4c;
	img[o++] = 0x8b;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x10;
	pc += 5;
	img[o++] = 0x4d;
	img[o++] = 0x8b;
	img[o++] = 0xc8;
	pc += 3;

	// Stack slots: [rbp+disp8], [rbp+disp32], [rsp] (mod=0), [rsp+disp32], reg-imm store,
	// non-stack modrm, bad SIB, negative imm, slot overwrite, and 9-slot eviction (both ptr & imm)!
	// 8: [rbp - 0x20] / [rbp - 0x18] (mod=1, rm=5) + overwrite existing ptr & imm slots first
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[8]);
	o += 7;
	pc += 7;
	// mov [rbp-0x20], rax TWICE (overwrite ptr slot)
	for (int rep = 0; rep < 2; rep++) {
		img[o++] = 0x48;
		img[o++] = 0x89;
		img[o++] = 0x45;
		img[o++] = 0xe0;
		pc += 4;
	}
	// mov qword [rbp-0x18], 2 (too small), then -1 (simm<=0), then valid len (overwrite imm slot!)
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x45;
	img[o++] = 0xe8;
	rz_write_at_le32(img, 2, o);
	o += 4;
	pc += 8;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x45;
	img[o++] = 0xe8;
	rz_write_at_le32(img, 0xffffffffU, o);
	o += 4;
	pc += 8;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x45;
	img[o++] = 0xe8;
	rz_write_at_le32(img, (ut32)strlen(strs[8]), o);
	o += 4;
	pc += 8;

	// 9: [rbp - 0x100] / [rbp - 0xf8] (mod=2, disp32, rm=5)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[9]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x85;
	rz_write_at_le32(img, (ut32)(st32)-0x100, o);
	o += 4;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x85;
	rz_write_at_le32(img, (ut32)(st32)-0xf8, o);
	o += 4;
	rz_write_at_le32(img, (ut32)strlen(strs[9]), o);
	o += 4;
	pc += 11;

	// 10: [rsp] (mod=0, rm=4, sib=0x24) + [rsp + 0x08]
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[10]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x04;
	img[o++] = 0x24;
	pc += 4;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x08;
	rz_write_at_le32(img, (ut32)strlen(strs[10]), o);
	o += 4;
	pc += 9;

	// 11: [rsp + 0x100] / [rsp + 0x108] (mod=2, disp32, rm=4, sib=0x24)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[11]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x84;
	img[o++] = 0x24;
	rz_write_at_le32(img, 0x100, o);
	o += 4;
	pc += 8;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x84;
	img[o++] = 0x24;
	rz_write_at_le32(img, 0x108, o);
	o += 4;
	rz_write_at_le32(img, (ut32)strlen(strs[11]), o);
	o += 4;
	pc += 12;

	// 12: mov [rsp + 0x30], rax (ptr); mov ebx, len; mov [rsp + 0x38], rbx (reg-imm -> stack_slot_record_imm!)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[12]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x30;
	pc += 5;
	img[o++] = 0xbb;
	rz_write_at_le32(img, (ut32)strlen(strs[12]), o);
	o += 4;
	pc += 5;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x5c;
	img[o++] = 0x24;
	img[o++] = 0x38;
	pc += 5;

	// Invalid stack modrm / bad SIB (both base!=4 and index!=4) / RIP-rel rm=5 mod=0 /
	// non-stack imm / reg with neither ptr nor imm / extra branch guards (41 50, 41 c3, 48 c7 /1,
	// 31 00, 48 31 00, ff d8, e9 +0, mismatched stack disp & oversized stack imm)
	img[o++] = 0x48; // mov [rbx + 0x10], rax (non-stack rm=3)
	img[o++] = 0x89;
	img[o++] = 0x43;
	img[o++] = 0x10;
	pc += 4;
	img[o++] = 0x48; // mov [rax + rcx], rax (bad SIB base=0 != 4)
	img[o++] = 0x89;
	img[o++] = 0x04;
	img[o++] = 0x08;
	pc += 4;
	img[o++] = 0x48; // mov [rsp + rax], rax (bad SIB base=4, index=0 != 4)
	img[o++] = 0x89;
	img[o++] = 0x04;
	img[o++] = 0x04;
	pc += 4;
	img[o++] = 0x48; // mov [rip + 0], rax (rm=5, mod=0 -> fails mod==1||mod==2)
	img[o++] = 0x89;
	img[o++] = 0x05;
	rz_write_at_le32(img, 0, o);
	o += 4;
	pc += 7;
	img[o++] = 0x4c; // mov [rsp + 0x40], r8 (r8 was cleared -> neither ptr nor imm)
	img[o++] = 0x89;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x40;
	pc += 5;
	img[o++] = 0x48; // mov qword [rbx + 0x10], 10 (non-stack imm)
	img[o++] = 0xc7;
	img[o++] = 0x43;
	img[o++] = 0x10;
	rz_write_at_le32(img, 10, o);
	o += 4;
	pc += 8;
	img[o++] = 0x41; // push r8 (41 50 -> b[1] < 0xb8)
	img[o++] = 0x50;
	pc += 2;
	img[o++] = 0x41; // 41 58 pop r8
	img[o++] = 0x58;
	pc += 2;
	img[o++] = 0x31; // xor [rax], eax ((b[1] & 0xc0) != 0xc0)
	img[o++] = 0x00;
	pc += 2;
	img[o++] = 0x48; // xor [rax], rax ((b[2] & 0xc0) != 0xc0)
	img[o++] = 0x31;
	img[o++] = 0x00;
	pc += 3;
	img[o++] = 0xff; // call/jmp non-/2/4: fcomp / dec (ff c8 -> dec eax, ((b[1]>>3)&7)==1)
	img[o++] = 0xc8;
	pc += 2;
	img[o++] = 0xe9; // jmp +0 (0xe9 reset inside analyzed BB)
	rz_write_at_le32(img, 0, o);
	o += 4;
	pc += 5;

	// Stack pair with oversized imm (> 4096) and non-adjacent disp (ptr at +0x10, imm at +0x20 & +0x18=5000)
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[0]);
	o += 7;
	pc += 7;
	img[o++] = 0x48;
	img[o++] = 0x89;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x10;
	pc += 5;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x20;
	rz_write_at_le32(img, 12, o);
	o += 4;
	pc += 9;
	img[o++] = 0x48;
	img[o++] = 0xc7;
	img[o++] = 0x44;
	img[o++] = 0x24;
	img[o++] = 0x18;
	rz_write_at_le32(img, 5000, o);
	o += 4;
	pc += 9;

	// Fill 9 distinct ptr slots ([rsp + 0x50..0x90] step 8) to trigger ptr slot memmove eviction
	emit_x64_lea_rip(img, o, pc, 0x48, 0, sva[0]);
	o += 7;
	pc += 7;
	for (ut8 k = 0; k < 9; k++) {
		img[o++] = 0x48;
		img[o++] = 0x89;
		img[o++] = 0x44;
		img[o++] = 0x24;
		img[o++] = (ut8)(0x50 + k * 8);
		pc += 5;
	}
	// Fill 9 distinct imm slots ([rbp - 0x40..-0x80] step -8) to trigger imm slot memmove eviction
	for (ut8 k = 0; k < 9; k++) {
		img[o++] = 0x48;
		img[o++] = 0xc7;
		img[o++] = 0x45;
		img[o++] = (ut8)(st8)(-0x40 - (int)k * 8);
		rz_write_at_le32(img, 5000, o); // > max so slots remain populated
		o += 4;
		pc += 8;
	}
	// Indirect CALL (ff d0), direct CALL (e8 00000000), RET imm16 (c2 08 00)
	img[o++] = 0xff;
	img[o++] = 0xd0;
	pc += 2;
	img[o++] = 0xe8;
	rz_write_at_le32(img, 0, o);
	o += 4;
	pc += 5;
	img[o++] = 0xc2;
	img[o++] = 0x08;
	img[o++] = 0x00;

	// Separate block at RVA 0x1400 (raw 0x600) for manual ninstr == 0 BB + indirect jmp ff e0 + eb 00
	size_t o2 = 0x600;
	ut64 pc2 = base + 0x1400;
	emit_x64_lea_rip(img, o2, pc2, 0x48, 1, sva[13]);
	o2 += 7;
	pc2 += 7;
	img[o2++] = 0xba;
	rz_write_at_le32(img, (ut32)strlen(strs[13]), o2);
	o2 += 4;
	img[o2++] = 0xff; // jmp rax (ff /4)
	img[o2++] = 0xe0;
	img[o2++] = 0xeb; // jmp +0
	img[o2++] = 0x00;
	img[o2++] = 0xc3;

	RzCore *core = open_synthetic_bin(img, img_a_sz, base);
	free(img);
	mu_assert_notnull(core, "open x64 analyzed PE64");

	rz_core_analysis_fcn(core, base + 0x1000, UT64_MAX, RZ_ANALYSIS_XREF_TYPE_NULL, 1);
	// Add manual function with: (1) ninstr == 0 block, (2) zero-size block, (3) unmapped block
	RzAnalysisFunction *mfcn = rz_analysis_create_function(core->analysis, "manual_x64", base + 0x1400, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(mfcn, "create manual x64 function");
	RzAnalysisBlock *bb_ninstr0 = rz_analysis_create_block(core->analysis, base + 0x1400, (ut64)(o2 - 0x600));
	RzAnalysisBlock *bb_zero = rz_analysis_create_block(core->analysis, base + 0x1500, 0);
	RzAnalysisBlock *bb_unmapped = rz_analysis_create_block(core->analysis, 0x70000000ULL, 16);
	rz_analysis_function_add_block(mfcn, bb_ninstr0);
	rz_analysis_function_add_block(mfcn, bb_zero);
	rz_analysis_function_add_block(mfcn, bb_unmapped);
	rz_analysis_block_unref(bb_ninstr0);
	rz_analysis_block_unref(bb_zero);
	rz_analysis_block_unref(bb_unmapped);
	// Disable io->ff so unmapped block triggers nr != bb->size continue
	core->io->ff = false;

	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover x64 analyzed metadata");
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	for (size_t i = 0; i < 14; i++) {
		RzBinString *bs = rz_bin_object_get_string_at(obj, sva[i], true);
		mu_assert_notnull(bs, "x64 reg/stack/ninstr0 string recovered");
		mu_assert_streq(bs->string, strs[i], "x64 string exact text");
	}
	const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, bb_panic_pc);
	mu_assert_notnull(cmt, "analyzed BB panic::Location comment set");
	mu_assert_streq(cmt, "rust panic: src/x64_bb.rs:33:5", "analyzed BB panic comment");
	rz_core_rust_info_free(info);
	rz_core_free(core);

	// Part B: Fast unanalyzed scanner (scan_x64_exec_sections_fast) with > 64 KiB .text
	// exercising pre-LEA 5/6/7-byte mov imm patterns and multi-chunk sliding window.
	const size_t text_sz = 0x11000;
	const size_t img_b_sz = 0x200 + text_sz + 0x400;
	ut8 *img_b = calloc(1, img_b_sz);
	mu_assert_notnull(img_b, "alloc >64KiB .text PE64");
	if (!img_b) {
		return false;
	}
	build_rust_pe64(img_b, img_b_sz, ".rdata", 0x400);
	rz_write_at_le32(img_b, (ut32)text_sz, 0x5c);
	rz_write_at_le32(img_b, 0x1000 + (ut32)text_sz + 0x1000, 0x90);
	// Section 0 (.text): RVA 0x1000, size 0x11000, raw 0x200
	rz_write_at_le32(img_b, (ut32)text_sz, 0x150);
	rz_write_at_le32(img_b, (ut32)text_sz, 0x158);
	// Section 1 (.rdata): RVA 0x12000, size 0x400, raw 0x11200
	const ut64 rdata_va = base + 0x12000;
	const size_t rdata_raw = 0x200 + text_sz;
	rz_write_at_le32(img_b, 0x12000, 0x17c);
	rz_write_at_le32(img_b, (ut32)rdata_raw, 0x184);

	const char *fstrs[5] = {
		"fast_pre5_str",
		"fast_pre6_str",
		"fast_pre7a_str",
		"fast_pre7b_str",
		"fast_chunk2_str",
	};
	ut64 fva[5];
	size_t foff = 0;
	for (size_t i = 0; i < 5; i++) {
		fva[i] = rdata_va + foff;
		memcpy(img_b + rdata_raw + foff, fstrs[i], strlen(fstrs[i]));
		foff += strlen(fstrs[i]);
	}

	// Place pre-LEA patterns in chunk 1 (offset 0x20 in .text)
	size_t fo = 0x200 + 0x20;
	ut64 fpc = base + 0x1020;
	// 0: 5-byte mov edx, len BEFORE lea rcx, [fva[0]]
	img_b[fo++] = 0xba;
	rz_write_at_le32(img_b, (ut32)strlen(fstrs[0]), fo);
	fo += 4;
	fpc += 5;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	// 1: 6-byte mov r8d, len (41 b8) BEFORE lea rdx, [fva[1]]
	img_b[fo++] = 0x41;
	img_b[fo++] = 0xb8;
	rz_write_at_le32(img_b, (ut32)strlen(fstrs[1]), fo);
	fo += 4;
	fpc += 6;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 2, fva[1]);
	fo += 7;
	fpc += 7;
	// 2: 7-byte mov rdx, len (48 c7 c2) BEFORE lea rcx, [fva[2]]
	img_b[fo++] = 0x48;
	img_b[fo++] = 0xc7;
	img_b[fo++] = 0xc2;
	rz_write_at_le32(img_b, (ut32)strlen(fstrs[2]), fo);
	fo += 4;
	fpc += 7;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[2]);
	fo += 7;
	fpc += 7;
	// 3: 7-byte mov r8, len (49 c7 c0) BEFORE lea rdx, [fva[3]]
	img_b[fo++] = 0x49;
	img_b[fo++] = 0xc7;
	img_b[fo++] = 0xc0;
	rz_write_at_le32(img_b, (ut32)strlen(fstrs[3]), fo);
	fo += 4;
	fpc += 7;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 2, fva[3]);
	fo += 7;
	fpc += 7;
	// Non-data LEA target (skipped by range_contains) + mismatched/out-of-range pre-movs
	// exercising 5/6/7-byte rejection branches before falling into the 4-insn lookahead loop
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, base + 0x1000);
	fo += 7;
	fpc += 7;
	// 5-byte: non-pair (ebx), <4 (2), >4096 (5000)
	img_b[fo++] = 0xbb;
	rz_write_at_le32(img_b, 10, fo);
	fo += 4;
	fpc += 5;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0xba;
	rz_write_at_le32(img_b, 2, fo);
	fo += 4;
	fpc += 5;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0xba;
	rz_write_at_le32(img_b, 5000, fo);
	fo += 4;
	fpc += 5;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	// 6-byte (41 b8..bf): non-pair (r9 with rcx), <4, >4096, plus 41 50 (not b8..bf)
	img_b[fo++] = 0x41;
	img_b[fo++] = 0xb9;
	rz_write_at_le32(img_b, 10, fo);
	fo += 4;
	fpc += 6;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0x41;
	img_b[fo++] = 0xb8;
	rz_write_at_le32(img_b, 2, fo);
	fo += 4;
	fpc += 6;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 2, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0x41;
	img_b[fo++] = 0xb8;
	rz_write_at_le32(img_b, 5000, fo);
	fo += 4;
	fpc += 6;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 2, fva[0]);
	fo += 7;
	fpc += 7;
	// 7-byte (48/49 c7 c0..c7): non-pair (rbx), <4, >4096, and non-c0..c7 modrm
	img_b[fo++] = 0x48;
	img_b[fo++] = 0xc7;
	img_b[fo++] = 0xc3;
	rz_write_at_le32(img_b, 10, fo);
	fo += 4;
	fpc += 7;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0x48;
	img_b[fo++] = 0xc7;
	img_b[fo++] = 0xc2;
	rz_write_at_le32(img_b, 2, fo);
	fo += 4;
	fpc += 7;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	img_b[fo++] = 0x48;
	img_b[fo++] = 0xc7;
	img_b[fo++] = 0xc2;
	rz_write_at_le32(img_b, 5000, fo);
	fo += 4;
	fpc += 7;
	emit_x64_lea_rip(img_b, fo, fpc, 0x48, 1, fva[0]);
	fo += 7;
	fpc += 7;
	// 4: Chunk 2 (> 64 KiB boundary) at offset 0x10100 in .text + LEA near very end (< 16 bytes left)
	size_t fo2 = 0x200 + 0x10100;
	ut64 fpc2 = base + 0x1000 + 0x10100;
	img_b[fo2++] = 0xba;
	rz_write_at_le32(img_b, (ut32)strlen(fstrs[4]), fo2);
	fo2 += 4;
	fpc2 += 5;
	emit_x64_lea_rip(img_b, fo2, fpc2, 0x48, 1, fva[4]);
	// LEA placed 11 bytes before end of .text -> win_end - pos == 4 < 16 (covers RZ_MIN branch)
	size_t fo_end = 0x200 + text_sz - 11;
	ut64 fpc_end = base + 0x1000 + text_sz - 11;
	emit_x64_lea_rip(img_b, fo_end, fpc_end, 0x48, 1, fva[0]);
	img_b[fo_end + 7] = 0x90;
	img_b[fo_end + 8] = 0x90;
	img_b[fo_end + 9] = 0x90;
	img_b[fo_end + 10] = 0x90;

	RzCore *core_b = open_synthetic_bin(img_b, img_b_sz, base);
	free(img_b);
	mu_assert_notnull(core_b, "open >64KiB .text PE64");
	RzCoreRustInfo *info_b = rz_core_analysis_recover_rust_metadata(core_b);
	mu_assert_notnull(info_b, "recover fast-scanner metadata");
	RzBinObject *obj_b = rz_bin_cur_object(core_b->bin);
	for (size_t i = 0; i < 5; i++) {
		RzBinString *bs = rz_bin_object_get_string_at(obj_b, fva[i], true);
		mu_assert_notnull(bs, "fast-scanner pre-LEA / chunk2 string recovered");
		mu_assert_streq(bs->string, fstrs[i], "fast-scanner string exact text");
	}
	rz_core_rust_info_free(info_b);
	rz_core_free(core_b);
	mu_end;
}

bool test_rust_arm64_analyzed_fcns_and_variants(void) {
	// ARM64 ELF64 with .rodata below .text (0x401000), .text (0x402000..0x404000),
	// and .data.rel.ro above .text (0x404000) to test both positive & negative ADR/ADRP,
	// shift-12 ADD, pre-loaded MOVZ before ADRP+ADD, BL reset, analyzed BB path, and tail B wrapper.
	const size_t img_sz = 0x5000;
	ut8 *img = calloc(1, img_sz);
	mu_assert_notnull(img, "alloc ARM64 variants ELF64");
	if (!img) {
		return false;
	}

	const ut64 rodata_va = 0x401000ULL;
	const ut64 text_va = 0x402000ULL;
	const ut64 hi_rodata_va = 0x404000ULL;
	const char shstrtab[] = "\0.rodata\0.text\0.data.rel.ro\0.shstrtab\0";
	memcpy(img + 0x100, shstrtab, sizeof(shstrtab));

	write_elf64_ehdr(img, 183 /* EM_AARCH64 */, text_va + 0x1020, 0x40, 0x200, 3, 5, 4);
	emit_elf64_phdr(img, 0x40, 1, 4, 0x1000, rodata_va, 0x1000);
	emit_elf64_phdr(img, 0x78, 1, 5, 0x2000, text_va, 0x2000);
	emit_elf64_phdr(img, 0xb0, 1, 4, 0x4000, hi_rodata_va, 0x1000);

	emit_elf64_shdr(img, 0x240, 1, 1, 2, rodata_va, 0x1000, 0x1000, 0, 0, 8, 0);
	emit_elf64_shdr(img, 0x280, 9, 1, 6, text_va, 0x2000, 0x2000, 0, 0, 4, 0);
	emit_elf64_shdr(img, 0x2c0, 15, 1, 2, hi_rodata_va, 0x4000, 0x1000, 0, 0, 8, 0);
	emit_elf64_shdr(img, 0x300, 28, 3, 0, 0, 0x100, sizeof(shstrtab), 0, 0, 1, 0);

	// String at exact page boundary 0x401000 for ADRP 0x400000 + ADD #1, LSL #12
	const char *s_shift = "arm64_lsl12_str";
	memcpy(img + 0x1000, s_shift, strlen(s_shift));
	// Positive-offset panic::Location in hi_rodata (0x404100)
	const char *s_hi_loc = "src/arm64_hi.rs";
	memcpy(img + 0x4000, s_hi_loc, strlen(s_hi_loc));
	rz_write_at_le64(img, hi_rodata_va, 0x4100);
	rz_write_at_le64(img, strlen(s_hi_loc), 0x4108);
	rz_write_at_le32(img, 88, 0x4110);
	rz_write_at_le32(img, 4, 0x4114);

	// 0x402000: user_main (analyzed function)
	size_t o = 0x2000;
	ut64 pc = text_va;
	// 1. Pre-load x1 = strlen(s_shift), then ADRP x0, 0x400000; ADD x0, x0, #1, LSL #12
	emit_arm64_movz(img, o, 1, (ut32)strlen(s_shift));
	o += 4;
	pc += 4;
	emit_arm64_adrp(img, o, pc, 0, 0x400000ULL);
	o += 4;
	pc += 4;
	emit_arm64_add_imm_shift(img, o, 0, 0, 1); // 0x400000 + (1<<12) = 0x401000!
	o += 4;
	pc += 4;
	// 2. ADD without has_page (rn=5), MOVZ xzr (rd=31), MOVZ len<4, STR without ptr/imm
	emit_arm64_add_imm(img, o, 2, 5, 0x10);
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 31, 16);
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 1, 2);
	o += 4;
	pc += 4;
	emit_arm64_str_sp(img, o, 10, 0x20);
	o += 4;
	pc += 4;
	// 3. Positive ADR pointing to panic::Location at 0x404100
	ut64 adr_panic_pc = pc;
	emit_arm64_adr(img, o, pc, 4, hi_rodata_va + 0x100);
	o += 4;
	pc += 4;
	// 4. ADR pointing to non-data (.text), rd >= 7, imm < 4 / imm > 4096 for both ADR and ADRP+ADD,
	//    and BL (resets regs/has_page but not slots)
	emit_arm64_adr(img, o, pc, 6, text_va + 0x200);
	o += 4;
	pc += 4;
	emit_arm64_adr(img, o, pc, 8, rodata_va); // rd >= 7
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 3, 2); // imm < 4
	o += 4;
	pc += 4;
	emit_arm64_adr(img, o, pc, 2, rodata_va);
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 3, 5000); // imm > 4096
	o += 4;
	pc += 4;
	emit_arm64_adr(img, o, pc, 2, rodata_va);
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 1, 2); // ADRP+ADD with imm < 4
	o += 4;
	pc += 4;
	emit_arm64_adrp(img, o, pc, 0, rodata_va);
	o += 4;
	pc += 4;
	emit_arm64_add_imm(img, o, 0, 0, 0);
	o += 4;
	pc += 4;
	emit_arm64_movz(img, o, 1, 5000); // ADRP+ADD with imm > 4096
	o += 4;
	pc += 4;
	emit_arm64_adrp(img, o, pc, 0, rodata_va);
	o += 4;
	pc += 4;
	emit_arm64_add_imm(img, o, 0, 0, 0);
	o += 4;
	pc += 4;
	emit_arm64_bl(img, o, pc, text_va + 0x1100);
	o += 4;
	pc += 4;
	// Pad with NOPs (0xd503201f) to cover >= 10% of 0x2000 .text so fallback raw scan is skipped
	for (size_t n = 0; n < 220; n++) {
		rz_write_at_le32(img, 0xd503201fU, o);
		o += 4;
		pc += 4;
	}
	rz_write_at_le32(img, 0xd65f03c0U, o);
	size_t user_main_sz = (o + 4) - 0x2000;

	// 0x403020 (file 0x3020): wrapper with NEGATIVE ADRP (0x401000) + ADD #1, LSL #12 (= 0x402000)
	// + positive tail B to lang_start at 0x403100!
	emit_arm64_adrp(img, 0x3020, text_va + 0x1020, 0, 0x401000ULL);
	emit_arm64_add_imm_shift(img, 0x3024, 0, 0, 1);
	emit_arm64_b(img, 0x3028, text_va + 0x1028, text_va + 0x1100);
	rz_write_at_le32(img, 0xd65f03c0U, 0x3100); // lang_start stub

	// 0x403140: invalid ARM64 wrapper (ADD without page, ADRP+ADD to rodata, BL outside .text, 2 calls)
	emit_arm64_add_imm(img, 0x3140, 0, 0, 0x10); // x0_has_page == false
	emit_arm64_adrp(img, 0x3144, text_va + 0x1144, 0, rodata_va);
	emit_arm64_add_imm(img, 0x3148, 0, 0, 0); // non-exec target
	emit_arm64_bl(img, 0x314c, text_va + 0x114c, rodata_va); // non-exec BL
	emit_arm64_adrp(img, 0x3150, text_va + 0x1150, 0, text_va);
	emit_arm64_add_imm(img, 0x3154, 0, 0, 0);
	emit_arm64_bl(img, 0x3158, text_va + 0x1158, text_va + 0x1100);
	emit_arm64_bl(img, 0x315c, text_va + 0x115c, text_va + 0x1100);
	rz_write_at_le32(img, 0xd65f03c0U, 0x3160);

	// 0x403180: ARM64 wrapper where cand_x0 == wrapper_va
	emit_arm64_adrp(img, 0x3180, text_va + 0x1180, 0, text_va + 0x1180);
	emit_arm64_add_imm(img, 0x3184, 0, 0, 0x180);
	emit_arm64_bl(img, 0x3188, text_va + 0x1188, text_va + 0x1100);
	rz_write_at_le32(img, 0xd65f03c0U, 0x318c);

	// 0x4031c0: ARM64 wrapper where cand_x0 == call_target
	emit_arm64_adrp(img, 0x31c0, text_va + 0x11c0, 0, text_va + 0x1100);
	emit_arm64_add_imm(img, 0x31c4, 0, 0, 0x100);
	emit_arm64_bl(img, 0x31c8, text_va + 0x11c8, text_va + 0x1100);
	rz_write_at_le32(img, 0xd65f03c0U, 0x31cc);

	// 0x403200: 128-byte NOP-only ARM64 wrapper (exits loop without RET/B)
	for (size_t k = 0; k < 32; k++) {
		rz_write_at_le32(img, 0xd503201fU, 0x3200 + k * 4);
	}

	RzCore *core = open_synthetic_bin(img, img_sz, UT64_MAX);
	free(img);
	mu_assert_notnull(core, "open ARM64 variants ELF64");

	// Manually populate analyzed ARM64 blocks: (1) full user_main (>10% of .text -> skips raw scan),
	// (2) smaller 16-byte block (bb->size <= bb_cap), (3) tiny 4-byte block (< 8 bytes skip),
	// (4) unmapped 16-byte block with io->ff=false (nr < 8 skip).
	RzAnalysisFunction *arm_fcn = rz_analysis_create_function(core->analysis, "arm64_user_main", text_va, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(arm_fcn, "create arm64 analyzed function");
	RzAnalysisBlock *arm_bb = rz_analysis_create_block(core->analysis, text_va, (ut64)user_main_sz);
	RzAnalysisBlock *arm_bb2 = rz_analysis_create_block(core->analysis, text_va + 0x1100, 16);
	RzAnalysisBlock *tiny_bb = rz_analysis_create_block(core->analysis, text_va + 0x1120, 4);
	RzAnalysisBlock *unmap_bb = rz_analysis_create_block(core->analysis, 0x70000000ULL, 16);
	rz_analysis_function_add_block(arm_fcn, arm_bb);
	rz_analysis_function_add_block(arm_fcn, arm_bb2);
	rz_analysis_function_add_block(arm_fcn, tiny_bb);
	rz_analysis_function_add_block(arm_fcn, unmap_bb);
	rz_analysis_block_unref(arm_bb);
	rz_analysis_block_unref(arm_bb2);
	rz_analysis_block_unref(tiny_bb);
	rz_analysis_block_unref(unmap_bb);
	core->io->ff = false;

	rz_flag_set(core->flags, "main", text_va + 0x1020, 1);
	RzCoreRustInfo *info = rz_core_analysis_recover_rust_metadata(core);
	mu_assert_notnull(info, "recover ARM64 analyzed metadata");
	mu_assert_eq(info->main_addr, text_va, "ARM64 negative ADRP + LSL12 + tail B recovers user_main");
	mu_assert_eq(info->lang_start_addr, text_va + 0x1100, "ARM64 tail B recovers lang_start");

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzBinString *bs = rz_bin_object_get_string_at(obj, rodata_va, true);
	mu_assert_notnull(bs, "ARM64 preloaded MOVZ + LSL12 string recovered");
	mu_assert_streq(bs->string, s_shift, "ARM64 LSL12 string text");

	const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, adr_panic_pc);
	mu_assert_notnull(cmt, "ARM64 positive ADR panic::Location comment set");
	mu_assert_streq(cmt, "rust panic: src/arm64_hi.rs:88:4", "ARM64 ADR panic comment");
	rz_core_rust_info_free(info);

	// Test invalid ARM64 wrappers: 2-call, cand_x0==wrapper_va, cand_x0==call_target, 128-byte NOP, non-exec
	ut64 bad_arm_mains[] = { text_va + 0x1140, text_va + 0x1180, text_va + 0x11c0, text_va + 0x1200, rodata_va };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(bad_arm_mains); i++) {
		rz_flag_unset_name(core->flags, "main");
		rz_flag_set(core->flags, "main", bad_arm_mains[i], 1);
		RzCoreRustInfo *info_bad = rz_core_analysis_recover_rust_metadata(core);
		mu_assert_notnull(info_bad, "invalid ARM64 wrapper metadata");
		mu_assert_eq(info_bad->main_addr, UT64_MAX, "invalid ARM64 wrapper rejected");
		rz_core_rust_info_free(info_bad);
	}

	rz_core_free(core);
	mu_end;
}

bool test_rust_section_filters_endian32_and_error_paths(void) {
	// 1. NULL-safe free & no-binary error paths (including CLI aalr error path)
	rz_core_rust_info_free(NULL);
	RzCore *empty_core = rz_core_new();
	mu_assert_notnull(empty_core, "create empty RzCore");
	mu_assert_null(rz_core_analysis_recover_rust_metadata(empty_core), "no binary returns NULL");
	mu_assert_eq(rz_core_analysis_resolve_rust_strings(empty_core), 0, "no binary resolves 0 strings");
	char *err_out = rz_core_cmd_str(empty_core, "aalr");
	free(err_out);
	rz_core_free(empty_core);

	// 2. Binary with NO data sections (only .text) + CLI aalr & aalrj on empty results
	//    + unsupported word size (16-bit) + unsupported 64-bit arch + bad x64 wrappers
	//    + PE relocs outside data_ranges.
	const ut64 base = 0x140000000ULL;
	ut8 pe_nodata[0x600];
	build_rust_pe64(pe_nodata, sizeof(pe_nodata), ".rdata", 0x200);
	rz_write_at_le16(pe_nodata, 1, 0x46); // only 1 section (.text)
	RzCore *core_nd = open_synthetic_bin(pe_nodata, sizeof(pe_nodata), base);
	mu_assert_notnull(core_nd, "open no-data PE64");

	RzCoreRustInfo *info_nd = rz_core_analysis_recover_rust_metadata(core_nd);
	mu_assert_notnull(info_nd, "no-data PE64 returns empty info");
	mu_assert_eq(info_nd->strings_recovered, 0, "no-data PE64 recovers 0 strings");
	rz_core_rust_info_free(info_nd);

	// Exercise aalr and aalrj when main == UT64_MAX, lang_start == UT64_MAX, empty crates/user_files
	char *empty_json = rz_core_cmd_str(core_nd, "aalrj");
	mu_assert_notnull(empty_json, "aalrj on empty result");
	mu_assert_true(strstr(empty_json, "\"main\":null") != NULL, "aalrj null main");
	mu_assert_true(strstr(empty_json, "\"lang_start\":null") != NULL, "aalrj null lang_start");
	free(empty_json);
	char *empty_std = rz_core_cmd_str(core_nd, "aalr");
	mu_assert_notnull(empty_std, "aalr on empty result");
	mu_assert_true(strstr(empty_std, "strings: 0") != NULL, "aalr zero strings");
	free(empty_std);

	// Exercise word_size == 2 (16-bit unsupported -> early cleanup)
	rz_config_set_i(core_nd->config, "asm.bits", 16);
	RzCoreRustInfo *info_16 = rz_core_analysis_recover_rust_metadata(core_nd);
	mu_assert_notnull(info_16, "16-bit early cleanup");
	rz_core_rust_info_free(info_16);
	rz_core_free(core_nd);

	// 3. PE64 with reloc ONLY in .text (detect_data_relocs returns false), bad x64 wrappers
	//    (main outside .text, 2-call wrapper, call outside .text), and non-x86/arm 64-bit arch
	ut8 pe_badw[0x800];
	build_rust_pe64(pe_badw, sizeof(pe_badw), ".rdata", 0x400);
	// Reloc block pointing only into .text (0x1000)
	rz_write_at_le32(pe_badw, 0x2200, 0xf0);
	rz_write_at_le32(pe_badw, 12, 0xf4);
	rz_write_at_le32(pe_badw, 0x1000, 0x600);
	rz_write_at_le32(pe_badw, 12, 0x604);
	rz_write_at_le16(pe_badw, (10 << 12) | 0x000, 0x608);
	rz_write_at_le16(pe_badw, 0, 0x60a);
	// 0x1000: bad wrapper exercising OOB LEA, PE non-rdx data LEA, mov with unset reg_text,
	// lea before stack_fn_va, wrong dst_reg, mismatched is_rbp/disp, 2 calls, and OOB call
	size_t bo = 0x200;
	ut64 bpc = base + 0x1000;
	emit_x64_lea_rip(pe_badw, bo, bpc, 0x48, 0, base + 0x99000); // neither exec nor data
	bo += 7;
	bpc += 7;
	emit_x64_lea_rip(pe_badw, bo, bpc, 0x48, 3, base + 0x2000); // PE data LEA in rbx (!= rdx)
	bo += 7;
	bpc += 7;
	pe_badw[bo++] = 0x48; // mov [rsp+0x10], rbx (reg_text[3] == UT64_MAX)
	pe_badw[bo++] = 0x89;
	pe_badw[bo++] = 0x5c;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x10;
	bpc += 5;
	pe_badw[bo++] = 0x48; // lea rcx, [rsp+0x10] (stack_fn_va == UT64_MAX)
	pe_badw[bo++] = 0x8d;
	pe_badw[bo++] = 0x4c;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x10;
	bpc += 5;
	emit_x64_lea_rip(pe_badw, bo, bpc, 0x48, 0, base + 0x1080); // lea rax, [exec]
	bo += 7;
	bpc += 7;
	pe_badw[bo++] = 0x48; // mov [rbx+0x10], rax (non-stack modrm -> decode false)
	pe_badw[bo++] = 0x89;
	pe_badw[bo++] = 0x43;
	pe_badw[bo++] = 0x10;
	bpc += 4;
	pe_badw[bo++] = 0x48; // mov [rsp+0x10], rax (sets stack_fn_va)
	pe_badw[bo++] = 0x89;
	pe_badw[bo++] = 0x44;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x10;
	bpc += 5;
	pe_badw[bo++] = 0x48; // lea rdx, [rsp+0x10] (wrong dst_reg)
	pe_badw[bo++] = 0x8d;
	pe_badw[bo++] = 0x54;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x10;
	bpc += 5;
	pe_badw[bo++] = 0x48; // lea rcx, [rsp+0x20] (mismatched disp)
	pe_badw[bo++] = 0x8d;
	pe_badw[bo++] = 0x4c;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x20;
	bpc += 5;
	pe_badw[bo++] = 0x48; // lea rcx, [rbp+0x10] (mismatched is_rbp)
	pe_badw[bo++] = 0x8d;
	pe_badw[bo++] = 0x4d;
	pe_badw[bo++] = 0x10;
	bpc += 4;
	pe_badw[bo++] = 0x48; // lea rcx, [rsp+0x10] (matches stack slot, but NO vtable -> has_vtable_arg1 false)
	pe_badw[bo++] = 0x8d;
	pe_badw[bo++] = 0x4c;
	pe_badw[bo++] = 0x24;
	pe_badw[bo++] = 0x10;
	bpc += 5;
	pe_badw[bo++] = 0xe8; // call 0x10c0 (in .text)
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(bpc + 5)), bo);
	bo += 4;
	bpc += 5;
	pe_badw[bo++] = 0xe8; // 2nd call 0x10c0 (calls == 2)
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(bpc + 5)), bo);
	bo += 4;
	bpc += 5;
	pe_badw[bo++] = 0xe8; // call outside .text (range_contains false)
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x2000) - (st64)(bpc + 5)), bo);
	bo += 4;
	pe_badw[bo++] = 0xc3;

	// 0x1080: wrapper where user_main == wrapper_va
	emit_x64_lea_rip(pe_badw, 0x280, base + 0x1080, 0x48, 1, base + 0x1080);
	pe_badw[0x287] = 0xe8;
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(base + 0x108c)), 0x288);
	pe_badw[0x28c] = 0xc3;

	// 0x10a0: wrapper where user_main == call_target
	emit_x64_lea_rip(pe_badw, 0x2a0, base + 0x10a0, 0x48, 1, base + 0x10c0);
	pe_badw[0x2a7] = 0xe8;
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(base + 0x10ac)), 0x2a8);
	pe_badw[0x2ac] = 0xc3;

	// 0x10c0: 128-byte NOP-only wrapper (exits 128-byte loop naturally, tests RZ_MIN < 16 too)
	memset(pe_badw + 0x2c0, 0x90, 128);

	// 0x1150: fat-ptr wrapper with arg0_points_to_stack_fn == true but has_vtable_arg1 == false
	size_t bo2 = 0x350;
	ut64 bpc2 = base + 0x1150;
	emit_x64_lea_rip(pe_badw, bo2, bpc2, 0x48, 0, base + 0x1080);
	bo2 += 7;
	bpc2 += 7;
	pe_badw[bo2++] = 0x48;
	pe_badw[bo2++] = 0x89;
	pe_badw[bo2++] = 0x44;
	pe_badw[bo2++] = 0x24;
	pe_badw[bo2++] = 0x10;
	bpc2 += 5;
	pe_badw[bo2++] = 0x48;
	pe_badw[bo2++] = 0x8d;
	pe_badw[bo2++] = 0x4c;
	pe_badw[bo2++] = 0x24;
	pe_badw[bo2++] = 0x10;
	bpc2 += 5;
	pe_badw[bo2++] = 0xe8;
	rz_write_at_le32(pe_badw, (ut32)(st32)((st64)(base + 0x10c0) - (st64)(bpc2 + 5)), bo2);
	bo2 += 4;
	pe_badw[bo2++] = 0xc3;

	RzCore *core_bw = open_synthetic_bin(pe_badw, sizeof(pe_badw), base);
	mu_assert_notnull(core_bw, "open bad-wrapper PE64");
	ut64 bad_x64_mains[] = { base + 0x1000, base + 0x1080, base + 0x10a0, base + 0x10c0, base + 0x1150, base + 0x2000 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(bad_x64_mains); i++) {
		rz_flag_unset_name(core_bw->flags, "main");
		rz_flag_set(core_bw->flags, "main", bad_x64_mains[i], 1);
		RzCoreRustInfo *info_bw = rz_core_analysis_recover_rust_metadata(core_bw);
		mu_assert_notnull(info_bw, "bad x64 wrapper metadata");
		mu_assert_eq(info_bw->main_addr, UT64_MAX, "bad x64 wrapper rejected");
		rz_core_rust_info_free(info_bw);
	}

	// Unsupported 64-bit arch (mips 64-bit) hits else-if("arm") false in both recover_rust_main & code_strings
	rz_config_set(core_bw->config, "asm.arch", "mips");
	rz_config_set_i(core_bw->config, "asm.bits", 64);
	RzCoreRustInfo *info_mips = rz_core_analysis_recover_rust_metadata(core_bw);
	mu_assert_notnull(info_mips, "non-x86/arm 64-bit arch");
	rz_core_rust_info_free(info_mips);
	rz_core_free(core_bw);

	// 4. Fallback section exclusion filter: ELF64 with NO named rodata sections,
	//    containing all excluded names (.rsrc, .reloc, .pdata, .idata, .tls, .eh_frame,
	//    .symtab, .strtab, .shstrtab, .debug_info), non-readable, zero-size, and .custom!
	const size_t filt_sz = 0x3000;
	ut8 *filt = calloc(1, filt_sz);
	mu_assert_notnull(filt, "alloc fallback-filter ELF64");
	if (!filt) {
		return false;
	}
	const char fshstr[] =
		"\0.rsrc\0.reloc\0.pdata\0.idata\0.tls\0.eh_frame\0.symtab\0.strtab\0.shstrtab\0.debug_info\0.noread\0.empty\0.custom\0.text\0";
	// Offsets:
	// 1:.rsrc 7:.reloc 14:.pdata 21:.idata 28:.tls 33:.eh_frame 43:.symtab 51:.strtab
	// 59:.shstrtab 69:.debug_info 81:.noread 89:.empty 96:.custom 104:.text
	memcpy(filt + 0x100, fshstr, sizeof(fshstr));
	// 15 sections (0=NULL, 1..14, shstrndx=9)
	write_elf64_ehdr(filt, 62, 0x402000, 0x40, 0x200, 2, 15, 9);
	emit_elf64_phdr(filt, 0x40, 1, 4, 0x1000, 0x401000, 0x1000);
	emit_elf64_phdr(filt, 0x78, 1, 5, 0x2000, 0x402000, 0x1000);

	const ut32 excl_names[10] = { 1, 7, 14, 21, 28, 33, 43, 51, 59, 69 };
	for (size_t i = 0; i < 10; i++) {
		ut32 stype = (i == 8) ? 3 : 1; // .shstrtab is SHT_STRTAB
		ut64 foff = (i == 8) ? 0x100 : (0x1000 + i * 0x40);
		ut64 ssz = (i == 8) ? sizeof(fshstr) : 0x40;
		emit_elf64_shdr(filt, 0x200 + (i + 1) * 64, excl_names[i], stype, 2 /* SHF_ALLOC */,
			0x401000 + i * 0x40, foff, ssz, 0, 0, 8, 0);
	}
	// Section 11: .noread (non-alloc / no perm), Section 12: .empty (vsize=0),
	// Section 13: .custom (unaligned start 0x401804 exercises RZ_ROUND, accepted by fallback!),
	// Section 14: .text
	emit_elf64_shdr(filt, 0x200 + 11 * 64, 81, 1, 0, 0x401500, 0x1500, 0x40, 0, 0, 8, 0);
	emit_elf64_shdr(filt, 0x200 + 12 * 64, 89, 1, 2, 0x401600, 0x1600, 0, 0, 0, 8, 0);
	emit_elf64_shdr(filt, 0x200 + 13 * 64, 96, 1, 2, 0x401804, 0x1804, 0x3fc, 0, 0, 4, 0);
	emit_elf64_shdr(filt, 0x200 + 14 * 64, 104, 1, 6, 0x402000, 0x2000, 0x400, 0, 0, 4, 0);

	const char *s_custom = "fallback_custom_ok";
	memcpy(filt + 0x1808, s_custom, strlen(s_custom));
	rz_write_at_le64(filt, 0x401808ULL, 0x1900);
	rz_write_at_le64(filt, strlen(s_custom), 0x1908);

	RzCore *core_filt = open_synthetic_bin(filt, filt_sz, UT64_MAX);
	free(filt);
	mu_assert_notnull(core_filt, "open fallback-filter ELF64");
	RzCoreRustInfo *info_filt = rz_core_analysis_recover_rust_metadata(core_filt);
	mu_assert_notnull(info_filt, "recover fallback-filter metadata");
	mu_assert_notnull(rz_bin_object_get_string_at(rz_bin_cur_object(core_filt->bin), 0x401808ULL, true),
		"custom fallback section string recovered");
	rz_core_rust_info_free(info_filt);
	rz_core_free(core_filt);

	// 5. 32-bit Big-Endian ELF32 (EM_PPC): tests word_size == 4, big_endian == true, bits != 64
	const size_t be_sz = 0x3000;
	ut8 *be = calloc(1, be_sz);
	mu_assert_notnull(be, "alloc 32-bit BE ELF32");
	if (!be) {
		return false;
	}
	memcpy(be, "\x7f"
		   "ELF",
		4);
	be[4] = 1; // ELFCLASS32
	be[5] = 2; // ELFDATA2MSB (Big-Endian)
	be[6] = 1;
	rz_write_at_be16(be, 2, 0x10); // ET_EXEC
	rz_write_at_be16(be, 20, 0x12); // EM_PPC
	rz_write_at_be32(be, 1, 0x14);
	rz_write_at_be32(be, 0x10002000U, 0x18); // e_entry
	rz_write_at_be32(be, 0x34, 0x1c); // e_phoff
	rz_write_at_be32(be, 0x200, 0x20); // e_shoff
	rz_write_at_be16(be, 52, 0x28);
	rz_write_at_be16(be, 32, 0x2a);
	rz_write_at_be16(be, 2, 0x2c);
	rz_write_at_be16(be, 40, 0x2e);
	rz_write_at_be16(be, 4, 0x30);
	rz_write_at_be16(be, 3, 0x32);
	// PT_LOAD 0: .rodata at 0x10001000
	rz_write_at_be32(be, 1, 0x34);
	rz_write_at_be32(be, 0x1000, 0x38);
	rz_write_at_be32(be, 0x10001000U, 0x3c);
	rz_write_at_be32(be, 0x10001000U, 0x40);
	rz_write_at_be32(be, 0x1000, 0x44);
	rz_write_at_be32(be, 0x1000, 0x48);
	rz_write_at_be32(be, 4, 0x4c);
	rz_write_at_be32(be, 0x1000, 0x50);
	// PT_LOAD 1: .text at 0x10002000
	rz_write_at_be32(be, 1, 0x54);
	rz_write_at_be32(be, 0x2000, 0x58);
	rz_write_at_be32(be, 0x10002000U, 0x5c);
	rz_write_at_be32(be, 0x10002000U, 0x60);
	rz_write_at_be32(be, 0x1000, 0x64);
	rz_write_at_be32(be, 0x1000, 0x68);
	rz_write_at_be32(be, 5, 0x6c);
	rz_write_at_be32(be, 0x1000, 0x70);

	const char be_shstr[] = "\0.rodata\0.text\0.shstrtab\0";
	memcpy(be + 0x100, be_shstr, sizeof(be_shstr));
	// Section 1: .rodata
	rz_write_at_be32(be, 1, 0x228);
	rz_write_at_be32(be, 1, 0x22c);
	rz_write_at_be32(be, 2, 0x230);
	rz_write_at_be32(be, 0x10001000U, 0x234);
	rz_write_at_be32(be, 0x1000, 0x238);
	rz_write_at_be32(be, 0x1000, 0x23c);
	rz_write_at_be32(be, 4, 0x248);
	// Section 2: .text
	rz_write_at_be32(be, 9, 0x250);
	rz_write_at_be32(be, 1, 0x254);
	rz_write_at_be32(be, 6, 0x258);
	rz_write_at_be32(be, 0x10002000U, 0x25c);
	rz_write_at_be32(be, 0x2000, 0x260);
	rz_write_at_be32(be, 0x1000, 0x264);
	rz_write_at_be32(be, 4, 0x270);
	// Section 3: .shstrtab
	rz_write_at_be32(be, 15, 0x278);
	rz_write_at_be32(be, 3, 0x27c);
	rz_write_at_be32(be, 0x100, 0x288);
	rz_write_at_be32(be, sizeof(be_shstr), 0x28c);
	rz_write_at_be32(be, 1, 0x298);

	const char *s_be_loc = "src/ppc32_be.rs";
	const char *s_be_str = "ppc32_be_static_str";
	memcpy(be + 0x1000, s_be_loc, strlen(s_be_loc));
	memcpy(be + 0x1040, s_be_str, strlen(s_be_str));
	// 32-bit BE panic::Location at 0x10001100 (16 bytes)
	rz_write_at_be32(be, 0x10001000U, 0x1100);
	rz_write_at_be32(be, (ut32)strlen(s_be_loc), 0x1104);
	rz_write_at_be32(be, 77, 0x1108);
	rz_write_at_be32(be, 11, 0x110c);
	// 32-bit BE static &str at 0x10001120 (8 bytes)
	rz_write_at_be32(be, 0x10001040U, 0x1120);
	rz_write_at_be32(be, (ut32)strlen(s_be_str), 0x1124);

	RzCore *core_be = open_synthetic_bin(be, be_sz, UT64_MAX);
	free(be);
	mu_assert_notnull(core_be, "open 32-bit BE ELF32");
	RzCoreRustInfo *info_be = rz_core_analysis_recover_rust_metadata(core_be);
	mu_assert_notnull(info_be, "recover 32-bit BE Rust metadata");
	mu_assert_eq(rz_pvector_len(info_be->panic_locs), 1, "32-bit BE panic::Location recovered");
	RzCoreRustPanicLoc *be_loc = rz_pvector_at(info_be->panic_locs, 0);
	mu_assert_streq(be_loc->file, s_be_loc, "32-bit BE panic file");
	mu_assert_eq(be_loc->line, 77, "32-bit BE panic line");
	mu_assert_eq(be_loc->col, 11, "32-bit BE panic col");
	RzBinString *bs_be = rz_bin_object_get_string_at(rz_bin_cur_object(core_be->bin), 0x10001040ULL, true);
	mu_assert_notnull(bs_be, "32-bit BE static &str recovered");
	mu_assert_streq(bs_be->string, s_be_str, "32-bit BE static &str text");
	rz_core_rust_info_free(info_be);
	rz_core_free(core_be);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rust_strings_panic_locations_and_main);
	mu_run_test(test_rust_renamed_section_and_invalid_utf8);
	mu_run_test(test_rust_inlined_lang_start_and_vendor_crates);
	mu_run_test(test_rust_analyzed_x64_fcns_and_chunk_boundary);
	mu_run_test(test_rust_arm64_strings_and_main);
	mu_run_test(test_rust_elf64_x64_relocs_sysv_and_cli);
	mu_run_test(test_rust_utf8_flags_paths_crates_and_stdlib);
	mu_run_test(test_rust_x64_all_reg_pairs_stack_slots_and_fast_scanner);
	mu_run_test(test_rust_arm64_analyzed_fcns_and_variants);
	mu_run_test(test_rust_section_filters_endian32_and_error_paths);
	return tests_passed != tests_run;
}

mu_main(all_tests)
