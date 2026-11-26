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

bool all_tests() {
	mu_run_test(test_rust_strings_panic_locations_and_main);
	mu_run_test(test_rust_renamed_section_and_invalid_utf8);
	mu_run_test(test_rust_inlined_lang_start_and_vendor_crates);
	mu_run_test(test_rust_analyzed_x64_fcns_and_chunk_boundary);
	mu_run_test(test_rust_arm64_strings_and_main);
	return tests_passed != tests_run;
}

mu_main(all_tests)
