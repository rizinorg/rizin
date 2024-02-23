// SPDX-FileCopyrightText: 2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include "../unit/minunit.h"

typedef struct {
	const char *name;
	ut64 addr;
} SymInfo;

const static SymInfo mipsbe_ip_symbols[] = {
	{ .name = "tnl_del_ioctl", .addr = 0x411608 },
	{ .name = "rtnl_rtntype_n2a", .addr = 0x40da54 },
	{ .name = "get_prefix", .addr = 0x41c174 },
	{ .name = "do_ip6tunnel", .addr = 0x4112c4 },
	{ .name = "inet_addr_match", .addr = 0x41b1e0 },
	{ .name = "getcmdline", .addr = 0x41ab98 },
	{ .name = "matches", .addr = 0x41b2b4},
	{ .name = "ll_name_to_index", .addr = 0x418990 },
	{ .name = "main", .addr = 0x402558 },
	{ .name = "duparg", .addr = 0x41b00c },
	{ .name = "rtnl_talk", .addr = 0x41a024 },
	{ .name = "get_jiffies", .addr = 0x41c47c },
	{ .name = "format_host", .addr = 0x41b428 },
	{ .name = "addattr32", .addr = 0x41961c },
	{ .name = "get_link_kind", .addr = 0x413720 },
};

const static SymInfo mipsbe_ip_imports[] = {
	{ .name = "getsockname", .addr = 0 },
	{ .name = "free", .addr = 0 },
	{ .name = "vlan_link_util", .addr = 0 }, // WEAK symbol
	{ .name = "fwrite", .addr = 0 },
	{ .name = "localtime", .addr = 0 },
	{ .name = "__uClibc_main", .addr = 0 },
	{ .name = "__udivdi3", .addr = 0 },
	{ .name = "in6addr_any", .addr = 0 }, // OBJ symbol
};

bool test_rz_bin_symbols(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/analysis/mipsbe-ip", &opt);
	mu_assert_notnull(bf, "mipsbe-ip binary could not be opened");
	mu_assert_notnull(bf->o, "bin object");

	RzBinObject *obj = rz_bin_cur_object(bin);
	const RzPVector *symbols = rz_bin_object_get_symbols(obj);
	mu_assert_notnull(symbols, "mipsbe-ip symbols");

	mu_assert_eq(rz_pvector_len(symbols), 204, "symbols count");
	size_t matches = 0, expected = RZ_ARRAY_SIZE(mipsbe_ip_symbols) - 1;
	void **it;
	RzBinSymbol *sym;
	rz_pvector_foreach (symbols, it) {
                sym = *it;
		for (int i = 0; i < expected; i++) {
			if (sym && sym->name && !strcmp(sym->name, mipsbe_ip_symbols[i].name) &&
					sym->vaddr == mipsbe_ip_symbols[i].addr) {
				matches++;
			}
		}
	}
	mu_assert_eq(matches, expected, "all checked symbols match");

	const RzPVector *imports = rz_bin_object_get_imports(obj);
	void **vec_it = NULL;
	mu_assert_notnull(symbols, "mipsbe-ip imports");
	matches = 0;
	expected = RZ_ARRAY_SIZE(mipsbe_ip_imports) - 1;
	rz_pvector_foreach (imports, vec_it) {
		sym = *vec_it;
		for (int i = 0; i < expected; i++) {
			if (sym && sym->name && !strcmp(sym->name, mipsbe_ip_imports[i].name)) {
				matches++;
			}
		}
	}
	mu_assert_eq(matches, expected, "all checked imports match");

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bin_symbols);
	return tests_passed != tests_run;
}

mu_main(all_tests)
