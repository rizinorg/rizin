// SPDX-FileCopyrightText: 2018 rkx1209 <rkx1209dev@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "nxo.h"

static char *readString(RzBuffer *buf, int off) {
	char symbol[128]; // assume 128 as max symbol name length
	int left = rz_buf_read_at(buf, off, (ut8 *)symbol, sizeof(symbol));
	if (left < 1) {
		return NULL;
	}
	symbol[sizeof(symbol) - 1] = 0;
	return rz_str_dup(symbol);
}

const char *fileType(const ut8 *buf) {
	if (!memcmp(buf, "NRO0", 4)) {
		return "nro0";
	}
	if (!memcmp(buf, "NRR0", 4)) {
		return "nrr0";
	}
	if (!memcmp(buf, "MOD0", 4)) {
		return "mod0";
	}
	if (!memcmp(buf, "NSO0", 4)) {
		return "nso0";
	}
	return NULL;
}

static void walkSymbols(RzBuffer *buf, RzBinNXOObj *bin, ut64 symtab, ut64 strtab, ut64 strtab_size, ut64 relplt, ut64 baddr) {
	int i, import = 0;
	RzBinSymbol *sym;
	RzBinImport *imp;
	for (i = 8; i < 99999; i++) {
		ut64 addr;
		if (!rz_buf_read_le64_at(buf, symtab + i, &addr)) {
			break;
		}
		ut64 size;
		if (!rz_buf_read_le64_at(buf, symtab + i + 8, &size)) {
			break;
		}

		i += 16; // NULL, NULL
		ut32 name;
		if (!rz_buf_read_le32_at(buf, symtab + i, &name)) {
			break;
		}
		// ut64 type = rz_buf_read_le32_at (buf, symtab + i + 4);
		char *symName = readString(buf, strtab + name);
		if (!symName) {
			break;
		}
		sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			free(symName);
			break;
		}
		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->bind = "NONE";
		sym->size = size;

		if (addr == 0) {
			import++;
			ut64 pltSym;
			if (!rz_buf_read_le64_at(buf, relplt + (import * 24), &pltSym)) {
				free(symName);
				rz_bin_symbol_free(sym);
				break;
			}
			imp = RZ_NEW0(RzBinImport);
			if (!imp) {
				RZ_FREE(sym);
				free(symName);
				break;
			}
			imp->name = symName;
			if (!imp->name) {
				goto out_walk_symbol;
			}
			imp->type = "FUNC";
			if (!imp->type) {
				goto out_walk_symbol;
			}
			imp->bind = "NONE";
			if (!imp->bind) {
				goto out_walk_symbol;
			}
			imp->ordinal = bin->imports_vec->v.len;
			rz_pvector_push(bin->imports_vec, imp);
			sym->is_imported = true;
			sym->name = rz_str_dup(symName);
			if (!sym->name) {
				goto out_walk_symbol;
			}
			sym->paddr = pltSym - 8;
			sym->vaddr = sym->paddr + baddr;
			RZ_LOG_INFO("f sym.imp.%s @ 0x%" PFMT64x "\n", symName, pltSym - 8);
		} else {
			sym->name = symName;
			if (!sym->name) {
				RZ_FREE(sym);
				break;
			}
			sym->paddr = addr;
			sym->vaddr = sym->paddr + baddr;
			RZ_LOG_INFO("f sym.%s %" PFMT64u " @ 0x%" PFMT64x "\n", symName, size, addr);
		}
		rz_pvector_push(bin->methods_vec, sym);
		i += 8 - 1;
	}
	return;

out_walk_symbol:
	RZ_FREE(sym);
	RZ_FREE(imp);
	return;
}

void parseMod(RzBuffer *buf, RzBinNXOObj *bin, ut32 mod0, ut64 baddr) {
	ut32 ptr;
	if (!rz_buf_read_le32_at(buf, mod0, &ptr)) {
		return;
	}

	RZ_LOG_INFO("magic %x at 0x%x\n", ptr, mod0);
	if (ptr == 0x30444f4d) { // MOD0
		RZ_LOG_INFO("is mode0\n");
		MODHeader mh = { 0 };
		if (!rz_buf_read_le32_at(buf, mod0, &mh.magic) ||
			!rz_buf_read_le32_at(buf, mod0 + 4, &mh.dynamic) ||
			!rz_buf_read_le32_at(buf, mod0 + 8, &mh.bss_start) ||
			!rz_buf_read_le32_at(buf, mod0 + 12, &mh.bss_end) ||
			!rz_buf_read_le32_at(buf, mod0 + 16, &mh.unwind_start) ||
			!rz_buf_read_le32_at(buf, mod0 + 20, &mh.unwind_end) ||
			!rz_buf_read_le32_at(buf, mod0 + 24, &mh.mod_object)) {
			return;
		}
		mh.mod_object += mod0;
		RZ_LOG_INFO("magic 0x%x\n", mh.magic);
		RZ_LOG_INFO("dynamic 0x%x\n", mh.dynamic);
		RZ_LOG_INFO("bss 0x%x 0x%x\n", mh.bss_start, mh.bss_end);
		RZ_LOG_INFO("unwind 0x%x 0x%x\n", mh.unwind_start, mh.unwind_end);
		RZ_LOG_INFO("-------------\n");
		RZ_LOG_INFO("mod 0x%x\n", mh.mod_object);
#define MO_(x) rz_buf_read_le64_at(buf, mh.mod_object + rz_offsetof(MODObject, x), &mo.x)
		MODObject mo = { 0 };
		if (!MO_(next) || !MO_(prev) || !MO_(relplt) || !MO_(reldyn) ||
			!MO_(base) || !MO_(dynamic) || !MO_(is_rela) ||
			!MO_(relplt_size) || !MO_(init) || !MO_(fini) ||
			!MO_(bucket) || !MO_(chain) || !MO_(strtab) ||
			!MO_(symtab) || !MO_(strtab_size)) {
			return;
		};
		RZ_LOG_INFO("next 0x%" PFMT64x "\n", mo.next);
		RZ_LOG_INFO("prev 0x%" PFMT64x "\n", mo.prev);
		RZ_LOG_INFO("base 0x%" PFMT64x "\n", mo.base);
		RZ_LOG_INFO("init 0x%" PFMT64x "\n", mo.init);
		RZ_LOG_INFO("fini 0x%" PFMT64x "\n", mo.fini);
		RZ_LOG_INFO("relplt 0x%" PFMT64x "\n", mo.relplt - mo.base);
		RZ_LOG_INFO("symtab = 0x%" PFMT64x "\n", mo.symtab - mo.base);
		RZ_LOG_INFO("strtab = 0x%" PFMT64x "\n", mo.strtab - mo.base);
		RZ_LOG_INFO("strtabsz = 0x%" PFMT64x "\n", mo.strtab_size);
		// ut32 modo = mh.mod_object;
		ut64 strtab = mo.strtab - mo.base;
		ut64 symtab = mo.symtab - mo.base;
		walkSymbols(buf, bin, symtab, strtab, mo.strtab_size, mo.relplt - mo.base, baddr);
	}
}
