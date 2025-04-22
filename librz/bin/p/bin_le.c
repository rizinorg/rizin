// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2023 svr <svr.work@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/le/le.h"

static RzBinInfo *le_info(RzBinFile *bf) {
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	LE_header *h = bin->header;
	info->bits = 32;
	info->type = rz_str_dup(bin->type);
	info->cpu = rz_str_dup(bin->cpu);
	info->os = rz_str_dup(bin->os);
	info->arch = rz_str_dup(bin->arch);
	info->file = rz_str_dup(bin->modname ? bin->modname : "");
	info->big_endian = h->border || h->worder;
	info->has_va = true;
	info->baddr = 0;
	return info;
}

static void le_header(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj);
	RzBin *rbin = bf->rbin;
	rz_bin_le_obj_t *bin = bf->o->bin_obj;
	LE_header *h = bin->header;
	PrintfCallback p = rbin->cb_printf;
	if (!h || !p) {
		return;
	}
	if (bin->mz_off == bin->le_off) {
		p("MZ header not present\n");
	} else {
		p("MZ header offset: 0x%" PFMT64x "\n", bin->mz_off);
	}
	p("LE header offset: 0x%" PFMT64x "\n", bin->le_off);
	p("Signature: %2s\n", h->magic);
	p("Byte Order: %s\n", h->border ? "Big" : "Little");
	p("Word Order: %s\n", h->worder ? "Big" : "Little");
	p("Format Level: %u\n", h->level);
	p("CPU: %s\n", bin->cpu);
	p("OS: %s\n", bin->os);
	p("Version: %u\n", h->ver);
	p("Flags: 0x%08x", h->mflags);
	if (h->mflags) {
#define PF_(mask, cond, name) \
	if ((h->mflags & mask) cond) { \
		p(" " name); \
	}
		PF_(M_SINGLE_DATA, , "SINGLEDATA");
		PF_(M_PP_LIB_INIT, , "INITINSTANCE");
		PF_(M_PP_LIB_TERM, , "TERMINSTANCE");
		PF_(M_INTERNAL_FIXUP, , "NOINTFIXUPS");
		PF_(M_EXTERNAL_FIXUP, , "NOEXTFIXUPS");
		if (h->mflags & M_USES_PM_WINDOWING) {
			p(" PMWINAPI");
		} else {
			PF_(M_PM_WINDOWING_INCOMP, , " PMWININCOMP");
			PF_(M_PM_WINDOWING_COMPAT, , " PMWINCOMPAT");
		}
		PF_(M_TYPE_PM_DLL, , "PROTDLL");
		PF_(M_TYPE_MASK, == M_TYPE_EXE, "EXE");
		PF_(M_TYPE_MASK, == M_TYPE_DLL, "DLL");
		PF_(M_TYPE_MASK, == M_TYPE_PDD, "PDD");
		PF_(M_TYPE_MASK, == M_TYPE_VDD, "VDD");
		PF_(M_MP_UNSAFE, , "MPUNSAFE");
	}
	p("\n");
	p("Pages: %u\n", h->mpages);
	p("InitialEipObj: %u\n", h->startobj);
	p("InitialEip: 0x%x\n", h->eip);
	p("InitialStackObj: %u\n", h->stackobj);
	p("InitialEsp: 0x%x\n", h->esp);
	p("Page Size: 0x%x\n", h->pagesize);
	if (bin->is_le) {
		p("Last Page Size: 0x%x\n", h->le_last_page_size);
	} else {
		p("Page Shift: 0x%x\n", h->pageshift);
	}
	p("Fixup Size: 0x%x\n", h->fixupsize);
	p("Fixup Checksum: 0x%x\n", h->fixupsum);
	p("Loader Size: 0x%x\n", h->ldrsize);
	p("Loader Checksum: 0x%x\n", h->ldrsum);
	p("Obj Table: 0x%x\n", h->objtab);
	p("Obj Count: %u\n", h->objcnt);
	p("Obj Page Map: 0x%x\n", h->objmap);
	p("Obj Iter Data Map: 0x%x\n", h->itermap);
	p("Resource Table: 0x%x\n", h->rsrctab);
	p("Resource Count: %u\n", h->rsrccnt);
	p("Resident Name Table: 0x%x\n", h->restab);
	p("Entry Table: 0x%x\n", h->enttab);
	p("Directives Table: 0x%x\n", h->dirtab);
	p("Directives Count: %u\n", h->dircnt);
	p("Fixup Page Table: 0x%x\n", h->fpagetab);
	p("Fixup Record Table: 0x%x\n", h->frectab);
	p("Import Module Name Table: 0x%x\n", h->impmod);
	p("Import Module Name Count: %u\n", h->impmodcnt);
	p("Import Procedure Name Table: 0x%x\n", h->impproc);
	p("Per-Page Checksum Table: 0x%x\n", h->pagesum);
	p("Enumerated Data Pages: 0x%x\n", h->datapage);
	p("Number of preload pages: %u\n", h->preload);
	p("Non-resident Names Table: 0x%x\n", h->nrestab);
	p("Size Non-resident Names: %u\n", h->cbnrestab);
	p("Checksum Non-resident Names: 0x%x\n", h->nressum);
	p("Autodata Obj: %u\n", h->autodata);
	p("Debug Info: 0x%x\n", h->debuginfo);
	p("Debug Length: 0x%x\n", h->debuglen);
	p("Preload pages: %u\n", h->instpreload);
	p("Demand pages: %u\n", h->instdemand);
	p("Heap Size: 0x%x\n", h->heapsize);
	p("Stack Size: 0x%x\n", h->stacksize);
}

RzBinPlugin rz_bin_plugin_le = {
	.name = "le",
	.desc = "LE/LX format plugin",
	.author = "GustavoLCR",
	.license = "LGPL3",
	.check_buffer = &rz_bin_le_check_buffer,
	.load_buffer = &rz_bin_le_load_buffer,
	.destroy = &rz_bin_le_destroy,
	.info = &le_info,
	.header = &le_header,
	.virtual_files = &rz_bin_le_get_virtual_files,
	.maps = &rz_bin_le_get_maps,
	.sections = &rz_bin_le_get_sections,
	.entries = &rz_bin_le_get_entry_points,
	.symbols = &rz_bin_le_get_symbols,
	.imports = &rz_bin_le_get_imports,
	.libs = &rz_bin_le_get_libs,
	.relocs = &rz_bin_le_get_relocs,
	// .regstate = &regstate
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_le,
	.version = RZ_VERSION
};
#endif
