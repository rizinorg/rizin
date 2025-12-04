// SPDX-FileCopyrightText: 2025 Harsh Kumar <harsh237hk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

// Apple C4000 (GNS1) Binary Format Loader

#define GNS1_MAGIC     0x474E5331  // "GNS1" in hex
#define GNS1_HDR_MIN   16

// Check if buffer contains a valid GNS1 binary
static bool check_buffer(RzBuffer *b) {
	ut8 buf[4];
	if (rz_buf_read_at(b, 0, buf, sizeof(buf)) != sizeof(buf)) {
		return false;
	}
	ut32 magic = rz_read_be32(buf);
	return magic == GNS1_MAGIC;
}

// Load the binary into Rizin's structure
static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	// Verify it's a GNS1 file
	if (!check_buffer(buf)) {
		return false;
	}

	// Read header information
	ut8 hdr[GNS1_HDR_MIN];
	if (rz_buf_read_at(buf, 0, hdr, sizeof(hdr)) != sizeof(hdr)) {
		return false;
	}

	// Parse header fields (adjust based on actual C4000 format)
	// For now, just validate the magic number
	ut32 magic = rz_read_be32(hdr);
	if (magic != GNS1_MAGIC) {
		return false;
	}

	// Set load address if specified
	if (obj && obj->opts.loadaddr) {
		// Load address is handled by Rizin's core
		RZ_LOG_DEBUG("GNS1: Load address set to 0x%llx\n", obj->opts.loadaddr);
	}

	return true;
}

// Get entry points
static RzPVector *entries(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)free);
	if (!ret) {
		return NULL;
	}

	RzBinAddr *addr = RZ_NEW0(RzBinAddr);
	if (!addr) {
		rz_pvector_free(ret);
		return NULL;
	}

	// Read entry point from header
	ut8 hdr[GNS1_HDR_MIN];
	if (rz_buf_read_at(bf->buf, 0, hdr, sizeof(hdr)) == sizeof(hdr)) {
		ut32 entry_point = rz_read_be32(hdr + 4);
		addr->vaddr = entry_point;
		addr->paddr = entry_point; // Adjust if needed
		rz_pvector_push(ret, addr);
	} else {
		free(addr);
	}

	return ret;
}

// Get sections
static RzPVector *sections(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	// Read header
	ut8 hdr[GNS1_HDR_MIN];
	if (rz_buf_read_at(bf->buf, 0, hdr, sizeof(hdr)) != sizeof(hdr)) {
		rz_pvector_free(ret);
		return NULL;
	}

	ut32 code_size = rz_read_be32(hdr + 8);
	ut32 data_offset = rz_read_be32(hdr + 12);

	// Add .text section
	RzBinSection *text = RZ_NEW0(RzBinSection);
	if (text) {
		text->name = strdup(".text");
		text->paddr = GNS1_HDR_MIN;
		text->vaddr = GNS1_HDR_MIN;
		text->size = code_size;
		text->vsize = code_size;
		text->perm = RZ_PERM_RX;
		rz_pvector_push(ret, text);
	}

	// Add .data section if present
	if (data_offset > 0) {
		RzBinSection *data = RZ_NEW0(RzBinSection);
		if (data) {
			data->name = strdup(".data");
			data->paddr = data_offset;
			data->vaddr = data_offset;
			data->size = rz_buf_size(bf->buf) - data_offset;
			data->vsize = data->size;
			data->perm = RZ_PERM_RW;
			rz_pvector_push(ret, data);
		}
	}

	return ret;
}

// Get binary information
static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->file = strdup(bf->file);
	ret->type = strdup("Apple C4000 Binary");
	ret->machine = strdup("C4000");
	ret->os = strdup("Apple");
	ret->arch = strdup("c4000");
	ret->bits = 32; // Adjust based on C4000 architecture
	ret->has_va = true;
	ret->big_endian = true; // Adjust if needed

	return ret;
}

// Plugin structure
RzBinPlugin rz_bin_plugin_gns1 = {
	.name = "gns1",
	.desc = "Apple C4000 GNS1 binary format",
	.author = "harsh kumar",
	.license = "LGPL3",
	.load_buffer = load_buffer,
	.check_buffer = check_buffer,
	.entries = entries,
	.sections = sections,
	.info = info,
};

// Modern Rizin doesn't use RzLibStruct for in-core plugins
// The plugin is registered via meson.build instead

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_gns1,
	.version = RZ_VERSION
};
#endif