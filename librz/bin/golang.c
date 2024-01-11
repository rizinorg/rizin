// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

/**
 * \file golang.c
 *
 * This is a parser for parsing the buildinfo structure which provides access to information
 * embedded in a Go binary about how it was built. This includes the Go toolchain version, and the
 * set of modules used (for binaries built in module mode).
 *
 * This structure always starts with a magic "\xff Go buildinf:", followed by pointer size and
 * version (the version also describes the endianness).
 *
 * This structure contains then the compiler/go version and the cmd arguments/settings provided at
 * compilation time.
 *
 * Starting from go1.18 the settings area is guarded by two magic numbers:
 * - `3077af0c9274080241e1c107e6d618e6` i.e. beginning of the settings
 * - `f932433186182072008242104116d8f2` i.e. ending of the settings
 * On earlier versions this section is actually pointing to some string structures
 * which contains the virt address and size of the string to parse.
 *
 * Example of the structure from a go1.18 binary.
 *
 * ff20 476f 2062 7569 6c64 696e 663a 0802  . Go buildinf:..
 * 0000 0000 0000 0000 0000 0000 0000 0000  ................
 * 0667 6f31 2e31 38d5 0130 77af 0c92 7408  .go1.18..0w...t.
 * 0241 e1c1 07e6 d618 e670 6174 6809 636f  .A.......path.co
 * 6d6d 616e 642d 6c69 6e65 2d61 7267 756d  mmand-line-argum
 * 656e 7473 0a62 7569 6c64 092d 636f 6d70  ents.build.-comp
 * 696c 6572 3d67 630a 6275 696c 6409 4347  iler=gc.build.CG
 * 4f5f 454e 4142 4c45 443d 310a 6275 696c  O_ENABLED=1.buil
 * 6409 4347 4f5f 4346 4c41 4753 3d0a 6275  d.CGO_CFLAGS=.bu
 * 696c 6409 4347 4f5f 4350 5046 4c41 4753  ild.CGO_CPPFLAGS
 * 3d0a 6275 696c 6409 4347 4f5f 4358 5846  =.build.CGO_CXXF
 * 4c41 4753 3d0a 6275 696c 6409 4347 4f5f  LAGS=.build.CGO_
 * 4c44 464c 4147 533d 0a62 7569 6c64 0947  LDFLAGS=.build.G
 * 4f41 5243 483d 6172 6d36 340a 6275 696c  OARCH=arm64.buil
 * 6409 474f 4f53 3d64 6172 7769 6e0a f932  d.GOOS=darwin..2
 * 4331 8618 2072 0082 4210 4116 d8f2 0000  C1.. r..B.A.....
 *
 * Example from `go version -m mybinary`:
 *
 *   devel go1.18-2d1d548 Tue Dec 21 03:55:43 2021 +0000
 *   path github.com/username/repository
 *   mod github.com/username/repository (devel)
 *   dep golang.org/x/arch v0.0.0-20201008161808-52c3e6f60cff h1:XmKBi9R6duxOB3lfc72wyrwiOY7X2Jl1wuI+RFOyMDE=
 *   path command-line-arguments
 *   build -compiler=gc
 *   build CGO_ENABLED=1
 *   build CGO_CFLAGS=
 *   build CGO_CPPFLAGS=
 *   build CGO_CXXFLAGS=
 *   build CGO_LDFLAGS=
 *   build GOARCH=amd64
 *   build GOOS=linux
 *   build GOAMD64=v1
 *   build vcs=git
 *   build vcs.revision=4bd670890aee5a14e36be1a72d19ca8573f2433b
 *   build vcs.time=2021-12-06T17:40:21Z
 *   build vcs.modified=true
 *
 * Reference:
 * - https://github.com/golang/go/blob/d09ca2cb8ec5306f20b527266ce161bd9292cad4/src/debug/buildinfo/buildinfo.go#L173
 * - https://github.com/golang/go/blob/d09ca2cb8ec5306f20b527266ce161bd9292cad4/src/cmd/go/internal/modload/build.go#L29
 */

#define GOLANG_MAX_UVARIANT   10
#define GOLANG_MAX_STRING_BUF 0x1000

#define GOLANG_MOD_START "\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6"

typedef struct golang_build_info_t {
	char *version;
	char *settings;
} GoBuildInfo;

static ut64 go_uvariant(ut8 *buffer, size_t size, ut32 *read) {
	ut64 x = 0;
	ut32 s = 0;
	for (size_t i = 0; i < size; ++i) {
		ut8 b = buffer[i];
		if (i == GOLANG_MAX_UVARIANT) {
			// overflow
			*read = 0;
			return 0;
		} else if (b < 0x80) {
			if (i == (GOLANG_MAX_UVARIANT - 1) && b > 1) {
				// overflow
				*read = 0;
				return 0;
			}
			*read = i + 1;
			return x | ((ut64)b) << s;
		}
		x |= ((ut64)(b & 0x7f)) << s;
		s += 7;
	}
	*read = 0;
	return 0;
}

static ut64 go_string(ut8 *buffer, size_t size, char **output) {
	ut32 read = 0;
	ut64 n = go_uvariant(buffer, size, &read);
	if (n <= 0 || n > (size - read)) {
		*output = NULL;
		return 0;
	}
	if (n > 32 && !memcmp(buffer + read, GOLANG_MOD_START, 16)) {
		n -= 33; // strips away the \n at the end + GOLANG_MOD_END
		buffer += 16;
	}
	char *copy = malloc(n + 1);
	if (!copy) {
		*output = NULL;
		return 0;
	}
	copy[n] = 0;
	memcpy(copy, buffer + read, n);
	*output = copy;
	return n + read;
}

static st64 io_read_va_at(RzBinFile *bf, ut64 vaddr, ut8 *buffer, ut64 size) {
	ut64 paddr = rz_bin_object_v2p(bf->o, vaddr);
	if (paddr == UT64_MAX) {
		return -1;
	}
	return rz_buf_read_at(bf->buf, paddr, buffer, size);
}

static char *go_string_from_table(RzBinFile *bf, ut32 ptr_size, ut64 offset, bool big_endian, ut32 *str_size) {
	ut8 buffer[16] = { 0 };

	// read table entry of max size 16 bytes
	if (io_read_va_at(bf, offset, (ut8 *)buffer, sizeof(buffer)) < 1) {
		return NULL;
	}

	ut64 paddr = 0, psize = 0;
	if (ptr_size == 4) {
		paddr = rz_read_ble32(buffer, big_endian);
		psize = rz_read_ble32(buffer + ptr_size, big_endian);
	} else {
		paddr = rz_read_ble64(buffer, big_endian);
		psize = rz_read_ble64(buffer + ptr_size, big_endian);
	}

	if (!psize || psize > GOLANG_MAX_STRING_BUF) {
		return NULL;
	}

	char *str = malloc(psize + 1);
	if (!str) {
		return NULL;
	} else if (io_read_va_at(bf, paddr, (ut8 *)str, psize) < 1) {
		free(str);
		return NULL;
	}
	str[psize] = 0;
	if (str_size) {
		*str_size = psize;
	}
	return str;
}

static void parse_go_build_info(RzBinFile *bf, GoBuildInfo *go_info, ut64 bi_paddr) {
	ut8 tmp32[32];

	// Read build info
	if (rz_buf_read_at(bf->buf, bi_paddr, tmp32, sizeof(tmp32)) < 1) {
		RZ_LOG_ERROR("goinfo: Cannot read build info header at 0x%08" PFMT64x " (phy)\n", bi_paddr);
		return;
	}

	ut32 ptr_size = tmp32[14];
	if (ptr_size != 4 && ptr_size != 8) {
		return;
	}

	ut32 setting_sz = 0;
	if (tmp32[15] & 2) {
		ut8 *buffer = malloc(GOLANG_MAX_STRING_BUF);
		// Read build info
		if (rz_buf_read_at(bf->buf, bi_paddr + 32, buffer, GOLANG_MAX_STRING_BUF) < 1) {
			RZ_LOG_ERROR("goinfo: Cannot read build info header at 0x%08" PFMT64x " (phy)\n", bi_paddr);
			return;
		}

		ut64 read = go_string(buffer, GOLANG_MAX_STRING_BUF, &go_info->version);
		if (!read) {
			free(buffer);
			RZ_LOG_ERROR("goinfo: Cannot read build info version\n");
			return;
		}

		// settings can be NULL.
		setting_sz = go_string(buffer + read, GOLANG_MAX_STRING_BUF - read, &go_info->settings);
		free(buffer);
	} else {
		bool big_endian = tmp32[15] != 0;
		ut64 version_offset = 0, setting_offset = 0;
		if (ptr_size == 4) {
			version_offset = rz_read_ble32(tmp32 + 16, big_endian);
			setting_offset = rz_read_ble32(tmp32 + 16 + ptr_size, big_endian);
		} else {
			version_offset = rz_read_ble64(tmp32 + 16, big_endian);
			setting_offset = rz_read_ble64(tmp32 + 16 + ptr_size, big_endian);
		}
		go_info->version = go_string_from_table(bf, ptr_size, version_offset, big_endian, NULL);
		go_info->settings = go_string_from_table(bf, ptr_size, setting_offset, big_endian, &setting_sz);
	}

	if (!go_info->settings) {
		return;
	}

	char *str = go_info->settings;
	// settings contains some whitespaces, we convert them into spaces.
	for (ut32 i = 0; str[i]; ++i) {
		if (str[i] < ' ') {
			str[i] = ' ';
		}
	}

	str = rz_str_replace(str, " build ", " ", 1);
	go_info->settings = rz_str_replace(str, "path command-line-arguments ", "cmd ", 0);
}

static bool is_go_build_info(const ut8 *magic) {
	return !memcmp(magic, "\xff Go buildinf:", 14);
}

struct scan_go_info_s {
	RzBinFile *bf;
	GoBuildInfo *go_info;
	RzBinSection *section;
};

static ut64 scan_go_build_info(const ut8 *buf, ut64 len, void *user) {
	const int build_info_align = 16;
	if (len < build_info_align) {
		return len;
	}
	struct scan_go_info_s *ctx = user;
	for (ut64 pos = 0; pos <= len - build_info_align; pos += build_info_align) {
		if (is_go_build_info(buf + pos)) {
			parse_go_build_info(ctx->bf, ctx->go_info, ctx->section->paddr + pos);
			return 0;
		}
	}
	return len;
}

static void find_go_build_info(RzBinFile *bf, GoBuildInfo *go_info, RzBinSection *section) {
	struct scan_go_info_s ctx = { bf, go_info, section };
	rz_buf_fwd_scan(bf->buf, section->paddr, section->size, scan_go_build_info, &ctx);
}

/**
 * \brief   Returns the golang compiler info if buildinfo struct is found.
 *
 * \param   RzBinFile    The RzBinFile to use for the search
 *
 * \return  Returns a string on success, otherwise NULL
 */
RZ_IPI RZ_OWN char *rz_bin_file_golang_compiler(RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);

	bool is_pe = false;
	GoBuildInfo go_info = { 0 };
	RzBinSection *section = NULL;
	void **it = NULL;
	RzPVector *sections = NULL;
	const char *plugname = bf->o->plugin->name;

	if (!strcmp(plugname, "pe") || !strcmp(plugname, "pe64")) {
		is_pe = true;
	} else if (strcmp(plugname, "elf") && strcmp(plugname, "elf64") &&
		strcmp(plugname, "mach0") && strcmp(plugname, "mach064")) {
		RZ_LOG_INFO("goinfo: unsupported bin format '%s'\n", plugname);
		return NULL;
	}

	sections = rz_bin_object_get_sections(bf->o);
	if (!sections) {
		return NULL;
	}

	rz_pvector_foreach (sections, it) {
		section = *it;
		if (is_pe && strstr(section->name, "data") && section->size > 16) {
			find_go_build_info(bf, &go_info, section);
		} else if (!is_pe && (strstr(section->name, "go_buildinfo") || strstr(section->name, "go.buildinfo"))) {
			parse_go_build_info(bf, &go_info, section->paddr);
		}
		if (go_info.version) {
			break;
		}
	}
	rz_pvector_free(sections);

	if (!go_info.version) {
		return NULL;
	} else if (go_info.settings) {
		char *res = rz_str_newf("%s (%s)", go_info.version, go_info.settings);
		free(go_info.version);
		free(go_info.settings);
		return res;
	}

	return go_info.version;
}
