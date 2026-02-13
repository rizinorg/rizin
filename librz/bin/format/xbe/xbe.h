// SPDX-FileCopyrightText: 2014 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _INCLUDE_XBE_H_
#define _INCLUDE_XBE_H_

#define XBE_MAGIC 0x48454258

#define XBE_EP_RETAIL 0xA8FC57AB
#define XBE_EP_DEBUG  0x94859D4B

#define XBE_KP_RETAIL 0x5b6d40b6
#define XBE_KP_DEBUG  0xefb1f152

#define XBE_EP_CHIHIRO 0x40B5C16E
#define XBE_KP_CHIHIRO 0x2290059D

#define XBE_MAX_THUNK 378

#define SECTION_WRITEABLE          0x00000001
#define SECTION_PRELOAD            0x00000002
#define SECTION_EXECUTABLE         0x00000004
#define SECTION_INSERTFILE         0x00000008
#define SECTION_HEAD_PAGE_READONLY 0x00000010
#define SECTION_TAIL_PAGE_READONLY 0x00000020

typedef struct {
	ut8 magic[4];
	ut8 signature[0x100];
	ut32 base;
	ut32 headers_size;
	ut32 image_size;
	ut32 image_header_size;
	ut32 timestamp;
	ut32 cert_addr;
	ut32 sections;
	ut32 sechdr_addr;
	ut32 init_flags;
	ut32 ep;
	ut32 tls_addr;
	ut32 pe_data[7];
	ut32 debug_path_addr;
	ut32 debug_name_addr;
	ut32 debug_uname_addr;
	ut32 kernel_thunk_addr;
	ut32 nonkernel_import_dir_addr;
	ut32 lib_versions;
	ut32 lib_versions_addr;
	ut32 kernel_lib_addr;
	ut32 xapi_lib_addr;
	ut32 padding[2];
} xbe_header;

typedef struct {
	ut32 flags;
	ut32 vaddr;
	ut32 vsize;
	ut32 offset;
	ut32 size;
	ut32 name_addr;
	ut32 refcount;
	ut32 padding[2];
	ut8 digest[20];
} xbe_section;

typedef struct {
	ut8 name[8];
	ut16 major;
	ut16 minor;
	ut16 build;
	ut16 flags;
} xbe_lib;

typedef struct {
	xbe_header header;
	int kt_key;
	int ep_key;
	RzVector /*<xbe_section>*/ sections;
	RzVector /*<xbe_lib>*/ libs;
} rz_bin_xbe_obj_t;

#endif
