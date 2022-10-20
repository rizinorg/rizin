// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2016 Alberto Ortega
// SPDX-License-Identifier: LGPL-3.0-only

/*
https://www.3dbrew.org/wiki/FIRM
More formats to support: https://www.3dbrew.org/wiki/Category:File_formats
https://github.com/LumaTeam/Luma3DS/blob/master/arm9/source/3dsheaders.h
*/

#ifndef NIN_N3DS_H
#define NIN_N3DS_H

#include <rz_types_base.h>

enum {
	N3DS_COPY_MODE_NDMA = 0,
	N3DS_COPY_MODE_XDMA = 1,
	N3DS_COPY_MODE_MEMCPY = 2,
};

typedef struct n3ds_firm_sect_hdr_t {
	ut32 offset;
	ut32 address;
	ut32 size;
	ut32 copy_mode;
	ut8 sha256[0x20];
	// ----- additional rizin info ----- //
	ut32 type; ///< This is not part of the real section header
} N3DSFirmSectHdr;

typedef struct n3ds_firm_hdr_t {
	ut8 magic[4];
	ut8 reserved1[4];
	ut32 arm11_ep;
	ut32 arm9_ep;
	ut8 reserved2[0x30];
	N3DSFirmSectHdr sections[4];
	ut8 rsa2048[0x100];
} N3DSFirmHdr;

#endif /* NIN_N3DS_H */
