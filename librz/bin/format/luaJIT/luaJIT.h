// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef LUAJIT_H
#define LUAJIT_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

extern ut64 LUAJIT_FLAG_END_OFFSET;

/*Magic Info*/
#define LUAJIT_MAGIC           "\x1b\x4c\x4a"
#define LUAJIT_MAGIC_OFFSET    0x00
#define LUAJIT_MAGIC_BYTE_SIZE 3
#define LUAJIT_VERSION_OFFSET  0x02
#define LUAJIT_FLAG_OFFSET_AT  0x04
#define LUAJIT_ULEB128_MAX     10

/*Flags*/
#define LUAJIT_BCDUMP_F_BE    0x01
#define LUAJIT_BCDUMP_F_STRIP 0x02
#define LUAJIT_BCDUMP_F_FFI   0x04
#define LUAJIT_BCDUMP_F_FR2   0x08

typedef struct LuaJIT_binInfo {
	int maj_vers; /*Major version*/
	int min_vers; /*Minor version*/
	RzBuffer /*<ut64>*/ *flags;
} LuaJITBinInfo;

/*Plugin*/
RZ_IPI bool luaJIT_check_buffer(RzBuffer *b);
RZ_IPI bool luaJIT_load_buffer(RzBinFile *b, RzBinObject *obj, RzBuffer *buf, Sdb *sdb);

/*parsing*/
RZ_IPI RzBinInfo *luaJIT_header_parser(RzBinFile *bf, ut8 min);
RZ_IPI ut64 luaJIT_parse_ULEB128(RzBuffer *r_buffer, RzBuffer *w_buffer, ut64 offset);

/*Common*/
RZ_IPI ut64 luaJIT_decode_ULEB128(RzBuffer *buf, ut64 start, ut64 *value);

#endif