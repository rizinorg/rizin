// SPDX-FileCopyrightText: 2014-2017 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef KD_H
#define KD_H
#include <rz_types_base.h>
#include "transport.h"

enum {
	KD_E_OK = 0,
	KD_E_BADCHKSUM = -1,
	KD_E_TIMEOUT = -2,
	KD_E_MALFORMED = -3,
	KD_E_IOERR = -4,
	KD_E_BREAK = -5,
};

enum KD_PACKET_TYPE {
	KD_PACKET_TYPE_UNUSED = 0,
	KD_PACKET_TYPE_STATE_CHANGE32 = 1,
	KD_PACKET_TYPE_STATE_MANIPULATE = 2,
	KD_PACKET_TYPE_DEBUG_IO = 3,
	KD_PACKET_TYPE_ACKNOWLEDGE = 4,
	KD_PACKET_TYPE_RESEND = 5,
	KD_PACKET_TYPE_RESET = 6,
	KD_PACKET_TYPE_STATE_CHANGE64 = 7,
	KD_PACKET_TYPE_POLL_BREAKIN = 8,
	KD_PACKET_TYPE_TRACE_IO = 9,
	KD_PACKET_TYPE_CONTROL_REQUEST = 10,
	KD_PACKET_TYPE_FILE_IO = 11
};

enum KD_PACKET_WAIT_STATE_CHANGE {
	DbgKdMinimumStateChange = 0x00003030,
	DbgKdExceptionStateChange = 0x00003030,
	DbgKdLoadSymbolsStateChange = 0x00003031,
	DbgKdCommandStringStateChange = 0x00003032,
	DbgKdMaximumStateChange = 0x00003033
};

enum KD_PACKET_MANIPULATE_TYPE {
	DbgKdMinimumManipulate = 0x00003130,
	DbgKdReadVirtualMemoryApi = 0x00003130,
	DbgKdWriteVirtualMemoryApi = 0x00003131,
	DbgKdGetContextApi = 0x00003132,
	DbgKdSetContextApi = 0x00003133,
	DbgKdWriteBreakPointApi = 0x00003134,
	DbgKdRestoreBreakPointApi = 0x00003135,
	DbgKdContinueApi = 0x00003136,
	DbgKdReadControlSpaceApi = 0x00003137,
	DbgKdWriteControlSpaceApi = 0x00003138,
	DbgKdReadIoSpaceApi = 0x00003139,
	DbgKdWriteIoSpaceApi = 0x0000313A,
	DbgKdRebootApi = 0x0000313B,
	DbgKdContinueApi2 = 0x0000313C,
	DbgKdReadPhysicalMemoryApi = 0x0000313D,
	DbgKdWritePhysicalMemoryApi = 0x0000313E,
	DbgKdQuerySpecialCallsApi = 0x0000313F,
	DbgKdSetSpecialCallApi = 0x00003140,
	DbgKdClearSpecialCallsApi = 0x00003141,
	DbgKdSetInternalBreakPointApi = 0x00003142,
	DbgKdGetInternalBreakPointApi = 0x00003143,
	DbgKdReadIoSpaceExtendedApi = 0x00003144,
	DbgKdWriteIoSpaceExtendedApi = 0x00003145,
	DbgKdGetVersionApi = 0x00003146,
	DbgKdWriteBreakPointExApi = 0x00003147,
	DbgKdRestoreBreakPointExApi = 0x00003148,
	DbgKdCauseBugCheckApi = 0x00003149,
	DbgKdSwitchProcessor = 0x00003150,
	DbgKdPageInApi = 0x00003151,
	DbgKdReadMachineSpecificRegister = 0x00003152,
	DbgKdWriteMachineSpecificRegister = 0x00003153,
	OldVlm1 = 0x00003154,
	OldVlm2 = 0x00003155,
	DbgKdSearchMemoryApi = 0x00003156,
	DbgKdGetBusDataApi = 0x00003157,
	DbgKdSetBusDataApi = 0x00003158,
	DbgKdCheckLowMemoryApi = 0x00003159,
	DbgKdClearAllInternalBreakpointsApi = 0x0000315A,
	DbgKdFillMemoryApi = 0x0000315B,
	DbgKdQueryMemoryApi = 0x0000315C,
	DbgKdSwitchPartition = 0x0000315D,
	DbgKdWriteCustomBreakpointApi = 0x0000315E,
	DbgKdGetContextEx = 0x0000315F,
	DbgKdSetContextEx = 0x00003160,
	DbgKdMaximumManipulate = 0x00003161
};

enum KD_PACKET_FILE_IO_TYPE {
	DbgKdCreateFileApi = 0x00003430,
	DbgKdReadFileApi = 0x00003431,
	DbgKdWriteFileApi = 0x00003432,
	DbgKdCloseFileApi = 0x00003433
};

#define KD_PACKET_UNUSED 0x00000000
#define KD_PACKET_DATA   0x30303030
#define KD_PACKET_CTRL   0x69696969

#define KD_INITIAL_PACKET_ID 0x80800000

#define KD_MAX_PAYLOAD     0x480
#define KD_PACKET_MAX_SIZE 4000 // Not used ? What is max payload ?

// http://msdn.microsoft.com/en-us/library/cc704588.aspx
#define KD_RET_OK     0x00000000
#define KD_RET_ERR    0xC0000001
#define KD_RET_ENOENT 0xC000000F

#define KD_MACH_I386  0x014C
#define KD_MACH_IA64  0x0200
#define KD_MACH_AMD64 0x8664
#define KD_MACH_ARM   0x01c0
#define KD_MACH_EBC   0x0EBC

#define DBGKD_VERS_FLAG_DATA  0x0002
#define DBGKD_VERS_FLAG_PTR64 0x0004

RZ_PACKED(
	typedef struct kd_req_t {
		ut32 req;
		ut16 cpu_level;
		ut16 cpu;
		ut32 ret;
		// Pad to 16-byte boundary (?)
		ut32 pad;
		union {
			RZ_PACKED(
				struct {
					ut64 addr;
					ut32 length;
					ut32 read;
				})
			rz_mem;
			RZ_PACKED(
				struct {
					ut16 major;
					ut16 minor;
					ut8 proto_major;
					ut8 proto_minor;
					ut16 flags;
					ut16 machine;
					ut8 misc[6];
					ut64 kernel_base;
					ut64 mod_addr;
					ut64 dbg_addr;
				})
			rz_ver;
			struct {
				ut32 reason;
				ut32 tf;
				ut32 dr7;
				ut32 css;
				ut32 cse;
			} rz_cont;
			struct {
				ut64 addr;
				ut32 handle;
			} rz_set_bp;
			struct {
				ut32 handle;
			} rz_del_bp;
			struct {
				ut64 addr;
				ut32 flags;
			} rz_set_ibp;
			struct {
				ut64 addr;
				ut32 flags;
				ut32 calls;
			} rz_get_ibp;
			struct {
				ut32 flags;
			} rz_ctx;
			struct {
				ut32 offset;
				ut32 count;
				ut32 copied;
			} rz_ctx_ex;
			struct {
				ut64 addr;
				ut64 reserved;
				ut32 address_space;
				ut32 flags;
			} rz_query_mem;

			// Pad the struct to 56 bytes
			ut8 raw[40];
		};
		ut8 data[];
	})
kd_req_t;

#define KD_EXC_BKPT 0x80000003
RZ_PACKED(
	typedef struct kd_stc_64 {
		ut32 state;
		ut16 cpu_level;
		ut16 cpu;
		ut32 cpu_count;
		ut32 pad1;
		ut64 kthread;
		ut64 pc;
		union {
			RZ_PACKED(
				struct {
					ut32 code;
					ut32 flags;
					ut64 ex_record;
					ut64 ex_addr;
				})
			exception;
			RZ_PACKED(
				struct {
					ut64 pathsize;
					ut64 base;
					ut64 pid;
					ut32 checksum;
					ut32 size;
					ut8 unload;
				})
			load_symbols;
		};
	})
kd_stc_64;

typedef struct kd_ioc_t {
	ut32 req;
	ut32 ret;
	ut64 pad[7];
} kd_ioc_t;

RZ_PACKED(
	typedef struct kd_packet_t {
		ut32 leader;
		ut16 type;
		ut16 length;
		ut32 id;
		ut32 checksum;
		ut8 data[];
	})
kd_packet_t;

// KDNET

#define KDNET_MAGIC        0x4d444247 // MDBG
#define KDNET_HMACKEY_SIZE 32
#define KDNET_HMAC_SIZE    16

#define KDNET_PACKET_TYPE_DATA    0
#define KDNET_PACKET_TYPE_CONTROL 1

RZ_PACKED(
	typedef struct kdnet_packet_t {
		ut32 magic; // KDNET_MAGIC
		ut8 version; // Protocol Number
		ut8 type; // Channel Type - 0 Data, 1 Control
	})
kdnet_packet_t;

// KDNet Data mask
#define KDNET_DATA_SIZE           8
#define KDNET_DATA_DIRECTION_MASK 0x80
#define KDNET_DATA_PADSIZE_MASK   0x7F
#define KDNET_DATA_SEQNO_MASK     0xFFFFFF00

// Compile time assertions macros taken from :
// http://www.pixelbeat.org/programming/gcc/static_assert.html
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b)  ASSERT_CONCAT_(a, b)
#define ct_assert(e)         enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1 / (!!(e)) }

ct_assert(sizeof(kd_packet_t) == 16);
ct_assert(sizeof(kd_req_t) == 56);
ct_assert(sizeof(kd_ioc_t) == 64);

int kd_send_ctrl_packet(io_desc_t *desc, const ut32 type, const ut32 id);
int kd_send_data_packet(io_desc_t *desc, const ut32 type, const ut32 id, const ut8 *req, const int req_len, const ut8 *buf, const ut32 buf_len);

int kd_read_packet(io_desc_t *desc, kd_packet_t **p);

bool kd_packet_is_valid(const kd_packet_t *p);
int kd_packet_is_ack(const kd_packet_t *p);

ut32 kd_data_checksum(const ut8 *buf, const ut64 buf_len);

#endif
