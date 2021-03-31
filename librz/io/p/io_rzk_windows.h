// SPDX-FileCopyrightText: 2016 skuater <skuater@hotmail.com>
// SPDX-FileCopyrightText: 2016 Rakholiya Jenish
// SPDX-FileCopyrightText: 2017 Jose Diaz <josediazplay@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef __IO_RZK_WINDOWS_H__
#define __IO_RZK_WINDOWS_H__

#include <rz_io.h>
#include <rz_lib.h>
#include <rz_types.h>
#include <rz_util.h>
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
} RzIOW32;
typedef struct _PPA {
	LARGE_INTEGER address;
	DWORD len;
	unsigned char buffer;
} PA, *PPA;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define RZK_DEVICE "\\\\.\\rzk\\"

#define IOCTL_CODE(DeviceType, Function, Method, Access) \
	(((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#if 0
FILE_DEVICE_UNKNOWN 0x22
FILE_READ_ACCESS 1
FILE_WRITE_ACCESS 2
#endif
#define CLOSE_DRIVER             IOCTL_CODE(0x22, 0x803, 0, 1 | 2)
#define IOCTL_READ_PHYS_MEM      IOCTL_CODE(0x22, 0x807, 0, 1 | 2)
#define IOCTL_READ_KERNEL_MEM    IOCTL_CODE(0x22, 0x804, 0, 1 | 2)
#define IOCTL_WRITE_KERNEL_MEM   IOCTL_CODE(0x22, 0x805, 0, 1 | 2)
#define IOCTL_GET_PHYSADDR       IOCTL_CODE(0x22, 0x809, 0, 1 | 2)
#define IOCTL_WRITE_PHYS_MEM     IOCTL_CODE(0x22, 0x808, 0, 1 | 2)
#define IOCTL_GET_SYSTEM_MODULES IOCTL_CODE(0x22, 0x80a, 0, 1 | 2)

extern HANDLE gHandleDriver;

BOOL StartStopService(LPCTSTR lpServiceName, BOOL bStop);
int GetSystemModules(RzIO *io);
int ReadKernelMemory(ut64 address, ut8 *buf, int len);
int WriteKernelMemory(ut64 address, const ut8 *buf, int len);
int Init(const char *driverPath);

#endif
