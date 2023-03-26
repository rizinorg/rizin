// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DMP_SPECS_H
#define DMP_SPECS_H

#include <rz_types_base.h>

#include "librz/bin/format/mdmp/mdmp_specs.h"

#define DMP64_MAGIC        "\x50\x41\x47\x45\x44\x55\x36\x34" // PAGEDU64
#define DMP_BMP_MAGIC      "\x53\x44\x4d\x50\x44\x55\x4d\x50" // SDMPDUMP
#define DMP_BMP_FULL_MAGIC "\x46\x44\x4d\x50\x44\x55\x4d\x50" // FDMPDUMP
#define DMP_UNUSED_MAGIC   "\x50\x41\x47\x45" // PAGE

#define DMP_DUMPTYPE_UNKNOWN      0
#define DMP_DUMPTYPE_FULL         1
#define DMP_DUMPTYPE_SUMMARY      2
#define DMP_DUMPTYPE_HEADER       3
#define DMP_DUMPTYPE_TRIAGE       4
#define DMP_DUMPTYPE_BITMAPFULL   5
#define DMP_DUMPTYPE_BITMAPKERNEL 6
#define DMP_DUMPTYPE_AUTOMATIC    7

#define DMP_PAGE_SIZE 0x1000

typedef struct _PHYSICAL_MEMORY_RUN {
	ut64 BasePage;
	ut64 PageCount;
} dmp_p_memory_run;

#define DMP_PHYSICAL_MEMORY_BLOCK_SIZE 700
#define DMP_CONTEXT_RECORD_SIZE_64     3000
#define DMP_CONTEXT_RECORD_SIZE_32     1200

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR32 {
	ut32 NumberOfRuns;
	ut32 NumberOfPages;
	dmp_p_memory_run Run[1];
} dmp32_p_memory_desc;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64 {
	ut32 NumberOfRuns; // 0x0
	ut32 _padding1;
	ut64 NumberOfPages; // 0x8
	dmp_p_memory_run Run[1];
} dmp64_p_memory_desc;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut32 MajorVersion;
	ut32 MinorVersion;
	ut32 DirectoryTableBase;
	ut32 PfnDataBase;
	ut32 PsLoadedModuleList;
	ut32 PsActiveProcessHead;
	ut32 MachineImageType;
	ut32 NumberProcessors;
	ut32 BugCheckCode;
	ut32 BugCheckParameter1;
	ut32 BugCheckParameter2;
	ut32 BugCheckParameter3;
	ut32 BugCheckParameter4;
	ut8 VersionUser[32];
	ut8 PaeEnabled;
	ut8 KdSecondaryVersion;
	ut8 VersionUser2[2];
	ut32 KdDebuggerDataBlock;
	union {
		dmp32_p_memory_desc PhysicalMemoryBlock;
		ut8 PhysicalMemoryBlockBuffer[DMP_PHYSICAL_MEMORY_BLOCK_SIZE];
	};
	ut8 ContextRecord[DMP_CONTEXT_RECORD_SIZE_32]; // 0x320 0x2cc bytes
	struct windows_exception_record32 Exception; // 0x7d0
	ut8 Comment[128];
	ut32 DumpType;
	ut32 MiniDumpFields;
	ut32 SecondaryDataState;
	ut32 ProductType;
	ut32 SuiteMask;
	ut32 WriterStatus;
	ut64 RequiredDumpSpace;
	ut64 SystemUpTime;
	ut64 SystemTime;
	ut8 reserved3[56];
} dmp32_header;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut32 MajorVersion;
	ut32 MinorVersion;
	ut64 DirectoryTableBase;
	ut64 PfnDataBase; // nt!_MMPFN
	ut64 PsLoadedModuleList;
	ut64 PsActiveProcessHead;
	ut32 MachineImageType;
	ut32 NumberProcessors;
	ut32 BugCheckCode; // 0x38
	ut8 _padding1[0x4];
	ut64 BugCheckParameter1;
	ut64 BugCheckParameter2;
	ut64 BugCheckParameter3;
	ut64 BugCheckParameter4;
	char VersionUser[32];
	ut64 KdDebuggerDataBlock; // 0x80
	union {
		dmp64_p_memory_desc PhysicalMemoryBlock; // 0x88 0x20 bytes
		ut8 PhysicalMemoryBlockBuffer[DMP_PHYSICAL_MEMORY_BLOCK_SIZE];
	};
	ut8 ContextRecord[DMP_CONTEXT_RECORD_SIZE_64]; // 0x348 0x4d0 bytes
	struct windows_exception_record64 Exception; // 0xf00 0x98 bytes
	ut32 DumpType; // 0xf98 0x4 bytes
	ut8 _padding2[0x4];
	ut64 RequiredDumpSpace; // 0xfa0
	ut64 SystemTime;
	ut8 Comment[128];
	ut64 SystemUpTime;
	ut32 MiniDumpFields;
	ut32 SecondaryDataState;
	ut32 ProductType;
	ut32 SuiteMask;
	ut32 WriterStatus;
	ut8 Unused1;
	ut8 KdSecondaryVersion;
	ut8 Unused[2];
	ut8 _reserved0[4016];
} dmp64_header;

typedef struct {
	ut8 Signature[4];
	ut8 ValidDump[4];
	ut8 _padding1[0x18];
	ut64 FirstPage;
	ut64 TotalPresentPages;
	ut64 Pages;
	ut8 Bitmap[1];
} dmp_bmp_header;

typedef struct {
	ut32 ServicePackBuild;
	ut32 SizeOfDump;
	ut32 ValidOffset; // Offset valid ULONG
	ut32 ContextOffset; // CONTEXT
	ut32 ExceptionOffset; // EXCEPTION
	ut32 MmOffset; // Mm
	ut32 UnloadedDriversOffset;
	ut32 PrcbOffset; // KPRCB
	ut32 ProcessOffset; // EPROCESS
	ut32 ThreadOffset; // ETHREAD
	ut32 CallStackOffset;
	ut32 SizeOfCallStack;
	ut32 DriverListOffset; // dmp_driver_entry32
	ut32 DriverCount;
	ut32 StringPoolOffset; // dmp_string
	ut32 StringPoolSize;
	ut32 BrokenDriverOffset;
	ut32 TriageOptions;
	ut32 TopOfStack;
	ut32 DataPageAddress;
	ut32 DataPageOffset;
	ut32 DataPageSize;
	ut32 DebuggerDataOffset; // KDBG
	ut32 DebuggerDataSize;
	ut32 DataBlocksOffset; // dmp32_triage_datablock
	ut32 DataBlocksCount;
} dmp32_triage;

typedef struct {
	ut32 ServicePackBuild;
	ut32 SizeOfDump;
	ut32 ValidOffset; // Offset valid ULONG
	ut32 ContextOffset; // CONTEXT
	ut32 ExceptionOffset; // EXCEPTION
	ut32 MmOffset; // Mm
	ut32 UnloadedDriversOffset;
	ut32 PrcbOffset; // KPRCB
	ut32 ProcessOffset; // EPROCESS
	ut32 ThreadOffset; // ETHREAD
	ut32 CallStackOffset;
	ut32 SizeOfCallStack;
	ut32 DriverListOffset; // dmp_driver_entry64
	ut32 DriverCount;
	ut32 StringPoolOffset; // dmp_string
	ut32 StringPoolSize;
	ut32 BrokenDriverOffset;
	ut32 TriageOptions;
	ut64 TopOfStack;
	union {
		struct {
			ut32 BStoreOffset;
			ut32 SizeOfBStore;
			ut64 LimitOfBStore;
		} Ia64;
	} ArchitectureSpecific;
	ut64 DataPageAddress;
	ut32 DataPageOffset;
	ut32 DataPageSize;
	ut32 DebuggerDataOffset; // KDBG
	ut32 DebuggerDataSize;
	ut32 DataBlocksOffset; // dmp64_triage_datablock
	ut32 DataBlocksCount;
} dmp64_triage;

typedef struct {
	ut64 virtualAddress;
	ut32 offset;
	ut32 size;
} dmp64_triage_datablock;

typedef struct {
	ut32 virtualAddress;
	ut32 offset;
	ut32 size;
} dmp32_triage_datablock;

typedef struct {
	ut64 Flink;
	ut64 Blink;
} dmp_list_entry64;

typedef struct {
	ut32 Flink;
	ut32 Blink;
} dmp_list_entry32;

typedef struct {
	ut16 lenght;
	ut16 max_length;
	ut64 buffer; // wchar
} dmp_unicode_string64;

typedef struct {
	ut16 lenght;
	ut16 max_length;
	ut32 buffer; // wchar
} dmp_unicode_string32;

typedef struct {
	dmp_list_entry32 InLoadOrderLinks;
	ut32 __Undefined1;
	ut32 __Undefined2;
	ut32 __Undefined3;
	ut32 NonPagedDebugInfo;
	ut32 DllBase;
	ut32 EntryPoint;
	ut32 SizeOfImage;
	dmp_unicode_string32 FullDllName;
	dmp_unicode_string32 BaseDllName;
	ut32 Flags;
	ut16 LoadCount;
	ut16 __Undefined5;
	ut32 __Undefined6;
	ut32 CheckSum;
	ut32 TimeDateStamp;
} dmp_kldr_data_table_entry32;

typedef struct {
	dmp_list_entry64 InLoadOrderLinks;
	ut64 __Undefined1;
	ut64 __Undefined2;
	ut64 __Undefined3;
	ut64 NonPagedDebugInfo;
	ut64 DllBase;
	ut64 EntryPoint;
	ut32 SizeOfImage;
	dmp_unicode_string64 FullDllName;
	dmp_unicode_string64 BaseDllName;
	ut32 Flags;
	ut16 LoadCount;
	ut16 __Undefined5;
	ut64 __Undefined6;
	ut32 CheckSum;
	ut32 __padding1;
	ut32 TimeDateStamp;
	ut32 __padding2;
} dmp_kldr_data_table_entry64;

typedef struct {
	ut32 DriverNameOffset;
	dmp_kldr_data_table_entry32 LdrEntry;
} dmp_driver_entry32;

typedef struct {
	ut32 DriverNameOffset;
	ut32 __alignment;
	dmp_kldr_data_table_entry64 LdrEntry;
} dmp_driver_entry64;

typedef struct {
	ut32 count;
	ut16 buffer[0]; // Wide unicode string
} dmp_string;

// Bug check codes

#define APC_INDEX_MISMATCH                                       0x00000001
#define DEVICE_QUEUE_NOT_BUSY                                    0x00000002
#define INVALID_AFFINITY_SET                                     0x00000003
#define INVALID_DATA_ACCESS_TRAP                                 0x00000004
#define INVALID_PROCESS_ATTACH_ATTEMPT                           0x00000005
#define INVALID_PROCESS_DETACH_ATTEMPT                           0x00000006
#define INVALID_SOFTWARE_INTERRUPT                               0x00000007
#define IRQL_NOT_DISPATCH_LEVEL                                  0x00000008
#define IRQL_NOT_GREATER_OR_EQUAL                                0x00000009
#define IRQL_NOT_LESS_OR_EQUAL                                   0x0000000A
#define NO_EXCEPTION_HANDLING_SUPPORT                            0x0000000B
#define MAXIMUM_WAIT_OBJECTS_EXCEEDED                            0x0000000C
#define MUTEX_LEVEL_NUMBER_VIOLATION                             0x0000000D
#define NO_USER_MODE_CONTEXT                                     0x0000000E
#define SPIN_LOCK_ALREADY_OWNED                                  0x0000000F
#define SPIN_LOCK_NOT_OWNED                                      0x00000010
#define THREAD_NOT_MUTEX_OWNER                                   0x00000011
#define TRAP_CAUSE_UNKNOWN                                       0x00000012
#define EMPTY_THREAD_REAPER_LIST                                 0x00000013
#define CREATE_DELETE_LOCK_NOT_LOCKED                            0x00000014
#define LAST_CHANCE_CALLED_FROM_KMODE                            0x00000015
#define CID_HANDLE_CREATION                                      0x00000016
#define CID_HANDLE_DELETION                                      0x00000017
#define REFERENCE_BY_POINTER                                     0x00000018
#define BAD_POOL_HEADER                                          0x00000019
#define MEMORY_MANAGEMENT                                        0x0000001A
#define PFN_SHARE_COUNT                                          0x0000001B
#define PFN_REFERENCE_COUNT                                      0x0000001C
#define NO_SPIN_LOCK_AVAILABLE                                   0x0000001D
#define KMODE_EXCEPTION_NOT_HANDLED                              0x0000001E
#define SHARED_RESOURCE_CONV_ERROR                               0x0000001F
#define KERNEL_APC_PENDING_DURING_EXIT                           0x00000020
#define QUOTA_UNDERFLOW                                          0x00000021
#define FILE_SYSTEM                                              0x00000022
#define FAT_FILE_SYSTEM                                          0x00000023
#define NTFS_FILE_SYSTEM                                         0x00000024
#define NPFS_FILE_SYSTEM                                         0x00000025
#define CDFS_FILE_SYSTEM                                         0x00000026
#define RDR_FILE_SYSTEM                                          0x00000027
#define CORRUPT_ACCESS_TOKEN                                     0x00000028
#define SECURITY_SYSTEM                                          0x00000029
#define INCONSISTENT_IRP                                         0x0000002A
#define PANIC_STACK_SWITCH                                       0x0000002B
#define PORT_DRIVER_INTERNAL                                     0x0000002C
#define SCSI_DISK_DRIVER_INTERNAL                                0x0000002D
#define DATA_BUS_ERROR                                           0x0000002E
#define INSTRUCTION_BUS_ERROR                                    0x0000002F
#define SET_OF_INVALID_CONTEXT                                   0x00000030
#define PHASE0_INITIALIZATION_FAILED                             0x00000031
#define PHASE1_INITIALIZATION_FAILED                             0x00000032
#define UNEXPECTED_INITIALIZATION_CALL                           0x00000033
#define CACHE_MANAGER                                            0x00000034
#define NO_MORE_IRP_STACK_LOCATIONS                              0x00000035
#define DEVICE_REFERENCE_COUNT_NOT_ZERO                          0x00000036
#define FLOPPY_INTERNAL_ERROR                                    0x00000037
#define SERIAL_DRIVER_INTERNAL                                   0x00000038
#define SYSTEM_EXIT_OWNED_MUTEX                                  0x00000039
#define SYSTEM_UNWIND_PREVIOUS_USER                              0x0000003A
#define SYSTEM_SERVICE_EXCEPTION                                 0x0000003B
#define INTERRUPT_UNWIND_ATTEMPTED                               0x0000003C
#define INTERRUPT_EXCEPTION_NOT_HANDLED                          0x0000003D
#define MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED               0x0000003E
#define NO_MORE_SYSTEM_PTES                                      0x0000003F
#define TARGET_MDL_TOO_SMALL                                     0x00000040
#define MUST_SUCCEED_POOL_EMPTY                                  0x00000041
#define ATDISK_DRIVER_INTERNAL                                   0x00000042
#define NO_SUCH_PARTITION                                        0x00000043
#define MULTIPLE_IRP_COMPLETE_REQUESTS                           0x00000044
#define INSUFFICIENT_SYSTEM_MAP_REGS                             0x00000045
#define DEREF_UNKNOWN_LOGON_SESSION                              0x00000046
#define REF_UNKNOWN_LOGON_SESSION                                0x00000047
#define CANCEL_STATE_IN_COMPLETED_IRP                            0x00000048
#define PAGE_FAULT_WITH_INTERRUPTS_OFF                           0x00000049
#define IRQL_GT_ZERO_AT_SYSTEM_SERVICE                           0x0000004A
#define STREAMS_INTERNAL_ERROR                                   0x0000004B
#define FATAL_UNHANDLED_HARD_ERROR                               0x0000004C
#define NO_PAGES_AVAILABLE                                       0x0000004D
#define PFN_LIST_CORRUPT                                         0x0000004E
#define NDIS_INTERNAL_ERROR                                      0x0000004F
#define PAGE_FAULT_IN_NONPAGED_AREA                              0x00000050
#define REGISTRY_ERROR                                           0x00000051
#define MAILSLOT_FILE_SYSTEM                                     0x00000052
#define NO_BOOT_DEVICE                                           0x00000053
#define LM_SERVER_INTERNAL_ERROR                                 0x00000054
#define DATA_COHERENCY_EXCEPTION                                 0x00000055
#define INSTRUCTION_COHERENCY_EXCEPTION                          0x00000056
#define XNS_INTERNAL_ERROR                                       0x00000057
#define FTDISK_INTERNAL_ERROR                                    0x00000058
#define PINBALL_FILE_SYSTEM                                      0x00000059
#define CRITICAL_SERVICE_FAILED                                  0x0000005A
#define SET_ENV_VAR_FAILED                                       0x0000005B
#define HAL_INITIALIZATION_FAILED                                0x0000005C
#define UNSUPPORTED_PROCESSOR                                    0x0000005D
#define OBJECT_INITIALIZATION_FAILED                             0x0000005E
#define SECURITY_INITIALIZATION_FAILED                           0x0000005F
#define PROCESS_INITIALIZATION_FAILED                            0x00000060
#define HAL1_INITIALIZATION_FAILED                               0x00000061
#define OBJECT1_INITIALIZATION_FAILED                            0x00000062
#define SECURITY1_INITIALIZATION_FAILED                          0x00000063
#define SYMBOLIC_INITIALIZATION_FAILED                           0x00000064
#define MEMORY1_INITIALIZATION_FAILED                            0x00000065
#define CACHE_INITIALIZATION_FAILED                              0x00000066
#define CONFIG_INITIALIZATION_FAILED                             0x00000067
#define FILE_INITIALIZATION_FAILED                               0x00000068
#define IO1_INITIALIZATION_FAILED                                0x00000069
#define LPC_INITIALIZATION_FAILED                                0x0000006A
#define PROCESS1_INITIALIZATION_FAILED                           0x0000006B
#define REFMON_INITIALIZATION_FAILED                             0x0000006C
#define SESSION1_INITIALIZATION_FAILED                           0x0000006D
#define SESSION2_INITIALIZATION_FAILED                           0x0000006E
#define SESSION3_INITIALIZATION_FAILED                           0x0000006F
#define SESSION4_INITIALIZATION_FAILED                           0x00000070
#define SESSION5_INITIALIZATION_FAILED                           0x00000071
#define ASSIGN_DRIVE_LETTERS_FAILED                              0x00000072
#define CONFIG_LIST_FAILED                                       0x00000073
#define BAD_SYSTEM_CONFIG_INFO                                   0x00000074
#define CANNOT_WRITE_CONFIGURATION                               0x00000075
#define PROCESS_HAS_LOCKED_PAGES                                 0x00000076
#define KERNEL_STACK_INPAGE_ERROR                                0x00000077
#define PHASE0_EXCEPTION                                         0x00000078
#define MISMATCHED_HAL                                           0x00000079
#define KERNEL_DATA_INPAGE_ERROR                                 0x0000007A
#define INACCESSIBLE_BOOT_DEVICE                                 0x0000007B
#define BUGCODE_NDIS_DRIVER                                      0x0000007C
#define INSTALL_MORE_MEMORY                                      0x0000007D
#define SYSTEM_THREAD_EXCEPTION_NOT_HANDLED                      0x0000007E
#define UNEXPECTED_KERNEL_MODE_TRAP                              0x0000007F
#define NMI_HARDWARE_FAILURE                                     0x00000080
#define SPIN_LOCK_INIT_FAILURE                                   0x00000081
#define DFS_FILE_SYSTEM                                          0x00000082
#define SETUP_FAILURE                                            0x00000085
#define MBR_CHECKSUM_MISMATCH                                    0x0000008B
#define KERNEL_MODE_EXCEPTION_NOT_HANDLED                        0x0000008E
#define PP0_INITIALIZATION_FAILED                                0x0000008F
#define PP1_INITIALIZATION_FAILED                                0x00000090
#define UP_DRIVER_ON_MP_SYSTEM                                   0x00000092
#define INVALID_KERNEL_HANDLE                                    0x00000093
#define KERNEL_STACK_LOCKED_AT_EXIT                              0x00000094
#define INVALID_WORK_QUEUE_ITEM                                  0x00000096
#define BOUND_IMAGE_UNSUPPORTED                                  0x00000097
#define END_OF_NT_EVALUATION_PERIOD                              0x00000098
#define INVALID_REGION_OR_SEGMENT                                0x00000099
#define SYSTEM_LICENSE_VIOLATION                                 0x0000009A
#define UDFS_FILE_SYSTEM                                         0x0000009B
#define MACHINE_CHECK_EXCEPTION                                  0x0000009C
#define USER_MODE_HEALTH_MONITOR                                 0x0000009E
#define DRIVER_POWER_STATE_FAILURE                               0x0000009F
#define INTERNAL_POWER_ERROR                                     0x000000A0
#define PCI_BUS_DRIVER_INTERNAL                                  0x000000A1
#define MEMORY_IMAGE_CORRUPT                                     0x000000A2
#define ACPI_DRIVER_INTERNAL                                     0x000000A3
#define CNSS_FILE_SYSTEM_FILTER                                  0x000000A4
#define ACPI_BIOS_ERROR                                          0x000000A5
#define BAD_EXHANDLE                                             0x000000A7
#define HAL_MEMORY_ALLOCATION                                    0x000000AC
#define VIDEO_DRIVER_DEBUG_REPORT_REQUEST                        0x000000AD
#define BGI_DETECTED_VIOLATION                                   0x000000B1
#define VIDEO_DRIVER_INIT_FAILURE                                0x000000B4
#define ATTEMPTED_SWITCH_FROM_DPC                                0x000000B8
#define CHIPSET_DETECTED_ERROR                                   0x000000B9
#define SESSION_HAS_VALID_VIEWS_ON_EXIT                          0x000000BA
#define NETWORK_BOOT_INITIALIZATION_FAILED                       0x000000BB
#define NETWORK_BOOT_DUPLICATE_ADDRESS                           0x000000BC
#define INVALID_HIBERNATED_STATE                                 0x000000BD
#define ATTEMPTED_WRITE_TO_READONLY_MEMORY                       0x000000BE
#define MUTEX_ALREADY_OWNED                                      0x000000BF
#define SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION                  0x000000C1
#define BAD_POOL_CALLER                                          0x000000C2
#define DRIVER_VERIFIER_DETECTED_VIOLATION                       0x000000C4
#define DRIVER_CORRUPTED_EXPOOL                                  0x000000C5
#define DRIVER_CAUGHT_MODIFYING_FREED_POOL                       0x000000C6
#define TIMER_OR_DPC_INVALID                                     0x000000C7
#define IRQL_UNEXPECTED_VALUE                                    0x000000C8
#define DRIVER_VERIFIER_IOMANAGER_VIOLATION                      0x000000C9
#define PNP_DETECTED_FATAL_ERROR                                 0x000000CA
#define DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS                      0x000000CB
#define PAGE_FAULT_IN_FREED_SPECIAL_POOL                         0x000000CC
#define PAGE_FAULT_BEYOND_END_OF_ALLOCATION                      0x000000CD
#define DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS    0x000000CE
#define TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE   0x000000CF
#define DRIVER_CORRUPTED_MMPOOL                                  0x000000D0
#define DRIVER_IRQL_NOT_LESS_OR_EQUAL                            0x000000D1
#define BUGCODE_ID_DRIVER                                        0x000000D2
#define DRIVER_PORTION_MUST_BE_NONPAGED                          0x000000D3
#define SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD 0x000000D4
#define DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL                  0x000000D5
#define DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION               0x000000D6
#define DRIVER_UNMAPPING_INVALID_VIEW                            0x000000D7
#define DRIVER_USED_EXCESSIVE_PTES                               0x000000D8
#define LOCKED_PAGES_TRACKER_CORRUPTION                          0x000000D9
#define SYSTEM_PTE_MISUSE                                        0x000000DA
#define DRIVER_CORRUPTED_SYSPTES                                 0x000000DB
#define DRIVER_INVALID_STACK_ACCESS                              0x000000DC
#define POOL_CORRUPTION_IN_FILE_AREA                             0x000000DE
#define IMPERSONATING_WORKER_THREAD                              0x000000DF
#define ACPI_BIOS_FATAL_ERROR                                    0x000000E0
#define WORKER_THREAD_RETURNED_AT_BAD_IRQL                       0x000000E1
#define MANUALLY_INITIATED_CRASH                                 0x000000E2
#define RESOURCE_NOT_OWNED                                       0x000000E3
#define WORKER_INVALID                                           0x000000E4
#define DRIVER_VERIFIER_DMA_VIOLATION                            0x000000E6
#define INVALID_FLOATING_POINT_STATE                             0x000000E7
#define INVALID_CANCEL_OF_FILE_OPEN                              0x000000E8
#define ACTIVE_EX_WORKER_THREAD_TERMINATION                      0x000000E9
#define THREAD_STUCK_IN_DEVICE_DRIVER                            0x000000EA
#define DIRTY_MAPPED_PAGES_CONGESTION                            0x000000EB
#define SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT                   0x000000EC
#define UNMOUNTABLE_BOOT_VOLUME                                  0x000000ED
#define CRITICAL_PROCESS_DIED                                    0x000000EF
#define STORAGE_MINIPORT_ERROR                                   0x000000F0
#define SCSI_VERIFIER_DETECTED_VIOLATION                         0x000000F1
#define HARDWARE_INTERRUPT_STORM                                 0x000000F2
#define DISORDERLY_SHUTDOWN                                      0x000000F3
#define CRITICAL_OBJECT_TERMINATION                              0x000000F4
#define FLTMGR_FILE_SYSTEM                                       0x000000F5
#define PCI_VERIFIER_DETECTED_VIOLATION                          0x000000F6
#define DRIVER_OVERRAN_STACK_BUFFER                              0x000000F7
#define RAMDISK_BOOT_INITIALIZATION_FAILED                       0x000000F8
#define DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN           0x000000F9
#define HTTP_DRIVER_CORRUPTED                                    0x000000FA
#define ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY                    0x000000FC
#define DIRTY_NOWRITE_PAGES_CONGESTION                           0x000000FD
#define BUGCODE_USB_DRIVER                                       0x000000FE
#define RESERVE_QUEUE_OVERFLOW                                   0x000000FF
#define LOADER_BLOCK_MISMATCH                                    0x00000100
#define CLOCK_WATCHDOG_TIMEOUT                                   0x00000101
#define DPC_WATCHDOG_TIMEOUT                                     0x00000102
#define MUP_FILE_SYSTEM                                          0x00000103
#define AGP_INVALID_ACCESS                                       0x00000104
#define AGP_GART_CORRUPTION                                      0x00000105
#define AGP_ILLEGALLY_REPROGRAMMED                               0x00000106
#define THIRD_PARTY_FILE_SYSTEM_FAILURE                          0x00000108
#define CRITICAL_STRUCTURE_CORRUPTION                            0x00000109
#define APP_TAGGING_INITIALIZATION_FAILED                        0x0000010A
#define FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION                   0x0000010C
#define WDF_VIOLATION                                            0x0000010D
#define VIDEO_MEMORY_MANAGEMENT_INTERNAL                         0x0000010E
#define RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED                   0x0000010F
#define RECURSIVE_NMI                                            0x00000111
#define MSRPC_STATE_VIOLATION                                    0x00000112
#define VIDEO_DXGKRNL_FATAL_ERROR                                0x00000113
#define VIDEO_SHADOW_DRIVER_FATAL_ERROR                          0x00000114
#define AGP_INTERNAL                                             0x00000115
#define VIDEO_TDR_FAILURE                                        0x00000116
#define VIDEO_TDR_TIMEOUT_DETECTED                               0x00000117
#define VIDEO_SCHEDULER_INTERNAL_ERROR                           0x00000119
#define EM_INITIALIZATION_FAILURE                                0x0000011A
#define DRIVER_RETURNED_HOLDING_CANCEL_LOCK                      0x0000011B
#define ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE                  0x0000011C
#define EVENT_TRACING_FATAL_ERROR                                0x0000011D
#define TOO_MANY_RECURSIVE_FAULTS                                0x0000011E
#define INVALID_DRIVER_HANDLE                                    0x0000011F
#define BITLOCKER_FATAL_ERROR                                    0x00000120
#define DRIVER_VIOLATION                                         0x00000121
#define WHEA_INTERNAL_ERROR                                      0x00000122
#define CRYPTO_SELF_TEST_FAILURE                                 0x00000123
#define NMR_INVALID_STATE                                        0x00000125
#define NETIO_INVALID_POOL_CALLER                                0x00000126
#define PAGE_NOT_ZERO                                            0x00000127
#define WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY              0x00000128
#define WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY       0x00000129
#define MUI_NO_VALID_SYSTEM_LANGUAGE                             0x0000012A
#define FAULTY_HARDWARE_CORRUPTED_PAGE                           0x0000012B
#define EXFAT_FILE_SYSTEM                                        0x0000012C
#define VOLSNAP_OVERLAPPED_TABLE_ACCESS                          0x0000012D
#define INVALID_MDL_RANGE                                        0x0000012E
#define VHD_BOOT_INITIALIZATION_FAILED                           0x0000012F
#define DYNAMIC_ADD_PROCESSOR_MISMATCH                           0x00000130
#define INVALID_EXTENDED_PROCESSOR_STATE                         0x00000131
#define RESOURCE_OWNER_POINTER_INVALID                           0x00000132
#define DPC_WATCHDOG_VIOLATION                                   0x00000133
#define DRIVE_EXTENDER                                           0x00000134
#define REGISTRY_FILTER_DRIVER_EXCEPTION                         0x00000135
#define VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE                    0x00000136
#define WIN32K_HANDLE_MANAGER                                    0x00000137
#define GPIO_CONTROLLER_DRIVER_ERROR                             0x00000138
#define KERNEL_SECURITY_CHECK_FAILURE                            0x00000139
#define KERNEL_MODE_HEAP_CORRUPTION                              0x0000013A
#define PASSIVE_INTERRUPT_ERROR                                  0x0000013B
#define INVALID_IO_BOOST_STATE                                   0x0000013C
#define CRITICAL_INITIALIZATION_FAILURE                          0x0000013D
#define STORAGE_DEVICE_ABNORMALITY_DETECTED                      0x00000140
#define PROCESSOR_DRIVER_INTERNAL                                0x00000143
#define BUGCODE_USB3_DRIVER                                      0x00000144
#define SECURE_BOOT_VIOLATION                                    0x00000145
#define ABNORMAL_RESET_DETECTED                                  0x00000147
#define REFS_FILE_SYSTEM                                         0x00000149
#define KERNEL_WMI_INTERNAL                                      0x0000014A
#define SOC_SUBSYSTEM_FAILURE                                    0x0000014B
#define FATAL_ABNORMAL_RESET_ERROR                               0x0000014C
#define EXCEPTION_SCOPE_INVALID                                  0x0000014D
#define SOC_CRITICAL_DEVICE_REMOVED                              0x0000014E
#define PDC_WATCHDOG_TIMEOUT                                     0x0000014F
#define TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK                     0x00000150
#define UNSUPPORTED_INSTRUCTION_MODE                             0x00000151
#define INVALID_PUSH_LOCK_FLAGS                                  0x00000152
#define KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION           0x00000153
#define UNEXPECTED_STORE_EXCEPTION                               0x00000154
#define OS_DATA_TAMPERING                                        0x00000155
#define KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION                   0x00000157
#define ILLEGAL_IOMMU_PAGE_FAULT                                 0x00000158
#define HAL_ILLEGAL_IOMMU_PAGE_FAULT                             0x00000159
#define SDBUS_INTERNAL_ERROR                                     0x0000015A
#define WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE  0x0000015B
#define WIN32K_ATOMIC_CHECK_FAILURE                              0x00000160
#define KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE                   0x00000162
#define WORKER_THREAD_TEST_CONDITION                             0x00000163
#define INVALID_RUNDOWN_PROTECTION_FLAGS                         0x0000016C
#define INVALID_SLOT_ALLOCATOR_FLAGS                             0x0000016D
#define ERESOURCE_INVALID_RELEASE                                0x0000016E
#define CRYPTO_LIBRARY_INTERNAL_ERROR                            0x00000170
#define CLUSTER_CSV_CLUSSVC_DISCONNECT_WATCHDOG                  0x00000171
#define COREMSGCALL_INTERNAL_ERROR                               0x00000173
#define COREMSG_INTERNAL_ERROR                                   0x00000174
#define ELAM_DRIVER_DETECTED_FATAL_ERROR                         0x00000178
#define PROFILER_CONFIGURATION_ILLEGAL                           0x0000017B
#define MICROCODE_REVISION_MISMATCH                              0x0000017E
#define VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD                       0x00000187
#define BAD_OBJECT_HEADER                                        0x00000189
#define SECURE_KERNEL_ERROR                                      0x0000018B
#define HYPERGUARD_VIOLATION                                     0x0000018C
#define SECURE_FAULT_UNHANDLED                                   0x0000018D
#define KERNEL_PARTITION_REFERENCE_VIOLATION                     0x0000018E
#define PF_DETECTED_CORRUPTION                                   0x00000191
#define KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL      0x00000192
#define LOADER_ROLLBACK_DETECTED                                 0x00000196
#define WIN32K_SECURITY_FAILURE                                  0x00000197
#define KERNEL_STORAGE_SLOT_IN_USE                               0x00000199
#define WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO            0x0000019A
#define TTM_FATAL_ERROR                                          0x0000019B
#define WIN32K_POWER_WATCHDOG_TIMEOUT                            0x0000019C
#define TTM_WATCHDOG_TIMEOUT                                     0x000001A0
#define WIN32K_CALLOUT_WATCHDOG_BUGCHECK                         0x000001A2
#define FAST_ERESOURCE_PRECONDITION_VIOLATION                    0x000001C6
#define STORE_DATA_STRUCTURE_CORRUPTION                          0x000001C7
#define MANUALLY_INITIATED_POWER_BUTTON_HOLD                     0x000001C8
#define SYNTHETIC_WATCHDOG_TIMEOUT                               0x000001CA
#define INVALID_SILO_DETACH                                      0x000001CB
#define INVALID_CALLBACK_STACK_ADDRESS                           0x000001CD
#define INVALID_KERNEL_STACK_ADDRESS                             0x000001CE
#define HARDWARE_WATCHDOG_TIMEOUT                                0x000001CF
#define CPI_FIRMWARE_WATCHDOG_TIMEOUT                            0x000001D0
#define WORKER_THREAD_INVALID_STATE                              0x000001D2
#define WFP_INVALID_OPERATION                                    0x000001D3
#define DRIVER_PNP_WATCHDOG                                      0x000001D5
#define WORKER_THREAD_RETURNED_WITH_NON_DEFAULT_WORKLOAD_CLASS   0x000001D6
#define EFS_FATAL_ERROR                                          0x000001D7
#define UCMUCSI_FAILURE                                          0x000001D8
#define HAL_IOMMU_INTERNAL_ERROR                                 0x000001D9
#define HAL_BLOCKED_PROCESSOR_INTERNAL_ERROR                     0x000001DA
#define IPI_WATCHDOG_TIMEOUT                                     0x000001DB
#define DMA_COMMON_BUFFER_VECTOR_ERROR                           0x000001DC
#define XBOX_ERACTRL_CS_TIMEOUT                                  0x00000356
#define BC_BLUETOOTH_VERIFIER_FAULT                              0x00000BFE
#define BC_BTHMINI_VERIFIER_FAULT                                0x00000BFF
#define HYPERVISOR_ERROR                                         0x00020001
#define SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M                    0x1000007E
#define UNEXPECTED_KERNEL_MODE_TRAP_M                            0x1000007F
#define KERNEL_MODE_EXCEPTION_NOT_HANDLED_M                      0x1000008E
#define THREAD_STUCK_IN_DEVICE_DRIVER_M                          0x100000EA
#define THREAD_TERMINATE_HELD_MUTEX                              0x4000008A
#define STATUS_CANNOT_LOAD_REGISTRY_FILE                         0xC0000218
#define WINLOGON_FATAL_ERROR                                     0xC000021A
#define STATUS_IMAGE_CHECKSUM_MISMATCH                           0xC0000221
#define MANUALLY_INITIATED_CRASH1                                0xDEADDEAD

#endif /* DMP_SPECS_H */
