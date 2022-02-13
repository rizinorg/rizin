// SPDX-FileCopyrightText: 2020 abcSup <zifan.tan@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

#include "dmp64.h"
#include "../pe/pe_specs.h"

static bool rz_bin_dmp64_init_triage(struct rz_bin_dmp64_obj_t *obj) {
	if (rz_buf_size(obj->b) < sizeof(dmp64_header) + sizeof(dmp64_triage)) {
		return false;
	}
	obj->triage64_header = RZ_NEW(dmp64_triage);
	if (!obj->triage64_header) {
		return false;
	}
	rz_buf_seek(obj->b, sizeof(dmp64_header), SEEK_SET);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ServicePackBuild);
	rz_buf_read_le32(obj->b, &obj->triage64_header->SizeOfDump);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ValidOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ContextOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ExceptionOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->MmOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->UnloadedDriversOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->PrcbOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ProcessOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->ThreadOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->CallStackOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->SizeOfCallStack);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DriverListOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DriverCount);
	rz_buf_read_le32(obj->b, &obj->triage64_header->StringPoolOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->StringPoolSize);
	rz_buf_read_le32(obj->b, &obj->triage64_header->BrokenDriverOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->TriageOptions);
	rz_buf_read_le64(obj->b, &obj->triage64_header->TopOfStack);
	rz_buf_read(obj->b, (ut8 *)&obj->triage64_header->ArchitectureSpecific, sizeof(obj->triage64_header->ArchitectureSpecific));
	rz_buf_read_le64(obj->b, &obj->triage64_header->DataPageAddress);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DataPageOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DataPageSize);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DebuggerDataOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DebuggerDataSize);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DataBlocksOffset);
	rz_buf_read_le32(obj->b, &obj->triage64_header->DataBlocksCount);
	return true;
}

static int rz_bin_dmp64_init_memory_runs(struct rz_bin_dmp64_obj_t *obj) {
	int i, j;
	dmp64_p_memory_desc *mem_desc = &obj->header->PhysicalMemoryBlock;
	if (!memcmp(mem_desc, DMP_UNUSED_MAGIC, 4)) {
		eprintf("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	ut64 num_runs = mem_desc->NumberOfRuns;
	if (num_runs * sizeof(dmp_p_memory_run) >= rz_offsetof(dmp64_header, ContextRecord)) {
		eprintf("Warning: Invalid PhysicalMemoryDescriptor\n");
		return false;
	}
	obj->pages = rz_list_newf(free);
	if (!obj->pages) {
		return false;
	}
	dmp_p_memory_run *runs = calloc(num_runs, sizeof(dmp_p_memory_run));
	ut64 num_runs_offset = rz_offsetof(dmp64_header, PhysicalMemoryBlockBuffer) + rz_offsetof(dmp64_p_memory_desc, NumberOfRuns);
	if (rz_buf_read_at(obj->b, num_runs_offset, (ut8 *)runs, num_runs * sizeof(dmp_p_memory_run)) < 0) {
		eprintf("Warning: read memory runs\n");
		free(runs);
		return false;
	};

	ut64 num_page = 0;
	ut64 base = sizeof(dmp64_header);
	for (i = 0; i < num_runs; i++) {
		dmp_p_memory_run *run = &(runs[i]);
		for (j = 0; j < run->PageCount; j++) {
			dmp_page_desc *page = RZ_NEW0(dmp_page_desc);
			if (!page) {
				free(runs);
				return false;
			}
			page->start = (run->BasePage + j) * DMP_PAGE_SIZE;
			page->file_offset = base + num_page * DMP_PAGE_SIZE;
			rz_list_append(obj->pages, page);
			num_page++;
		}
	}
	if (mem_desc->NumberOfPages != num_page) {
		eprintf("Warning: Number of Pages not matches\n");
	}

	free(runs);
	return true;
}

static int rz_bin_dmp64_init_header(struct rz_bin_dmp64_obj_t *obj) {
	if (!(obj->header = RZ_NEW0(dmp64_header))) {
		rz_sys_perror("RZ_NEW0 (header)");
		return false;
	}
	if (rz_buf_read_at(obj->b, 0, (ut8 *)obj->header, sizeof(dmp64_header)) < 0) {
		eprintf("Warning: read header\n");
		return false;
	}
	obj->dtb = obj->header->DirectoryTableBase;

	return true;
}

static void free_driver(dmp_driver_desc *driver) {
	free(driver->file);
	free(driver);
}

static bool rz_bin_dmp64_init_triage_drivers(struct rz_bin_dmp64_obj_t *obj) {
	if (!obj->triage64_header) {
		return false;
	}

	obj->drivers = rz_list_newf((RzListFree)free_driver);
	if (!obj->drivers) {
		return false;
	}
	ut32 address = obj->triage64_header->DriverListOffset;
	int i;
	for (i = 0; i < obj->triage64_header->DriverCount; i++) {
		dmp_driver_desc *driver = RZ_NEW0(dmp_driver_desc);
		if (!driver) {
			break;
		}
		ut32 name_offset = 0;
		const ut64 kldr_entry_addr = address + rz_offsetof(dmp_driver_entry64, LdrEntry);
		rz_buf_read_le32_at(obj->b, kldr_entry_addr + rz_offsetof(dmp_kldr_data_table_entry64, SizeOfImage), &driver->size);
		rz_buf_read_le32_at(obj->b, kldr_entry_addr + rz_offsetof(dmp_kldr_data_table_entry64, TimeDateStamp), &driver->timestamp);
		rz_buf_read_le64_at(obj->b, kldr_entry_addr + rz_offsetof(dmp_kldr_data_table_entry64, DllBase), &driver->base);
		rz_buf_read_le32_at(obj->b, address + rz_offsetof(dmp_driver_entry64, DriverNameOffset), &name_offset);

		dmp_string str = { 0 };
		rz_buf_seek(obj->b, name_offset, SEEK_SET);
		rz_buf_read_le32(obj->b, &str.count);
		if (str.count > 1024) {
			free(driver);
			return false;
		}
		ut8 *file = calloc(str.count + 1, sizeof(ut16));
		ut8 *file_utf8 = calloc(str.count + 1, sizeof(ut16));
		if (!file) {
			free(driver);
			free(file);
			free(file_utf8);
			return false;
		}
		rz_buf_read(obj->b, file, str.count * sizeof(ut16));
		const size_t size = (str.count + 1) * sizeof(ut16);
		rz_str_utf16_to_utf8(file_utf8, size, file, size, true);
		driver->file = (char *)file_utf8;
		free(file);
		rz_list_push(obj->drivers, driver);
		address += sizeof(dmp_driver_entry64);
	}
	return true;
}

static bool rz_bin_dmp64_init_triage_datablocks(struct rz_bin_dmp64_obj_t *obj) {
	if (!obj->triage64_header) {
		return false;
	}

	obj->datablocks = rz_list_newf(free);
	if (!obj->datablocks) {
		return false;
	}

	rz_buf_seek(obj->b, obj->triage64_header->DataBlocksOffset, SEEK_SET);

	ut32 i;
	for (i = 0; i < obj->triage64_header->DataBlocksCount; i++) {
		dmp64_triage_datablock *db = RZ_NEW0(dmp64_triage_datablock);
		if (!db) {
			break;
		}
		rz_buf_read_le64(obj->b, &db->virtualAddress);
		rz_buf_read_le32(obj->b, &db->offset);
		rz_buf_read_le32(obj->b, &db->size);
		rz_list_push(obj->datablocks, db);
	}

	if (obj->triage64_header->DebuggerDataOffset) {
		dmp64_triage_datablock *db = RZ_NEW0(dmp64_triage_datablock);
		if (!db) {
			return true;
		}
		db->virtualAddress = obj->header->KdDebuggerDataBlock;
		db->offset = obj->triage64_header->DebuggerDataOffset;
		db->size = obj->triage64_header->DebuggerDataSize;
		rz_list_push(obj->datablocks, db);
	}

	return true;
}

static int rz_bin_dmp64_init_bmp_pages(struct rz_bin_dmp64_obj_t *obj) {
	if (!obj->bmp_header) {
		return false;
	}
	obj->pages = rz_list_newf(free);
	if (!obj->pages) {
		return false;
	}
	ut64 paddr_base = obj->bmp_header->FirstPage;
	ut64 num_pages = obj->bmp_header->Pages;
	RzBitmap *bitmap = rz_bitmap_new(num_pages);
	rz_bitmap_set_bytes(bitmap, obj->bitmap, num_pages / 8);

	ut64 num_bitset = 0;
	ut64 i;
	bool create_new_page = true;
	dmp_page_desc *page;
	for (i = 0; i < num_pages; i++) {
		if (!rz_bitmap_test(bitmap, i)) {
			create_new_page = true;
			continue;
		}
		if (!create_new_page) {
			page->size += DMP_PAGE_SIZE;
			num_bitset++;
			continue;
		}
		page = RZ_NEW0(dmp_page_desc);
		if (!page) {
			rz_bitmap_free(bitmap);
			return false;
		}
		if (UT64_MUL_OVFCHK(i, DMP_PAGE_SIZE)) {
			break;
		}
		page->start = i * DMP_PAGE_SIZE;
		page->file_offset = paddr_base + num_bitset * DMP_PAGE_SIZE;
		page->size = DMP_PAGE_SIZE;
		rz_list_append(obj->pages, page);
		num_bitset++;
		create_new_page = false;
	}
	if (obj->bmp_header->TotalPresentPages != num_bitset) {
		eprintf("Warning: TotalPresentPages not matched\n");
		rz_bitmap_free(bitmap);
		return false;
	}

	rz_bitmap_free(bitmap);
	return true;
}

static int rz_bin_dmp64_init_bmp_header(struct rz_bin_dmp64_obj_t *obj) {
	if (!(obj->bmp_header = RZ_NEW0(dmp_bmp_header))) {
		rz_sys_perror("RZ_NEW0 (dmp_bmp_header)");
		return false;
	}
	if (rz_buf_read_at(obj->b, sizeof(dmp64_header), (ut8 *)obj->bmp_header, rz_offsetof(dmp_bmp_header, Bitmap)) < 0) {
		eprintf("Warning: read bmp_header\n");
		return false;
	}
	if (memcmp(obj->bmp_header, DMP_BMP_MAGIC, 8) &&
		memcmp(obj->bmp_header, DMP_BMP_FULL_MAGIC, 8)) {
		eprintf("Warning: Invalid Bitmap Magic\n");
		return false;
	}
	ut64 bitmapsize = obj->bmp_header->Pages / 8;
	obj->bitmap = calloc(1, bitmapsize);
	if (rz_buf_read_at(obj->b, sizeof(dmp64_header) + rz_offsetof(dmp_bmp_header, Bitmap), obj->bitmap, bitmapsize) < 0) {
		eprintf("Warning: read bitmap\n");
		return false;
	}

	return true;
}

static int rz_bin_dmp64_init(struct rz_bin_dmp64_obj_t *obj) {
	if (!rz_bin_dmp64_init_header(obj)) {
		eprintf("Warning: Invalid Kernel Dump x64 Format\n");
		return false;
	}
	switch (obj->header->DumpType) {
	case DMP_DUMPTYPE_TRIAGE:
		if (!rz_bin_dmp64_init_triage(obj) ||
			!rz_bin_dmp64_init_triage_datablocks(obj) ||
			!rz_bin_dmp64_init_triage_drivers(obj)) {
			return false;
		}
		break;
	case DMP_DUMPTYPE_BITMAPFULL:
	case DMP_DUMPTYPE_BITMAPKERNEL:
		if (!rz_bin_dmp64_init_bmp_header(obj) ||
			!rz_bin_dmp64_init_bmp_pages(obj)) {
			return false;
		}
		break;
	case DMP_DUMPTYPE_FULL:
		if (!rz_bin_dmp64_init_memory_runs(obj)) {
			return false;
		}
		break;
	default:
		break;
	}

	return true;
}

void rz_bin_dmp64_free(struct rz_bin_dmp64_obj_t *obj) {
	if (!obj) {
		return;
	}

	rz_buf_free(obj->b);
	obj->b = NULL;
	free(obj->header);
	free(obj->bmp_header);
	free(obj->triage64_header);
	free(obj->runs);
	free(obj->bitmap);
	rz_list_free(obj->pages);
	free(obj);
}

struct rz_bin_dmp64_obj_t *rz_bin_dmp64_new_buf(RzBuffer *buf) {
	struct rz_bin_dmp64_obj_t *obj = RZ_NEW0(struct rz_bin_dmp64_obj_t);
	if (!obj) {
		return NULL;
	}
	obj->kv = sdb_new0();
	obj->size = (ut32)rz_buf_size(buf);
	obj->b = rz_buf_ref(buf);

	if (!rz_bin_dmp64_init(obj)) {
		rz_bin_dmp64_free(obj);
		return NULL;
	}

	return obj;
}

const char *rz_bin_dmp64_bugcheckcode_as_str(ut32 BugCheckCode) {
#define CASE(code) \
	case code: return #code;
	switch (BugCheckCode) {
		CASE(APC_INDEX_MISMATCH)
		CASE(DEVICE_QUEUE_NOT_BUSY)
		CASE(INVALID_AFFINITY_SET)
		CASE(INVALID_DATA_ACCESS_TRAP)
		CASE(INVALID_PROCESS_ATTACH_ATTEMPT)
		CASE(INVALID_PROCESS_DETACH_ATTEMPT)
		CASE(INVALID_SOFTWARE_INTERRUPT)
		CASE(IRQL_NOT_DISPATCH_LEVEL)
		CASE(IRQL_NOT_GREATER_OR_EQUAL)
		CASE(IRQL_NOT_LESS_OR_EQUAL)
		CASE(NO_EXCEPTION_HANDLING_SUPPORT)
		CASE(MAXIMUM_WAIT_OBJECTS_EXCEEDED)
		CASE(MUTEX_LEVEL_NUMBER_VIOLATION)
		CASE(NO_USER_MODE_CONTEXT)
		CASE(SPIN_LOCK_ALREADY_OWNED)
		CASE(SPIN_LOCK_NOT_OWNED)
		CASE(THREAD_NOT_MUTEX_OWNER)
		CASE(TRAP_CAUSE_UNKNOWN)
		CASE(EMPTY_THREAD_REAPER_LIST)
		CASE(CREATE_DELETE_LOCK_NOT_LOCKED)
		CASE(LAST_CHANCE_CALLED_FROM_KMODE)
		CASE(CID_HANDLE_CREATION)
		CASE(CID_HANDLE_DELETION)
		CASE(REFERENCE_BY_POINTER)
		CASE(BAD_POOL_HEADER)
		CASE(MEMORY_MANAGEMENT)
		CASE(PFN_SHARE_COUNT)
		CASE(PFN_REFERENCE_COUNT)
		CASE(NO_SPIN_LOCK_AVAILABLE)
		CASE(KMODE_EXCEPTION_NOT_HANDLED)
		CASE(SHARED_RESOURCE_CONV_ERROR)
		CASE(KERNEL_APC_PENDING_DURING_EXIT)
		CASE(QUOTA_UNDERFLOW)
		CASE(FILE_SYSTEM)
		CASE(FAT_FILE_SYSTEM)
		CASE(NTFS_FILE_SYSTEM)
		CASE(NPFS_FILE_SYSTEM)
		CASE(CDFS_FILE_SYSTEM)
		CASE(RDR_FILE_SYSTEM)
		CASE(CORRUPT_ACCESS_TOKEN)
		CASE(SECURITY_SYSTEM)
		CASE(INCONSISTENT_IRP)
		CASE(PANIC_STACK_SWITCH)
		CASE(PORT_DRIVER_INTERNAL)
		CASE(SCSI_DISK_DRIVER_INTERNAL)
		CASE(DATA_BUS_ERROR)
		CASE(INSTRUCTION_BUS_ERROR)
		CASE(SET_OF_INVALID_CONTEXT)
		CASE(PHASE0_INITIALIZATION_FAILED)
		CASE(PHASE1_INITIALIZATION_FAILED)
		CASE(UNEXPECTED_INITIALIZATION_CALL)
		CASE(CACHE_MANAGER)
		CASE(NO_MORE_IRP_STACK_LOCATIONS)
		CASE(DEVICE_REFERENCE_COUNT_NOT_ZERO)
		CASE(FLOPPY_INTERNAL_ERROR)
		CASE(SERIAL_DRIVER_INTERNAL)
		CASE(SYSTEM_EXIT_OWNED_MUTEX)
		CASE(SYSTEM_UNWIND_PREVIOUS_USER)
		CASE(SYSTEM_SERVICE_EXCEPTION)
		CASE(INTERRUPT_UNWIND_ATTEMPTED)
		CASE(INTERRUPT_EXCEPTION_NOT_HANDLED)
		CASE(MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED)
		CASE(NO_MORE_SYSTEM_PTES)
		CASE(TARGET_MDL_TOO_SMALL)
		CASE(MUST_SUCCEED_POOL_EMPTY)
		CASE(ATDISK_DRIVER_INTERNAL)
		CASE(NO_SUCH_PARTITION)
		CASE(MULTIPLE_IRP_COMPLETE_REQUESTS)
		CASE(INSUFFICIENT_SYSTEM_MAP_REGS)
		CASE(DEREF_UNKNOWN_LOGON_SESSION)
		CASE(REF_UNKNOWN_LOGON_SESSION)
		CASE(CANCEL_STATE_IN_COMPLETED_IRP)
		CASE(PAGE_FAULT_WITH_INTERRUPTS_OFF)
		CASE(IRQL_GT_ZERO_AT_SYSTEM_SERVICE)
		CASE(STREAMS_INTERNAL_ERROR)
		CASE(FATAL_UNHANDLED_HARD_ERROR)
		CASE(NO_PAGES_AVAILABLE)
		CASE(PFN_LIST_CORRUPT)
		CASE(NDIS_INTERNAL_ERROR)
		CASE(PAGE_FAULT_IN_NONPAGED_AREA)
		CASE(REGISTRY_ERROR)
		CASE(MAILSLOT_FILE_SYSTEM)
		CASE(NO_BOOT_DEVICE)
		CASE(LM_SERVER_INTERNAL_ERROR)
		CASE(DATA_COHERENCY_EXCEPTION)
		CASE(INSTRUCTION_COHERENCY_EXCEPTION)
		CASE(XNS_INTERNAL_ERROR)
		CASE(FTDISK_INTERNAL_ERROR)
		CASE(PINBALL_FILE_SYSTEM)
		CASE(CRITICAL_SERVICE_FAILED)
		CASE(SET_ENV_VAR_FAILED)
		CASE(HAL_INITIALIZATION_FAILED)
		CASE(UNSUPPORTED_PROCESSOR)
		CASE(OBJECT_INITIALIZATION_FAILED)
		CASE(SECURITY_INITIALIZATION_FAILED)
		CASE(PROCESS_INITIALIZATION_FAILED)
		CASE(HAL1_INITIALIZATION_FAILED)
		CASE(OBJECT1_INITIALIZATION_FAILED)
		CASE(SECURITY1_INITIALIZATION_FAILED)
		CASE(SYMBOLIC_INITIALIZATION_FAILED)
		CASE(MEMORY1_INITIALIZATION_FAILED)
		CASE(CACHE_INITIALIZATION_FAILED)
		CASE(CONFIG_INITIALIZATION_FAILED)
		CASE(FILE_INITIALIZATION_FAILED)
		CASE(IO1_INITIALIZATION_FAILED)
		CASE(LPC_INITIALIZATION_FAILED)
		CASE(PROCESS1_INITIALIZATION_FAILED)
		CASE(REFMON_INITIALIZATION_FAILED)
		CASE(SESSION1_INITIALIZATION_FAILED)
		CASE(SESSION2_INITIALIZATION_FAILED)
		CASE(SESSION3_INITIALIZATION_FAILED)
		CASE(SESSION4_INITIALIZATION_FAILED)
		CASE(SESSION5_INITIALIZATION_FAILED)
		CASE(ASSIGN_DRIVE_LETTERS_FAILED)
		CASE(CONFIG_LIST_FAILED)
		CASE(BAD_SYSTEM_CONFIG_INFO)
		CASE(CANNOT_WRITE_CONFIGURATION)
		CASE(PROCESS_HAS_LOCKED_PAGES)
		CASE(KERNEL_STACK_INPAGE_ERROR)
		CASE(PHASE0_EXCEPTION)
		CASE(MISMATCHED_HAL)
		CASE(KERNEL_DATA_INPAGE_ERROR)
		CASE(INACCESSIBLE_BOOT_DEVICE)
		CASE(BUGCODE_NDIS_DRIVER)
		CASE(INSTALL_MORE_MEMORY)
		CASE(SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)
		CASE(UNEXPECTED_KERNEL_MODE_TRAP)
		CASE(NMI_HARDWARE_FAILURE)
		CASE(SPIN_LOCK_INIT_FAILURE)
		CASE(DFS_FILE_SYSTEM)
		CASE(SETUP_FAILURE)
		CASE(MBR_CHECKSUM_MISMATCH)
		CASE(KERNEL_MODE_EXCEPTION_NOT_HANDLED)
		CASE(PP0_INITIALIZATION_FAILED)
		CASE(PP1_INITIALIZATION_FAILED)
		CASE(UP_DRIVER_ON_MP_SYSTEM)
		CASE(INVALID_KERNEL_HANDLE)
		CASE(KERNEL_STACK_LOCKED_AT_EXIT)
		CASE(INVALID_WORK_QUEUE_ITEM)
		CASE(BOUND_IMAGE_UNSUPPORTED)
		CASE(END_OF_NT_EVALUATION_PERIOD)
		CASE(INVALID_REGION_OR_SEGMENT)
		CASE(SYSTEM_LICENSE_VIOLATION)
		CASE(UDFS_FILE_SYSTEM)
		CASE(MACHINE_CHECK_EXCEPTION)
		CASE(USER_MODE_HEALTH_MONITOR)
		CASE(DRIVER_POWER_STATE_FAILURE)
		CASE(INTERNAL_POWER_ERROR)
		CASE(PCI_BUS_DRIVER_INTERNAL)
		CASE(MEMORY_IMAGE_CORRUPT)
		CASE(ACPI_DRIVER_INTERNAL)
		CASE(CNSS_FILE_SYSTEM_FILTER)
		CASE(ACPI_BIOS_ERROR)
		CASE(BAD_EXHANDLE)
		CASE(HAL_MEMORY_ALLOCATION)
		CASE(VIDEO_DRIVER_DEBUG_REPORT_REQUEST)
		CASE(BGI_DETECTED_VIOLATION)
		CASE(VIDEO_DRIVER_INIT_FAILURE)
		CASE(ATTEMPTED_SWITCH_FROM_DPC)
		CASE(CHIPSET_DETECTED_ERROR)
		CASE(SESSION_HAS_VALID_VIEWS_ON_EXIT)
		CASE(NETWORK_BOOT_INITIALIZATION_FAILED)
		CASE(NETWORK_BOOT_DUPLICATE_ADDRESS)
		CASE(INVALID_HIBERNATED_STATE)
		CASE(ATTEMPTED_WRITE_TO_READONLY_MEMORY)
		CASE(MUTEX_ALREADY_OWNED)
		CASE(SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION)
		CASE(BAD_POOL_CALLER)
		CASE(DRIVER_VERIFIER_DETECTED_VIOLATION)
		CASE(DRIVER_CORRUPTED_EXPOOL)
		CASE(DRIVER_CAUGHT_MODIFYING_FREED_POOL)
		CASE(TIMER_OR_DPC_INVALID)
		CASE(IRQL_UNEXPECTED_VALUE)
		CASE(DRIVER_VERIFIER_IOMANAGER_VIOLATION)
		CASE(PNP_DETECTED_FATAL_ERROR)
		CASE(DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS)
		CASE(PAGE_FAULT_IN_FREED_SPECIAL_POOL)
		CASE(PAGE_FAULT_BEYOND_END_OF_ALLOCATION)
		CASE(DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS)
		CASE(TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE)
		CASE(DRIVER_CORRUPTED_MMPOOL)
		CASE(DRIVER_IRQL_NOT_LESS_OR_EQUAL)
		CASE(BUGCODE_ID_DRIVER)
		CASE(DRIVER_PORTION_MUST_BE_NONPAGED)
		CASE(SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD)
		CASE(DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL)
		CASE(DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION)
		CASE(DRIVER_UNMAPPING_INVALID_VIEW)
		CASE(DRIVER_USED_EXCESSIVE_PTES)
		CASE(LOCKED_PAGES_TRACKER_CORRUPTION)
		CASE(SYSTEM_PTE_MISUSE)
		CASE(DRIVER_CORRUPTED_SYSPTES)
		CASE(DRIVER_INVALID_STACK_ACCESS)
		CASE(POOL_CORRUPTION_IN_FILE_AREA)
		CASE(IMPERSONATING_WORKER_THREAD)
		CASE(ACPI_BIOS_FATAL_ERROR)
		CASE(WORKER_THREAD_RETURNED_AT_BAD_IRQL)
		CASE(MANUALLY_INITIATED_CRASH)
		CASE(RESOURCE_NOT_OWNED)
		CASE(WORKER_INVALID)
		CASE(DRIVER_VERIFIER_DMA_VIOLATION)
		CASE(INVALID_FLOATING_POINT_STATE)
		CASE(INVALID_CANCEL_OF_FILE_OPEN)
		CASE(ACTIVE_EX_WORKER_THREAD_TERMINATION)
		CASE(THREAD_STUCK_IN_DEVICE_DRIVER)
		CASE(DIRTY_MAPPED_PAGES_CONGESTION)
		CASE(SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT)
		CASE(UNMOUNTABLE_BOOT_VOLUME)
		CASE(CRITICAL_PROCESS_DIED)
		CASE(STORAGE_MINIPORT_ERROR)
		CASE(SCSI_VERIFIER_DETECTED_VIOLATION)
		CASE(HARDWARE_INTERRUPT_STORM)
		CASE(DISORDERLY_SHUTDOWN)
		CASE(CRITICAL_OBJECT_TERMINATION)
		CASE(FLTMGR_FILE_SYSTEM)
		CASE(PCI_VERIFIER_DETECTED_VIOLATION)
		CASE(DRIVER_OVERRAN_STACK_BUFFER)
		CASE(RAMDISK_BOOT_INITIALIZATION_FAILED)
		CASE(DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN)
		CASE(HTTP_DRIVER_CORRUPTED)
		CASE(ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY)
		CASE(DIRTY_NOWRITE_PAGES_CONGESTION)
		CASE(BUGCODE_USB_DRIVER)
		CASE(RESERVE_QUEUE_OVERFLOW)
		CASE(LOADER_BLOCK_MISMATCH)
		CASE(CLOCK_WATCHDOG_TIMEOUT)
		CASE(DPC_WATCHDOG_TIMEOUT)
		CASE(MUP_FILE_SYSTEM)
		CASE(AGP_INVALID_ACCESS)
		CASE(AGP_GART_CORRUPTION)
		CASE(AGP_ILLEGALLY_REPROGRAMMED)
		CASE(THIRD_PARTY_FILE_SYSTEM_FAILURE)
		CASE(CRITICAL_STRUCTURE_CORRUPTION)
		CASE(APP_TAGGING_INITIALIZATION_FAILED)
		CASE(FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION)
		CASE(WDF_VIOLATION)
		CASE(VIDEO_MEMORY_MANAGEMENT_INTERNAL)
		CASE(RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED)
		CASE(RECURSIVE_NMI)
		CASE(MSRPC_STATE_VIOLATION)
		CASE(VIDEO_DXGKRNL_FATAL_ERROR)
		CASE(VIDEO_SHADOW_DRIVER_FATAL_ERROR)
		CASE(AGP_INTERNAL)
		CASE(VIDEO_TDR_FAILURE)
		CASE(VIDEO_TDR_TIMEOUT_DETECTED)
		CASE(VIDEO_SCHEDULER_INTERNAL_ERROR)
		CASE(EM_INITIALIZATION_FAILURE)
		CASE(DRIVER_RETURNED_HOLDING_CANCEL_LOCK)
		CASE(ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE)
		CASE(EVENT_TRACING_FATAL_ERROR)
		CASE(TOO_MANY_RECURSIVE_FAULTS)
		CASE(INVALID_DRIVER_HANDLE)
		CASE(BITLOCKER_FATAL_ERROR)
		CASE(DRIVER_VIOLATION)
		CASE(WHEA_INTERNAL_ERROR)
		CASE(CRYPTO_SELF_TEST_FAILURE)
		CASE(NMR_INVALID_STATE)
		CASE(NETIO_INVALID_POOL_CALLER)
		CASE(PAGE_NOT_ZERO)
		CASE(WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY)
		CASE(WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY)
		CASE(MUI_NO_VALID_SYSTEM_LANGUAGE)
		CASE(FAULTY_HARDWARE_CORRUPTED_PAGE)
		CASE(EXFAT_FILE_SYSTEM)
		CASE(VOLSNAP_OVERLAPPED_TABLE_ACCESS)
		CASE(INVALID_MDL_RANGE)
		CASE(VHD_BOOT_INITIALIZATION_FAILED)
		CASE(DYNAMIC_ADD_PROCESSOR_MISMATCH)
		CASE(INVALID_EXTENDED_PROCESSOR_STATE)
		CASE(RESOURCE_OWNER_POINTER_INVALID)
		CASE(DPC_WATCHDOG_VIOLATION)
		CASE(DRIVE_EXTENDER)
		CASE(REGISTRY_FILTER_DRIVER_EXCEPTION)
		CASE(VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE)
		CASE(WIN32K_HANDLE_MANAGER)
		CASE(GPIO_CONTROLLER_DRIVER_ERROR)
		CASE(KERNEL_SECURITY_CHECK_FAILURE)
		CASE(KERNEL_MODE_HEAP_CORRUPTION)
		CASE(PASSIVE_INTERRUPT_ERROR)
		CASE(INVALID_IO_BOOST_STATE)
		CASE(CRITICAL_INITIALIZATION_FAILURE)
		CASE(STORAGE_DEVICE_ABNORMALITY_DETECTED)
		CASE(PROCESSOR_DRIVER_INTERNAL)
		CASE(BUGCODE_USB3_DRIVER)
		CASE(SECURE_BOOT_VIOLATION)
		CASE(ABNORMAL_RESET_DETECTED)
		CASE(REFS_FILE_SYSTEM)
		CASE(KERNEL_WMI_INTERNAL)
		CASE(SOC_SUBSYSTEM_FAILURE)
		CASE(FATAL_ABNORMAL_RESET_ERROR)
		CASE(EXCEPTION_SCOPE_INVALID)
		CASE(SOC_CRITICAL_DEVICE_REMOVED)
		CASE(PDC_WATCHDOG_TIMEOUT)
		CASE(TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK)
		CASE(UNSUPPORTED_INSTRUCTION_MODE)
		CASE(INVALID_PUSH_LOCK_FLAGS)
		CASE(KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION)
		CASE(UNEXPECTED_STORE_EXCEPTION)
		CASE(OS_DATA_TAMPERING)
		CASE(KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION)
		CASE(ILLEGAL_IOMMU_PAGE_FAULT)
		CASE(HAL_ILLEGAL_IOMMU_PAGE_FAULT)
		CASE(SDBUS_INTERNAL_ERROR)
		CASE(WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE)
		CASE(WIN32K_ATOMIC_CHECK_FAILURE)
		CASE(KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE)
		CASE(WORKER_THREAD_TEST_CONDITION)
		CASE(INVALID_RUNDOWN_PROTECTION_FLAGS)
		CASE(INVALID_SLOT_ALLOCATOR_FLAGS)
		CASE(ERESOURCE_INVALID_RELEASE)
		CASE(CRYPTO_LIBRARY_INTERNAL_ERROR)
		CASE(CLUSTER_CSV_CLUSSVC_DISCONNECT_WATCHDOG)
		CASE(COREMSGCALL_INTERNAL_ERROR)
		CASE(COREMSG_INTERNAL_ERROR)
		CASE(ELAM_DRIVER_DETECTED_FATAL_ERROR)
		CASE(PROFILER_CONFIGURATION_ILLEGAL)
		CASE(MICROCODE_REVISION_MISMATCH)
		CASE(VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD)
		CASE(BAD_OBJECT_HEADER)
		CASE(SECURE_KERNEL_ERROR)
		CASE(HYPERGUARD_VIOLATION)
		CASE(SECURE_FAULT_UNHANDLED)
		CASE(KERNEL_PARTITION_REFERENCE_VIOLATION)
		CASE(PF_DETECTED_CORRUPTION)
		CASE(KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL)
		CASE(LOADER_ROLLBACK_DETECTED)
		CASE(WIN32K_SECURITY_FAILURE)
		CASE(KERNEL_STORAGE_SLOT_IN_USE)
		CASE(WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO)
		CASE(TTM_FATAL_ERROR)
		CASE(WIN32K_POWER_WATCHDOG_TIMEOUT)
		CASE(TTM_WATCHDOG_TIMEOUT)
		CASE(WIN32K_CALLOUT_WATCHDOG_BUGCHECK)
		CASE(FAST_ERESOURCE_PRECONDITION_VIOLATION)
		CASE(STORE_DATA_STRUCTURE_CORRUPTION)
		CASE(MANUALLY_INITIATED_POWER_BUTTON_HOLD)
		CASE(SYNTHETIC_WATCHDOG_TIMEOUT)
		CASE(INVALID_SILO_DETACH)
		CASE(INVALID_CALLBACK_STACK_ADDRESS)
		CASE(INVALID_KERNEL_STACK_ADDRESS)
		CASE(HARDWARE_WATCHDOG_TIMEOUT)
		CASE(CPI_FIRMWARE_WATCHDOG_TIMEOUT)
		CASE(WORKER_THREAD_INVALID_STATE)
		CASE(WFP_INVALID_OPERATION)
		CASE(DRIVER_PNP_WATCHDOG)
		CASE(WORKER_THREAD_RETURNED_WITH_NON_DEFAULT_WORKLOAD_CLASS)
		CASE(EFS_FATAL_ERROR)
		CASE(UCMUCSI_FAILURE)
		CASE(HAL_IOMMU_INTERNAL_ERROR)
		CASE(HAL_BLOCKED_PROCESSOR_INTERNAL_ERROR)
		CASE(IPI_WATCHDOG_TIMEOUT)
		CASE(DMA_COMMON_BUFFER_VECTOR_ERROR)
		CASE(XBOX_ERACTRL_CS_TIMEOUT)
		CASE(BC_BLUETOOTH_VERIFIER_FAULT)
		CASE(BC_BTHMINI_VERIFIER_FAULT)
		CASE(HYPERVISOR_ERROR)
		CASE(SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M)
		CASE(UNEXPECTED_KERNEL_MODE_TRAP_M)
		CASE(KERNEL_MODE_EXCEPTION_NOT_HANDLED_M)
		CASE(THREAD_STUCK_IN_DEVICE_DRIVER_M)
		CASE(THREAD_TERMINATE_HELD_MUTEX)
		CASE(STATUS_CANNOT_LOAD_REGISTRY_FILE)
		CASE(WINLOGON_FATAL_ERROR)
		CASE(STATUS_IMAGE_CHECKSUM_MISMATCH)
		CASE(MANUALLY_INITIATED_CRASH1)
	case 0:
		return "Not a crash";
	default:
		return "Unknown";
	}
	return NULL;
}
