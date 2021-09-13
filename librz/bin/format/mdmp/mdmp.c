// SPDX-FileCopyrightText: 2016-2017 Davis
// SPDX-FileCopyrightText: 2016-2017 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "mdmp.h"
// XXX: this is a random number, no idea how long it should be.
#define COMMENTS_SIZE 32

ut64 rz_bin_mdmp_get_paddr(struct rz_bin_mdmp_obj *obj, ut64 vaddr) {
	/* FIXME: Will only resolve exact matches, probably no need to fix as
	** this function will become redundant on the optimisation stage */
	struct minidump_memory_descriptor64 *memory;
	ut64 index, paddr = 0;
	RzListIter *it;

	/* Loop through the memories sections looking for a match */
	index = obj->streams.memories64.base_rva;
	rz_list_foreach (obj->streams.memories64.memories, it, memory) {
		if (vaddr == memory->start_of_memory_range) {
			paddr = index;
			break;
		}
		index += memory->data_size;
	}
	return paddr;
}

struct minidump_memory_info *rz_bin_mdmp_get_mem_info(struct rz_bin_mdmp_obj *obj, ut64 vaddr) {
	struct minidump_memory_info *mem_info;
	RzListIter *it;

	if (!obj) {
		return NULL;
	}

	rz_list_foreach (obj->streams.memory_infos, it, mem_info) {
		if (mem_info->allocation_base && vaddr == mem_info->base_address) {
			return mem_info;
		}
	}

	return NULL;
}

ut32 rz_bin_mdmp_get_perm(struct rz_bin_mdmp_obj *obj, ut64 vaddr) {
	struct minidump_memory_info *mem_info;

	if (!(mem_info = rz_bin_mdmp_get_mem_info(obj, vaddr))) {
		/* if there is no mem info in the dump, assume default permission */
		return RZ_PERM_R;
	}

	/* FIXME: Have I got these mappings right, I am not sure I have!!! */

	switch (mem_info->protect) {
	case MINIDUMP_PAGE_READONLY:
		return RZ_PERM_R;
	case MINIDUMP_PAGE_READWRITE:
		return RZ_PERM_RW;
	case MINIDUMP_PAGE_EXECUTE:
		return RZ_PERM_X;
	case MINIDUMP_PAGE_EXECUTE_READ:
		return RZ_PERM_RX;
	case MINIDUMP_PAGE_EXECUTE_READWRITE:
		return RZ_PERM_RWX;
	case MINIDUMP_PAGE_NOACCESS:
	case MINIDUMP_PAGE_WRITECOPY:
	case MINIDUMP_PAGE_EXECUTE_WRITECOPY:
	case MINIDUMP_PAGE_GUARD:
	case MINIDUMP_PAGE_NOCACHE:
	case MINIDUMP_PAGE_WRITECOMBINE:
	default:
		return 0;
	}
}

static void rz_bin_mdmp_free_pe32_bin(void *pe_bin_) {
	struct Pe32_rz_bin_mdmp_pe_bin *pe_bin = pe_bin_;
	if (pe_bin) {
		sdb_free(pe_bin->bin->kv);
		Pe32_rz_bin_pe_free(pe_bin->bin);
		RZ_FREE(pe_bin);
	}
}

static void rz_bin_mdmp_free_pe64_bin(void *pe_bin_) {
	struct Pe64_rz_bin_mdmp_pe_bin *pe_bin = pe_bin_;
	if (pe_bin) {
		sdb_free(pe_bin->bin->kv);
		Pe64_rz_bin_pe_free(pe_bin->bin);
		RZ_FREE(pe_bin);
	}
}

void rz_bin_mdmp_free(struct rz_bin_mdmp_obj *obj) {
	if (!obj) {
		return;
	}

	rz_list_free(obj->streams.ex_threads);
	rz_list_free(obj->streams.memories);
	rz_list_free(obj->streams.memories64.memories);
	rz_list_free(obj->streams.memory_infos);
	rz_list_free(obj->streams.modules);
	rz_list_free(obj->streams.operations);
	rz_list_free(obj->streams.thread_infos);
	rz_list_free(obj->streams.threads);
	rz_list_free(obj->streams.token_infos);
	rz_list_free(obj->streams.unloaded_modules);
	free(obj->streams.exception);
	free(obj->streams.system_info);
	free(obj->streams.comments_a);
	free(obj->streams.comments_w);
	free(obj->streams.handle_data);
	free(obj->streams.function_table);
	free(obj->streams.misc_info.misc_info_1);

	rz_list_free(obj->pe32_bins);
	rz_list_free(obj->pe64_bins);

	rz_buf_free(obj->b);
	free(obj->hdr);
	obj->b = NULL;
	free(obj);

	return;
}

static void rz_bin_mdmp_init_parsing(struct rz_bin_mdmp_obj *obj) {
	/* TODO: Handle unions, can we? */
	/* FIXME: Why are we getting struct missing errors when it finds them */
	sdb_set(obj->kv, "mdmp_mem_state.cparse",
		"enum mdmp_mem_state { MEM_COMMIT=0x1000, "
		"MEM_FREE=0x10000, MEM_RESERVE=0x02000 };",
		0);

	sdb_set(obj->kv, "mdmp_mem_type.cparse",
		"enum mdmp_mem_type { MEM_IMAGE=0x1000000, "
		"MEM_MAPPED=0x40000, MEM_PRIVATE=0x20000 };",
		0);

	sdb_set(obj->kv, "mdmp_page_protect.cparse",
		"enum mdmp_page_protect { PAGE_NOACCESS=1, "
		"PAGE_READONLY=2, PAGE_READWRITE=4, PAGE_WRITECOPY=8, "
		"PAGE_EXECUTE=0x10, PAGE_EXECUTE_READ=0x20, "
		"PAGE_EXECUTE_READWRITE=0x40, PAGE_EXECUTE_WRITECOPY=0x80, "
		"PAGE_GUARD=0x100, PAGE_NOCACHE=0x200, "
		"PAGE_WRITECOMBINE=0x400, PAGE_TARGETS_INVALID=0x40000000 };",
		0);

	sdb_set(obj->kv, "mdmp_misc1_flags.cparse",
		"enum mdmp_misc1_flags { MINIDUMP_MISC1_PROCESS_ID=1, "
		"MINIDUMP_MISC1_PROCESS_TIMES=2, "
		"MINIDUMP_MISC1_PROCESSOR_POWER_INFO=4 };",
		0);

	sdb_set(obj->kv, "mdmp_processor_architecture.cparse",
		"enum mdmp_processor_architecture { "
		"PROCESSOR_ARCHITECTURE_INTEL=0, "
		"PROCESSOR_ARCHITECTURE_ARM=5, "
		"PROCESSOR_ARCHITECTURE_IA64=6, "
		"PROCESSOR_ARCHITECTURE_AMD64=9, "
		"PROCESSOR_ARCHITECTURE_UNKNOWN=0xffff };",
		0);

	sdb_set(obj->kv, "mdmp_product_type.cparse",
		"enum mdmp_product_type { "
		"VER_NT_WORKSTATION=1, VER_NT_DOMAIN_CONTROLLER=2, "
		"VER_NT_SERVER=3 };",
		0);

	sdb_set(obj->kv, "mdmp_platform_id.cparse",
		"enum mdmp_platform_id { "
		"VER_PLATFORM_WIN32s=0, "
		"VER_PLATFORM_WIN32_WINDOWS=1, "
		"VER_PLATFORM_WIN32_NT=2 };",
		0);

	sdb_set(obj->kv, "mdmp_suite_mask.cparse",
		"enum mdmp_suite_mask { "
		"VER_SUITE_SMALLBUSINESS=1, VER_SUITE_ENTERPRISE=2, "
		"VER_SUITE_BACKOFFICE=4, VER_SUITE_TERMINAL=0x10, "
		"VER_SUITE_SMALLBUSINESS_RESTRICTED=0x20, "
		"VER_SUITE_EMBEDDEDNT=0x40, VER_SUITE_DATACENTER=0x80, "
		"VER_SUITE_SINGLEUSERTS=0x100, VER_SUITE_PERSONAL=0x200, "
		"VER_SUITE_BLADE=0x400, VER_SUITE_STORAGE_SERVER=0x2000, "
		"VER_SUITE_COMPUTE_SERVER=0x4000 };",
		0);

	sdb_set(obj->kv, "mdmp_callback_type.cparse",
		"enum mdmp_callback_type { ModuleCallback=0,"
		"ThreadCallback=1, ThreadExCallback=2, "
		"IncludeThreadCallback=3, IncludeModuleCallback=4, "
		"MemoryCallback=5, CancelCallback=6, "
		"WriteKernelMinidumpCallback=7, "
		"KernelMinidumpStatusCallback=8, "
		"RemoveMemoryCallback=9, "
		"IncludeVmRegionCallback=10, "
		"IoStartCallback=11, IoWriteAllCallback=12, "
		"IoFinishCallback=13, ReadMemoryFailureCallback=14, "
		"SecondaryFlagsCallback=15 };",
		0);

	sdb_set(obj->kv, "mdmp_exception_code.cparse",
		"enum mdmp_exception_code { "
		"DBG_CONTROL_C=0x40010005, "
		"EXCEPTION_GUARD_PAGE_VIOLATION=0x80000001, "
		"EXCEPTION_DATATYPE_MISALIGNMENT=0x80000002, "
		"EXCEPTION_BREAKPOINT=0x80000003, "
		"EXCEPTION_SINGLE_STEP=0x80000004, "
		"EXCEPTION_ACCESS_VIOLATION=0xc0000005, "
		"EXCEPTION_IN_PAGE_ERROR=0xc0000006, "
		"EXCEPTION_INVALID_HANDLE=0xc0000008, "
		"EXCEPTION_ILLEGAL_INSTRUCTION=0xc000001d, "
		"EXCEPTION_NONCONTINUABLE_EXCEPTION=0xc0000025, "
		"EXCEPTION_INVALID_DISPOSITION=0xc0000026, "
		"EXCEPTION_ARRAY_BOUNDS_EXCEEDED=0xc000008c, "
		"EXCEPTION_FLOAT_DENORMAL_OPERAND=0xc000008d, "
		"EXCEPTION_FLOAT_DIVIDE_BY_ZERO=0xc000008e, "
		"EXCEPTION_FLOAT_INEXACT_RESULT=0xc000008f, "
		"EXCEPTION_FLOAT_INVALID_OPERATION=0xc0000090, "
		"EXCEPTION_FLOAT_OVERFLOW=0xc0000091, "
		"EXCEPTION_FLOAT_STACK_CHECK=0xc0000092, "
		"EXCEPTION_FLOAT_UNDERFLOW=0xc0000093, "
		"EXCEPTION_INTEGER_DIVIDE_BY_ZERO=0xc0000094, "
		"EXCEPTION_INTEGER_OVERFLOW=0xc0000095, "
		"EXCEPTION_PRIVILEGED_INSTRUCTION=0xc0000096, "
		"EXCEPTION_STACK_OVERFLOW=0xc00000fd, "
		"EXCEPTION_POSSIBLE_DEADLOCK=0xc0000194 };",
		0);

	sdb_set(obj->kv, "mdmp_exception_flags.cparse",
		"enum mdmp_exception_flags { "
		"EXCEPTION_CONTINUABLE=0, "
		"EXCEPTION_NONCONTINUABLE=1 };",
		0);

	sdb_set(obj->kv, "mdmp_handle_object_information_type.cparse",
		"enum mdmp_handle_object_information_type { "
		"MiniHandleObjectInformationNone=0, "
		"MiniThreadInformation1=1, MiniMutantInformation1=2, "
		"MiniMutantInformation2=3, MiniMutantProcessInformation1=4, "
		"MiniProcessInformation2=5 };",
		0);

	sdb_set(obj->kv, "mdmp_secondary_flags.cparse",
		"enum mdmp_secondary_flags { "
		"MiniSecondaryWithoutPowerInfo=0 };",
		0);

	sdb_set(obj->kv, "mdmp_stream_type.cparse",
		"enum mdmp_stream_type { UnusedStream=0, "
		"ReservedStream0=1, ReservedStream1=2, "
		"ThreadListStream=3, ModuleListStream=4, "
		"MemoryListStream=5, ExceptionStream=6, "
		"SystemInfoStream=7, ThreadExListStream=8, "
		"Memory64ListStream=9, CommentStreamA=10, "
		"CommentStreamW=11, HandleDataStream=12, "
		"FunctionTableStream=13, UnloadedModuleListStream=14, "
		"MiscInfoStream=15, MemoryInfoListStream=16, "
		"ThreadInfoListStream=17, "
		"HandleOperationListStream=18, "
		"LastReservedStream=0xffff };",
		0);

	sdb_set(obj->kv, "mdmp_type.cparse", "enum mdmp_type { "
					     "MiniDumpNormal=0x0, "
					     "MiniDumpWithDataSegs=0x1, "
					     "MiniDumpWithFullMemory=0x2, "
					     "MiniDumpWithHandleData=0x4, "
					     "MiniDumpFilterMemory=0x8, "
					     "MiniDumpScanMemory=0x10, "
					     "MiniDumpWithUnloadedModule=0x20, "
					     "MiniDumpWihinDirectlyReferencedMemory=0x40, "
					     "MiniDumpFilterWithModulePaths=0x80,"
					     "MiniDumpWithProcessThreadData=0x100, "
					     "MiniDumpWithPrivateReadWriteMemory=0x200, "
					     "MiniDumpWithoutOptionalDate=0x400, "
					     "MiniDumpWithFullMemoryInfo=0x800, "
					     "MiniDumpWithThreadInfo=0x1000, "
					     "MiniDumpWithCodeSegs=0x2000, "
					     "MiniDumpWithoutAuxiliaryState=0x4000, "
					     "MiniDumpWithFullAuxiliaryState=0x8000, "
					     "MiniDumpWithPrivateWriteCopyMemory=0x10000, "
					     "MiniDumpIgnoreInaccessibleMemory=0x20000, "
					     "MiniDumpWithTokenInformation=0x40000, "
					     "MiniDumpWithModuleHeaders=0x80000, "
					     "MiniDumpFilterTriage=0x100000, "
					     "MiniDumpValidTypeFlags=0x1fffff };",
		0);

	sdb_set(obj->kv, "mdmp_module_write_flags.cparse",
		"enum mdmp_module_write_flags { "
		"ModuleWriteModule=0, ModuleWriteDataSeg=2, "
		"ModuleWriteMiscRecord=4, ModuleWriteCvRecord=8, "
		"ModuleReferencedByMemory=0x10, ModuleWriteTlsData=0x20, "
		"ModuleWriteCodeSegs=0x40 };",
		0);

	sdb_set(obj->kv, "mdmp_thread_write_flags.cparse",
		"enum mdmp_thread_write_flags { "
		"ThreadWriteThread=0, ThreadWriteStack=2, "
		"ThreadWriteContext=4, ThreadWriteBackingStore=8, "
		"ThreadWriteInstructionWindow=0x10, "
		"ThreadWriteThreadData=0x20, "
		"ThreadWriteThreadInfo=0x40 };",
		0);

	sdb_set(obj->kv, "mdmp_context_flags.cparse",
		"enum mdmp_context_flags { CONTEXT_i386=0x10000, "
		"CONTEXT_CONTROL=0x10001, CONTEXT_INTEGER=0x10002, "
		"CONTEXT_SEGMENTS=0x10004, CONTEXT_FLOATING_POINT=0x10008, "
		"CONTEXT_DEBUG_REGISTERS=0x10010, "
		"CONTEXT_EXTENDED_REGISTERS=0x10020 };",
		0);

	sdb_set(obj->kv, "mdmp_location_descriptor.format",
		"dd DataSize RVA", 0);
	sdb_set(obj->kv, "mdmp_location_descriptor64.format",
		"qq DataSize RVA", 0);
	sdb_set(obj->kv, "mdmp_memory_descriptor.format", "q? "
							  "StartOfMemoryRange "
							  "(mdmp_location_descriptor)Memory",
		0);
	sdb_set(obj->kv, "mdmp_memory_descriptor64.format", "qq "
							    "StartOfMemoryRange DataSize",
		0);

#if 0
	/* TODO: Flag dependent thus not fully implemented */
	sdb_set (obj->kv, "mdmp_context.format", "[4]B "
		"(mdmp_context_flags)ContextFlags", 0);
#endif

	sdb_set(obj->kv, "mdmp_vs_fixedfileinfo.format", "ddddddddddddd "
							 "dwSignature dwStrucVersion dwFileVersionMs "
							 "dwFileVersionLs dwProductVersionMs "
							 "dwProductVersionLs dwFileFlagsMask dwFileFlags "
							 "dwFileOs dwFileType dwFileSubtype dwFileDateMs "
							 "dwFileDateLs",
		0);

	sdb_set(obj->kv, "mdmp_string.format", "dZ Length Buffer", 0);
}

static bool read_hdr(RzBuffer *b, struct minidump_header *hdr) {
	st64 tmp = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (tmp < 0) {
		return false;
	}

	if (rz_buf_seek(b, 0, RZ_BUF_SET) < 0) {
		return false;
	}

	bool result = true;

	ut32 signature = 0;
	if (!rz_buf_read_le32(b, &signature)) {
		result = false;
	}
	hdr->signature = signature;

	ut32 version = 0;
	if (!rz_buf_read_le32(b, &version)) {
		result = false;
	}
	hdr->version = version;

	ut32 number_of_streams = 0;
	if (!rz_buf_read_le32(b, &number_of_streams)) {
		result = false;
	}
	hdr->number_of_streams = number_of_streams;

	ut32 stream_directory_rva = 0;
	if (!rz_buf_read_le32(b, &stream_directory_rva)) {
		result = false;
	}
	hdr->stream_directory_rva = stream_directory_rva;

	ut32 check_sum = 0;
	if (!rz_buf_read_le32(b, &check_sum)) {
		result = false;
	}
	hdr->check_sum = check_sum;

	ut32 reserved = 0;
	if (!rz_buf_read_le32(b, &reserved)) {
		result = false;
	}
	hdr->reserved = reserved;

	ut64 flags = 0;
	if (!rz_buf_read_le64(b, &flags)) {
		result = false;
	}
	hdr->flags = flags;

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return false;
	}

	return result;
}

static bool rz_bin_mdmp_init_hdr(struct rz_bin_mdmp_obj *obj) {
	obj->hdr = RZ_NEW(struct minidump_header);
	if (!obj->hdr) {
		return false;
	}
	read_hdr(obj->b, obj->hdr);

	if (obj->hdr->number_of_streams == 0) {
		eprintf("[WARN] No streams present!\n");
		return false;
	}

	if (obj->hdr->stream_directory_rva < sizeof(struct minidump_header)) {
		eprintf("[ERROR] RVA for directory resides in the header!\n");
		return false;
	}

	if (obj->hdr->check_sum) {
		eprintf("[INFO] Checksum present but needs validating!\n");
		return false;
	}

	sdb_num_set(obj->kv, "mdmp.hdr.time_date_stamp", obj->hdr->time_date_stamp, 0);
	sdb_num_set(obj->kv, "mdmp.hdr.flags", obj->hdr->flags, 0);
	sdb_num_set(obj->kv, "mdmp_header.offset", 0, 0);
	sdb_set(obj->kv, "mdmp_header.format", "[4]zddddt[8]B Signature "
					       "Version NumberOfStreams StreamDirectoryRVA CheckSum "
					       "TimeDateStamp (mdmp_type)Flags",
		0);

	return true;
}

static bool read_module_aux(RzBuffer *b, ut64 addr, struct minidump_module *module) {
	ut64 base_of_image;
	if (!rz_buf_read_le64(b, &base_of_image)) {
		return false;
	}
	module->base_of_image = base_of_image;

	ut32 size_of_image;
	if (!rz_buf_read_le32(b, &size_of_image)) {
		return false;
	}
	module->size_of_image = size_of_image;

	ut32 check_sum;
	if (!rz_buf_read_le32(b, &check_sum)) {
		return false;
	}
	module->check_sum = check_sum;

	ut32 time_date_stamp;
	if (!rz_buf_read_le32(b, &time_date_stamp)) {
		return false;
	}
	module->time_date_stamp = time_date_stamp;

	ut32 module_name_rva;
	if (!rz_buf_read_le32(b, &module_name_rva)) {
		return false;
	}
	module->module_name_rva = module_name_rva;

	ut32 dw_signature;
	if (!rz_buf_read_le32(b, &dw_signature)) {
		return false;
	}
	module->version_info.dw_signature = dw_signature;

	ut32 dw_struc_version;
	if (!rz_buf_read_le32(b, &dw_struc_version)) {
		return false;
	}
	module->version_info.dw_struc_version = dw_struc_version;

	ut32 dw_file_version_ms;
	if (!rz_buf_read_le32(b, &dw_file_version_ms)) {
		return false;
	}
	module->version_info.dw_file_version_ms = dw_file_version_ms;

	ut32 dw_file_version_ls;
	if (!rz_buf_read_le32(b, &dw_file_version_ls)) {
		return false;
	}
	module->version_info.dw_file_version_ls = dw_file_version_ls;

	ut32 dw_product_version_ms;
	if (!rz_buf_read_le32(b, &dw_product_version_ms)) {
		return false;
	}
	module->version_info.dw_product_version_ms = dw_product_version_ms;

	ut32 dw_product_version_ls;
	if (!rz_buf_read_le32(b, &dw_product_version_ls)) {
		return false;
	}
	module->version_info.dw_product_version_ls = dw_product_version_ls;

	ut32 dw_file_flags_mask;
	if (!rz_buf_read_le32(b, &dw_file_flags_mask)) {
		return false;
	}
	module->version_info.dw_file_flags_mask = dw_file_flags_mask;

	ut32 dw_file_flags;
	if (!rz_buf_read_le32(b, &dw_file_flags)) {
		return false;
	}
	module->version_info.dw_file_flags = dw_file_flags;

	ut32 dw_file_os;
	if (!rz_buf_read_le32(b, &dw_file_os)) {
		return false;
	}
	module->version_info.dw_file_os = dw_file_os;

	ut32 dw_file_type;
	if (!rz_buf_read_le32(b, &dw_file_type)) {
		return false;
	}
	module->version_info.dw_file_type = dw_file_type;

	ut32 dw_file_subtype;
	if (!rz_buf_read_le32(b, &dw_file_subtype)) {
		return false;
	}
	module->version_info.dw_file_subtype = dw_file_subtype;

	ut32 dw_file_date_ms;
	if (!rz_buf_read_le32(b, &dw_file_date_ms)) {
		return false;
	}
	module->version_info.dw_file_date_ms = dw_file_date_ms;

	ut32 dw_file_date_ls;
	if (!rz_buf_read_le32(b, &dw_file_date_ls)) {
		return false;
	}
	module->version_info.dw_file_date_ls = dw_file_date_ls;

	ut32 cv_record_data_size;
	if (!rz_buf_read_le32(b, &cv_record_data_size)) {
		return false;
	}
	module->cv_record.data_size = cv_record_data_size;

	ut32 cv_record_rva;
	if (!rz_buf_read_le32(b, &cv_record_rva)) {
		return false;
	}
	module->cv_record.rva = cv_record_rva;

	ut32 misc_record_data_size;
	if (!rz_buf_read_le32(b, &misc_record_data_size)) {
		return false;
	}
	module->misc_record.data_size = misc_record_data_size;

	ut32 misc_record_rva;
	if (!rz_buf_read_le32(b, &misc_record_rva)) {
		return false;
	}
	module->misc_record.rva = misc_record_rva;

	ut64 reserved_0;
	if (!rz_buf_read_le64(b, &reserved_0)) {
		return false;
	}
	module->reserved_0 = reserved_0;

	ut64 reserved_1;
	if (!rz_buf_read_le64(b, &reserved_1)) {
		return false;
	}
	module->reserved_1 = reserved_1;

	return true;
}

static bool read_module(RzBuffer *b, ut64 addr, struct minidump_module *module) {
	st64 tmp = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (tmp < 0) {
		return false;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return false;
	}

	bool result = read_module_aux(b, addr, module);

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return false;
	}

	return result;
}

static bool read_memory64_list(RzBuffer *b, ut64 addr, struct minidump_memory64_list *memory64_list) {
	st64 tmp = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (tmp < 0) {
		return false;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return false;
	}

	ut64 number_of_memory_ranges;
	if (!rz_buf_read_le64(b, &number_of_memory_ranges)) {
		return false;
	}
	memory64_list->number_of_memory_ranges = number_of_memory_ranges;

	ut64 base_rva;
	if (!rz_buf_read_le64(b, &base_rva)) {
		return false;
	}
	memory64_list->base_rva = base_rva;

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return false;
	}

	return true;
}

static bool read_desc(RzBuffer *b, ut64 addr, struct minidump_memory_descriptor64 *desc) {
	st64 tmp = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (tmp < 0) {
		return false;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return false;
	}

	ut64 start_of_memory_range;
	if (!rz_buf_read_le64(b, &start_of_memory_range)) {
		return false;
	}
	desc->start_of_memory_range = start_of_memory_range;

	ut64 data_size;
	if (!rz_buf_read_le64(b, &data_size)) {
		return false;
	}
	desc->data_size = data_size;

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return false;
	}

	return true;
}

static bool rz_bin_mdmp_init_directory_entry(struct rz_bin_mdmp_obj *obj, struct minidump_directory *entry) {
	struct minidump_handle_operation_list handle_operation_list;
	struct minidump_memory_list memory_list;
	struct minidump_memory64_list memory64_list;
	struct minidump_memory_info_list memory_info_list;
	struct minidump_module_list module_list;
	struct minidump_thread_list thread_list;
	struct minidump_thread_ex_list thread_ex_list;
	struct minidump_thread_info_list thread_info_list;
	struct minidump_token_info_list token_info_list;
	struct minidump_unloaded_module_list unloaded_module_list;
	ut64 offset;
	int i, r;

	/* We could confirm data sizes but a malcious MDMP will always get around
	** this! But we can ensure that the data is not outside of the file */
	if ((ut64)entry->location.rva + entry->location.data_size > rz_buf_size(obj->b)) {
		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
		return false;
	}

	ut32 number_of_modules;

	switch (entry->stream_type) {
	case THREAD_LIST_STREAM:
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&thread_list, sizeof(thread_list));
		if (r != sizeof(thread_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread.format", "ddddq?? "
						       "ThreadId SuspendCount PriorityClass Priority "
						       "Teb (mdmp_memory_descriptor)Stack "
						       "(mdmp_location_descriptor)ThreadContext",
			0);
		sdb_num_set(obj->kv, "mdmp_thread_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_thread_list.format",
			sdb_fmt("d[%d]? "
				"NumberOfThreads (mdmp_thread)Threads",
				thread_list.number_of_threads),
			0);

		/* TODO: Not yet fully parsed or utilised */
		break;
	case MODULE_LIST_STREAM:
		if (!rz_buf_read_le32_at(obj->b, entry->location.rva, &number_of_modules)) {
			break;
		}
		module_list.number_of_modules = number_of_modules;

		sdb_set(obj->kv, "mdmp_module.format", "qddtd???qq "
						       "BaseOfImage SizeOfImage CheckSum "
						       "TimeDateStamp ModuleNameRVA "
						       "(mdmp_vs_fixedfileinfo)VersionInfo "
						       "(mdmp_location_descriptor)CvRecord "
						       "(mdmp_location_descriptor)MiscRecord "
						       "Reserved0 Reserved1",
			0);
		sdb_num_set(obj->kv, "mdmp_module_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_module_list.format",
			sdb_fmt("d[%d]? "
				"NumberOfModule (mdmp_module)Modules",
				module_list.number_of_modules),
			0);

		offset = entry->location.rva + sizeof(module_list);
		for (i = 0; i < module_list.number_of_modules; i++) {
			struct minidump_module *module = RZ_NEW(struct minidump_module);
			if (!module) {
				break;
			}
			if (!read_module(obj->b, offset, module)) {
				break;
			}
			rz_list_append(obj->streams.modules, module);
			offset += sizeof(*module);
		}
		break;
	case MEMORY_LIST_STREAM:
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&memory_list, sizeof(memory_list));
		if (r != sizeof(memory_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_memory_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_memory_list.format",
			sdb_fmt("d[%d]? "
				"NumberOfMemoryRanges "
				"(mdmp_memory_descriptor)MemoryRanges ",
				memory_list.number_of_memory_ranges),
			0);

		offset = entry->location.rva + sizeof(memory_list);
		for (i = 0; i < memory_list.number_of_memory_ranges; i++) {
			struct minidump_memory_descriptor *desc = RZ_NEW(struct minidump_memory_descriptor);
			if (!desc) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)desc, sizeof(*desc));
			if (r != sizeof(*desc)) {
				break;
			}
			rz_list_append(obj->streams.memories, desc);
			offset += sizeof(*desc);
		}
		break;
	case EXCEPTION_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.exception = RZ_NEW(struct minidump_exception_stream);
		if (!obj->streams.exception) {
			break;
		}

		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)obj->streams.exception, sizeof(*obj->streams.exception));
		if (r != sizeof(*obj->streams.exception)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_exception.format", "[4]E[4]Eqqdd[15]q "
							  "(mdmp_exception_code)ExceptionCode "
							  "(mdmp_exception_flags)ExceptionFlags "
							  "ExceptionRecord ExceptionAddress "
							  "NumberParameters __UnusedAlignment "
							  "ExceptionInformation",
			0);
		sdb_num_set(obj->kv, "mdmp_exception_stream.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_exception_stream.format", "dd?? "
								 "ThreadId __Alignment "
								 "(mdmp_exception)ExceptionRecord "
								 "(mdmp_location_descriptor)ThreadContext",
			0);

		break;
	case SYSTEM_INFO_STREAM:
		obj->streams.system_info = RZ_NEW(struct minidump_system_info);
		if (!obj->streams.system_info) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)obj->streams.system_info, sizeof(*obj->streams.system_info));
		if (r != sizeof(*obj->streams.system_info)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_system_info.offset",
			entry->location.rva, 0);
		/* TODO: We need E as a byte! */
		sdb_set(obj->kv, "mdmp_system_info.format", "[2]EwwbBddd[4]Ed[2]Ew[2]q "
							    "(mdmp_processor_architecture)ProcessorArchitecture "
							    "ProcessorLevel ProcessorRevision NumberOfProcessors "
							    "(mdmp_product_type)ProductType "
							    "MajorVersion MinorVersion BuildNumber (mdmp_platform_id)PlatformId "
							    "CsdVersionRva (mdmp_suite_mask)SuiteMask Reserved2 ProcessorFeatures",
			0);

		break;
	case THREAD_EX_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&thread_ex_list, sizeof(thread_ex_list));
		if (r != sizeof(thread_ex_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread_ex.format", "ddddq??? "
							  "ThreadId SuspendCount PriorityClass Priority "
							  "Teb (mdmp_memory_descriptor)Stack "
							  "(mdmp_location_descriptor)ThreadContext "
							  "(mdmp_memory_descriptor)BackingStore",
			0);
		sdb_num_set(obj->kv, "mdmp_thread_ex_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_thread_ex_list.format",
			sdb_fmt("d[%d]? NumberOfThreads "
				"(mdmp_thread_ex)Threads",
				thread_ex_list.number_of_threads),
			0);

		offset = entry->location.rva + sizeof(thread_ex_list);
		for (i = 0; i < thread_ex_list.number_of_threads; i++) {
			struct minidump_thread_ex *thread = RZ_NEW(struct minidump_thread_ex);
			if (!thread) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)thread, sizeof(*thread));
			if (r != sizeof(*thread)) {
				break;
			}
			rz_list_append(obj->streams.ex_threads, thread);
			offset += sizeof(*thread);
		}
		break;
	case MEMORY_64_LIST_STREAM:
		if (!read_memory64_list(obj->b, entry->location.rva, &memory64_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_memory64_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_memory64_list.format",
			sdb_fmt("qq[%" PFMT64d "]? NumberOfMemoryRanges "
				"BaseRva "
				"(mdmp_memory_descriptor64)MemoryRanges",
				memory64_list.number_of_memory_ranges),
			0);

		obj->streams.memories64.base_rva = memory64_list.base_rva;
		offset = entry->location.rva + sizeof(memory64_list);
		for (i = 0; i < memory64_list.number_of_memory_ranges; i++) {
			struct minidump_memory_descriptor64 *desc = RZ_NEW(struct minidump_memory_descriptor64);
			if (!desc) {
				break;
			}
			read_desc(obj->b, offset, desc);
			rz_list_append(obj->streams.memories64.memories, desc);
			offset += sizeof(*desc);
		}
		break;
	case COMMENT_STREAM_A:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_a = RZ_NEWS(ut8, COMMENTS_SIZE);
		if (!obj->streams.comments_a) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, obj->streams.comments_a, COMMENTS_SIZE);
		if (r != COMMENTS_SIZE) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_comment_stream_a.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_comment_stream_a.format",
			"s CommentA", 0);

		break;
	case COMMENT_STREAM_W:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.comments_w = RZ_NEWS(ut8, COMMENTS_SIZE);
		if (!obj->streams.comments_w) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, obj->streams.comments_w, COMMENTS_SIZE);
		if (r != COMMENTS_SIZE) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_comment_stream_w.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_comment_stream_w.format",
			"s CommentW", 0);

		break;
	case HANDLE_DATA_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.handle_data = RZ_NEW(struct minidump_handle_data_stream);
		if (!obj->streams.handle_data) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)obj->streams.handle_data, sizeof(*obj->streams.handle_data));
		if (r != sizeof(*obj->streams.handle_data)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_handle_data_stream.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_handle_data_stream.format", "dddd "
								   "SizeOfHeader SizeOfDescriptor "
								   "NumberOfDescriptors Reserved",
			0);
		break;
	case FUNCTION_TABLE_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.function_table = RZ_NEW(struct minidump_function_table_stream);
		if (!obj->streams.function_table) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)obj->streams.function_table, sizeof(*obj->streams.function_table));
		if (r != sizeof(*obj->streams.function_table)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_function_table_stream.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_function_table_stream.format", "dddddd "
								      "SizeOfHeader SizeOfDescriptor SizeOfNativeDescriptor "
								      "SizeOfFunctionEntry NumberOfDescriptors SizeOfAlignPad",
			0);
		break;
	case UNLOADED_MODULE_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&unloaded_module_list, sizeof(unloaded_module_list));
		if (r != sizeof(unloaded_module_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_unloaded_module.format", "qddtd "
								"BaseOfImage SizeOfImage CheckSum TimeDateStamp "
								"ModuleNameRva",
			0);
		sdb_num_set(obj->kv, "mdmp_unloaded_module_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_unloaded_module_list.format", "ddd "
								     "SizeOfHeader SizeOfEntry NumberOfEntries",
			0);

		offset = entry->location.rva + sizeof(unloaded_module_list);
		for (i = 0; i < unloaded_module_list.number_of_entries; i++) {
			struct minidump_unloaded_module *module = RZ_NEW(struct minidump_unloaded_module);
			if (!module) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)module, sizeof(*module));
			if (r != sizeof(*module)) {
				break;
			}
			rz_list_append(obj->streams.unloaded_modules, module);
			offset += sizeof(*module);
		}
		break;
	case MISC_INFO_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.misc_info.misc_info_1 = RZ_NEW(struct minidump_misc_info);
		if (!obj->streams.misc_info.misc_info_1) {
			break;
		}
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)obj->streams.misc_info.misc_info_1, sizeof(*obj->streams.misc_info.misc_info_1));
		if (r != sizeof(*obj->streams.misc_info.misc_info_1)) {
			break;
		}

		/* TODO: Handle different sizes */
		sdb_num_set(obj->kv, "mdmp_misc_info.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_misc_info.format", "d[4]Bdtttddddd "
							  "SizeOfInfo (mdmp_misc1_flags)Flags1 ProcessId "
							  "ProcessCreateTime ProcessUserTime ProcessKernelTime "
							  "ProcessorMaxMhz ProcessorCurrentMhz "
							  "ProcessorMhzLimit ProcessorMaxIdleState "
							  "ProcessorCurrentIdleState",
			0);

		break;
	case MEMORY_INFO_LIST_STREAM:
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&memory_info_list, sizeof(memory_info_list));
		if (r != sizeof(memory_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_memory_info.format",
			"qq[4]Edq[4]E[4]E[4]Ed BaseAddress AllocationBase "
			"(mdmp_page_protect)AllocationProtect __Alignment1 RegionSize "
			"(mdmp_mem_state)State (mdmp_page_protect)Protect "
			"(mdmp_mem_type)Type __Alignment2",
			0);
		sdb_num_set(obj->kv, "mdmp_memory_info_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_memory_info_list.format",
			sdb_fmt("ddq[%" PFMT64d "]? SizeOfHeader SizeOfEntry "
				"NumberOfEntries (mdmp_memory_info)MemoryInfo",
				memory_info_list.number_of_entries),
			0);

		offset = entry->location.rva + sizeof(memory_info_list);
		for (i = 0; i < memory_info_list.number_of_entries; i++) {
			struct minidump_memory_info *info = RZ_NEW(struct minidump_memory_info);
			if (!info) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)info, sizeof(*info));
			if (r != sizeof(*info)) {
				break;
			}
			rz_list_append(obj->streams.memory_infos, info);
			offset += sizeof(*info);
		}
		break;
	case THREAD_INFO_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&thread_info_list, sizeof(thread_info_list));
		if (r != sizeof(thread_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread_info.format", "ddddttttqq "
							    "ThreadId DumpFlags DumpError ExitStatus CreateTime "
							    "ExitTime KernelTime UserTime StartAddress Affinity",
			0);
		sdb_num_set(obj->kv, "mdmp_thread_info_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_thread_info_list.format", "ddd "
								 "SizeOfHeader SizeOfEntry NumberOfEntries",
			0);

		offset = entry->location.rva + sizeof(thread_info_list);
		for (i = 0; i < thread_info_list.number_of_entries; i++) {
			struct minidump_thread_info *info = RZ_NEW(struct minidump_thread_info);
			if (!info) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)info, sizeof(*info));
			if (r != sizeof(*info)) {
				break;
			}
			rz_list_append(obj->streams.thread_infos, info);
			offset += sizeof(*info);
		}
		break;
	case HANDLE_OPERATION_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&handle_operation_list, sizeof(handle_operation_list));
		if (r != sizeof(handle_operation_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_handle_operation_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_handle_operation_list.format", "dddd "
								      "SizeOfHeader SizeOfEntry NumberOfEntries Reserved",
			0);

		offset = entry->location.rva + sizeof(handle_operation_list);
		for (i = 0; i < handle_operation_list.number_of_entries; i++) {
			struct avrf_handle_operation *op = RZ_NEW(struct avrf_handle_operation);
			if (!op) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)op, sizeof(*op));
			if (r != sizeof(*op)) {
				break;
			}
			rz_list_append(obj->streams.operations, op);
			offset += sizeof(*op);
		}

		break;
	case TOKEN_STREAM:
		/* TODO: Not fully parsed or utilised */
		r = rz_buf_read_at(obj->b, entry->location.rva, (ut8 *)&token_info_list, sizeof(token_info_list));
		if (r != sizeof(token_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_token_info.format", "ddq "
							   "TokenSize TokenId TokenHandle",
			0);

		sdb_num_set(obj->kv, "mdmp_token_info_list.offset",
			entry->location.rva, 0);
		sdb_set(obj->kv, "mdmp_token_info_list.format", "dddd "
								"TokenListSize TokenListEntries ListHeaderSize ElementHeaderSize",
			0);

		offset = entry->location.rva + sizeof(token_info_list);
		for (i = 0; i < token_info_list.number_of_entries; i++) {
			struct minidump_token_info *info = RZ_NEW(struct minidump_token_info);
			if (!info) {
				break;
			}
			r = rz_buf_read_at(obj->b, offset, (ut8 *)info, sizeof(*info));
			if (r != sizeof(*info)) {
				break;
			}
			rz_list_append(obj->streams.token_infos, info);
			offset += sizeof(*info);
		}
		break;

	case LAST_RESERVED_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		break;
	case UNUSED_STREAM:
	case RESERVED_STREAM_0:
	case RESERVED_STREAM_1:
		/* Silently ignore reserved streams */
		break;
	default:
		eprintf("[WARN] Invalid or unsupported enumeration encountered %d\n", entry->stream_type);
		break;
	}
	return true;
}

static bool read_entry(RzBuffer *b, ut64 addr, struct minidump_directory *entry) {
	st64 tmp = rz_buf_seek(b, 0, RZ_BUF_CUR);
	if (tmp < 0) {
		return false;
	}

	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return false;
	}

	ut32 stream_type;
	if (!rz_buf_read_le32(b, &stream_type)) {
		return false;
	}
	entry->stream_type = stream_type;

	ut32 data_size;
	if (!rz_buf_read_le32(b, &data_size)) {
		return false;
	}
	entry->location.data_size = data_size;

	ut32 rva;
	if (!rz_buf_read_le32(b, &rva)) {
		return false;
	}
	entry->location.rva = rva;

	if (rz_buf_seek(b, tmp, RZ_BUF_SET) < 0) {
		return false;
	}

	return true;
}

static bool rz_bin_mdmp_init_directory(struct rz_bin_mdmp_obj *obj) {
	ut32 i;
	struct minidump_directory entry;

	sdb_num_set(obj->kv, "mdmp_directory.offset",
		obj->hdr->stream_directory_rva, 0);
	sdb_set(obj->kv, "mdmp_directory.format", "[4]E? "
						  "(mdmp_stream_type)StreamType "
						  "(mdmp_location_descriptor)Location",
		0);

	ut64 rvadir = obj->hdr->stream_directory_rva;
	ut64 bytes_left = rvadir < obj->size ? obj->size - rvadir : 0;
	size_t max_entries = RZ_MIN(obj->hdr->number_of_streams, bytes_left / sizeof(struct minidump_directory));
	if (max_entries < obj->hdr->number_of_streams) {
		eprintf("[ERROR] Number of streams = %u is greater than is supportable by bin size\n",
			obj->hdr->number_of_streams);
	}
	/* Parse each entry in the directory */
	for (i = 0; i < max_entries; i++) {
		ut32 delta = i * sizeof(struct minidump_directory);
		if (read_entry(obj->b, rvadir + delta, &entry)) {
			if (!rz_bin_mdmp_init_directory_entry(obj, &entry)) {
				return false;
			}
		}
	}

	return true;
}

static bool rz_bin_mdmp_patch_pe_headers(RzBuffer *pe_buf) {
	int i;
	Pe64_image_dos_header dos_hdr;
	Pe64_image_nt_headers nt_hdr;

	Pe64_read_dos_header(pe_buf, &dos_hdr);
	Pe64_read_nt_headers(pe_buf, dos_hdr.e_lfanew, &nt_hdr);

	/* Patch RawData in headers */
	ut64 sect_hdrs_off = dos_hdr.e_lfanew + 4 + sizeof(Pe64_image_file_header) + nt_hdr.file_header.SizeOfOptionalHeader;
	Pe64_image_section_header section_hdr;
	for (i = 0; i < nt_hdr.file_header.NumberOfSections; i++) {
		Pe64_read_image_section_header(pe_buf, sect_hdrs_off + i * sizeof(section_hdr), &section_hdr);
		section_hdr.PointerToRawData = section_hdr.VirtualAddress;
		Pe64_write_image_section_header(pe_buf, sect_hdrs_off + i * sizeof(section_hdr), &section_hdr);
	}

	return true;
}

static int check_pe32_buf(RzBuffer *buf, ut64 length) {
	unsigned int idx;
	if (!buf || length <= 0x3d) {
		return false;
	}

	ut8 tmp1;
	if (!rz_buf_read8_at(buf, 0x3c, &tmp1)) {
		return false;
	}

	ut8 tmp2;
	if (!rz_buf_read8_at(buf, 0x3d, &tmp2)) {
		return false;
	}

	idx = tmp1 | (tmp2 << 8);

	if (length > idx + 0x18 + 2) {
		ut8 tmp1[2], tmp2[2], tmp3[2];
		rz_buf_read_at(buf, 0, tmp1, 2);
		rz_buf_read_at(buf, idx, tmp2, 2);
		rz_buf_read_at(buf, idx + 0x18, tmp3, 2);
		if (!memcmp(tmp1, "MZ", 2) && !memcmp(tmp2, "PE", 2) && !memcmp(tmp3, "\x0b\x01", 2)) {
			return true;
		}
	}

	return false;
}

static int check_pe64_buf(RzBuffer *buf, ut64 length) {
	int idx, ret = false;
	if (!buf || length <= 0x3d) {
		return false;
	}

	ut8 tmp1;
	if (!rz_buf_read8_at(buf, 0x3c, &tmp1)) {
		return false;
	}

	ut8 tmp2;
	if (!rz_buf_read8_at(buf, 0x3d, &tmp2)) {
		return false;
	}

	idx = tmp1 | (tmp2 << 8);

	if (length >= idx + 0x20) {
		ut8 tmp1[2], tmp2[2], tmp3[2];
		rz_buf_read_at(buf, 0, tmp1, 2);
		rz_buf_read_at(buf, idx, tmp2, 2);
		rz_buf_read_at(buf, idx + 0x18, tmp3, 2);
		if (!memcmp(tmp1, "MZ", 2) && !memcmp(tmp2, "PE", 2) && !memcmp(tmp3, "\x0b\x02", 2)) {
			ret = true;
		}
	}
	return ret;
}

static bool rz_bin_mdmp_init_pe_bins(struct rz_bin_mdmp_obj *obj) {
	bool dup;
	ut64 paddr;
	struct minidump_module *module;
	struct Pe32_rz_bin_mdmp_pe_bin *pe32_bin, *pe32_dup;
	struct Pe64_rz_bin_mdmp_pe_bin *pe64_bin, *pe64_dup;
	RzBuffer *buf;
	RzListIter *it, *it_dup;

	rz_list_foreach (obj->streams.modules, it, module) {
		/* Duplicate modules can appear in the MDMP module list,
		** filtering them out seems to be the correct behaviour */
		if (!(paddr = rz_bin_mdmp_get_paddr(obj, module->base_of_image))) {
			continue;
		}
		ut8 *b = RZ_NEWS(ut8, module->size_of_image);
		if (!b) {
			continue;
		}
		int r = rz_buf_read_at(obj->b, paddr, b, module->size_of_image);
		buf = rz_buf_new_with_bytes(b, r);
		dup = false;
		if (check_pe32_buf(buf, module->size_of_image)) {
			rz_list_foreach (obj->pe32_bins, it_dup, pe32_dup) {
				if (pe32_dup->vaddr == module->base_of_image) {
					dup = true;
					continue;
				}
			}
			if (dup) {
				continue;
			}
			if (!(pe32_bin = RZ_NEW0(struct Pe32_rz_bin_mdmp_pe_bin))) {
				continue;
			}
			rz_bin_mdmp_patch_pe_headers(buf);
			pe32_bin->vaddr = module->base_of_image;
			pe32_bin->paddr = paddr;
			pe32_bin->bin = Pe32_rz_bin_pe_new_buf(buf, 0);

			rz_list_append(obj->pe32_bins, pe32_bin);
		} else if (check_pe64_buf(buf, module->size_of_image)) {
			rz_list_foreach (obj->pe64_bins, it_dup, pe64_dup) {
				if (pe64_dup->vaddr == module->base_of_image) {
					dup = true;
					continue;
				}
			}
			if (dup) {
				continue;
			}
			if (!(pe64_bin = RZ_NEW0(struct Pe64_rz_bin_mdmp_pe_bin))) {
				continue;
			}
			rz_bin_mdmp_patch_pe_headers(buf);
			pe64_bin->vaddr = module->base_of_image;
			pe64_bin->paddr = paddr;
			pe64_bin->bin = Pe64_rz_bin_pe_new_buf(buf, 0);

			rz_list_append(obj->pe64_bins, pe64_bin);
		}
		rz_buf_free(buf);
	}
	return true;
}

static int rz_bin_mdmp_init(struct rz_bin_mdmp_obj *obj) {
	rz_bin_mdmp_init_parsing(obj);

	if (!rz_bin_mdmp_init_hdr(obj)) {
		eprintf("[ERROR] Failed to initialise header\n");
		return false;
	}

	if (!rz_bin_mdmp_init_directory(obj)) {
		eprintf("[ERROR] Failed to initialise directory structures!\n");
		return false;
	}

	if (!rz_bin_mdmp_init_pe_bins(obj)) {
		eprintf("[ERROR] Failed to initialise pe binaries!\n");
		return false;
	}

	return true;
}

struct rz_bin_mdmp_obj *rz_bin_mdmp_new_buf(RzBuffer *buf) {
	bool fail = false;
	struct rz_bin_mdmp_obj *obj = RZ_NEW0(struct rz_bin_mdmp_obj);
	if (!obj) {
		return NULL;
	}
	obj->kv = sdb_new0();
	obj->size = (ut32)rz_buf_size(buf);

	fail |= (!(obj->streams.ex_threads = rz_list_new()));
	fail |= (!(obj->streams.memories = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.memories64.memories = rz_list_new()));
	fail |= (!(obj->streams.memory_infos = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.modules = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.operations = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.thread_infos = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.token_infos = rz_list_newf((RzListFree)free)));
	fail |= (!(obj->streams.threads = rz_list_new()));
	fail |= (!(obj->streams.unloaded_modules = rz_list_newf((RzListFree)free)));

	fail |= (!(obj->pe32_bins = rz_list_newf(rz_bin_mdmp_free_pe32_bin)));
	fail |= (!(obj->pe64_bins = rz_list_newf(rz_bin_mdmp_free_pe64_bin)));

	if (fail) {
		rz_bin_mdmp_free(obj);
		return NULL;
	}

	obj->b = rz_buf_ref(buf);
	if (!rz_bin_mdmp_init(obj)) {
		rz_bin_mdmp_free(obj);
		return NULL;
	}

	return obj;
}
