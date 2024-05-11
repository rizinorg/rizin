// SPDX-FileCopyrightText: 2016-2017 Davis
// SPDX-FileCopyrightText: 2016-2017 Alex Kornitzer <alex.kornitzer@countercept.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#include "mdmp.h"
// XXX: this is a random number, no idea how long it should be.
#define COMMENTS_SIZE 32

ut64 rz_bin_mdmp_get_paddr(MiniDmpObj *obj, ut64 vaddr) {
	/* FIXME: Will only resolve exact matches, probably no need to fix as
	** this function will become redundant on the optimisation stage */
	MiniDmpMemDescr64 *memory;
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

MiniDmpMemInfo *rz_bin_mdmp_get_mem_info(MiniDmpObj *obj, ut64 vaddr) {
	MiniDmpMemInfo *mem_info;
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

ut32 rz_bin_mdmp_get_perm(MiniDmpObj *obj, ut64 vaddr) {
	MiniDmpMemInfo *mem_info;

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

static void rz_bin_mdmp_free_pe32_bin(struct Pe32_rz_bin_mdmp_pe_bin *pe_bin) {
	if (!pe_bin) {
		return;
	}
	if (pe_bin->bin) {
		sdb_free(pe_bin->bin->kv);
		Pe32_rz_bin_pe_free(pe_bin->bin);
	}
	free(pe_bin);
}

static void rz_bin_mdmp_free_pe64_bin(struct Pe64_rz_bin_mdmp_pe_bin *pe_bin) {
	if (!pe_bin) {
		return;
	}
	if (pe_bin->bin) {
		sdb_free(pe_bin->bin->kv);
		Pe64_rz_bin_pe_free(pe_bin->bin);
	}
	free(pe_bin);
}

void rz_bin_mdmp_free(MiniDmpObj *obj) {
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

static void mdmp_obj_sdb_init(MiniDmpObj *obj) {
	/* TODO: Handle unions, can we? */
	/* FIXME: Why are we getting struct missing errors when it finds them */
	sdb_set(obj->kv, "mdmp_mem_state.cparse",
		"enum mdmp_mem_state { MEM_COMMIT=0x1000, "
		"MEM_FREE=0x10000, MEM_RESERVE=0x02000 };");

	sdb_set(obj->kv, "mdmp_mem_type.cparse",
		"enum mdmp_mem_type { MEM_IMAGE=0x1000000, "
		"MEM_MAPPED=0x40000, MEM_PRIVATE=0x20000 };");

	sdb_set(obj->kv, "mdmp_page_protect.cparse",
		"enum mdmp_page_protect { PAGE_NOACCESS=1, "
		"PAGE_READONLY=2, PAGE_READWRITE=4, PAGE_WRITECOPY=8, "
		"PAGE_EXECUTE=0x10, PAGE_EXECUTE_READ=0x20, "
		"PAGE_EXECUTE_READWRITE=0x40, PAGE_EXECUTE_WRITECOPY=0x80, "
		"PAGE_GUARD=0x100, PAGE_NOCACHE=0x200, "
		"PAGE_WRITECOMBINE=0x400, PAGE_TARGETS_INVALID=0x40000000 };");

	sdb_set(obj->kv, "mdmp_misc1_flags.cparse",
		"enum mdmp_misc1_flags { MINIDUMP_MISC1_PROCESS_ID=1, "
		"MINIDUMP_MISC1_PROCESS_TIMES=2, "
		"MINIDUMP_MISC1_PROCESSOR_POWER_INFO=4 };");

	sdb_set(obj->kv, "mdmp_processor_architecture.cparse",
		"enum mdmp_processor_architecture { "
		"PROCESSOR_ARCHITECTURE_INTEL=0, "
		"PROCESSOR_ARCHITECTURE_ARM=5, "
		"PROCESSOR_ARCHITECTURE_IA64=6, "
		"PROCESSOR_ARCHITECTURE_AMD64=9, "
		"PROCESSOR_ARCHITECTURE_UNKNOWN=0xffff };");

	sdb_set(obj->kv, "mdmp_product_type.cparse",
		"enum mdmp_product_type { "
		"VER_NT_WORKSTATION=1, VER_NT_DOMAIN_CONTROLLER=2, "
		"VER_NT_SERVER=3 };");

	sdb_set(obj->kv, "mdmp_platform_id.cparse",
		"enum mdmp_platform_id { "
		"VER_PLATFORM_WIN32s=0, "
		"VER_PLATFORM_WIN32_WINDOWS=1, "
		"VER_PLATFORM_WIN32_NT=2 };");

	sdb_set(obj->kv, "mdmp_suite_mask.cparse",
		"enum mdmp_suite_mask { "
		"VER_SUITE_SMALLBUSINESS=1, VER_SUITE_ENTERPRISE=2, "
		"VER_SUITE_BACKOFFICE=4, VER_SUITE_TERMINAL=0x10, "
		"VER_SUITE_SMALLBUSINESS_RESTRICTED=0x20, "
		"VER_SUITE_EMBEDDEDNT=0x40, VER_SUITE_DATACENTER=0x80, "
		"VER_SUITE_SINGLEUSERTS=0x100, VER_SUITE_PERSONAL=0x200, "
		"VER_SUITE_BLADE=0x400, VER_SUITE_STORAGE_SERVER=0x2000, "
		"VER_SUITE_COMPUTE_SERVER=0x4000 };");

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
		"SecondaryFlagsCallback=15 };");

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
		"EXCEPTION_POSSIBLE_DEADLOCK=0xc0000194 };");

	sdb_set(obj->kv, "mdmp_exception_flags.cparse",
		"enum mdmp_exception_flags { "
		"EXCEPTION_CONTINUABLE=0, "
		"EXCEPTION_NONCONTINUABLE=1 };");

	sdb_set(obj->kv, "mdmp_handle_object_information_type.cparse",
		"enum mdmp_handle_object_information_type { "
		"MiniHandleObjectInformationNone=0, "
		"MiniThreadInformation1=1, MiniMutantInformation1=2, "
		"MiniMutantInformation2=3, MiniMutantProcessInformation1=4, "
		"MiniProcessInformation2=5 };");

	sdb_set(obj->kv, "mdmp_secondary_flags.cparse",
		"enum mdmp_secondary_flags { "
		"MiniSecondaryWithoutPowerInfo=0 };");

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
		"LastReservedStream=0xffff };");

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
					     "MiniDumpValidTypeFlags=0x1fffff };");

	sdb_set(obj->kv, "mdmp_module_write_flags.cparse",
		"enum mdmp_module_write_flags { "
		"ModuleWriteModule=0, ModuleWriteDataSeg=2, "
		"ModuleWriteMiscRecord=4, ModuleWriteCvRecord=8, "
		"ModuleReferencedByMemory=0x10, ModuleWriteTlsData=0x20, "
		"ModuleWriteCodeSegs=0x40 };");

	sdb_set(obj->kv, "mdmp_thread_write_flags.cparse",
		"enum mdmp_thread_write_flags { "
		"ThreadWriteThread=0, ThreadWriteStack=2, "
		"ThreadWriteContext=4, ThreadWriteBackingStore=8, "
		"ThreadWriteInstructionWindow=0x10, "
		"ThreadWriteThreadData=0x20, "
		"ThreadWriteThreadInfo=0x40 };");

	sdb_set(obj->kv, "mdmp_context_flags.cparse",
		"enum mdmp_context_flags { CONTEXT_i386=0x10000, "
		"CONTEXT_CONTROL=0x10001, CONTEXT_INTEGER=0x10002, "
		"CONTEXT_SEGMENTS=0x10004, CONTEXT_FLOATING_POINT=0x10008, "
		"CONTEXT_DEBUG_REGISTERS=0x10010, "
		"CONTEXT_EXTENDED_REGISTERS=0x10020 };");

	sdb_set(obj->kv, "mdmp_location_descriptor.format",
		"dd DataSize RVA");
	sdb_set(obj->kv, "mdmp_location_descriptor64.format",
		"qq DataSize RVA");
	sdb_set(obj->kv, "mdmp_memory_descriptor.format", "q? "
							  "StartOfMemoryRange "
							  "(mdmp_location_descriptor)Memory");
	sdb_set(obj->kv, "mdmp_memory_descriptor64.format", "qq "
							    "StartOfMemoryRange DataSize");

#if 0
	/* TODO: Flag dependent thus not fully implemented */
	sdb_set (obj->kv, "mdmp_context.format", "[4]B "
		"(mdmp_context_flags)ContextFlags");
#endif

	sdb_set(obj->kv, "mdmp_vs_fixedfileinfo.format", "ddddddddddddd "
							 "dwSignature dwStrucVersion dwFileVersionMs "
							 "dwFileVersionLs dwProductVersionMs "
							 "dwProductVersionLs dwFileFlagsMask dwFileFlags "
							 "dwFileOs dwFileType dwFileSubtype dwFileDateMs "
							 "dwFileDateLs");

	sdb_set(obj->kv, "mdmp_string.format", "dZ Length Buffer");
}

static bool mdmp_read_header(RzBuffer *b, MiniDmpHeader *hdr) {
	ut64 offset = 0;
	return rz_buf_read_le32_offset(b, &offset, &hdr->signature) &&
		rz_buf_read_le32_offset(b, &offset, &hdr->version) &&
		rz_buf_read_le32_offset(b, &offset, &hdr->number_of_streams) &&
		rz_buf_read_le32_offset(b, &offset, &hdr->stream_directory_rva) &&
		rz_buf_read_le32_offset(b, &offset, &hdr->check_sum) &&
		rz_buf_read_le32_offset(b, &offset, &hdr->reserved) &&
		rz_buf_read_le64_offset(b, &offset, &hdr->flags);
}

static bool rz_bin_mdmp_init_hdr(MiniDmpObj *obj) {
	obj->hdr = RZ_NEW(MiniDmpHeader);
	if (!obj->hdr || !mdmp_read_header(obj->b, obj->hdr)) {
		return false;
	}

	if (obj->hdr->number_of_streams == 0) {
		RZ_LOG_WARN("No streams present!\n");
		return false;
	}

	if (obj->hdr->stream_directory_rva < sizeof(MiniDmpHeader)) {
		RZ_LOG_ERROR("RVA for directory resides in the header!\n");
		return false;
	}

	if (obj->hdr->check_sum) {
		RZ_LOG_INFO("Checksum present but needs validating!\n");
		return false;
	}

	sdb_num_set(obj->kv, "mdmp.hdr.time_date_stamp", obj->hdr->time_date_stamp);
	sdb_num_set(obj->kv, "mdmp.hdr.flags", obj->hdr->flags);
	sdb_num_set(obj->kv, "mdmp_header.offset", 0);
	sdb_set(obj->kv, "mdmp_header.format", "[4]zddddt[8]B Signature "
					       "Version NumberOfStreams StreamDirectoryRVA CheckSum "
					       "TimeDateStamp (mdmp_type)Flags");

	return true;
}

#define mdmp_read_module_list(b, addr, list)   rz_buf_read_le32_at(b, addr, list.number_of_modules)
#define mdmp_read_thread_list(b, addr, list)   rz_buf_read_le32_at(b, addr, list.number_of_threads)
#define mdmp_read_memory_list32(b, addr, list) rz_buf_read_le32_at(b, addr, list.number_of_memory_ranges)

static bool mdmp_read_memory_list64(RzBuffer *b, ut64 addr, MiniDmpMemList64 *list) {
	ut64 offset = addr;
	return rz_buf_read_le64_offset(b, &offset, &list->number_of_memory_ranges) &&
		rz_buf_read_le64_offset(b, &offset, &list->base_rva);
}

static bool mdmp_read_location_descriptor32(RzBuffer *b, ut64 *offset, MiniDmpLocDescr32 *desc) {
	return rz_buf_read_le32_offset(b, offset, &desc->data_size) &&
		rz_buf_read_le32_offset(b, offset, &desc->rva);
}

static bool mdmp_read_memory_descriptor32(RzBuffer *b, ut64 *offset, MiniDmpMemDescr32 *desc) {
	return rz_buf_read_le64_offset(b, offset, &desc->start_of_memory_range) &&
		mdmp_read_location_descriptor32(b, offset, &desc->memory);
}

static bool mdmp_read_memory_descriptor64(RzBuffer *b, ut64 *offset, MiniDmpMemDescr64 *desc) {
	return rz_buf_read_le64_offset(b, offset, &desc->start_of_memory_range) &&
		rz_buf_read_le64_offset(b, offset, &desc->data_size);
}

static bool mdmp_read_thread_ex(RzBuffer *b, ut64 *offset, MiniDmpThreadEx *th) {
	return rz_buf_read_le32_offset(b, offset, &th->thread_id) &&
		rz_buf_read_le32_offset(b, offset, &th->suspend_count) &&
		rz_buf_read_le32_offset(b, offset, &th->priority_class) &&
		rz_buf_read_le32_offset(b, offset, &th->priority) &&
		rz_buf_read_le64_offset(b, offset, &th->teb) &&
		mdmp_read_memory_descriptor32(b, offset, &th->stack) &&
		mdmp_read_location_descriptor32(b, offset, &th->thread_context) &&
		mdmp_read_memory_descriptor32(b, offset, &th->backing_store);
}

static bool mdmp_read_vs_fixedfileinfo(RzBuffer *b, ut64 *offset, VSFixedFileInfo *info) {
	return rz_buf_read_le32_offset(b, offset, &info->dw_signature) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_struc_version) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_version_ms) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_version_ls) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_product_version_ms) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_product_version_ls) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_flags_mask) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_flags) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_os) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_type) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_subtype) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_date_ms) &&
		rz_buf_read_le32_offset(b, offset, &info->dw_file_date_ls);
}

static bool mdmp_read_module(RzBuffer *b, ut64 *offset, MiniDmpModule *module) {
	return rz_buf_read_le64_offset(b, offset, &module->base_of_image) &&
		rz_buf_read_le32_offset(b, offset, &module->size_of_image) &&
		rz_buf_read_le32_offset(b, offset, &module->check_sum) &&
		rz_buf_read_le32_offset(b, offset, &module->time_date_stamp) &&
		rz_buf_read_le32_offset(b, offset, &module->module_name_rva) &&
		mdmp_read_vs_fixedfileinfo(b, offset, &module->version_info) &&
		mdmp_read_location_descriptor32(b, offset, &module->cv_record) &&
		mdmp_read_location_descriptor32(b, offset, &module->misc_record) &&
		rz_buf_read_le64_offset(b, offset, &module->reserved_0) &&
		rz_buf_read_le64_offset(b, offset, &module->reserved_1);
}

static bool mdmp_read_exception(RzBuffer *b, ut64 *offset, MiniDmpException *exc) {
	return rz_buf_read_le32_offset(b, offset, &exc->exception_code) &&
		rz_buf_read_le32_offset(b, offset, &exc->exception_flags) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_record) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_address) &&
		rz_buf_read_le32_offset(b, offset, &exc->number_parameters) &&
		rz_buf_read_le32_offset(b, offset, &exc->__unused_alignment) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[0]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[1]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[2]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[3]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[4]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[5]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[6]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[7]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[8]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[9]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[10]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[11]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[12]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[13]) &&
		rz_buf_read_le64_offset(b, offset, &exc->exception_information[14]);
}

static bool mdmp_read_exception_stream(RzBuffer *b, ut64 *offset, MiniDmpExcStream *stream) {
	return rz_buf_read_le32_offset(b, offset, &stream->thread_id) &&
		rz_buf_read_le32_offset(b, offset, &stream->__alignment) &&
		mdmp_read_exception(b, offset, &stream->exception_record) &&
		mdmp_read_location_descriptor32(b, offset, &stream->thread_context);
}

static bool mdmp_read_function_table_stream(RzBuffer *b, ut64 addr, MiniDmpFuncTableStream *stream) {
	ut64 offset = addr;
	return rz_buf_read_le32_offset(b, &offset, &stream->size_of_header) &&
		rz_buf_read_le32_offset(b, &offset, &stream->size_of_descriptor) &&
		rz_buf_read_le32_offset(b, &offset, &stream->size_of_native_descriptor) &&
		rz_buf_read_le32_offset(b, &offset, &stream->size_of_function_entry) &&
		rz_buf_read_le32_offset(b, &offset, &stream->number_of_descriptors) &&
		rz_buf_read_le32_offset(b, &offset, &stream->size_of_align_pad);
}

static bool mdmp_read_handle_data_stream(RzBuffer *b, ut64 addr, MiniDmpHandleDataStream *stream) {
	ut64 offset = addr;
	return rz_buf_read_le32_offset(b, &offset, &stream->size_of_header) &&
		rz_buf_read_le32_offset(b, &offset, &stream->size_of_descriptor) &&
		rz_buf_read_le32_offset(b, &offset, &stream->number_of_descriptors) &&
		rz_buf_read_le32_offset(b, &offset, &stream->reserved);
}

static bool mdmp_read_memory_info_list(RzBuffer *b, ut64 *offset, MiniDmpMemInfoList *list) {
	return rz_buf_read_le32_offset(b, offset, &list->size_of_header) &&
		rz_buf_read_le32_offset(b, offset, &list->size_of_entry) &&
		rz_buf_read_le64_offset(b, offset, &list->number_of_entries);
}

static bool mdmp_read_memory_info(RzBuffer *b, ut64 *offset, MiniDmpMemInfo *info) {
	return rz_buf_read_le64_offset(b, offset, &info->base_address) &&
		rz_buf_read_le64_offset(b, offset, &info->allocation_base) &&
		rz_buf_read_le32_offset(b, offset, &info->allocation_protect) &&
		rz_buf_read_le32_offset(b, offset, &info->__alignment_1) &&
		rz_buf_read_le64_offset(b, offset, &info->region_size) &&
		rz_buf_read_le32_offset(b, offset, &info->state) &&
		rz_buf_read_le32_offset(b, offset, &info->protect) &&
		rz_buf_read_le32_offset(b, offset, &info->type) &&
		rz_buf_read_le32_offset(b, offset, &info->__alignment_2);
}

static bool mdmp_read_misc_info(RzBuffer *b, ut64 addr, MiniDmpMiscInfo *info) {
	ut64 offset = addr;
	return rz_buf_read_le32_offset(b, &offset, &info->size_of_info) &&
		rz_buf_read_le32_offset(b, &offset, &info->flags_1) &&
		rz_buf_read_le32_offset(b, &offset, &info->process_id) &&
		rz_buf_read_le32_offset(b, &offset, &info->process_create_time) &&
		rz_buf_read_le32_offset(b, &offset, &info->process_user_time) &&
		rz_buf_read_le32_offset(b, &offset, &info->process_kernel_time);
}

static bool mdmp_read_system_info(RzBuffer *b, ut64 addr, MiniDmpSysInfo *info) {
	ut64 offset = addr;

	return rz_buf_read_le16_offset(b, &offset, &info->processor_architecture) &&
		rz_buf_read_le16_offset(b, &offset, &info->processor_level) &&
		rz_buf_read_le16_offset(b, &offset, &info->processor_revision) &&
		rz_buf_read8_offset(b, &offset, &info->number_of_processors) &&
		rz_buf_read8_offset(b, &offset, &info->product_type) &&
		rz_buf_read_le32_offset(b, &offset, &info->major_version) &&
		rz_buf_read_le32_offset(b, &offset, &info->minor_version) &&
		rz_buf_read_le32_offset(b, &offset, &info->build_number) &&
		rz_buf_read_le32_offset(b, &offset, &info->platform_id) &&
		rz_buf_read_le32_offset(b, &offset, &info->csd_version_rva) &&
		rz_buf_read_le32_offset(b, &offset, &info->reserved_1) &&
		rz_buf_read_le64_offset(b, &offset, &info->cpu.other_cpu_info.processor_features[0]) &&
		rz_buf_read_le64_offset(b, &offset, &info->cpu.other_cpu_info.processor_features[1]);
}

static bool mdmp_read_thread_info(RzBuffer *b, ut64 *offset, MiniDmpThreadInfo *info) {
	return rz_buf_read_le32_offset(b, offset, &info->thread_id) &&
		rz_buf_read_le32_offset(b, offset, &info->dump_flags) &&
		rz_buf_read_le32_offset(b, offset, &info->dump_error) &&
		rz_buf_read_le32_offset(b, offset, &info->exit_status) &&
		rz_buf_read_le64_offset(b, offset, &info->create_time) &&
		rz_buf_read_le64_offset(b, offset, &info->exit_time) &&
		rz_buf_read_le64_offset(b, offset, &info->kernel_time) &&
		rz_buf_read_le64_offset(b, offset, &info->user_time) &&
		rz_buf_read_le64_offset(b, offset, &info->start_address) &&
		rz_buf_read_le64_offset(b, offset, &info->affinity);
}

static bool mdmp_read_thread_info_list(RzBuffer *b, ut64 *offset, MiniDmpThreadInfoList *list) {
	return rz_buf_read_le32_offset(b, offset, &list->size_of_header) &&
		rz_buf_read_le32_offset(b, offset, &list->size_of_entry) &&
		rz_buf_read_le32_offset(b, offset, &list->number_of_entries);
}

static bool mdmp_read_token_info(RzBuffer *b, ut64 *offset, MiniDmpTokenInfo *info) {
	return rz_buf_read_le32_offset(b, offset, &info->token_size) &&
		rz_buf_read_le32_offset(b, offset, &info->token_id) &&
		rz_buf_read_le64_offset(b, offset, &info->token_handle);
}

static bool mdmp_read_token_info_list(RzBuffer *b, ut64 *offset, MiniDmpTokenInfoList *list) {
	return rz_buf_read_le32_offset(b, offset, &list->size_of_list) &&
		rz_buf_read_le32_offset(b, offset, &list->number_of_entries) &&
		rz_buf_read_le32_offset(b, offset, &list->list_header_size) &&
		rz_buf_read_le32_offset(b, offset, &list->element_header_size);
}

static bool mdmp_read_unloaded_module(RzBuffer *b, ut64 *offset, MiniDmpUnloadedModule *module) {
	return rz_buf_read_le64_offset(b, offset, &module->base_of_image) &&
		rz_buf_read_le32_offset(b, offset, &module->size_of_image) &&
		rz_buf_read_le32_offset(b, offset, &module->check_sum) &&
		rz_buf_read_le32_offset(b, offset, &module->time_date_stamp) &&
		rz_buf_read_le32_offset(b, offset, &module->module_name_rva);
}

static bool mdmp_read_unloaded_module_list(RzBuffer *b, ut64 *offset, MiniDmpUnloadedModuleList *list) {
	return rz_buf_read_le32_offset(b, offset, &list->size_of_header) &&
		rz_buf_read_le32_offset(b, offset, &list->size_of_entry) &&
		rz_buf_read_le32_offset(b, offset, &list->number_of_entries);
}

static bool mdmp_read_avrf_backtrace_information(RzBuffer *b, ut64 *offset, AVRFBacktraceInfo *info) {
	if (!rz_buf_read_le32_offset(b, offset, &info->depth) ||
		!rz_buf_read_le32_offset(b, offset, &info->index)) {
		return false;
	}
	for (size_t i = 0; i < AVRF_MAX_TRACES; ++i) {
		if (!rz_buf_read_le64_offset(b, offset, &info->return_addresses[i])) {
			return false;
		}
	}
	return true;
}

static bool mdmp_read_avrf_handle_operation(RzBuffer *b, ut64 *offset, AVRFHandleOp *op) {
	return rz_buf_read_le64_offset(b, offset, &op->handle) &&
		rz_buf_read_le32_offset(b, offset, &op->process_id) &&
		rz_buf_read_le32_offset(b, offset, &op->thread_id) &&
		rz_buf_read_le32_offset(b, offset, &op->operation_type) &&
		rz_buf_read_le32_offset(b, offset, &op->spare_0) &&
		mdmp_read_avrf_backtrace_information(b, offset, &op->back_trace_information);
}

static bool mdmp_read_handle_operation_list(RzBuffer *b, ut64 *offset, MiniDmpHandleOpList *list) {
	return rz_buf_read_le32_offset(b, offset, &list->size_of_header) &&
		rz_buf_read_le32_offset(b, offset, &list->size_of_entry) &&
		rz_buf_read_le32_offset(b, offset, &list->number_of_entries) &&
		rz_buf_read_le32_offset(b, offset, &list->reserved);
}

static bool mdmp_init_directory_entry(MiniDmpObj *obj, MiniDmpDir *entry) {
	MiniDmpHandleOpList handle_operation_list = { 0 };
	MiniDmpMemList32 memory_list = { 0 };
	MiniDmpMemList64 memory64_list = { 0 };
	MiniDmpMemInfoList memory_info_list = { 0 };
	MiniDmpModuleList module_list = { 0 };
	MiniDmpThreadList thread_list = { 0 };
	MiniDmpThreadExList thread_ex_list = { 0 };
	MiniDmpThreadInfoList thread_info_list = { 0 };
	MiniDmpTokenInfoList token_info_list = { 0 };
	MiniDmpUnloadedModuleList unloaded_module_list = { 0 };
	ut64 offset;
	int i, r;
	char tmpbuf[256];

	/* We could confirm data sizes but a malcious MDMP will always get around
	** this! But we can ensure that the data is not outside of the file */
	if ((ut64)entry->location.rva + entry->location.data_size > rz_buf_size(obj->b)) {
		RZ_LOG_ERROR("Size Mismatch - Stream data is larger than file size!\n");
		return false;
	}

	switch (entry->stream_type) {
	case THREAD_LIST_STREAM:
		if (!mdmp_read_thread_list(obj->b, entry->location.rva, &thread_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread.format", "ddddq?? "
						       "ThreadId SuspendCount PriorityClass Priority "
						       "Teb (mdmp_memory_descriptor)Stack "
						       "(mdmp_location_descriptor)ThreadContext");
		sdb_num_set(obj->kv, "mdmp_thread_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_thread_list.format",
			rz_strf(tmpbuf, "d[%d]? "
					"NumberOfThreads (mdmp_thread)Threads",
				thread_list.number_of_threads));

		/* TODO: Not yet fully parsed or utilised */
		break;
	case MODULE_LIST_STREAM:
		if (!mdmp_read_module_list(obj->b, entry->location.rva, &module_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_module.format", "qddtd???qq "
						       "BaseOfImage SizeOfImage CheckSum "
						       "TimeDateStamp ModuleNameRVA "
						       "(mdmp_vs_fixedfileinfo)VersionInfo "
						       "(mdmp_location_descriptor)CvRecord "
						       "(mdmp_location_descriptor)MiscRecord "
						       "Reserved0 Reserved1");
		sdb_num_set(obj->kv, "mdmp_module_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_module_list.format",
			rz_strf(tmpbuf, "d[%d]? "
					"NumberOfModule (mdmp_module)Modules",
				module_list.number_of_modules));

		offset = entry->location.rva + sizeof(module_list);
		for (i = 0; i < module_list.number_of_modules; i++) {
			MiniDmpModule *module = RZ_NEW(MiniDmpModule);
			if (!module) {
				break;
			}
			if (!mdmp_read_module(obj->b, &offset, module) ||
				!rz_list_append(obj->streams.modules, module)) {
				free(module);
				break;
			}
		}
		break;
	case MEMORY_LIST_STREAM:
		if (!mdmp_read_memory_list32(obj->b, entry->location.rva, &memory_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_memory_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_memory_list.format",
			rz_strf(tmpbuf, "d[%d]? "
					"NumberOfMemoryRanges "
					"(mdmp_memory_descriptor)MemoryRanges ",
				memory_list.number_of_memory_ranges));

		offset = entry->location.rva + sizeof(MiniDmpModuleList);
		for (i = 0; i < memory_list.number_of_memory_ranges; i++) {
			MiniDmpMemDescr32 *desc = RZ_NEW(MiniDmpMemDescr32);
			if (!desc ||
				!mdmp_read_memory_descriptor32(obj->b, &offset, desc) ||
				!rz_list_append(obj->streams.memories, desc)) {
				free(desc);
				break;
			}
		}
		break;
	case EXCEPTION_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.exception = RZ_NEW(MiniDmpExcStream);
		offset = entry->location.rva;
		if (!obj->streams.exception ||
			!mdmp_read_exception_stream(obj->b, &offset, obj->streams.exception)) {
			RZ_FREE(obj->streams.exception);
			break;
		}

		sdb_set(obj->kv, "mdmp_exception.format", "[4]E[4]Eqqdd[15]q "
							  "(mdmp_exception_code)ExceptionCode "
							  "(mdmp_exception_flags)ExceptionFlags "
							  "ExceptionRecord ExceptionAddress "
							  "NumberParameters __UnusedAlignment "
							  "ExceptionInformation");
		sdb_num_set(obj->kv, "mdmp_exception_stream.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_exception_stream.format", "dd?? "
								 "ThreadId __Alignment "
								 "(mdmp_exception)ExceptionRecord "
								 "(mdmp_location_descriptor)ThreadContext");

		break;
	case SYSTEM_INFO_STREAM:
		obj->streams.system_info = RZ_NEW(MiniDmpSysInfo);
		if (!obj->streams.system_info ||
			!mdmp_read_system_info(obj->b, entry->location.rva, obj->streams.system_info)) {
			RZ_FREE(obj->streams.system_info);
			break;
		}
		sdb_num_set(obj->kv, "mdmp_system_info.offset",
			entry->location.rva);
		/* TODO: We need E as a byte! */
		sdb_set(obj->kv, "mdmp_system_info.format", "[2]EwwbBddd[4]Ed[2]Ew[2]q "
							    "(mdmp_processor_architecture)ProcessorArchitecture "
							    "ProcessorLevel ProcessorRevision NumberOfProcessors "
							    "(mdmp_product_type)ProductType "
							    "MajorVersion MinorVersion BuildNumber (mdmp_platform_id)PlatformId "
							    "CsdVersionRva (mdmp_suite_mask)SuiteMask Reserved2 ProcessorFeatures");

		break;
	case THREAD_EX_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		if (!mdmp_read_thread_list(obj->b, entry->location.rva, &thread_ex_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread_ex.format", "ddddq??? "
							  "ThreadId SuspendCount PriorityClass Priority "
							  "Teb (mdmp_memory_descriptor)Stack "
							  "(mdmp_location_descriptor)ThreadContext "
							  "(mdmp_memory_descriptor)BackingStore");
		sdb_num_set(obj->kv, "mdmp_thread_ex_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_thread_ex_list.format",
			rz_strf(tmpbuf, "d[%d]? NumberOfThreads "
					"(mdmp_thread_ex)Threads",
				thread_ex_list.number_of_threads));

		offset = entry->location.rva + sizeof(MiniDmpThreadExList);
		for (i = 0; i < thread_ex_list.number_of_threads; i++) {
			MiniDmpThreadEx *thread = RZ_NEW(MiniDmpThreadEx);
			if (!thread ||
				!mdmp_read_thread_ex(obj->b, &offset, thread) ||
				!rz_list_append(obj->streams.ex_threads, thread)) {
				free(thread);
				break;
			}
		}
		break;
	case MEMORY_64_LIST_STREAM:
		if (!mdmp_read_memory_list64(obj->b, entry->location.rva, &memory64_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_memory64_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_memory64_list.format",
			rz_strf(tmpbuf, "qq[%" PFMT64d "]? NumberOfMemoryRanges "
					"BaseRva "
					"(mdmp_memory_descriptor64)MemoryRanges",
				memory64_list.number_of_memory_ranges));

		obj->streams.memories64.base_rva = memory64_list.base_rva;
		offset = entry->location.rva + sizeof(MiniDmpMemList64);
		for (i = 0; i < memory64_list.number_of_memory_ranges; i++) {
			MiniDmpMemDescr64 *desc = RZ_NEW(MiniDmpMemDescr64);
			if (!desc ||
				!mdmp_read_memory_descriptor64(obj->b, &offset, desc) ||
				!rz_list_append(obj->streams.memories64.memories, desc)) {
				free(desc);
				break;
			}
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
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_comment_stream_a.format",
			"s CommentA");

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
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_comment_stream_w.format",
			"s CommentW");

		break;
	case HANDLE_DATA_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.handle_data = RZ_NEW(MiniDmpHandleDataStream);
		if (!obj->streams.handle_data ||
			!mdmp_read_handle_data_stream(obj->b, entry->location.rva, obj->streams.handle_data)) {
			RZ_FREE(obj->streams.handle_data);
			break;
		}

		sdb_num_set(obj->kv, "mdmp_handle_data_stream.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_handle_data_stream.format", "dddd "
								   "SizeOfHeader SizeOfDescriptor "
								   "NumberOfDescriptors Reserved");
		break;
	case FUNCTION_TABLE_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.function_table = RZ_NEW(MiniDmpFuncTableStream);
		if (!obj->streams.function_table ||
			!mdmp_read_function_table_stream(obj->b, entry->location.rva, obj->streams.function_table)) {
			RZ_FREE(obj->streams.function_table);
			break;
		}

		sdb_num_set(obj->kv, "mdmp_function_table_stream.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_function_table_stream.format", "dddddd "
								      "SizeOfHeader SizeOfDescriptor SizeOfNativeDescriptor "
								      "SizeOfFunctionEntry NumberOfDescriptors SizeOfAlignPad");
		break;
	case UNLOADED_MODULE_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		offset = entry->location.rva;
		if (!mdmp_read_unloaded_module_list(obj->b, &offset, &unloaded_module_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_unloaded_module.format", "qddtd "
								"BaseOfImage SizeOfImage CheckSum TimeDateStamp "
								"ModuleNameRva");
		sdb_num_set(obj->kv, "mdmp_unloaded_module_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_unloaded_module_list.format", "ddd "
								     "SizeOfHeader SizeOfEntry NumberOfEntries");

		for (i = 0; i < unloaded_module_list.number_of_entries; i++) {
			MiniDmpUnloadedModule *module = RZ_NEW(MiniDmpUnloadedModule);
			if (!module ||
				!mdmp_read_unloaded_module(obj->b, &offset, module) ||
				!rz_list_append(obj->streams.unloaded_modules, module)) {
				free(module);
				break;
			}
		}
		break;
	case MISC_INFO_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		obj->streams.misc_info.misc_info_1 = RZ_NEW(MiniDmpMiscInfo);
		if (!obj->streams.misc_info.misc_info_1 ||
			!mdmp_read_misc_info(obj->b, entry->location.rva, obj->streams.misc_info.misc_info_1)) {
			RZ_FREE(obj->streams.misc_info.misc_info_1);
			break;
		}

		/* TODO: Handle different sizes */
		sdb_num_set(obj->kv, "mdmp_misc_info.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_misc_info.format", "d[4]Bdtttddddd "
							  "SizeOfInfo (mdmp_misc1_flags)Flags1 ProcessId "
							  "ProcessCreateTime ProcessUserTime ProcessKernelTime "
							  "ProcessorMaxMhz ProcessorCurrentMhz "
							  "ProcessorMhzLimit ProcessorMaxIdleState "
							  "ProcessorCurrentIdleState");

		break;
	case MEMORY_INFO_LIST_STREAM:
		offset = entry->location.rva;
		if (!mdmp_read_memory_info_list(obj->b, &offset, &memory_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_memory_info.format",
			"qq[4]Edq[4]E[4]E[4]Ed BaseAddress AllocationBase "
			"(mdmp_page_protect)AllocationProtect __Alignment1 RegionSize "
			"(mdmp_mem_state)State (mdmp_page_protect)Protect "
			"(mdmp_mem_type)Type __Alignment2");
		sdb_num_set(obj->kv, "mdmp_memory_info_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_memory_info_list.format",
			rz_strf(tmpbuf, "ddq[%" PFMT64d "]? SizeOfHeader SizeOfEntry "
					"NumberOfEntries (mdmp_memory_info)MemoryInfo",
				memory_info_list.number_of_entries));

		for (i = 0; i < memory_info_list.number_of_entries; i++) {
			MiniDmpMemInfo *info = RZ_NEW(MiniDmpMemInfo);
			if (!info ||
				!mdmp_read_memory_info(obj->b, &offset, info) ||
				!rz_list_append(obj->streams.memory_infos, info)) {
				free(info);
				break;
			}
		}
		break;
	case THREAD_INFO_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		offset = entry->location.rva;
		if (!mdmp_read_thread_info_list(obj->b, &offset, &thread_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_thread_info.format", "ddddttttqq "
							    "ThreadId DumpFlags DumpError ExitStatus CreateTime "
							    "ExitTime KernelTime UserTime StartAddress Affinity");
		sdb_num_set(obj->kv, "mdmp_thread_info_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_thread_info_list.format", "ddd "
								 "SizeOfHeader SizeOfEntry NumberOfEntries");

		for (i = 0; i < thread_info_list.number_of_entries; i++) {
			MiniDmpThreadInfo *info = RZ_NEW(MiniDmpThreadInfo);
			if (!info ||
				!mdmp_read_thread_info(obj->b, &offset, info) ||
				!rz_list_append(obj->streams.thread_infos, info)) {
				free(info);
				break;
			}
		}
		break;
	case HANDLE_OPERATION_LIST_STREAM:
		/* TODO: Not yet fully parsed or utilised */
		offset = entry->location.rva;
		if (!mdmp_read_handle_operation_list(obj->b, &offset, &handle_operation_list)) {
			break;
		}

		sdb_num_set(obj->kv, "mdmp_handle_operation_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_handle_operation_list.format", "dddd "
								      "SizeOfHeader SizeOfEntry NumberOfEntries Reserved");

		for (i = 0; i < handle_operation_list.number_of_entries; i++) {
			AVRFHandleOp *op = RZ_NEW(AVRFHandleOp);
			if (!op ||
				!mdmp_read_avrf_handle_operation(obj->b, &offset, op) ||
				!rz_list_append(obj->streams.operations, op)) {
				free(op);
				break;
			}
		}

		break;
	case TOKEN_STREAM:
		/* TODO: Not fully parsed or utilised */
		offset = entry->location.rva;
		if (!mdmp_read_token_info_list(obj->b, &offset, &token_info_list)) {
			break;
		}

		sdb_set(obj->kv, "mdmp_token_info.format", "ddq "
							   "TokenSize TokenId TokenHandle");

		sdb_num_set(obj->kv, "mdmp_token_info_list.offset",
			entry->location.rva);
		sdb_set(obj->kv, "mdmp_token_info_list.format", "dddd "
								"TokenListSize TokenListEntries ListHeaderSize ElementHeaderSize");

		for (i = 0; i < token_info_list.number_of_entries; i++) {
			MiniDmpTokenInfo *info = RZ_NEW(MiniDmpTokenInfo);
			if (!info ||
				!mdmp_read_token_info(obj->b, &offset, info) ||
				!rz_list_append(obj->streams.token_infos, info)) {
				free(info);
				break;
			}
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
		RZ_LOG_WARN("Invalid or unsupported enumeration encountered %d\n", entry->stream_type);
		break;
	}
	return true;
}

static bool mdmp_read_directory(MiniDmpObj *obj, ut64 addr, MiniDmpDir *entry) {
	ut64 offset = addr;
	return rz_buf_read_le32_offset(obj->b, &offset, &entry->stream_type) &&
		mdmp_read_location_descriptor32(obj->b, &offset, &entry->location) &&
		mdmp_init_directory_entry(obj, entry);
}

static bool rz_bin_mdmp_init_directory(MiniDmpObj *obj) {
	sdb_num_set(obj->kv, "mdmp_directory.offset",
		obj->hdr->stream_directory_rva);
	sdb_set(obj->kv, "mdmp_directory.format", "[4]E? "
						  "(mdmp_stream_type)StreamType "
						  "(mdmp_location_descriptor)Location");

	ut64 rvadir = obj->hdr->stream_directory_rva;
	ut64 bytes_left = rvadir < obj->size ? obj->size - rvadir : 0;
	size_t max_entries = RZ_MIN(obj->hdr->number_of_streams, bytes_left / sizeof(MiniDmpDir));
	if (max_entries < obj->hdr->number_of_streams) {
		RZ_LOG_ERROR("Number of streams = %u is greater than is supportable by bin size\n",
			obj->hdr->number_of_streams);
	}
	/* Parse each entry in the directory */
	for (ut32 i = 0; i < max_entries; i++) {
		ut32 delta = i * sizeof(MiniDmpDir);
		MiniDmpDir entry = { 0 };
		if (!mdmp_read_directory(obj, rvadir + delta, &entry)) {
			return false;
		}
	}

	return true;
}

static bool rz_bin_mdmp_patch_pe_headers(RzBuffer *pe_buf) {
	int i;
	Pe64_image_dos_header dos_hdr;
	Pe64_image_nt_headers nt_hdr;

	if (!Pe64_read_dos_header(pe_buf, &dos_hdr)) {
		return false;
	}
	if (!Pe64_read_nt_headers(pe_buf, dos_hdr.e_lfanew, &nt_hdr)) {
		return false;
	}

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

static bool rz_bin_mdmp_init_pe_bins(MiniDmpObj *obj) {
	bool dup;
	ut64 paddr;
	MiniDmpModule *module;
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

static int rz_bin_mdmp_init(MiniDmpObj *obj) {
	mdmp_obj_sdb_init(obj);

	if (!rz_bin_mdmp_init_hdr(obj)) {
		RZ_LOG_ERROR("Failed to initialise header\n");
		return false;
	}

	if (!rz_bin_mdmp_init_directory(obj)) {
		RZ_LOG_ERROR("Failed to initialise directory structures!\n");
		return false;
	}

	if (!rz_bin_mdmp_init_pe_bins(obj)) {
		RZ_LOG_ERROR("Failed to initialise pe binaries!\n");
		return false;
	}

	return true;
}

MiniDmpObj *rz_bin_mdmp_new_buf(RzBuffer *buf) {
	MiniDmpObj *obj = RZ_NEW0(MiniDmpObj);
	if (!obj) {
		return NULL;
	}
	obj->kv = sdb_new0();
	obj->size = (ut32)rz_buf_size(buf);
	if (!obj->kv ||
		!(obj->streams.ex_threads = rz_list_new()) ||
		!(obj->streams.memories = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.memories64.memories = rz_list_new()) ||
		!(obj->streams.memory_infos = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.modules = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.operations = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.thread_infos = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.token_infos = rz_list_newf((RzListFree)free)) ||
		!(obj->streams.threads = rz_list_new()) ||
		!(obj->streams.unloaded_modules = rz_list_newf((RzListFree)free)) ||
		!(obj->pe32_bins = rz_list_newf((RzListFree)rz_bin_mdmp_free_pe32_bin)) ||
		!(obj->pe64_bins = rz_list_newf((RzListFree)rz_bin_mdmp_free_pe64_bin))) {
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
