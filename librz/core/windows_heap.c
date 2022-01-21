// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <TlHelp32.h>
#include <windows_heap.h>
#include "..\..\debug\p\native\maps\windows_maps.h"
#include "..\..\bin\pdb\pdb_downloader.h"
#include "..\..\bin\pdb\pdb.h"

/*
 *	Viewer discretion advised: Spaghetti code ahead
 *	Some Code references:
 *	https://securityxploded.com/enumheaps.php
 *	https://bitbucket.org/evolution536/crysearch-memory-scanner/
 *	https://processhacker.sourceforge.io
 *	http://www.tssc.de/winint
 *	https://www.nirsoft.net/kernel_struct/vista/
 *	https://github.com/yoichi/HeapStat/blob/master/heapstat.cpp
 *	https://doxygen.reactos.org/
 *
 *	References:
 *	Windows NT(2000) Native API Reference (Book)
 *	Papers:
 *	http://illmatics.com/Understanding_the_LFH.pdf
 *	http://illmatics.com/Windows%208%20Heap%20Internals.pdf
 *	https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf
 *
 *	This code has 2 different approaches to getting the heap info:
 *		1) Calling InitHeapInfo with both PDI_HEAPS and PDI_HEAP_BLOCKS.
 *			This will fill a buffer with HeapBlockBasicInfo like structures which
 *			is then walked through by calling GetFirstHeapBlock and subsequently GetNextHeapBlock
 *			(see 1st link). This approach is the more generic one as it uses Windows functions.
 *			Unfortunately it fails to offer more detailed information about each block (although it is possible to get this info later) and
 *			also fails misteriously once the count of allocated blocks reach a certain threshold (1mil or so) or if segment heap is active for the
 *			program (in this case everything locks in the next call for the function)
 *		2) In case 1 fails, Calling GetHeapBlocks, which will manually read and parse (poorly :[ ) each block.
 *			First it calls InitHeapInfo	with only the PDI_HEAPS flag, with the only objective of getting a list of heap header addresses. It will then
 *			do the job that InitHeapInfo would do if it was called with PDI_HEAP_BLOCKS as well, filling a buffer with HeapBlockBasicInfo structures that
 *			can also be walked with GetFirstHeapBlock and GetNextHeapBlock (and HeapBlockExtraInfo when needed).
 *
 *	TODO:
 *		Var to select algorithm?
 *		x86 vs x64 vs WOW64
 *		Graphs
 *		Print structures
 *		Make sure GetHeapBlocks actually works
 *		Maybe instead of using hardcoded structs we can get the offsets from ntdll.pdb
 */

#define PDI_MODULES         0x01
#define PDI_HEAPS           0x04
#define PDI_HEAP_TAGS       0x08
#define PDI_HEAP_BLOCKS     0x10
#define PDI_HEAP_ENTRIES_EX 0x200

static size_t RtlpHpHeapGlobalsOffset = 0;
static size_t RtlpLFHKeyOffset = 0;

#define CHECK_INFO(heapInfo) \
	if (!heapInfo) { \
		eprintf("It wasn't possible to get the heap information\n"); \
		return; \
	} \
	if (!heapInfo->count) { \
		rz_cons_print("No heaps for this process\n"); \
		return; \
	}

#define CHECK_INFO_RETURN_NULL(heapInfo) \
	if (!heapInfo) { \
		eprintf("It wasn't possible to get the heap information\n"); \
		return NULL; \
	} \
	if (!heapInfo->count) { \
		rz_cons_print("No heaps for this process\n"); \
		return NULL; \
	}

#define UPDATE_FLAGS(hb, flags) \
	if (((flags)&0xf1) || ((flags)&0x0200)) { \
		hb->dwFlags = LF32_FIXED; \
	} else if ((flags)&0x20) { \
		hb->dwFlags = LF32_MOVEABLE; \
	} else if ((flags)&0x0100) { \
		hb->dwFlags = LF32_FREE; \
	} \
	hb->dwFlags |= ((flags) >> SHIFT) << SHIFT;

static bool __is_windows_ten(void) {
	int major = 0;
	RSysInfo *info = rz_sys_info();
	if (info && info->version) {
		char *dot = strchr(info->version, '.');
		if (dot) {
			*dot = '\0';
			major = atoi(info->version);
		}
	}
	rz_sys_info_free(info);
	return major == 10;
}

static char *get_type(WPARAM flags) {
	char *state = "";
	switch (flags & 0xFFFF) {
	case LF32_FIXED:
		state = "(FIXED)";
		break;
	case LF32_FREE:
		state = "(FREE)";
		break;
	case LF32_MOVEABLE:
		state = "(MOVEABLE)";
		break;
	}
	char *heaptype = "";
	if (flags & SEGMENT_HEAP_BLOCK) {
		heaptype = "Segment";
	} else if (flags & NT_BLOCK) {
		heaptype = "NT";
	}
	char *type = "";
	if (flags & LFH_BLOCK) {
		type = "/LFH";
	} else if (flags & LARGE_BLOCK) {
		type = "/LARGE";
	} else if (flags & BACKEND_BLOCK) {
		type = "/BACKEND";
	} else if (flags & VS_BLOCK) {
		type = "/VS";
	}
	return rz_str_newf("%s %s%s", state, heaptype, type);
}

static bool initialize_windows_ntdll_query_api_functions(void) {
	HANDLE ntdll = LoadLibrary(TEXT("ntdll.dll"));
	if (!ntdll) {
		return false;
	}
	if (!RtlCreateQueryDebugBuffer) {
		RtlCreateQueryDebugBuffer = (PDEBUG_BUFFER(NTAPI *)(DWORD, BOOLEAN))GetProcAddress(ntdll, "RtlCreateQueryDebugBuffer");
	}
	if (!RtlQueryProcessDebugInformation) {
		RtlQueryProcessDebugInformation = (NTSTATUS(NTAPI *)(DWORD, DWORD, PDEBUG_BUFFER))GetProcAddress(ntdll, "RtlQueryProcessDebugInformation");
	}
	if (!RtlDestroyQueryDebugBuffer) {
		RtlDestroyQueryDebugBuffer = (NTSTATUS(NTAPI *)(PDEBUG_BUFFER))GetProcAddress(ntdll, "RtlDestroyQueryDebugBuffer");
	}
	if (!w32_NtQueryInformationProcess) {
		w32_NtQueryInformationProcess = (NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(ntdll, "NtQueryInformationProcess");
	}
	return true;
}

static bool is_segment_heap(HANDLE h_proc, PVOID heapBase) {
	HEAP heap;
	if (ReadProcessMemory(h_proc, heapBase, &heap, sizeof(HEAP), NULL)) {
		if (heap.SegmentSignature == 0xddeeddee) {
			return true;
		}
	}
	return false;
}

// These functions are basically Heap32First and Heap32Next but faster
static bool GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb) {
	rz_return_val_if_fail(heapInfo && hb, false);
	PHeapBlockBasicInfo block;

	hb->index = 0;
	hb->dwAddress = 0;
	hb->dwFlags = 0;
	hb->extraInfo = NULL;

	block = (PHeapBlockBasicInfo)heapInfo->Blocks;
	if (!block) {
		return false;
	}

	SIZE_T index = hb->index;
	do {
		if (index > heapInfo->BlockCount) {
			return false;
		}
		hb->dwAddress = block[index].address;
		hb->dwSize = block->size;
		if (block[index].extra & EXTRA_FLAG) {
			PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
			hb->dwSize -= extra->unusedBytes;
			hb->extraInfo = extra;
			hb->dwAddress = (WPARAM)hb->dwAddress + extra->granularity;
		} else {
			hb->dwAddress = (WPARAM)hb->dwAddress + heapInfo->Granularity;
			hb->extraInfo = NULL;
		}
		index++;
	} while (block[index].flags & 2);

	WPARAM flags = block[hb->index].flags;
	UPDATE_FLAGS(hb, flags);

	hb->index = index;
	return true;
}

static bool GetNextHeapBlock(PDEBUG_HEAP_INFORMATION heapInfo, PHeapBlock hb) {
	rz_return_val_if_fail(heapInfo && hb, false);
	PHeapBlockBasicInfo block;

	block = (PHeapBlockBasicInfo)heapInfo->Blocks;
	SIZE_T index = hb->index;

	if (index > heapInfo->BlockCount) {
		return false;
	}

	if (block[index].flags & 2) {
		do {
			if (index > heapInfo->BlockCount) {
				return false;
			}

			// new address = curBlockAddress + Granularity;
			hb->dwAddress = block[index].address + heapInfo->Granularity;

			index++;
			hb->dwSize = block->size;
		} while (block[index].flags & 2);
		hb->index = index;
	} else {
		hb->dwSize = block[index].size;
		if (block[index].extra & EXTRA_FLAG) {
			PHeapBlockExtraInfo extra = (PHeapBlockExtraInfo)(block[index].extra & ~EXTRA_FLAG);
			hb->extraInfo = extra;
			hb->dwSize -= extra->unusedBytes;
			hb->dwAddress = block[index].address + extra->granularity;
		} else {
			hb->extraInfo = NULL;
			hb->dwAddress = (WPARAM)hb->dwAddress + hb->dwSize;
		}
		hb->index++;
	}

	WPARAM flags;
	if (block[index].extra & EXTRA_FLAG) {
		flags = block[index].flags;
	} else {
		flags = (USHORT)block[index].flags;
	}
	UPDATE_FLAGS(hb, flags);

	return true;
}

static void free_extra_info(PDEBUG_HEAP_INFORMATION heap) {
	rz_return_if_fail(heap);
	HeapBlock hb;
	if (GetFirstHeapBlock(heap, &hb)) {
		do {
			RZ_FREE(hb.extraInfo);
		} while (GetNextHeapBlock(heap, &hb));
	}
}

static inline bool has_heap_globals(void) {
	return RtlpHpHeapGlobalsOffset && RtlpLFHKeyOffset;
}

static bool GetHeapGlobalsOffset(RzDebug *dbg, HANDLE h_proc) {
	if (has_heap_globals()) {
		return true;
	}
	RzCore *core = dbg->corebind.core;
	RzList *modules = rz_w32_dbg_modules(dbg);
	RzListIter *it;
	RzDebugMap *map;
	bool found = false;
	rz_list_foreach (modules, it, map) {
		if (!strcmp(map->name, "ntdll.dll")) {
			found = true;
			break;
		}
	}
	if (!found) {
		eprintf("ntdll.dll not loaded.\n");
		rz_list_free(modules);
		return false;
	}

	ut64 baseaddr = map->addr;

	// Open ntdll.dll file
	int fd;
	if ((fd = rz_io_fd_open(core->io, map->file, RZ_PERM_R, 0)) == -1) {
		rz_list_free(modules);
		return false;
	}

	rz_list_free(modules);

	// Load ntdll.dll in RzBin to get its GUID
	RzBinOptions opt = { 0 };
	opt.fd = fd;
	opt.sz = rz_io_fd_size(core->io, fd);
	opt.obj_opts.baseaddr = baseaddr;
	RzBinFile *obf = rz_bin_cur(core->bin);
	RzBinFile *bf = rz_bin_open_io(core->bin, &opt);
	if (!bf) {
		rz_io_fd_close(core->io, fd);
		return false;
	}
	RzBinInfo *info = rz_bin_get_info(core->bin);
	if (!info) {
		goto fail;
	}
	char *pdb_path = rz_str_newf("%s\\ntdll.pdb\\%s\\ntdll.pdb",
		rz_config_get(core->config, "pdb.symstore"), info->guid);
	if (!pdb_path) {
		goto fail;
	}
	if (!rz_file_exists(pdb_path)) {
		// Download ntdll.pdb
		SPDBOptions opts;
		opts.extract = rz_config_get_i(core->config, "pdb.extract");
		opts.symbol_store_path = rz_config_get(core->config, "pdb.symstore");
		opts.symbol_server = rz_config_get(core->config, "pdb.server");
		if (rz_bin_pdb_download(core, NULL, false, &opts)) {
			eprintf("Failed to download ntdll.pdb file\n");
			free(pdb_path);
			goto fail;
		}
	}

	// Get ntdll.dll PDB info and parse json output
	RzPdb *pdb = rz_bin_pdb_parse_from_file(pdb_path);
	if (!pdb) {
		free(pdb_path);
		goto fail;
	}

	free(pdb_path);
	ut64 baddr = rz_config_get_i(core->config, "bin.baddr");
	if (core->bin->cur && core->bin->cur->o && core->bin->cur->o->opts.baseaddr) {
		baddr = core->bin->cur->o->opts.baseaddr;
	} else {
		eprintf("Warning: Cannot find base address, flags will probably be misplaced\n");
	}
	PJ *pj = pj_new();
	if (!pj) {
		rz_bin_pdb_free(pdb);
		goto fail;
	}
	char *j = rz_core_bin_pdb_gvars_as_string(pdb, baddr, pj, RZ_OUTPUT_MODE_JSON);
	if (!j) {
		rz_bin_pdb_free(pdb);
		pj_free(pj);
		goto fail;
	}
	pj_free(pj);
	rz_bin_pdb_free(pdb);
	RzJson *json = rz_json_parse(j);
	if (!json) {
		RZ_LOG_ERROR("rz_core_pdb_info returned invalid JSON");
		free(j);
		goto fail;
	}
	free(j);

	// Go through gvars array and search for the heap globals symbols
	const RzJson *gvars = rz_json_get(json, "gvars");
	gvars = gvars->children.first;
	do {
		const RzJson *gdata_name = rz_json_get(gvars, "gdata_name");
		if (!strcmp(gdata_name->str_value, "RtlpHpHeapGlobals")) {
			const RzJson *address = rz_json_get(gvars, "address");
			RtlpHpHeapGlobalsOffset = address->num.u_value;
		} else if (!strcmp(gdata_name->str_value, "RtlpLFHKey")) {
			const RzJson *address = rz_json_get(gvars, "address");
			RtlpLFHKeyOffset = address->num.u_value;
		}
	} while ((gvars = gvars->next) && !has_heap_globals());

	free(json);
fail:
	rz_bin_file_delete(core->bin, bf);
	rz_bin_file_set_cur_binfile(core->bin, obf);
	rz_io_fd_close(core->io, fd);
	return has_heap_globals();
}

static bool GetLFHKey(RzDebug *dbg, HANDLE h_proc, bool segment, WPARAM *lfhKey) {
	rz_return_val_if_fail(dbg, 0);
	WPARAM lfhKeyLocation;

	if (!GetHeapGlobalsOffset(dbg, h_proc)) {
		*lfhKey = 0;
		return false;
	}

	if (segment) {
		lfhKeyLocation = RtlpHpHeapGlobalsOffset + sizeof(WPARAM);
	} else {
		lfhKeyLocation = RtlpLFHKeyOffset; // ntdll!RtlpLFHKey
	}
	if (!ReadProcessMemory(h_proc, (PVOID)lfhKeyLocation, lfhKey, sizeof(WPARAM), NULL)) {
		rz_sys_perror("ReadProcessMemory");
		eprintf("LFH key not found.\n");
		*lfhKey = 0;
		return false;
	}
	return true;
}

static bool DecodeHeapEntry(RzDebug *dbg, PHEAP heap, PHEAP_ENTRY entry) {
	rz_return_val_if_fail(heap && entry, false);
	if (dbg->bits == RZ_SYS_BITS_64) {
		entry = (PHEAP_ENTRY)((ut8 *)entry + dbg->bits);
	}
	if (heap->EncodeFlagMask && (*(UINT32 *)entry & heap->EncodeFlagMask)) {
		if (dbg->bits == RZ_SYS_BITS_64) {
			heap = (PHEAP)((ut8 *)heap + dbg->bits);
		}
		*(WPARAM *)entry ^= *(WPARAM *)&heap->Encoding;
	}
	return !(((BYTE *)entry)[0] ^ ((BYTE *)entry)[1] ^ ((BYTE *)entry)[2] ^ ((BYTE *)entry)[3]);
}

static bool DecodeLFHEntry(RzDebug *dbg, PHEAP heap, PHEAP_ENTRY entry, PHEAP_USERDATA_HEADER userBlocks, WPARAM key, WPARAM addr) {
	rz_return_val_if_fail(heap && entry, false);
	if (dbg->bits == RZ_SYS_BITS_64) {
		entry = (PHEAP_ENTRY)((ut8 *)entry + dbg->bits);
	}

	if (heap->EncodeFlagMask) {
		*(DWORD *)entry ^= PtrToInt(heap->BaseAddress) ^ (DWORD)(((DWORD)addr - PtrToInt(userBlocks)) << 0xC) ^ (DWORD)key ^ (addr >> 4);
	}
	return !(((BYTE *)entry)[0] ^ ((BYTE *)entry)[1] ^ ((BYTE *)entry)[2] ^ ((BYTE *)entry)[3]);
}

typedef struct _th_query_params {
	RzDebug *dbg;
	DWORD mask;
	PDEBUG_BUFFER db;
	DWORD ret;
	bool fin;
	bool hanged;
} th_query_params;

static DWORD WINAPI __th_QueryDebugBuffer(void *param) {
	th_query_params *params = (th_query_params *)param;
	params->ret = RtlQueryProcessDebugInformation(params->dbg->pid, params->mask, params->db);
	params->fin = true;
	if (params->hanged) {
		RtlDestroyQueryDebugBuffer(params->db);
		free(params);
	}
	return 0;
}

static RzList *GetListOfHeaps(RzDebug *dbg, HANDLE ph) {
	PROCESS_BASIC_INFORMATION pib;
	if (w32_NtQueryInformationProcess(ph, ProcessBasicInformation, &pib, sizeof(pib), NULL)) {
		rz_sys_perror("NtQueryInformationProcess");
		return NULL;
	}
	PEB peb;
	ReadProcessMemory(ph, pib.PebBaseAddress, &peb, sizeof(PEB), NULL);
	RzList *heaps = rz_list_new();
	PVOID heapAddress;
	PVOID *processHeaps;
	ULONG numberOfHeaps;
	if (dbg->bits == RZ_SYS_BITS_64) {
		processHeaps = *((PVOID *)(((ut8 *)&peb) + 0xF0));
		numberOfHeaps = *((ULONG *)(((ut8 *)&peb) + 0xE8));
	} else {
		processHeaps = *((PVOID *)(((ut8 *)&peb) + 0x90));
		numberOfHeaps = *((ULONG *)(((ut8 *)&peb) + 0x88));
	}
	do {
		ReadProcessMemory(ph, processHeaps, &heapAddress, sizeof(PVOID), NULL);
		rz_list_push(heaps, heapAddress);
		processHeaps += 1;
	} while (--numberOfHeaps);
	return heaps;
}

/*
 *	This function may fail with PDI_HEAP_BLOCKS if:
 *		There's too many allocations
 *		The Segment Heap is activated (will block next time called)
 *		Notes:
 *			Some LFH allocations seem misaligned
 */
static PDEBUG_BUFFER InitHeapInfo(RzDebug *dbg, DWORD mask) {
	// Check:
	//	RtlpQueryProcessDebugInformationFromWow64
	//	RtlpQueryProcessDebugInformationRemote
	PDEBUG_BUFFER db = RtlCreateQueryDebugBuffer(0, FALSE);
	if (!db) {
		return NULL;
	}
	th_query_params *params = RZ_NEW0(th_query_params);
	if (!params) {
		RtlDestroyQueryDebugBuffer(db);
		return NULL;
	}
	*params = (th_query_params){ dbg, mask, db, 0, false, false };
	HANDLE th = CreateThread(NULL, 0, &__th_QueryDebugBuffer, params, 0, NULL);
	if (th) {
		WaitForSingleObject(th, 5000);
	} else {
		RtlDestroyQueryDebugBuffer(db);
		return NULL;
	}
	if (!params->fin) {
		// why after it fails the first time it blocks on the second? That's annoying
		// It stops blocking if i pause rizin in the debugger. is it a race?
		// why it fails with 1000000 allocs? also with processes with segment heap enabled?
		params->hanged = true;
		eprintf("RtlQueryProcessDebugInformation hanged\n");
		db = NULL;
	} else if (params->ret) {
		RtlDestroyQueryDebugBuffer(db);
		db = NULL;
		rz_sys_perror("RtlQueryProcessDebugInformation");
	}
	CloseHandle(th);
	if (db) {
		return db;
	}

	// TODO: Not do this
	if (mask == PDI_HEAPS && __is_windows_ten()) {
		db = RtlCreateQueryDebugBuffer(0, FALSE);
		if (!db) {
			return NULL;
		}
		PHeapInformation heapInfo = RZ_NEW0(HeapInformation);
		if (!heapInfo) {
			RtlDestroyQueryDebugBuffer(db);
			return NULL;
		}
		HANDLE h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dbg->pid);
		if (!h_proc) {
			RZ_LOG_ERROR("OpenProcess failed\n");
			free(heapInfo);
			RtlDestroyQueryDebugBuffer(db);
			return NULL;
		}
		RzList *heaps = GetListOfHeaps(dbg, h_proc);
		CloseHandle(h_proc);
		heapInfo->count = heaps->length;
		void *tmp = realloc(heapInfo, sizeof(DEBUG_HEAP_INFORMATION) * heapInfo->count + sizeof(heapInfo));
		if (!tmp) {
			free(heapInfo);
			RtlDestroyQueryDebugBuffer(db);
			return NULL;
		}
		heapInfo = tmp;
		int i = 0;
		RzListIter *it;
		void *heapBase;
		rz_list_foreach (heaps, it, heapBase) {
			heapInfo->heaps[i].Base = heapBase;
			heapInfo->heaps[i].Granularity = sizeof(HEAP_ENTRY);
			heapInfo->heaps[i].Allocated = 0;
			heapInfo->heaps[i].Committed = 0;
			i++;
		}
		db->HeapInformation = heapInfo;
		rz_list_free(heaps);
		return db;
	}
	return NULL;
}

#define GROW_BLOCKS() \
	if (allocated <= count * sizeof(HeapBlockBasicInfo)) { \
		SIZE_T old_alloc = allocated; \
		allocated *= 2; \
		PVOID tmp = blocks; \
		blocks = realloc(blocks, allocated); \
		if (!blocks) { \
			blocks = tmp; \
			goto err; \
		} \
		memset((BYTE *)blocks + old_alloc, 0, old_alloc); \
	}

#define GROW_PBLOCKS() \
	if (*allocated <= *count * sizeof(HeapBlockBasicInfo)) { \
		SIZE_T old_alloc = *allocated; \
		*allocated *= 2; \
		PVOID tmp = *blocks; \
		tmp = realloc(*blocks, *allocated); \
		if (!tmp) { \
			return false; \
		} \
		*blocks = tmp; \
		memset((BYTE *)(*blocks) + old_alloc, 0, old_alloc); \
	}

static bool __lfh_segment_loop(HANDLE h_proc, PHeapBlockBasicInfo *blocks, SIZE_T *allocated, WPARAM lfhKey, WPARAM *count, WPARAM first, WPARAM next) {
	while ((first != next) && next) {
		HEAP_LFH_SUBSEGMENT subsegment;
		ReadProcessMemory(h_proc, (void *)next, &subsegment, sizeof(HEAP_LFH_SUBSEGMENT), NULL);
		subsegment.BlockOffsets.EncodedData ^= (DWORD)lfhKey ^ ((DWORD)next >> 0xC);
		WPARAM mask = 1, offset = 0;
		int l;
		for (l = 0; l < subsegment.BlockCount; l++) {
			if (!mask) {
				mask = 1;
				offset++;
				ReadProcessMemory(h_proc, (WPARAM *)(next + offsetof(HEAP_LFH_SUBSEGMENT, BlockBitmap)) + offset,
					&subsegment.BlockBitmap, sizeof(WPARAM), NULL);
			}
			if (subsegment.BlockBitmap[0] & mask) {
				GROW_PBLOCKS();
				WPARAM off = (WPARAM)subsegment.BlockOffsets.FirstBlockOffset + l * (WPARAM)subsegment.BlockOffsets.BlockSize;
				(*blocks)[*count].address = next + off;
				(*blocks)[*count].size = subsegment.BlockOffsets.BlockSize;
				(*blocks)[*count].flags = 1 | SEGMENT_HEAP_BLOCK | LFH_BLOCK;
				PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
				if (!extra) {
					return false;
				}
				extra->segment = next;
				extra->granularity = sizeof(HEAP_ENTRY);
				(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
				*count += 1;
			}
			mask <<= 2;
		}
		next = (WPARAM)subsegment.ListEntry.Flink;
	}
	return true;
}

static bool GetSegmentHeapBlocks(RzDebug *dbg, HANDLE h_proc, PVOID heapBase, PHeapBlockBasicInfo *blocks, WPARAM *count, SIZE_T *allocated) {
	rz_return_val_if_fail(h_proc && blocks && count && allocated, false);
	WPARAM bytesRead;
	SEGMENT_HEAP segheapHeader;
	ReadProcessMemory(h_proc, heapBase, &segheapHeader, sizeof(SEGMENT_HEAP), &bytesRead);

	if (segheapHeader.Signature != 0xddeeddee) {
		return false;
	}
	WPARAM lfhKey;
	WPARAM lfhKeyLocation = RtlpHpHeapGlobalsOffset + sizeof(WPARAM);
	if (!ReadProcessMemory(h_proc, (PVOID)lfhKeyLocation, &lfhKey, sizeof(WPARAM), &bytesRead)) {
		rz_sys_perror("ReadProcessMemory");
		eprintf("LFH key not found.\n");
		return false;
	}

	// LFH
	byte numBuckets = _countof(segheapHeader.LfhContext.Buckets);
	int j;
	for (j = 0; j < numBuckets; j++) {
		if ((WPARAM)segheapHeader.LfhContext.Buckets[j] & 1) {
			continue;
		}
		HEAP_LFH_BUCKET bucket;
		ReadProcessMemory(h_proc, segheapHeader.LfhContext.Buckets[j], &bucket, sizeof(HEAP_LFH_BUCKET), &bytesRead);
		HEAP_LFH_AFFINITY_SLOT affinitySlot, *paffinitySlot;
		ReadProcessMemory(h_proc, bucket.AffinitySlots, &paffinitySlot, sizeof(PHEAP_LFH_AFFINITY_SLOT), &bytesRead);
		bucket.AffinitySlots++;
		ReadProcessMemory(h_proc, paffinitySlot, &affinitySlot, sizeof(HEAP_LFH_AFFINITY_SLOT), &bytesRead);
		WPARAM first = (WPARAM)paffinitySlot + offsetof(HEAP_LFH_SUBSEGMENT_OWNER, AvailableSubsegmentList);
		WPARAM next = (WPARAM)affinitySlot.State.AvailableSubsegmentList.Flink;
		if (!__lfh_segment_loop(h_proc, blocks, allocated, lfhKey, count, first, next)) {
			return false;
		}
		first = (WPARAM)paffinitySlot + offsetof(HEAP_LFH_SUBSEGMENT_OWNER, FullSubsegmentList);
		next = (WPARAM)affinitySlot.State.FullSubsegmentList.Flink;
		if (!__lfh_segment_loop(h_proc, blocks, allocated, lfhKey, count, first, next)) {
			return false;
		}
	}

	// Large Blocks
	if (segheapHeader.LargeAllocMetadata.Root) {
		PRTL_BALANCED_NODE node = malloc(sizeof(RTL_BALANCED_NODE));
		RzStack *s = rz_stack_new(segheapHeader.LargeReservedPages);
		PRTL_BALANCED_NODE curr = segheapHeader.LargeAllocMetadata.Root;
		do { // while (!rz_stack_is_empty(s));
			GROW_PBLOCKS();
			while (curr) {
				rz_stack_push(s, curr);
				ReadProcessMemory(h_proc, curr, node, sizeof(RTL_BALANCED_NODE), &bytesRead);
				curr = node->Left;
			};
			curr = (PRTL_BALANCED_NODE)rz_stack_pop(s);
			HEAP_LARGE_ALLOC_DATA entry;
			ReadProcessMemory(h_proc, curr, &entry, sizeof(HEAP_LARGE_ALLOC_DATA), &bytesRead);
			(*blocks)[*count].address = entry.VirtualAddess - entry.UnusedBytes; // This is a union
			(*blocks)[*count].flags = 1 | SEGMENT_HEAP_BLOCK | LARGE_BLOCK;
			(*blocks)[*count].size = ((entry.AllocatedPages >> 12) << 12);
			PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
			if (!extra) {
				return false;
			}
			extra->unusedBytes = entry.UnusedBytes;
			ReadProcessMemory(h_proc, (void *)(*blocks)[*count].address, &extra->granularity, sizeof(USHORT), &bytesRead);
			(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
			curr = entry.TreeNode.Right;
			*count += 1;
		} while (curr || !rz_stack_is_empty(s));
		rz_stack_free(s);
		free(node);
	}

	WPARAM RtlpHpHeapGlobal;
	ReadProcessMemory(h_proc, (PVOID)RtlpHpHeapGlobalsOffset, &RtlpHpHeapGlobal, sizeof(WPARAM), &bytesRead);
	// Backend Blocks (And VS)
	int i;
	for (i = 0; i < 2; i++) {
		HEAP_SEG_CONTEXT ctx = segheapHeader.SegContexts[i];
		WPARAM ctxFirstEntry = (WPARAM)heapBase + offsetof(SEGMENT_HEAP, SegContexts) + sizeof(HEAP_SEG_CONTEXT) * i + offsetof(HEAP_SEG_CONTEXT, SegmentListHead);
		HEAP_PAGE_SEGMENT pageSegment;
		WPARAM currPageSegment = (WPARAM)ctx.SegmentListHead.Flink;
		do {
			if (!ReadProcessMemory(h_proc, (PVOID)currPageSegment, &pageSegment, sizeof(HEAP_PAGE_SEGMENT), &bytesRead)) {
				break;
			}
			for (WPARAM j = 2; j < 256; j++) {
				if ((pageSegment.DescArray[j].RangeFlags &
					    (PAGE_RANGE_FLAGS_FIRST | PAGE_RANGE_FLAGS_ALLOCATED)) ==
					(PAGE_RANGE_FLAGS_FIRST | PAGE_RANGE_FLAGS_ALLOCATED)) {
					GROW_PBLOCKS();
					(*blocks)[*count].address = currPageSegment + j * 0x1000;
					(*blocks)[*count].size = (WPARAM)pageSegment.DescArray[j].UnitSize * 0x1000;
					(*blocks)[*count].flags = SEGMENT_HEAP_BLOCK | BACKEND_BLOCK | 1;
					PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
					if (!extra) {
						return false;
					}
					extra->segment = currPageSegment;
					extra->unusedBytes = pageSegment.DescArray[j].UnusedBytes;
					(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
					*count += 1;
				}
				// Hack (i don't know if all blocks like this are VS or not)
				if (pageSegment.DescArray[j].RangeFlags & 0xF && pageSegment.DescArray[j].UnusedBytes == 0x1000) {
					HEAP_VS_SUBSEGMENT vsSubsegment;
					WPARAM start, from = currPageSegment + j * 0x1000;
					ReadProcessMemory(h_proc, (PVOID)from, &vsSubsegment, sizeof(HEAP_VS_SUBSEGMENT), &bytesRead);
					// Walk through subsegment
					start = from += sizeof(HEAP_VS_SUBSEGMENT);
					while (from < (WPARAM)start + vsSubsegment.Size * sizeof(HEAP_VS_CHUNK_HEADER)) {
						HEAP_VS_CHUNK_HEADER vsChunk;
						ReadProcessMemory(h_proc, (PVOID)from, &vsChunk, sizeof(HEAP_VS_CHUNK_HEADER), &bytesRead);
						vsChunk.Sizes.HeaderBits ^= from ^ RtlpHpHeapGlobal;
						WPARAM sz = vsChunk.Sizes.UnsafeSize * sizeof(HEAP_VS_CHUNK_HEADER);
						if (vsChunk.Sizes.Allocated) {
							GROW_PBLOCKS();
							(*blocks)[*count].address = from;
							(*blocks)[*count].size = sz;
							(*blocks)[*count].flags = VS_BLOCK | SEGMENT_HEAP_BLOCK | 1;
							PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
							if (!extra) {
								return false;
							}
							extra->granularity = sizeof(HEAP_VS_CHUNK_HEADER) * 2;
							(*blocks)[*count].extra = EXTRA_FLAG | (WPARAM)extra;
							*count += 1;
						}
						from += sz;
					}
				}
			}
			currPageSegment = (WPARAM)pageSegment.ListEntry.Flink;
		} while (currPageSegment && currPageSegment != ctxFirstEntry);
	}
	return true;
}

static PDEBUG_BUFFER GetHeapBlocks(DWORD pid, RzDebug *dbg) {
	// TODO:
	// - Break this behemoth
	// - x86 vs x64 vs WOW64 (use dbg->bits or new structs or just a big union with both versions)
#if defined(_M_X64)
	if (dbg->bits == RZ_SYS_BITS_32) {
		return NULL; // Nope nope nope
	}
#endif
	WPARAM bytesRead;
	HANDLE h_proc = NULL;
	PDEBUG_BUFFER db = InitHeapInfo(dbg, PDI_HEAPS);
	if (!db || !db->HeapInformation) {
		RZ_LOG_ERROR("InitHeapInfo Failed\n");
		goto err;
	}
	h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!h_proc) {
		RZ_LOG_ERROR("OpenProcess failed\n");
		goto err;
	}

	WPARAM lfhKey;
	if (!GetLFHKey(dbg, h_proc, false, &lfhKey)) {
		RtlDestroyQueryDebugBuffer(db);
		CloseHandle(h_proc);
		eprintf("GetHeapBlocks: Failed to get LFH key.\n");
		return NULL;
	}

	PHeapInformation heapInfo = db->HeapInformation;
	int i;
	for (i = 0; i < heapInfo->count; i++) {
		WPARAM from = 0;
		ut64 count = 0;
		PDEBUG_HEAP_INFORMATION heap = &heapInfo->heaps[i];
		HEAP_ENTRY heapEntry;
		HEAP heapHeader;
		const SIZE_T sz_entry = sizeof(HEAP_ENTRY);
		ReadProcessMemory(h_proc, heap->Base, &heapHeader, sizeof(HEAP), &bytesRead);

		SIZE_T allocated = 128 * sizeof(HeapBlockBasicInfo);
		PHeapBlockBasicInfo blocks = calloc(allocated, 1);
		if (!blocks) {
			RZ_LOG_ERROR("Memory Allocation failed\n");
			goto err;
		}

		// SEGMENT_HEAP
		if (heapHeader.SegmentSignature == 0xddeeddee) {
			bool ret = GetSegmentHeapBlocks(dbg, h_proc, heap->Base, &blocks, &count, &allocated);
			heap->Blocks = blocks;
			heap->BlockCount = count;
			if (!ret) {
				goto err;
			}
			continue;
		}

		// VirtualAlloc'd blocks
		PLIST_ENTRY fentry = (PVOID)((WPARAM)heapHeader.BaseAddress + offsetof(HEAP, VirtualAllocdBlocks));
		PLIST_ENTRY entry = heapHeader.VirtualAllocdBlocks.Flink;
		while (entry && (entry != fentry)) {
			HEAP_VIRTUAL_ALLOC_ENTRY vAlloc;
			ReadProcessMemory(h_proc, entry, &vAlloc, sizeof(HEAP_VIRTUAL_ALLOC_ENTRY), &bytesRead);
			DecodeHeapEntry(dbg, &heapHeader, &vAlloc.BusyBlock);
			GROW_BLOCKS();
			blocks[count].address = (WPARAM)entry;
			blocks[count].flags = 1 | ((vAlloc.BusyBlock.Flags | NT_BLOCK | LARGE_BLOCK) & ~2ULL);
			blocks[count].size = vAlloc.ReserveSize;
			PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
			if (!extra) {
				goto err;
			}
			extra->granularity = sizeof(HEAP_VIRTUAL_ALLOC_ENTRY);
			extra->unusedBytes = vAlloc.ReserveSize - vAlloc.CommitSize;
			blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
			count++;
			entry = vAlloc.Entry.Flink;
		}

		// LFH Activated
		if (heapHeader.FrontEndHeap && heapHeader.FrontEndHeapType == 0x2) {
			LFH_HEAP lfhHeader;
			if (!ReadProcessMemory(h_proc, heapHeader.FrontEndHeap, &lfhHeader, sizeof(LFH_HEAP), &bytesRead)) {
				rz_sys_perror("ReadProcessMemory");
				goto err;
			}

			PLIST_ENTRY curEntry, firstEntry = (PVOID)((WPARAM)heapHeader.FrontEndHeap + offsetof(LFH_HEAP, SubSegmentZones));
			curEntry = lfhHeader.SubSegmentZones.Flink;

			// Loops through all _HEAP_SUBSEGMENTs
			do { // (curEntry != firstEntry)
				HEAP_LOCAL_SEGMENT_INFO info;
				HEAP_LOCAL_DATA localData;
				HEAP_SUBSEGMENT subsegment;
				HEAP_USERDATA_HEADER userdata;
				LFH_BLOCK_ZONE blockZone;

				WPARAM curSubsegment = (WPARAM)(curEntry + 2);
				int next = 0;
				do { // (next < blockZone.NextIndex)
					if (!ReadProcessMemory(h_proc, (PVOID)curSubsegment, &subsegment, sizeof(HEAP_SUBSEGMENT), &bytesRead) || !subsegment.BlockSize || !ReadProcessMemory(h_proc, subsegment.LocalInfo, &info, sizeof(HEAP_LOCAL_SEGMENT_INFO), &bytesRead) || !ReadProcessMemory(h_proc, info.LocalData, &localData, sizeof(HEAP_LOCAL_DATA), &bytesRead) || !ReadProcessMemory(h_proc, localData.CrtZone, &blockZone, sizeof(LFH_BLOCK_ZONE), &bytesRead)) {
						break;
					}

					if (!subsegment.UserBlocks || !subsegment.BlockSize) {
						goto next_subsegment;
					}

					size_t sz = subsegment.BlockSize * sizeof(HEAP_ENTRY);
					ReadProcessMemory(h_proc, subsegment.UserBlocks, &userdata, sizeof(HEAP_USERDATA_HEADER), &bytesRead);
					userdata.EncodedOffsets.StrideAndOffset ^= PtrToInt(subsegment.UserBlocks) ^ PtrToInt(heapHeader.FrontEndHeap) ^ (WPARAM)lfhKey;
					size_t bitmapsz = (userdata.BusyBitmap.SizeOfBitMap + 8 - userdata.BusyBitmap.SizeOfBitMap % 8) / 8;
					WPARAM *bitmap = calloc(bitmapsz > sizeof(WPARAM) ? bitmapsz : sizeof(WPARAM), 1);
					if (!bitmap) {
						goto err;
					}
					ReadProcessMemory(h_proc, userdata.BusyBitmap.Buffer, bitmap, bitmapsz, &bytesRead);
					WPARAM mask = 1;
					// Walk through the busy bitmap
					int j;
					size_t offset;
					for (j = 0, offset = 0; j < userdata.BusyBitmap.SizeOfBitMap; j++) {
						if (!mask) {
							mask = 1;
							offset++;
						}
						// Only if block is busy
						if (*(bitmap + offset) & mask) {
							GROW_BLOCKS();
							WPARAM off = userdata.EncodedOffsets.FirstAllocationOffset + sz * j;
							from = (WPARAM)subsegment.UserBlocks + off;
							ReadProcessMemory(h_proc, (PVOID)from, &heapEntry, sz_entry, &bytesRead);
							DecodeLFHEntry(dbg, &heapHeader, &heapEntry, subsegment.UserBlocks, lfhKey, from);
							blocks[count].address = from;
							blocks[count].flags = 1 | NT_BLOCK | LFH_BLOCK;
							blocks[count].size = sz;
							PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
							if (!extra) {
								goto err;
							}
							extra->granularity = sizeof(HEAP_ENTRY);
							extra->segment = curSubsegment;
							blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
							count++;
						}
						mask <<= 1;
					}
					free(bitmap);
				next_subsegment:
					curSubsegment += sizeof(HEAP_SUBSEGMENT);
					next++;
				} while (next < blockZone.NextIndex || subsegment.BlockSize);

				LIST_ENTRY entry;
				ReadProcessMemory(h_proc, curEntry, &entry, sizeof(entry), &bytesRead);
				curEntry = entry.Flink;
			} while (curEntry != firstEntry);
		}

		HEAP_SEGMENT oldSegment, segment;
		WPARAM firstSegment = (WPARAM)heapHeader.SegmentList.Flink;
		ReadProcessMemory(h_proc, (PVOID)(firstSegment - offsetof(HEAP_SEGMENT, SegmentListEntry)), &segment, sizeof(HEAP_SEGMENT), &bytesRead);
		// NT Blocks (Loops through all _HEAP_SEGMENTs)
		do {
			from = (WPARAM)segment.FirstEntry;
			if (!from) {
				goto next;
			}
			do {
				if (!ReadProcessMemory(h_proc, (PVOID)from, &heapEntry, sz_entry, &bytesRead)) {
					break;
				}
				DecodeHeapEntry(dbg, &heapHeader, &heapEntry);
				if (!heapEntry.Size) {
					// Last Heap block
					count--;
					break;
				}

				SIZE_T real_sz = heapEntry.Size * sz_entry;

				GROW_BLOCKS();
				PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
				if (!extra) {
					goto err;
				}
				extra->granularity = sizeof(HEAP_ENTRY);
				extra->segment = (WPARAM)segment.BaseAddress;
				blocks[count].extra = EXTRA_FLAG | (WPARAM)extra;
				blocks[count].address = from;
				blocks[count].flags = heapEntry.Flags | NT_BLOCK | BACKEND_BLOCK;
				blocks[count].size = real_sz;
				from += real_sz;
				count++;
			} while (from <= (WPARAM)segment.LastValidEntry);
		next:
			oldSegment = segment;
			from = (WPARAM)segment.SegmentListEntry.Flink - offsetof(HEAP_SEGMENT, SegmentListEntry);
			ReadProcessMemory(h_proc, (PVOID)from, &segment, sizeof(HEAP_SEGMENT), &bytesRead);
		} while ((WPARAM)oldSegment.SegmentListEntry.Flink != firstSegment);
		heap->Blocks = blocks;
		heap->BlockCount = count;

		if (!heap->Committed && !heap->Allocated) {
			heap->Committed = heapHeader.Counters.TotalMemoryCommitted;
			heap->Allocated = heapHeader.Counters.LastPolledSize;
		}
	}
	CloseHandle(h_proc);
	return db;
err:
	if (h_proc) {
		CloseHandle(h_proc);
	}
	if (db) {
		int i;
		for (i = 0; i < heapInfo->count; i++) {
			PDEBUG_HEAP_INFORMATION heap = &heapInfo->heaps[i];
			free_extra_info(heap);
			RZ_FREE(heap->Blocks);
		}
		RtlDestroyQueryDebugBuffer(db);
	}
	return NULL;
}

static PHeapBlock GetSingleSegmentBlock(RzDebug *dbg, HANDLE h_proc, PSEGMENT_HEAP heapBase, WPARAM offset) {
	// TODO:
	// - Backend (Is this needed?)
	PHeapBlock hb = RZ_NEW0(HeapBlock);
	if (!hb) {
		RZ_LOG_ERROR("GetSingleSegmentBlock: Allocation failed.\n");
		return NULL;
	}
	PHeapBlockExtraInfo extra = RZ_NEW0(HeapBlockExtraInfo);
	if (!extra) {
		RZ_LOG_ERROR("GetSingleSegmentBlock: Allocation failed.\n");
		goto err;
	}
	hb->extraInfo = extra;
	extra->heap = (WPARAM)heapBase;
	WPARAM granularity = (WPARAM)dbg->bits * 2;
	WPARAM headerOff = offset - granularity;
	SEGMENT_HEAP heap;
	ReadProcessMemory(h_proc, heapBase, &heap, sizeof(SEGMENT_HEAP), NULL);
	WPARAM RtlpHpHeapGlobal;
	ReadProcessMemory(h_proc, (PVOID)RtlpHpHeapGlobalsOffset, &RtlpHpHeapGlobal, sizeof(WPARAM), NULL);

	WPARAM pgSegOff = headerOff & heap.SegContexts[0].SegmentMask;
	WPARAM segSignature;
	ReadProcessMemory(h_proc, (PVOID)(pgSegOff + sizeof(LIST_ENTRY)), &segSignature, sizeof(WPARAM), NULL); // HEAP_PAGE_SEGMENT.Signature
	WPARAM test = RtlpHpHeapGlobal ^ pgSegOff ^ segSignature ^ ((WPARAM)heapBase + offsetof(SEGMENT_HEAP, SegContexts));
	if (test == 0xa2e64eada2e64ead) { // Hardcoded in ntdll
		HEAP_PAGE_SEGMENT segment;
		ReadProcessMemory(h_proc, (PVOID)pgSegOff, &segment, sizeof(HEAP_PAGE_SEGMENT), NULL);
		WPARAM pgRangeDescOff = ((headerOff - pgSegOff) >> heap.SegContexts[0].UnitShift) << 5;
		WPARAM pageIndex = pgRangeDescOff / sizeof(HEAP_PAGE_RANGE_DESCRIPTOR);
		if (!(segment.DescArray[pageIndex].RangeFlags & PAGE_RANGE_FLAGS_FIRST)) {
			pageIndex -= segment.DescArray[pageIndex].UnitOffset;
		}
		// VS
		WPARAM subsegmentOffset = pgSegOff + pageIndex * 0x1000;
		if (segment.DescArray[pageIndex].RangeFlags & 0xF && segment.DescArray[pageIndex].UnusedBytes == 0x1000) {
			HEAP_VS_SUBSEGMENT subsegment;
			ReadProcessMemory(h_proc, (PVOID)subsegmentOffset, &subsegment, sizeof(HEAP_VS_SUBSEGMENT), NULL);
			if ((subsegment.Size ^ 0x2BED) == subsegment.Signature) {
				HEAP_VS_CHUNK_HEADER header;
				ReadProcessMemory(h_proc, (PVOID)(headerOff - sizeof(HEAP_VS_CHUNK_HEADER)), &header, sizeof(HEAP_VS_CHUNK_HEADER), NULL);
				header.Sizes.HeaderBits ^= RtlpHpHeapGlobal ^ headerOff;
				hb->dwAddress = offset;
				hb->dwSize = header.Sizes.UnsafeSize * sizeof(HEAP_VS_CHUNK_HEADER);
				hb->dwFlags = 1 | SEGMENT_HEAP_BLOCK | VS_BLOCK;
				extra->granularity = granularity + sizeof(HEAP_VS_CHUNK_HEADER);
				extra->segment = subsegmentOffset;
				return hb;
			}
		}
		// LFH
		if (segment.DescArray[pageIndex].RangeFlags & PAGE_RANGE_FLAGS_LFH_SUBSEGMENT) {
			HEAP_LFH_SUBSEGMENT subsegment;
			ReadProcessMemory(h_proc, (PVOID)subsegmentOffset, &subsegment, sizeof(HEAP_LFH_SUBSEGMENT), NULL);
			WPARAM lfhKey;
			GetLFHKey(dbg, h_proc, true, &lfhKey);
			subsegment.BlockOffsets.EncodedData ^= (DWORD)lfhKey ^ ((DWORD)subsegmentOffset >> 0xC);
			hb->dwAddress = offset;
			hb->dwSize = subsegment.BlockOffsets.BlockSize;
			hb->dwFlags = 1 | SEGMENT_HEAP_BLOCK | LFH_BLOCK;
			extra->granularity = granularity;
			extra->segment = subsegmentOffset;
			return hb;
		}
	}

	// Try Large Blocks
	if ((offset & 0xFFFF) < 0x100) {
		if (!heap.LargeAllocMetadata.Root) {
			goto err;
		}
		RTL_BALANCED_NODE node;
		WPARAM curr = (WPARAM)heap.LargeAllocMetadata.Root;
		ReadProcessMemory(h_proc, (PVOID)curr, &node, sizeof(RTL_BALANCED_NODE), NULL);

		while (curr) {
			HEAP_LARGE_ALLOC_DATA entry;
			ReadProcessMemory(h_proc, (PVOID)curr, &entry, sizeof(HEAP_LARGE_ALLOC_DATA), NULL);
			WPARAM VirtualAddess = entry.VirtualAddess - entry.UnusedBytes;
			if ((offset & ~0xFFFFULL) > VirtualAddess) {
				curr = (WPARAM)node.Right;
			} else if ((offset & ~0xFFFFULL) < VirtualAddess) {
				curr = (WPARAM)node.Left;
			} else {
				hb->dwAddress = VirtualAddess;
				hb->dwSize = ((entry.AllocatedPages >> 12) << 12) - entry.UnusedBytes;
				hb->dwFlags = SEGMENT_HEAP_BLOCK | LARGE_BLOCK | 1;
				extra->unusedBytes = entry.UnusedBytes;
				ReadProcessMemory(h_proc, (PVOID)hb->dwAddress, &extra->granularity, sizeof(USHORT), NULL);
				return hb;
			}
			if (curr) {
				ReadProcessMemory(h_proc, (PVOID)curr, &node, sizeof(RTL_BALANCED_NODE), NULL);
			}
		}
	}
err:
	free(hb);
	free(extra);
	return NULL;
}

static PHeapBlock GetSingleBlock(RzDebug *dbg, ut64 offset) {
	PHeapBlock hb = RZ_NEW0(HeapBlock);
	PDEBUG_BUFFER db = NULL;
	PHeapBlockExtraInfo extra = NULL;

	if (!hb) {
		RZ_LOG_ERROR("GetSingleBlock: Allocation failed.\n");
		return NULL;
	}
	HANDLE h_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dbg->pid);
	if (!h_proc) {
		rz_sys_perror("GetSingleBlock/OpenProcess");
		goto err;
	}
	db = InitHeapInfo(dbg, PDI_HEAPS);
	if (!db) {
		goto err;
	}
	extra = RZ_NEW0(HeapBlockExtraInfo);
	if (!extra) {
		RZ_LOG_ERROR("GetSingleBlock: Allocation failed.\n");
		goto err;
	}
	WPARAM NtLFHKey;
	GetLFHKey(dbg, h_proc, false, &NtLFHKey);
	PHeapInformation heapInfo = db->HeapInformation;
	int i;
	for (i = 0; i < heapInfo->count; i++) {
		DEBUG_HEAP_INFORMATION heap = heapInfo->heaps[i];
		if (is_segment_heap(h_proc, heap.Base)) {
			free(hb);
			RZ_FREE(extra);
			hb = GetSingleSegmentBlock(dbg, h_proc, heap.Base, offset);
			if (!hb) {
				goto err;
			}
			break;
		} else {
			HEAP h;
			HEAP_ENTRY entry;
			WPARAM entryOffset = offset - heap.Granularity;
			if (!ReadProcessMemory(h_proc, heap.Base, &h, sizeof(HEAP), NULL) ||
				!ReadProcessMemory(h_proc, (PVOID)entryOffset, &entry, sizeof(HEAP_ENTRY), NULL)) {
				goto err;
			}
			extra->granularity = heap.Granularity;
			hb->extraInfo = extra;
			HEAP_ENTRY tmpEntry = entry;
			if (DecodeHeapEntry(dbg, &h, &tmpEntry)) {
				entry = tmpEntry;
				hb->dwAddress = offset;
				UPDATE_FLAGS(hb, (DWORD)entry.Flags | NT_BLOCK);
				if (entry.UnusedBytes == 0x4) {
					HEAP_VIRTUAL_ALLOC_ENTRY largeEntry;
					if (ReadProcessMemory(h_proc, (PVOID)(offset - sizeof(HEAP_VIRTUAL_ALLOC_ENTRY)), &largeEntry, sizeof(HEAP_VIRTUAL_ALLOC_ENTRY), NULL)) {
						hb->dwSize = largeEntry.CommitSize;
						hb->dwFlags |= LARGE_BLOCK;
						extra->unusedBytes = largeEntry.ReserveSize - largeEntry.CommitSize;
						extra->granularity = sizeof(HEAP_VIRTUAL_ALLOC_ENTRY);
					}
				} else {
					hb->dwSize = (WPARAM)entry.Size * heap.Granularity;
					hb->dwFlags |= BACKEND_BLOCK;
				}
				break;
			}
			// LFH
			if (entry.UnusedBytes & 0x80) {
				tmpEntry = entry;
				WPARAM userBlocksOffset;
				if (dbg->bits == RZ_SYS_BITS_64) {
					*(((WPARAM *)&tmpEntry) + 1) ^= PtrToInt(h.BaseAddress) ^ (entryOffset >> 0x4) ^ (DWORD)NtLFHKey;
					userBlocksOffset = entryOffset - (USHORT)((*(((WPARAM *)&tmpEntry) + 1)) >> 0xC);
				} else {
					*((WPARAM *)&tmpEntry) ^= PtrToInt(h.BaseAddress) ^ ((DWORD)(entryOffset) >> 0x4) ^ (DWORD)NtLFHKey;
					userBlocksOffset = entryOffset - (USHORT)(*((WPARAM *)&tmpEntry) >> 0xC);
				}
				// Confirm it is LFH
				if (DecodeLFHEntry(dbg, &h, &entry, (PVOID)userBlocksOffset, NtLFHKey, entryOffset)) {
					HEAP_USERDATA_HEADER UserBlocks;
					HEAP_SUBSEGMENT subsegment;
					if (!ReadProcessMemory(h_proc, (PVOID)userBlocksOffset, &UserBlocks, sizeof(HEAP_USERDATA_HEADER), NULL)) {
						rz_sys_perror("GetSingleBlock/ReadProcessMemory");
						continue;
					}
					if (!ReadProcessMemory(h_proc, (PVOID)UserBlocks.SubSegment, &subsegment, sizeof(HEAP_SUBSEGMENT), NULL)) {
						continue;
					}
					hb->dwAddress = offset;
					hb->dwSize = (WPARAM)subsegment.BlockSize * heap.Granularity;
					hb->dwFlags = 1 | LFH_BLOCK | NT_BLOCK;
					break;
				}
			}
		}
	}
	if (!hb->dwSize) {
		goto err;
	}
	RtlDestroyQueryDebugBuffer(db);
	CloseHandle(h_proc);
	return hb;
err:
	if (h_proc) {
		CloseHandle(h_proc);
	}
	if (db) {
		RtlDestroyQueryDebugBuffer(db);
	}
	free(hb);
	free(extra);
	return NULL;
}

static RzTable *__new_heapblock_tbl(void) {
	RzTable *tbl = rz_table_new();
	rz_table_add_column(tbl, rz_table_type("number"), "HeaderAddress", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "UserAddress", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Size", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Granularity", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Unused", -1);
	rz_table_add_column(tbl, rz_table_type("String"), "Type", -1);
	return tbl;
}

RZ_IPI void rz_heap_list_w32(RzCore *core, RzOutputMode mode) {
	initialize_windows_ntdll_query_api_functions();
	ULONG pid = core->dbg->pid;
	PDEBUG_BUFFER db = InitHeapInfo(core->dbg, PDI_HEAPS | PDI_HEAP_BLOCKS);
	if (!db) {
		if (__is_windows_ten()) {
			db = GetHeapBlocks(pid, core->dbg);
		}
		if (!db) {
			eprintf("Couldn't get heap info.\n");
			return;
		}
	}
	PHeapInformation heapInfo = db->HeapInformation;
	CHECK_INFO(heapInfo);
	int i;
	RzTable *tbl = rz_table_new();
	rz_table_add_column(tbl, rz_table_type("number"), "Address", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Blocks", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Allocated", -1);
	rz_table_add_column(tbl, rz_table_type("number"), "Commited", -1);
	PJ *pj = pj_new();
	pj_a(pj);
	for (i = 0; i < heapInfo->count; i++) {
		DEBUG_HEAP_INFORMATION heap = heapInfo->heaps[i];
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_o(pj);
			pj_kN(pj, "address", (ut64)heap.Base);
			pj_kN(pj, "count", (ut64)heap.BlockCount);
			pj_kN(pj, "allocated", (ut64)heap.Allocated);
			pj_kN(pj, "committed", (ut64)heap.Committed);
			pj_end(pj);
		} else {
			rz_table_add_rowf(tbl, "xnnn", (ut64)heap.Base, (ut64)heap.BlockCount, (ut64)heap.Allocated, (ut64)heap.Committed);
		}
		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			free_extra_info(&heap);
			RZ_FREE(heap.Blocks);
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
	} else {
		rz_cons_println(rz_table_tostring(tbl));
	}
	rz_table_free(tbl);
	pj_free(pj);
	RtlDestroyQueryDebugBuffer(db);
}

static void w32_list_heaps_blocks(RzCore *core, RzOutputMode mode, bool flag) {
	DWORD pid = core->dbg->pid;
	PDEBUG_BUFFER db;
	if (__is_windows_ten()) {
		db = GetHeapBlocks(pid, core->dbg);
	} else {
		db = InitHeapInfo(core->dbg, PDI_HEAPS | PDI_HEAP_BLOCKS);
	}
	if (!db) {
		eprintf("Couldn't get heap info.\n");
		return;
	}
	PHeapInformation heapInfo = db->HeapInformation;
	CHECK_INFO(heapInfo);
	HeapBlock *block = malloc(sizeof(HeapBlock));
	int i;
	RzTable *tbl = __new_heapblock_tbl();
	PJ *pj = pj_new();
	pj_a(pj);
	for (i = 0; i < heapInfo->count; i++) {
		bool go = true;
		if (flag) {
			if (heapInfo->heaps[i].BlockCount > 50000) {
				go = rz_cons_yesno('n', "Are you sure you want to add %lu flags? (y/N)", heapInfo->heaps[i].BlockCount);
			}
		} else if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_o(pj);
			pj_kN(pj, "heap", (WPARAM)heapInfo->heaps[i].Base);
			pj_k(pj, "blocks");
			pj_a(pj);
		}

		char *type;
		if (GetFirstHeapBlock(&heapInfo->heaps[i], block) & go) {
			do {
				type = get_type(block->dwFlags);
				if (!type) {
					type = "";
				}
				ut64 granularity = block->extraInfo ? block->extraInfo->granularity : heapInfo->heaps[i].Granularity;
				ut64 address = (ut64)block->dwAddress - granularity;
				ut64 unusedBytes = block->extraInfo ? block->extraInfo->unusedBytes : 0;
				if (flag) {
					char *name = rz_str_newf("alloc.%" PFMT64x "", address);
					if (!rz_flag_set(core->flags, name, address, block->dwSize)) {
						eprintf("Flag couldn't be set for block at 0x%" PFMT64x, address);
					}
					free(name);
				} else if (mode == RZ_OUTPUT_MODE_JSON) {
					pj_o(pj);
					pj_kN(pj, "header_address", address);
					pj_kN(pj, "user_address", (ut64)block->dwAddress);
					pj_kN(pj, "unused", unusedBytes);
					pj_kN(pj, "size", block->dwSize);
					pj_ks(pj, "type", type);
					pj_end(pj);
				} else {
					rz_table_add_rowf(tbl, "xxnnns", address, (ut64)block->dwAddress, block->dwSize, granularity, unusedBytes, type);
				}
			} while (GetNextHeapBlock(&heapInfo->heaps[i], block));
		}
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_end(pj);
			pj_end(pj);
		}
		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			// RtlDestroyQueryDebugBuffer wont free this for some reason
			free_extra_info(&heapInfo->heaps[i]);
			RZ_FREE(heapInfo->heaps[i].Blocks);
		}
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
	} else if (!flag) {
		rz_cons_println(rz_table_tostring(tbl));
	}
	rz_table_free(tbl);
	pj_free(pj);
	RtlDestroyQueryDebugBuffer(db);
}

RZ_IPI void rz_heap_debug_block_win(RzCore *core, const char *addr, RzOutputMode mode, bool flag) {
	initialize_windows_ntdll_query_api_functions();
	ut64 off = 0;
	if (!addr) {
		w32_list_heaps_blocks(core, mode, flag);
		return;
	}

	off = rz_num_math(core->num, addr);
	PHeapBlock hb = GetSingleBlock(core->dbg, off);
	if (!hb) {
		return;
	}
	ut64 granularity = hb->extraInfo->granularity;
	char *type = get_type(hb->dwFlags);
	if (!type) {
		type = "";
	}
	PJ *pj = pj_new();
	RzTable *tbl = __new_heapblock_tbl();
	ut64 headerAddr = off - granularity;
	if (mode == RZ_OUTPUT_MODE_STANDARD) {
		rz_table_add_rowf(tbl, "xxnnns", headerAddr, off, (ut64)hb->dwSize, granularity, (ut64)hb->extraInfo->unusedBytes, type);
		rz_cons_println(rz_table_tostring(tbl));
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(pj);
		pj_kN(pj, "header_address", headerAddr);
		pj_kN(pj, "user_address", off);
		pj_ks(pj, "type", type);
		pj_kN(pj, "size", hb->dwSize);
		if (hb->extraInfo->unusedBytes) {
			pj_kN(pj, "unused", hb->extraInfo->unusedBytes);
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
	}
	free(hb->extraInfo);
	free(hb);
	rz_table_free(tbl);
	pj_free(pj);
}

RZ_IPI RzList *rz_heap_blocks_list(RzCore *core) {
	initialize_windows_ntdll_query_api_functions();
	DWORD pid = core->dbg->pid;
	PDEBUG_BUFFER db;
	RzList *blocks_list = rz_list_newf(free);
	if (__is_windows_ten()) {
		db = GetHeapBlocks(pid, core->dbg);
	} else {
		db = InitHeapInfo(core->dbg, PDI_HEAPS | PDI_HEAP_BLOCKS);
	}
	if (!db) {
		eprintf("Couldn't get heap info.\n");
		return blocks_list;
	}

	PHeapInformation heapInfo = db->HeapInformation;
	CHECK_INFO_RETURN_NULL(heapInfo);
	HeapBlock *block = malloc(sizeof(HeapBlock));
	for (int i = 0; i < heapInfo->count; i++) {
		bool go = true;
		char *type;
		if (GetFirstHeapBlock(&heapInfo->heaps[i], block) & go) {
			do {
				type = get_type(block->dwFlags);
				if (!type) {
					type = "";
				}
				ut64 granularity = block->extraInfo ? block->extraInfo->granularity : heapInfo->heaps[i].Granularity;
				ut64 address = (ut64)block->dwAddress - granularity;
				ut64 unusedBytes = block->extraInfo ? block->extraInfo->unusedBytes : 0;

				// add blocks to list
				RzWindowsHeapBlock *heap_block = RZ_NEW0(RzWindowsHeapBlock);
				if (!heap_block) {
					rz_list_free(blocks_list);
					RtlDestroyQueryDebugBuffer(db);
					return NULL;
				}
				heap_block->headerAddress = address;
				heap_block->userAddress = (ut64)block->dwAddress;
				heap_block->size = block->dwSize;
				strcpy(heap_block->type, type);
				heap_block->unusedBytes = unusedBytes;
				heap_block->granularity = granularity;

				rz_list_append(blocks_list, heap_block);
			} while (GetNextHeapBlock(&heapInfo->heaps[i], block));
		}
		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			// RtlDestroyQueryDebugBuffer wont free this for some reason
			free_extra_info(&heapInfo->heaps[i]);
			RZ_FREE(heapInfo->heaps[i].Blocks);
		}
	}
	RtlDestroyQueryDebugBuffer(db);
	return blocks_list;
}

RZ_IPI RzList *rz_heap_list(RzCore *core) {
	initialize_windows_ntdll_query_api_functions();
	ULONG pid = core->dbg->pid;
	PDEBUG_BUFFER db = InitHeapInfo(core->dbg, PDI_HEAPS | PDI_HEAP_BLOCKS);
	if (!db) {
		if (__is_windows_ten()) {
			db = GetHeapBlocks(pid, core->dbg);
		}
		if (!db) {
			eprintf("Couldn't get heap info.\n");
			return NULL;
		}
	}

	RzList *heaps_list = rz_list_newf(free);
	PHeapInformation heapInfo = db->HeapInformation;
	CHECK_INFO_RETURN_NULL(heapInfo);
	for (int i = 0; i < heapInfo->count; i++) {
		DEBUG_HEAP_INFORMATION heap = heapInfo->heaps[i];
		// add heaps to list
		RzWindowsHeapInfo *rzHeapInfo = RZ_NEW0(RzWindowsHeapInfo);
		if (!rzHeapInfo) {
			rz_list_free(heaps_list);
			RtlDestroyQueryDebugBuffer(db);
			return NULL;
		}
		rzHeapInfo->base = (ut64)heap.Base;
		rzHeapInfo->blockCount = (ut64)heap.BlockCount;
		rzHeapInfo->allocated = (ut64)heap.Allocated;
		rzHeapInfo->committed = (ut64)heap.Committed;

		rz_list_append(heaps_list, rzHeapInfo);

		if (!(db->InfoClassMask & PDI_HEAP_BLOCKS)) {
			free_extra_info(&heap);
			RZ_FREE(heap.Blocks);
		}
	}

	RtlDestroyQueryDebugBuffer(db);
	return heaps_list;
}