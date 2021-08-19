// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <DbgHelp.h>
#include <w32dbg_wrap.h>

#define DEF_PROC(proc) proc##_t *w32_##proc
#define GET_PROC(proc) \
	w32_##proc = (proc##_t *)GetProcAddress(dbghelp, #proc); \
	if (!w32_##proc) { \
		return false; \
	}

typedef BOOL __stdcall SymInitialize_t(
	_In_ HANDLE hProcess,
	_In_opt_ PCSTR UserSearchPath,
	_In_ BOOL fInvadeProcess);

typedef BOOL __stdcall SymCleanup_t(
	_In_ HANDLE hProcess);

typedef PVOID __stdcall SymFunctionTableAccess64_t(
	_In_ HANDLE hProcess,
	_In_ DWORD64 AddrBase);

typedef DWORD64 __stdcall SymGetModuleBase64_t(
	_In_ HANDLE hProcess,
	_In_ DWORD64 qwAddr);

typedef BOOL __stdcall StackWalk64_t(
	_In_ DWORD MachineType,
	_In_ HANDLE hProcess,
	_In_ HANDLE hThread,
	_Inout_ LPSTACKFRAME64 StackFrame,
	_Inout_ PVOID ContextRecord,
	_In_opt_ PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
	_In_opt_ PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
	_In_opt_ PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
	_In_opt_ PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);

DEF_PROC(SymInitialize);
DEF_PROC(SymCleanup);
DEF_PROC(SymFunctionTableAccess64);
DEF_PROC(SymGetModuleBase64);
DEF_PROC(StackWalk64);

static inline bool initialize_sym_api(void) {
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	HMODULE dbghelp = LoadLibrary(TEXT("DbgHelp"));
	if (!dbghelp) {
		return false;
	}
	GET_PROC(SymInitialize);
	GET_PROC(SymCleanup);
	GET_PROC(SymFunctionTableAccess64);
	GET_PROC(SymGetModuleBase64);
	GET_PROC(StackWalk64);
	initialized = true;
	return true;
}

static RzList *backtrace_windows(RzDebug *dbg, ut64 at) {
	initialize_sym_api();
	static RzThreadLock *lock = NULL;
	if (!lock) {
		lock = rz_th_lock_new(false);
		if (!lock) {
			return NULL;
		}
	}
	W32DbgWInst *wrap = dbg->plugin_data;
#if __arm64__
	DWORD machine_type = IMAGE_FILE_MACHINE_ARM64;
#elif __arm__
	DWORD machine_type = IMAGE_FILE_MACHINE_ARMNT;
#elif __x86_64__
	DWORD machine_type = IMAGE_FILE_MACHINE_AMD64;
#else
	DWORD machine_type = IMAGE_FILE_MACHINE_I386;
#endif
	STACKFRAME64 stack = { 0 };
	stack.AddrFrame.Mode = AddrModeFlat;
	stack.AddrFrame.Offset = rz_reg_getv(dbg->reg, rz_reg_get_name(dbg->reg, RZ_REG_NAME_BP));
	stack.AddrStack.Mode = AddrModeFlat;
	stack.AddrStack.Offset = rz_reg_getv(dbg->reg, rz_reg_get_name(dbg->reg, RZ_REG_NAME_SP));
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrPC.Offset = rz_reg_getv(dbg->reg, rz_reg_get_name(dbg->reg, RZ_REG_NAME_PC));

	RzList *list = rz_list_newf(free);
	if (!list) {
		return NULL;
	}
	CONTEXT *ctx = (CONTEXT *)rz_reg_arena_peek(dbg->reg);
	rz_th_lock_enter(lock);
	w32_SymInitialize(wrap->pi.hProcess, NULL, TRUE);
	while (w32_StackWalk64(machine_type, wrap->pi.hProcess, wrap->pi.hThread, &stack, ctx, NULL, w32_SymFunctionTableAccess64, w32_SymGetModuleBase64, NULL)) {
		RzDebugFrame *frame = RZ_NEW0(RzDebugFrame);
		if (!frame) {
			break;
		}
		frame->addr = stack.AddrPC.Offset;
		frame->bp = stack.AddrFrame.Offset;
		frame->sp = stack.AddrStack.Offset;
		frame->size = frame->bp - frame->sp;
		if (!rz_list_append(list, frame)) {
			free(frame);
			break;
		}
	}
	w32_SymCleanup(wrap->pi.hProcess);
	rz_th_lock_leave(lock);
	free(ctx);
	return list;
}

#undef DEF_PROC
#undef GET_PROC
