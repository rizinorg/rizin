// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#if __WINDOWS__
#include <windows.h>
#endif

static RzCore *core = NULL;

#if __UNIX__

// XXX check if its already opened
static RzCoreFile *openself(void) {
	RzCoreFile *fd = NULL;
	char *out = rz_core_cmd_str(core, "o");
	if (out) {
		if (!strstr(out, "self://")) {
			fd = rz_core_file_open(core, "self://", RZ_PERM_RW, 0);
		}
		free(out);
	}
	return fd;
}

static void sigusr1(int s) {
	RzCoreFile *fd = openself();
	rz_core_prompt_loop(core);
	rz_core_file_close(core, fd);
}

static void sigusr2(int s) {
	(void)openself();
	rz_core_cmd0(core, "=H&");
}

static void _libwrap_init() __attribute__((constructor));
static void _libwrap_init(void) {
	char *web;
	rz_sys_signal(SIGUSR1, sigusr1);
	rz_sys_signal(SIGUSR2, sigusr2);
	printf("librz initialized. send SIGUSR1 to %d in order to reach the rizin prompt\n", getpid());
	printf("kill -USR1 %d\n", getpid());
	fflush(stdout);
	web = rz_sys_getenv("RZ_RUN_WEB");
	core = rz_core_new();
	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL, NULL);
	if (web) {
		rz_core_cmd0(core, "=H&");
		rz_sys_setenv("RZ_RUN_WEB", NULL);
		free(web);
	}
	// TODO: maybe reopen every time a signal is spawned to reload memory regions information
	// TODO: open io_self
}
#elif __WINDOWS__
void alloc_console(void) {
	CONSOLE_SCREEN_BUFFER_INFO coninfo;
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD lpMode;

	AllocConsole();
	GetConsoleMode(hStdin, &lpMode);
	SetConsoleMode(hStdin, lpMode & (~ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT));
	GetConsoleScreenBufferInfo(hStdin, &coninfo);
	coninfo.dwSize.Y = 4096;
	SetConsoleScreenBufferSize(hStdin, coninfo.dwSize);

	rz_xfreopen("conin$", "r", stdin);
	rz_xfreopen("conout$", "w", stdout);
	rz_xfreopen("conout$", "w", stderr);
}

static void start_rz(void) {
	core = rz_core_new();
	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL, NULL);
	RzCoreFile *fd = rz_core_file_open(core, "self://", RZ_PERM_RW, 0);
	rz_core_prompt_loop(core);
	rz_core_file_close(core, fd);
}

/**
 * Neat little helper function to later enable injecting without
 * a .exe
 * simply call: rundll32.exe librz.dll,rundll_inject 0,0,0,0
 * TODO: implement all injecting methods
 */
void rundll_inject(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	/* do something here */
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD result, LPVOID lpReserved) {
	switch (result) {
	case DLL_PROCESS_DETACH:
		break;
	case DLL_PROCESS_ATTACH:
		alloc_console();
		start_rz();
		break;
	}
	return 1;
}
#endif
