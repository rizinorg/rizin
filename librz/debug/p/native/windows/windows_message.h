#include <rz_types.h>

typedef struct _window {
	DWORD pid;
	DWORD tid;
	HANDLE h;
	char *name;
	ut64 proc;
} window;

RZ_API bool rz_w32_add_winmsg_breakpoint(RzDebug *dbg, const char *input);
RZ_API void rz_w32_identify_window(void);
RZ_API void rz_w32_print_windows(RzDebug *dbg);
