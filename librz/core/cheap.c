#include <rz_core.h>
#include "core_private.h"

/* API calls of windows heap for Cutter */
#if __WINDOWS__
RZ_API RzList *rz_heap_windows_blocks_list(RzCore *core) {
	return rz_heap_blocks_list(core);
}

RZ_API RzList *rz_heap_windows_heap_list(RzCore *core) {
	return rz_heap_list(core);
}
#else

RZ_API RzList *rz_heap_windows_blocks_list(RzCore *core) {
	return NULL;
}

RZ_API RzList *rz_heap_windows_heap_list(RzCore *core) {
	return NULL;
}

#endif
