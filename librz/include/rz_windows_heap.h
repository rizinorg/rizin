#ifndef RZ_WINDOWS_HEAP_H
#define RZ_WINDOWS_HEAP_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_heap_block {
	ut64 userAddress;
	ut64 headerAddress;
	ut64 granularity;
	ut64 unusedBytes;
	char type[100];
	ut64 size;
} RzWindowsHeapBlock;

typedef struct rz_heap_info {
	ut64 base;
	ut64 blockCount;
	ut64 allocated;
	ut64 committed;
} RzWindowsHeapInfo;

#ifdef __cplusplus
}
#endif

#endif //
