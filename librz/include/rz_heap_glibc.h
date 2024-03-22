#ifndef RZ_HEAP_GLIBC_H
#define RZ_HEAP_GLIBC_H

#include <rz_types.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_heap_glibc);

#define PRINTF_A(color, fmt, ...) rz_cons_printf("%s" fmt "%s", \
	rz_config_get_b(core->config, "scr.color") ? color : "", \
	__VA_ARGS__, \
	rz_config_get_b(core->config, "scr.color") ? Color_RESET : "")
#define PRINTF_YA(fmt, ...) PRINTF_A(pal->offset, fmt, __VA_ARGS__)
#define PRINTF_GA(fmt, ...) PRINTF_A(pal->args, fmt, __VA_ARGS__)
#define PRINTF_BA(fmt, ...) PRINTF_A(pal->num, fmt, __VA_ARGS__)
#define PRINTF_RA(fmt, ...) PRINTF_A(pal->invalid, fmt, __VA_ARGS__)

#define PRINT_A(color, msg) rz_cons_printf("%s%s%s", \
	rz_config_get_b(core->config, "scr.color") ? color : "", \
	msg, \
	rz_config_get_b(core->config, "scr.color") ? Color_RESET : "")
#define PRINT_YA(msg) PRINT_A(pal->offset, msg)
#define PRINT_GA(msg) PRINT_A(pal->args, msg)
#define PRINT_BA(msg) PRINT_A(pal->num, msg)
#define PRINT_RA(msg) PRINT_A(pal->invalid, msg)

#define PREV_INUSE     0x1
#define IS_MMAPPED     0x2
#define NON_MAIN_ARENA 0x4

#define NBINS                  128
#define NSMALLBINS             64
#define NFASTBINS              10
#define BINMAPSHIFT            5
#define SZ                     core->dbg->bits
#define FASTBIN_IDX_TO_SIZE(i) ((SZ * 4) + (SZ * 2) * (i - 1))
#define BITSPERMAP             (1U << BINMAPSHIFT)
#define BINMAPSIZE             (NBINS / BITSPERMAP)
#define NPAD                   -6
#define TCACHE_MAX_BINS        64
#define TCACHE_FILL_COUNT      7
#define TCACHE_NEW_VERSION     230

#define MMAP_ALIGN_32 0x14
#define MMAP_ALIGN_64 0x18
#define MMAP_OFFSET   0x8

#define HDR_SZ_32          0x8
#define HDR_SZ_64          0x10
#define TC_HDR_SZ          0x10
#define TC_SZ_32           0x0
#define TC_SZ_64           0x10
#define HEAP_PAGE_SIZE     0x21000
#define HEAP_PAGE_SIZE_X86 0x22000

// Introduced with glibc 2.32

#define largebin_index_32(size) \
	(((((ut32)(size)) >> 6) <= 38) ? 56 + (((ut32)(size)) >> 6) : ((((ut32)(size)) >> 9) <= 20) ? 91 + (((ut32)(size)) >> 9) \
			: ((((ut32)(size)) >> 12) <= 10)                                            ? 110 + (((ut32)(size)) >> 12) \
			: ((((ut32)(size)) >> 15) <= 4)                                             ? 119 + (((ut32)(size)) >> 15) \
			: ((((ut32)(size)) >> 18) <= 2)                                             ? 124 + (((ut32)(size)) >> 18) \
												    : 126)
#define largebin_index_32_big(size) \
	(((((ut32)(size)) >> 6) <= 45) ? 49 + (((ut32)(size)) >> 6) : ((((ut32)(size)) >> 9) <= 20) ? 91 + (((ut32)(size)) >> 9) \
			: ((((ut32)(size)) >> 12) <= 10)                                            ? 110 + (((ut32)(size)) >> 12) \
			: ((((ut32)(size)) >> 15) <= 4)                                             ? 119 + (((ut32)(size)) >> 15) \
			: ((((ut32)(size)) >> 18) <= 2)                                             ? 124 + (((ut32)(size)) >> 18) \
												    : 126)
#define largebin_index_64(size) \
	(((((ut32)(size)) >> 6) <= 48) ? 48 + (((ut32)(size)) >> 6) : ((((ut32)(size)) >> 9) <= 20) ? 91 + (((ut32)(size)) >> 9) \
			: ((((ut32)(size)) >> 12) <= 10)                                            ? 110 + (((ut32)(size)) >> 12) \
			: ((((ut32)(size)) >> 15) <= 4)                                             ? 119 + (((ut32)(size)) >> 15) \
			: ((((ut32)(size)) >> 18) <= 2)                                             ? 124 + (((ut32)(size)) >> 18) \
												    : 126)

#define largebin_index(size) \
	(SZ == 8 ? largebin_index_64(size) : largebin_index_32(size))

#define fastbin_index(size) \
	(SZ == 8 ? (size >> 4) - 2 : (size >> 3) - 2)
/* Not works 32 bit on 64 emulation
#define largebin_index(size) \
  (SZ == 8 ? largebin_index_64 (size)                          \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (size)     \
   : largebin_index_32 (size))
*/

typedef struct rz_malloc_chunk_64 {
	ut64 prev_size; /* Size of previous chunk (if free).  */
	ut64 size; /* Size in bytes, including overhead. */

	ut64 fd; /* double links -- used only if free. */
	ut64 bk;

	/* Only used for large blocks: pointer to next larger size.  */
	ut64 fd_nextsize; /* double links -- used only if free. */
	ut64 bk_nextsize;
} RzHeapChunk_64;

typedef struct rz_malloc_chunk_32 {
	ut32 prev_size; /* Size of previous chunk (if free).  */
	ut32 size; /* Size in bytes, including overhead. */

	ut32 fd; /* double links -- used only if free. */
	ut32 bk;

	/* Only used for large blocks: pointer to next larger size.  */
	ut32 fd_nextsize; /* double links -- used only if free. */
	ut32 bk_nextsize;
} RzHeapChunk_32;

/*
typedef RzHeapChunk64 *mfastbinptr64;
typedef RzHeapChunk64 *mchunkptr64;

typedef RzHeapChunk32 *mfastbinptr32;
typedef RzHeapChunk32 *mchunkptr32;
*/

typedef struct rz_malloc_state_32 {
	int mutex; /* serialized access */
	int flags; /* flags */
	int have_fastchunks; /* new free blocks in fastbin chunks? */
	ut32 fastbinsY[NFASTBINS]; /* array of fastchunks */
	ut32 top; /* top chunk's base addr */
	ut32 last_remainder; /* remainder top chunk's addr */
	ut32 bins[NBINS * 2 - 2]; /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; /* bitmap of bins */
	ut32 next; /* double linked list of chunks */
	ut32 next_free; /* double linked list of free chunks */
	unsigned int attached_threads; /* threads attached */
	ut32 system_mem; /* current allocated memory of current arena */
	ut32 max_system_mem; /* maximum system memory */
} RzHeap_MallocState_32;

typedef struct rz_malloc_state_64 {
	int mutex; /* serialized access */
	int flags; /* flags */
	int have_fastchunks; /* new free blocks in fastbin chunks? */
	ut64 fastbinsY[NFASTBINS]; /* array of fastchunks */
	ut64 top; /* top chunk's base addr */
	ut64 last_remainder; /* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2]; /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; /* bitmap of bins */
	ut64 next; /* double linked list of chunks */
	ut64 next_free; /* double linked list of free chunks */
	unsigned int attached_threads; /* threads attached */
	ut64 system_mem; /* current allocated memory of current arena */
	ut64 max_system_mem; /* maximum system memory */
} RzHeap_MallocState_64;

typedef struct rz_tcache_perthread_struct_32 {
	ut16 counts[TCACHE_MAX_BINS];
	ut32 entries[TCACHE_MAX_BINS];
} RzHeapTcache_32;

typedef struct rz_tcache_perthread_struct_64 {
	ut16 counts[TCACHE_MAX_BINS];
	ut64 entries[TCACHE_MAX_BINS];
} RzHeapTcache_64;

typedef struct rz_tcache_perthread_struct_pre_230_32 {
	ut8 counts[TCACHE_MAX_BINS];
	ut32 entries[TCACHE_MAX_BINS];
} RzHeapTcachePre230_32;

typedef struct rz_tcache_perthread_struct_pre_230_64 {
	ut8 counts[TCACHE_MAX_BINS];
	ut64 entries[TCACHE_MAX_BINS];
} RzHeapTcachePre230_64;

typedef enum { NEW,
	OLD } tcache_type;

typedef struct {
	tcache_type type;
	union {
		RzHeapTcache_64 *heap_tcache;
		RzHeapTcachePre230_64 *heap_tcache_pre_230;
	} RzHeapTcache;
} RTcache_64;

typedef struct {
	tcache_type type;
	union {
		RzHeapTcache_32 *heap_tcache;
		RzHeapTcachePre230_32 *heap_tcache_pre_230;
	} RzHeapTcache;
} RTcache_32;

typedef struct rz_malloc_state_tcache_32 {
	int mutex; /* serialized access */
	int flags; /* flags */
	int have_fast_chunks; /* have fast chunks */
	ut32 fastbinsY[NFASTBINS + 1]; /* array of fastchunks */
	ut32 top; /* top chunk's base addr */
	ut32 last_remainder; /* remainder top chunk's addr */
	ut32 bins[NBINS * 2 - 2]; /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; /* bitmap of bins */
	ut32 next; /* double linked list of chunks */
	ut32 next_free; /* double linked list of free chunks */
	unsigned int attached_threads; /* threads attached */
	ut32 system_mem; /* current allocated memory of current arena */
	ut32 max_system_mem; /* maximum system memory */
} RzHeap_MallocState_tcache_32;

typedef struct rz_malloc_state_tcache_64 {
	int mutex; /* serialized access */
	int flags; /* flags */
	int have_fast_chunks; /* have fast chunks */
	ut64 fastbinsY[NFASTBINS]; /* array of fastchunks */
	ut64 top; /* top chunk's base addr */
	ut64 last_remainder; /* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2]; /* array of remainder free chunks */
	unsigned int binmap[BINMAPSIZE]; /* bitmap of bins */
	ut64 next; /* double linked list of chunks */
	ut64 next_free; /* double linked list of free chunks */
	unsigned int attached_threads; /* threads attached */
	ut64 system_mem; /* current allocated memory of current arena */
	ut64 max_system_mem; /* maximum system memory */
} RzHeap_MallocState_tcache_64;

typedef struct rz_malloc_state {
	int mutex; /* serialized access */
	int flags; /* flags */
	unsigned int binmap[BINMAPSIZE]; /* bitmap of bins */

	/*tcache*/
	int have_fast_chunks; /* have fast chunks */
	unsigned int attached_threads; /* threads attached */

	/*64 bits members */
	ut64 fastbinsY[NFASTBINS]; /* array of fastchunks */
	ut64 top; /* top chunk's base addr */
	ut64 last_remainder; /* remainder top chunk's addr */
	ut64 bins[NBINS * 2 - 2]; /* array of remainder free chunks */
	ut64 next; /* double linked list of chunks */
	ut64 next_free; /* double linked list of free chunks */
	ut64 system_mem; /* current allocated memory of current arena */
	ut64 max_system_mem; /* maximum system memory */
} MallocState;

typedef struct rz_heap_info_32 {
	ut32 ar_ptr; /* Arena for this heap. */
	ut32 prev; /* Previous heap. */
	ut32 size; /* Current size in bytes. */
	ut32 mprotect_size; /* Size in bytes that has been mprotected PROT_READ|PROT_WRITE.  */

	/* Make sure the following data is properly aligned, particularly
	that sizeof (heap_info) + 2 * SZ is a multiple of
	MALLOC_ALIGNMENT. */
	/* char pad[NPAD * SZ & MALLOC_ALIGN_MASK]; */
} RzHeapInfo_32;

typedef struct rz_heap_info_64 {
	ut64 ar_ptr; /* Arena for this heap. */
	ut64 prev; /* Previous heap. */
	ut64 size; /* Current size in bytes. */
	ut64 mprotect_size; /* Size in bytes that has been mprotected PROT_READ|PROT_WRITE.  */

	/* Make sure the following data is properly aligned, particularly
	that sizeof (heap_info) + 2 * SZ is a multiple of
	MALLOC_ALIGNMENT. */
	/* char pad[NPAD * SZ & MALLOC_ALIGN_MASK]; */
} RzHeapInfo_64;

typedef enum rz_heap_bin_type {
	RZ_HEAP_BIN_ANY,
	RZ_HEAP_BIN_TCACHE,
	RZ_HEAP_BIN_FAST,
	RZ_HEAP_BIN_UNSORTED,
	RZ_HEAP_BIN_SMALL,
	RZ_HEAP_BIN_LARGE
} RzHeapBinType;

typedef struct rz_heap_chunk_list_item {
	ut64 addr; /* Base addr of the chunk */
	ut64 size; /* Size of the chunk */
	char *status; /* Status of the chunk, allocated/free/corrupted */
} RzHeapChunkListItem;

typedef struct rz_arena_list_item {
	ut64 addr; /* Base addr of the arena */
	char *type; /* Type of arena, main/thread */
	MallocState *arena; /* The MallocState for the arena */
} RzArenaListItem;

typedef struct rz_heap_chunk_simple {
	ut64 addr; /* Base addr of the chunk*/
	ut64 prev_size; /* size of prev_chunk*/
	ut64 size; /* size of chunk */
	bool non_main_arena; /* flag for NON_MAIN_ARENA */
	bool prev_inuse; /* flag for PREV_INUSE*/
	bool is_mmapped; /* flag for IS_MMAPPED*/
	ut64 fd; /* fd pointer, only if free */
	ut64 bk; /* bk pointer, only if free */
	ut64 fd_nextsize; /* fd nextsize pointer, only if free */
	ut64 bk_nextsize; /* bk nextsize pointer, only if free */
} RzHeapChunkSimple;

typedef struct rz_heap_bin {
	ut64 addr;
	ut64 size;
	ut64 fd;
	ut64 bk;
	int bin_num;
	char *type;
	RzList /*<RzHeapChunkListItem *>*/ *chunks; /* list of chunks in the bins */
	char *message; /* indicating the list is corrupted or double free*/
} RzHeapBin;

RZ_API RzHeapChunkSimple *rz_heap_chunk_wrapper_32(RzCore *core, ut32 addr);
RZ_API RzHeapChunkSimple *rz_heap_chunk_wrapper_64(RzCore *core, ut64 addr);

RZ_API RzHeapChunk_64 *rz_heap_get_chunk_at_addr_64(RzCore *core, ut64 addr);
RZ_API RzHeapChunk_32 *rz_heap_get_chunk_at_addr_32(RzCore *core, ut32 addr);

RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list_64(RzCore *core, ut64 m_arena, MallocState *main_arena);
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arenas_list_32(RzCore *core, ut32 m_arena, MallocState *main_arena);

RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_64(RzCore *core, MallocState *main_arena, ut64 m_arena, ut64 m_state, bool top_chunk);
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_32(RzCore *core, MallocState *main_arena, ut32 m_arena, ut32 m_state, bool top_chunk);

RZ_API bool rz_heap_resolve_main_arena_64(RzCore *core, ut64 *m_arena);
RZ_API bool rz_heap_resolve_main_arena_32(RzCore *core, ut32 *m_arena);
RZ_API double rz_get_glibc_version_64(RzCore *core, const char *libc_path, ut8 *banner);
RZ_API double rz_get_glibc_version_32(RzCore *core, const char *libc_path, ut8 *banner);

RZ_API bool rz_heap_update_main_arena_64(RzCore *core, ut64 m_arena, MallocState *main_arena);
RZ_API bool rz_heap_update_main_arena_32(RzCore *core, ut32 m_arena, MallocState *main_arena);

RZ_API bool rz_heap_write_heap_chunk_64(RzCore *core, RzHeapChunkSimple *chunk_simple);
RZ_API bool rz_heap_write_heap_chunk_32(RzCore *core, RzHeapChunkSimple *chunk_simple);

RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content_64(RzCore *core, ut64 arena_base);
RZ_API RzList /*<RzHeapBin *>*/ *rz_heap_tcache_content_32(RzCore *core, ut32 arena_base);

RZ_API MallocState *rz_heap_get_arena_64(RzCore *core, ut64 m_state);
RZ_API MallocState *rz_heap_get_arena_32(RzCore *core, ut32 m_state);

RZ_API RzHeapBin *rz_heap_fastbin_content_64(RzCore *core, MallocState *main_arena, int bin_num);
RZ_API RzHeapBin *rz_heap_fastbin_content_32(RzCore *core, MallocState *main_arena, int bin_num);

RZ_API RzHeapBin *rz_heap_bin_content_64(RzCore *core, MallocState *main_arena, int bin_num, ut64 m_arena);
RZ_API RzHeapBin *rz_heap_bin_content_32(RzCore *core, MallocState *main_arena, int bin_num, ut32 m_arena);

RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_wrapper_64(RzCore *core, ut64 m_state);
RZ_API RzList /*<RzHeapChunkListItem *>*/ *rz_heap_chunks_list_wrapper_32(RzCore *core, ut64 m_state);

RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arena_list_wrapper_64(RzCore *core);
RZ_API RzList /*<RzArenaListItem *>*/ *rz_heap_arena_list_wrapper_32(RzCore *core);

RZ_IPI int rz_cmd_heap_fastbins_print_64(void *data, const char *input);
RZ_IPI int rz_cmd_heap_fastbins_print_32(void *data, const char *input);

RZ_IPI int rz_cmd_heap_bins_list_print_64(RzCore *core, const char *input);
RZ_IPI int rz_cmd_heap_bins_list_print_32(RzCore *core, const char *input);

RZ_API void rz_heap_bin_free_64(RzHeapBin *bin);
RZ_API void rz_heap_bin_free_32(RzHeapBin *bin);

#ifdef __cplusplus
}
#endif
#endif
