#ifndef RZ_BP_H
#define RZ_BP_H

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_io.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_bp);

#define RZ_BP_MAXPIDS     10
#define RZ_BP_CONT_NORMAL 0

typedef struct rz_bp_arch_t {
	int bits;
	int length;
	int endian;
	const ut8 *bytes;
} RzBreakpointArch;

enum {
	RZ_BP_TYPE_SW,
	RZ_BP_TYPE_HW,
	RZ_BP_TYPE_COND,
	RZ_BP_TYPE_FAULT,
	RZ_BP_TYPE_DELETE,
};

typedef struct rz_bp_plugin_t {
	char *name;
	char *arch;
	int type; // RZ_BP_TYPE_SW
	int nbps;
	RzBreakpointArch *bps;
} RzBreakpointPlugin;

typedef struct rz_bp_item_t {
	char *name;
	char *module_name; /*module where you get the base address*/
	st64 module_delta; /*delta to apply to module */
	ut64 addr;
	ut64 delta;
	int size; /* size of breakpoint area */
	bool swstep; /* is this breakpoint from a swstep? */
	int perm;
	int hw;
	int trace;
	int internal; /* used for internal purposes */
	int enabled;
	int togglehits; /* counter that toggles breakpoint on reaching 0 */
	int hits;
	ut8 *obytes; /* original bytes */
	ut8 *bbytes; /* breakpoint bytes */
	int pids[RZ_BP_MAXPIDS];
	char *data;
	char *cond; /* used for conditional breakpoints */
	char *expr; /* to be used for named breakpoints (see rz_debug_bp_update) */
} RzBreakpointItem;

struct rz_bp_t;
typedef int (*RzBreakpointCallback)(struct rz_bp_t *bp, RzBreakpointItem *b, bool set);

/**
 * \brief Outer context of mappings/etc. in which the RzBreakpoint instance will operate in.
 * In practical Rizin, this is implemented by RzCore.
 */
typedef struct rz_bp_context_t {
	void *user;
	bool (*is_mapped)(ut64 addr, int perm, void *user); ///< check if the address is mapped and has the given permissions
	void (*maps_sync)(void *user); ///< synchronize any maps from the debugee
	int (*bits_at)(ut64 addr, void *user); ///< get the arch-bitness to use at the given address (e.g. thumb or 32)
} RzBreakpointContext;

typedef struct rz_bp_t {
	void *user;
	RzBreakpointContext ctx;
	int stepcont;
	int endian;
	bool bpinmaps; /* Only enable breakpoints inside a valid map */
	RzIOBind iob; // compile time dependency
	RzBreakpointPlugin *cur;
	RzList /*<RzBreakpointTrace *>*/ *traces; // XXX
	HtSP /*<RzBreakpointPlugin *>*/ *plugins;
	PrintfCallback cb_printf;
	RzBreakpointCallback breakpoint;
	/* storage of breakpoints */
	int nbps;
	int nhwbps;
	RzList /*<RzBreakpointItem *>*/ *bps; // list of breakpoints
	RzBreakpointItem **bps_idx;
	int bps_idx_count;
	ut64 baddr;
} RzBreakpoint;

typedef struct rz_bp_trace_t {
	ut64 addr;
	ut64 addr_end;
	ut8 *traps;
	ut8 *buffer;
	ut8 *bits;
	int length;
	int bitlen;
} RzBreakpointTrace;

/**
 * \brief Compare plugins by name (via strcmp).
 */
static inline int rz_breakpoint_plugin_cmp(RZ_NULLABLE const RzBreakpointPlugin *a, RZ_NULLABLE const RzBreakpointPlugin *b) {
	if (!a && !b) {
		return 0;
	} else if (!a) {
		return -1;
	} else if (!b) {
		return 1;
	}
	return rz_str_cmp(a->name, b->name, -1);
}

#ifdef RZ_API
RZ_API RzBreakpoint *rz_bp_new(RZ_BORROW RZ_NONNULL RzBreakpointContext *ctx);
RZ_API RzBreakpoint *rz_bp_free(RzBreakpoint *bp);

RZ_API bool rz_bp_del(RzBreakpoint *bp, ut64 addr);
RZ_API bool rz_bp_del_all(RzBreakpoint *bp);

RZ_API bool rz_bp_plugin_add(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin);
RZ_API bool rz_bp_plugin_del(RzBreakpoint *bp, RZ_BORROW RZ_NONNULL RzBreakpointPlugin *plugin);
RZ_API int rz_bp_use(RZ_NONNULL RzBreakpoint *bp, RZ_NONNULL const char *name);
RZ_API int rz_bp_plugin_del_byname(RzBreakpoint *bp, RZ_NONNULL const char *name);
RZ_API void rz_bp_plugin_list(RzBreakpoint *bp);

RZ_API int rz_bp_size(RZ_NONNULL RzBreakpoint *bp, int bits);
RZ_API int rz_bp_size_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr);

/* bp item attribs setters */
RZ_API int rz_bp_get_bytes(RZ_NONNULL RzBreakpoint *bp, ut64 addr, RZ_NONNULL ut8 *buf, int len);
RZ_API int rz_bp_set_trace(RzBreakpoint *bp, ut64 addr, int set);
RZ_API int rz_bp_set_trace_all(RzBreakpoint *bp, int set);
RZ_API RzBreakpointItem *rz_bp_enable(RzBreakpoint *bp, ut64 addr, int set, int count);
RZ_API bool rz_bp_enable_all(RzBreakpoint *bp, int set);

/* index api */
RZ_API int rz_bp_del_index(RzBreakpoint *bp, int idx);
RZ_API RzBreakpointItem *rz_bp_get_index(RzBreakpoint *bp, int idx);
RZ_API int rz_bp_get_index_at(RzBreakpoint *bp, ut64 addr);

RZ_API RZ_BORROW RzBreakpointItem *rz_bp_get_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr);
RZ_API RZ_BORROW RzBreakpointItem *rz_bp_get_ending_at(RZ_NONNULL RzBreakpoint *bp, ut64 addr);
RZ_API RzBreakpointItem *rz_bp_get_in(RzBreakpoint *bp, ut64 addr, int perm);

RZ_API bool rz_bp_is_valid(RzBreakpoint *bp, RzBreakpointItem *b);
RZ_API bool rz_bp_item_set_cond(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *cond);
RZ_API bool rz_bp_item_set_data(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *data);
RZ_API bool rz_bp_item_set_expr(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *expr);
RZ_API bool rz_bp_item_set_name(RZ_NONNULL RzBreakpointItem *item, RZ_NULLABLE const char *name);

RZ_API int rz_bp_add_fault(RzBreakpoint *bp, ut64 addr, int size, int perm);

RZ_API RZ_BORROW RzBreakpointItem *rz_bp_add_sw(RZ_NONNULL RzBreakpoint *bp, ut64 addr, int size, int perm);
RZ_API RzBreakpointItem *rz_bp_add_hw(RzBreakpoint *bp, ut64 addr, int size, int perm);
RZ_API void rz_bp_restore_one(RzBreakpoint *bp, RzBreakpointItem *b, bool set);
RZ_API int rz_bp_restore(RzBreakpoint *bp, bool set);
RZ_API bool rz_bp_restore_except(RzBreakpoint *bp, bool set, ut64 addr);

/* traptrace */
RZ_API void rz_bp_traptrace_free(void *ptr);
RZ_API void rz_bp_traptrace_enable(RzBreakpoint *bp, int enable);
RZ_API void rz_bp_traptrace_reset(RzBreakpoint *bp, int hard);
RZ_API ut64 rz_bp_traptrace_next(RzBreakpoint *bp, ut64 addr);
RZ_API int rz_bp_traptrace_add(RzBreakpoint *bp, ut64 from, ut64 to);
RZ_API int rz_bp_traptrace_free_at(RzBreakpoint *bp, ut64 from);
RZ_API void rz_bp_traptrace_list(RzBreakpoint *bp);
RZ_API int rz_bp_traptrace_at(RzBreakpoint *bp, ut64 from, int len);
RZ_API RzList /*<RzBreakpointTrace *>*/ *rz_bp_traptrace_new(void);

/* watchpoint */
RZ_API RZ_BORROW RzBreakpointItem *rz_bp_watch_add(RZ_NONNULL RzBreakpoint *bp, ut64 addr, int size, int hw, int perm);

/* serialize */
typedef void *RzSerializeBpParser;
RZ_API void rz_serialize_bp_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzBreakpoint *bp);
RZ_API RzSerializeBpParser rz_serialize_bp_parser_new(void);
RZ_API bool rz_serialize_bp_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzBreakpoint *bp, RZ_NULLABLE RzSerializeResultInfo *res);

#endif
#ifdef __cplusplus
}
#endif

#endif
