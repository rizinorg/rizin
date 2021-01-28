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

typedef struct rz_bp_t {
	void *user;
	int stepcont;
	int endian;
	int bits;
	bool bpinmaps; /* Only enable breakpoints inside a valid map */
	RzCoreBind corebind;
	RzIOBind iob; // compile time dependency
	RzBreakpointPlugin *cur;
	RzList *traces; // XXX
	RzList *plugins;
	PrintfCallback cb_printf;
	RzBreakpointCallback breakpoint;
	/* storage of breakpoints */
	int nbps;
	int nhwbps;
	RzList *bps; // list of breakpoints
	RzBreakpointItem **bps_idx;
	int bps_idx_count;
	st64 delta;
	ut64 baddr;
} RzBreakpoint;

// DEPRECATED: USE RZ_PERM
enum {
	RZ_BP_PROT_EXEC = 1,
	RZ_BP_PROT_WRITE = 2,
	RZ_BP_PROT_READ = 4,
	RZ_BP_PROT_ACCESS = 8,
};

typedef struct rz_bp_trace_t {
	ut64 addr;
	ut64 addr_end;
	ut8 *traps;
	ut8 *buffer;
	ut8 *bits;
	int length;
	int bitlen;
} RzBreakpointTrace;

#ifdef RZ_API
RZ_API RzBreakpoint *rz_bp_new(void);
RZ_API RzBreakpoint *rz_bp_free(RzBreakpoint *bp);

RZ_API int rz_bp_del(RzBreakpoint *bp, ut64 addr);
RZ_API int rz_bp_del_all(RzBreakpoint *bp);

RZ_API int rz_bp_plugin_add(RzBreakpoint *bp, RzBreakpointPlugin *foo);
RZ_API int rz_bp_use(RzBreakpoint *bp, const char *name, int bits);
RZ_API int rz_bp_plugin_del(RzBreakpoint *bp, const char *name);
RZ_API void rz_bp_plugin_list(RzBreakpoint *bp);

RZ_API int rz_bp_in(RzBreakpoint *bp, ut64 addr, int perm);
// deprecate?
RZ_API int rz_bp_list(RzBreakpoint *bp, int rad);
RZ_API int rz_bp_size(RzBreakpoint *bp);

/* bp item attribs setters */
RZ_API int rz_bp_get_bytes(RzBreakpoint *bp, ut8 *buf, int len, int endian, int idx);
RZ_API int rz_bp_set_trace(RzBreakpoint *bp, ut64 addr, int set);
RZ_API int rz_bp_set_trace_all(RzBreakpoint *bp, int set);
RZ_API RzBreakpointItem *rz_bp_enable(RzBreakpoint *bp, ut64 addr, int set, int count);
RZ_API int rz_bp_enable_all(RzBreakpoint *bp, int set);

/* index api */
RZ_API int rz_bp_del_index(RzBreakpoint *bp, int idx);
RZ_API RzBreakpointItem *rz_bp_get_index(RzBreakpoint *bp, int idx);
RZ_API int rz_bp_get_index_at(RzBreakpoint *bp, ut64 addr);
RZ_API RzBreakpointItem *rz_bp_item_new(RzBreakpoint *bp);

RZ_API RzBreakpointItem *rz_bp_get_at(RzBreakpoint *bp, ut64 addr);
RZ_API RzBreakpointItem *rz_bp_get_in(RzBreakpoint *bp, ut64 addr, int perm);

RZ_API bool rz_bp_is_valid(RzBreakpoint *bp, RzBreakpointItem *b);

RZ_API int rz_bp_add_cond(RzBreakpoint *bp, const char *cond);
RZ_API int rz_bp_del_cond(RzBreakpoint *bp, int idx);
RZ_API int rz_bp_add_fault(RzBreakpoint *bp, ut64 addr, int size, int perm);

RZ_API RzBreakpointItem *rz_bp_add_sw(RzBreakpoint *bp, ut64 addr, int size, int perm);
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
RZ_API RzList *rz_bp_traptrace_new(void);
RZ_API void rz_bp_traptrace_enable(RzBreakpoint *bp, int enable);

/* watchpoint */
RZ_API RzBreakpointItem *rz_bp_watch_add(RzBreakpoint *bp, ut64 addr, int size, int hw, int rw);

/* plugin pointers */
extern RzBreakpointPlugin rz_bp_plugin_x86;
extern RzBreakpointPlugin rz_bp_plugin_arm;
extern RzBreakpointPlugin rz_bp_plugin_mips;
extern RzBreakpointPlugin rz_bp_plugin_ppc;
extern RzBreakpointPlugin rz_bp_plugin_sh;
extern RzBreakpointPlugin rz_bp_plugin_bf;
#endif
#ifdef __cplusplus
}
#endif

#endif
