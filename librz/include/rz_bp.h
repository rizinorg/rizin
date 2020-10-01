#ifndef R2_BP_H
#define R2_BP_H

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_io.h>
#include <rz_list.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(rz_bp);

#define R_BP_MAXPIDS 10
#define R_BP_CONT_NORMAL 0
#define R_BP_CONT_NORMAL 0

typedef struct rz_bp_arch_t {
	int bits;
	int length;
	int endian;
	const ut8 *bytes;
} RBreakpointArch;

enum {
	R_BP_TYPE_SW,
	R_BP_TYPE_HW,
	R_BP_TYPE_COND,
	R_BP_TYPE_FAULT,
	R_BP_TYPE_DELETE,
};

typedef struct rz_bp_plugin_t {
	char *name;
	char *arch;
	int type; // R_BP_TYPE_SW
	int nbps;
	RBreakpointArch *bps;
} RBreakpointPlugin;

typedef struct rz_bp_item_t {
	char *name;
	char *module_name; /*module where you get the base address*/
	st64 module_delta; /*delta to apply to module */
	ut64 addr;
	ut64 delta;
	int size; /* size of breakpoint area */
	int recoil; /* recoil */
	bool swstep; 	/* is this breakpoint from a swstep? */
	int perm;
	int hw;
	int trace;
	int internal; /* used for internal purposes */
	int enabled;
	int togglehits; /* counter that toggles breakpoint on reaching 0 */
	int hits;
	ut8 *obytes; /* original bytes */
	ut8 *bbytes; /* breakpoint bytes */
	int pids[R_BP_MAXPIDS];
	char *data;
	char *cond; /* used for conditional breakpoints */
	char *expr; /* to be used for named breakpoints (see rz_debug_bp_update) */
} RBreakpointItem;

struct rz_bp_t;
typedef int (*RBreakpointCallback)(struct rz_bp_t *bp, RBreakpointItem *b, bool set);

typedef struct rz_bp_t {
	void *user;
	int stepcont;
	int endian;
	int bits;
	bool bpinmaps; /* Only enable breakpoints inside a valid map */
	RzCoreBind corebind;
	RzIOBind iob; // compile time dependency
	RBreakpointPlugin *cur;
	RzList *traces; // XXX
	RzList *plugins;
	PrintfCallback cb_printf;
	RBreakpointCallback breakpoint;
	/* storage of breakpoints */
	int nbps;
	int nhwbps;
	RzList *bps; // list of breakpoints
	RBreakpointItem **bps_idx;
	int bps_idx_count;
	st64 delta;
	ut64 baddr;
} RBreakpoint;

// DEPRECATED: USE R_PERM
enum {
	R_BP_PROT_EXEC = 1,
	R_BP_PROT_WRITE = 2,
	R_BP_PROT_READ = 4,
	R_BP_PROT_ACCESS = 8,
};

typedef struct rz_bp_trace_t {
	ut64 addr;
	ut64 addr_end;
	ut8 *traps;
	ut8 *buffer;
	ut8 *bits;
	int length;
	int bitlen;
} RBreakpointTrace;

#ifdef RZ_API
RZ_API RBreakpoint *rz_bp_new(void);
RZ_API RBreakpoint *rz_bp_free(RBreakpoint *bp);

RZ_API int rz_bp_del(RBreakpoint *bp, ut64 addr);
RZ_API int rz_bp_del_all(RBreakpoint *bp);

RZ_API int rz_bp_plugin_add(RBreakpoint *bp, RBreakpointPlugin *foo);
RZ_API int rz_bp_use(RBreakpoint *bp, const char *name, int bits);
RZ_API int rz_bp_plugin_del(RBreakpoint *bp, const char *name);
RZ_API void rz_bp_plugin_list(RBreakpoint *bp);

RZ_API int rz_bp_in(RBreakpoint *bp, ut64 addr, int perm);
// deprecate?
RZ_API int rz_bp_list(RBreakpoint *bp, int rad);
RZ_API int rz_bp_size(RBreakpoint *bp);

/* bp item attribs setters */
RZ_API int rz_bp_get_bytes(RBreakpoint *bp, ut8 *buf, int len, int endian, int idx);
RZ_API int rz_bp_set_trace(RBreakpoint *bp, ut64 addr, int set);
RZ_API int rz_bp_set_trace_all(RBreakpoint *bp, int set);
RZ_API RBreakpointItem *rz_bp_enable(RBreakpoint *bp, ut64 addr, int set, int count);
RZ_API int rz_bp_enable_all(RBreakpoint *bp, int set);

/* index api */
RZ_API int rz_bp_del_index(RBreakpoint *bp, int idx);
RZ_API RBreakpointItem *rz_bp_get_index(RBreakpoint *bp, int idx);
RZ_API int rz_bp_get_index_at (RBreakpoint *bp, ut64 addr);
RZ_API RBreakpointItem *rz_bp_item_new (RBreakpoint *bp);

RZ_API RBreakpointItem *rz_bp_get_at (RBreakpoint *bp, ut64 addr);
RZ_API RBreakpointItem *rz_bp_get_in (RBreakpoint *bp, ut64 addr, int perm);

RZ_API bool rz_bp_is_valid(RBreakpoint *bp, RBreakpointItem *b);

RZ_API int rz_bp_add_cond(RBreakpoint *bp, const char *cond);
RZ_API int rz_bp_del_cond(RBreakpoint *bp, int idx);
RZ_API int rz_bp_add_fault(RBreakpoint *bp, ut64 addr, int size, int perm);

RZ_API RBreakpointItem *rz_bp_add_sw(RBreakpoint *bp, ut64 addr, int size, int perm);
RZ_API RBreakpointItem *rz_bp_add_hw(RBreakpoint *bp, ut64 addr, int size, int perm);
RZ_API void rz_bp_restore_one(RBreakpoint *bp, RBreakpointItem *b, bool set);
RZ_API int rz_bp_restore(RBreakpoint *bp, bool set);
RZ_API bool rz_bp_restore_except(RBreakpoint *bp, bool set, ut64 addr);

/* traptrace */
RZ_API void rz_bp_traptrace_free(void *ptr);
RZ_API void rz_bp_traptrace_enable(RBreakpoint *bp, int enable);
RZ_API void rz_bp_traptrace_reset(RBreakpoint *bp, int hard);
RZ_API ut64 rz_bp_traptrace_next(RBreakpoint *bp, ut64 addr);
RZ_API int rz_bp_traptrace_add(RBreakpoint *bp, ut64 from, ut64 to);
RZ_API int rz_bp_traptrace_free_at(RBreakpoint *bp, ut64 from);
RZ_API void rz_bp_traptrace_list(RBreakpoint *bp);
RZ_API int rz_bp_traptrace_at(RBreakpoint *bp, ut64 from, int len);
RZ_API RzList *rz_bp_traptrace_new(void);
RZ_API void rz_bp_traptrace_enable(RBreakpoint *bp, int enable);

/* watchpoint */
RZ_API RBreakpointItem *rz_bp_watch_add(RBreakpoint *bp, ut64 addr, int size, int hw, int rw);

/* plugin pointers */
extern RBreakpointPlugin rz_bp_plugin_x86;
extern RBreakpointPlugin rz_bp_plugin_arm;
extern RBreakpointPlugin rz_bp_plugin_mips;
extern RBreakpointPlugin rz_bp_plugin_ppc;
extern RBreakpointPlugin rz_bp_plugin_sh;
extern RBreakpointPlugin rz_bp_plugin_bf;
#endif
#ifdef __cplusplus
}
#endif

#endif
