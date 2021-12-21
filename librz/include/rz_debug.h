#ifndef RZ_DEBUG_H
#define RZ_DEBUG_H

#include <rz_types.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_util.h>
#include <rz_reg.h>
#include <rz_egg.h>
#include <rz_bp.h>
#include <rz_io.h>
#include <rz_msg_digest.h>
#include <rz_syscall.h>
#include <rz_cmd.h>

#include <rz_config.h>
#include "rz_bind.h"
#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_debug);

/* hack to fix compilation of debugger on BSD systems */
/* This needs some testing (netbsd, freebsd, openbsd, kfreebsd) */
#if __BSD__
#include <machine/reg.h>

/* hakish hack to hack the openbsd/sparc64 hack */
#undef reg
#undef fpreg
#undef fpstate
#undef trapframe
#undef rwindow

#ifdef PTRACE_SYSCALL
/* on freebsd does not have the same meaning */
#undef PTRACE_SYSCALL
#endif

#define PTRACE_PEEKTEXT   PT_READ_I
#define PTRACE_POKETEXT   PT_WRITE_I
#define PTRACE_PEEKDATA   PT_READ_D
#define PTRACE_POKEDATA   PT_WRITE_D
#define PTRACE_ATTACH     PT_ATTACH
#define PTRACE_DETACH     PT_DETACH
#define PTRACE_SINGLESTEP PT_STEP
#define PTRACE_CONT       PT_CONTINUE
#define PTRACE_GETREGS    PT_GETREGS
#define PTRACE_SETREGS    PT_SETREGS
#define PTRACE_SYSCALL    PT_STEP
#endif

#define CMD_CHECK_DEBUG_DEAD(core) \
	do { \
		if (rz_debug_is_dead(core->dbg)) { \
			rz_cons_println("Debugging is not enabled. Run ood?"); \
			return RZ_CMD_STATUS_ERROR; \
		} \
	} while (0)
#define SNAP_PAGE_SIZE    4096
#define CHECK_POINT_LIMIT 0x100000 // TODO: take the benchmark
/*
 * states that a process can be in
 */
typedef enum {
	RZ_DBG_PROC_STOP = 's',
	RZ_DBG_PROC_RUN = 'r',
	RZ_DBG_PROC_SLEEP = 'S',
	RZ_DBG_PROC_ZOMBIE = 'z',
	RZ_DBG_PROC_DEAD = 'd',
	RZ_DBG_PROC_RAISED = 'R' // has produced a signal, breakpoint, etc..
} RzDebugPidState;

// signal handling must support application and debugger level options
typedef enum {
	RZ_DBG_SIGNAL_IGNORE = 0, // ignore signal handler
	RZ_DBG_SIGNAL_CONT = 1, // pass signal to chlidren and continue execution
	RZ_DBG_SIGNAL_SKIP = 2, //
	//..
} RzDebugSignalMode;

/*
 * when a user wants to resume from a breakpoint, we need to know how they want
 * to proceed. these values indicate their intention.
 */
typedef enum {
	RZ_DBG_RECOIL_NONE = 0,
	RZ_DBG_RECOIL_STEP,
	RZ_DBG_RECOIL_CONTINUE
} RzDebugRecoilMode;

/*
 * List of reasons that an inferior might have stopped
 */
typedef enum {
	RZ_DEBUG_REASON_DEAD = -1,
	RZ_DEBUG_REASON_NONE = 0,
	RZ_DEBUG_REASON_SIGNAL,
	RZ_DEBUG_REASON_SEGFAULT,
	RZ_DEBUG_REASON_BREAKPOINT,
	RZ_DEBUG_REASON_TRACEPOINT,
	RZ_DEBUG_REASON_COND,
	RZ_DEBUG_REASON_READERR,
	RZ_DEBUG_REASON_STEP,
	RZ_DEBUG_REASON_ABORT,
	RZ_DEBUG_REASON_WRITERR,
	RZ_DEBUG_REASON_DIVBYZERO,
	RZ_DEBUG_REASON_ILLEGAL,
	RZ_DEBUG_REASON_UNKNOWN,
	RZ_DEBUG_REASON_ERROR,
	RZ_DEBUG_REASON_NEW_PID,
	RZ_DEBUG_REASON_NEW_TID,
	RZ_DEBUG_REASON_NEW_LIB,
	RZ_DEBUG_REASON_EXIT_PID,
	RZ_DEBUG_REASON_EXIT_TID,
	RZ_DEBUG_REASON_EXIT_LIB,
	RZ_DEBUG_REASON_TRAP,
	RZ_DEBUG_REASON_SWI,
	RZ_DEBUG_REASON_INT,
	RZ_DEBUG_REASON_FPU,
	RZ_DEBUG_REASON_USERSUSP,
} RzDebugReasonType;

/* TODO: move to rz_analysis */
typedef struct rz_debug_frame_t {
	ut64 addr;
	int size;
	ut64 sp;
	ut64 bp;
} RzDebugFrame;

typedef struct rz_debug_reason_t {
	int /*RzDebugReasonType*/ type;
	int tid;
	int signum;
	ut64 bp_addr;
	ut64 timestamp;
	ut64 addr;
	ut64 ptr;
} RzDebugReason;

typedef struct rz_debug_map_t {
	char *name;
	ut64 addr;
	ut64 addr_end;
	ut64 size;
	ut64 offset;
	char *file;
	int perm;
	int user;
	bool shared;
} RzDebugMap;

typedef struct rz_debug_signal_t {
	int type;
	int num;
	ut64 handler;
} RzDebugSignal;

typedef struct rz_debug_desc_t {
	int fd;
	char *path;
	int perm;
	int type;
	ut64 off;
} RzDebugDesc;

typedef struct rz_debug_snap_t {
	char *name;
	ut64 addr;
	ut64 addr_end;
	ut32 size;
	ut8 *data;
	int perm;
	int user;
	bool shared;
} RzDebugSnap;

typedef struct {
	int cnum;
	ut64 data;
} RzDebugChangeReg;

typedef struct {
	int cnum;
	ut8 data;
} RzDebugChangeMem;

typedef struct rz_debug_checkpoint_t {
	int cnum;
	RzRegArena *arena[RZ_REG_TYPE_LAST];
	RzList *snaps; // <RzDebugSnap>
} RzDebugCheckpoint;

typedef struct rz_debug_session_t {
	ut32 cnum;
	ut32 maxcnum;
	RzDebugCheckpoint *cur_chkpt;
	RzVector *checkpoints; /* RzVector<RzDebugCheckpoint> */
	HtUP *memory; /* RzVector<RzDebugChangeMem> */
	HtUP *registers; /* RzVector<RzDebugChangeReg> */
	int reasontype /*RzDebugReasonType*/;
	RzBreakpointItem *bp;
} RzDebugSession;

/* Session file format */
typedef struct rz_session_header {
	ut64 addr;
	ut32 id;
	ut32 difflist_len;
} RSessionHeader;

typedef struct rz_diff_entry {
	ut32 base_idx;
	ut32 pages_len;
} RzDiffEntry;

typedef struct rz_snap_entry {
	ut64 addr;
	ut32 size;
	ut64 timestamp;
	int perm;
} RSnapEntry;

typedef struct rz_debug_trace_t {
	RzList *traces;
	int count;
	int enabled;
	// int changed;
	int tag;
	int dup;
	char *addresses;
	// TODO: add range here
	HtPP *ht;
} RzDebugTrace;

typedef struct rz_debug_tracepoint_t {
	ut64 addr;
	ut64 tags; // XXX
	int tag; // XXX
	int size;
	int count;
	int times;
	ut64 stamp;
} RzDebugTracepoint;

typedef struct rz_debug_t {
	char *arch;
	int bits; /// XXX: MUST SET ///
	int hitinfo;

	int main_pid;
	int pid; /* selected process id */
	int tid; /* selected thread id */
	int forked_pid; /* last pid created by fork */
	int n_threads;
	RzList *threads; /* NOTE: list contents are platform-specific */

	char *malloc; /*choose malloc parser: 0 = glibc, 1 = jemalloc*/

	/* dbg.* config options (see e?dbg)
	 * NOTE: some settings are checked inline instead of tracked here.
	 */
	int bpsize; /* size of a breakpoint */
	char *btalgo; /* select backtrace algorithm */
	int btdepth; /* backtrace depth */
	int regcols; /* display columns */
	int swstep; /* steps with software traps */
	int stop_all_threads; /* stop all threads at any stop */
	int trace_forks; /* stop on new children */
	int trace_execs; /* stop on new execs */
	int trace_aftersyscall; /* stop after the syscall (before if disabled) */
	int trace_clone; /* stop on new threads */
	int follow_child; /* On fork, trace the child */
	bool create_new_console; /* Create a new console window for the debugee on debug start */
	char *glob_libs; /* stop on lib load */
	char *glob_unlibs; /* stop on lib unload */
	bool consbreak; /* SIGINT handle for attached processes */
	bool continue_all_threads;

	/* tracking debugger state */
	int steps; /* counter of steps done */
	RzDebugReason reason; /* stop reason */
	RzDebugRecoilMode recoil_mode; /* what did the user want to do? */
	ut64 stopaddr; /* stop address  */

	/* tracing vars */
	RzDebugTrace *trace;
	HtUP *tracenodes;
	RTree *tree;
	RzList *call_frames;

	RzReg *reg;
	RzList *q_regs;
	RzBreakpoint *bp;
	char *snap_path;

	/* io */
	PrintfCallback cb_printf;
	RzIOBind iob;

	struct rz_debug_plugin_t *cur;
	void *plugin_data;
	RzList *plugins;

	bool pc_at_bp; /* after a breakpoint, is the pc at the bp? */
	bool pc_at_bp_set; /* is the pc_at_bp variable set already? */

	RzEvent *ev;

	RzAnalysis *analysis;
	RzList *maps; // <RzDebugMap>
	RzList *maps_user; // <RzDebugMap>

	bool trace_continue;
	RzAnalysisOp *cur_op;
	RzDebugSession *session;

	Sdb *sgnls;
	RzCoreBind corebind;
	// internal use only
	int _mode;
	RzNum *num;
	RzEgg *egg;
	bool verbose;
	bool main_arena_resolved; /* is the main_arena resolved already? */
	int glibc_version;
} RzDebug;

typedef struct rz_debug_desc_plugin_t {
	int (*open)(const char *path);
	int (*close)(int fd);
	int (*read)(int fd, ut64 addr, int len);
	int (*write)(int fd, ut64 addr, int len);
	int (*seek)(int fd, ut64 addr);
	int (*dup)(int fd, int newfd);
	RzList *(*list)(int pid);
} RzDebugDescPlugin;

typedef struct rz_debug_info_t {
	int pid;
	int tid;
	int uid;
	int gid;
	char *usr;
	char *exe;
	char *cmdline;
	char *libname;
	char *cwd;
	int status; // zombie, running, sleeping, ...
	int signum;
	void *lib;
	void *thread;
	char *kernel_stack;
	// retrieve mem/fd/core limits?
	// list of threads ? hasthreads? counter?
	// environment?
	// /proc/pid/syscall ???
} RzDebugInfo;

/* TODO: pass dbg and user data pointer everywhere */
typedef struct rz_debug_plugin_t {
	const char *name;
	const char *license;
	const char *author;
	const char *version;
	ut32 bits;
	const char *arch;
	int canstep;
	int keepio;
	bool (*init)(RzDebug *dbg, void **user);
	void (*fini)(RzDebug *debug, void *user);
	/* life */
	RzDebugInfo *(*info)(RzDebug *dbg, const char *arg);
	int (*startv)(int argc, char **argv);
	int (*attach)(RzDebug *dbg, int pid);
	int (*detach)(RzDebug *dbg, int pid);
	int (*select)(RzDebug *dbg, int pid, int tid);
	RzList *(*threads)(RzDebug *dbg, int pid);
	RzList *(*pids)(RzDebug *dbg, int pid);
	RzList *(*tids)(RzDebug *dbg, int pid);
	RzList (*backtrace)(RzDebug *dbg, int count);
	/* flow */
	int (*stop)(RzDebug *dbg);
	int (*step)(RzDebug *dbg);
	int (*step_over)(RzDebug *dbg);
	int (*cont)(RzDebug *dbg, int pid, int tid, int sig);
	RzDebugReasonType (*wait)(RzDebug *dbg, int pid);
	bool (*gcore)(RzDebug *dbg, char *path, RzBuffer *dest);
	bool (*kill)(RzDebug *dbg, int pid, int tid, int sig);
	RzList *(*kill_list)(RzDebug *dbg);
	int (*contsc)(RzDebug *dbg, int pid, int sc);
	RzList *(*frames)(RzDebug *dbg, ut64 at);
	RzBreakpointCallback breakpoint; /// Callback to be used for RzBreakpoint. When called, RzBreakpoint.user points to the RzDebug.
	// XXX: specify, pid, tid, or RzDebug ?
	int (*reg_read)(RzDebug *dbg, int type, ut8 *buf, int size);
	int (*reg_write)(RzDebug *dbg, int type, const ut8 *buf, int size); // XXX struct rz_regset_t regs);
	char *(*reg_profile)(RzDebug *dbg);
	int (*set_reg_profile)(RzDebug *dbg, const char *str);
	/* memory */
	RzList *(*map_get)(RzDebug *dbg);
	RzList *(*modules_get)(RzDebug *dbg);
	RzDebugMap *(*map_alloc)(RzDebug *dbg, ut64 addr, int size, bool thp);
	int (*map_dealloc)(RzDebug *dbg, ut64 addr, int size);
	int (*map_protect)(RzDebug *dbg, ut64 addr, int size, int perms);
	int (*drx)(RzDebug *dbg, int n, ut64 addr, int size, int rwx, int g, int api_type);
	RzDebugDescPlugin desc;
	// TODO: use RzList here
} RzDebugPlugin;

// TODO: rename to rz_debug_process_t ? maybe a thread too ?
typedef struct rz_debug_pid_t {
	int pid;
	int ppid;
	char status; /* stopped, running, zombie, sleeping ,... */
	int runnable; /* when using 'run', 'continue', .. this proc will be runnable */
	bool signalled;
	char *path;
	int uid;
	int gid;
	ut64 pc;
} RzDebugPid;

#ifdef RZ_API
RZ_API RzDebug *rz_debug_new(int hard);
RZ_API RzDebug *rz_debug_free(RzDebug *dbg);

RZ_API int rz_debug_attach(RzDebug *dbg, int pid);
RZ_API int rz_debug_detach(RzDebug *dbg, int pid);
RZ_API int rz_debug_startv(RzDebug *dbg, int argc, char **argv);
RZ_API int rz_debug_start(RzDebug *dbg, const char *cmd);

/* reason we stopped */
RZ_API RzDebugReasonType rz_debug_stop_reason(RzDebug *dbg);
RZ_API const char *rz_debug_reason_to_string(int type);

/* wait for another event */
RZ_API RzDebugReasonType rz_debug_wait(RzDebug *dbg, RzBreakpointItem **bp);

/* continuations */
RZ_API int rz_debug_step(RzDebug *dbg, int steps);
RZ_API int rz_debug_step_over(RzDebug *dbg, int steps);
RZ_API int rz_debug_continue_until(RzDebug *dbg, ut64 addr);
RZ_API int rz_debug_continue_until_nonblock(RzDebug *dbg, ut64 addr);
RZ_API int rz_debug_continue_until_optype(RzDebug *dbg, int type, int over);
RZ_API int rz_debug_continue_until_nontraced(RzDebug *dbg);
RZ_API int rz_debug_continue_syscall(RzDebug *dbg, int sc);
RZ_API int rz_debug_continue_syscalls(RzDebug *dbg, int *sc, int n_sc);
RZ_API int rz_debug_continue(RzDebug *dbg);
RZ_API int rz_debug_continue_kill(RzDebug *dbg, int signal);
#if __WINDOWS__
RZ_API int rz_debug_continue_pass_exception(RzDebug *dbg);
#endif

/* process/thread handling */
RZ_API bool rz_debug_select(RzDebug *dbg, int pid, int tid);
// RZ_API int rz_debug_pid_add(RzDebug *dbg);
// RZ_API int rz_debug_pid_add_thread(RzDebug *dbg);
// RZ_API int rz_debug_pid_del(RzDebug *dbg);
// RZ_API int rz_debug_pid_del_thread(RzDebug *dbg);
RZ_API int rz_debug_pid_list(RzDebug *dbg, int pid, char fmt);
RZ_API RzDebugPid *rz_debug_pid_new(const char *path, int pid, int uid, char status, ut64 pc);
RZ_API RzDebugPid *rz_debug_pid_free(RzDebugPid *pid);
RZ_API RzList *rz_debug_pids(RzDebug *dbg, int pid);

RZ_API bool rz_debug_set_arch(RzDebug *dbg, const char *arch, int bits);
RZ_API bool rz_debug_use(RzDebug *dbg, const char *str);

RZ_API RzDebugInfo *rz_debug_info(RzDebug *dbg, const char *arg);
RZ_API void rz_debug_info_free(RzDebugInfo *rdi);

RZ_API ut64 rz_debug_get_baddr(RzDebug *dbg, const char *file);

/* send signals */
RZ_API void rz_debug_signal_init(RzDebug *dbg);
RZ_API int rz_debug_signal_send(RzDebug *dbg, int num);
RZ_API int rz_debug_signal_what(RzDebug *dbg, int num);
RZ_API int rz_debug_signal_resolve(RzDebug *dbg, const char *signame);
RZ_API const char *rz_debug_signal_resolve_i(RzDebug *dbg, int signum);
RZ_API void rz_debug_signal_setup(RzDebug *dbg, int num, int opt);
RZ_API int rz_debug_signal_set(RzDebug *dbg, int num, ut64 addr);
RZ_API void rz_debug_signal_list(RzDebug *dbg, RzOutputMode mode);
RZ_API bool rz_debug_can_kill(RzDebug *dbg);
RZ_API int rz_debug_kill(RzDebug *dbg, int pid, int tid, int sig);
RZ_API RzList *rz_debug_kill_list(RzDebug *dbg);
// XXX: must be uint64 action
RZ_API int rz_debug_kill_setup(RzDebug *dbg, int sig, int action);

/* handle.c */
RZ_API void rz_debug_plugin_init(RzDebug *dbg);
RZ_API int rz_debug_plugin_set(RzDebug *dbg, const char *str);
RZ_API bool rz_debug_plugin_add(RzDebug *dbg, RzDebugPlugin *foo);
RZ_API bool rz_debug_plugin_set_reg_profile(RzDebug *dbg, const char *str);

/* memory */
RZ_API RzList *rz_debug_modules_list(RzDebug *);
RZ_API RzDebugMap *rz_debug_map_alloc(RzDebug *dbg, ut64 addr, int size, bool thp);
RZ_API int rz_debug_map_dealloc(RzDebug *dbg, RzDebugMap *map);
RZ_API RzList *rz_debug_map_list_new(void);
RZ_API RzDebugMap *rz_debug_map_get(RzDebug *dbg, ut64 addr);
RZ_API RzDebugMap *rz_debug_map_new(char *name, ut64 addr, ut64 addr_end, int perm, int user);
RZ_API void rz_debug_map_free(RzDebugMap *map);
RZ_API void rz_debug_map_print(RzDebug *dbg, ut64 addr, RzCmdStateOutput *state);
RZ_API void rz_debug_map_list_visual(RzDebug *dbg, ut64 addr, const char *input, int colors);
RZ_API RzList *rz_debug_map_list(RzDebug *dbg, bool user_map);

/* descriptors */
RZ_API RzDebugDesc *rz_debug_desc_new(int fd, char *path, int perm, int type, int off);
RZ_API void rz_debug_desc_free(RzDebugDesc *p);
RZ_API int rz_debug_desc_open(RzDebug *dbg, const char *path);
RZ_API int rz_debug_desc_close(RzDebug *dbg, int fd);
RZ_API int rz_debug_desc_dup(RzDebug *dbg, int fd, int newfd);
RZ_API int rz_debug_desc_read(RzDebug *dbg, int fd, ut64 addr, int len);
RZ_API int rz_debug_desc_seek(RzDebug *dbg, int fd, ut64 addr); // TODO: whence?
RZ_API int rz_debug_desc_write(RzDebug *dbg, int fd, ut64 addr, int len);
RZ_API int rz_debug_desc_list(RzDebug *dbg, int rad);

/* registers */
RZ_API bool rz_debug_reg_profile_sync(RzDebug *dbg);
RZ_API int rz_debug_reg_sync(RzDebug *dbg, int type, int write);
RZ_API int rz_debug_reg_set(RzDebug *dbg, const char *name, ut64 num);
RZ_API ut64 rz_debug_reg_get(RzDebug *dbg, const char *name);

RZ_API ut64 rz_debug_execute(RzDebug *dbg, const ut8 *buf, int len, int restore);
RZ_API bool rz_debug_map_sync(RzDebug *dbg);

RZ_API int rz_debug_stop(RzDebug *dbg);

/* backtrace */
RZ_API RzList *rz_debug_frames(RzDebug *dbg, ut64 at);

RZ_API bool rz_debug_is_dead(RzDebug *dbg);
RZ_API int rz_debug_map_protect(RzDebug *dbg, ut64 addr, int size, int perms);

/* breakpoints (most in rz_bp, this calls those) */
RZ_API RzBreakpointItem *rz_debug_bp_add(RzDebug *dbg, ut64 addr, int hw, bool watch, int rw, const char *module, st64 m_delta);
RZ_API void rz_debug_bp_rebase(RzDebug *dbg, ut64 old_base, ut64 new_base);
RZ_API void rz_debug_bp_update(RzDebug *dbg);

/* pid */
RZ_API int rz_debug_thread_list(RzDebug *dbg, int pid, char fmt);

RZ_API void rz_debug_tracenodes_reset(RzDebug *dbg);

RZ_API void rz_debug_trace_reset(RzDebug *dbg);
RZ_API int rz_debug_trace_pc(RzDebug *dbg, ut64 pc);
RZ_API void rz_debug_trace_op(RzDebug *dbg, RzAnalysisOp *op);
RZ_API void rz_debug_trace_at(RzDebug *dbg, const char *str);
RZ_API RzDebugTracepoint *rz_debug_trace_get(RzDebug *dbg, ut64 addr);
RZ_API void rz_debug_trace_list(RzDebug *dbg, int mode, ut64 offset);
RZ_API RzDebugTracepoint *rz_debug_trace_add(RzDebug *dbg, ut64 addr, int size);
RZ_API RzDebugTrace *rz_debug_trace_new(void);
RZ_API void rz_debug_trace_free(RzDebugTrace *dbg);
RZ_API int rz_debug_trace_tag(RzDebug *dbg, int tag);
RZ_API int rz_debug_child_fork(RzDebug *dbg);
RZ_API int rz_debug_child_clone(RzDebug *dbg);

RZ_API void rz_debug_drx_list(RzDebug *dbg);
RZ_API int rz_debug_drx_set(RzDebug *dbg, int idx, ut64 addr, int len, int rwx, int g);
RZ_API int rz_debug_drx_unset(RzDebug *dbg, int idx);

/* esil */
RZ_API ut64 rz_debug_num_callback(RzNum *userptr, const char *str, int *ok);
RZ_API int rz_debug_esil_stepi(RzDebug *dbg);
RZ_API ut64 rz_debug_esil_step(RzDebug *dbg, ut32 count);
RZ_API ut64 rz_debug_esil_continue(RzDebug *dbg);
RZ_API void rz_debug_esil_watch(RzDebug *dbg, int rwx, int dev, const char *expr);
RZ_API void rz_debug_esil_watch_reset(RzDebug *dbg);
RZ_API void rz_debug_esil_watch_list(RzDebug *dbg);
RZ_API int rz_debug_esil_watch_empty(RzDebug *dbg);
RZ_API void rz_debug_esil_prestep(RzDebug *d, int p);

/* record & replay */
// RZ_API ut8 rz_debug_get_byte(RzDebug *dbg, ut32 cnum, ut64 addr);
RZ_API bool rz_debug_add_checkpoint(RzDebug *dbg);
RZ_API bool rz_debug_session_add_reg_change(RzDebugSession *session, int arena, ut64 offset, ut64 data);
RZ_API bool rz_debug_session_add_mem_change(RzDebugSession *session, ut64 addr, ut8 data);
RZ_API void rz_debug_session_restore_reg_mem(RzDebug *dbg, ut32 cnum);
RZ_API void rz_debug_session_list_memory(RzDebug *dbg);
RZ_API void rz_debug_session_serialize(RzDebugSession *session, Sdb *db);
RZ_API void rz_debug_session_deserialize(RzDebugSession *session, Sdb *db);
RZ_API bool rz_debug_session_save(RzDebugSession *session, const char *file);
RZ_API bool rz_debug_session_load(RzDebug *dbg, const char *file);
RZ_API bool rz_debug_trace_ins_before(RzDebug *dbg);
RZ_API bool rz_debug_trace_ins_after(RzDebug *dbg);

RZ_API RzDebugSession *rz_debug_session_new(void);
RZ_API void rz_debug_session_free(RzDebugSession *session);

RZ_API RzDebugSnap *rz_debug_snap_map(RzDebug *dbg, RzDebugMap *map);
RZ_API bool rz_debug_snap_contains(RzDebugSnap *snap, ut64 addr);
RZ_API ut8 *rz_debug_snap_get_hash(RzDebugSnap *snap, RzMsgDigestSize *size);
RZ_API bool rz_debug_snap_is_equal(RzDebugSnap *a, RzDebugSnap *b);
RZ_API void rz_debug_snap_free(RzDebugSnap *snap);

RZ_API int rz_debug_step_back(RzDebug *dbg, int steps);
RZ_API bool rz_debug_goto_cnum(RzDebug *dbg, ut32 cnum);
RZ_API int rz_debug_step_cnum(RzDebug *dbg, int steps);
RZ_API bool rz_debug_continue_back(RzDebug *dbg);

/* serialize */
RZ_API void rz_serialize_debug_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg);
RZ_API bool rz_serialize_debug_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzDebug *dbg, RZ_NULLABLE RzSerializeResultInfo *res);

/* ptrace */
#if HAVE_PTRACE
static inline long rz_debug_ptrace(RzDebug *dbg, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data) {
	return dbg->iob.ptrace(dbg->iob.io, request, pid, addr, data);
}

static inline void *rz_debug_ptrace_func(RzDebug *dbg, void *(*func)(void *), void *user) {
	return dbg->iob.ptrace_func(dbg->iob.io, func, user);
}
#endif

/* plugin pointers */
extern RzDebugPlugin rz_debug_plugin_native;
extern RzDebugPlugin rz_debug_plugin_esil;
extern RzDebugPlugin rz_debug_plugin_rap;
extern RzDebugPlugin rz_debug_plugin_gdb;
extern RzDebugPlugin rz_debug_plugin_bf;
extern RzDebugPlugin rz_debug_plugin_io;
extern RzDebugPlugin rz_debug_plugin_winkd;
extern RzDebugPlugin rz_debug_plugin_windbg;
extern RzDebugPlugin rz_debug_plugin_bochs;
extern RzDebugPlugin rz_debug_plugin_qnx;
extern RzDebugPlugin rz_debug_plugin_null;
#endif

#ifdef __cplusplus
}
#endif

#endif

/* regset */
// RZ_API struct rz_regset_t* rz_regset_diff(struct rz_regset_t *a, struct rz_regset_t *b);
// RZ_API int rz_regset_set(struct rz_regset_t *r, int idx, const char *name, ut64 value);
// RZ_API struct rz_regset_t *rz_regset_new(int size);
// RZ_API void rz_regset_free(struct rz_regset_t *r);

#if 0
Missing callbacks
=================
 - alloc
 - dealloc
 - list maps (memory regions)
 - change memory protections
 - touchtrace
 - filedescriptor set/get/mod..
 - get/set signals
 - get regs, set regs

#endif
