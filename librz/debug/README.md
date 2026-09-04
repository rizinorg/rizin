#THIS IS A WORK IN PROGRESS

The `rz_debug_continue_kill` function is the core execution engine of the Rizin debugger. It manages process resumption, handles background events/exceptions, and determines whether to return control to the user or silently keep running.

---

```c
RZ_API int rz_debug_continue_kill(RzDebug *dbg, int sig);

```

* **Returns:** The active Thread ID (**TID**) where the debugger halted, or `0` if the process died.

---

## High-Level Workflow

The function executes a continuous control loop divided into three main phases:

### 1. Process Resumption & Recoil

* **Time-Travel Check:** If inspecting a reverse-debugging session's past history, it skips live execution and forwards through recorded snapshots instead.
* **Recoil (Step-Off):** If the program counter is sitting exactly on a breakpoint, it temporarily lifts the breakpoint, single-steps forward by one instruction, restores the breakpoint, and resumes. This prevents the debugger from getting trapped on the same line.

### 2. The Silent Event Filter

When the target process hits a trap, the loop intercepts the event reason (`rz_debug_wait`). If the event is an internal background task, it handles it silently and loops back (`continue`) to keep the program running without bothering the user:

* **Conditional Breakpoints:** Evaluates the condition; resumes if false.
* **Disabled Breakpoints:** Ignores and skips over them.
* **OS Events (Linux/Windows):** Automatically processes process forks (`fork`), thread creations (`NEW_TID`), thread exits, and library loads.
* **Tracepoints:** Logs the tracing metric, steps over it, and moves on.
* **OS Signals:** Either injects the signal directly into the application's native signal handler or forcibly steps past the faulting instruction to skip the handler entirely.

### 3. Cleanup & Halt

When a legitimate user breakpoint or unexpected crash occurs, the loop breaks:

1. **Thread Alignment:** Synchronizes the debugger's focus to the specific thread that tripped the halt.
2. **Breakpoint Restoration:** Restores software breakpoint patches back into memory.
3. **History Snapshot:** If recording is active, it saves a time-travel checkpoint so the user can safely rewind back to this exact stop later.