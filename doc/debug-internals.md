# Rizin Debugger Internals

The debugger is designed using a multi-tiered plug-in architecture that allows
overriding functionality for architecture or platform-specific reasons.

The bulk of the debugger functionality within Rizin core is split between the
"io", "reg", "bp", and "debug". More information on the specific files within
the tree follows.


## librz/include/r_debug.h

This is the main header file for the debugger. It defines all the relevant
structures and top-level functions, APIs, etc. The debugger plug-in API is also
defined in here.


## librz/io/p/io_debug.c

In order to interface with Rizin IO, a plug-in is provided. This handles, for
example, spawning processes under a debugger.


## librz/reg

The "reg" module provides functionality for reading and writing registers as
well as setting up profiles. (??profiles??)

The functionality lives in the following files:
(?? why so many files? can this be simplified??)

    librz/reg/arena.c        // ?? used by analysis and debugger
    librz/reg/cond.c         // condition registers
    librz/reg/double.c       // support for double-precision floating point numbers
    librz/reg/profile.c      // ?? used by analysis and debugger
    librz/reg/reg.c          // top-level register specific code (all of rizin)
    librz/reg/value.c        // dealing with register values
    librz/reg/t/p.c          // test code for printing general-purpose registers
    librz/reg/t/regdiff.c    // ?? test code for?
    librz/reg/t/test.c       // test code for register handling


## librz/bp

The "bp" subsystem of Rizin implements all the necessary details for dealing
with breakpoints on any given architecture. It handles managing the list of
breakpoints and more.

Rizin supports a multitude of different types of breakpoints.
(`??` is there a list? sw, hw, and trace? anything else??)

    librz/bp/bp.c            // main breakpoint management code
    librz/bp/io.c            // setting and resetting(??) breakpoints
    librz/bp/parser.h        // header for breakpoint parser (??)
    librz/bp/parser.c        // code for breakpoint parser (??)
    librz/bp/plugin.c        // breakpoint plugin management
    librz/bp/traptrace.c     // traptrace (??)
    librz/bp/watch.c         // watch points (mostly not implemented)

For architecture specific-handling, "bp" delegates various functionality to
plugins. The interface for these plugins is much simpler than other plugins
used in the Rizin debugger -- they only define which byte sequences represent
valid breakpoints for a given architecture.

    librz/bp/p/bp_arm.c      // ARM64, ARM, Thumb, Thumb-2 (big/little endians)
    librz/bp/p/bp_bf.c       // Brainfuck!
    librz/bp/p/bp_mips.c     // MIPS, big/little endian
    librz/bp/p/bp_ppc.c      // PowerPC, big/little endian
    librz/bp/p/bp_sh.c       // SuperH
    librz/bp/p/bp_x86.c      // int3...


## librz/debug/debug.c

The main top-level debugger functionality lives here. It aims to abstract away
the common code flow and integration into Rizin while delegating more nuanced
system interactions to plug-ins.

    librz/debug/arg.c        // used by the analysis engine (??)
    librz/debug/desc.c       // code for handling file descriptors inside an inferior
    librz/debug/esil.c       // ESIL related debugging code (??)
    librz/debug/map.c        // top-level API for dealing with memory maps
    librz/debug/pid.c        // top-level API for dealing with processes
    librz/debug/plugin.c     // top-level debugger plugin API handling
    librz/debug/reg.c        // top-level code for register r/w and display
    librz/debug/signal.c     // top-level functions for signals
    librz/debug/snap.c       // code for saving, restoring, showing memory snapshots
    librz/debug/trace.c      // top-level tracing API (counting insn hits, etc)
    librz/debug/t/main.c     // test code for the debugger API

## librz/core/cmd_debug.c

Most of the time a debugger is used by a human to try to understand subtle
problems with software and/or hardware. That task would be very difficult
without a user interface of some kind. The CLI commands exposed to Rizin are
implemented in here. To get more information about this interface, consult the
user manual or try "d?" to get a crash course.


## Debugger Plug-Ins

As mentioned before, the platform specific debugger functionality is delegated
to back-end plugins that implement the necessary interactions, protocols, or
otherwise to get the job done. These plug-ins implement the rizin debugger
plug-in API defined in r_debug.h.


### librz/debug/p/debug_bf.c

A debugger plug-in capable of debugging brainfuck code!

    librz/debug/p/bfvm.c     // Brainfuck VM implementation
    librz/debug/p/bfvm.h


### librz/debug/p/debug_bochs.c

A debugger plug-in that utilizes bochs emulator to control execution.

### librz/debug/p/debug_esil.c

This debugger plug-in enables debugging and tracing Rizin own intermediate
language, Evaluable Strings Intermediate Language (ESIL).

### librz/debug/p/debug_gdb.c

A Rizin debugger plug-in that uses a remote GDB server/stub as its backend.
The protocol parsing itself is located at shlr/gdb. And corresponding IO plugin is
located in librz/io/p/io_gdb.c

### librz/debug/p/debug_native.c

The "native" debugger plug-in is a bit of a doozy. It implements functionality
for debugging on the most common platforms available: Windows, OSX, Linux, and
BSD. Much of the underlying debug API between these platforms are similar and
thus much of the code within this plug-in is shared. The parts that are not
shared are implemented by platform-specific functions that are provided in the
following files:

    // architecture-specific debugger code
    librz/debug/p/native/arm.c                       // unused?
    
    // code for handling backtracing
    librz/debug/p/native/bt.c
    librz/debug/p/native/bt/fuzzy-all.c
    librz/debug/p/native/bt/generic-x64.c
    librz/debug/p/native/bt/generic-x86.c
    
    // architecture-specific register handling
    librz/debug/p/native/drx.c                       // x86-specific debug registers
    librz/debug/p/native/reg.c                       // cute include of the files below
    librz/debug/p/native/reg/kfbsd-x64.h
    librz/debug/p/native/reg/kfbsd-x86.h
    librz/debug/p/native/reg/netbsd-x64.h
    librz/debug/p/native/reg/netbsd-x86.h
    librz/debug/p/native/reg/windows-x64.h
    librz/debug/p/native/reg/windows-x86.h
    
    // platform-specific debugger code on Linux
    librz/debug/p/native/linux/linux_debug.c         // main linux-specific debugging code
    librz/debug/p/native/linux/linux_debug.h         // including cute penguin ascii art
    
    // architecture-specific register handling on Linux (?? what is this format??)
    librz/debug/p/native/linux/reg/linux-arm.h
    librz/debug/p/native/linux/reg/linux-arm64.h
    librz/debug/p/native/linux/reg/linux-mips.h
    librz/debug/p/native/linux/reg/linux-ppc.h
    librz/debug/p/native/linux/reg/linux-x64.h
    librz/debug/p/native/linux/reg/linux-x64-32.h
    librz/debug/p/native/linux/reg/linux-x86.h
    
    // platform-specific debugger code on Windows
    librz/debug/p/native/w32.c                       // !! not used by anything else
    librz/debug/p/native/maps/windows.c              // platform-specific memory map handling
    librz/debug/p/native/windows/windows_debug.c     // main code for win32 debugger plugin
    librz/debug/p/native/windows/windows_debug.h     // including cute windows ascii art
    
    // platform-specific debugger code on XNU (OSX/iOS/etc)
    librz/debug/p/native/darwin.c                    // !! not used by anything else
    librz/debug/p/native/maps/darwin.c               // platform-specific memory map handling
    librz/debug/p/native/xnu/xnu_debug.c             // main XNU-specific debugging code
    librz/debug/p/native/xnu/xnu_debug.h             // including cute apple ascii art
    librz/debug/p/native/xnu/trap_arm.c              // ARM family hardware bps (??)
    librz/debug/p/native/xnu/trap_x86.c              // x86 family hardware bps (??)
    librz/debug/p/native/xnu/xnu_excthreads.c        // additional XNU thread handling
    librz/debug/p/native/xnu/xnu_threads.c           // XNU thread and register handling
    librz/debug/p/native/xnu/xnu_threads.h
    
    // architecture-specific register handling on XNU (?? what is this format??)
    librz/debug/p/native/xnu/reg/darwin-x86.h
    librz/debug/p/native/xnu/reg/darwin-arm.h
    librz/debug/p/native/xnu/reg/darwin-ppc.h
    librz/debug/p/native/xnu/reg/darwin-arm64.h
    librz/debug/p/native/xnu/reg/darwin-x64.h

    // platform-specific debugger code on BSD
    librz/debug/p/native/bsd/bsd_debug.c         // main BSD debugging code
    librz/debug/p/native/bsd/bsd_debug.h


### librz/debug/p/debug_qnx.c

A debugger plug-in that enables debugging code natively on QNX systems. Corresponding
IO plugin is located in librz/io/p/io_qnx.c
See doc/qnx

### librz/debug/p/debug_rap.c

See doc/rap

### librz/debug/p/debug_winkd.c

A debugger plugin that enables debugging code remotely via WinDbg protocol. WinDbg protocol
parser is located in shlr/winkd. Corresponding IO plugin located in librz/io/p/io_winkd.c
See doc/winkd

## Conclusion

Best of luck!
