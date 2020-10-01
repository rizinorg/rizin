Sandboxing r2
=============

rizin supports sandboxing natively by wrapping all attempts
to access the filesystem, network or run programs.

But for some platforms, the kernel provides a native sandboxing
experience. ATM only OSX and OpenBSD are supported by r2, feel
free to extend the support to Linux and Windows.

OSX
---

OSX Seatbelt implements a system-level sandbox for applications,
the rules are described in a lispy .sb file:

	$ sandbox-exec -f rizin.sb r2 -S /bin/ls

**NOTE**: r2 -S is an alias for -e cfg.sandbox=true


OpenBSD (from 5.9)
------------------

OpenBSD comes with support for sandboxing using the pledge(2) syscall.

Only the following are allowed:

- stdio and tty manipulation
- filesystem reading
- mmap(2) `PROT_EXEC` manipulation

OpenBSD (until 5.9)
-------------------

OpenBSD comes with support for sandboxing using the systrace utility.

	$ man systrace

Generate default profile

	$ systrace -A r2 /bin/ls

Run with the generated profile

	$ systrace -a r2 -S /bin/ls

FreeBSD (from 10.0)
-------------------

FreeBSD comes with the Capsicum framework support,
 using cap_enter(2).

Operations limited on what basic capability mode support.

Other
-----

Only r2's sandbox is supported.

- disables file system access
- disables network connectivity
- disables forks (no shell escapes or debugger)
- activated before showing the prompt

	$ r2 -S /bin/ls
