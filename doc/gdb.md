Connecting rizin with gdb
======================

Running gdbserver
-----------------

    $ gdbserver :2345 /bin/ls
    (gdb) target remote localhost:2345

Connecting from rizin
------------------

    $ rizin -D gdb gdb://127.0.0.1:2345


Supported implementations
=========================
rizin has support for connecting to remote GDB instances:

                x86-32   x86-64   arm    arm64   sh
    winedbg       x        x       -      -      -
    qemu          x        x       ?      x      -
    gdbserver     x        x       ?      ?      ?

    x = supported
    ? = untested
    - = not supported

Supported Commands
------------------

- read/write memory

  Writing or reading memory is implemented through the m/M packet.

- read registers

  Reading registers is currently implemented through the `g` packet of the gdb protocol.
  It returns the whole register profile at once.

- write registers

  There are two ways of writing registers. The first one is through the `P` packet.
  It works like this: `P<register_index>=<register_value>`
  The second one is the `G` packet, that writes the whole register profile at once.
  The implementation first tries to use the newer `P` packet and if it receives a `$00#`
  packet (not implemented), it falls back to the `G` packet.

- stepping

  Single-stepping is implemented through the `vCont;s` packet when vCont is supported,
  falling back to the `s` packet otherwise.

- breakpoints

  Software breakpoints are set and removed using the `Z0`/`z0` packets.
  Hardware breakpoints use `Z1`/`z1`. Watchpoints (read, write, access) use
  `Z2`/`z2`, `Z3`/`z3`, and `Z4`/`z4` respectively.

- attach/detach

  Attaching to a running process uses the `vAttach` packet. Detaching uses the `D` packet.
  Multiprocess detach uses `D;<pid>`.

- file access

  Remote file operations (open, read, close) are supported through the `vFile` packet,
  allowing rizin to read files (e.g. `/proc/<pid>/maps`) directly from the remote target.

- thread and process listing

  Thread and process enumeration is supported via XML target descriptions and the
  `qXfer:threads:read` packet.

Supported Packets
-----------------

- `?`  : Query stop reason
- `g`  : Read all registers at once
- `G`  : Write all registers at once
- `p`  : Read a single register
- `P`  : Write a single register
- `m`  : Read memory
- `M`  : Write memory
- `s`  : Single step
- `c`  : Continue execution
- `vCont` : Continue or step with optional signal, per-thread control
- `vAttach` : Attach to a process by PID
- `D`  : Detach from target
- `k`  : Kill the remote process
- `Z0`/`z0` : Set/remove software breakpoint
- `Z1`/`z1` : Set/remove hardware breakpoint
- `Z2`/`z2` : Set/remove write watchpoint
- `Z3`/`z3` : Set/remove read watchpoint
- `Z4`/`z4` : Set/remove access watchpoint
- `qSupported` : Query supported features
- `qRcmd` : Send a command to the remote target's interpreter
- `qOffsets` : Get load offsets for sections
- `vFile` : Remote file I/O operations
- `qXfer:threads:read` : Read thread list via XML
