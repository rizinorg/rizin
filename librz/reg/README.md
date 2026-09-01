# RzReg

`RzReg` is the Rizin module for managing and manipulating register sets for various architectures. It provides a portable way to define register layouts, store their values, and access them by name or role.

## Components
The module is divided into several key components:

### RzReg
The main container that holds register sets, profiles, and arenas.

### RzRegProfile
Defines the register layout for a specific architecture. It includes:
- **Register Definitions**: Mapping names to types, sizes, and offsets.
- **Aliases**: Mapping common roles (like PC, SP) to specific registers.

### RzRegArena
A byte buffer that stores the actual values of registers. `RzReg` maintains a pool of arenas for each register type, supporting features like snapshots/undo.

### RzRegItem
Represents an individual register with its metadata (name, type, size, offset).

## Register Profile Format
Rizin uses a simple text format to define register profiles:

- **Alias**: `=<role> <name>`
- **Definition**: `(<type>@)<arena> <name> .<size> <offset> <packed> (# <comment>)`
  - The `(<type>@)<arena>` syntax allows specifying a logical register type that differs from the storage arena. For example, `xmm@fpu` defines a register of type `xmm` that is stored within the `fpu` arena. If `@` is omitted, the type and arena are the same.
  - `<name>`: The name of the register.
  - `.<size>`: The size of the register in bits. Must be prefixed with `.`.
  - `<offset>`: The offset within the arena in bytes. Bit offsets can be specified using `.bit` suffix (e.g., `48.2`).
  - `<packed>`: The packed size of the register (usually 0).
  - `(# <comment>)`: Optional comment.

## API Usage

### Initialization and Profile Loading

```c
RzReg *reg = rz_reg_new();
const char *profile = "gpr  rax  .64  0  0\n"
                      "gpr  rbx  .64  8  0\n"
                      "gpr  rip  .64  16 0\n"
                      "gpr  rsp  .64  24 0\n"
                      "=PC  rip\n" // program counter
                      "=SP  rsp\n"; // stack pointer
rz_reg_set_profile_string(reg, profile);
```

### Accessing Register Values

```c
// Get value by name
ut64 rax_val = rz_reg_getv(reg, "rax");

// Set value by name
rz_reg_setv(reg, "rbx", 0x1234);

// Access by role
ut64 pc_val = rz_reg_get_value_by_role(reg, RZ_REG_NAME_PC);
```

### Arena Management

```c
// Push current register state to the arena pool (snapshot)
rz_reg_arena_push(reg);

// Modify registers...
rz_reg_setv(reg, "rax", 0);

// Restore previous state
rz_reg_arena_pop(reg);
```

## Adding New Register Profiles

To add a new register profile for a supported or new architecture, follow these steps:

1. **Create the Profile File**: Create a new `.sdb.txt` file in `librz/reg/d/`. Use the format described in the "Register Profile Format" section.
2. **Update the Build System**: Open `librz/reg/d/meson.build` and add the base filename (without `.sdb.txt`) to the `sdb_files` list.

```meson
sdb_files = [
    'avr-ATmega8-8',
    'my-new-arch'  # Add your profile here
]
```

3. **Verify the Profile**:
    - Reconfigure and build Rizin.
    - Use the `drp` (display register profile) command in Rizin or use the `reg_example` to ensure it parses correctly.