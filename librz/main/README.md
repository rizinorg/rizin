# RzMain

The `rz_main` library implements CLI entry points for the Rizin toolset and exports
them as C API (see `rz_main.h`).

> [!NOTE]
> Internally used in `binrz\*` for creating binaries.

## Tools

[Description of each utility](https://book.rizin.re/src/introduction/overview.html)

## Architecture

`main.c` contains:
- dispatch table mapping tool names to their callbacks and corresponding `rz_main_find` 
- `rz_main_version_print` for obtaining a version of the tool

Each file with tool name provide CLI logic.