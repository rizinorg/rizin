# Command parsing and command handling

The Rizin shell language is originally derived from the Radare2 shell language.
There is a parser generated with
[tree-sitter](https://tree-sitter.github.io/tree-sitter/), which allows you to
write grammars in JavaScript. You can see our grammar
[here](https://github.com/rizinorg/rizin/blob/dev/subprojects/rizin-shell-parser/grammar.js).
The parser recognizes the entire syntax of the rizin shell language,
like:

- [basic statements](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/subprojects/rizin-shell-parser/grammar.js#L238): `<command-name> <arg1> <arg2> ... <argN>`
- [temporary modifier statements](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/subprojects/rizin-shell-parser/grammar.js#L98): `<statement> @ <address`, `<statement> @a:x86:32`, etc.
- [iterator statements](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/subprojects/rizin-shell-parser/grammar.js#L118): `<statement> @@ sym.*`, `<statement> @@=<addr1> <addr2> ... <addrN>`, etc.
- [redirection and pipe statements](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/subprojects/rizin-shell-parser/grammar.js#L146): `<statement> [fd|type]> <file>`, `<statement> | <program>`, etc.
- [grep statements](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/subprojects/rizin-shell-parser/grammar.js#L148): `<statement>~<grep-pattern>`
- and many others

These patterns deal with the structure of the rizin shell language, but
they don't parse the input of each specific command available in the rizin shell
(e.g. `af`, `pd`, etc.). The parser just splits the input statement into a
"command name" and a list of "arguments".

### Commands registry

The parser alone already provides better consistency with regards to how the
shell behaves, as all commands are split in the same way and it has a more rigid
behavior. However it was also essential to have a global commands registry,
where a command could be registered together with all the information associated
with it, like help messages, description, etc..

The module
[`RzCmd`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/include/rz_cmd.h)
is the one in charge of dealing with commands. It provides API to register a new
"command descriptor" (called
[`RzCmdDesc`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/include/rz_cmd.h#L388)),
deregister it, call the right command descriptor handler based on a list of
command name + arguments, get the help of a command and potentially do many
other things.

As rizin commands mainly form a tree, `RzCmdDesc` are organized in a
tree, with each descriptor having references to its parent and its children.
Moreover, a descriptor has its help messages and its handler.

To make the retrieval of the right command easier, they are also stored in a
hashtable, using their names as keys.

## How to write a new command?

Let's make an example and suppose we want to add the `sky` command, which
would find all occurrences of the word "sky" in a binary. The first thing to
do is to see where `sky` command could be added by reading
[`librz/core/cmd_descs/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/core/cmd_descs/cmd_descs.yaml).
`sky` is `s` command's subcommand and they are split and placed inside the .YAML
file specified by the descriptor `subcommands` of the respective command. Since `sky`
starts with an `s`, its subcommands would be in [`librz/core/cmd_descs/cmd_seek.yaml`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/core/cmd_descs/cmd_seek.yaml).
That file respects the same tree structure used when executing rizin and seeing its help,
so it should be simple to see where to place it. If we want to place it under the
`s` sub-tree, we just need to define the descriptors for the command with at least
`name`, `cname`, `summary` and a list of `args` accepted by the command.

Now we need to choose what kind of command (`type` field in YAML) we want to
have. We can see the various types in the
[`RzCmdDescType`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/include/rz_cmd.h#L326-L380)
enum, however let's assume we want a regular command, which is the default
one, so no action is required in this regard.

If our new `sky` command accepts a numeric argument, we can specify it in the
`args` list, by using the type `RZ_CMD_ARG_TYPE_NUM`.

Then we only need to write the actual code that performs the command's job.
You have to call it according to the `cname` field you previously set for the
`sky` command, appending `_handler` to that string.


Below you can see how the code for adding the `sky` command would look like:
```YAML
  - name: sky
    cname: sky
    summary: Print current address / Seek to address
    args:
      - name: limit
        type: RZ_CMD_ARG_TYPE_NUM
        optional: true
```
```C
// cmd_seek.c (example, real place depends on the parent command)
RZ_IPI RzCmdStatus rz_sky_handler(RzCore *core, int argc, const char **argv) {
	// argc/argv is like in main(), i.e. argv[0] always contains the command name
	int limit = -1;
	if (argc > 1) {
		limit = rz_num_math (core->num, argv[1]);
	}
	// ... add the logic of your command
	return RZ_CMD_STATUS_OK;
}
```

The YAML file is used at built-time (by meson only) to autogenerate two
files: `cmd_descs.c` and `cmd_descs.h`.

## Where is the handler of command `x`?

You can use the script `sys/rzshell_which.py` to get the name of the function
handling the specified command.

If that doesn't work, please report the problem to us! However, you can still
find the handler yourself by looking at the file
[`librz/core/cmd_descs/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/core/cmd_descs/cmd_descs.yaml).
By looking at the `cname` field of the command descriptor, you can see what is
the name of the handler of the `x` command. It is always of the form `rz_<cname>_handler`.
So for the command `x` with `cname = hex` the handler is `rz_hex_handler`.

Some examples:
- command: `wv`, type: unspecified (default to `RZ_CMD_DESC_TYPE_ARGV`), handler: `rz_write_value_handler`
- command: `w6d`, type: unspecified (default to `RZ_CMD_DESC_TYPE_ARGV`), handler: `rz_write_base64_decode_handler`

## How to improve the help messages of a command

Find the command in
[`librz/core/cmd_descs/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/6f40dfe493f0caf9e0541e1ee83e3d8012b5750f/librz/core/cmd_descs/cmd_descs.yaml),
then fix/improve the `summary` and/or `description` fields. If the command cannot be directly found in `cmd_descs.yaml`, look for the other files in `librz/core/cmd_descs`.

## How to show examples of a command or additional details

You may notice some commands like `e`, `w` and others have additional
sections where you can show more extensive help with `??` e.g. `e??` (or `w??` etc.).
Those additional sections are called `details` and they can be seen in
existing commands e.g.:
https://github.com/rizinorg/rizin/blob/c4a1a501fa9e998aec26005829d391dad3a30dca/librz/core/cmd_descs/cmd_eval.yaml#L14-L31
Their structure is explained at the beginning of [`librz/core/cmd_descs/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/c4a1a501fa9e998aec26005829d391dad3a30dca/librz/core/cmd_descs/cmd_descs.yaml#L27-L29).
A _possible_ difference between `?` and `??` is shown below:
```
[0x00000000]> w?
Usage: w[?]   # Write commands
| w <string>        # Write string
| wB[-]             # Set or unset bits with given value
| wv[1248]          # Write value of given size
| w0 <len>          # Write <len> bytes with value 0x00
| w<1248><+-> [<n>] # Increment/decrement byte, word, ...
| w6<de>            # Write base64 [d]ecoded or [e]ncoded string
| we<nsx>           # Extend write operations (insert bytes instead of replacing)
| wu <file>         # Apply unified hex patch (see output of cu)
| wr <len>          # Write <len> random bytes
| wc[j*-+ip?]       # Write cache commands
| wz <string>       # Write zero-terminated string
| wf[xfs]           # Write data from file, socket, offset
| ww <string>       # Write wide (16-bit) little-endian string
| wx[f]             # Write hexadecimal data
| wa[ifo]           # Write opcodes
| wb <hex>          # Write in current block a hexstring cyclically
| wm[-]             # Set binary mask hexpair to be used as cyclic write mask
| wo<?>             # Write a block with a special operation
| wD[/]             # Write de Bruijn pattern
| wd <src> <len>    # Duplicate <len> bytes from <src> offset to current seek
| ws <string>       # Write 1 byte for length and then the string

Detailed help for w <string> is provided by w??.
```
```
[0x00000000]> w??
Usage: w <string>   # Write string

Examples:
| w 123\n    # Write the chars '1', '2', '3' and a newline
| w ab\0cd\0 # Write the chars 'a', 'b', a NUL, 'c', 'd' and another NUL

Escape sequences:
| \0   # NUL (0x0)
| \a   # Bell (0x7)
| \b   # Backspace (0x8)
| \e   # Escape (0x1b)
| \f   # Form feed (0xc)
| \n   # Newline (0xa)
| \r   # Carriage return (0xd)
| \t   # Tab (0x9)
| \v   # Vertical tab (0xb)
| \\   # Backslash ('\')
| \xhh # Byte in hexadecimal
| \nnn # Byte in octal (eg. \033 for the escape char)
```
