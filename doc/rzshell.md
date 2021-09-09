# Command parsing and command handling

Rizin has moved away from the default way of parsing radare2 commands and the
way commands were handled there. It enables by default what is/was called in r2
`cfg.newshell`, which enables a generated parser that parses rizin commands and
a new way of registering and developing commands.

## A bit of history

Rizin is a fork of radare2. Radare2 did not have, until recently, a generic
parser for user inputs, but each command had to parse its arguments by itself.
Moreover, there was no global register of commands available in the radare2
shell, instead the input was chopped by looking for specific characters and then
it was analyzed char by char, using big switch-cases to recognize the right
command.

As an example, you can see
[cmd_flag.c:1163](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd_flag.c#L1163),
which identifies the `fsr` command and then parses its input to check if an
argument was available or not.

This approach, although simple at the beginning, has some drawbacks like the
inconsistency coming from having many different places in the code doing mostly
the same thing (e.g. checking if an argument is available or not), the inability
to easily register/unregister new commands at runtime (e.g. a new Core plugin
that wants to provide a new command) or the inconsistency between commands
actually available and commands shown to users in help messages.

## Rizin shell

Not long ago, radare2 introduced the variable `cfg.newshell` that, when enabled,
allows you to use new features in the code. Rizin has chosen to enable this by
default and it is going to transition most commands to the new way of writing
commands, which will make it easier/faster to write commands and make the
overall CLI experience more consistent and reliable.

Rizin uses a parser generated with
[tree-sitter](https://tree-sitter.github.io/tree-sitter/), which allows you to
write grammars in JavaScript. You can see our grammar
[here](https://github.com/rizinorg/rizin/blob/dev/shlr/rizin-shell-parser/grammar.js).
The parser recognizes the entire syntax of the rizin/radare2 shell language,
like:

- [basic statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L330): `<command-name> <arg1> <arg2> ... <argN>`
- [temporary modifier statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L124): `<statement> @ <address`, `<statement> @a:x86:32`, etc.
- [iterator statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L142): `<statement> @@ sym.*`, `<statement> @@=<addr1> <addr2> ... <addrN>`, etc.
- [redirection and pipe statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L177): `<statement> [fd|type]> <file>`, `<statement> | <program>`, etc.
- [grep statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L184): `<statement>~<grep-pattern>`
- and many others

These patterns deal with the structure of the rizin/radare2 shell language, but
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
[`RzCmd`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h)
is the one in charge of dealing with commands. It provides API to register a new
"command descriptor" (called
[`RzCmdDesc`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h#L153)),
deregister it, call the right command descriptor handler based on a list of
command name + arguments, get the help of a command and potentially do many
other things.

As rizin/radare2 commands mainly form a tree, `RzCmdDesc` are organized in a
tree, with each descriptor having references to its parent and its children.
Moreover, a descriptor has its help messages and its handler.

To make the retrieval of the right command easier, they are also stored in a
hashtable, using their names as keys.

## How to write a new command?

Let's make an example and suppose we want to add the `sky` command, which
would find all occurrences of the word "sky" in a binary. The first thing to
do is to see where `sky` command could be added by reading
[`librz/core/cmd_descs/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/6d901ca8a2ba674e268957fa8c24b3484bfc3626/librz/core/cmd_descs/cmd_descs.yaml).
`sky` is `s` command's subcommand and they are splitted and placed inside the .YAML 
file specified by the descriptor `subcommands` of the respective command. Since `sky`
starts with an `s`, its subcommands would be in [`librz/core/cmd_descs/cmd_seek.yaml`](https://github.com/rizinorg/rizin/blob/6d901ca8a2ba674e268957fa8c24b3484bfc3626/librz/core/cmd_descs/cmd_seek.yaml).
That file respects the same tree structure used when executing rizin and seeing its help,
so it should be simple to see where to place it. If we want to place it under the
`s` sub-tree, we just need to define the descriptors for the command with at least
`name`, `cname`, `summary` and a list of `args` accepted by the command.

Now we need to choose what kind of command (`type` field in YAML) we want to
have. We can see the various types in the
[`RzCmdDescType`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h#L135-L151)
enum, however let's assume we want a regular command, which is the default
one, so no action is required in this regard.

If our new `sky` command accepts a numeric argument, we can specify it in the
`args` list, by using the type `RZ_CMD_ARG_TYPE_NUM`.

Then we only need to write the actual code that performs the command's job.
You have to call it according to the `cname` field you previously set for the
`sky` command, appending `_handler` to that string.


Below you can see how the code for adding the `sky` command would look like:
```YAML
- name: s
  cname: cmd_seek
  summary: Seek to address
  type: RZ_CMD_DESC_TYPE_OLDINPUT
  subcommands:
    - name: sky
      cname: sky
      summary: Find all occurrences of the work "sky" in the opened file
      args:
        - name: n
          type: RZ_CMD_ARG_TYPE_NUM
          optional: true
```
```C
// cmd_seek.c (example, real place depends on the parent command)
static RzCmdStatus sky_handler(RzCore *core, int argc, const char **argv) {
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

If you are looking for the handler of command `x`, you just have to look at
the file
[`librz/core/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/9ce5003ca647cdfc181ac3c0f6206762ebb9e3e9/librz/core/cmd_descs.yaml).
By looking at the `cname` field of the command descriptor, you can see what
is the name of the handler of the `x` command. If the `cname` is `hex` and
the type is `RZ_CMD_DESC_TYPE_OLDINPUT`, then the handler will be named
`rz_hex`. In all other cases, the handler will be named `rz_hex_handler`.

Some examples:
- command: `wv`, type: unspecified (default to `RZ_CMD_DESC_TYPE_ARGV`), handler: `rz_write_value_handler`
- command: `w6d`, type: unspecified (default to `RZ_CMD_DESC_TYPE_ARGV`), handler: `rz_write_base64_decode_handler`
- command: `s`, type: `RZ_CMD_DESC_TYPE_OLDINPUT`, handler: `rz_cmd_seek`

## How to improve the help messages of a command

Find the command in
[`librz/core/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/9ce5003ca647cdfc181ac3c0f6206762ebb9e3e9/librz/core/cmd_descs.yaml),
then fix/improve the `summary` and/or `description` fields.

## How to show examples of a command or additional details

You may notice some commands like `env`, `%`, `*` and others have additional
sections when you show the extensive help with e.g. `env??` (or `%??`, etc.).
Those additional secions are called `details` and they can be specified,
again, in the file
[`librz/core/cmd_descs.yaml`](https://github.com/rizinorg/rizin/blob/9ce5003ca647cdfc181ac3c0f6206762ebb9e3e9/librz/core/cmd_descs.yaml).
The structure is explained at the beginning of the file and it can be seen in
existing commands (e.g.
https://github.com/rizinorg/rizin/blob/9ce5003ca647cdfc181ac3c0f6206762ebb9e3e9/librz/core/cmd_descs.yaml#L325
). The result, looks something like:
```
[0x00000000]> %??
Usage: %[varname[=varvalue]]   # get/set environment variables

Examples:
| %            # list all environment variables
| %SHELL       # print value of SHELL variable
| %TMPDIR=/tmp # set TMPDIR to "/tmp"
| envSHELL     # same as `%SHELL`

Environment:
| RZ_FILE          # currently opened file name
| RZ_OFFSET        # 10base offset 64bit value
| RZ_XOFFSET       # same as above, but in 16 base
| RZ_BSIZE         # block size
| RZ_ENDIAN        # 'big' or 'little'
| RZ_IOVA          # is io.va true? virtual addressing (1,0)
| RZ_DEBUG         # debug mode enabled? (1,0)
| RZ_SIZE          # file size
| RZ_ARCH          # value of asm.arch
| RZ_BITS          # arch reg size (8, 16, 32, 64)
| RZ_BIN_LANG      # assume this lang to demangle
| RZ_BIN_DEMANGLE  # demangle or not
| RZ_BIN_PDBSERVER # e pdb.server
```
