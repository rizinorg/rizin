# Command parsing and command handling

Rizin has moved away from the default way of parsing radare2 commands and the
way commands were handled there. It enables by default what is called in r2
`cfg.newshell`, which enables a generated parser that parses rizin commands and
a new way of registering and developing commands.

## A bit of history

Rizin is a fork of radare2. Radare2 did not have, until recently, a generic
parser for user inputs, but each command had to parse its arguments by
itself. Moreover, there was no global register of commands available in the
radare2 shell, instead the input was chopped by looking for specific characters
and then it was analyzed char by char, using big switch-cases to recognize the
right command.

As an example, you can see
[cmd_flag.c:1163](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd_flag.c#L1163),
which identifies the `fsr` command and then parses its input to check if an
argument was available or not.

This approach, although simple at the beginning, has some drawbacks like the
inconsistency coming from having many different places in the code doing mostly
the same thing (e.g. checking if an argument is available or not), the
inability to easily register/unregister new commands at runtime (e.g. a new Core
plugin that wants to provide a new command) or the inconsistency between
commands actually available and commands shown to users in help messages.

## cfg.newshell

Not long ago, radare2 introduced the variable `cfg.newshell`, that when enabled
allows you to use new features in the code. Rizin has chosen to enable this by
default and it is going to transition most commands to the new way of writing
commands, which we think will make it easier/faster to write commands and make
the overall CLI experience more consistent and reliable.

Rizin uses a parser generated with
[tree-sitter](https://tree-sitter.github.io/tree-sitter/), which allows you to
write grammars in JavaScript. You can see our grammar
[here](https://github.com/rizinorg/rizin/blob/dev/shlr/rizin-shell-parser/grammar.js).
The parser recognizes some basic statement of the rizin/radare2 shell language, like:

- [basic statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L330): `<command-name> <arg1> <arg2> ... <argN>`
- [temporary modifier statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L124): `<statement> @ <address`, `<statement> @a:x86:32`, etc.
- [iterator statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L142): `<statement> @@ sym.*`, `<statement> @@=<addr1> <addr2> ... <addrN>`, etc.
- [redirection and pipe statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L177): `<statement> [fd|type]> <file>`, `<statement> | <program>`, etc.
- [grep statements](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/shlr/rizin-shell-parser/grammar.js#L184): `<statement>~<grep-pattern>`
- and many others

These patterns deal with the structure of the rizin/radare2 shell language, but
they don't parse the input of each specific command available in the rizin
shell (e.g. `af`, `pd`, etc.). The parser just splits the input statement into a
"command name" and a list of "arguments".

### Commands registry

The parser alone already provides better consistency with regards to how the
shell behaves, as all commands are split in the same way and it has a more rigid
behavior. However it was also essential to have a global commands registry,
where a command could be registered together with all the information associated
with it, like help messages, description, etc..

The module
[RzCmd](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h)
is the one in charge of dealing with commands. It provides API to register a new
"command descriptor" (called `RzCmdDesc`), deregister it, call the right command
descriptor handler based on a list of command name + arguments, get the help of
a command and potentially do many other things.

As radare2/rizin commands mainly form a tree, `RzCmdDesc` are organized in a
tree, with each descriptor having references to its parent and its children.
Moreover, a descriptor has its help messages and its handler.

To make the retrieval of the right command easier, they are also stored in a
hashtable, using their names as keys.

## How to write a new command?

Let's make an example and suppose we want to add the `sky` command, which would
find all occurrences of the word "sky" in a binary. By looking at
[cmd.c](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd.c#L7118)
we can find the right function where to define this new command. In this case,
it would be the `s` branch, which does some additional initialization in
`cmd_seek_init`. `cmd_seek_init` is defined
[here](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd_seek.c#L65)
and it gets called with `parent` being the command descriptor of the `s`
command. We of course want our `sky` command to be a child of `s`.

Now we need to choose what kind of `RzCmdDesc` we want to have. We can see the
various types in the `RzCmdDescType` enum.

For now, suppose we simply want a regular `sky` command under `s`. It is enough
to add a line with `DEFINE_CMD_ARGV_DESC (core, sky, parent);`. This macro
expects some things in place:

- a handler named `sky_handler` of the type
  [`RzCmdArgvCb`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h#L29),
  which gets argc/argv and does the actual job of the `sky` command. See
  `RzCmdStatus` enum for a list of possible status the command handler can
  return.
- a `RzCmdDescHelp` structure named `sky_help`, which shall be defined/declared
  together with all others in `cmd_helps.c`/`cmd_helps.h`. This structure
  provides all the strings that are useful to understand what a command does and
  they can be queried by using `<cmd>?` or `<cmd>??`.
  
If at some point we want to make `sky` a group and add some sub-commands to it
(e.g. `sky`, `skyl`, `skyf`, `skyp`) we have to change its type to
`RZ_CMD_DESC_TYPE_GROUP` by using `DEFINE_CMD_ARGV_GROUP_EXEC` instead of
`DEFINE_CMD_ARGV_DESC`. So we would use something like:
```C
DEFINE_CMD_ARGV_GROUP_EXEC (core, sky, parent);
DEFINE_CMD_ARGV_DESC (core, skyl, sky_cd);
DEFINE_CMD_ARGV_DESC (core, skyf, sky_cd);
DEFINE_CMD_ARGV_DESC (core, skyp, sky_cd);
```

`DEFINE_CMD_ARGV_GORUP_EXEC (core, sky, parent)` expects:
- a handler named `sky_handler`, as before
- a `RzCmdDescHelp` structure named `sky_help`, as before. This is used to
  describe details and help messages of the `sky` command, as before. It should
  explain how the `sky` command works, what are its arguments, etc.. For
  example, its description could be something like `It prints the addresses, one per
  line, of each occurrence of the "sky" word in the currently opened file.`,
  while its summary `Finds occurrences of word "sky"`.
- a `RzCmdDescHelp` structure named `sky_group_help` which is used to describe
  the `sky` command as a group. For example, the summary of the group could be
  `Commands to work with the sky, planets and stars`.
  
If we wanted to have a group named `sky` without an actual `sky` command, we
would instead use `DEFINE_CMD_ARGV_GROUP` macro. In this case, the handler
`sky_handler` is not expected/required.

## How to convert an oldinput command descriptor to argv?

If we want to convert a particular sub-command, just add the command we want
to convert as explained in the previous section. `RzCmd` will automatically
select the new handler if it can finds one.

If we want to convert an entire sub-tree of the available commands (e.g. we want
to convert all `y` sub-tree), we have to start by adapting
[`rz_core_cmd_init`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd.c#L7176),
by making sure to specify a `descriptor_init` if not available, help structures
as required, the type of the command descriptor (very likely it will be a
`RZ_CMD_DESC_TYPE_GROUP`), and the command handler, in case the name of the
group is used to also identify a command.

At this point we can either convert in one shot all existing subcommands to use
`RZ_CMD_DESC_TYPE_ARGV`/`GROUP` as appropriate (this is the state we want to be
in, but it may require time to convert everything), or we could do the
transition gradually and define the subcommands as `RZ_CMD_DESC_TYPE_OLDINPUT`.

If we take the `RZ_CMD_DESC_TYPE_ARGV`/`GROUP` approach, we just have to
create new commands like explained above. If possible, try to refactor the code
to share as much as possible with existing handlers and avoid duplication. If
the command to implement is simple enough, don't waste too much time with this,
as `cfg.newshell` is anyway the default.

Otherwise, `RZ_CMD_DESC_TYPE_OLDINPUT` is used to describe command handlers that
do the parsing themselves, like the existing ones, and handlers of this type
have the signature `typedef int (*RzCmdCb) (void *user, const char *input)`. We
can define children of the command descriptor with `DEFINE_CMD_OLDINPUT_DESC`
and mostly re-use existing code. As an example, see [commit
cde558e6e5788d0a6d544ab975b144ed59190676](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd_write.c#L2174).
In that case, only some commands (`w0`, `w1+`, `w6`, `wB`, etc.) were converted
to the newshell style, while `wh`, `we`, `wp`, etc. were still handled by the
existing handlers.

To define the command descriptor as `RZ_CMD_DESC_TYPE_OLDINPUT`, we can use
`DEFINE_CMD_OLDINPUT_DESC (core, yz, parent)`, which expects:
- a handler named `yz_handler_old` of the type
  [`RzCmdCb`](https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/include/rz_cmd.h#L28),
  which gets `RzCore` as first argument and a pointer to the first character
  after `yz` (the name of the command) of the input string.
- a `RzCmdDescHelp` structure named `yz_help`, which shall be defined/declared
  together with all others in `cmd_helps.c`/`cmd_helps.h`. This structure
  provides all the strings that are useful to understand what a command does and
  they can be queried by using `<cmd>?` or `<cmd>??`.
  
We probably won't need to create `yz_handler_old` from scratch, as there is
already code that handles that, though it is probably nested in some
switch-cases (e.g.
https://github.com/rizinorg/rizin/blob/cde558e6e5788d0a6d544ab975b144ed59190676/librz/core/cmd.c#L878).
In such a case, we are expected to do a bit of refactoring and extract pieces of
code in a separate function, named `yz_handler_old`, and use it in the
switch-case code.
