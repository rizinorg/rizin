# How to report issues

Before reporting an issue with GitHub, be sure that:
* You are using the latest released version of Rizin or the latest git version
* You are using a clean installation
* The issue was not already reported

When the above conditions are satisfied, feel free to submit an issue while
trying to be as precise as possible. If you can, provide the problematic binary,
the steps to reproduce the error and a backtrace in case of SEGFAULTs. Try to
follow the issue template that comes by default. Any information will help to
fix the problem.

# How to contribute

There are a few guidelines that we need contributors to follow so that we can
try to keep the codebase consistent and clean.

## Getting Started

* Make sure you have a GitHub account and solid ability to use `git`.
* Fork the repository on GitHub.
* Create a topic branch from `dev`. Please avoid working directly on the `dev` branch.
* Make commits of logical units.
* Be sure to follow the CODINGSTYLE (more on this in [DEVELOPERS.md][]).
* Submit the Pull Request(PR) on Github.
* When relevant, write a test in [test/](test).

## Rebasing onto updated dev

Every so often, your PR will lag behind `dev` and get conflicts.

To "update" your branch `my-awesome-feature`, you *rebase* it onto
the latest `rizinorg/dev`, and *force-push* the result into your fork.

#### Step 1: Switch to `dev` branch.
```sh
$ git checkout dev
```
#### Step 2: Pull new commits published to rizinorg repo.
```sh
$ git pull https://github.com/rizinorg/rizin
```
#### Step 3: Switch back to `my-awesome-feature` branch.
```sh
$ git checkout my-awesome-feature
```
#### Step 4: Rebase the `my-awesome-feature` branch.
```sh
$ git rebase dev
```
Optionally, use the alternative mode "interactive rebase". It allows
to `squash` your commits all into one, reorder, reword them, etc.
```sh
$ git rebase -i dev
```
Follow git instructions when conflicts arise.

#### Step 5: Publish your updated local branch.
```sh
$ git push -f
```
This `-f` *force-flag* is needed because git commits are immutable: rebasing
creates newer versions of them. git needs to confirm the destruction of
previous incarnations.

When afraid to touch force and risk losing your work (do backups!..),
try *merging dev into your branch* instead of rebasing onto it.
This is discouraged, as it produces ugly hard-to-maintain commit history.

## Commit message rules

When commiting your changes into the repository you may want to follow some
rules to make the git history more readable and consistent:

* Start the message capitalized (only the first character must be in uppercase)
* Be short and concise, the whole concept must fit one line
* If a command is inlined, use backticks
* For extra details, add an empty line and use asterisk item list below
* Use present simple grammar tense (Add vs Added, Fix vs Fixed/Fixes)
* Add a double-hashtag if the change matters for the changelog (See below)

### Commit message hashtag list:

* ##analysis - analysis related
* ##asm      - assembler
* ##bin      - binary parsing
* ##build    - build fixes/changes
* ##config   - config variables changes/additions/renamings
* ##cons     - console/terminal-related
* ##crypto   - cryptography
* ##debug    - debugger stuff
* ##diff     - diffing code, strings, basic blocks, ...
* ##disasm   - disassembler
* ##doc      - documentation
* ##egg      - the `rz_lang` compiler
* ##emu      - emulation, including esil
* ##graph    - basic block graph, callgraph, ...
* ##io       - related to the `rz_io` library
* ##json     - json fixes/changes
* ##lang     - bindings
* ##meta     - metadata handling other than printing
* ##optimization-space/time optimizations
* ##port     - portability (new OS/architectures)
* ##print    - printing data, structures, strings, tables, types ..
* ##projects - saving/loading state
* ##refactor - improve code quality
* ##remote   - rizin over tcp, http, rap, serial .. including collaboration
* ##search   - rz_find, / command, ..
* ##shell    - commandline, newshell, ..
* ##signatures-searching/generating them
* ##test     - testing infrastructure fixes/changes
* ##tools    - rz-pm, rz_run, rz_ax ... that don't fit in other categories
* ##util     - core APIs
* ##visual   - visual UI, including panels

# Additional resources

 * [README.md][]
 * [DEVELOPERS.md][]

[README.md]: https://github.com/rizinorg/rizin/blob/dev/README.md
[DEVELOPERS.md]: https://github.com/rizinorg/rizin/blob/dev/DEVELOPERS.md

If you need more confidence in your git skills, check out this quick guide:
<https://learnxinyminutes.com/docs/git/>
