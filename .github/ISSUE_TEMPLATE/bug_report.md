---
name: Bug report
about: Create a report to help us improve

---

# This template is meant for bug reports, if you have a feature request, please be as descriptive as possible and delete the template

Make sure you are testing using the latest git version of rizin before submitting any issue.

*If you would like to report a bug, please fill the template below*

### Work environment

| Questions                                            | Answers
|------------------------------------------------------|--------------------
| OS/arch/bits (mandatory)                             | Debian arm 64, Ubuntu x86 32
| File format of the file you reverse (mandatory)      | PE, ELF etc.
| Architecture/bits of the file (mandatory)            | PPC, x86/32, x86/64 etc.
| `rizin -v` full output, **not truncated** (mandatory)  | rizin 0.2.0-git @ linux-x86-64, package: 0.2.0.1 (ret2libc) commit: c875be9afde5a6eed037249854b8a8759517263c, build: 2021-01-26__18:17:13


### Expected behavior

### Actual behavior

### Steps to reproduce the behavior
- Please share the binary if it is shareable by drag and dropping it here in a zip archive (mandatory)
- Use [Asciinema](https://asciinema.org) to describe the issue and share the link here (mandatory if you can't share the binary)
- Use code markdown `CODE` to make your code visible
- Or even better, create a Pull Request containing the test case in the [`test/`](https://github.com/rizinorg/rizin/tree/dev/test) folder. See, for example, [`test/db/cmd/cmd_search`](https://github.com/rizinorg/rizin/blob/dev/test/db/cmd/cmd_search).
- If the test requies to use the binary of some kind, please create a Pull Request to the [rizinorg/rizin-testbins](https://github.com/rizinorg/rizin-testbins) repository.

### Additional Logs, screenshots, source code,  configuration dump, ...

Drag and drop zip archives containing the Additional info here, don't use external services or link.
