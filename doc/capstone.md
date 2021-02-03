Capstone
========

Capstone Engine is the disassembler engine used by Rizin by default for 
some architectures.

Rizin supports capstone 3, 4 and next.

* capstone3: legacy support (only for Debian probably)
* capstone4: stable release at the moment of writing this
* capstone-next: next branch, still under development

By default Rizin will build statically against a bundled version of capstone4
(with some custom patches applied). Please be aware that by default Rizin
will download Capstone through meson subprojects in the source directory
`subprojects/capstone`.

Using system capstone
---------------------

You can build Rizin against the system version of capstone, by specifying the
`use_sys_capstone` meson option and then compile as usual.

```
$ meson -Duse_sys_capstone=true build
```

Using another version of capstone
---------------------

Although by default Rizin uses capstone4, it is possible to compile it with
version 3 or the next version, by using `use_capstone_version` meson option.

```
$ meson -Duse_capstone_version=v3 build-capstonev3
```
or
```
$ meson -Duse_capstone_version=next build-capstonev5
```