Capstone
========

Capstone Engine is the disassembler engine used by Rizin by default for 
some architectures.

Rizin supports capstone 3, 4 and 5.

* capstone3: legacy support (only for Debian probably)
* capstone4: stable release at the moment of writing this
* capstone5: next branch, still under development

By default Rizin will build statically against a bundled version of capstone4
(with some custom patches applied). Please be aware that by default Rizin will
download Capstone in the source directory `shlr/capstone`.

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
$ meson -Duse_capstone_version=v5 build-capstonev5
```

Test different capstone versions
----------------------

As mentioned before, by default Rizin downloads capstone code in the source
directory `shlr/capstone`, so if you want to test the same set of changes on
multiple Capstone versions, you have to specify the `capstone_in_builddir`
option.

```
$ meson -Dcapstone_in_builddir=true -Duse_capstone_version=v3 build-capstonev3
```

The above command, for example, will download the Capstone code in the *build*
directory `build-capstonev3/shlr/capstone` instead of the *source* one.
