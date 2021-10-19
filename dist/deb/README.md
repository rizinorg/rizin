These files are mainly created to support the
[Open Build Service](https://build.opensuse.org/package/show/home:RizinOrg/rizin), with the
[debtransform](https://raw.githubusercontent.com/openSUSE/obs-build/master/debtransform)
tool.

For example:
```
$ mkdir outdir
$ perl ./debtransform --changelog debian.changelog --release 0.3.0-1 . rizin.dsc outdir
```

If you want to build for an older version of Debian/Ubuntu that required special
patches, you can use a different .dsc file:
```
$ mkdir outdir
$ perl ./debtransform --changelog debian.changelog --release 0.3.0-1 . rizin-Debian_10.dsc outdir
```