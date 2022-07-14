SDB (string database)
=====================

sdb is a simple string key/value database based on djb's cdb
disk storage and supports arrays introspection.

Author
------
pancake <pancake@nopcode.org>

Contains
--------
* namespaces (multiple sdb paths)
* atomic database sync (never corrupted)
* commandline frontend for sdb databases
* arrays support (syntax sugar)

Rips
----
* disk storage based on cdb code
* linked lists from rizin api

Compilation
-----------
SDB requires [Meson](https://mesonbuild.com/) and [Ninja](https://ninja-build.org/) buildsystems to be built:
```
meson build
ninja -C build
```

Changes
-------
I have modified cdb code a little to create smaller databases and
be memory leak free in order to use it from a library.

The sdb's cdb database format is 10% smaller than the original
one. This is because keylen and valuelen are encoded in 4 bytes:
1 for the key length and 3 for the value length.

In a test case, a 4.3MB cdb database takes only 3.9MB after this
file format change.

Usage example
-------------
Let's create a database!
```
$ sdb d hello=world
$ sdb d hello
world
```
Using arrays (>=0.6):
```
$ sdb - '[]list=1,2' '[0]list' '[0]list=foo' '[]list' '[+1]list=bar'
1
foo
2
```
Using the commandline without any disk database:
```
$ sdb - foo=bar foo a=3 +a -a
bar
4
3
```
```
$ sdb -
foo=bar
foo
bar
a=3
+a
4
-a
3
```
Remove the database
```
$ rm -f d
```
