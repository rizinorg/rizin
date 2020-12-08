Trying to escape from the librz/core mess, we should put all the heap stuff into a separate place and use it from analysis/heap.c

TODO

* remove all use of assert
* remove unused statements
* convert macros into C code, this should be a runtime library, not a compile time one
