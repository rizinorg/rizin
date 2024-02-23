# RzIO

This library contains is about all I/O operations that are needed in the Rizin
framework. The main concepts here are `RzIO`, `RzIODesc`, `RzIOMap`, and
`RzIOPlugin`. When working with the Rizin framework, files are "mapped" into a
64bit address space. When you open a raw binary file, it is opened at address 0,
for example. However, you could open other files at different addresses and view
all of them together in the same address space.

`RzIO` is the main object through which other modules perform I/O and it links
together all RzIO concepts. 

`RzIODesc` represents an opened URI (like a local file). These descriptors have
an URI that specify what `RzIOPlugin` to use to open a resource. The most common
one allows users to open local files, however one could open files over an HTTP
server, inside a ZIP-compressed file, from the shared memory, etc.. For example,
`zip:///myfile.zip//file_inside.elf` would open the file `file_inside.elf` by
reading the ZIP file `myfile.zip` and uncompressing it on the fly.

`RzIOMap` expresses how a `RzIODesc` is mapped into the Rizin address space.
When analyzing a raw binary file, for example, you may just want to map the
whole file, however when dealing with binary file formats (e.g. ELF, PE, MachO)
having the file layed out in memory similarly to how a loader would load it,
greatly helps analyzing the binary. Thus, through `RzIOMap` you specify how
parts of a `RzIODesc` are mapped into the memory (usually sections/segments are
mapped at specific addresses).

Files are opened by default in read-only mode, however it is usually possible to
open/re-open them in write mode too. When this is done, writes in the mapped
addresses are done in the real resource, if possible. If users want to write
some temporary data without actually modifying the resource, it is useful to use
the *cache* concept in `RzIO`. The cache provides a layer on top of `RzIOMap` to
write/read data temporarily.

## What can I expect here?
- I/O operations, like read from address, write to address, seek, resize, etc.
- Functions to open new files/resources
- Functions to map parts of a RzIODesc into the Rizin space
- Functions to manipulate maps and opened descriptors
- Functions to deal with the cache
- `RzIO` Plugins to perform I/O operations on various kinds of resources
