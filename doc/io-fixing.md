`r_io/r_core-file` fixing
=======================

Conceptual things:
------------------

- in general only code from `r_io` should be used for io related stuff, io is NOT a core-task
	- wrappers are ok, but no re-implementations (there might be exceptions but those must be reasonable argued)
		- linkage is not argument -> use RIOBind
	- esil-custom reads and writes should use RIOBind too
- if a file gets opened a RIODesc MUST be created
- if a file gets opened in usual cases a RIOMap MUST be created
- if a file gets opened in unsusual cases it's not necessary to create a RIOMap
	- if no RIOMap was created for a fd reading and writing from and to this fd is only possible via `r_io_pread` and `r_io_pwrite`
	- this is only an option if only 1 file can be opened for a task or if the fd will never see the user-land
		- Rahash2 for example won't need creating a RIOMap
- if a file gets closed all RIOMaps for that belong to the fd MUST get destroyed
- if a file gets closed the RIODesc MUST get destroyed
- the cores primary task is to delegate the different parts of r2
	- creating a new RIOMap or RIODesc on file-opening is NOT a core-task
	- the same goes for destroying RIOMaps and RIODesc on closing a file
    	- there is no need for a map-list in the core directly. core->io->maps is the only list to store maps (for the long run, functions that return a list with maps are ok)

Documentation:
--------------

There is no need for a huge documentation!!! But code with fundamental
importance often needs a few lines on what it should do, its concept and
sometimes a few lines of the code itself need some kind of 'justification' or
explanation. librz/io/vio.c is a hardcore example for this RIO-code has
fundamental importance, because everything will fail if io does not work
correctly.  This is needed to make bug-fixing easier, faster and better.

Need review:
------------

	librz/io/io.c
	librz/core/file.c

Tasks:
------

- we should fix all the tests before doing this.
	- talk about ioneg
- remove re-implemtations of `r_io` (middle)
- implement `r_io_open_at` (easy) ; this should open a file, add a RIODesc and a RIOMap that maps the file to an offset that is passed as an arg
- make `r_io_open` creating a new map (easy) ; this should open a file, add a RIODesc and a RIOMap that maps the file to 0
  - this means cleaning up `r_core_file_open` too (hard?)
- implement `r_io_open_no_map` (easy) ; this should open a file and add a RIODesc. the file can only be accessed via `r_io_pread` and `r_io_pwrite`
- make `r_io_close` destroy all maps that belong to the file that should be closed (easy)
  - this means cleaning up `r_core_file_close` too (hard?)
- implement (hard); this should find all maps in a certain range, resolve their fds, RIODescs and paddr and then call pwrite
- implement (hard); this should find all sections in a certain range, resolve the maddr that belongs to a vaddr and call mwrite, unsectioned area should be passed directly to mwrite
- implement `r_io_reopen` (easy); keep the maps for a fd and reopen it, possibly with different permissions
	- this means cleaning up `r_core_file_reopen` too (hard?)
