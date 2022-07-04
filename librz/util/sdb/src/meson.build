libsdb_sources = files(
  'array.c',
  'set.c',
  'base64.c',
  'buffer.c',
  'cdb.c',
  'cdb_make.c',
  'diff.c',
  'disk.c',
  'fmt.c',
  'ht_uu.c',
  'ht_pp.c',
  'ht_up.c',
  'ht_pu.c',
  'journal.c',
  'json.c',
  #'json/api.c',
  #'json/indent.c',
  #'json/js0n.c',
  #'json/path.c',
  #'json/rangstr.c',
  'lock.c',
  'ls.c',
  'match.c',
  'ns.c',
  'num.c',
  'query.c',
  'sdb.c',
  'sdbht.c',
  'util.c',
  'text.c'
)

libsdb_inc = [platform_inc, include_directories(['..', '.'])]

libsdb = static_library('sdb', libsdb_sources,
  include_directories: libsdb_inc,
  implicit_include_directories: false,
  install: false,
)

sdb_dep = declare_dependency(
  link_whole: libsdb,
  include_directories: libsdb_inc,
)

if meson.is_cross_build()
  libsdb_native = static_library('sdb_native', libsdb_sources,
    native: true,
    include_directories: libsdb_inc,
    implicit_include_directories: false,
    install: false,
  )

  sdb_native_dep = declare_dependency(
    link_with: libsdb_native,
    include_directories: libsdb_inc,
  )
else
  sdb_native_dep = sdb_dep
endif

include_files = files(
  'buffer.h',
  'cdb.h',
  'cdb_make.h',
  'config.h',
  'ht_inc.h',
  'ht_pp.h',
  'ht_up.h',
  'ht_uu.h',
  'ht_pu.h',
  'ls.h',
  'sdb.h',
  'sdbht.h',
  'set.h',
)

install_headers(include_files, install_dir: join_paths(sdb_incdir, 'sdb'))
