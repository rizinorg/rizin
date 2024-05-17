libsdb_sources = files(
  'array.c',
  'base64.c',
  'buffer.c',
  'cdb.c',
  'cdb_make.c',
  'diff.c',
  'disk.c',
  'fmt.c',
  'lock.c',
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

include_files = files(
  'buffer.h',
  'cdb.h',
  'cdb_make.h',
  'sdb.h',
  'sdbht.h',
)

install_headers(include_files, install_dir: join_paths(rizin_incdir, 'sdb'))
