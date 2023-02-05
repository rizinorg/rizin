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

include_files = files(
  'buffer.h',
  'cdb.h',
  'cdb_make.h',
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

install_headers(include_files, install_dir: join_paths(rizin_incdir, 'sdb'))
