sdb_incdir = rizin_incdir

subdir('src')

sdb_exe = executable('sdb_native', 'src/main.c',
  dependencies: sdb_native_dep,
  install: false,
  native: true,
  implicit_include_directories: false,
)

sdb_gen_cmd = [
  sdb_exe,
  '@OUTPUT@',
  '==',
  '@INPUT@'
]
