tags_rz_sources = [
  'dylib',
  'alloc',
  'time',
  'env',
  'fs',
  'network',
  'threads',
  'process',
  'stdout',
  'string'
]

custom_target('tags.rz',
  input: tags_rz_sources,
  output: 'tags.rz',
  command: [py3_exe, create_tags_rz_py, '@INPUT@'],
  capture: true,
  build_by_default: true,
  install: true,
  install_dir: rizin_flags
)
