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

if have_python
  tags_rz_cmd = [py3_exe, create_tags_rz_py, '@INPUT@']
else
  create_tags_rz_exe = executable('create_tags_rz', create_tags_rz_c,
    native: meson.is_cross_build(),
    install: false,
  )
  tags_rz_cmd = [create_tags_rz_exe, '@INPUT@']
endif

custom_target('tags.rz',
  input: tags_rz_sources,
  output: 'tags.rz',
  command: tags_rz_cmd,
  capture: true,
  build_by_default: true,
  install: true,
  install_dir: rizin_flags
)
