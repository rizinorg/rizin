files = [
  'subprocess-helloworld',
  'subprocess-stdin',
  'subprocess-multiargs',
  'subprocess-interactive',
]

warn_unused_flag = '-Wno-unused-result'
auxiliary_c_args = meson.get_compiler('c').has_argument(warn_unused_flag) ? [warn_unused_flag] : []
auxiliaries = []
foreach file : files
  auxiliaries += [executable(file, '@0@.c'.format(file),
    c_args: auxiliary_c_args,
    install: false,
  )]
endforeach
