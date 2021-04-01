files = [
  'subprocess-helloworld',
  'subprocess-stdin',
  'subprocess-multiargs',
  'subprocess-interactive',
]

warn_unused_flag = '-Wno-unused-result'
foreach file : files
  executable(file, '@0@.c'.format(file),
    c_args: meson.get_compiler('c').has_argument(warn_unused_flag) ? [warn_unused_flag] : [],
    install: false
  )
endforeach
