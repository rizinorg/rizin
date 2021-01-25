files = [
  'subprocess-helloworld',
  'subprocess-stdin',
  'subprocess-multiargs',
]

foreach file : files
  executable(file, '@0@.c'.format(file),
    c_args: meson.get_compiler('c').get_id() == 'gcc' ? ['-Wno-unused-result'] : [],
    install: false
  )
endforeach
