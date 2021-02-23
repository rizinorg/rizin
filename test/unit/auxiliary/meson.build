files = [
  'subprocess-helloworld',
  'subprocess-stdin',
  'subprocess-multiargs',
  'subprocess-interactive',
]

foreach file : files
  executable(file, '@0@.c'.format(file),
    install: false
  )
endforeach