project('nettle', 'c',
  license: 'LGPL',
  version: '3.7.3'
)
# https://git.lysator.liu.se/nettle/nettle

inc = include_directories('.')

sources = [
  'aes128-decrypt.c',
  'aes128-encrypt.c',
  'aes128-set-decrypt-key.c',
  'aes128-set-encrypt-key.c',
  'aes192-decrypt.c',
  'aes192-encrypt.c',
  'aes192-set-decrypt-key.c',
  'aes192-set-encrypt-key.c',
  'aes256-decrypt.c',
  'aes256-encrypt.c',
  'aes256-set-decrypt-key.c',
  'aes256-set-encrypt-key.c',
  'aesdata.c',
  'aes-decrypt.c',
  'aes-decrypt-internal.c',
  'aes-decrypt-table.c',
  'aes-encrypt.c',
  'aes-encrypt-internal.c',
  'aes-encrypt-table.c',
  'aes-invert-internal.c',
  'aes-set-decrypt-key.c',
  'aes-set-encrypt-key.c',
  'aes-set-key-internal.c',
]

libaes = static_library('nettle-aes',
  sources,
  include_directories : inc,
  install : false)

aes_dep = declare_dependency(
  include_directories : inc,
  link_with : libaes)
