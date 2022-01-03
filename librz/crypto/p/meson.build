crypto_plugins = [
  'aes',
  'aes_cbc',
  'base64',
  'base91',
  'blowfish',
  'cps2',
  'des',
  'punycode',
  'rc2',
  'rc4',
  'rc6',
  'rol',
  'ror',
  'rot',
  'serpent',
  'xor',
]

if crypto_enabled_static_plugins == ['*']
  crypto_enabled_static_plugins = crypto_plugins
endif
if crypto_enabled_shared_plugins == ['*']
  crypto_enabled_shared_plugins = crypto_plugins
endif

crypto_static_plugins = []
crypto_shared_plugins = []
foreach p : crypto_plugins
  if p in crypto_enabled_static_plugins + crypto_enabled_shared_plugins
    subdir(p)
    if p in crypto_enabled_static_plugins
      crypto_static_plugins += [plugin]
    else
      crypto_shared_plugins += [plugin]
    endif
  endif
endforeach
