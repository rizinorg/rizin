nettle_proj = subproject('nettle')
aes_dep = nettle_proj.get_variable('aes_dep')

plugin = static_library('aes',
  ['crypto_aes.c'],
  dependencies: [rz_crypto_dependencies, aes_dep])
