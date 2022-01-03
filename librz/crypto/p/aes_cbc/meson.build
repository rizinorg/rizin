nettle_proj = subproject('nettle')
aes_dep = nettle_proj.get_variable('aes_dep')

plugin = static_library('aes_cbc',
  ['crypto_aes_cbc.c'],
  dependencies: [rz_crypto_dependencies, aes_dep])
