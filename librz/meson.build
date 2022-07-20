subdir('include')

subdir('util')
subdir('demangler')
subdir('socket')
subdir('hash')
subdir('crypto')

subdir('cons')
subdir('diff')
subdir('io')
subdir('bp')
subdir('syscall')
subdir('search')
subdir('magic')
subdir('flag')
subdir('reg')
subdir('type')
subdir('bin')
subdir('config')
subdir('parse')
subdir('lang')
subdir('asm')
subdir('il')
subdir('analysis')
subdir('sign')
subdir('egg')
subdir('debug')
subdir('core')

subdir('main')

plugins = [
  core_plugins,
  analysis_plugins,
  asm_plugins,
  bp_plugins,
  bin_plugins,
  bin_xtr_plugins,
  crypto_plugins,
  io_plugins,
  debug_plugins,
  egg_plugins,
  lang_plugins,
  hash_plugins,
  parse_plugins,
  demangler_plugins,
]

conf_data = configuration_data()
foreach plugin : plugins
  l = []
  foreach p : plugin.get('list')
    l += ['&' + plugin.get('base_cname') + p]
  endforeach
  conf_data.set(plugin.get('conf_name'), ', '.join(l))
endforeach

config_h = configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data
)

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  cmake_mod.configure_package_config_file(
    name: 'Rizin',
    input: 'RizinConfig.cmake.in',
    install_dir: rizin_cmakedir / 'Rizin',
    configuration: conf,
  )
endif
