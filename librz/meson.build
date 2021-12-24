modules = [
  'util',
  'demangler',
  'socket',
  'hash',
  'crypto',
  'cons',
  'diff',
  'io',
  'bp',
  'syscall',
  'search',
  'magic',
  'flag',
  'reg',
  'type',
  'bin',
  'config',
  'parse',
  'lang',
  'asm',
  'il',
  'analysis',
  'signature',
  'egg',
  'debug',
  'core',
  'main',
]

modules_with_plugins = [
  'demangler',
  'hash',
  'crypto',
  'io',
  'bp',
  'bin',
  'parse',
  'lang',
  'asm',
  'analysis',
  'egg',
  'debug',
  'core',
]

# Determine which plugins to compile and how
# Go through the various crypto_plugins, core_plugins, egg_plugins, etc. meson
# options and set the following meson variables:
#
# - <module>_enabled_static_plugins: list of plugins that needs to be statically compiled (e.g. crypto_enabled_static_plugins)
# - <module>_enabled_shared_plugins: list of plugins that needs to be dynamically compiled (e.g. crypto_enabled_shared_plugins)
#
# If the list contains the single element '*' all plugins for that category shall be enabled.
foreach module : modules_with_plugins
  enabled_static_plugins = []
  enabled_shared_plugins = []

  enabled_plugins = get_option('@0@_plugins'.format(module))

  foreach plugin : enabled_plugins
    parts = plugin.split('.')
    type = 'static'
    if parts.length() == 1
      name = parts[0]
    elif parts.length() == 2
      type = parts[0]
      name = parts[1]
    else
      error('Wrong @0@ plugin name format: @1@.'.format(module, plugin))
    endif

    if type == 'static'
      if name == '*'
        enabled_static_plugins = ['*']
        break
      else
        enabled_static_plugins += [name]
      endif
    else
      if name == '*'
        enabled_shared_plugins = ['*']
        break
      else
        enabled_shared_plugins += [name]
      endif
    endif
  endforeach

  set_variable('@0@_enabled_static_plugins'.format(module), enabled_static_plugins)
  set_variable('@0@_enabled_shared_plugins'.format(module), enabled_shared_plugins)
endforeach
bin_xtr_enabled_shared_plugins = ['*']
bin_xtr_enabled_static_plugins = ['*']

subdir('include')
foreach module : modules
  subdir(module)
endforeach

foreach module : modules_with_plugins
  enabled_static_plugins = get_variable('@0@_enabled_static_plugins'.format(module))
  enabled_static_plugins_str = []
  foreach p : enabled_static_plugins
    enabled_static_plugins_str += ['&rz_@0@_plugin_@1@'.format(module, p)]
  endforeach
  set_variable('@0@_enabled_static_plugins_str'.format(module), enabled_static_plugins_str)
endforeach

bin_xtr_enabled_static_plugins_str = []
foreach p : bin_xtr_enabled_static_plugins
  bin_xtr_enabled_static_plugins_str += ['&rz_bin_xtr_plugin_@0@'.format(p)]
endforeach


conf_data = configuration_data()
conf_data.set('plugins_core', ','.join(core_enabled_static_plugins_str))
conf_data.set('plugins_analysis', ','.join(analysis_enabled_static_plugins_str))
conf_data.set('plugins_asm', ','.join(asm_enabled_static_plugins_str))
conf_data.set('plugins_bp', ','.join(bp_enabled_static_plugins_str))
conf_data.set('plugins_bin', ','.join(bin_enabled_static_plugins_str))
conf_data.set('plugins_bin_xtr', ','.join(bin_xtr_enabled_static_plugins_str))
conf_data.set('plugins_crypto', ','.join(crypto_enabled_static_plugins_str))
conf_data.set('plugins_io', ','.join(io_enabled_static_plugins_str))
conf_data.set('plugins_debug', ','.join(debug_enabled_static_plugins_str))
conf_data.set('plugins_egg', ','.join(egg_enabled_static_plugins_str))
conf_data.set('plugins_lang', ','.join(lang_enabled_static_plugins_str))
conf_data.set('plugins_parse', ','.join(parse_enabled_static_plugins_str))
conf_data.set('plugins_demangler', ','.join(demangler_enabled_static_plugins_str))
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
