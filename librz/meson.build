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
subdir('signature')
subdir('egg')
subdir('debug')
subdir('core')

subdir('main')

conf_data = configuration_data()
conf_data.set('plugins_core', '&rz_core_plugin_' + ', &rz_core_plugin_'.join(core_plugins) + ', 0')
conf_data.set('plugins_analysis', '&rz_analysis_plugin_' + ', &rz_analysis_plugin_'.join(analysis_plugins) + ', 0')
conf_data.set('plugins_asm', '&rz_asm_plugin_' + ', &rz_asm_plugin_'.join(asm_plugins) + ', 0')
conf_data.set('plugins_bp', '&rz_bp_plugin_' + ', &rz_bp_plugin_'.join(bp_plugins) + ', 0')
conf_data.set('plugins_bin', '&rz_bin_plugin_' + ', &rz_bin_plugin_'.join(bin_plugins) + ', 0')
conf_data.set('plugins_bin_ldr', '&rz_bin_ldr_plugin_' + ', &rz_bin_ldr_plugin_'.join(bin_ldr_plugins) + ', 0')
conf_data.set('plugins_bin_xtr', '&rz_bin_xtr_plugin_' + ', &rz_bin_xtr_plugin_'.join(bin_xtr_plugins) + ', 0')
conf_data.set('plugins_crypto', '&rz_crypto_plugin_' + ', &rz_crypto_plugin_'.join(crypto_plugins) + ', 0')
conf_data.set('plugins_io', '&rz_io_plugin_' + ', &rz_io_plugin_'.join(io_plugins) + ', 0')
conf_data.set('plugins_debug', '&rz_debug_plugin_' + ', &rz_debug_plugin_'.join(debug_plugins) + ', 0')
conf_data.set('plugins_egg', '&rz_egg_plugin_' + ', &rz_egg_plugin_'.join(egg_plugins) + ', 0')
conf_data.set('plugins_lang', '&rz_lang_plugin_' + ', &rz_lang_plugin_'.join(lang_plugins) + ', 0')
conf_data.set('plugins_parse', '&rz_parse_plugin_' + ', &rz_parse_plugin_'.join(parse_plugins) + ', 0')
conf_data.set('plugins_demangler', '&rz_demangler_plugin_' + ', &rz_demangler_plugin_'.join(demangler_plugins))
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
