
modules = {} # every rizin module subdir registers in here

subdir('include')

subdir('util')
subdir('demangler')
subdir('socket')
subdir('hash')
subdir('crypto')

subdir('cons')
subdir('diff')
subdir('io')
subdir('syscall')
subdir('magic')
subdir('search')
subdir('flag')
subdir('mark')
subdir('reg')
subdir('type')
subdir('bin')
subdir('config')
subdir('lang')
subdir('il')
subdir('arch')
subdir('sign')
subdir('egg')
subdir('debug')
subdir('core')

subdir('main')

foreach module_name, module : modules
  include_subdirs = ['librz']
  if 'include_subdirs_extra' in module
    include_subdirs += module['include_subdirs_extra']
  endif

  # pkg-config
  pkgconfig_vars = []
  if 'plugins' in module
    pkgconfig_vars += ['plugindir=@0@'.format(rizin_plugins)]
  endif
  pkgconfig_vars += ['datdir=@0@'.format(rizin_datdir_rz)]

  pkgconfig_mod.generate(module['target'],
    subdirs: include_subdirs,
    version: rizin_version,
    name: module_name,
    filebase: module_name,
    requires: module['dependencies'],
    description: 'rizin foundation libraries',
    variables: pkgconfig_vars,
  )

  # cmake
  if not is_static_libs_only
    conf = configuration_data()
    conf.set('RZ_VERSION', rizin_version)
    conf.set('RIZIN_MODULE', module['target'].name())
    conf.set('RIZIN_MODULE_DEPS', ' '.join(module['dependencies']))
    conf.set('PACKAGE_RELATIVE_PATH', cmake_package_relative_path)
    conf.set('INSTALL_INCDIR', rizin_incdir)
    conf.set('INSTALL_LIBDIR', rizin_libdir)
    conf.set('INSTALL_PLUGDIR', rizin_plugins)
    conf.set('rizin_libname', module['target'].name())
    # meson's cmake module is not used on purpose due to:
    #   https://todo.sr.ht/~lattis/muon/24
    #   https://github.com/mesonbuild/meson/issues/9702
    configure_file(
      output: conf.get('rizin_libname') + 'Config.cmake',
      input: 'RzModulesConfig.cmake.in',
      install_dir: rizin_cmakedir / conf.get('rizin_libname'),
      configuration: conf,
    )
  endif

  # plugins
  if 'plugins' in module
    foreach plugin : module['plugins']
      plugins_h = configuration_data()
      static_plugins = []
      export_plugins = []
      base_name = plugin.get('base_name')
      base_struct = plugin.get('base_struct')
      foreach plugin_name : plugin.get('list')
        plugin_var = base_name + '_plugin_' + plugin_name
        static_plugins += ['&' + plugin_var]
        export_plugins += ['extern ' + base_struct + ' ' + plugin_var + ';']
      endforeach
      plugins_h.set('plugin_static', ', '.join(static_plugins))
      plugins_h.set('plugin_exports', '\n'.join(export_plugins))
      plugins_h.set('MODULE_NAME', base_name.to_upper())
      configure_file(
        input: 'plugins.h.in',
        output: base_name + '_plugins.h',
        configuration: plugins_h
      )
    endforeach
  endif
endforeach

if not is_static_libs_only
  conf = configuration_data()
  conf.set('RZ_VERSION', rizin_version)
  conf.set('INSTALL_PLUGDIR', rizin_plugins)
  # meson's cmake module is not used on purpose due to:
  #   https://todo.sr.ht/~lattis/muon/24
  #   https://github.com/mesonbuild/meson/issues/9702
  configure_file(
    output: 'RizinConfig.cmake',
    input: 'RizinConfig.cmake.in',
    install_dir: rizin_cmakedir / 'Rizin',
    configuration: conf,
  )
endif
