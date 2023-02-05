
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

conf_data = configuration_data()
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
      l = []
      foreach p : plugin.get('list')
        l += ['&' + plugin.get('base_cname') + p]
      endforeach
      conf_data.set(plugin.get('conf_name'), ', '.join(l))
    endforeach
  endif
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
