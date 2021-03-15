fs = import('fs')

subdir('include')

# NOTE: Cannot be included here because right now shlr depends on some librz
# libraries, while other librz libraries depend in turn on shlr.
#
# subdir('util')
# subdir('socket')
# subdir('hash')
# subdir('crypto')
# subdir('cons')
#

modules = [
    'io',
    'bp',
    'syscall',
    'search',
    'magic',
    'flag',
    'reg',
    'bin',
    'config',
    'parse',
    'lang',
    'asm',
    'analysis',
    'egg',
    'debug',
    'core',
    'main',
]

# Iterate over modules that may provide plugins that can be linked either
# statically or dynamically into Rizin. Static plugins are embedded in Rizin
# itself, while shared plugins are compiled as separate libraries that are load
# at runtime by Rizin.
#
# To define a plugin for a module, add its name in `<module>_plugins` in
# `<module>/p/meson.build and define:
# - `<module>_<pluginName>_sources`: an array of source files
# - `<module>_<pluginName>_headers`: an array of include directories (optional)
# - `<module>_<pluginName>_deps`: an array of meson dependencies (optional)
#
# Example:
# Plugins for RzAsm are listed in `asm_plugins` in `librz/asm/p/meson.build`.
# x86_cs plugin is defined with `asm_x86_cs_sources`, to list all C files
# needed to compile the plugin, and `asm_x86_cs_deps` to list the additional
# dependencies needed.
foreach module : modules
  if fs.is_dir(module / 'p') and fs.exists(module / 'p' / 'meson.build')
    subdir(module / 'p')

    plugins = get_variable('@0@_plugins'.format(module), [])
    if plugins != []
      # determine which plugins to compile and how
      enabled_plugins = get_option('@0@_plugins'.format(module))
      enabled_static_plugins = []
      enabled_shared_plugins = []

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

        if name not in plugins and name != '*'
          error('@0@ plugin @1@ does not exist!'.format(module, name))
        endif

        if name == '*'
          to_add = plugins
        else
          to_add = [name]
        endif

        if type == 'static'
          enabled_static_plugins += to_add
        else
          enabled_shared_plugins += to_add
        endif
      endforeach
      set_variable('@0@_enabled_static_plugins'.format(module), enabled_static_plugins)
      set_variable('@0@_enabled_shared_plugins'.format(module), enabled_shared_plugins)

      # compile static plugins
      static_plugins = get_variable('@0@_enabled_static_plugins'.format(module))
      module_plugins_dep = []
      static_plugins_str = []
      foreach p : plugins
        c_files = get_variable('@0@_@1@_sources'.format(module, p))
        h_files = get_variable('@0@_@1@_headers'.format(module, p), [])
        plugin_deps = get_variable('@0@_@1@_deps'.format(module, p), [])

        plugin_inc = [h_files, platform_inc]
        name = '@0@_plugin_@1@'.format(module, p)

        if p in static_plugins
          plugin = static_library(name, c_files,
            include_directories: plugin_inc,
            dependencies: [plugin_deps, rz_util_dep],
            c_args: library_cflags,
            install: false,
          )

          plugin_dep = declare_dependency(link_with: plugin, include_directories: plugin_inc)
          module_plugins_dep += [plugin_dep]
          static_plugins_str += ['&rz_@0@_plugin_@1@'.format(module, p)]
        endif
      endforeach
      static_plugins_str += ['0']

      set_variable('rz_@0@_plugins_dep'.format(module), module_plugins_dep)
      set_variable('@0@_enabled_static_plugins_str'.format(module), static_plugins_str)
    else
      warning('No @0@_plugins variable defined'.format(module))
    endif
  endif

  subdir(module)

  if fs.is_dir(module / 'p') and fs.exists(module / 'p' / 'meson.build')
    # compile static plugins
    plugins = get_variable('@0@_plugins'.format(module), [])
    if plugins != []
      shared_plugins = get_variable('@0@_enabled_shared_plugins'.format(module))
      module_dep = get_variable('rz_@0@_dep'.format(module))

      # compile shared plugins
      foreach p : plugins
        c_files = get_variable('@0@_@1@_sources'.format(module, p))
        h_files = get_variable('@0@_@1@_headers'.format(module, p), [])
        plugin_deps = get_variable('@0@_@1@_deps'.format(module, p), [])

        plugin_inc = [h_files, platform_inc]
        name = '@0@_plugin_@1@'.format(module, p)

        if p in shared_plugins
          plugin = shared_library(name, c_files,
            include_directories: plugin_inc,
            dependencies: [module_dep, plugin_deps, rz_util_dep],
            install: true,
            install_dir: rizin_plugins,
          )
        endif
      endforeach
    endif
  endif
endforeach