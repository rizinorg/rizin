demangler_plugins = [
  'java',
  'msvc',
  'objc',
]

if get_option('use_gpl')
  demangler_plugins += ['cpp', 'rust']
endif

if get_option('use_swift_demangler')
  demangler_plugins += 'swift'
endif


if demangler_enabled_static_plugins == ['*']
  demangler_enabled_static_plugins = demangler_plugins
endif
if demangler_enabled_shared_plugins == ['*']
  demangler_enabled_shared_plugins = demangler_plugins
endif

demangler_static_plugins = []
demangler_shared_plugins = []
foreach p : demangler_plugins
  if p in demangler_enabled_static_plugins + demangler_enabled_shared_plugins
    subdir(p)
    if p in demangler_enabled_static_plugins
      demangler_static_plugins += [plugin]
    else
      demangler_shared_plugins += [plugin]
    endif
  endif
endforeach
