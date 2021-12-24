lang_plugins = [
  'lib',
  'pipe',
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'c',
    'cpipe'
  ]
endif

if lang_enabled_static_plugins == ['*']
  lang_enabled_static_plugins = lang_plugins
endif
if lang_enabled_shared_plugins == ['*']
  lang_enabled_shared_plugins = lang_plugins
endif

lang_static_plugins = []
lang_shared_plugins = []
foreach p : lang_plugins
  if p in lang_enabled_static_plugins + lang_enabled_shared_plugins
    subdir(p)
    if p in lang_enabled_static_plugins
      lang_static_plugins += [plugin]
    else
      lang_shared_plugins += [plugin]
    endif
  endif
endforeach
