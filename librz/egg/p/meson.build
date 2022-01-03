egg_plugins = [
  'exec',
  'xor',
]


if egg_enabled_static_plugins == ['*']
  egg_enabled_static_plugins = egg_plugins
endif
if egg_enabled_shared_plugins == ['*']
  egg_enabled_shared_plugins = egg_plugins
endif

egg_static_plugins = []
egg_shared_plugins = []
foreach p : egg_plugins
  if p in egg_enabled_static_plugins + egg_enabled_shared_plugins
    subdir(p)
    if p in egg_enabled_static_plugins
      egg_static_plugins += [plugin]
    else
      egg_shared_plugins += [plugin]
    endif
  endif
endforeach
