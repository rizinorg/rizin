bp_plugins = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

if bp_enabled_static_plugins == ['*']
  bp_enabled_static_plugins = bp_plugins
endif
if bp_enabled_shared_plugins == ['*']
  bp_enabled_shared_plugins = bp_plugins
endif

bp_static_plugins = []
bp_shared_plugins = []
foreach p : bp_plugins
  if p in bp_enabled_static_plugins + bp_enabled_shared_plugins
    subdir(p)
    if p in bp_enabled_static_plugins
      bp_static_plugins += [plugin]
    else
      bp_shared_plugins += [plugin]
    endif
  endif
endforeach
