# handle ptrace-wrap dependency
if use_ptrace_wrap
  subdir('ptrace-wrap')
endif

if host_machine.system() == 'windows'
  subdir('w32dbg_wrap')
endif

# handle mpc dependency
r = run_command(py3_exe, check_meson_subproject_py, 'mpc')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

mpc_proj = subproject('mpc', default_options: ['default_library=static'])
mpc_dep = mpc_proj.get_variable('mpc_dep')

# handle yxml dependency
r = run_command(py3_exe, check_meson_subproject_py, 'yxml')
if r.returncode() == 1 and get_option('subprojects_check')
  error('Subprojects are not updated. Please run `git clean -dxff subprojects/` to delete all local subprojects directories. If you want to compile against current subprojects then set option `subprojects_check=false`.')
endif

yxml_proj = subproject('yxml', default_options: ['default_library=static'])
yxml_dep = yxml_proj.get_variable('yxml_dep')
