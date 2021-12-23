project('ptrace-wrap', 'c')

thread_dep = dependency('threads', static: get_option('is_static_build'))
rz_util_dep = dependency('rz_util')

ptrace_wrap_inc = include_directories('include')

ptrace_wrap_src = ['src/ptrace_wrap.c']

ptrace_wrap_lib = static_library('ptrace_wrap',
                          ptrace_wrap_src,
                          include_directories: ptrace_wrap_inc,
                          dependencies: [thread_dep, rz_util_dep])

ptrace_wrap_dep = declare_dependency(link_with: ptrace_wrap_lib, include_directories: ptrace_wrap_inc)
meson.override_dependency('ptrace-wrap', ptrace_wrap_dep)

# subdir('test')
