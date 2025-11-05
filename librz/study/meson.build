# SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

study_plugins_list = [
  'abstr_int_proto',
]

study_plugins = {
  'base_name': 'rz_study',
  'base_struct': 'RzStudy',
  'list': study_plugins_list,
}

rz_study_sources = [
  'interpreter.c',
  'p/study_abstr_int_proto.c',
]

rz_study_inc = [platform_inc]

rz_study = library('rz_study', rz_study_sources,
  include_directories: rz_study_inc,
  c_args: ['-DRZ_API_STUDY_ONLY=1'],
  dependencies: [
    rz_arch_dep, # Legacy analysis module
    rz_cons_dep,
    rz_hash_dep,
    rz_io_dep,
    rz_magic_dep,
    rz_search_dep,
    rz_syscall_dep,
    rz_type_dep,
    rz_util_dep,
  ],
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion,
  version: rizin_version,
  name_suffix: lib_name_suffix,
  name_prefix: lib_name_prefix,
)

rz_study_dep = declare_dependency(link_with: rz_study,
                               include_directories: rz_study_inc)
meson.override_dependency('rz_study', rz_study_dep)

modules += { 'rz_study': {
    'target': rz_study,
    'dependencies': [
      'rz_arch',
      'rz_cons',
      'rz_hash',
      'rz_io',
      'rz_magic',
      'rz_search',
      'rz_syscall',
      'rz_type',
      'rz_util'
    ],
    'plugins': [study_plugins]
}}
