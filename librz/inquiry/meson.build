# SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

inquiry_plugins_list = [
  'interpreter_prototype',
]

inquiry_plugins = {
  'base_name': 'rz_inquiry',
  'base_struct': 'RzInquiryPlugin',
  'list': inquiry_plugins_list,
}

rz_inquiry_sources = [
  'inquiry.c',
  'inquiry_helpers.c',
]

subdir('interpreter')

rz_inquiry_inc = [platform_inc]

rz_inquiry = library('rz_inquiry', rz_inquiry_sources,
  include_directories: rz_inquiry_inc,
  dependencies: [
    rz_arch_dep, # Legacy analysis module
    rz_bin_dep,
    rz_cons_dep,
    rz_hash_dep,
    rz_il_dep,
    rz_interpreter_dep,
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

rz_inquiry_dep = declare_dependency(link_with: rz_inquiry,
                               include_directories: rz_inquiry_inc)
meson.override_dependency('rz_inquiry', rz_inquiry_dep)

modules += { 'rz_inquiry': {
    'target': rz_inquiry,
    'dependencies': [
      'rz_arch',
      'rz_bin',
      'rz_cons',
      'rz_hash',
      'rz_il',
      'rz_interpreter',
      'rz_io',
      'rz_magic',
      'rz_search',
      'rz_syscall',
      'rz_type',
      'rz_util'
    ],
    'plugins': [inquiry_plugins]
}}
