# #############################################################################
# Copyright (c) 2018-present     Dima Krasner <dima@dimakrasner.com>
#                                lzutao <taolzu(at)gmail.com>
# All rights reserved.
#
# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# #############################################################################

project('zstd',
  ['c'],
  license: ['BSD', 'GPLv2'],
  default_options : [
    # There shouldn't be any need to force a C standard convention for zstd
    # but in case one would want that anyway, this can be done here.
    # 'c_std=gnu99',
    # 'buildtype=release',
    # 'warning_level=3',
    # -Wdocumentation does not actually pass, nor do the test binaries,
    # so this isn't safe
    # 'werror=true'
  ],
  version: '1.5.7',
  meson_version: '>=0.50.0')

cc = meson.get_compiler('c')
windows_mod = import('windows')

host_machine_os = host_machine.system()
os_windows = 'windows'
os_linux = 'linux'
os_darwin = 'darwin'
os_freebsd = 'freebsd'
os_sun = 'sunos'

cc_id = cc.get_id()
compiler_gcc = 'gcc'
compiler_clang = 'clang'
compiler_msvc = 'msvc'

zstd_version = meson.project_version()

zstd_libversion = zstd_version

# =============================================================================
# Installation directories
# =============================================================================

zstd_prefix = get_option('prefix')
zstd_bindir = get_option('bindir')
zstd_datadir = get_option('datadir')
zstd_mandir = get_option('mandir')
zstd_docdir = join_paths(zstd_datadir, 'doc', meson.project_name())

# =============================================================================
# Project options
# =============================================================================

# Built-in options
use_debug = get_option('debug')
buildtype = get_option('buildtype')
default_library_type = get_option('default_library')

# Custom options
debug_level = get_option('debug_level')
legacy_level = get_option('legacy_level')
use_backtrace = get_option('backtrace')
use_static_runtime = get_option('static_runtime')

bin_programs = get_option('bin_programs')
bin_contrib = get_option('bin_contrib')
bin_tests = get_option('bin_tests')

feature_multi_thread = get_option('multi_thread')
feature_zlib = get_option('zlib')
feature_lzma = get_option('lzma')
feature_lz4 = get_option('lz4')

# =============================================================================
# Dependencies
# =============================================================================

libm_dep = cc.find_library('m', required: false)
thread_dep = dependency('threads', required: feature_multi_thread)
use_multi_thread = thread_dep.found()
# Arguments in dependency should be equivalent to those passed to pkg-config
zlib_dep = dependency('zlib', required: feature_zlib)
use_zlib = zlib_dep.found()
lzma_dep = dependency('liblzma', required: feature_lzma)
use_lzma = lzma_dep.found()
lz4_dep = dependency('lz4', required: feature_lz4)
use_lz4 = lz4_dep.found()

# =============================================================================
# Compiler flags
# =============================================================================

add_project_arguments('-DXXH_NAMESPACE=ZSTD_', language: ['c'])

if cc_id == compiler_msvc
  msvc_compile_flags = [ '/D_UNICODE', '/DUNICODE' ]
  if use_multi_thread
    msvc_compile_flags += '/MP'
  endif
  if use_static_runtime
    msvc_compile_flags += '/MT'
  endif
  add_project_arguments(msvc_compile_flags, language: ['c'])
endif

# Use the safe way to access unaligned values as all other methods fail
# on OpenBSD/sparc64 with gcc.
add_project_arguments('-DMEM_FORCE_MEMORY_ACCESS=0', language: ['c'])

# =============================================================================
# Subdirs
# =============================================================================

subdir('lib')
