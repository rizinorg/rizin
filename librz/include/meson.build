include_files = [
  'rz_agraph.h',
  'rz_analysis.h',
  'rz_arch.h',
  'rz_asm.h',
  'rz_basefind.h',
  'rz_bin.h',
  'rz_bin_dwarf.h',
  'rz_bin_source_line.h',
  'rz_bind.h',
  'rz_bp.h',
  'rz_cmd.h',
  'rz_cmp.h',
  'rz_config.h',
  'rz_cons.h',
  'rz_constructor.h',
  'rz_core.h',
  'rz_crypto.h',
  'rz_debug.h',
  'rz_demangler.h',
  'rz_diff.h',
  'rz_egg.h',
  'rz_endian.h',
  'rz_flag.h',
  'rz_flirt.h',
  'rz_getopt.h',
  'rz_heap_glibc.h',
  'rz_heap_jemalloc.h',
  'rz_il.h',
  'rz_io.h',
  'rz_lang.h',
  'rz_lib.h',
  'rz_list.h',
  'rz_magic.h',
  'rz_main.h',
  'rz_hash.h',
  'rz_parse.h',
  'rz_pdb.h',
  'rz_platform.h',
  'rz_project.h',
  'rz_reg.h',
  'rz_search.h',
  'rz_sign.h',
  'rz_skiplist.h',
  'rz_skyline.h',
  'rz_socket.h',
  'rz_syscall.h',
  'rz_th.h',
  'rz_type.h',
  'rz_types.h',
  'rz_types_base.h',
  'rz_types_overflow.h',
  'rz_util.h',
  'rz_vector.h',
  'rz_windows.h',
  'rz_windows_heap.h',
  'rz_rop.h',
]
install_headers(include_files, install_dir: rizin_incdir)

rz_util_files = [
  'rz_util/rz_alloc.h',
  'rz_util/rz_annotated_code.h',
  'rz_util/rz_ascii_table.h',
  'rz_util/rz_asn1.h',
  'rz_util/rz_assert.h',
  'rz_util/rz_axml.h',
  'rz_util/rz_base64.h',
  'rz_util/rz_base91.h',
  'rz_util/rz_big.h',
  'rz_util/rz_bits.h',
  'rz_util/rz_bitvector.h',
  'rz_util/rz_buf.h',
  'rz_util/rz_debruijn.h',
  'rz_util/rz_event.h',
  'rz_util/rz_file.h',
  'rz_util/rz_float.h',
  'rz_util/rz_graph.h',
  'rz_util/rz_graph_drawable.h',
  'rz_util/rz_hex.h',
  'rz_util/rz_idpool.h',
  'rz_util/rz_intervaltree.h',
  'rz_util/rz_itv.h',
  'rz_util/rz_json.h',
  'rz_util/rz_lang_byte_array.h',
  'rz_util/rz_log.h',
  'rz_util/rz_luhn.h',
  'rz_util/rz_mem.h',
  'rz_util/rz_name.h',
  'rz_util/rz_num.h',
  'rz_util/rz_panels.h',
  'rz_util/rz_path.h',
  'rz_util/rz_pj.h',
  'rz_util/rz_pkcs7.h',
  'rz_util/rz_print.h',
  'rz_util/rz_protobuf.h',
  'rz_util/rz_punycode.h',
  'rz_util/rz_range.h',
  'rz_util/rz_rbtree.h',
  'rz_util/rz_regex.h',
  'rz_util/rz_iterator.h',
  'rz_util/rz_serialize.h',
  'rz_util/rz_signal.h',
  'rz_util/rz_spaces.h',
  'rz_util/rz_stack.h',
  'rz_util/rz_str.h',
  'rz_util/rz_str_constpool.h',
  'rz_util/rz_str_search.h',
  'rz_util/rz_str_util.h',
  'rz_util/rz_strbuf.h',
  'rz_util/rz_strpool.h',
  'rz_util/rz_subprocess.h',
  'rz_util/rz_sys.h',
  'rz_util/rz_table.h',
  'rz_util/rz_th_ht.h',
  'rz_util/rz_time.h',
  'rz_util/rz_tree.h',
  'rz_util/rz_uleb128.h',
  'rz_util/rz_utf16.h',
  'rz_util/rz_utf32.h',
  'rz_util/rz_utf8.h',
  'rz_util/rz_version.h',
  'rz_util/rz_x509.h',
  'rz_util/ht_inc.h',
  'rz_util/ht_pp.h',
  'rz_util/ht_pu.h',
  'rz_util/ht_up.h',
  'rz_util/ht_uu.h',
  'rz_util/ht_sp.h',
  'rz_util/ht_ss.h',
  'rz_util/ht_su.h',
  'rz_util/rz_set.h',
]
install_headers(rz_util_files, install_dir: join_paths(rizin_incdir, 'rz_util'))

rz_il_definitions_files = [
  'rz_il/definitions/bool.h',
  'rz_il/definitions/definitions.h',
  'rz_il/definitions/label.h',
  'rz_il/definitions/mem.h',
  'rz_il/definitions/sort.h',
  'rz_il/definitions/value.h',
  'rz_il/definitions/variable.h',
  'rz_il/definitions/float.h',
]
install_headers(rz_il_definitions_files, install_dir: join_paths(rizin_incdir, 'rz_il', 'definitions'))

rz_il_files = [
  'rz_il/rz_il_opcodes.h',
  'rz_il/rz_il_opbuilder_begin.h',
  'rz_il/rz_il_opbuilder_end.h',
  'rz_il/rz_il_events.h',
  'rz_il/rz_il_reg.h',
  'rz_il/rz_il_validate.h',
  'rz_il/rz_il_vm.h'
]
install_headers(rz_il_files, install_dir: join_paths(rizin_incdir, 'rz_il'))

rz_crypto_files = [
  'rz_crypto/rz_des.h'
]
install_headers(rz_crypto_files, install_dir: join_paths(rizin_incdir, 'rz_crypto'))

if get_option('use_gpl')
  sflib_common_files = [
    'sflib/common/sftypes.h',
    'sflib/common/sfsocketcall.h'
  ]

  sflib_arch = [
    'linux-x86-64',
    'linux-x86-32',
    'linux-arm-64',
    'linux-arm-32',
    'darwin-x86-64',
    'darwin-x86-32',
    'darwin-arm-64'
  ]

  sflib_arch_files = [
    'sflib.h',
    'sfsyscall.h',
    'sfsysnr.h'
  ]

  install_headers(sflib_common_files, install_dir: join_paths(rizin_incdir, 'sflib/common'))
  foreach arch : sflib_arch
    foreach file : sflib_arch_files
      install_headers(join_paths('sflib', arch, file), install_dir: join_paths(rizin_incdir, 'sflib', arch))
    endforeach
  endforeach
endif
