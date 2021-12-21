include_files = [
  'include/rz_agraph.h',
  'include/rz_analysis.h',
  'include/rz_arch.h',
  'include/rz_asm.h',
  'include/rz_basefind.h',
  'include/rz_bin.h',
  'include/rz_bin_dwarf.h',
  'include/rz_bind.h',
  'include/rz_bp.h',
  'include/rz_cmd.h',
  'include/rz_cmp.h',
  'include/rz_config.h',
  'include/rz_cons.h',
  'include/rz_core.h',
  'include/rz_crypto.h',
  'include/rz_debug.h',
  'include/rz_demangler.h',
  'include/rz_diff.h',
  'include/rz_egg.h',
  'include/rz_endian.h',
  'include/rz_flag.h',
  'include/rz_flirt.h',
  'include/rz_getopt.h',
  'include/rz_heap_glibc.h',
  'include/rz_heap_jemalloc.h',
  'include/rz_il.h',
  'include/rz_io.h',
  'include/rz_lang.h',
  'include/rz_lib.h',
  'include/rz_list.h',
  'include/rz_magic.h',
  'include/rz_main.h',
  'include/rz_msg_digest.h',
  'include/rz_parse.h',
  'include/rz_pdb.h',
  'include/rz_project.h',
  'include/rz_reg.h',
  'include/rz_regex.h',
  'include/rz_search.h',
  'include/rz_sign.h',
  'include/rz_skiplist.h',
  'include/rz_skyline.h',
  'include/rz_socket.h',
  'include/rz_syscall.h',
  'include/rz_th.h',
  'include/rz_type.h',
  'include/rz_types.h',
  'include/rz_types_base.h',
  'include/rz_types_overflow.h',
  'include/rz_util.h',
  'include/rz_vector.h',
  'include/rz_windows_heap.h',
]
install_headers(include_files, install_dir: rizin_incdir)

rz_util_files = [
  'include/rz_util/rz_alloc.h',
  'include/rz_util/rz_annotated_code.h',
  'include/rz_util/rz_ascii_table.h',
  'include/rz_util/rz_asn1.h',
  'include/rz_util/rz_assert.h',
  'include/rz_util/rz_base64.h',
  'include/rz_util/rz_base91.h',
  'include/rz_util/rz_big.h',
  'include/rz_util/rz_bitmap.h',
  'include/rz_util/rz_bitvector.h',
  'include/rz_util/rz_buf.h',
  'include/rz_util/rz_debruijn.h',
  'include/rz_util/rz_event.h',
  'include/rz_util/rz_file.h',
  'include/rz_util/rz_graph.h',
  'include/rz_util/rz_graph_drawable.h',
  'include/rz_util/rz_hex.h',
  'include/rz_util/rz_idpool.h',
  'include/rz_util/rz_intervaltree.h',
  'include/rz_util/rz_itv.h',
  'include/rz_util/rz_json.h',
  'include/rz_util/rz_log.h',
  'include/rz_util/rz_luhn.h',
  'include/rz_util/rz_mem.h',
  'include/rz_util/rz_name.h',
  'include/rz_util/rz_num.h',
  'include/rz_util/rz_path.h',
  'include/rz_util/rz_panels.h',
  'include/rz_util/rz_pj.h',
  'include/rz_util/rz_pkcs7.h',
  'include/rz_util/rz_pool.h',
  'include/rz_util/rz_print.h',
  'include/rz_util/rz_protobuf.h',
  'include/rz_util/rz_punycode.h',
  'include/rz_util/rz_queue.h',
  'include/rz_util/rz_range.h',
  'include/rz_util/rz_rbtree.h',
  'include/rz_util/rz_serialize.h',
  'include/rz_util/rz_signal.h',
  'include/rz_util/rz_spaces.h',
  'include/rz_util/rz_stack.h',
  'include/rz_util/rz_str.h',
  'include/rz_util/rz_str_constpool.h',
  'include/rz_util/rz_str_search.h',
  'include/rz_util/rz_str_util.h',
  'include/rz_util/rz_strbuf.h',
  'include/rz_util/rz_strpool.h',
  'include/rz_util/rz_subprocess.h',
  'include/rz_util/rz_sys.h',
  'include/rz_util/rz_table.h',
  'include/rz_util/rz_time.h',
  'include/rz_util/rz_tree.h',
  'include/rz_util/rz_uleb128.h',
  'include/rz_util/rz_utf16.h',
  'include/rz_util/rz_utf32.h',
  'include/rz_util/rz_utf8.h',
  'include/rz_util/rz_x509.h',
]
install_headers(rz_util_files, install_dir: join_paths(rizin_incdir, 'rz_util'))

rz_il_definitions_files = [
  'include/rz_il/definitions/bag.h',
  'include/rz_il/definitions/bool.h',
  'include/rz_il/definitions/definitions.h',
  'include/rz_il/definitions/label.h',
  'include/rz_il/definitions/mem.h',
  'include/rz_il/definitions/value.h',
  'include/rz_il/definitions/variable.h',
]
install_headers(rz_il_definitions_files, install_dir: join_paths(rizin_incdir, 'rz_il', 'definitions'))

rz_il_files = [
  'include/rz_il/rzil_opcodes.h',
  'include/rz_il/rzil_vm_events.h',
  'include/rz_il/rzil_vm.h',
  'include/rz_il/vm_layer.h',
]
install_headers(rz_il_files, install_dir: join_paths(rizin_incdir, 'rz_il'))

rz_crypto_files = [
  'include/rz_crypto/rz_des.h'
]
install_headers(rz_crypto_files, install_dir: join_paths(rizin_incdir, 'rz_crypto'))

if get_option('use_gpl')
  sflib_common_files = [
    'include/sflib/common/sftypes.h',
    'include/sflib/common/sfsocketcall.h'
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
      install_headers(join_paths('include/sflib', arch, file), install_dir: join_paths(rizin_incdir, 'sflib', arch))
    endforeach
  endforeach
endif
