// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PROLOGUES_GENERATOR_H
#define RZ_PROLOGUES_GENERATOR_H

#include <rz_core.h>

RZ_API RzCmdStatus rz_cmd_raw_prologues_gen_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_raw_prologues_gen_all_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_raw_prologues_gen_dir_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_prologues_generalize_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_prologues_store_clear_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_prologues_trie_clear_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_reset_session_handler(RzCore *core, int argc, const char **argv);
RZ_API RzCmdStatus rz_cmd_prefix_tree_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode);
RZ_API RzCmdStatus rz_cmd_prologues_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode);

#endif // RZ_PROLOGUES_GENERATOR_H
