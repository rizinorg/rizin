// SPDX-FileCopyrightText: 2022 GustavoLCR
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>

RzDebugReasonType windows_exception_to_reason(ut32 exception_code);
bool windows_is_exception_fatal(ut32 exception_code);
void windows_print_exception_event(ut32 pid, ut32 tid, ut32 exception_code, bool second_chance);
