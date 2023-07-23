// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debugger.h>

RzDebuggerPlugin rz_debugger_plugin_null = {
	.name = "null",
	.license = "LGPL3",
	.author = "RizinOrg",
	.version = "1.0",
	/* plugin constructor/destructor */
	.init = NULL,
	.fini = NULL,
	/* process information */
	.info = NULL, ///< Returns the information regarding a process
	/* process actions */
	.attach = NULL, ///< Attach to a process
	.detach = NULL, ///< Detach from a process
	.select = NULL, ///< Selects a thread/process linked to a process parent
	.threads = NULL, ///< Returns the list of processes/threads linked to a process id
	.processes = NULL, ///< Returns the list of processes linked to a parent id (parent 0 for all the processes)
	.step = NULL, ///< Steps over an instruction
	.step_over = NULL, ///< Steps over a call
	.continue_signal = NULL, ///< Continue the process after a signal
	.continue_syscall = NULL, ///< Continue the process after a syscall
	.wait = NULL, ///< Awaits for the process
	.stop = NULL, ///< Stops the execution of the process
	.kill = NULL, ///< Sends a signal to kill the process
	.backtrace = NULL, ///< Returns the backtrace of a process at a given address
	/* process register */
	.register_sync = NULL, ///< Allows syncronization of one or all registers, from and to the debugger.
	.profile_get = NULL, ///< Gets the process register profile
	.profile_set = NULL, ///< Sets the process register profile
	/* process memory */
	.memory_get = NULL, ///< Returns the process memory mapping
	.modules_get = NULL, ///< Returns the process module mapping
	/* process file operations */
	.new_core_file = NULL, ///< Allows to generate a core file of the process
	.download_file = NULL, ///< Allows to download the binary from the remote locatio
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debugger_plugin_null,
	.version = RZ_VERSION
};
#endif
