// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROCFS_H
#define PROCFS_H

int procfs_pid_slurp(int pid, char *prop, char *out, size_t len);

#endif
