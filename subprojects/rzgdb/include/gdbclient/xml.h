// SPDX-FileCopyrightText: 2014 defragger <rlaemmert@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* For handling parsing xml from gdbserver */

#ifndef GDBCLIENT_XML_H
#define GDBCLIENT_XML_H

#include "libgdbr.h"

int gdbr_read_target_xml(libgdbr_t *g);
int gdbr_read_processes_xml(libgdbr_t *g, int pid, RzList *list);

#endif // GDBCLIENT_XML_H
