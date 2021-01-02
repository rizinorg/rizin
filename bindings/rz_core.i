%module rz_core
%{
#include <rz_core.h>
%}

RzCore *rz_core_new(void);
char *rz_core_cmd_str(RzCore *core, const char *cmd);
void rz_core_free(RzCore *core);
// %include <rz_core.h>

