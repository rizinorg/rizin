%module rz_core
%{
#include "rz_core.h"
#include "rz_list.h"
#include "tmp.h"
#include "rz_bin.h"

RzCorePlugin rz_core_plugin_java;
%}

%pythoncode %{
import json
%}

#define RZ_DEPRECATE
#define RZ_API
#define RZ_IPI
#define RZ_BORROW

%include "rz_types.h"
%include "tmp.h"

// Explicitely declare required types to produce bindings generation
%template(RzBinSectionList) RzListWrapper<RzBinSection*>;

// Create a core wrapper structure and extend it to provide only
// required APIs

%extend RZ {
  RZ(const char *bin = NULL) {
    RZ* r = (RZ*) malloc(sizeof(RZ));
    if (!r) {
      // TODO
    }
    r->_core = rz_core_new();
    if (!r->_core) {
      // TODO
    }
    rz_core_cmd_str(r->_core, "e scr.color=0");
    if (bin) {
      rz_core_cmd_strf(r->_core, "o %s", bin);
    }
    return r;
  }

  ~RZ() {
    rz_core_free($self->_core);
    free($self);
  }

  char* cmd(const char *cmd) {
    return rz_core_cmd_str($self->_core, cmd);
  }

  RzList *get_sections_x() {
    return rz_bin_get_sections($self->_core->bin);
  }

  RzListWrapper<RzBinSection *> get_sections() {
    return RzListWrapper<RzBinSection *>(rz_bin_get_sections($self->_core->bin));
  }

%pythoncode %{
  def cmdj(self, cmd):
      data = self.cmd(cmd)
      return json.loads(data)
%}
}

