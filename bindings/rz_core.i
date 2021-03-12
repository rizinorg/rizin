%module rz_core
%{
#include "rz_core.h"
#include "tmp.h"
%}

%pythoncode %{
import json
%}

#if 0

// First way: include the whole rz_core.h and here be dragons
// currently fails because of extern rz_core_plugin_java but that is the idea

#undef RZ_API
#define RZ_DEPRECATE
%include "rz_types.h"
%include "rz_core.h"

%extend rz_core_t {
  rz_core_t() {
    return rz_core_new();
  }

  ~rz_core_t() {
  }

  char* cmd(const char *cmd) {
    return rz_core_cmd_str($self, cmd);
  }

%pythoncode %{
  def cmdj(self, cmd):
      data = self.cmd(cmd)
      return json.loads(data)
%}
}



#else

// Second way : create a wrapper structure and extend it to provide only
// required APIs

%include "tmp.h"

%extend RZ {
  RZ() {
    RZ* r = malloc(sizeof(RZ));
    if (!r) {
      // TODO
    }
    r->_core = rz_core_new();
    if (!r->_core) {
      // TODO
    }
    rz_core_cmd_str(r->_core, "e scr.color=0");
    return r;
  }

  ~RZ() {
    rz_core_free($self->_core);
    free($self);
  }

  char* cmd(const char *cmd) {
    return rz_core_cmd_str($self->_core, cmd);
  }

%pythoncode %{
  def cmdj(self, cmd):
      data = self.cmd(cmd)
      return json.loads(data)
%}
}


#endif




#if 0

//rz_core_t *rz_core_new(void);
//char *rz_core_cmd_str(rz_core_t *core, const char *cmd);
//void rz_core_free(rz_core_t *core);

#endif

