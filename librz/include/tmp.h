
#include "rz_types.h"

typedef struct RZ {
  struct rz_core_t* _core;
} RZ;

#ifdef SWIG

typedef struct rz_bin_section_t {
  char *name;
  ut64 size;
  ut64 vsize;
  ut64 vaddr;
  ut64 paddr;
  ut32 perm;
  // per section platform info
  const char *arch;
  ut64 type;
  ut64 flags;
  char *format;
  int bits;
  bool has_strings;
  bool add; // indicates when you want to add the section to io `S` command
  bool is_data;
  bool is_segment;
} RzBinSection;


#endif // SWIG

// Wrappers for internal core structures
// Templates the RzList so the bindings know what data structure the list contains
// Extends the RzList so it can be subscriptable in Python

template <typename T> class RzListWrapper {
  private:
    RzList *l;
  public:
    RzListWrapper(RzList *l) : l(l) {}
    ~RzListWrapper() {}

    const int __len__() {
      return l->length;
    }

    const T __getitem__(size_t i) {
      if (l->length <= 0 || i >= l->length) {
        // Error
        return nullptr;
      }
      if (i < 0) {
        i = l->length - 1;
      }
      //return reinterpret_cast<T *>(rz_list_get_n(l, i));
      return static_cast<T>(rz_list_get_n(l, i));
    }
};

template <typename T> class RzListWrapper;
typedef RzListWrapper<RzBinSection*> RzBinSectionList;

