#ifndef RZ_PANELS_H
#define RZ_PANELS_H

#include <rz_types.h>
#include <rz_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	VERTICAL,
	HORIZONTAL,
	NONE
} RzPanelLayout;

typedef enum {
	PANEL_TYPE_DEFAULT = 0,
	PANEL_TYPE_MENU = 1
} RzPanelType;

typedef enum {
	PANEL_EDGE_NONE = 0,
	PANEL_EDGE_BOTTOM,
	PANEL_EDGE_RIGHT
} RzPanelEdge;

typedef void (*RzPanelMenuUpdateCallback)(void *user, const char *parent);
typedef void (*RzPanelDirectionCallback)(void *user, int direction);
typedef void (*RzPanelRotateCallback)(void *user, bool rev);
typedef void (*RzPanelPrintCallback)(void *user, void *p);

typedef struct rz_panel_pos_t {
	int x;
	int y;
	int w;
	int h;
} RzPanelPos;

typedef struct rz_panel_model_t {
	RzPanelDirectionCallback directionCb;
	RzPanelRotateCallback rotateCb;
	RzPanelPrintCallback print_cb;
	RzPanelType type;
	char *cmd;
	char *title;
	ut64 baseAddr;
	ut64 addr;
	bool cache;
	char *cmdStrCache;
	char *readOnly;
	char *funcName;
	RzPVector /*<char *>*/ filter;
	int n_filter;
	int rotate;
} RzPanelModel;

typedef struct rz_panel_view_t {
	RzPanelPos pos;
	RzPanelPos prevPos;
	int sx;
	int sy;
	int curpos;
	bool refresh;
	int edge;
} RzPanelView;

typedef struct rz_panel_t {
	RzPanelModel *model;
	RzPanelView *view;
} RzPanel;

typedef void (*RzPanelAlmightyCallback)(void *user, RzPanel *panel, const RzPanelLayout dir, RZ_NULLABLE const char *title);

RZ_IPI void rz_panel_free(RZ_NULLABLE RzPanel *panel);

#ifdef __cplusplus
}
#endif

#endif //  RZ_PANELS_H
