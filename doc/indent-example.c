/* rizin - LGPL - [$minyear-$maxyear] - [$author]*/

#include <rz_core.h>

typedef struct rz_core_rtr_host_t2 {
	int proto;
	int port;
	char host[512];
	char file[1024];
	RzSocket *fd;
} RzCoreRtrHost2;

static const char *help_msg_aa[] = {
	"Usage:", "aa[0*?]", " # see also 'af' and 'afna'",
	"aa", " ", "alias for 'af@@ sym.*;af@entry0;afva'", //;.afna @@ fcn.*'",
	"aa*", "", "analyze all flags starting with sym. (af @@ sym.*)",
	NULL
};

static int cmpaddr(const void *_a, const void *_b) {
	const RzAnalFunction *a = _a, *b = _b;
	return a->addr - b->addr;
}

int main(int argc, char **argv) {
	rz_anal_esil_set_pc (core->anal->esil, fcn? fcn->addr: core->offset);
	switch (*input) {
	case '\0': // "aft"
		seek = core->offset;
		rz_anal_esil_set_pc (core->anal->esil, fcn? fcn->addr: core->offset);
		rz_core_anal_type_match (core, fcn);
		rz_core_seek (core, seek, true);
		break;
	case '0':
		{
			int a = 0;
			printf ("LocalA: %d\n", a);
		}
		break;
	case 'a':
		argc--;
		/* fallthrough */
	case 'b':
	case '?':
	default:
		rz_core_cmd_help (core, help_msg_aft);
		break;
	}
	return 0;
}
