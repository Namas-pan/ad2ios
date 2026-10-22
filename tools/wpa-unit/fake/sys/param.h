/* Host shim for <sys/param.h> (tools/wpa-unit only). */
#ifndef _WPAUNIT_SYS_PARAM_H_
#define _WPAUNIT_SYS_PARAM_H_

#include <sys/types.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

#endif
