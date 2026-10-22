/* Host shim for <libkern/libkern.h> (tools/wpa-unit only). */
#ifndef _WPAUNIT_LIBKERN_LIBKERN_H_
#define _WPAUNIT_LIBKERN_LIBKERN_H_

#include <sys/param.h>
#include <string.h>

/* A macro, not a function: <strings.h> already declares bzero() on the host. */
#define bzero(p, n) memset((p), 0, (n))

#endif
