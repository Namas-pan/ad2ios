/*
 * Host shim: just enough of <sys/types.h> for the kernel sources under test.
 * Only used by tools/wpa-unit; never compiled into the kernel.
 */
#ifndef _WPAUNIT_SYS_TYPES_H_
#define _WPAUNIT_SYS_TYPES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;

#endif
