/*
 * file format structures
 * copied from the nfdump project file nffile.h, version 1.5.7 on 2008/07/25
 */

#ifndef _FILE_H
#define _FILE_H

#include <stdint.h>

/* from common.h */
typedef void* pointer_addr_t;

/* from nffile.h */
#define IdentLen	128
#define IdentNone	"none"

#define FILE_MAGIC	0xA50C
#define FILE_VERSION	1

#include "nffile.h"

#endif
