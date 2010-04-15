#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nffile.h"
#include "convert.h"

/*
 * A netflow record in v1 block format has the same size as in v2 block format.
 *
 * old record size = new record size = 36bytes + x, where x is the sum of
 * IP address block (IPv4 or IPv6) + packet counter + byte counter ( 4/8 bytes) 
 *
 *    v1								v2
 * 
 *  0 uint32_t    flags;						uint16_t	type; 	
 *									uint16_t	size;
 *
 *  1 uint16_t    size;							uint8_t		flags;		
 * 									uint8_t 	exporter_ref;
 *    uint16_t    exporter_ref; => 0					uint16_t	ext_map;
 *
 *  2 uint16_t    msec_first;						uint16_t	msec_first;
 *    uint16_t    msec_last;						uint16_t	msec_last;
 *
 *  3 uint32_t    first;						uint32_t	first;
 *  4 uint32_t    last;							uint32_t	last;
 *
 *  5 uint8_t     dir;							uint8_t		fwd_status;
 *    uint8_t     tcp_flags;						uint8_t		tcp_flags;
 *    uint8_t     prot;							uint8_t		prot;
 *    uint8_t     tos;							uint8_t		tos;
 *
 *  6 uint16_t    input;						uint16_t	srcport;
 *    uint16_t    output;						uint16_t	dstport;
 *
 *  7 uint16_t    srcport;						x bytes IP/pkts/bytes
 *    uint16_t    dstport;
 *
 *  8 uint16_t    srcas;
 *    uint16_t    dstas;
 *									uint16_t    input;
 *									uint16_t    output;
 *
 *									uint16_t    srcas;
 *  9 x bytes IP/pkts/byte						uint16_t    dstas;
 */

void convert_v2_to_v1(void *mem) {

	common_record_t *v1 = (common_record_t*)mem;
	common_record_v2_t *v2 = (common_record_v2_t*)mem;

	uint32_t *index = (uint32_t*)mem;
	
	char *tmpbuf;

	uint16_t tmp[4];
	uint16_t *ptr;

	size_t cplen;

	// index 0
	tmp[0] = v2->size;
	v1->flags = v2->flags;

	// index 1
	v1->mark = v2->exporter_ref;
	v1->size = tmp[0];

	// index 2,3,4 already correct

	// index 5 (dont know what that means, just reset it for now)
	v1->dir = 0;

	cplen = 0;
	switch (v1->flags) {
		case 0:	// IPv4 8 byte + 2 x 4 byte counter
			cplen = 16;
			break;
		case 1: // IPv6 32 byte + 2 x 4 byte counter
			cplen = 40;
			break;
		case 2:	// IPv4 8 byte + 1 x 4 + 1 x 8 byte counter
			cplen = 20;
			break;
		case 3:	// IPv6 32 byte + 1 x 4 + 1 x 8 byte counter
			cplen = 44;
			break;
		case 4:	// IPv4 8 byte + 1 x 8 + 1 x 4 byte counter
			cplen = 20;
			break;
		case 5:	// IPv6 32 byte + 1 x 8 + 1 x 4 byte counter
			cplen = 44;
			break;
		case 6:	// IPv4 8 byte + 2 x 8 byte counter
			cplen = 24;
			break;
		case 7:	// IPv6 32 byte + 2 x 8 byte counter
			cplen = 48;
			break;
		default:
			// this should never happen - catch it anyway
			cplen = 0;
	}

	ptr = (uint16_t*)&index[7+(cplen>>2)];

	// index 6
	tmp[0] = v2->srcport;
	tmp[1] = v2->dstport;
	v1->input = *ptr;
	v1->output = *(ptr+1);

	// index 9
	tmp[2] = *(ptr+2);
	tmp[3] = *(ptr+3);

	tmpbuf = malloc(cplen);
	memcpy(tmpbuf, (void*)&index[7], cplen);
	memcpy((void*)&index[9], tmpbuf, cplen);
	free(tmpbuf);

	// index 7
	v1->srcport = tmp[0];
	v1->dstport = tmp[1];

	// index 8
	v1->srcas = *(ptr+2);
	v1->dstas = *(ptr+3);

}
