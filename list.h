/*
 * nfportscan - extract scans for one port over a range of ips
 *              from cisco netflow data files
 *
 * (c) by Alexander Neumann <alexander@bumpern.de>
 *        Florian Weingarten <flo@hackvalue.de>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include "nffile.h"

#ifndef LIST_H
#define LIST_H

/* structures for counting ssh flows */
typedef struct {
    uint32_t srcaddr;
    uint16_t dstport;
    uint8_t protocol;
    unsigned int flows;
    uint64_t packets;
    uint64_t octets;
    uint32_t first;
    uint32_t last;
    unsigned int length;
    unsigned int fill;
    uint32_t dstaddr[];
} incident_record_t;

typedef struct {
    unsigned int length;
    unsigned int fill;
    incident_record_t *records[];
} hashtable_entry_t;

typedef struct {
    unsigned int flows;
    unsigned int incident_flows;
    unsigned int initial_size;
    unsigned int increment;
    hashtable_entry_t *hashtable[];
} incident_list_t;

/* use a 16bit hash */
#define HASH_SIZE 0x10000

/* allocate memory and initialize list, flow counter must be initialized
 * afterwards, memory must be free()d later */
incident_list_t *list_init(unsigned int initial_size, unsigned int increment);

/* returns 0 on success, < 0 if error occured */
int list_insert(incident_list_t **list, master_record_t *rec);

/* deallocate memory for a list */
int list_free(incident_list_t *list);

#endif
