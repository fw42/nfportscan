/*
 * nfportscan - extract scans for one port over a range of ips
 *              from cisco netflow data files
 *
 * (c) by Alexander Neumann <alexander@bumpern.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * For more information on the GPL, please go to:
 * http://www.gnu.org/copyleft/gpl.html
 }}} */

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
    unsigned int packets;
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
