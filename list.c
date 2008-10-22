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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "list.h"

static uint16_t list_hash(uint32_t srcaddr, uint16_t dstport)
{
    /* use a simple XOR hash of the two 16bit values for srcaddr and dstport */
    uint16_t hash = ((uint16_t)srcaddr) ^ ((uint16_t)(srcaddr >> 16)) ^ dstport;
    return hash;
}

incident_list_t *list_init(unsigned int initial_size, unsigned int increment)
{
    /* allocate memory */
    incident_list_t *list = malloc(sizeof(incident_list_t) +
            HASH_SIZE * sizeof(hashtable_entry_t *));

    //printf("allocating %u byte for list...\n", sizeof(incident_list_t) + HASH_SIZE * sizeof(hashtable_entry_t *));

    if (list == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for list\n",
                sizeof(incident_list_t) + HASH_SIZE * sizeof(hashtable_entry_t *));
        exit(3);
    }

    list->flows = 0;
    list->incident_flows = 0;
    list->initial_size = initial_size;
    list->increment = increment;

    for (unsigned int i = 0; i < HASH_SIZE; i++) {
        /* allocate memory for hashtable entry */
        hashtable_entry_t *entry = malloc(sizeof(hashtable_entry_t) +
                                initial_size * sizeof(incident_record_t *));

        //printf("allocating %u byte for hashtable_entry...\n", sizeof(hashtable_entry_t) + initial_size * sizeof(incident_record_t));

        if (entry == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for hashtable entry\n",
                    sizeof(incident_list_t) + HASH_SIZE * sizeof(hashtable_entry_t *));
            exit(3);
        }

        entry->length = initial_size;
        entry->fill = 0;

        list->hashtable[i] = entry;
    }

    return list;
}

int list_insert(incident_list_t **list, uint32_t srcaddr, uint16_t dstport, uint8_t protocol, uint16_t dstaddr)
{
    incident_list_t *l = *list;

    /* compute the hash value (== index in hashtable) */
    uint16_t hash = list_hash(srcaddr, dstport);

    /* search hashtable hashtable entry structure */
    hashtable_entry_t *entry = l->hashtable[hash];

    /* check if this (srcaddr, dstport) is already known */
    incident_record_t *incident = NULL;
    unsigned int incident_index;
    for (unsigned int i = 0; i < entry->fill; i++) {
        if (entry->records[i]->srcaddr == srcaddr &&
            entry->records[i]->dstport == dstport &&
            entry->records[i]->protocol == protocol) {
            incident = entry->records[i];
            incident_index = i;
            break;
        }
    }

    if (incident) {
        //printf("found (srcaddr,dstport) ");

        incident->flows++;

        /* if (srcaddr, dstport) is known, check if this dstaddr is also known */
        for (unsigned int i = 0; i < incident->fill; i++) {
            if (incident->dstaddr[i] == dstaddr) {

                /* if dstaddr is already in list, we're done */
                //printf("dstaddr also found\n");
                return 0;
            }
        }

        //printf("dstaddr not found\n");

        /* else test if there is enough storage for another dstaddr */
        if (incident->fill == incident->length) {

            /* allocate more memory */
            incident->length += l->increment;
            //printf("  realloc(): %u\n", incident->length);
            incident = realloc(incident, sizeof(incident_record_t) +
                     incident->length * sizeof(uint32_t));

            if (incident == NULL) {
                fprintf(stderr, "unable to allocate %d byte of memory for incident\n",
                    sizeof(incident_record_t) + incident->length * sizeof(uint32_t));
                exit(3);
            }

            entry->records[incident_index] = incident;
        }

        /* save dstaddr */
        incident->dstaddr[incident->fill++] = dstaddr;

    } else {
        /* if (srcaddr, dstport) in not known, insert with current dstaddr */

        /* check if there is enough space for storing the pointer to the incident_record_t */
        if (entry->fill == entry->length) {

            /* increase memory */
            entry->length += l->increment;
            entry = realloc(entry, sizeof(hashtable_entry_t) +
                     entry->length * sizeof(incident_record_t *));

            if (entry == NULL) {
                fprintf(stderr, "unable to allocate %d byte of memory for hashtable entry\n",
                      sizeof(hashtable_entry_t) + entry->length * sizeof(incident_record_t *));
                exit(3);
            }


            /* store (potentially) new pointer */
            l->hashtable[hash] = entry;
        }

        /* store the record at the end of the list */
        incident_record_t *record = malloc(sizeof(incident_record_t) +
                                           l->initial_size * sizeof(uint32_t));

        if (record == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for entry record\n",
                    sizeof(incident_record_t) + l->initial_size * sizeof(uint32_t));
            exit(3);
        }

        /* init values */
        record->srcaddr = srcaddr;
        record->dstport = dstport;
        record->protocol = protocol;
        record->flows = 1;
        record->length = l->initial_size;
        record->fill = 1;
        record->dstaddr[0] = dstaddr;

        /* store pointer to record */
        entry->records[entry->fill++] = record;
    }

    return 0;
}

int list_free(incident_list_t *list)
{
    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        for (unsigned int i = 0; i < list->hashtable[h]->fill; i++) {
            free(list->hashtable[h]->records[i]);
        }
        free(list->hashtable[h]);
    }
    free(list);
    return 0;
}
