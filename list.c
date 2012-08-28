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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <omp.h>
#include "list.h"


// One OpenMP lock for every hashtable entry
omp_lock_t *locks;

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

    if (list == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for list (malloc(): %s)\n",
                sizeof(incident_list_t) + HASH_SIZE * sizeof(hashtable_entry_t *), strerror(errno));
        exit(3);
    }

    list->flows = 0;
    list->incident_flows = 0;
    list->initial_size = initial_size;
    list->increment = increment;

    // Initialize memory for locks on heap (NOT stack!!)
    locks = malloc(sizeof(omp_lock_t) * HASH_SIZE);
    if(locks == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for OpenMP locks (malloc(): %s)\n",
            sizeof(omp_lock_t) * HASH_SIZE, strerror(errno));
        exit(3);
    }

    for (unsigned int i = 0; i < HASH_SIZE; i++) {
        /* allocate memory for hashtable entry */
        hashtable_entry_t *entry = malloc(sizeof(hashtable_entry_t) +
                                initial_size * sizeof(incident_record_t *));

        if (entry == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for hashtable entry (malloc(): %s)\n",
                    sizeof(hashtable_entry_t) + initial_size * sizeof(incident_record_t*), strerror(errno));
            exit(3);
        }

        entry->length = initial_size;
        entry->fill = 0;

        // Init OpenMP lock for this hashtable entry
        omp_init_lock(&(locks[i]));

        list->hashtable[i] = entry;
    }

    return list;
}

int list_insert(incident_list_t **list, master_record_t *rec)
{
    uint32_t srcaddr = rec->v4.srcaddr;
    uint16_t dstport = rec->dstport;
    uint8_t protocol = rec->prot;
    uint32_t dstaddr = rec->v4.dstaddr;
    uint64_t packets = rec->dPkts;
    uint64_t octets = rec->dOctets;

    incident_list_t *l = *list;

    /* compute the hash value (== index in hashtable) */
    uint16_t hash = list_hash(srcaddr, dstport);

    // Block until lock is ready (do this BEFORE entry is set, otherwise data might get inconsistent)
    omp_lock_t *lock = &(locks[hash]);
    omp_set_lock(lock);

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

        incident->flows++;
        incident->packets += packets;
        incident->octets += octets;

        // update timestamp of first and last sight
        incident->first = (incident->first > rec->first) ? rec->first : incident->first;
        incident->last  = (incident->last  < rec->last ) ? rec->last  : incident->last;

        /* if (srcaddr, dstport) is known, check if this dstaddr is also known */
        for (unsigned int i = 0; i < incident->fill; i++) {
            if (incident->dstaddr[i] == dstaddr) {
                /* if dstaddr is already in list, we're done */
                omp_unset_lock(lock);
                return 0;
            }
        }

        /* else test if there is enough storage for another dstaddr */
        if (incident->fill == incident->length) {

            /* allocate more memory */
            incident->length += l->increment;

            // Save length, in case realloc returns NULL (and overwrites our pointer)
            unsigned int tmplen = incident->length;

            incident = realloc(incident, sizeof(incident_record_t) +
                     incident->length * sizeof(uint32_t));

            if (incident == NULL) {
                fprintf(stderr, "unable to allocate %d byte of memory for incident (malloc(): %s)\n",
                    sizeof(incident_record_t) + tmplen * sizeof(uint32_t), strerror(errno));

                if(errno == ENOMEM) {
                    fprintf(stderr, "probably not enough memory :-(\n");
                }

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

            // Save length, in case realloc fails and returns NULL
            unsigned int tmplen = entry->length;

            entry = realloc(entry, sizeof(hashtable_entry_t) +
                     entry->length * sizeof(incident_record_t *));

            if (entry == NULL) {
                fprintf(stderr, "unable to allocate %d byte of memory for hashtable entry (malloc(): %s)\n",
                      sizeof(hashtable_entry_t) + tmplen * sizeof(incident_record_t *), strerror(errno));

                if(errno == ENOMEM) {
                    fprintf(stderr, "probably not enough memory :-(\n");
                }

                exit(3);
            }

            /* store (potentially) new pointer */
            l->hashtable[hash] = entry;
        }

        /* store the record at the end of the list */
        incident_record_t *record = malloc(sizeof(incident_record_t) +
                                           l->initial_size * sizeof(uint32_t));

        if (record == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for entry record (malloc(): %s)\n",
                    sizeof(incident_record_t) + l->initial_size * sizeof(uint32_t), strerror(errno));

            if(errno == ENOMEM) {
                fprintf(stderr, "probably not enough memory :-(\n");
            }

            exit(3);
        }

        /* init values */
        record->srcaddr = srcaddr;
        record->dstport = dstport;
        record->protocol = protocol;
        record->flows = 1;
        record->packets = packets;
        record->octets = octets;
        record->first = rec->first;
        record->last = rec->last;
        record->length = l->initial_size;
        record->fill = 1;
        record->dstaddr[0] = dstaddr;

        /* store pointer to record */
        entry->records[entry->fill++] = record;
    }

    // Release lock
    omp_unset_lock(lock);

    return 0;
}

int list_free(incident_list_t *list)
{
    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        for (unsigned int i = 0; i < list->hashtable[h]->fill; i++) {
            free(list->hashtable[h]->records[i]);
        }

        omp_destroy_lock(&(locks[h]));
        free(list->hashtable[h]);

    }
    free(locks);
    free(list);
    return 0;
}
