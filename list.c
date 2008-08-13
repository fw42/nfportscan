#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "list.h"

incident_list_t *list_init(unsigned int initial_size, unsigned int increment)
{
    /* allocate memory */
    incident_list_t *list = malloc(sizeof(incident_list_t) +
            initial_size * sizeof(incident_record_t));

    if (list == NULL)
        return NULL;

    list->length = initial_size;
    list->fill = 0;
    list->increment = increment;

    return list;
}

int list_insert(incident_list_t **list, uint32_t srcaddr, uint16_t dstport)
{
    /* test if list is big enough */
    if ((*list)->fill == (*list)->length) {
        (*list)->length += (*list)->increment;
        unsigned int new_size = (*list)->length * sizeof(incident_record_t)
            + sizeof(incident_list_t);
        *list = realloc(*list, new_size);

        if (*list == NULL) {
            fprintf(stderr, "unable to expand incident list, realloc() failed\n");
            exit(3);
        }

    }

    incident_list_t *l = *list;

    /* search in list */
    unsigned int min = 0;
    unsigned int max = l->fill;
    unsigned int pos;

    while(1) {
        if (max == min) {
            pos = max;
            break;
        }

        pos = (max+min)/2;

        if (srcaddr < l->records[pos].srcaddr ||
            (srcaddr == l->records[pos].srcaddr && dstport < l->records[pos].dstport))
            max = pos;
        else
            min = pos+1;
    }

    if (pos < l->fill) {
        /* move away everything after (and including) pos */
        memmove(&l->records[pos+1], &l->records[pos], (l->fill-pos) * sizeof(incident_record_t));
    }

    l->records[pos].srcaddr = srcaddr;
    l->records[pos].dstport = dstport;
    l->records[pos].flows = 1;
    l->fill++;

    return 0;
}

int list_search(incident_list_t **list, uint32_t srcaddr, uint16_t dstport)
{
    incident_list_t *l = *list;

    /* search in list */
    unsigned int min = 0;
    unsigned int max = l->fill;
    unsigned int pos;
    
    while(1) {
        pos = (max+min)/2;


        if (l->records[pos].srcaddr == srcaddr && l->records[pos].dstport == dstport)
            return pos;

        if (min == max)
            return -1;

        if (srcaddr < l->records[pos].srcaddr ||
            (srcaddr == l->records[pos].srcaddr && dstport < l->records[pos].dstport)) {
            max = pos;
        } else {
            min = pos+1;
        }
    }
}
