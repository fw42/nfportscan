#include <stdint.h>

#ifndef LIST_H
#define LIST_H

/* structures for counting ssh flows */
typedef struct {
    uint32_t srcaddr;
    uint16_t dstport;
    unsigned int flows;
} incident_record_t;

typedef struct {
    unsigned int length;
    unsigned int fill;
    unsigned int increment;
    unsigned int global_flows;
    unsigned int incident_flows;
    incident_record_t records[];
} incident_list_t;

/* allocate memory and initialize list, flow counter must be initialized
 * afterwards, memory must be free()d later */
incident_list_t *list_init(unsigned int initial_size, unsigned int increment);

/* returns 0 on success, 1 if list has to be grown, < 0 if error occured */
int list_insert(incident_list_t **list, uint32_t srcaddr, uint16_t dstport);

/* returns index on success, -1 if not found */
int list_search(incident_list_t **list, uint32_t srcaddr, uint16_t dstport);

#endif
