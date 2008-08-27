#include <stdint.h>

#ifndef LIST_H
#define LIST_H

/* structures for counting ssh flows */
typedef struct {
    uint32_t srcaddr;
    uint16_t dstport;
    unsigned int flows;
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
int list_insert(incident_list_t **list, uint32_t srcaddr, uint16_t dstport, uint16_t dstaddr);

/* deallocate memory for a list */
int list_free(incident_list_t *list);

#endif
