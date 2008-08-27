#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <time.h>

#include "list.h"

int main(void) {
    printf("creating list...\n");
    incident_list_t *list = list_init(10, 10);

    if (list == NULL) {
        printf("unable to allocate memory for list: %s\n", strerror(errno));
        exit(2);
    }

    printf("initializing random generator\n");
    //srandom(time(NULL));

    for (unsigned int i = 0; i < 5000000; i++) {
        uint32_t src = random() & 0xffff;
        uint16_t port = random() & 0xff;
        uint32_t dst = random() & 0xffff;

        list_insert(&list, src, port, dst);

        if (i % 1000 == 0) {
            printf(".");
            fflush(stdout);
        }

        //int ret = list_search(&list, src, port);
        //if (ret < 0)
        //    printf("not found??\n");
        //else
        //    printf("found at pos %i\n", ret);

        //printf("-> %i\n", ret);
        //printf("\n");
    }

#if 0
    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        if (list->hashtable[h]->fill) {
            printf("hash %4x:\n", h);
            hashtable_entry_t *ht = list->hashtable[h];
            for (unsigned int i = 0; i < ht->fill; i++) {
                printf("  * (%u, %u): %u (%u)\n",
                        ht->records[i]->srcaddr, ht->records[i]->dstport,
                        ht->records[i]->fill, ht->records[i]->flows);
            }
        }
    }
#endif

#if 0
    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        printf("hash %8x: %u\n", h, list->hashtable[h]->fill);
    }
#endif



    printf("\n");
    list_free(list);

    return 0;
}
