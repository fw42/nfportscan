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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include "file.h"
#include "list.h"
#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"

#define PROTO_TCP 6
#define PROTO_UDP 17
#define IPV4_ADDR_STR_LEN_MAX 20
#define INCIDENT_LIST_INITIAL 10
#define INCIDENT_LIST_EXPAND 10
#define SORT_LIST_INITIAL 1000
#define SORT_LIST_EXPAND 100
#define WHITE_LIST_INITIAL 10
#define WHITE_LIST_EXPAND 10

typedef struct {
    uint32_t baseaddr;
    uint8_t bits;
} ip_network_t;

/* global options */
typedef struct {
    unsigned int verbose;
    unsigned int threshhold;
    enum {
        SORT_HOSTS,
        SORT_FLOWS,
        SORT_IP,
        SORT_PORT,
    } sort_field;
    enum {
        SORT_DESC,
        SORT_ASC,
    } sort_order;
    struct {
        unsigned int fill;
        unsigned int length;
        ip_network_t *list;
    } net_whitelist;
    struct {
        unsigned int fill;
        unsigned int length;
        uint16_t *list;
    } port_whitelist;
    char *filter;
    FilterEngine_data_t *engine;
} options_t;

options_t opts;

static void print_help(FILE *output)
{
    fprintf(output, "USAGE: nfportscan [OPTIONS] FILE [FILE] ...\n"
                    "  -t    --threshhold   set dsthost minimum for an ip address to be reported\n"
                    "                       (default: 100)\n"
                    "  -H    --sort-hosts   sort by host destination count\n"
                    "  -f    --sort-flows   sort by flow count\n"
                    "  -i    --sort-ip      sort by host source ip\n"
                    "  -P    --sort-port    sort by destination port\n"
                    "  -a    --order-asceding   sort list ascending\n"
                    "  -d    --order-desceding  sort list descending\n"
                    "  -w    --whitelist-network    whitelist a network (in CIDR)\n"
                    "  -p    --whitelist-port       whitelist a port\n"
                    "                (whitelist options can be specified multiple times)\n"
                    "  -F    --filter       apply filter before counting\n"
                    "  -v    --verbose      set verbosity level\n"
                    "  -h    --help         print this help\n");
}

static int incident_compare(const void *a, const void *b) {
    incident_record_t *ia = (incident_record_t *)a;
    incident_record_t *ib = (incident_record_t *)b;

    if (opts.sort_field == SORT_HOSTS) {
        if (ia->fill < ib->fill)
            return opts.sort_order == SORT_ASC ? -1 : 1;
        else if (ia->fill > ib->fill)
            return opts.sort_order == SORT_ASC ? 1 : -1;
        else
            return 0;
    } else if (opts.sort_field == SORT_FLOWS) {
        if (ia->flows < ib->flows)
            return opts.sort_order == SORT_ASC ? -1 : 1;
        else if (ia->flows > ib->flows)
            return opts.sort_order == SORT_ASC ? 1 : -1;
        else
            return 0;
    } else if (opts.sort_field == SORT_IP) {
        if (ia->srcaddr < ib->srcaddr)
            return opts.sort_order == SORT_ASC ? -1 : 1;
        else if (ia->srcaddr > ib->srcaddr)
            return opts.sort_order == SORT_ASC ? 1 : -1;
        else
            return 0;
    } else if (opts.sort_field == SORT_PORT) {
        if (ia->dstport < ib->dstport)
            return opts.sort_order == SORT_ASC ? -1 : 1;
        else if (ia->dstport > ib->dstport)
            return opts.sort_order == SORT_ASC ? 1 : -1;
        else
            return 0;
    }

    return 0;
}

static int process_flow(master_record_t *mrec, incident_list_t **list)
{
    incident_list_t *l = *list;
    /* count global flows */
    l->flows++;

    /* throw away everything except TCP or UDP IPv4 flows */
    if ( (mrec->prot != PROTO_TCP && mrec->prot != PROTO_UDP)
                || mrec->flags & FLAG_IPV6_ADDR)
        return 0;

    /* test, if either the master record matches the filter expression, or no
     * filter has been given */
    if ( opts.filter ) {
        opts.engine->nfrecord = (uint64_t *)mrec;
        if (opts.engine->FilterEngine(opts.engine) == 0) {
            if (opts.verbose >= 4)
                printf("flow record failed to pass filter\n");
            return 0;
        }
    }

    /* count flows */
    l->incident_flows++;

    /* insert into list */
    list_insert(list, mrec->v4.srcaddr, mrec->dstport, mrec->v4.dstaddr);

    if (opts.verbose >= 4) {
        char src[IPV4_ADDR_STR_LEN_MAX], dst[IPV4_ADDR_STR_LEN_MAX];

        /* convert source and destination ip to network byte order */
        mrec->v4.srcaddr = htonl(mrec->v4.srcaddr);
        mrec->v4.dstaddr = htonl(mrec->v4.dstaddr);

        /* make strings from ips */
        inet_ntop(AF_INET, &mrec->v4.srcaddr, src, sizeof(src));
        inet_ntop(AF_INET, &mrec->v4.dstaddr, dst, sizeof(dst));

        printf("incident flow: %s: %d -> %s: %d\n", src, mrec->srcport, dst, mrec->dstport);
    }

    return 1;
}

static int process_file(char *file, incident_list_t **list)
{
    if (opts.verbose)
        printf("processing file %s\n", file);

    int fd;
    if ( (fd = open(file, O_RDONLY)) == -1 ) {
        fprintf(stderr, "unable to open file \"%s\": %s\n", file, strerror(errno));
        close(fd);
        return -1;
    }

    /* read header */
    file_header_t header;
    int len;
    if ((len = read(fd, &header, sizeof(header))) == -1) {
        fprintf(stderr, "%s: read error: %s\n", file, strerror(errno));
        close(fd);
        return -1;
    }

    if (len < (signed int)sizeof(header)) {
        fprintf(stderr, "%s: incomplete file header: got %d bytes\n", file, len);
        close(fd);
        return -2;
    }

    if (opts.verbose >= 2) {
        printf("header says:\n");
        printf("    magic: 0x%04x\n", header.magic);
        printf("    version: 0x%04x\n", header.version);
        printf("    flags: 0x%x\n", header.flags);
        printf("    blocks: %d\n", header.NumBlocks);
        printf("    ident: \"%s\"\n", header.ident);
    }

    if (header.magic != FILE_MAGIC) {
        fprintf(stderr, "%s: wrong magic: 0x%04x\n", file, header.magic);
        close(fd);
        return -3;
    }

    if (header.version != FILE_VERSION) {
        fprintf(stderr, "%s: file has newer version %d, this program "
                "only supports version %d\n", file, header.version, FILE_VERSION);
        close(fd);
        return -4;
    }

    if (header.flags != 0) {
        fprintf(stderr, "%s: file is compressed, this is not supported\n", file);
        close(fd);
        return -5;
    }

    /* read stat record */
    stat_record_t stats;
    if ((len = read(fd, &stats, sizeof(stats))) == -1) {
        fprintf(stderr, "%s: read error: %s\n", file, strerror(errno));
        close(fd);
        return -1;
    }

    if (len < (signed int)sizeof(stat_record_t)) {
        fprintf(stderr, "%s: incomplete stat record\n", file);
        close(fd);
        return -6;
    }

    if (opts.verbose >= 2) {
        printf("stat:\n");
        printf("    flows: %llu\n", (unsigned long long)stats.numflows);
        printf("    bytes: %llu\n", (unsigned long long)stats.numbytes);
        printf("    packets: %llu\n", (unsigned long long)stats.numpackets);
        printf("-------------------\n");
    }

    while(header.NumBlocks--) {

        /* read block header */
        data_block_header_t bheader;
        if ( (len = read(fd, &bheader, sizeof(bheader))) == -1) {
            fprintf(stderr, "%s: read error: %s\n", file, strerror(errno));
            close(fd);
            return -1;
        }

        if ( len < (signed int)sizeof(bheader)) {
            fprintf(stderr, "%s: incomplete data block header\n", file);
            close(fd);
            return -7;
        }

        if (opts.verbose >= 3) {
            printf("    data block header:\n");
            printf("        data records: %d\n", bheader.NumBlocks);
            printf("        size: %d bytes\n", bheader.size);
            printf("        id: %d\n", bheader.id);
        }

        if (bheader.id != DATA_BLOCK_TYPE_1) {
            fprintf(stderr, "%s: data block has unknown id %d\n", file, bheader.id);
        }

        /* read complete block into buffer */
        void *buf = malloc(bheader.size);

        if (buf == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory\n", bheader.size);
            exit(3);
        }

        if ( (len = read(fd, buf, bheader.size)) == -1) {
            fprintf(stderr, "%s: read error: %s\n", file, strerror(errno));
            close(fd);
            return -1;
        }

        if ( len < (signed int)bheader.size ) {
            fprintf(stderr, "%s: incomplete data block\n", file);
            close(fd);
            return -7;
        }

        common_record_t *c = buf;

        while (bheader.NumBlocks--) {
            /* expand common record into master record */
            master_record_t mrec;
            ExpandRecord(c, &mrec);

            /* advance pointer */
            c = (common_record_t *)((pointer_addr_t)c + c->size);

            process_flow(&mrec, list);
        }

        free(buf);
    }

    close(fd);
    return 0;
}

static void add_whitelist_network(char *str)
{
    /* parse CIDR bits */
    char *slash = strchr(str, '/');
    if (slash == NULL) {
        fprintf(stderr, "ERROR: whitelist network has to be specified in CIDR notation!\n");
        exit(5);
    }

    /* split string in two */
    *slash = '\0';
    slash++;
    /* parse bits */
    int bits = atoi(slash);

    uint8_t cidr_bits = 0;
    if (bits >= 0 && bits <= 32)
        cidr_bits = (uint8_t)bits;
    else {
        fprintf(stderr, "ERROR: invalid number of CIDR bits: %s\n", slash);
        exit(7);
    }

    uint32_t cidr_base_addr = 0;

    char *ipptr = strtok(str, ".");
    while (ipptr) {
        /* parse integer */
        int b = atoi(ipptr);
        if (b >= 0 && b <= 255) {
            uint8_t byte = (uint8_t)b;
            /* construct uint32_t for network base address, in network byte order */
            cidr_base_addr <<= 8;
            cidr_base_addr |= byte;
        } else {
            fprintf(stderr, "invalid ip address: \"%s\"\n", ipptr);
            exit(6);
        }

        ipptr = strtok(NULL, ".");
    }

    uint32_t mask = (uint32_t)((uint64_t)(1<<(32-cidr_bits))-1);
    if (cidr_base_addr & mask) {
        fprintf(stderr, "Warning: fixing invalid CIDR address (too many bits set)\n");
        cidr_base_addr &= ~mask;
    }

    char src[IPV4_ADDR_STR_LEN_MAX];

    /* convert source ip to network byte order */
    uint32_t base_addr = htonl(cidr_base_addr);
    /* make string from ip */
    inet_ntop(AF_INET, &base_addr, src, sizeof(src));

    if (opts.net_whitelist.fill == opts.net_whitelist.length) {
        opts.net_whitelist.length += WHITE_LIST_EXPAND;
        opts.net_whitelist.list = realloc(opts.net_whitelist.list,
                opts.net_whitelist.length * sizeof(ip_network_t));

        if (opts.net_whitelist.list == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for ip network whitelist\n",
                    WHITE_LIST_INITIAL * sizeof(ip_network_t));
            exit(3);
        }
    }

    opts.net_whitelist.list[opts.net_whitelist.fill].baseaddr = cidr_base_addr;
    opts.net_whitelist.list[opts.net_whitelist.fill].bits = cidr_bits;
    opts.net_whitelist.fill++;

    if (opts.verbose >= 3)
        printf("whitelisted network: %s/%u\n", src, cidr_bits);
}

static void add_whitelist_port(char *str)
{
    int p = atoi(str);

    if (p < 0 || p > 65535) {
        fprintf(stderr, "ERROR: invalid port: %s\n", str);
        exit(7);
    }

    uint16_t port = (uint16_t)p;

    if (opts.port_whitelist.fill == opts.port_whitelist.length) {
        opts.port_whitelist.length += WHITE_LIST_EXPAND;
        opts.port_whitelist.list = realloc(opts.port_whitelist.list,
                opts.port_whitelist.length * sizeof(uint16_t));

        if (opts.port_whitelist.list == NULL) {
            fprintf(stderr, "unable to allocate %d byte of memory for ip network whitelist\n",
                    WHITE_LIST_INITIAL * sizeof(uint16_t));
            exit(3);
        }
    }

    opts.port_whitelist.list[opts.port_whitelist.fill] = port;
    opts.port_whitelist.fill++;

    if (opts.verbose >= 3)
        printf("whitelisted port: %u\n", port);

}

static int address_whitelisted(uint32_t addr)
{
    for (unsigned int i = 0; i < opts.net_whitelist.fill; i++) {
        uint32_t mask = ~(uint32_t)((uint64_t)(1<<(32-opts.net_whitelist.list[i].bits))-1);
        if (opts.net_whitelist.list[i].baseaddr == (addr & mask))
            return 1;
    }

    return 0;
}

static int port_whitelisted(uint16_t port)
{
    for (unsigned int i = 0; i < opts.port_whitelist.fill; i++) {
        if (opts.port_whitelist.list[i] == port)
            return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"threshhold", required_argument, 0, 't'},
        {"sort-hosts", no_argument, 0, 'H'},
        {"sort-flows", no_argument, 0, 'f'},
        {"sort-ip", no_argument, 0, 'i'},
        {"sort-port", no_argument, 0, 'P'},
        {"order-ascending", no_argument, 0, 'a'},
        {"order-descending", no_argument, 0, 'd'},
        {"whitelist-network", required_argument, 0, 'w'},
        {"whitelist-port", required_argument, 0, 'p'},
        {"filter", required_argument, 0, 'F'},
        { NULL, 0, 0, 0 }
    };

    /* initialize options */
    opts.verbose = 0;
    opts.threshhold = 100;
    opts.filter = NULL;
    opts.engine = NULL;
    opts.sort_field = SORT_HOSTS;
    opts.sort_order = SORT_DESC;
    opts.net_whitelist.fill = 0;
    opts.net_whitelist.length = WHITE_LIST_INITIAL;
    opts.net_whitelist.list = malloc(WHITE_LIST_INITIAL * sizeof(ip_network_t));

    if (opts.net_whitelist.list == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for ip network whitelist\n",
                WHITE_LIST_INITIAL * sizeof(ip_network_t));
        exit(3);
    }

    opts.port_whitelist.fill = 0;
    opts.port_whitelist.length = WHITE_LIST_INITIAL;
    opts.port_whitelist.list = malloc(WHITE_LIST_INITIAL * sizeof(uint16_t));

    if (opts.port_whitelist.list == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for ip network whitelist\n",
                WHITE_LIST_INITIAL * sizeof(uint16_t));
        exit(3);
    }

    int c;
    while ((c = getopt_long(argc, argv, "hvt:HfiPadw:p:F:", longopts, 0)) != -1) {
        switch (c) {
            case 'h': print_help(stdout);
                      exit(0);
                      break;
            case 'v': opts.verbose++;
                      break;
            case 't': opts.threshhold = atoi(optarg);
                      break;
            case 'H': opts.sort_field = SORT_HOSTS;
                      break;
            case 'f': opts.sort_field = SORT_FLOWS;
                      break;
            case 'i': opts.sort_field = SORT_IP;
                      break;
            case 'P': opts.sort_field = SORT_PORT;
                      break;
            case 'a': opts.sort_order = SORT_ASC;
                      break;
            case 'd': opts.sort_order = SORT_DESC;
                      break;
            case 'w': add_whitelist_network(optarg);
                      break;
            case 'p': add_whitelist_port(optarg);
                      break;
            case 'F': opts.filter = optarg;
                      opts.engine = CompileFilter(optarg);
                      if (!opts.engine) {
                          fprintf(stderr, "filter parse failed\n");
                          exit(254);
                      }
                      break;
            case '?': print_help(stderr);
                      exit(1);
                      break;
        }
    }

    if (opts.verbose) {
        printf("threshhold is %u, sorting by ", opts.threshhold);
        switch (opts.sort_field) {
            case SORT_HOSTS: printf("destination hosts ");
                             break;
            case SORT_FLOWS: printf("flows ");
                             break;
            case SORT_IP: printf("source ip ");
                             break;
            case SORT_PORT: printf("destination port ");
                             break;
        }

        switch (opts.sort_order) {
            case SORT_ASC: printf("(ascending)\n");
                           break;
            case SORT_DESC: printf("(descending)\n");
                           break;
        }
    }

    if (argv[optind] == NULL)
        printf("no files given, use %s --help for more information\n", argv[0]);

    /* init incident list */
    incident_list_t *list = list_init(INCIDENT_LIST_INITIAL, INCIDENT_LIST_EXPAND);
    list->flows = 0;
    list->incident_flows = 0;

    while (argv[optind] != NULL)
        process_file(argv[optind++], &list);

    if (opts.verbose)
        printf("scanned %u flows, found %u incident flows (%.2f%%)\n", list->flows,
                list->incident_flows, (double)list->incident_flows/(double)list->flows * 100);

    /* allocate memory for sorted output list */
    struct {
        unsigned int fill;
        unsigned int length;
        incident_record_t *list;
    } result;

    result.fill = 0;
    result.length = SORT_LIST_INITIAL;
    result.list = malloc(SORT_LIST_INITIAL * sizeof(incident_record_t));

    if (result.list == NULL) {
        fprintf(stderr, "unable to allocate %d byte of memory for sorted list\n", 
                result.length * sizeof(incident_record_t));
        exit(3);
    }

    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        if (list->hashtable[h]->fill) {
            hashtable_entry_t *ht = list->hashtable[h];
            for (unsigned int i = 0; i < ht->fill; i++) {
                if (ht->records[i]->fill > opts.threshhold &&
                    !address_whitelisted(ht->records[i]->srcaddr) &&
                    !port_whitelisted(ht->records[i]->dstport)) {

                    if (result.fill == result.length) {
                        result.length += SORT_LIST_EXPAND;
                        result.list = realloc(result.list,
                                result.length * sizeof(incident_record_t));

                        if (result.list == NULL) {
                            fprintf(stderr, "unable to expand sorted list\n");
                            exit(3);
                        }
                    }

                    memcpy(&result.list[result.fill++], ht->records[i],
                            sizeof(incident_record_t));

                }
            }
        }
    }

    if (opts.verbose)
        printf("sorting result list...\n");

    qsort(&result.list[0], result.fill, sizeof(incident_record_t), incident_compare);

    for (unsigned int i = 0; i < result.fill; i++) {
        char src[IPV4_ADDR_STR_LEN_MAX];

        /* convert source ip to network byte order */
        result.list[i].srcaddr = htonl(result.list[i].srcaddr);
        /* make string from ip */
        inet_ntop(AF_INET, &result.list[i].srcaddr, src, sizeof(src));

        printf("  * %15s -> %5u : %10u dsthosts (%10u flows)\n",
                src, result.list[i].dstport,
                result.list[i].fill, result.list[i].flows);
    }

    free(opts.net_whitelist.list);
    free(opts.port_whitelist.list);
    free(result.list);
    list_free(list);

    return EXIT_SUCCESS;
}
