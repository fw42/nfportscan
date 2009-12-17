/*
 * nfportscan - extract scans for one port over a range of ips
 *              from cisco netflow data files
 *
 * (c) by Alexander Neumann <alexander@bumpern.de>
 *        Florian Weingarten <weingarten@rz.rwth-aachen.de>
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
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>

#include <malloc.h>

// OpenMP (multithreading)
#include <omp.h>

#include "file.h"
#include "list.h"
#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"

#include "version.h"
#ifndef VERSION
    #define VERSION "(unknown, compiled from git)"
#endif

#define DEFAULT_TIMEFORMAT "%d.%m.%y %H:%M:%S"

#define PROTO_ICMP 1
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
    unsigned int showfirstlast;
	unsigned int lastduration;
    unsigned int threshhold;
	char *timeformat;
    enum {
        SORT_HOSTS,
        SORT_FLOWS,
        SORT_IP,
        SORT_PORT,
		SORT_FIRST,
		SORT_DUR
    } sort_field;
    enum {
        SORT_DESC,
        SORT_ASC,
    } sort_order;
    char *filter;
    enum {
        NORMAL,
        CSV,
    } output;
    // This is an array of pointers because we use one
    // filter engine for each thread. Otherwise, they will interfere somehow
    // and things go bad.
    FilterEngine_data_t **engine;
} options_t;

options_t opts;

/** Print usage dialog (-h) */
static void print_help(FILE *output)
{
    fprintf(output, "USAGE: nfportscan [OPTIONS] FILE [FILE] ...\n"
                    "  -t  --threshhold       set dsthost minimum for an ip address to be reported\n"
                    "                         (default: 100)\n"
                    "  -T  --firstlast        show timestamps of first and last sights of flow\n"
					"  -s  --timeformat       overwrite time string format\n"
					"                         (default: \"%s\", strftime() syntax)\n"
					"  -D  --lastduration     show duration instead of last timestamp\n"
					"                         (in combination with -T)\n"
                    "  -H  --sort-hosts       sort by host destination count\n"
                    "  -f  --sort-flows       sort by flow count\n"
                    "  -i  --sort-ip          sort by host source ip\n"
                    "  -P  --sort-port        sort by destination port\n"
					"  -b  --sort-first       sort by timestamp of first sight\n"
					"  -e  --sort-duration    sort by duration between first and last sight\n"
                    "  -a  --order-asceding   sort list ascending\n"
                    "  -d  --order-desceding  sort list descending\n"
                    "  -p  --processors       set number of processors/threads to use (max: %d)\n"
                    "  -F  --filter           apply filter before counting\n"
                    "  -c  --csv              output data separated by TAB and NEWLINE\n"
                    "  -v  --verbose          set verbosity level\n"
                    "  -V  --version          print program version\n"
                    "  -h  --help             print this help\n",
			DEFAULT_TIMEFORMAT, omp_get_num_procs()
	);
}

void print_memory_usage(void) {
    struct mallinfo stats = mallinfo();
    printf("Allocated heap memory: %u bytes (%u bytes used)\n", stats.arena, stats.uordblks);
}

void print_time_usage(struct timeval *start, struct timeval *stop) {

    unsigned long int seconds = stop->tv_sec - start->tv_sec;
    unsigned int minutes = seconds / 60;
    seconds %= 60;
    printf("Time needed to analyze files: %u minutes %lu seconds\n", minutes, seconds);

}

/** Compare two incidents (used by quicksort) */
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
    } else if (opts.sort_field == SORT_DUR) {
		if ((ia->last - ia->first) < (ib->last - ib->first))
			return opts.sort_order == SORT_ASC ? -1 : 1;
		else if ((ia->last - ia->first) > (ib->last - ib->first))
			return opts.sort_order == SORT_ASC ? 1 : -1;
		else
			return 0;
	} else if (opts.sort_field == SORT_FIRST) {
		if (ia->first < ib->first)
			return opts.sort_order == SORT_ASC ? -1 : 1;
		else if (ia->first > ib->first)
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
    #pragma omp atomic
    l->flows++;

    /* throw away everything except TCP, UDP and ICMP IPv4 flows */
    if ( (mrec->prot != PROTO_TCP
                && mrec->prot != PROTO_UDP
                && mrec->prot != PROTO_ICMP)
            || mrec->flags & FLAG_IPV6_ADDR)
        return 0;

    /* test, if either the master record matches the filter expression, or no
     * filter has been given */
    if ( opts.filter ) {
        opts.engine[omp_get_thread_num()]->nfrecord = (uint64_t *)mrec;
        if (opts.engine[omp_get_thread_num()]->FilterEngine(opts.engine[omp_get_thread_num()]) == 0) {
            if (opts.verbose >= 4)
                printf("flow record failed to pass filter\n");
            return 0;
        }
    }

    /* count flows */
    #pragma omp atomic
    l->incident_flows++;

    /* insert into list */
    if(list_insert(list, mrec) == -1) {
        return -1;
    }

    if (opts.verbose >= 4) {
        char src[IPV4_ADDR_STR_LEN_MAX], dst[IPV4_ADDR_STR_LEN_MAX];

        /* convert source and destination ip to network byte order */
        mrec->v4.srcaddr = htonl(mrec->v4.srcaddr);
        mrec->v4.dstaddr = htonl(mrec->v4.dstaddr);

        /* make strings from ips */
        inet_ntop(AF_INET, &mrec->v4.srcaddr, src, sizeof(src));
        inet_ntop(AF_INET, &mrec->v4.dstaddr, dst, sizeof(dst));

        printf("incident flow: (proto %u) %s: %d -> %s: %d\n", mrec->prot, src, mrec->srcport, dst, mrec->dstport);
    }

    return 1;
}

static int process_file(char *file, incident_list_t **list, int filenum, int totalfiles)
{
    if (opts.verbose)
        printf("Thread %d: processing file %2d of %d: %s\n", omp_get_thread_num(), filenum, totalfiles, file);

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
            fprintf(stderr, "unable to allocate %d byte of memory (malloc(): %s)\n", bheader.size, strerror(errno));
            
            if(errno == ENOMEM) {
                fprintf(stderr, "probably not enough memory :-(\n");
            }

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

            if(process_flow(&mrec, list) == -1) {
                free(buf);
                close(fd);
                return -1;
            }
        }

        free(buf);
    }

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    const struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"threshhold", required_argument, 0, 't'},
		{"firstlast", no_argument, 0, 'T'},
		{"timeformat", required_argument, 0, 's'},
		{"lastduration", no_argument, 0, 'D'},
        {"sort-hosts", no_argument, 0, 'H'},
        {"sort-flows", no_argument, 0, 'f'},
        {"sort-ip", no_argument, 0, 'i'},
        {"sort-port", no_argument, 0, 'P'},
		{"sort-duration", no_argument, 0, 'e'},
		{"sort-first", no_argument, 0, 'b'},
        {"order-ascending", no_argument, 0, 'a'},
        {"order-descending", no_argument, 0, 'd'},
        {"processors", required_argument, 0, 'p'},
        {"filter", required_argument, 0, 'F'},
        {"csv", no_argument, 0, 'c'},
        {"version", no_argument, 0, 'V'},
        { NULL, 0, 0, 0 }
    };

    struct timeval start, stop;
    gettimeofday(&start,NULL);

    /* initialize options */
    opts.verbose = 0;
    opts.threshhold = 100;
    opts.filter = NULL;
    opts.engine = malloc(sizeof(FilterEngine_data_t*) * omp_get_num_procs());
    
    int i;
    for(i=0; i<omp_get_num_procs(); i++) {
        opts.engine[i] = NULL;
    }

    opts.sort_field = SORT_HOSTS;
    opts.sort_order = SORT_DESC;
    opts.output = NORMAL;
	opts.timeformat = DEFAULT_TIMEFORMAT;

    int c;
    while ((c = getopt_long(argc, argv, "hvVbTDet:p:HfiPadF:cs:", longopts, 0)) != -1) {
        switch (c) {
            case 'h': print_help(stdout);
                      exit(0);
                      break;
            case 'v': opts.verbose++;
                      break;
            case 'T': opts.showfirstlast = 1;
                      break;
            case 't': opts.threshhold = atoi(optarg);
                      break;
			case 's': opts.timeformat = malloc(strlen(optarg));
					  strcpy(opts.timeformat, optarg);
					  break;
            case 'p': {
                        unsigned int procs;
                        if(sscanf(optarg, "%u", &procs) != 1) {
                            fprintf(stderr, "Wrong argument (%s)\n", optarg);
                            exit(EXIT_FAILURE);
                        }
                        omp_set_num_threads(procs);
                        break;                    
                      }
			case 'D': opts.lastduration = 1;
					  break;
            case 'H': opts.sort_field = SORT_HOSTS;
                      break;
            case 'f': opts.sort_field = SORT_FLOWS;
                      break;
            case 'i': opts.sort_field = SORT_IP;
                      break;
            case 'P': opts.sort_field = SORT_PORT;
                      break;
			case 'e': opts.sort_field = SORT_DUR;
					  break;
			case 'b': opts.sort_field = SORT_FIRST;
					  break;
            case 'a': opts.sort_order = SORT_ASC;
                      break;
            case 'd': opts.sort_order = SORT_DESC;
                      break;
            case 'F': opts.filter = optarg;
                      for(i=0; i<omp_get_num_procs(); i++) {
                          opts.engine[i] = CompileFilter(optarg);

                          if (!opts.engine[i]) {
                              fprintf(stderr, "filter parse failed\n");
                              exit(254);
                          }
                      }
                      break;
            case 'c': opts.output = CSV;
                      break;
            case 'V': printf("nfportscan " VERSION ", compiled at " __DATE__ " " __TIME__ "\n");
                      exit(0);
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
			case SORT_DUR: printf("duration");
							 break;
			case SORT_FIRST: printf("first sight");
							 break;
        }

        switch (opts.sort_order) {
            case SORT_ASC: printf("(ascending)\n");
                           break;
            case SORT_DESC: printf("(descending)\n");
                           break;
        }
    }

    if (argv[optind] == NULL) {
        printf("no files given, use %s --help for more information\n", argv[0]);
        exit(0);
    }

    /* init incident list */
    incident_list_t *list = list_init(INCIDENT_LIST_INITIAL, INCIDENT_LIST_EXPAND);
    list->flows = 0;
    list->incident_flows = 0;

    // Count number of file arguments
    int optind_tmp = optind;
    int num_files = 0;
    while(argv[optind++] != NULL) num_files++;

    // Read files, each file in a seperate thread
    #pragma omp parallel for
    for(i=0; i<num_files; i++) {
        process_file(argv[optind_tmp + i], &list, i, num_files);
    }

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
        fprintf(stderr, "unable to allocate %d byte of memory for sorted list (malloc(): %s)\n",
                result.length * sizeof(incident_record_t), strerror(errno));
        exit(3);
    }

    for (unsigned int h = 0; h < HASH_SIZE; h++) {
        if (list->hashtable[h]->fill) {
            hashtable_entry_t *ht = list->hashtable[h];
            for (unsigned int i = 0; i < ht->fill; i++) {
                if (ht->records[i]->fill > opts.threshhold) {

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

//  if (opts.verbose)
        printf("Total: %u hits. Scanned %u flows, found %u incident flows (%.2f%%)\n\n", result.fill, list->flows,
                list->incident_flows, (double)list->incident_flows/(double)list->flows * 100);

    if (opts.verbose)
        printf("sorting result list...\n");

    qsort(&result.list[0], result.fill, sizeof(incident_record_t), incident_compare);

    if (opts.output == CSV)
        printf("source ip\tport\tproto\thosts\tflows\tpackets\toctets\tfirst\tlast\n");

    for (unsigned int i = 0; i < result.fill; i++) {
        char src[IPV4_ADDR_STR_LEN_MAX];

        /* convert source ip to network byte order */
        result.list[i].srcaddr = htonl(result.list[i].srcaddr);
        /* make string from ip */
        inet_ntop(AF_INET, &result.list[i].srcaddr, src, sizeof(src));

        char *protocol;
        if (result.list[i].protocol == PROTO_UDP)
            protocol = "UDP";
        else if (result.list[i].protocol == PROTO_TCP)
            protocol = "TCP";
        else
            protocol = "";

        if (opts.output == NORMAL) {

            char buf_first[100], buf_last[100];
		    strftime(buf_first, 100, opts.timeformat, localtime((time_t*)&(result.list[i].first)));

			if(opts.lastduration) {
				snprintf(buf_last,  100, "%02d min %02d sec", (result.list[i].last - result.list[i].first) / 60, (result.list[i].last - result.list[i].first) % 60);
			} else {
				strftime(buf_last,  100, opts.timeformat, localtime((time_t*)&(result.list[i].last) ));
			}

            if (result.list[i].protocol == PROTO_ICMP) {
                printf("  * %15s -> %2u/%2u (ICMP): %10u dsts (%7u flows, %7llu pckts, %9llu octs)",
                        src,
                        (uint8_t)(result.list[i].dstport >> 8),
                        (uint8_t)result.list[i].dstport,
                        result.list[i].fill, result.list[i].flows,
                        result.list[i].packets, result.list[i].octets
                );
            } else {
                printf("  * %15s -> %6u (%s): %10u dsts (%7u flows, %7llu pckts, %9llu octs)",
                        src, result.list[i].dstport,
                        protocol,
                        result.list[i].fill, result.list[i].flows,
                        result.list[i].packets, result.list[i].octets
                );
            }

            if(opts.showfirstlast) {
				printf("  (%s, %s)", buf_first, buf_last);
            }
            puts("");

        } else { /* opts.output == CSV */
            printf("%s\t%u\t%s\t"
                    "%u\t%u\t%llu\t%llu\t%u\t%u\n",
                    src, result.list[i].dstport,
                    protocol,
                    result.list[i].fill, result.list[i].flows,
                    result.list[i].packets, result.list[i].octets,
					result.list[i].first, result.list[i].last
			);

        }
    }

    puts("");
    gettimeofday(&stop,NULL);
    print_time_usage(&start,&stop);
//  print_memory_usage();
//  malloc_stats();
    puts("");

    free(result.list);
    list_free(list);
    free(opts.engine);

    return EXIT_SUCCESS;
}
