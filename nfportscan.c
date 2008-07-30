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

#include "file.h"

#define PROTO_TCP 6
#define IPV4_ADDR_STR_LEN_MAX 20

/* global options */
typedef struct {
    unsigned int verbose;
} options_t;

options_t opts;

static void print_help(FILE *output)
{
    fprintf(output, "USAGE: nfportscan [OPTIONS] FILE [FILE] ...\n"
                    "  -v    --verbose   set verbosity level\n"
                    "  -h    --help      print this help\n");
}

static int read_file(char *file)
{
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

#ifdef DEBUG
    printf("header says:\n");
    printf("    magic: 0x%04x\n", header.magic);
    printf("    version: 0x%04x\n", header.version);
    printf("    flags: 0x%x\n", header.flags);
    printf("    blocks: %d\n", header.NumBlocks);
    printf("    ident: \"%s\"\n", header.ident);
#endif

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

#ifdef DEBUG
    printf("stat:\n");
    printf("    flows: %llu\n", (unsigned long long)stats.numflows);
    printf("    bytes: %llu\n", (unsigned long long)stats.numbytes);
    printf("    packets: %llu\n", (unsigned long long)stats.numpackets);
    printf("-------------------\n");
#endif

    uint32_t blocks_remaining = header.NumBlocks;
    while (blocks_remaining > 0) {

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

        printf("    data block header:\n");
        printf("        data records: %d\n", bheader.NumBlocks);
        printf("        size: %d bytes\n", bheader.size);
        printf("        id: %d\n", bheader.id);

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

            /* throw away everything except TCP in IPv4 flows */
            if (mrec.prot != PROTO_TCP || mrec.flags & FLAG_IPV6_ADDR)
                continue;

            char src[IPV4_ADDR_STR_LEN_MAX], dst[IPV4_ADDR_STR_LEN_MAX];

            /* convert source and destination ip to network byte order */
            mrec.v4.srcaddr = htonl(mrec.v4.srcaddr);
            mrec.v4.dstaddr = htonl(mrec.v4.dstaddr);

            /* make strings from ips */
            inet_ntop(AF_INET, &mrec.v4.srcaddr, src, sizeof(src));
            inet_ntop(AF_INET, &mrec.v4.dstaddr, dst, sizeof(dst));

            printf("flow: %s: %d -> %s: %d\n", src, mrec.srcport, dst, mrec.dstport);
        }

        free(buf);

        blocks_remaining--;
    }

    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    const struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        { NULL, 0, 0, 0 }
    };

    /* initialize options */
    opts.verbose = 0;

    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, 0)) != -1) {
        switch (c) {
            case 'h': print_help(stdout);
                      exit(0);
                      break;
            case 'v': opts.verbose++;
                      break;
            case '?': print_help(stderr);
                      exit(1);
                      break;
        }
    }

    while (argv[optind] != NULL)
        read_file(argv[optind++]);

    return EXIT_SUCCESS;
}
