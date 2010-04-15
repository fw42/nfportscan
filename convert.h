#define DATA_BLOCK_TYPE_2 2

typedef struct common_record_v2_s {

 	// record head
 	uint16_t	type;
 	uint16_t	size;

	// record meta data
	uint8_t		flags;

	uint8_t		exporter_ref;
 	uint16_t	ext_map;

	// netflow common record
 	uint16_t	msec_first;
 	uint16_t	msec_last;
 	uint32_t	first;
 	uint32_t	last;
 
 	uint8_t		fwd_status;
 	uint8_t		tcp_flags;
 	uint8_t		prot;
 	uint8_t		tos;
 	uint16_t	srcport;
 	uint16_t	dstport;

	// link to extensions
 	uint32_t	data[1];

} common_record_v2_t;
