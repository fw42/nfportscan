/*
 *  This file is part of the nfdump project.
 *
 *  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
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
 *  
 *  $Author: peter $
 *
 *  $Id: nf_common.c 97 2008-02-21 09:50:02Z peter $
 *
 *  $LastChangedRevision: 97 $
 *	
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#include <stdint.h>

#include "nffile.h"
//#include "panonymizer.h"
#include "nf_common.h"
#include "util.h"

#ifdef __SUNPRO_C
extern 
#endif
inline void Proto_string(uint8_t protonum, char *protostr);

#ifdef __SUNPRO_C
extern 
#endif
inline void format_number(uint64_t num, char *s, int fixed_width);

#ifdef __SUNPRO_C
extern 
#endif
inline void condense_v6(char *s);


typedef void (*string_function_t)(master_record_t *, char *);

static struct token_list_s {
	string_function_t	string_function;	// function generation output string
	char				*string_buffer;		// buffer for output string
} *token_list;

static int	max_token_index	= 0;
static int	token_index		= 0;

#define BLOCK_SIZE	32

static char **format_list;		// ordered list of all individual strings formating the output line
static int	max_format_index	= 0;
static int	format_index		= 0;

static int		do_anonymize;
static int		do_tag;
static int 		long_v6 = 0;
static uint64_t numflows;
static double	duration;

#define STRINGSIZE 1024
#define IP_STRING_LEN   40

static char header_string[STRINGSIZE];
static char data_string[STRINGSIZE];

static const double _1KB = 1024.0;
static const double _1MB = 1024.0 * 1024.0;
static const double _1GB = 1024.0 * 1024.0 * 1024.0;
static const double _1TB = 1024.0 * 1024.0 * 1024.0 * 1024.0;

// tag 
static char tag_string[2];

/* prototypes */
static inline void ICMP_Port_decode(master_record_t *r, char *string);

static void InitFormatParser(void);

static void AddToken(int index);

static void AddString(char *string);

static void String_FirstSeen(master_record_t *r, char *string);

static void String_LastSeen(master_record_t *r, char *string);

static void String_Duration(master_record_t *r, char *string);

static void String_Protocol(master_record_t *r, char *string);

static void String_SrcAddr(master_record_t *r, char *string);

static void String_SrcAddrPort(master_record_t *r, char *string);

static void String_DstAddr(master_record_t *r, char *string);

static void String_DstAddrPort(master_record_t *r, char *string);

static void String_SrcPort(master_record_t *r, char *string);

static void String_DstPort(master_record_t *r, char *string);

static void String_SrcAS(master_record_t *r, char *string);

static void String_DstAS(master_record_t *r, char *string);

static void String_Input(master_record_t *r, char *string);

static void String_Output(master_record_t *r, char *string);

static void String_Packets(master_record_t *r, char *string);

static void String_Bytes(master_record_t *r, char *string);

static void String_Flows(master_record_t *r, char *string);

static void String_Tos(master_record_t *r, char *string);

static void String_Flags(master_record_t *r, char *string);

static void String_bps(master_record_t *r, char *string);

static void String_pps(master_record_t *r, char *string);

static void String_bpp(master_record_t *r, char *string);

static struct format_token_list_s {
	char				*token;				// token
	int					is_address;			// is an IP address
	char				*header;			// header line description
	string_function_t	string_function;	// function generation output string
} format_token_list[] = {
	{ "%ts",  0, "Date flow start        ", String_FirstSeen },		// Start Time - first seen
	{ "%te",  0, "Date flow end          ", String_LastSeen },		// End Time	- last seen
	{ "%td",  0, " Duration", 				String_Duration },		// Duration
	{ "%pr",  0, "Proto", 					String_Protocol },		// Protocol
	{ "%sa",  1, "     Src IP Addr", 		String_SrcAddr },		// Source Address
	{ "%da",  1, "     Dst IP Addr", 		String_DstAddr },		// Destination Address
	{ "%sap", 1, "     Src IP Addr:Port ",	String_SrcAddrPort },	// Source Address:Port
	{ "%dap", 1, "     Dst IP Addr:Port ",  String_DstAddrPort },	// Destination Address:Port
	{ "%sp",  0, "Src Pt", 				 	String_SrcPort },		// Source Port
	{ "%dp",  0, "Dst Pt", 				 	String_DstPort },		// Destination Port
	{ "%sas", 0, "Src AS",				 	String_SrcAS },			// Source AS
	{ "%das", 0, "Dst AS",				 	String_DstAS },			// Destination AS
	{ "%in",  0, " Input", 				 	String_Input },			// Input Interface num
	{ "%out", 0, "Output", 				 	String_Output },		// Output Interface num
	{ "%pkt", 0, " Packets", 			 	String_Packets },		// Packets
	{ "%byt", 0, "   Bytes", 			 	String_Bytes },			// Bytes
	{ "%fl",  0, "Flows", 				 	String_Flows },			// Flows
	{ "%dp",  0, "Src AS", 				 	String_DstAS },			// Destination AS
	{ "%pkt", 0, "Dst AS", 				 	String_Packets },		// Packets
	{ "%flg", 0,  " Flags", 			 	String_Flags },			// TCP Flags
	{ "%tos", 0, "Tos", 				 	String_Tos },			// Tos
	{ "%bps", 0, "     bps", 	 		 	String_bps },			// bps - bits per second
	{ "%pps", 0, "     pps", 			 	String_pps },			// pps - packets per second
	{ "%bpp", 0, "   Bpp", 				 	String_bpp },			// bps - Bytes perl package
	{ NULL, 0, NULL, NULL }
};

/* each of the tokens above must not generate output strings larger than this */
#define MAX_STRING_LENGTH	64

#define NumProtos	138

char protolist[NumProtos][6] = {
	"    0",	// 0   	masked out - no protocol info - set to '0'
	"ICMP ",	// 1   	Internet Control Message
	"IGMP ",	// 2	Internet Group Management
	"GGP  ",	// 3	Gateway-to-Gateway
	"IPIP ",	// 4	IP in IP (encapsulation)
	"ST   ",	// 5	Stream
	"TCP  ",	// 6	Transmission Control
	"CBT  ",	// 7	CBT
	"EGP  ",	// 8	Exterior Gateway Protocol
	"IGP  ",	// 9	any private interior gateway (used by Cisco for their IGRP)
	"BBN  ",	// 10	BBN RCC Monitoring
	"NVPII",	// 11	Network Voice Protocol
	"PUP  ",	// 12	PUP
	"ARGUS",	// 13	ARGUS
	"ENCOM",	// 14	EMCON
	"XNET ",	// 15	Cross Net Debugger
	"CHAOS",	// 16	Chaos
	"UDP  ",	// 17	User Datagram 
	"MUX  ",	// 18	Multiplexing
	"DCN  ",	// 19	DCN Measurement Subsystems
	"HMP  ",	// 20	Host Monitoring
	"PRM  ",	// 21	Packet Radio Measurement
	"XNS  ",	// 22	XEROX NS IDP 
	"Trnk1",	// 23	Trunk-1
	"Trnk2",	// 24	Trunk-2
	"Leaf1",	// 25	Leaf-1
	"Leaf2",	// 26	Leaf-2
	"RDP  ",	// 27	Reliable Data Protocol
	"IRTP ",	// 28	Internet Reliable Transaction
	"ISO-4",	// 29	ISO Transport Protocol Class 4
	"NETBK",	// 30	Bulk Data Transfer Protocol
	"MFESP",	// 31	MFE Network Services Protocol
	"MEINP",	// 32	MERIT Internodal Protocol
	"DCCP ",	// 33	Datagram Congestion Control Protocol
	"3PC  ",	// 34	Third Party Connect Protocol
	"IDPR ",	// 35	Inter-Domain Policy Routing Protocol 
	"XTP  ",	// 36	XTP
	"DDP  ",	// 37	Datagram Delivery Protocol
	"IDPR ",	// 38	IDPR Control Message Transport Proto
	"TP++ ",	// 39	TP++ Transport Protocol
	"IL   ",	// 40	IL Transport Protocol
	"IPv6 ",	// 41	IPv6
	"SDRP ",	// 42	Source Demand Routing Protocol
	"Rte6 ",	// 43	Routing Header for IPv6
	"Frag6",	// 44	Fragment Header for IPv6
	"IDRP ",	// 45	Inter-Domain Routing Protocol
	"RSVP ",	// 46	Reservation Protocol 
	"GRE  ",	// 47	General Routing Encapsulation
	"MHRP ",	// 48	Mobile Host Routing Protocol
	"BNA  ",	// 49	BNA
	"ESP  ",    // 50	Encap Security Payload 
	"AH   ",    // 51	Authentication Header
	"INLSP",    // 52	Integrated Net Layer Security  TUBA 
	"SWIPE",    // 53	IP with Encryption 
	"NARP ",    // 54	NBMA Address Resolution Protocol
	"MOBIL",    // 55	IP Mobility
	"TLSP ",    // 56	Transport Layer Security Protocol
	"SKIP ",    // 57	SKIP
	"ICMP6",	// 58	ICMP for IPv6
	"NOHE6",    // 59	No Next Header for IPv6
	"OPTS6",    // 60	Destination Options for IPv6
	"HOST ",    // 61	any host internal protocol
	"CFTP ",    // 62	CFTP
	"NET  ",    // 63	any local network
	"SATNT",    // 64	SATNET and Backroom EXPAK
	"KLAN ",    // 65	Kryptolan
	"RVD  ",    // 66	MIT Remote Virtual Disk Protocol
	"IPPC ",    // 67	Internet Pluribus Packet Core
	"FS   ",    // 68	any distributed file system
	"SATM ",    // 69	SATNET Monitoring 
	"VISA ",    // 70	VISA Protocol
	"IPCV ",    // 71	Internet Packet Core Utility
	"CPNX ",    // 72	Computer Protocol Network Executive
	"CPHB ",    // 73	Computer Protocol Heart Beat
	"WSN  ",    // 74	Wang Span Network
	"PVP  ",    // 75	Packet Video Protocol 
	"BSATM",    // 76	Backroom SATNET Monitoring
	"SUNND",    // 77	SUN ND PROTOCOL-Temporary
	"WBMON",    // 78	WIDEBAND Monitoring
	"WBEXP",    // 79	WIDEBAND EXPAK
	"ISOIP",    // 80	ISO Internet Protocol
	"VMTP ",    // 81	VMTP
	"SVMTP",    // 82	SECURE-VMTP
	"VINES",    // 83	VINES
	"TTP  ",    // 84	TTP
	"NSIGP",    // 85	NSFNET-IGP
	"DGP  ",    // 86	Dissimilar Gateway Protocol
	"TCP  ",    // 87	TCF
	"EIGRP",    // 88	EIGRP
	"OSPF ",    // 89	OSPFIGP
	"S-RPC",    // 90	Sprite RPC Protocol
	"LARP ",    // 91	Locus Address Resolution Protocol
	"MTP  ",    // 92	Multicast Transport Protocol
	"AX.25",    // 93	AX.25 Frames
	"IPIP ",	// 94	IP-within-IP Encapsulation Protocol
	"MICP ",    // 95	Mobile Internetworking Control Protocol
	"SCCSP",    // 96	Semaphore Communications Sec. Protocol
	"ETHIP",    // 97	Ethernet-within-IP Encapsulation
	"ENCAP",    // 98	Encapsulation Header
	"99   ",    // 99	any private encryption scheme
	"GMTP ",    // 100	GMTP
	"IFMP ",    // 101	Ipsilon Flow Management Protocol
	"PNNI ",    // 102	PNNI over IP 
	"PIM  ",	// 103	Protocol Independent Multicast
	"ARIS ",    // 104	ARIS
	"SCPS ",    // 105	SCPS
	"QNX  ",    // 106	QNX
	"A/N  ",    // 107	Active Networks
	"IPcmp",    // 108	IP Payload Compression Protocol
	"SNP  ",    // 109	Sitara Networks Protocol
	"CpqPP",    // 110	Compaq Peer Protocol
	"IPXIP",    // 111	IPX in IP
	"VRRP ",    // 112	Virtual Router Redundancy Protocol
	"PGM  ",    // 113	PGM Reliable Transport Protocol
	"0hop ",    // 114	any 0-hop protocol
	"L2TP ",    // 115	Layer Two Tunneling Protocol
	"DDX  ",    // 116	D-II Data Exchange (DDX)
	"IATP ",    // 117	Interactive Agent Transfer Protocol
	"STP  ",    // 118	Schedule Transfer Protocol
	"SRP  ",    // 119	SpectraLink Radio Protocol
	"UTI  ",    // 120	UTI
	"SMP  ",    // 121	Simple Message Protocol
	"SM   ",    // 122	SM
	"PTP  ",    // 123	Performance Transparency Protocol
	"ISIS4",    // 124	ISIS over IPv4
	"FIRE ",    // 125	FIRE
	"CRTP ",    // 126	Combat Radio Transport Protocol
	"CRUDP",    // 127	Combat Radio User Datagram
	"128  ",    // 128	SSCOPMCE
	"IPLT ",    // 129	IPLP
	"SPS  ",    // 130	Secure Packet Shield 
	"PIPE ",    // 131	Private IP Encapsulation within IP
	"SCTP ",    // 132	Stream Control Transmission Protocol
	"FC   ",    // 133	Fibre Channel
	"134  ",    // 134	RSVP-E2E-IGNORE
	"MHEAD",    // 135	Mobility Header
	"UDP-L",    // 136	UDPLite
	"MPLS "    // 137	MPLS-in-IP 
};


/* functions */

void Setv6Mode(int mode) {
	long_v6 += mode;
} 

int Getv6Mode(void) {
	return long_v6;
} 

#ifdef __SUNPRO_C
extern
#endif
inline void Proto_string(uint8_t protonum, char *protostr) {

	if ( protonum >= NumProtos ) {
		snprintf(protostr,16,"%-5i", protonum );
	} else {
		strncpy(protostr, protolist[protonum], 16);
	}

} // End of Proto_string

int Proto_num(char *protostr) {
int i, len;

	if ( (len = strlen(protostr)) >= 6 )
		return -1;

	for ( i=0; i<NumProtos; i++ ) {
		if ( strncasecmp(protostr,protolist[i], len) == 0 && 
			( protolist[i][len] == 0 || protolist[i][len] == ' ') )
			return i;
	}

	return -1;

} // End of Proto_num

void format_file_block_header(void *header, uint64_t numflows, char ** s, int anon, int tag) {
data_block_header_t *h = (data_block_header_t *)header;
	
	snprintf(data_string,STRINGSIZE-1 ,""
"File Block Header: \n"
"  NumBlocks     =  %10u\n"
"  Size          =  %10u\n"
"  id         	 =  %10u\n",
		h->NumBlocks,
		h->size,
		h->id);
	*s = data_string;

} // End of format_file_block_header

void format_file_block_record(void *record, uint64_t numflows, char ** s, int anon, int tag) {
uint64_t	anon_ip[2];
char 		as[IP_STRING_LEN], ds[IP_STRING_LEN], datestr1[64], datestr2[64], flags_str[16];
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;

	as[0] = 0;
	ds[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
#if 0
		if ( anon ) {
			anonymize_v6(r->v6.srcaddr, anon_ip);
			r->v6.srcaddr[0] = anon_ip[0];
			r->v6.srcaddr[1] = anon_ip[1];

			anonymize_v6(r->v6.dstaddr, anon_ip);
			r->v6.dstaddr[0] = anon_ip[0];
			r->v6.dstaddr[1] = anon_ip[1];
		}
#endif
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
		if ( ! long_v6 ) {
			condense_v6(as);
			condense_v6(ds);
		}
	} else {	// IPv4
#if 0
		if ( anon ) {
			r->v4.srcaddr = anonymize(r->v4.srcaddr);
			r->v4.dstaddr = anonymize(r->v4.dstaddr);
		}
#endif
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
	}
	as[IP_STRING_LEN-1] = 0;
	ds[IP_STRING_LEN-1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	String_Flags(record, flags_str);
	snprintf(data_string, STRINGSIZE-1, "\n"
"Flow Record: \n"
"  Flags       =       0x%.8x\n"
"  size        =            %5u\n"
"  mark        =            %5u\n"
"  srcaddr     = %16s\n"
"  dstaddr     = %16s\n"
"  first       =       %10u [%s]\n"
"  last        =       %10u [%s]\n"
"  msec_first  =            %5u\n"
"  msec_last   =            %5u\n"
"  dir         =              %3u\n"
"  tcp_flags   =             0x%2x %s\n"
"  prot        =              %3u\n"
"  tos         =              %3u\n"
"  input       =            %5u\n"
"  output      =            %5u\n"
"  srcas       =            %5u\n"
"  dstas       =            %5u\n"
"  srcport     =            %5u\n"
"  dstport     =            %5u\n"
"  dPkts       =       %10llu\n"
"  dOctets     =       %10llu\n"
, 
		r->flags, r->size, r->mark, as, ds, r->first, datestr1, r->last, datestr2,
		r->msec_first, r->msec_last, r->dir, r->tcp_flags, flags_str, r->prot, r->tos,
		r->input, r->output, r->srcas, r->dstas, r->srcport, r->dstport,
		(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	data_string[STRINGSIZE-1] = 0;
	*s = data_string;


} // End of format_file_block_record

void flow_record_to_pipe(void *record, uint64_t numflows, char ** s, int anon, int tag) {
uint64_t	anon_ip[2];
uint32_t	sa[4], da[4];
int			af;
master_record_t *r = (master_record_t *)record;

	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
#if 0
		if ( anon ) {
			anonymize_v6(r->v6.srcaddr, anon_ip);
			r->v6.srcaddr[0] = anon_ip[0];
			r->v6.srcaddr[1] = anon_ip[1];

			anonymize_v6(r->v6.dstaddr, anon_ip);
			r->v6.dstaddr[0] = anon_ip[0];
			r->v6.dstaddr[1] = anon_ip[1];
		}
#endif
		af = PF_INET6;
	} else {	// IPv4
#if 0
		if ( anon ) {
			r->v4.srcaddr = anonymize(r->v4.srcaddr);
			r->v4.dstaddr = anonymize(r->v4.dstaddr);
		}
#endif
		af = PF_INET;
	}

	// Make sure Endian does not screw us up
    sa[0] = ( r->v6.srcaddr[0] >> 32 ) & 0xffffffffLL;
    sa[1] = r->v6.srcaddr[0] & 0xffffffffLL;
    sa[2] = ( r->v6.srcaddr[1] >> 32 ) & 0xffffffffLL;
    sa[3] = r->v6.srcaddr[1] & 0xffffffffLL;

    da[0] = ( r->v6.dstaddr[0] >> 32 ) & 0xffffffffLL;
    da[1] = r->v6.dstaddr[0] & 0xffffffffLL;
    da[2] = ( r->v6.dstaddr[1] >> 32 ) & 0xffffffffLL;
    da[3] = r->v6.dstaddr[1] & 0xffffffffLL;

	snprintf(data_string, STRINGSIZE-1 ,"%i|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu",
				af, r->first, r->msec_first ,r->last, r->msec_last, r->prot, 
				sa[0], sa[1], sa[2], sa[3], r->srcport, da[0], da[1], da[2], da[3], r->dstport, 
				r->srcas, r->dstas, r->input, r->output,
				r->tcp_flags, r->tos, (unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	data_string[STRINGSIZE-1] = 0;

	*s = data_string;

} // End of flow_record_pipe

void format_special(void *record, uint64_t flows, char ** s, int anon, int tag) {
master_record_t *r = (master_record_t *)record;
int	i, index;

	do_anonymize  = anon;
	do_tag		  = tag;
	tag_string[0] = do_tag ? TAG_CHAR : '\0';
	tag_string[1] = '\0';
	numflows  = flows;

	duration = r->last - r->first;
	duration += ((double)r->msec_last - (double)r->msec_first) / 1000.0;
	for ( i=0; i<token_index; i++ ) {
		token_list[i].string_function(r, token_list[i].string_buffer);
	}

	// concat all strings together for the output line
	i = 0;
	for ( index=0; index<format_index; index++ ) {
		int j = 0;
		while ( format_list[index][j] && i < STRINGSIZE ) 
			data_string[i++] = format_list[index][j++];
	}
	if ( i < STRINGSIZE ) 
		data_string[i] = '\0';

	data_string[STRINGSIZE-1] = '\0';
	*s = data_string;

} // End of format_special 

char *format_special_header(void) {
	return header_string;
} // End of format_special_header

static void InitFormatParser(void) {

	max_format_index = max_token_index = BLOCK_SIZE;
	format_list = (char **)malloc(max_format_index * sizeof(char *));
	token_list  = (struct token_list_s *)malloc(max_token_index * sizeof(struct token_list_s));
	if ( !format_list || !token_list ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

} // End of InitFormatParser

static void AddToken(int index) {

	if ( token_index >= max_token_index ) { // no slot available - expand table
		max_token_index += BLOCK_SIZE;
		token_list = (struct token_list_s *)realloc(token_list, max_token_index * sizeof(struct token_list_s));
		if ( !token_list ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}
	token_list[token_index].string_function	 = format_token_list[index].string_function;
	token_list[token_index].string_buffer = malloc(MAX_STRING_LENGTH);
	AddString(token_list[token_index].string_buffer);
	token_index++;

} // End of AddToken

/* Add either a static string or the memory for a variable string from a token to the list */
static void AddString(char *string) {

	if ( !string ) {
		fprintf(stderr, "Panic! NULL string in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	if ( format_index >= max_format_index ) { // no slot available - expand table
		max_format_index += BLOCK_SIZE;
		format_list = (char **)realloc(format_list, max_format_index * sizeof(char *));
		if ( !format_list ) {
			fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			exit(255);
		}
	}
	format_list[format_index++] = string;

} // End of AddString

int ParseOutputFormat(char *format) {
char *c, *s, *h;
int	i, remaining;

	InitFormatParser();

	c = s = strdup(format);
	if ( !s ) {
		fprintf(stderr, "Memory allocation error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	h = header_string;
	*h = '\0';
	while ( *c ) {
		if ( *c == '%' ) {	// it's a token from format_token_list
			i = 0;
			remaining = strlen(c);
			while ( format_token_list[i].token ) {	// sweep through the list
				int len = strlen(format_token_list[i].token);

				// a token is separated by either a space, another token, or end of string
				if ( remaining >= len &&  !isalpha((int)c[len]) ) {
					// separator found a expected position
					char p = c[len]; 	// save separator;
					c[len] = '\0';
					if ( strncmp(format_token_list[i].token, c, len) == 0 ) {	// token found
						AddToken(i);
						if ( long_v6 && format_token_list[i].is_address )
							snprintf(h, STRINGSIZE-1-strlen(h), "%23s%s", "", format_token_list[i].header);
						else
							snprintf(h, STRINGSIZE-1-strlen(h), "%s", format_token_list[i].header);
						h += strlen(h);
						c[len] = p;
						c += len;
						break;
					} else {
						c[len] = p;
					}
				}
				i++;
			}
			if ( format_token_list[i].token == NULL ) {
				fprintf(stderr, "Output format parse error at: %s\n", c);
				free(s);
				return 0;
			}
		} else {			// it's a static string
			/* a static string goes up to next '%' or end of string */
			char *p = strchr(c, '%');
			char format[16];
			if ( p ) {
				// p points to next '%' token
				*p = '\0';
				AddString(strdup(c));
				snprintf(format, 15, "%%%zus", strlen(c));
				format[15] = '\0';
				snprintf(h, STRINGSIZE-1-strlen(h), format, "");
				h += strlen(h);
				*p = '%';
				c = p;
			} else {
				// static string up to end of format string
				AddString(strdup(c));
				snprintf(format, 15, "%%%zus", strlen(c));
				format[15] = '\0';
				snprintf(h, STRINGSIZE-1-strlen(h), format, "");
				h += strlen(h);
				*c = '\0';
			}
		}
	}

	free(s);
	return 1;

} // End of ParseOutputFormat

#ifdef __SUNPRO_C
extern
#endif
inline void format_number(uint64_t num, char *s, int fixed_width) {
double f = num;

	if ( f >= _1TB ) {
		if ( fixed_width ) 
			snprintf(s, 31, "%5.1f T", f / _1TB );
		else 
			snprintf(s, 31, "%.1f T", f / _1TB );
	} else if ( f >= _1GB ) {
		if ( fixed_width ) 
			snprintf(s, 31, "%5.1f G", f / _1GB );
		else 
			snprintf(s, 31, "%.1f G", f / _1GB );
	} else if ( f >= _1MB ) {
		if ( fixed_width ) 
			snprintf(s, 31, "%5.1f M", f / _1MB );
		else 
			snprintf(s, 31, "%.1f M", f / _1MB );
/*
	} else if ( f >= _1KB ) {
		snprintf(s, 31, "%5.1f K", f / _1KB );
*/
	} else  {
		if ( fixed_width ) 
			snprintf(s, 31, "%4.0f", f );
		else 
			snprintf(s, 31, "%.0f", f );
	} 

} // End of format_number

inline void condense_v6(char *s) {
size_t len = strlen(s);
char	*p, *q;

	if ( len <= 16 )
		return;

	// orig:      2001:620:1000:cafe:20e:35ff:fec0:fed5 len = 37
	// condensed: 2001:62..e0:fed5
	p = s + 7;
	*p++ = '.';
	*p++ = '.';
	q = s + len - 7;
	while ( *q ) { 
		*p++ = *q++; 
	}
	*p = 0;

} // End of condense_v6

static inline void ICMP_Port_decode(master_record_t *r, char *string) {
uint8_t	type, code;

	if ( r->prot == IPPROTO_ICMP || r->prot == IPPROTO_ICMPV6 ) { // ICMP
		type = r->dstport >> 8;
		code = r->dstport & 0xFF;
		snprintf(string, MAX_STRING_LENGTH-1, "%u.%u",  type, code);
	} else { 	// dst port
		snprintf(string, MAX_STRING_LENGTH-1, "%u",  r->dstport);
	}
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of ICMP_Port_decode

/* functions, which create the individual strings for the output line */
static void String_FirstSeen(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->first;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03u", r->msec_first);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_FirstSeen

static void String_LastSeen(master_record_t *r, char *string) {
time_t 	tt;
struct tm * ts;
char 	*s;

	tt = r->last;
	ts = localtime(&tt);
	strftime(string, MAX_STRING_LENGTH-1, "%Y-%m-%d %H:%M:%S", ts);
	s = string + strlen(string);
	snprintf(s, MAX_STRING_LENGTH-strlen(string)-1,".%03u", r->msec_last);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_LastSeen

static void String_Duration(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%9.3f", duration);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Duration

static void String_Protocol(master_record_t *r, char *string) {
char s[16];

	Proto_string(r->prot, s);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Protocol

static void String_SrcAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

		if ( do_anonymize ) {
#if 0
			anonymize_v6(r->v6.srcaddr, ip);
#endif
		} else {
			ip[0] = r->v6.srcaddr[0];
			ip[1] = r->v6.srcaddr[1];
		}

		ip[0] = htonll(ip[0]);
		ip[1] = htonll(ip[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
#if 0
		ip = do_anonymize ? anonymize(r->v4.srcaddr) : r->v4.srcaddr;
#else
        ip = r->v4.srcaddr;
#endif
		ip = htonl(ip);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_SrcAddr

static void String_SrcAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

#if 0
		if ( do_anonymize ) {
			anonymize_v6(r->v6.srcaddr, ip);
		} else {
			ip[0] = r->v6.srcaddr[0];
			ip[1] = r->v6.srcaddr[1];
		}
#else
        ip[0] = r->v6.srcaddr[0];
        ip[1] = r->v6.srcaddr[1];
#endif

		ip[0] = htonll(ip[0]);
		ip[1] = htonll(ip[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
#if 0
		ip = do_anonymize ? anonymize(r->v4.srcaddr) : r->v4.srcaddr;
#else
        ip = r->v4.srcaddr;
#endif
		ip = htonl(ip);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5i", tag_string, tmp_str, portchar, r->srcport);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5i", tag_string, tmp_str, portchar, r->srcport);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_SrcAddrPort

static void String_DstAddr(master_record_t *r, char *string) {
char tmp_str[IP_STRING_LEN];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

#if 0
		if ( do_anonymize ) {
			anonymize_v6(r->v6.dstaddr, ip);
		} else {
			ip[0] = r->v6.dstaddr[0];
			ip[1] = r->v6.dstaddr[1];
		}
#else
        ip[0] = r->v6.dstaddr[0];
        ip[1] = r->v6.dstaddr[1];
#endif

		ip[0] = htonll(ip[0]);
		ip[1] = htonll(ip[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
	} else {	// IPv4
		uint32_t	ip;
#if 0
		ip = do_anonymize ? anonymize(r->v4.dstaddr) : r->v4.dstaddr;
#else
        ip = r->v4.dstaddr;
#endif
		ip = htonl(ip);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s", tag_string, tmp_str);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s", tag_string, tmp_str);

	string[MAX_STRING_LENGTH-1] = 0;


} // End of String_DstAddr

static void String_DstAddrPort(master_record_t *r, char *string) {
char 	tmp_str[IP_STRING_LEN], portchar;
char 	icmp_port[MAX_STRING_LENGTH];

	tmp_str[0] = 0;
	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		uint64_t	ip[2];

#if 0
		if ( do_anonymize ) {
			anonymize_v6(r->v6.dstaddr, ip);
		} else {
			ip[0] = r->v6.dstaddr[0];
			ip[1] = r->v6.dstaddr[1];
		}
#else
			ip[0] = r->v6.dstaddr[0];
			ip[1] = r->v6.dstaddr[1];
#endif

		ip[0] = htonll(ip[0]);
		ip[1] = htonll(ip[1]);
		inet_ntop(AF_INET6, ip, tmp_str, sizeof(tmp_str));
		if ( ! long_v6 ) {
			condense_v6(tmp_str);
		}
		portchar = '.';
	} else {	// IPv4
		uint32_t	ip;
#if 0
		ip = do_anonymize ? anonymize(r->v4.dstaddr) : r->v4.dstaddr;
#else
		ip = r->v4.dstaddr;
#endif
		ip = htonl(ip);
		inet_ntop(AF_INET, &ip, tmp_str, sizeof(tmp_str));
		portchar = ':';
	}
	tmp_str[IP_STRING_LEN-1] = 0;
	ICMP_Port_decode(r, icmp_port);

	if ( long_v6 ) 
		snprintf(string, MAX_STRING_LENGTH-1, "%s%39s%c%-5s", tag_string, tmp_str, portchar, icmp_port);
	else
		snprintf(string, MAX_STRING_LENGTH-1, "%s%16s%c%-5s", tag_string, tmp_str, portchar, icmp_port);

	string[MAX_STRING_LENGTH-1] = 0;

} // End of String_DstAddrPort

static void String_SrcPort(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->srcport);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcPort

static void String_DstPort(master_record_t *r, char *string) {
char tmp[MAX_STRING_LENGTH];

	ICMP_Port_decode(r, tmp);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%6s", tmp);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstPort

static void String_SrcAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->srcas);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_SrcAS

static void String_DstAS(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->dstas);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_DstAS

static void String_Input(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->input);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Input

static void String_Output(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", r->output);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Output

static void String_Packets(master_record_t *r, char *string) {
char s[32];

	format_number(r->dPkts, s, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Packets

static void String_Bytes(master_record_t *r, char *string) {
char s[32];

	format_number(r->dOctets, s, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Bytes

static void String_Flows(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%5llu", (unsigned long long)numflows);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Flows

static void String_Tos(master_record_t *r, char *string) {

	snprintf(string, MAX_STRING_LENGTH-1 ,"%3u", r->tos);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Tos

static void String_Flags(master_record_t *r, char *string) {

	// if record contains unusuall flags, print the flags in hex as 0x.. number
	if ( r->tcp_flags > 63 ) {
		snprintf(string, 7, "  0x%2x\n", r->tcp_flags );
	} else {
		string[0] = r->tcp_flags & 32 ? 'U' : '.';
		string[1] = r->tcp_flags & 16 ? 'A' : '.';
		string[2] = r->tcp_flags &  8 ? 'P' : '.';
		string[3] = r->tcp_flags &  4 ? 'R' : '.';
		string[4] = r->tcp_flags &  2 ? 'S' : '.';
		string[5] = r->tcp_flags &  1 ? 'F' : '.';
	}
	string[6] = '\0';

} // End of String_Flags

static void String_bps(master_record_t *r, char *string) {
uint64_t	bps;
char s[32];

	if ( duration ) {
		bps = ( r->dOctets << 3 ) / duration;	// bits per second. ( >> 3 ) -> * 8 to convert octets into bits
	} else {
		bps = 0;
	}
	format_number(bps, s, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_bps

static void String_pps(master_record_t *r, char *string) {
uint64_t	pps;
char s[32];

	if ( duration ) {
		pps = r->dPkts / duration;				// packets per second
	} else {
		pps = 0;
	}
	format_number(pps, s, FIXED_WIDTH);
	snprintf(string, MAX_STRING_LENGTH-1 ,"%8s", s);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_Duration

static void String_bpp(master_record_t *r, char *string) {
uint32_t 	Bpp; 

	string[MAX_STRING_LENGTH-1] = '\0';

	if ( r->dPkts ) 
		Bpp = r->dOctets / r->dPkts;			// Bytes per Packet
	else 
		Bpp = 0;
	snprintf(string, MAX_STRING_LENGTH-1 ,"%6u", Bpp);
	string[MAX_STRING_LENGTH-1] = '\0';

} // End of String_bpp

