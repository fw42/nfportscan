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
 *  $Id: grammar.y 97 2008-02-21 09:50:02Z peter $
 *
 *  $LastChangedRevision: 97 $
 *	
 *
 *
 */

%{

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <stdint.h>

#include "nf_common.h"
#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nftree.h"
#include "ipconv.h"
#include "util.h"

/*
 * function prototypes
 */
static void  yyerror(char *msg);

static uint32_t ChainHosts(uint64_t *hostlist, int num_records, int type);

enum { SOURCE = 1, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION };


/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint64_t		*IPstack;
extern uint32_t	StartNode;
extern uint16_t	Extended;
extern int (*FilterEngine)(uint32_t *);

static uint32_t num_ip;

%}

%union {
	uint64_t		value;
	char			*s;
	FilterParam_t	param;
	void			*list;
}

%token ANY IP IF IDENT TOS FLAGS PROTO HOSTNAME NET PORT IN OUT SRC DST EQ LT GT
%token NUMBER STRING IDENT ALPHA_FLAGS PROTOSTR PORTNUM ICMP_TYPE ICMP_CODE AS PACKETS BYTES PPS BPS BPP DURATION
%token IPV4 IPV6
%token NOT END
%type <value>	expr NUMBER PORTNUM ICMP_TYPE ICMP_CODE
%type <s>	STRING IDENT ALPHA_FLAGS PROTOSTR 
%type <param> dqual inout term comp 
%type <list> iplist ullist

%left	'+' OR
%left	'*' AND
%left	NEGATE

%%
prog: 		/* empty */
	| expr 	{   
		StartNode = $1; 
	}
	;

term:	ANY { /* this is an unconditionally true expression, as a filter applies in any case */
		$$.self = NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL ); 
	}

	| IDENT STRING {	
		if ( !ScreenIdentString($2) ) {
			yyerror("Illegal ident string");
			YYABORT;
		}

		uint32_t	index = AddIdent($2);
		$$.self = NewBlock(0, 0, index, CMP_IDENT, FUNC_NONE, NULL ); 
	}

	| IPV4 { 
		$$.self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(0LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}

	| IPV6 { 
		$$.self = NewBlock(OffsetRecordFlags, (1LL << ShiftRecordFlags)  & MaskRecordFlags, 
					(1LL << ShiftRecordFlags)  & MaskRecordFlags, CMP_EQ, FUNC_NONE, NULL); 
	}

	| PROTO NUMBER { 
		int64_t	proto;
		proto = $2;

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		$$.self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 

	}

	| PROTO STRING { 
		int64_t	proto;
		proto = Proto_num($2);

		if ( proto > 255 ) {
			yyerror("Protocol number > 255");
			YYABORT;
		}
		if ( proto < 0 ) {
			yyerror("Unknown protocol");
			YYABORT;
		}
		$$.self = NewBlock(OffsetProto, MaskProto, (proto << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL); 
	}

	| PACKETS comp NUMBER { 
		$$.self = NewBlock(OffsetPackets, MaskPackets, $3, $2.comp, FUNC_NONE, NULL); 
	}

	| BYTES comp NUMBER {	
		$$.self = NewBlock(OffsetBytes, MaskBytes, $3, $2.comp, FUNC_NONE, NULL); 
	}

	| PPS comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_PPS, NULL); 
	}

	| BPS comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_BPS, NULL); 
	}

	| BPP comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_BPP, NULL); 
	}

	| DURATION comp NUMBER {	
		$$.self = NewBlock(0, AnyMask, $3, $2.comp, FUNC_DURATION, NULL); 
	}

	| TOS comp NUMBER {	
		if ( $3 > 255 ) {
			yyerror("TOS must be 0..255");
			YYABORT;
		}
		$$.self = NewBlock(OffsetTos, MaskTos, ($3 << ShiftTos) & MaskTos, $2.comp, FUNC_NONE, NULL); 
	}

	| FLAGS comp NUMBER	{	
		if ( $3 > 63 ) {
			yyerror("Flags must be 0..63");
			YYABORT;
		}
		$$.self = NewBlock(OffsetFlags, MaskFlags, ($3 << ShiftFlags) & MaskFlags, $2.comp, FUNC_NONE, NULL); 
	}

	| FLAGS STRING	{	
		uint64_t fl = 0;
		int cnt     = 0;
		size_t		len = strlen($2);

		if ( len > 7 ) {
			yyerror("Too many flags");
			YYABORT;
		}

		if ( strchr($2, 'F') ) { fl |=  1; cnt++; }
		if ( strchr($2, 'S') ) { fl |=  2; cnt++; }
		if ( strchr($2, 'R') ) { fl |=  4; cnt++; }
		if ( strchr($2, 'P') ) { fl |=  8; cnt++; }
		if ( strchr($2, 'A') ) { fl |=  16; cnt++; }
		if ( strchr($2, 'U') ) { fl |=  32; cnt++; }
		if ( strchr($2, 'X') ) { fl =  63; cnt++; }

		if ( cnt != len ) {
			yyerror("Too many flags");
			YYABORT;
		}

		$$.self = NewBlock(OffsetFlags, (fl << ShiftFlags) & MaskFlags, 
					(fl << ShiftFlags) & MaskFlags, CMP_FLAGS, FUNC_NONE, NULL); 
	}

	| dqual IP STRING { 	
		int af, bytes, ret;

		ret = parse_ip(&af, $3, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Error parsing IP address.");
			YYABORT;
		}

		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		if ( ret == -2 ) {
			// could not resolv host => 'not any'
			$$.self = Invert(NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE, NULL )); 
		} else {

			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			if ( $$.direction == SOURCE || $$.direction == DESTINATION ) {
				$$.self = ChainHosts(IPstack, num_ip, $$.direction);
			} else {
				uint32_t src = ChainHosts(IPstack, num_ip, SOURCE);
				uint32_t dst = ChainHosts(IPstack, num_ip, DESTINATION);
	
				if ( $$.direction == SOURCE_OR_DESTINATION ) {
					$$.self = Connect_OR(src, dst);
				} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
					$$.self = Connect_AND(src, dst);
				} else {
					/* should never happen */
					yyerror("Internal parser error");
					YYABORT;
				}
			}
		}
	}

	| dqual IP IN '[' iplist ']' { 	

		$$.direction = $1.direction;
		if ( $$.direction == SOURCE ) {
			$$.self = NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 );
		} else if ( $$.direction == DESTINATION) {
			$$.self = NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 );
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 )
			);
		} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
			$$.self = Connect_AND(
					NewBlock(OffsetSrcIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetDstIPv6a, MaskIPv6, 0 , CMP_IPLIST, FUNC_NONE, (void *)$5 )
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}

	| dqual PORT comp NUMBER {	
		$$.direction = $1.direction;
		if ( $4 > 65535 ) {
			yyerror("Port outside of range 0..65535");
			YYABORT;
		}

		if ( $$.direction == SOURCE ) {
			$$.self = NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL );
		} else if ( $$.direction == DESTINATION) {
			$$.self = NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL );
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
				NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL ),
				NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL )
			);
		} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
			$$.self = Connect_AND(
				NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE, NULL ),
				NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE, NULL )
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}

	| dqual PORT IN '[' ullist ']' { 	
		struct ULongListNode *node;

		$$.direction = $1.direction;
		if ( $$.direction == SOURCE ) {
			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
			}
			$$.self = NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
		} else if ( $$.direction == DESTINATION) {
			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				node->value = (node->value << ShiftDstPort) & MaskDstPort;
			}
			$$.self = NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
		} else { // src and/or dst port
			// we need a second list due to different shifts for src and dst ports
			ULongtree_t *root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {

				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstPort) & MaskDstPort;
				node->value = (node->value << ShiftSrcPort) & MaskSrcPort;
				RB_INSERT(ULongtree, root, n);
			}

			if ( $$.direction == SOURCE_OR_DESTINATION ) {

				$$.self = Connect_OR(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
			} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
				$$.self = Connect_AND(
					NewBlock(OffsetPort, MaskSrcPort, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetPort, MaskDstPort, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
			} else {
				/* should never happen */
				yyerror("Internal parser error");
				YYABORT;
			}
		}
	}

	| ICMP_TYPE NUMBER {
		if ( $2 > 255 ) {
			yyerror("ICMP tpye of range 0..15");
			YYABORT;
		}
		$$.self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			NewBlock(OffsetProto, MaskProto, (1LL << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
			NewBlock(OffsetPort, MaskICMPtype, ($2 << ShiftICMPtype) & MaskICMPtype, CMP_EQ, FUNC_NONE, NULL )
		);

	}

	| ICMP_CODE NUMBER {
		if ( $2 > 255 ) {
			yyerror("ICMP code of range 0..15");
			YYABORT;
		}
		$$.self = Connect_AND(
			// imply proto ICMP with a proto ICMP block
			NewBlock(OffsetProto, MaskProto, (1LL << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE, NULL), 
			NewBlock(OffsetPort, MaskICMPcode, ($2 << ShiftICMPcode) & MaskICMPcode, CMP_EQ, FUNC_NONE, NULL )
		);

	}

	| dqual AS NUMBER {	
		$$.direction = $1.direction;
		if ( $3 > 65535 || $3 < 0 ) {
			yyerror("AS number of range 0..65535");
			YYABORT;
		}

		if ( $$.direction == SOURCE ) {
			$$.self = NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE, NULL );
		} else if ( $$.direction == DESTINATION) {
			$$.self = NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE, NULL);
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
				NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE, NULL)
			);
		} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
			$$.self = Connect_AND(
				NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE, NULL)
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}

	| dqual AS IN '[' ullist ']' { 	
		struct ULongListNode *node;

		$$.direction = $1.direction;
		if ( $$.direction == SOURCE ) {
			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
			}
			$$.self = NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
		} else if ( $$.direction == DESTINATION) {
			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {
				node->value = (node->value << ShiftDstAS) & MaskDstAS;
			}
			$$.self = NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 );
		} else {
			// src and/or dst AS
			// we need a second list due to different shifts for src and dst AS
			ULongtree_t *root = malloc(sizeof(ULongtree_t));

			struct ULongListNode *n;
			if ( root == NULL) {
				yyerror("malloc() error");
				YYABORT;
			}
			RB_INIT(root);

			RB_FOREACH(node, ULongtree, (ULongtree_t *)$5) {

				if ((n = malloc(sizeof(struct ULongListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				n->value 	= (node->value << ShiftDstAS) & MaskDstAS;
				node->value = (node->value << ShiftSrcAS) & MaskSrcAS;
				RB_INSERT(ULongtree, root, n);
			}

			if ( $$.direction == SOURCE_OR_DESTINATION ) {
				$$.self = Connect_OR(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
			} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
				$$.self = Connect_AND(
					NewBlock(OffsetAS, MaskSrcAS, 0, CMP_ULLIST, FUNC_NONE, (void *)$5 ),
					NewBlock(OffsetAS, MaskDstAS, 0, CMP_ULLIST, FUNC_NONE, (void *)root )
				);
			} else {
				/* should never happen */
				yyerror("Internal parser error");
				YYABORT;
			}
		}
	}

	| dqual NET STRING STRING { 
		int af, bytes, ret;
		uint64_t	mask[2];
		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET ) {
			yyerror("IP netmask syntax valid only for IPv4");
			YYABORT;
		}
		if ( bytes != 4 ) {
			yyerror("Need complete IP address");
			YYABORT;
		}

		ret = parse_ip(&af, $4, mask, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set

		if ( af != PF_INET || bytes != 4 ) {
			yyerror("Invalid netmask for IPv4 address");
			YYABORT;
		}

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		$$.direction = $1.direction;

		if ( $$.direction == SOURCE ) {
			$$.self = Connect_AND(
				NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
			);
		} else if ( $$.direction == DESTINATION) {
			$$.self = Connect_AND(
				NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
			);
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
						Connect_AND(
							NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						),
						Connect_AND(
							NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						)
			);
		} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
			$$.self = Connect_AND(
						Connect_AND(
							NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						),
						Connect_AND(
							NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						)
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}

	| dqual NET STRING '/' NUMBER { 
		int af, bytes, ret;
		uint64_t	mask[2];

		ret = parse_ip(&af, $3, IPstack, &bytes, STRICT_IP, &num_ip);
		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( ret == -1 ) {
			yyerror("IP address required - hostname not allowed here.");
			YYABORT;
		}
		// ret == -2 will never happen here, as STRICT_IP is set


		if ( $5 > (bytes*8) ) {
			yyerror("Too many netbits for this IP addresss");
			YYABORT;
		}

		if ( af == PF_INET ) {
			mask[0] = 0xffffffffffffffffLL;
			mask[1] = 0xffffffffffffffffLL << ( 32 - $5 );
		} else {	// PF_INET6
			if ( $5 > 64 ) {
				mask[0] = 0xffffffffffffffffLL;
				mask[1] = 0xffffffffffffffffLL << ( 128 - $5 );
			} else {
				mask[0] = 0xffffffffffffffffLL << ( 64 - $5 );
				mask[1] = 0;
			}
		}
		// IP aadresses are stored in network representation 
		mask[0]	 = mask[0];
		mask[1]	 = mask[1];

		IPstack[0] &= mask[0];
		IPstack[1] &= mask[1];

		$$.direction = $1.direction;
		if ( $$.direction == SOURCE ) {
			$$.self = Connect_AND(
				NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
			);
		} else if ( $$.direction == DESTINATION) {
			$$.self = Connect_AND(
				NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
			);
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
						Connect_AND(
							NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						),
						Connect_AND(
							NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						)
			);
		} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
			$$.self = Connect_AND(
						Connect_AND(
							NewBlock(OffsetSrcIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetSrcIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						),
						Connect_AND(
							NewBlock(OffsetDstIPv6b, mask[1], IPstack[1] , CMP_EQ, FUNC_NONE, NULL ),
							NewBlock(OffsetDstIPv6a, mask[0], IPstack[0] , CMP_EQ, FUNC_NONE, NULL )
						)
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}

	| inout IF NUMBER {
		if ( $3 > 65535 ) {
			yyerror("Input interface number must be 0..65535");
			YYABORT;
		}
		if ( $$.direction == SOURCE ) {
			$$.self = NewBlock(OffsetInOut, MaskInput, ($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL); 
		} else if ( $$.direction == DESTINATION) {
			$$.self = NewBlock(OffsetInOut, MaskOutput, ($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL); 
		} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
			$$.self = Connect_OR(
				NewBlock(OffsetInOut, MaskInput, ($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE, NULL),
				NewBlock(OffsetInOut, MaskOutput, ($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE, NULL)
			);
		} else {
			/* should never happen */
			yyerror("Internal parser error");
			YYABORT;
		}
	}
	;

/* iplist definition */
iplist:	STRING	{ 
		int i, af, bytes, ret;
		struct IPListNode *node;

		IPlist_t *root = malloc(sizeof(IPlist_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		ret = parse_ip(&af, $1, IPstack, &bytes, ALLOW_LOOKUP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		// ret == -1 will never happen here, as ALLOW_LOOKUP is set
		
		if ( ret != -2 ) {
			if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
				yyerror("incomplete IP address");
				YYABORT;
			}

			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
				RB_INSERT(IPtree, root, node);
			}

		}
		$$ = (void *)root;

	}
	| iplist STRING { 
		int i, af, bytes, ret;
		struct IPListNode *node;

		ret = parse_ip(&af, $2, IPstack, &bytes, STRICT_IP, &num_ip);

		if ( ret == 0 ) {
			yyerror("Invalid IP address");
			YYABORT;
		}
		if ( af && (( af == PF_INET && bytes != 4 ) || ( af == PF_INET6 && bytes != 16 ))) {
			yyerror("incomplete IP address");
			YYABORT;
		}

		// ret == - 2 means lookup failure
		if ( ret != -2 ) {
			for ( i=0; i<num_ip; i++ ) {
				if ((node = malloc(sizeof(struct IPListNode))) == NULL) {
					yyerror("malloc() error");
					YYABORT;
				}
				node->ip[0] = IPstack[2*i];
				node->ip[1] = IPstack[2*i+1];
	
				RB_INSERT(IPtree, (IPlist_t *)$$, node);
			}
		}
	}
	;

/* ULlist definition */
ullist:	NUMBER	{ 
		struct ULongListNode *node;

		if ( $1 > 65535 ) {
			yyerror("Value outside of range 0..65535");
			YYABORT;
		}
		ULongtree_t *root = malloc(sizeof(ULongtree_t));

		if ( root == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		RB_INIT(root);

		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = $1;

		RB_INSERT(ULongtree, root, node);
		$$ = (void *)root;
	}
	| ullist NUMBER { 
		struct ULongListNode *node;

		if ( $2 > 65535 ) {
			yyerror("Value outside of range 0..65535");
			YYABORT;
		}
		if ((node = malloc(sizeof(struct ULongListNode))) == NULL) {
			yyerror("malloc() error");
			YYABORT;
		}
		node->value = $2;
		RB_INSERT(ULongtree, (ULongtree_t *)$$, node);
	}
	;

/* scaling  qualifiers */

/* comparator qualifiers */
comp:				{ $$.comp = CMP_EQ; }
	| EQ			{ $$.comp = CMP_EQ; }
	| LT			{ $$.comp = CMP_LT; }
	| GT			{ $$.comp = CMP_GT; }
	;

/* 'direction' qualifiers */
dqual:	  			{ $$.direction = SOURCE_OR_DESTINATION;  }
	| SRC			{ $$.direction = SOURCE;				 }
	| DST			{ $$.direction = DESTINATION;			 }
	| SRC OR DST 	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| DST OR SRC	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| SRC AND DST	{ $$.direction = SOURCE_AND_DESTINATION; }
	| DST AND SRC	{ $$.direction = SOURCE_AND_DESTINATION; }
	;

inout:	  			{ $$.direction = SOURCE_OR_DESTINATION;  }
	| IN			{ $$.direction = SOURCE;				 }
	| OUT			{ $$.direction = DESTINATION;			 }
	;

expr:	term		{ $$ = $1.self;        }
	| expr OR  expr	{ $$ = Connect_OR($1, $3);  }
	| expr AND expr	{ $$ = Connect_AND($1, $3); }
	| NOT expr	%prec NEGATE	{ $$ = Invert($2);			}
	| '(' expr ')'	{ $$ = $2; }
	;

%%

static void  yyerror(char *msg) {
	fprintf(stderr,"line %d: %s at '%s'\n", lineno, msg, yytext);
} /* End of yyerror */

static uint32_t ChainHosts(uint64_t *hostlist, int num_records, int type) {
uint32_t offset_a, offset_b, i, j, block;

	if ( type == SOURCE ) {
		offset_a = OffsetSrcIPv6a;
		offset_b = OffsetSrcIPv6b;
	} else {
		offset_a = OffsetDstIPv6a;
		offset_b = OffsetDstIPv6b;
	}

	i = 0;
	block = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
	i += 2;
	for ( j=1; j<num_records; j++ ) {
		uint32_t b = Connect_AND(
				NewBlock(offset_b, MaskIPv6, hostlist[i+1] , CMP_EQ, FUNC_NONE, NULL ),
				NewBlock(offset_a, MaskIPv6, hostlist[i] , CMP_EQ, FUNC_NONE, NULL )
			);
		block = Connect_OR(block, b);
		i += 2;
	}

	return block;

} // End of ChainHosts
