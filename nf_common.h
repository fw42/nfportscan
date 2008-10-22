/*
 *  nfcapd : Reads netflow data from socket and saves the
 *  data into a file. The file gets automatically rotated
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
 *  $Id: nf_common.h 95 2007-10-15 06:05:26Z peter $
 *
 *  $LastChangedRevision: 95 $
 *	
 *
 */

#include <stdint.h>

typedef void (*printer_t)(void *, uint64_t, char **, int, int);

typedef struct msec_time_s {
	time_t		sec;
	uint16_t	msec;
} msec_time_tt;

/* common minimum netflow header for all versions */
typedef struct common_flow_header {
  uint16_t  version;
  uint16_t  count;
} common_flow_header_t;

/* buffer size issues */

// 100MB max buffer size when dynamically extending
#define MAX_BUFFER_SIZE 104857600	

/* input buffer size, to read data from the network */
#define NETWORK_INPUT_BUFF_SIZE 65535	// Maximum UDP message size

/* output buffer size, tmp buffer, before writing data to the file 
 * when this buffer is 85% full, it gets written to disk.
 * no read cycle must ever produce more output data than it reads from the network
 * so 8,5 MB + 1 MB = 9.5MB of 10MB
 */
#define BUFFSIZE 1048576

/* if the output buffer reaches this limit, it gets flushed. This means,
 * that 0.5MB input data may produce max 1MB data in output buffer, otherwise
 * a buffer overflow may occur, and data does not get processed correctly.
 * However, every Process_vx function checks buffer boundaries.
 */
#define OUTPUT_FLUSH_LIMIT BUFFSIZE * 0.8


/* prototypes */

void Setv6Mode(int mode);

int Getv6Mode(void);

int Proto_num(char *protostr);

void format_file_block_header(void *header, uint64_t numflows, char **s, int anon, int tag);

void format_file_block_record(void *record, uint64_t numflows, char **s, int anon, int tag);

void flow_record_to_pipe(void *record, uint64_t numflows, char ** s, int anon, int tag);

int ParseOutputFormat(char *format);

void format_special(void *record, uint64_t flows, char ** s, int anon, int tag);

char *format_special_header(void);

#define FIXED_WIDTH 1
#define VAR_LENGTH  0

#define TAG_CHAR ''

