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
 *  $Id: scanner.l 97 2008-02-21 09:50:02Z peter $
 *
 *  $LastChangedRevision: 97 $
 *	
 *
 *
 */

%{

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include <stdint.h>

#include "rbtree.h"
#include "nfdump.h"
#include "grammar.h"
int lineno = 1;

#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else
static char *in_buffer;

#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif

%}

N				[0-9]+
H				(0X|0x)[0-9A-Fa-f]+

%%

[0-9]+			{ 
					yylval.value = (uint64_t) strtoull(yytext,NULL,10);
					return NUMBER;
				}

[0-9]+[kmgt]{0,1}	{ 
					size_t len = strlen(yytext);
					switch (yytext[len-1]) {
						case 'k':
							yylval.value = 1024LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 'm':
							yylval.value = 1024LL * 1024LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 'g':
							yylval.value = 1024LL * 1024LL * 1024LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						case 't':
							yylval.value = 1024LL * 1024LL * 1024LL * 1024LL * (uint64_t) strtoull(yytext,NULL,10);
							break;
						default:
							yylval.value = (uint64_t) strtoull(yytext,NULL,10);
					}
					return NUMBER;
				}

any				{ return ANY; }
ip|host			{ return IP; }
hostname		{ return HOSTNAME; }
if				{ return IF; }
in				{ return IN; }
ident			{ return IDENT; }
out				{ return OUT; }

flags			{ return FLAGS; }
proto			{ return PROTO; }
tos				{ return TOS; }
net				{ return NET; }
port			{ return PORT; }
as				{ return AS; }
packets			{ return PACKETS; }
bytes			{ return BYTES; }
bpp				{ return BPP; }
bps				{ return BPS; }
pps				{ return PPS; }
duration		{ return DURATION; }
ipv4|inet		{ return IPV4; }
ipv6|inet6		{ return IPV6; }
icmp-type		{ return ICMP_TYPE; }
icmp-code		{ return ICMP_CODE; }
and|"&&"		{ return AND; }
or|"||"			{ return OR; }
not|"!"			{ return NOT; }
"="|"=="|eq		{ return EQ; }
">"|gt			{ return GT; }
"<"|lt			{ return LT; }
src				{ return SRC; }
dst				{ return DST; }
#.*				{ ; }
[ \t]			{ ; }

[a-zA-Z0-9_:\.\-]+ { 
					yylval.s = strdup(yytext);
					return STRING; 
				}
\n				{ lineno++; }
.				{ return yytext[0]; }
			
%%

void lex_init(char *buf) {
#ifdef FLEX_SCANNER
        in_buffer = yy_scan_string(buf);
#else
        in_buffer = buf;
#endif
}

/*
 * Do any cleanup necessary after parsing.
 */
void lex_cleanup(void) {
#ifdef FLEX_SCANNER
        if (in_buffer != NULL)
                yy_delete_buffer(in_buffer);
        in_buffer = NULL;
#endif
}

int yywrap(void) {
	return 1;
}

int ScreenIPString(char *string) {
	char *c;

	// [0-9A-Fa-f:][0-9A-Fa-f\.:]+[0-9A-Fa-f:] {
	int len = strlen(string);
	if ( len < 3 || len > 39 ) 
		return 0;
	
	if ( !isxdigit(string[0]) ) 
		return 0;

	c = &string[1];
	while ( *c ) {
		if ( *c != '.' || *c != ':' || !isxdigit(*c) ) 
			return 0;
		c++;
	}
	return 1;

} // End of ScreenString

int ScreenIdentString(char *string) {
	char *c;

	// ident[a-zA-Z0-9_\-]+ { 
	int len = strlen(string);
	if ( len == 0 || len > 255 ) 
		return 0;
	
	c = &string[0];
	while ( *c ) {
		if ( *c != '_' && *c != '-' && !isalnum(*c) ) 
			return 0;
		c++;
	}
	return 1;


} // End of ScreenIdentString


