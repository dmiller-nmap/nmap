#ifndef lint
static char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define yyclearin (yychar=(-1))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING (yyerrflag!=0)
#define YYPREFIX "yy"
#line 2 "grammar.y"
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
#ifndef lint
static const char rcsid[] =
    "@(#) $Header$ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdlib.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <net/if.h>

#include <netinet/in.h>

#include <stdio.h>

#include "pcap-int.h"

#include "gencode.h"
#include <pcap-namedb.h>

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#define QSET(q, p, d, a) (q).proto = (p),\
			 (q).dir = (d),\
			 (q).addr = (a)

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void
yyerror(char *msg)
{
	++n_errors;
	bpf_error("%s", msg);
	/* NOTREACHED */
}

#ifndef YYBISON
int yyparse(void);

int
pcap_parse()
{
	return (yyparse());
}
#endif

#line 85 "grammar.y"
typedef union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		struct block *b;
	} blk;
	struct block *rblk;
} YYSTYPE;
#line 108 "y.tab.c"
#define DST 257
#define SRC 258
#define HOST 259
#define GATEWAY 260
#define NET 261
#define MASK 262
#define PORT 263
#define LESS 264
#define GREATER 265
#define PROTO 266
#define PROTOCHAIN 267
#define BYTE 268
#define ARP 269
#define RARP 270
#define IP 271
#define TCP 272
#define UDP 273
#define ICMP 274
#define IGMP 275
#define IGRP 276
#define PIM 277
#define ATALK 278
#define AARP 279
#define DECNET 280
#define LAT 281
#define SCA 282
#define MOPRC 283
#define MOPDL 284
#define TK_BROADCAST 285
#define TK_MULTICAST 286
#define NUM 287
#define INBOUND 288
#define OUTBOUND 289
#define LINK 290
#define GEQ 291
#define LEQ 292
#define NEQ 293
#define ID 294
#define EID 295
#define HID 296
#define HID6 297
#define LSH 298
#define RSH 299
#define LEN 300
#define IPV6 301
#define ICMPV6 302
#define AH 303
#define ESP 304
#define VLAN 305
#define ISO 306
#define ESIS 307
#define ISIS 308
#define CLNP 309
#define OR 310
#define AND 311
#define UMINUS 312
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,   24,    1,    1,    1,    1,    1,   20,   21,
    2,    2,    2,    3,    3,    3,    3,    3,    3,    3,
    3,   23,   22,    4,    4,    4,    7,    7,    5,    5,
    8,    8,    8,    8,    8,    8,    6,    6,    6,    6,
    6,    6,    9,    9,   10,   10,   10,   10,   10,   10,
   11,   11,   11,   12,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   25,
   25,   25,   25,   25,   25,   25,   25,   25,   18,   18,
   18,   19,   19,   19,   13,   13,   14,   14,   14,   14,
   14,   14,   14,   14,   14,   14,   14,   14,   14,   15,
   15,   15,   15,   15,   17,   17,
};
short yylen[] = {                                         2,
    2,    1,    0,    1,    3,    3,    3,    3,    1,    1,
    1,    1,    3,    1,    3,    3,    1,    3,    1,    1,
    2,    1,    1,    1,    3,    3,    1,    1,    1,    2,
    3,    2,    2,    2,    2,    2,    2,    3,    1,    3,
    3,    1,    1,    0,    1,    1,    3,    3,    3,    3,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    2,
    2,    2,    2,    4,    1,    1,    2,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    4,    6,    3,    3,
    3,    3,    3,    3,    3,    3,    2,    3,    1,    1,
    1,    1,    1,    1,    1,    3,
};
short yydefred[] = {                                      3,
    0,    0,    0,    0,    0,   57,   58,   56,   59,   60,
   61,   62,   63,   64,   65,   66,   67,   68,   69,   71,
   70,  115,   85,   86,   55,  109,   72,   73,   74,   75,
    0,   76,   77,   78,   79,   22,    0,   23,    0,    4,
   29,    0,    0,    0,   96,    0,   95,    0,    0,   42,
   82,   83,    0,   87,    0,  107,    0,    0,   10,    9,
    0,    0,   14,   20,    0,    0,   37,   11,   12,    0,
    0,    0,    0,   51,   54,   52,   53,   34,   35,   80,
   81,    0,   33,   36,   90,   92,   94,    0,    0,    0,
    0,    0,    0,    0,    0,   89,   91,   93,    0,    0,
    0,    0,    0,    0,   30,  111,  110,  113,  114,  112,
    0,    0,    0,    6,    5,    0,    0,    0,    8,    7,
    0,    0,    0,   24,    0,    0,    0,   21,    0,    0,
    0,    0,   31,    0,    0,    0,    0,    0,    0,  101,
  102,    0,    0,    0,   38,  108,  116,   84,    0,   16,
   15,   18,   13,    0,    0,   48,   50,   47,   49,   97,
    0,   25,   26,    0,   98,
};
short yydgoto[] = {                                       1,
  102,  128,   68,  125,   40,   41,  126,   42,   43,   82,
   83,   84,   44,   45,  111,   57,   47,   99,  100,   61,
   62,   58,   71,    2,   50,
};
short yysindex[] = {                                      0,
    0,  180, -256, -250, -240,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  -40,    0,    0,    0,    0,    0,  251,    0, -286,    0,
    0,  209,  -31,  526,    0,  -41,    0,  180,  180,    0,
    0,    0,  110,    0,  -40,    0,  -41,  251,    0,    0,
  134,  134,    0,    0,  -45,    6,    0,    0,    0,  209,
  209, -270, -252,    0,    0,    0,    0,    0,    0,    0,
    0, -254,    0,    0,    0,    0,    0,  251,  251,  251,
  251,  251,  251,  251,  251,    0,    0,    0,  251,  251,
  251,  -38,   14,   25,    0,    0,    0,    0,    0,    0,
 -219,   25,  -24,    0,    0,    0,  134,  134,    0,    0,
 -218, -207, -194,    0,   64, -286,   25,    0, -148, -134,
 -130, -129,    0,  -15,  -15,  -30,  121,   -9,   -9,    0,
    0,  -24,  -24,  579,    0,    0,    0,    0,   25,    0,
    0,    0,    0,  209,  209,    0,    0,    0,    0,    0,
 -157,    0,    0,   39,    0,
};
short yyrindex[] = {                                      0,
    0,   20,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   29,    0,    0,    0,    0,    0,    0,    0,  133,    0,
    0,    0,    0,    0,    0,    4,    0,  441,  441,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  441,  441,    0,    0,   65,   82,    0,    0,    0,    0,
    0,  213,  283,    0,    0,    0,    0,    0,    0,    0,
    0,  298,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  558,  568,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    1,  441,  441,    0,    0,
    0,    0,    0,    0, -203,    0, -195,    0,    0,    0,
    0,    0,    0,   26,   51,   60,   76,   11,   36,    0,
    0,   85,   90,    0,    0,    0,    0,    0,  452,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
  137,   41,  -60,    0,  -27,    0,    0,    0,    0,    0,
   58,    0,  596,  -42,    0,   93,  605,    0,    0,   17,
   21,  600,   97,    0,    0,
};
#define YYTABLESIZE 878
short yytable[] = {                                      38,
   12,  122,  145,   39,   74,  103,   76,   91,   77,  124,
   99,   94,   92,   91,   93,  103,   95,   94,   92,    2,
   93,  105,   95,   59,   60,  105,   94,   92,   88,   93,
   51,   95,   94,  115,  120,  100,   52,   95,   95,  129,
  130,   12,   95,   95,   39,   95,   53,   95,   99,  101,
  106,   99,  123,   99,  146,   99,  124,  131,  132,  104,
   95,   95,   95,  105,   17,  147,  105,  148,   99,   88,
   99,   99,   99,  100,  103,  103,  100,  150,  100,  151,
  100,   19,   67,  105,   40,  105,  105,  105,  106,   41,
  105,  106,  152,  100,   46,  100,  100,  100,   49,   90,
  104,  114,  119,   99,  153,   17,   28,   28,  106,  156,
  106,  106,  106,  103,   27,   27,  103,  104,  105,  104,
  104,  104,   19,  157,   95,   40,  158,  159,  100,  164,
   41,  165,    1,  103,   99,  103,  103,  103,   39,  133,
   46,   46,  154,  106,   49,   49,  155,  107,    0,  105,
    0,    0,  104,   46,   46,    0,    0,  118,  118,  100,
    0,    0,   94,   92,    0,   93,   36,   95,  103,  110,
  109,  108,    0,   38,  106,    0,    0,    0,   37,    0,
    0,    0,    0,  104,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  162,  163,    0,    0,    0,  103,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   46,
   46,    0,   36,  118,  118,    0,  121,    0,    0,   38,
    0,    0,    0,    0,   37,   72,   73,   74,   75,   76,
    0,   77,    0,  106,   78,   79,    0,    0,    0,    0,
    0,   36,    0,    0,    0,   46,   22,    0,   38,    0,
    0,    0,   46,   80,   81,    0,    0,    0,    0,    0,
   43,   43,   43,   43,   43,    0,   43,   88,   89,   43,
   43,   59,   60,   88,   89,    0,   44,   44,   44,   44,
   44,    0,   44,    0,    0,   44,   44,    0,   43,   43,
   38,   95,   95,   95,    0,   37,    0,    0,   95,   95,
    0,   99,   99,   99,   44,   44,    0,    0,   99,   99,
   12,   12,    0,   39,   39,   45,  105,  105,  105,    0,
   99,   99,   45,  105,  105,    0,  100,  100,  100,    0,
   32,    0,    0,  100,  100,  105,  105,   32,   88,   88,
    0,  106,  106,  106,    0,  100,  100,    0,  106,  106,
  104,  104,  104,    0,    0,    0,    0,    0,    0,    0,
  106,  106,    0,    0,    0,    0,  103,  103,  103,  104,
  104,    0,    0,    0,   17,   17,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  103,  103,    0,    0,    0,
    0,   19,   19,    0,   40,   40,    0,    3,    4,   41,
   41,    5,    6,    7,    8,    9,   10,   11,   12,   13,
   14,   15,   16,   17,   18,   19,   20,   21,   88,   89,
   22,   23,   24,   25,    0,    0,    0,   63,   64,   65,
   66,    0,    0,   26,   27,   28,   29,   30,   31,   32,
   33,   34,   35,    3,    4,    0,    0,    5,    6,    7,
    8,    9,   10,   11,   12,   13,   14,   15,   16,   17,
   18,   19,   20,   21,    0,    0,   22,   23,   24,   25,
    0,   46,    0,   46,    0,   46,    0,    0,    0,   26,
   27,   28,   29,   30,   31,   32,   33,   34,   35,   95,
    0,    0,    0,   95,   95,   22,   95,    0,   95,   46,
    0,    0,   63,   64,   65,   66,   46,   46,   46,   46,
    0,   95,   95,   95,    0,    0,    0,    0,    0,    6,
    7,    8,    9,   10,   11,   12,   13,   14,   15,   16,
   17,   18,   19,   20,   21,    0,    0,   22,    0,    0,
   25,   45,    0,   45,    0,   45,    0,    0,    0,    0,
   26,   27,   28,   29,   30,    0,   32,   33,   34,   35,
    0,    0,    0,   91,    0,    0,    0,   94,   92,   45,
   93,    0,   95,    0,    0,   95,   45,   45,   45,   45,
    0,    0,    0,    0,   32,   98,   97,   96,    0,    0,
    0,   32,   32,   32,   32,   96,    0,    0,    0,   96,
   96,   48,   96,    0,   96,   95,    0,    0,    0,   95,
   95,    0,   95,    0,   95,    0,   91,   96,   96,   96,
   94,   92,    0,   93,    0,   95,    0,   95,   95,   95,
   55,    0,   56,    0,    0,   54,  161,    0,    0,    0,
    0,   70,    0,    0,    0,    0,   69,   48,   48,   90,
    0,    0,  104,  113,   55,    0,    0,    0,    0,  112,
  117,  117,  104,    0,    0,  116,  116,    0,    0,   55,
   70,  160,    0,    0,  127,   69,    0,    0,    0,    0,
    0,   96,    0,  134,  135,  136,  137,  138,  139,  140,
  141,   95,    0,    0,  142,  143,  144,   44,   44,   44,
   44,   44,   90,   44,    0,    0,   44,   44,    0,    0,
    0,    0,    0,    0,    0,    0,   48,  117,    0,    0,
    0,  149,  116,    0,    0,   44,   44,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   95,   95,   95,    0,    0,    0,    0,   95,
   95,    0,    0,   70,   70,    0,    0,    0,   69,   69,
    0,   27,   27,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   85,   86,   87,    0,
    0,    0,    0,   88,   89,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   96,   96,
   96,    0,    0,    0,    0,   96,   96,    0,   95,   95,
   95,    0,    0,    0,    0,   95,   95,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   88,   89,
};
short yycheck[] = {                                      40,
    0,   47,   41,    0,  259,   48,  261,   38,  263,   70,
    0,   42,   43,   38,   45,   58,   47,   42,   43,    0,
   45,   49,   47,  310,  311,    0,   42,   43,    0,   45,
  287,   47,   42,   61,   62,    0,  287,   47,   38,  310,
  311,   41,   42,   43,   41,   45,  287,   47,   38,   91,
    0,   41,   47,   43,   41,   45,  117,  310,  311,    0,
   60,   61,   62,   38,    0,   41,   41,  287,   58,   41,
   60,   61,   62,   38,  117,    0,   41,  296,   43,  287,
   45,    0,   42,   58,    0,   60,   61,   62,   38,    0,
  118,   41,  287,   58,    2,   60,   61,   62,    2,  124,
   41,   61,   62,   93,   41,   41,  310,  311,   58,  258,
   60,   61,   62,   38,  310,  311,   41,   58,   93,   60,
   61,   62,   41,  258,  124,   41,  257,  257,   93,  287,
   41,   93,    0,   58,  124,   60,   61,   62,    2,   82,
   48,   49,  126,   93,   48,   49,  126,   38,   -1,  124,
   -1,   -1,   93,   61,   62,   -1,   -1,   61,   62,  124,
   -1,   -1,   42,   43,   -1,   45,   33,   47,   93,   60,
   61,   62,   -1,   40,  124,   -1,   -1,   -1,   45,   -1,
   -1,   -1,   -1,  124,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  154,  155,   -1,   -1,   -1,  124,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  117,
  118,   -1,   33,  117,  118,   -1,  262,   -1,   -1,   40,
   -1,   -1,   -1,   -1,   45,  257,  258,  259,  260,  261,
   -1,  263,   -1,  124,  266,  267,   -1,   -1,   -1,   -1,
   -1,   33,   -1,   -1,   -1,   33,  287,   -1,   40,   -1,
   -1,   -1,   40,  285,  286,   -1,   -1,   -1,   -1,   -1,
  257,  258,  259,  260,  261,   -1,  263,  298,  299,  266,
  267,  310,  311,  298,  299,   -1,  257,  258,  259,  260,
  261,   -1,  263,   -1,   -1,  266,  267,   -1,  285,  286,
   40,  291,  292,  293,   -1,   45,   -1,   -1,  298,  299,
   -1,  291,  292,  293,  285,  286,   -1,   -1,  298,  299,
  310,  311,   -1,  310,  311,   33,  291,  292,  293,   -1,
  310,  311,   40,  298,  299,   -1,  291,  292,  293,   -1,
   33,   -1,   -1,  298,  299,  310,  311,   40,  310,  311,
   -1,  291,  292,  293,   -1,  310,  311,   -1,  298,  299,
  291,  292,  293,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  310,  311,   -1,   -1,   -1,   -1,  291,  292,  293,  310,
  311,   -1,   -1,   -1,  310,  311,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  310,  311,   -1,   -1,   -1,
   -1,  310,  311,   -1,  310,  311,   -1,  264,  265,  310,
  311,  268,  269,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,  298,  299,
  287,  288,  289,  290,   -1,   -1,   -1,  294,  295,  296,
  297,   -1,   -1,  300,  301,  302,  303,  304,  305,  306,
  307,  308,  309,  264,  265,   -1,   -1,  268,  269,  270,
  271,  272,  273,  274,  275,  276,  277,  278,  279,  280,
  281,  282,  283,  284,   -1,   -1,  287,  288,  289,  290,
   -1,  259,   -1,  261,   -1,  263,   -1,   -1,   -1,  300,
  301,  302,  303,  304,  305,  306,  307,  308,  309,   38,
   -1,   -1,   -1,   42,   43,  287,   45,   -1,   47,  287,
   -1,   -1,  294,  295,  296,  297,  294,  295,  296,  297,
   -1,   60,   61,   62,   -1,   -1,   -1,   -1,   -1,  269,
  270,  271,  272,  273,  274,  275,  276,  277,  278,  279,
  280,  281,  282,  283,  284,   -1,   -1,  287,   -1,   -1,
  290,  259,   -1,  261,   -1,  263,   -1,   -1,   -1,   -1,
  300,  301,  302,  303,  304,   -1,  306,  307,  308,  309,
   -1,   -1,   -1,   38,   -1,   -1,   -1,   42,   43,  287,
   45,   -1,   47,   -1,   -1,  124,  294,  295,  296,  297,
   -1,   -1,   -1,   -1,  287,   60,   61,   62,   -1,   -1,
   -1,  294,  295,  296,  297,   38,   -1,   -1,   -1,   42,
   43,    2,   45,   -1,   47,   38,   -1,   -1,   -1,   42,
   43,   -1,   45,   -1,   47,   -1,   38,   60,   61,   62,
   42,   43,   -1,   45,   -1,   47,   -1,   60,   61,   62,
   31,   -1,   37,   -1,   -1,   31,   58,   -1,   -1,   -1,
   -1,   42,   -1,   -1,   -1,   -1,   42,   48,   49,  124,
   -1,   -1,   48,   58,   55,   -1,   -1,   -1,   -1,   55,
   61,   62,   58,   -1,   -1,   61,   62,   -1,   -1,   70,
   71,   93,   -1,   -1,   70,   71,   -1,   -1,   -1,   -1,
   -1,  124,   -1,   88,   89,   90,   91,   92,   93,   94,
   95,  124,   -1,   -1,   99,  100,  101,  257,  258,  259,
  260,  261,  124,  263,   -1,   -1,  266,  267,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  117,  118,   -1,   -1,
   -1,  117,  118,   -1,   -1,  285,  286,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  291,  292,  293,   -1,   -1,   -1,   -1,  298,
  299,   -1,   -1,  154,  155,   -1,   -1,   -1,  154,  155,
   -1,  310,  311,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  291,  292,  293,   -1,
   -1,   -1,   -1,  298,  299,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  291,  292,
  293,   -1,   -1,   -1,   -1,  298,  299,   -1,  291,  292,
  293,   -1,   -1,   -1,   -1,  298,  299,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  298,  299,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 312
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,"'&'",0,"'('","')'","'*'","'+'",0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,
0,"':'",0,"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'['",0,"']'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'|'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"DST","SRC","HOST","GATEWAY","NET","MASK","PORT",
"LESS","GREATER","PROTO","PROTOCHAIN","BYTE","ARP","RARP","IP","TCP","UDP",
"ICMP","IGMP","IGRP","PIM","ATALK","AARP","DECNET","LAT","SCA","MOPRC","MOPDL",
"TK_BROADCAST","TK_MULTICAST","NUM","INBOUND","OUTBOUND","LINK","GEQ","LEQ",
"NEQ","ID","EID","HID","HID6","LSH","RSH","LEN","IPV6","ICMPV6","AH","ESP",
"VLAN","ISO","ESIS","ISIS","CLNP","OR","AND","UMINUS",
};
char *yyrule[] = {
"$accept : prog",
"prog : null expr",
"prog : null",
"null :",
"expr : term",
"expr : expr and term",
"expr : expr and id",
"expr : expr or term",
"expr : expr or id",
"and : AND",
"or : OR",
"id : nid",
"id : pnum",
"id : paren pid ')'",
"nid : ID",
"nid : HID '/' NUM",
"nid : HID MASK HID",
"nid : HID",
"nid : HID6 '/' NUM",
"nid : HID6",
"nid : EID",
"nid : not id",
"not : '!'",
"paren : '('",
"pid : nid",
"pid : qid and id",
"pid : qid or id",
"qid : pnum",
"qid : pid",
"term : rterm",
"term : not term",
"head : pqual dqual aqual",
"head : pqual dqual",
"head : pqual aqual",
"head : pqual PROTO",
"head : pqual PROTOCHAIN",
"head : pqual ndaqual",
"rterm : head id",
"rterm : paren expr ')'",
"rterm : pname",
"rterm : arth relop arth",
"rterm : arth irelop arth",
"rterm : other",
"pqual : pname",
"pqual :",
"dqual : SRC",
"dqual : DST",
"dqual : SRC OR DST",
"dqual : DST OR SRC",
"dqual : SRC AND DST",
"dqual : DST AND SRC",
"aqual : HOST",
"aqual : NET",
"aqual : PORT",
"ndaqual : GATEWAY",
"pname : LINK",
"pname : IP",
"pname : ARP",
"pname : RARP",
"pname : TCP",
"pname : UDP",
"pname : ICMP",
"pname : IGMP",
"pname : IGRP",
"pname : PIM",
"pname : ATALK",
"pname : AARP",
"pname : DECNET",
"pname : LAT",
"pname : SCA",
"pname : MOPDL",
"pname : MOPRC",
"pname : IPV6",
"pname : ICMPV6",
"pname : AH",
"pname : ESP",
"pname : ISO",
"pname : ESIS",
"pname : ISIS",
"pname : CLNP",
"other : pqual TK_BROADCAST",
"other : pqual TK_MULTICAST",
"other : LESS NUM",
"other : GREATER NUM",
"other : BYTE NUM byteop NUM",
"other : INBOUND",
"other : OUTBOUND",
"other : VLAN pnum",
"other : VLAN",
"relop : '>'",
"relop : GEQ",
"relop : '='",
"irelop : LEQ",
"irelop : '<'",
"irelop : NEQ",
"arth : pnum",
"arth : narth",
"narth : pname '[' arth ']'",
"narth : pname '[' arth ':' NUM ']'",
"narth : arth '+' arth",
"narth : arth '-' arth",
"narth : arth '*' arth",
"narth : arth '/' arth",
"narth : arth '&' arth",
"narth : arth '|' arth",
"narth : arth LSH arth",
"narth : arth RSH arth",
"narth : '-' arth",
"narth : paren narth ')'",
"narth : LEN",
"byteop : '&'",
"byteop : '|'",
"byteop : '<'",
"byteop : '>'",
"byteop : '='",
"pnum : NUM",
"pnum : paren pnum ')'",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH 500
#endif
#endif
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short yyss[YYSTACKSIZE];
YYSTYPE yyvs[YYSTACKSIZE];
#define yystacksize YYSTACKSIZE
#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse()
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register char *yys;
    extern char *getenv();

    if (yys = getenv("YYDEBUG"))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if (yyn = yydefred[yystate]) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yyss + yystacksize - 1)
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#ifdef lint
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#ifdef lint
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yyss + yystacksize - 1)
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 137 "grammar.y"
{
	finish_parse(yyvsp[0].blk.b);
}
break;
case 3:
#line 142 "grammar.y"
{ yyval.blk.q = qerr; }
break;
case 5:
#line 145 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 6:
#line 146 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 7:
#line 147 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 8:
#line 148 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 9:
#line 150 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 10:
#line 152 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 12:
#line 155 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 13:
#line 157 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 14:
#line 159 "grammar.y"
{ yyval.blk.b = gen_scode(yyvsp[0].s, yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 15:
#line 160 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, NULL, yyvsp[0].i,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 16:
#line 162 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, yyvsp[0].s, 0,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 17:
#line 164 "grammar.y"
{
				  /* Decide how to parse HID based on proto */
				  yyval.blk.q = yyvsp[-1].blk.q;
				  yyval.blk.b = gen_ncode(yyvsp[0].s, 0, yyval.blk.q);
				}
break;
case 18:
#line 169 "grammar.y"
{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yyvsp[-2].s, NULL, yyvsp[0].i,
				    yyval.blk.q = yyvsp[-3].blk.q);
#else
				  bpf_error("'ip6addr/prefixlen' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 19:
#line 178 "grammar.y"
{
#ifdef INET6
				  yyval.blk.b = gen_mcode6(yyvsp[0].s, 0, 128,
				    yyval.blk.q = yyvsp[-1].blk.q);
#else
				  bpf_error("'ip6addr' not supported "
					"in this configuration");
#endif /*INET6*/
				}
break;
case 20:
#line 187 "grammar.y"
{ yyval.blk.b = gen_ecode(yyvsp[0].e, yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 21:
#line 188 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 22:
#line 190 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 23:
#line 192 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 25:
#line 195 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 26:
#line 196 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 27:
#line 198 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 30:
#line 203 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 31:
#line 205 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-2].i, yyvsp[-1].i, yyvsp[0].i); }
break;
case 32:
#line 206 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, yyvsp[0].i, Q_DEFAULT); }
break;
case 33:
#line 207 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 34:
#line 208 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTO); }
break;
case 35:
#line 209 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTOCHAIN); }
break;
case 36:
#line 210 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 37:
#line 212 "grammar.y"
{ yyval.blk = yyvsp[0].blk; }
break;
case 38:
#line 213 "grammar.y"
{ yyval.blk.b = yyvsp[-1].blk.b; yyval.blk.q = yyvsp[-2].blk.q; }
break;
case 39:
#line 214 "grammar.y"
{ yyval.blk.b = gen_proto_abbrev(yyvsp[0].i); yyval.blk.q = qerr; }
break;
case 40:
#line 215 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 0);
				  yyval.blk.q = qerr; }
break;
case 41:
#line 217 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 1);
				  yyval.blk.q = qerr; }
break;
case 42:
#line 219 "grammar.y"
{ yyval.blk.b = yyvsp[0].rblk; yyval.blk.q = qerr; }
break;
case 44:
#line 223 "grammar.y"
{ yyval.i = Q_DEFAULT; }
break;
case 45:
#line 226 "grammar.y"
{ yyval.i = Q_SRC; }
break;
case 46:
#line 227 "grammar.y"
{ yyval.i = Q_DST; }
break;
case 47:
#line 228 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 48:
#line 229 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 49:
#line 230 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 50:
#line 231 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 51:
#line 234 "grammar.y"
{ yyval.i = Q_HOST; }
break;
case 52:
#line 235 "grammar.y"
{ yyval.i = Q_NET; }
break;
case 53:
#line 236 "grammar.y"
{ yyval.i = Q_PORT; }
break;
case 54:
#line 239 "grammar.y"
{ yyval.i = Q_GATEWAY; }
break;
case 55:
#line 241 "grammar.y"
{ yyval.i = Q_LINK; }
break;
case 56:
#line 242 "grammar.y"
{ yyval.i = Q_IP; }
break;
case 57:
#line 243 "grammar.y"
{ yyval.i = Q_ARP; }
break;
case 58:
#line 244 "grammar.y"
{ yyval.i = Q_RARP; }
break;
case 59:
#line 245 "grammar.y"
{ yyval.i = Q_TCP; }
break;
case 60:
#line 246 "grammar.y"
{ yyval.i = Q_UDP; }
break;
case 61:
#line 247 "grammar.y"
{ yyval.i = Q_ICMP; }
break;
case 62:
#line 248 "grammar.y"
{ yyval.i = Q_IGMP; }
break;
case 63:
#line 249 "grammar.y"
{ yyval.i = Q_IGRP; }
break;
case 64:
#line 250 "grammar.y"
{ yyval.i = Q_PIM; }
break;
case 65:
#line 251 "grammar.y"
{ yyval.i = Q_ATALK; }
break;
case 66:
#line 252 "grammar.y"
{ yyval.i = Q_AARP; }
break;
case 67:
#line 253 "grammar.y"
{ yyval.i = Q_DECNET; }
break;
case 68:
#line 254 "grammar.y"
{ yyval.i = Q_LAT; }
break;
case 69:
#line 255 "grammar.y"
{ yyval.i = Q_SCA; }
break;
case 70:
#line 256 "grammar.y"
{ yyval.i = Q_MOPDL; }
break;
case 71:
#line 257 "grammar.y"
{ yyval.i = Q_MOPRC; }
break;
case 72:
#line 258 "grammar.y"
{ yyval.i = Q_IPV6; }
break;
case 73:
#line 259 "grammar.y"
{ yyval.i = Q_ICMPV6; }
break;
case 74:
#line 260 "grammar.y"
{ yyval.i = Q_AH; }
break;
case 75:
#line 261 "grammar.y"
{ yyval.i = Q_ESP; }
break;
case 76:
#line 262 "grammar.y"
{ yyval.i = Q_ISO; }
break;
case 77:
#line 263 "grammar.y"
{ yyval.i = Q_ESIS; }
break;
case 78:
#line 264 "grammar.y"
{ yyval.i = Q_ISIS; }
break;
case 79:
#line 265 "grammar.y"
{ yyval.i = Q_CLNP; }
break;
case 80:
#line 267 "grammar.y"
{ yyval.rblk = gen_broadcast(yyvsp[-1].i); }
break;
case 81:
#line 268 "grammar.y"
{ yyval.rblk = gen_multicast(yyvsp[-1].i); }
break;
case 82:
#line 269 "grammar.y"
{ yyval.rblk = gen_less(yyvsp[0].i); }
break;
case 83:
#line 270 "grammar.y"
{ yyval.rblk = gen_greater(yyvsp[0].i); }
break;
case 84:
#line 271 "grammar.y"
{ yyval.rblk = gen_byteop(yyvsp[-1].i, yyvsp[-2].i, yyvsp[0].i); }
break;
case 85:
#line 272 "grammar.y"
{ yyval.rblk = gen_inbound(0); }
break;
case 86:
#line 273 "grammar.y"
{ yyval.rblk = gen_inbound(1); }
break;
case 87:
#line 274 "grammar.y"
{ yyval.rblk = gen_vlan(yyvsp[0].i); }
break;
case 88:
#line 275 "grammar.y"
{ yyval.rblk = gen_vlan(-1); }
break;
case 89:
#line 277 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 90:
#line 278 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 91:
#line 279 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 92:
#line 281 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 93:
#line 282 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 94:
#line 283 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 95:
#line 285 "grammar.y"
{ yyval.a = gen_loadi(yyvsp[0].i); }
break;
case 97:
#line 288 "grammar.y"
{ yyval.a = gen_load(yyvsp[-3].i, yyvsp[-1].a, 1); }
break;
case 98:
#line 289 "grammar.y"
{ yyval.a = gen_load(yyvsp[-5].i, yyvsp[-3].a, yyvsp[-1].i); }
break;
case 99:
#line 290 "grammar.y"
{ yyval.a = gen_arth(BPF_ADD, yyvsp[-2].a, yyvsp[0].a); }
break;
case 100:
#line 291 "grammar.y"
{ yyval.a = gen_arth(BPF_SUB, yyvsp[-2].a, yyvsp[0].a); }
break;
case 101:
#line 292 "grammar.y"
{ yyval.a = gen_arth(BPF_MUL, yyvsp[-2].a, yyvsp[0].a); }
break;
case 102:
#line 293 "grammar.y"
{ yyval.a = gen_arth(BPF_DIV, yyvsp[-2].a, yyvsp[0].a); }
break;
case 103:
#line 294 "grammar.y"
{ yyval.a = gen_arth(BPF_AND, yyvsp[-2].a, yyvsp[0].a); }
break;
case 104:
#line 295 "grammar.y"
{ yyval.a = gen_arth(BPF_OR, yyvsp[-2].a, yyvsp[0].a); }
break;
case 105:
#line 296 "grammar.y"
{ yyval.a = gen_arth(BPF_LSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 106:
#line 297 "grammar.y"
{ yyval.a = gen_arth(BPF_RSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 107:
#line 298 "grammar.y"
{ yyval.a = gen_neg(yyvsp[0].a); }
break;
case 108:
#line 299 "grammar.y"
{ yyval.a = yyvsp[-1].a; }
break;
case 109:
#line 300 "grammar.y"
{ yyval.a = gen_loadlen(); }
break;
case 110:
#line 302 "grammar.y"
{ yyval.i = '&'; }
break;
case 111:
#line 303 "grammar.y"
{ yyval.i = '|'; }
break;
case 112:
#line 304 "grammar.y"
{ yyval.i = '<'; }
break;
case 113:
#line 305 "grammar.y"
{ yyval.i = '>'; }
break;
case 114:
#line 306 "grammar.y"
{ yyval.i = '='; }
break;
case 116:
#line 309 "grammar.y"
{ yyval.i = yyvsp[-1].i; }
break;
#line 1201 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yyss + yystacksize - 1)
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
