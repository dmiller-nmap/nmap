#ifndef lint
static char const 
yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28 2000/01/17 02:04:06 bde Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
static int yygrowstack();
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
#line 113 "y.tab.c"
#define YYERRCODE 256
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
#define SCTP 272
#define TCP 273
#define UDP 274
#define ICMP 275
#define IGMP 276
#define IGRP 277
#define PIM 278
#define VRRP 279
#define ATALK 280
#define AARP 281
#define DECNET 282
#define LAT 283
#define SCA 284
#define MOPRC 285
#define MOPDL 286
#define TK_BROADCAST 287
#define TK_MULTICAST 288
#define NUM 289
#define INBOUND 290
#define OUTBOUND 291
#define LINK 292
#define GEQ 293
#define LEQ 294
#define NEQ 295
#define ID 296
#define EID 297
#define HID 298
#define HID6 299
#define AID 300
#define LSH 301
#define RSH 302
#define LEN 303
#define IPV6 304
#define ICMPV6 305
#define AH 306
#define ESP 307
#define VLAN 308
#define ISO 309
#define ESIS 310
#define ISIS 311
#define CLNP 312
#define STP 313
#define IPX 314
#define NETBEUI 315
#define OR 316
#define AND 317
#define UMINUS 318
const short yylhs[] = {                                        -1,
    0,    0,   24,    1,    1,    1,    1,    1,   20,   21,
    2,    2,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    3,   23,   22,    4,    4,    4,    7,    7,    5,
    5,    8,    8,    8,    8,    8,    8,    6,    6,    6,
    6,    6,    6,    9,    9,   10,   10,   10,   10,   10,
   10,   11,   11,   11,   12,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   25,   25,   25,   25,   25,
   25,   25,   25,   25,   18,   18,   18,   19,   19,   19,
   13,   13,   14,   14,   14,   14,   14,   14,   14,   14,
   14,   14,   14,   14,   14,   15,   15,   15,   15,   15,
   17,   17,
};
const short yylen[] = {                                         2,
    2,    1,    0,    1,    3,    3,    3,    3,    1,    1,
    1,    1,    3,    1,    3,    3,    1,    3,    1,    1,
    1,    2,    1,    1,    1,    3,    3,    1,    1,    1,
    2,    3,    2,    2,    2,    2,    2,    2,    3,    1,
    3,    3,    1,    1,    0,    1,    1,    3,    3,    3,
    3,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    2,    2,    2,    2,    4,
    1,    1,    2,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    4,    6,    3,    3,    3,    3,    3,    3,
    3,    3,    2,    3,    1,    1,    1,    1,    1,    1,
    1,    3,
};
const short yydefred[] = {                                      3,
    0,    0,    0,    0,    0,   58,   59,   57,   60,   61,
   62,   63,   64,   65,   66,   67,   68,   69,   70,   71,
   72,   74,   73,  121,   91,   92,   56,  115,   75,   76,
   77,   78,    0,   79,   80,   81,   82,   83,   84,   85,
   23,    0,   24,    0,    4,   30,    0,    0,    0,  102,
    0,  101,    0,    0,   43,   88,   89,    0,   93,    0,
  113,    0,    0,   10,    9,    0,    0,   14,   20,    0,
    0,   21,   38,   11,   12,    0,    0,    0,    0,   52,
   55,   53,   54,   35,   36,   86,   87,    0,   34,   37,
   96,   98,  100,    0,    0,    0,    0,    0,    0,    0,
    0,   95,   97,   99,    0,    0,    0,    0,    0,    0,
   31,  117,  116,  119,  120,  118,    0,    0,    0,    6,
    5,    0,    0,    0,    8,    7,    0,    0,    0,   25,
    0,    0,    0,   22,    0,    0,    0,    0,   32,    0,
    0,    0,    0,    0,    0,  107,  108,    0,    0,    0,
   39,  114,  122,   90,    0,   16,   15,   18,   13,    0,
    0,   49,   51,   48,   50,  103,    0,   26,   27,    0,
  104,
};
const short yydgoto[] = {                                       1,
  108,  134,   74,  131,   45,   46,  132,   47,   48,   88,
   89,   90,   49,   50,  117,   62,   52,  105,  106,   66,
   67,   63,   77,    2,   55,
};
const short yysindex[] = {                                      0,
    0,  192, -284, -282, -268,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -38,    0,    0,    0,    0,    0,    0,    0,
    0,  244,    0, -279,    0,    0,  190,  -71,  543,    0,
  -68,    0,  192,  192,    0,    0,    0,   95,    0,  -38,
    0,  -68,  244,    0,    0,  140,  140,    0,    0,  -44,
  -21,    0,    0,    0,    0,  190,  190, -276, -251,    0,
    0,    0,    0,    0,    0,    0,    0, -160,    0,    0,
    0,    0,    0,  244,  244,  244,  244,  244,  244,  244,
  244,    0,    0,    0,  244,  244,  244,  -41,  -13,   10,
    0,    0,    0,    0,    0,    0, -234,   10,  191,    0,
    0,    0,  140,  140,    0,    0, -240, -229, -211,    0,
   39, -279,   10,    0, -165, -163, -155, -151,    0,  -12,
  -12,  -28,  207,  -34,  -34,    0,    0,  191,  191,  551,
    0,    0,    0,    0,   10,    0,    0,    0,    0,  190,
  190,    0,    0,    0,    0,    0, -174,    0,    0,   23,
    0,
};
const short yyrindex[] = {                                      0,
    0,   20,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    9,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  118,    0,    0,    0,    0,    0,    0,
    4,    0,  421,  421,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  421,  421,    0,    0,   16,
   18,    0,    0,    0,    0,    0,    0,  276,  321,    0,
    0,    0,    0,    0,    0,    0,    0,  326,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  569,  590,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,  421,  421,    0,    0,    0,    0,    0,    0,
 -206,    0, -204,    0,    0,    0,    0,    0,    0,   47,
   76,   86,   29,   11,   36,    0,    0,   27,   34,    0,
    0,    0,    0,    0,   81,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,
};
const short yygindex[] = {                                      0,
  119,   17,  -70,    0,  -42,    0,    0,    0,    0,    0,
   32,    0,  600,  -31,    0,  174,  594,    0,    0,   -2,
    7,   98,  478,    0,    0,
};
#define YYTABLESIZE 892
const short yytable[] = {                                     151,
   12,   43,  128,   40,   56,  130,   57,  100,   94,   97,
  105,  111,  101,  100,   98,   17,   99,   19,  101,    2,
   58,  109,  107,  121,  126,  129,   41,  152,  109,  100,
   98,  109,   99,   42,  101,  106,   64,   65,  101,  135,
  136,   12,  101,  101,   40,  101,  111,  101,  105,   94,
  153,  105,  130,  105,  154,  105,   17,  156,   19,  157,
  101,  101,  101,   73,  137,  138,  109,   41,  105,  109,
  105,  105,  105,  106,   42,  112,  106,  158,  106,  159,
  106,  111,  120,  125,  111,  110,  109,  111,  109,  109,
  109,  109,  162,  106,  163,  106,  106,  106,   80,   53,
   82,  164,   83,  105,  111,  165,  111,  111,  111,   29,
   29,   28,   28,  112,  170,  171,  112,    1,  101,  139,
   44,  109,  101,  101,  101,  101,  110,  101,  106,  160,
   60,    0,  113,  112,  105,  112,  112,  112,  161,  111,
  101,  101,  101,  110,   76,  110,  110,  110,    0,    0,
   53,   53,  109,    0,  116,  115,  114,   60,    0,  106,
    0,    0,    0,  123,  123,    0,    0,    0,  112,    0,
  111,    0,   41,   60,   76,   51,  168,  169,  110,   43,
    0,    0,    0,    0,   42,   78,   79,   80,   81,   82,
    0,   83,    0,    0,   84,   85,    0,    0,    0,  112,
    0,    0,    0,    0,  101,    0,    0,    0,    0,  110,
    0,    0,    0,    0,    0,   86,   87,  127,  112,    0,
   53,  123,   41,    0,   41,    0,   51,   51,   97,   43,
    0,   43,  100,   98,    0,   99,   42,  101,    0,   51,
   51,    0,    0,    0,    0,    0,    0,    0,  100,   98,
   24,   99,    0,  101,    0,    0,    0,   76,   76,    0,
   44,   44,   44,   44,   44,    0,   44,    0,    0,   44,
   44,    0,   94,   95,   64,   65,   45,   45,   45,   45,
   45,    0,   45,   43,    0,   45,   45,    0,   42,    0,
   44,   44,    0,  101,  101,  101,   51,   51,    0,    0,
    0,  101,  101,  105,  105,  105,   45,   45,   47,    0,
    0,  105,  105,    0,   96,   47,   12,   12,    0,   40,
   40,  109,  109,  109,   94,   94,  105,  105,  106,  106,
  106,   17,   17,   19,   19,    0,  106,  106,    0,  111,
  111,  111,   41,   41,  109,  109,    0,  111,  111,   42,
   42,  106,  106,   46,    0,    0,    0,    0,   33,    0,
   46,    0,  111,  111,    0,   33,    0,    0,  112,  112,
  112,    0,    0,  101,  101,  101,  112,  112,  110,  110,
  110,  101,  101,    0,    0,    0,    0,    0,    0,    0,
    0,  112,  112,    0,    0,    0,   28,   28,    0,    0,
    0,  110,  110,    3,    4,    0,    0,    5,    6,    7,
    8,    9,   10,   11,   12,   13,   14,   15,   16,   17,
   18,   19,   20,   21,   22,   23,    0,    0,   24,   25,
   26,   27,    0,    0,    0,   68,   69,   70,   71,   72,
    0,    0,   28,   29,   30,   31,   32,   33,   34,   35,
   36,   37,   38,   39,   40,    3,    4,    0,    0,    5,
    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,
   16,   17,   18,   19,   20,   21,   22,   23,   24,   54,
   24,   25,   26,   27,    0,   68,   69,   70,   71,   72,
    0,   94,   95,    0,   28,   29,   30,   31,   32,   33,
   34,   35,   36,   37,   38,   39,   40,   94,   95,    0,
    0,    0,    6,    7,    8,    9,   10,   11,   12,   13,
   14,   15,   16,   17,   18,   19,   20,   21,   22,   23,
   54,   54,   24,    0,   47,   27,   47,    0,   47,    0,
    0,    0,    0,  124,  124,    0,   28,   29,   30,   31,
   32,    0,   34,   35,   36,   37,   38,   39,   40,    0,
    0,    0,    0,    0,   47,    0,    0,    0,    0,    0,
    0,   47,   47,   47,   47,   47,    0,    0,    0,   46,
   97,   46,    0,   46,  100,   98,    0,   99,   97,  101,
    0,    0,  100,   98,    0,   99,    0,  101,    0,    0,
  124,  124,  104,  103,  102,    0,  102,    0,  167,   46,
  102,  102,    0,  102,   33,  102,   46,   46,   46,   46,
   46,   33,   33,   33,   33,   33,   59,  101,  102,  102,
  102,  101,  101,    0,  101,    0,  101,    0,    0,    0,
   75,   61,    0,  166,    0,    0,  110,    0,    0,  101,
  101,  101,    0,  118,    0,    0,  110,    0,    0,  122,
  122,    0,  119,    0,    0,    0,   96,    0,    0,  133,
   75,    0,    0,    0,   96,    0,    0,   45,   45,   45,
   45,   45,    0,   45,    0,    0,   45,   45,    0,    0,
    0,    0,  102,  140,  141,  142,  143,  144,  145,  146,
  147,    0,    0,    0,  148,  149,  150,   45,   45,    0,
    0,    0,    0,  101,    0,    0,  155,  122,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   75,   75,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   91,   92,   93,    0,    0,
    0,    0,    0,   94,   95,    0,    0,    0,    0,    0,
    0,   94,   95,    0,    0,    0,    0,    0,    0,    0,
    0,  102,  102,  102,    0,    0,    0,    0,    0,  102,
  102,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  101,  101,  101,    0,    0,    0,    0,    0,
  101,  101,
};
const short yycheck[] = {                                      41,
    0,   40,   47,    0,  289,   76,  289,   42,    0,   38,
    0,   54,   47,   42,   43,    0,   45,    0,   47,    0,
  289,   53,   91,   66,   67,   47,    0,   41,    0,   42,
   43,   63,   45,    0,   47,    0,  316,  317,   38,  316,
  317,   41,   42,   43,   41,   45,    0,   47,   38,   41,
   41,   41,  123,   43,  289,   45,   41,  298,   41,  289,
   60,   61,   62,   47,  316,  317,   38,   41,   58,   41,
   60,   61,   62,   38,   41,    0,   41,  289,   43,   41,
   45,  124,   66,   67,   38,    0,   58,   41,   60,   61,
   62,  123,  258,   58,  258,   60,   61,   62,  259,    2,
  261,  257,  263,   93,   58,  257,   60,   61,   62,  316,
  317,  316,  317,   38,  289,   93,   41,    0,   38,   88,
    2,   93,   42,   43,  124,   45,   41,   47,   93,  132,
   33,   -1,   38,   58,  124,   60,   61,   62,  132,   93,
   60,   61,   62,   58,   47,   60,   61,   62,   -1,   -1,
   53,   54,  124,   -1,   60,   61,   62,   60,   -1,  124,
   -1,   -1,   -1,   66,   67,   -1,   -1,   -1,   93,   -1,
  124,   -1,   33,   76,   77,    2,  160,  161,   93,   40,
   -1,   -1,   -1,   -1,   45,  257,  258,  259,  260,  261,
   -1,  263,   -1,   -1,  266,  267,   -1,   -1,   -1,  124,
   -1,   -1,   -1,   -1,  124,   -1,   -1,   -1,   -1,  124,
   -1,   -1,   -1,   -1,   -1,  287,  288,  262,  124,   -1,
  123,  124,   33,   -1,   33,   -1,   53,   54,   38,   40,
   -1,   40,   42,   43,   -1,   45,   45,   47,   -1,   66,
   67,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   42,   43,
  289,   45,   -1,   47,   -1,   -1,   -1,  160,  161,   -1,
  257,  258,  259,  260,  261,   -1,  263,   -1,   -1,  266,
  267,   -1,  301,  302,  316,  317,  257,  258,  259,  260,
  261,   -1,  263,   40,   -1,  266,  267,   -1,   45,   -1,
  287,  288,   -1,  293,  294,  295,  123,  124,   -1,   -1,
   -1,  301,  302,  293,  294,  295,  287,  288,   33,   -1,
   -1,  301,  302,   -1,  124,   40,  316,  317,   -1,  316,
  317,  293,  294,  295,  316,  317,  316,  317,  293,  294,
  295,  316,  317,  316,  317,   -1,  301,  302,   -1,  293,
  294,  295,  316,  317,  316,  317,   -1,  301,  302,  316,
  317,  316,  317,   33,   -1,   -1,   -1,   -1,   33,   -1,
   40,   -1,  316,  317,   -1,   40,   -1,   -1,  293,  294,
  295,   -1,   -1,  293,  294,  295,  301,  302,  293,  294,
  295,  301,  302,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  316,  317,   -1,   -1,   -1,  316,  317,   -1,   -1,
   -1,  316,  317,  264,  265,   -1,   -1,  268,  269,  270,
  271,  272,  273,  274,  275,  276,  277,  278,  279,  280,
  281,  282,  283,  284,  285,  286,   -1,   -1,  289,  290,
  291,  292,   -1,   -1,   -1,  296,  297,  298,  299,  300,
   -1,   -1,  303,  304,  305,  306,  307,  308,  309,  310,
  311,  312,  313,  314,  315,  264,  265,   -1,   -1,  268,
  269,  270,  271,  272,  273,  274,  275,  276,  277,  278,
  279,  280,  281,  282,  283,  284,  285,  286,  289,    2,
  289,  290,  291,  292,   -1,  296,  297,  298,  299,  300,
   -1,  301,  302,   -1,  303,  304,  305,  306,  307,  308,
  309,  310,  311,  312,  313,  314,  315,  301,  302,   -1,
   -1,   -1,  269,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,  285,  286,
   53,   54,  289,   -1,  259,  292,  261,   -1,  263,   -1,
   -1,   -1,   -1,   66,   67,   -1,  303,  304,  305,  306,
  307,   -1,  309,  310,  311,  312,  313,  314,  315,   -1,
   -1,   -1,   -1,   -1,  289,   -1,   -1,   -1,   -1,   -1,
   -1,  296,  297,  298,  299,  300,   -1,   -1,   -1,  259,
   38,  261,   -1,  263,   42,   43,   -1,   45,   38,   47,
   -1,   -1,   42,   43,   -1,   45,   -1,   47,   -1,   -1,
  123,  124,   60,   61,   62,   -1,   38,   -1,   58,  289,
   42,   43,   -1,   45,  289,   47,  296,  297,  298,  299,
  300,  296,  297,  298,  299,  300,   33,   38,   60,   61,
   62,   42,   43,   -1,   45,   -1,   47,   -1,   -1,   -1,
   47,   42,   -1,   93,   -1,   -1,   53,   -1,   -1,   60,
   61,   62,   -1,   60,   -1,   -1,   63,   -1,   -1,   66,
   67,   -1,   63,   -1,   -1,   -1,  124,   -1,   -1,   76,
   77,   -1,   -1,   -1,  124,   -1,   -1,  257,  258,  259,
  260,  261,   -1,  263,   -1,   -1,  266,  267,   -1,   -1,
   -1,   -1,  124,   94,   95,   96,   97,   98,   99,  100,
  101,   -1,   -1,   -1,  105,  106,  107,  287,  288,   -1,
   -1,   -1,   -1,  124,   -1,   -1,  123,  124,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  160,  161,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  293,  294,  295,   -1,   -1,
   -1,   -1,   -1,  301,  302,   -1,   -1,   -1,   -1,   -1,
   -1,  301,  302,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  293,  294,  295,   -1,   -1,   -1,   -1,   -1,  301,
  302,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  293,  294,  295,   -1,   -1,   -1,   -1,   -1,
  301,  302,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 318
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,"'&'",0,"'('","')'","'*'","'+'",0,"'-'",0,"'/'",0,0,0,0,0,0,0,0,0,
0,"':'",0,"'<'","'='","'>'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'['",0,"']'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'|'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"DST","SRC","HOST","GATEWAY","NET","MASK","PORT",
"LESS","GREATER","PROTO","PROTOCHAIN","BYTE","ARP","RARP","IP","SCTP","TCP",
"UDP","ICMP","IGMP","IGRP","PIM","VRRP","ATALK","AARP","DECNET","LAT","SCA",
"MOPRC","MOPDL","TK_BROADCAST","TK_MULTICAST","NUM","INBOUND","OUTBOUND","LINK",
"GEQ","LEQ","NEQ","ID","EID","HID","HID6","AID","LSH","RSH","LEN","IPV6",
"ICMPV6","AH","ESP","VLAN","ISO","ESIS","ISIS","CLNP","STP","IPX","NETBEUI",
"OR","AND","UMINUS",
};
const char * const yyrule[] = {
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
"nid : AID",
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
"pname : SCTP",
"pname : TCP",
"pname : UDP",
"pname : ICMP",
"pname : IGMP",
"pname : IGRP",
"pname : PIM",
"pname : VRRP",
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
"pname : STP",
"pname : IPX",
"pname : NETBEUI",
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
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
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
        if (yyssp >= yysslim && yygrowstack())
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
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
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
                if (yyssp >= yysslim && yygrowstack())
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
#line 141 "grammar.y"
{
	finish_parse(yyvsp[0].blk.b);
}
break;
case 3:
#line 146 "grammar.y"
{ yyval.blk.q = qerr; }
break;
case 5:
#line 149 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 6:
#line 150 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 7:
#line 151 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 8:
#line 152 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 9:
#line 154 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 10:
#line 156 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 12:
#line 159 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 13:
#line 161 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 14:
#line 163 "grammar.y"
{ yyval.blk.b = gen_scode(yyvsp[0].s, yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 15:
#line 164 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, NULL, yyvsp[0].i,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 16:
#line 166 "grammar.y"
{ yyval.blk.b = gen_mcode(yyvsp[-2].s, yyvsp[0].s, 0,
				    yyval.blk.q = yyvsp[-3].blk.q); }
break;
case 17:
#line 168 "grammar.y"
{
				  /* Decide how to parse HID based on proto */
				  yyval.blk.q = yyvsp[-1].blk.q;
				  yyval.blk.b = gen_ncode(yyvsp[0].s, 0, yyval.blk.q);
				}
break;
case 18:
#line 173 "grammar.y"
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
#line 182 "grammar.y"
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
#line 191 "grammar.y"
{ 
				  yyval.blk.b = gen_ecode(yyvsp[0].e, yyval.blk.q = yyvsp[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yyvsp[0].e);
				}
break;
case 21:
#line 200 "grammar.y"
{
				  yyval.blk.b = gen_acode(yyvsp[0].e, yyval.blk.q = yyvsp[-1].blk.q);
				  /*
				   * $1 was allocated by "pcap_ether_aton()",
				   * so we must free it now that we're done
				   * with it.
				   */
				  free(yyvsp[0].e);
				}
break;
case 22:
#line 209 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 23:
#line 211 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 24:
#line 213 "grammar.y"
{ yyval.blk = yyvsp[-1].blk; }
break;
case 26:
#line 216 "grammar.y"
{ gen_and(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 27:
#line 217 "grammar.y"
{ gen_or(yyvsp[-2].blk.b, yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 28:
#line 219 "grammar.y"
{ yyval.blk.b = gen_ncode(NULL, (bpf_u_int32)yyvsp[0].i,
						   yyval.blk.q = yyvsp[-1].blk.q); }
break;
case 31:
#line 224 "grammar.y"
{ gen_not(yyvsp[0].blk.b); yyval.blk = yyvsp[0].blk; }
break;
case 32:
#line 226 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-2].i, yyvsp[-1].i, yyvsp[0].i); }
break;
case 33:
#line 227 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, yyvsp[0].i, Q_DEFAULT); }
break;
case 34:
#line 228 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 35:
#line 229 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTO); }
break;
case 36:
#line 230 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, Q_PROTOCHAIN); }
break;
case 37:
#line 231 "grammar.y"
{ QSET(yyval.blk.q, yyvsp[-1].i, Q_DEFAULT, yyvsp[0].i); }
break;
case 38:
#line 233 "grammar.y"
{ yyval.blk = yyvsp[0].blk; }
break;
case 39:
#line 234 "grammar.y"
{ yyval.blk.b = yyvsp[-1].blk.b; yyval.blk.q = yyvsp[-2].blk.q; }
break;
case 40:
#line 235 "grammar.y"
{ yyval.blk.b = gen_proto_abbrev(yyvsp[0].i); yyval.blk.q = qerr; }
break;
case 41:
#line 236 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 0);
				  yyval.blk.q = qerr; }
break;
case 42:
#line 238 "grammar.y"
{ yyval.blk.b = gen_relation(yyvsp[-1].i, yyvsp[-2].a, yyvsp[0].a, 1);
				  yyval.blk.q = qerr; }
break;
case 43:
#line 240 "grammar.y"
{ yyval.blk.b = yyvsp[0].rblk; yyval.blk.q = qerr; }
break;
case 45:
#line 244 "grammar.y"
{ yyval.i = Q_DEFAULT; }
break;
case 46:
#line 247 "grammar.y"
{ yyval.i = Q_SRC; }
break;
case 47:
#line 248 "grammar.y"
{ yyval.i = Q_DST; }
break;
case 48:
#line 249 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 49:
#line 250 "grammar.y"
{ yyval.i = Q_OR; }
break;
case 50:
#line 251 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 51:
#line 252 "grammar.y"
{ yyval.i = Q_AND; }
break;
case 52:
#line 255 "grammar.y"
{ yyval.i = Q_HOST; }
break;
case 53:
#line 256 "grammar.y"
{ yyval.i = Q_NET; }
break;
case 54:
#line 257 "grammar.y"
{ yyval.i = Q_PORT; }
break;
case 55:
#line 260 "grammar.y"
{ yyval.i = Q_GATEWAY; }
break;
case 56:
#line 262 "grammar.y"
{ yyval.i = Q_LINK; }
break;
case 57:
#line 263 "grammar.y"
{ yyval.i = Q_IP; }
break;
case 58:
#line 264 "grammar.y"
{ yyval.i = Q_ARP; }
break;
case 59:
#line 265 "grammar.y"
{ yyval.i = Q_RARP; }
break;
case 60:
#line 266 "grammar.y"
{ yyval.i = Q_SCTP; }
break;
case 61:
#line 267 "grammar.y"
{ yyval.i = Q_TCP; }
break;
case 62:
#line 268 "grammar.y"
{ yyval.i = Q_UDP; }
break;
case 63:
#line 269 "grammar.y"
{ yyval.i = Q_ICMP; }
break;
case 64:
#line 270 "grammar.y"
{ yyval.i = Q_IGMP; }
break;
case 65:
#line 271 "grammar.y"
{ yyval.i = Q_IGRP; }
break;
case 66:
#line 272 "grammar.y"
{ yyval.i = Q_PIM; }
break;
case 67:
#line 273 "grammar.y"
{ yyval.i = Q_VRRP; }
break;
case 68:
#line 274 "grammar.y"
{ yyval.i = Q_ATALK; }
break;
case 69:
#line 275 "grammar.y"
{ yyval.i = Q_AARP; }
break;
case 70:
#line 276 "grammar.y"
{ yyval.i = Q_DECNET; }
break;
case 71:
#line 277 "grammar.y"
{ yyval.i = Q_LAT; }
break;
case 72:
#line 278 "grammar.y"
{ yyval.i = Q_SCA; }
break;
case 73:
#line 279 "grammar.y"
{ yyval.i = Q_MOPDL; }
break;
case 74:
#line 280 "grammar.y"
{ yyval.i = Q_MOPRC; }
break;
case 75:
#line 281 "grammar.y"
{ yyval.i = Q_IPV6; }
break;
case 76:
#line 282 "grammar.y"
{ yyval.i = Q_ICMPV6; }
break;
case 77:
#line 283 "grammar.y"
{ yyval.i = Q_AH; }
break;
case 78:
#line 284 "grammar.y"
{ yyval.i = Q_ESP; }
break;
case 79:
#line 285 "grammar.y"
{ yyval.i = Q_ISO; }
break;
case 80:
#line 286 "grammar.y"
{ yyval.i = Q_ESIS; }
break;
case 81:
#line 287 "grammar.y"
{ yyval.i = Q_ISIS; }
break;
case 82:
#line 288 "grammar.y"
{ yyval.i = Q_CLNP; }
break;
case 83:
#line 289 "grammar.y"
{ yyval.i = Q_STP; }
break;
case 84:
#line 290 "grammar.y"
{ yyval.i = Q_IPX; }
break;
case 85:
#line 291 "grammar.y"
{ yyval.i = Q_NETBEUI; }
break;
case 86:
#line 293 "grammar.y"
{ yyval.rblk = gen_broadcast(yyvsp[-1].i); }
break;
case 87:
#line 294 "grammar.y"
{ yyval.rblk = gen_multicast(yyvsp[-1].i); }
break;
case 88:
#line 295 "grammar.y"
{ yyval.rblk = gen_less(yyvsp[0].i); }
break;
case 89:
#line 296 "grammar.y"
{ yyval.rblk = gen_greater(yyvsp[0].i); }
break;
case 90:
#line 297 "grammar.y"
{ yyval.rblk = gen_byteop(yyvsp[-1].i, yyvsp[-2].i, yyvsp[0].i); }
break;
case 91:
#line 298 "grammar.y"
{ yyval.rblk = gen_inbound(0); }
break;
case 92:
#line 299 "grammar.y"
{ yyval.rblk = gen_inbound(1); }
break;
case 93:
#line 300 "grammar.y"
{ yyval.rblk = gen_vlan(yyvsp[0].i); }
break;
case 94:
#line 301 "grammar.y"
{ yyval.rblk = gen_vlan(-1); }
break;
case 95:
#line 303 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 96:
#line 304 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 97:
#line 305 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 98:
#line 307 "grammar.y"
{ yyval.i = BPF_JGT; }
break;
case 99:
#line 308 "grammar.y"
{ yyval.i = BPF_JGE; }
break;
case 100:
#line 309 "grammar.y"
{ yyval.i = BPF_JEQ; }
break;
case 101:
#line 311 "grammar.y"
{ yyval.a = gen_loadi(yyvsp[0].i); }
break;
case 103:
#line 314 "grammar.y"
{ yyval.a = gen_load(yyvsp[-3].i, yyvsp[-1].a, 1); }
break;
case 104:
#line 315 "grammar.y"
{ yyval.a = gen_load(yyvsp[-5].i, yyvsp[-3].a, yyvsp[-1].i); }
break;
case 105:
#line 316 "grammar.y"
{ yyval.a = gen_arth(BPF_ADD, yyvsp[-2].a, yyvsp[0].a); }
break;
case 106:
#line 317 "grammar.y"
{ yyval.a = gen_arth(BPF_SUB, yyvsp[-2].a, yyvsp[0].a); }
break;
case 107:
#line 318 "grammar.y"
{ yyval.a = gen_arth(BPF_MUL, yyvsp[-2].a, yyvsp[0].a); }
break;
case 108:
#line 319 "grammar.y"
{ yyval.a = gen_arth(BPF_DIV, yyvsp[-2].a, yyvsp[0].a); }
break;
case 109:
#line 320 "grammar.y"
{ yyval.a = gen_arth(BPF_AND, yyvsp[-2].a, yyvsp[0].a); }
break;
case 110:
#line 321 "grammar.y"
{ yyval.a = gen_arth(BPF_OR, yyvsp[-2].a, yyvsp[0].a); }
break;
case 111:
#line 322 "grammar.y"
{ yyval.a = gen_arth(BPF_LSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 112:
#line 323 "grammar.y"
{ yyval.a = gen_arth(BPF_RSH, yyvsp[-2].a, yyvsp[0].a); }
break;
case 113:
#line 324 "grammar.y"
{ yyval.a = gen_neg(yyvsp[0].a); }
break;
case 114:
#line 325 "grammar.y"
{ yyval.a = yyvsp[-1].a; }
break;
case 115:
#line 326 "grammar.y"
{ yyval.a = gen_loadlen(); }
break;
case 116:
#line 328 "grammar.y"
{ yyval.i = '&'; }
break;
case 117:
#line 329 "grammar.y"
{ yyval.i = '|'; }
break;
case 118:
#line 330 "grammar.y"
{ yyval.i = '<'; }
break;
case 119:
#line 331 "grammar.y"
{ yyval.i = '>'; }
break;
case 120:
#line 332 "grammar.y"
{ yyval.i = '='; }
break;
case 122:
#line 335 "grammar.y"
{ yyval.i = yyvsp[-1].i; }
break;
#line 1327 "y.tab.c"
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
    if (yyssp >= yysslim && yygrowstack())
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
