/*
 * Copyright (c) 1999, 2000
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 * Portions Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 * The Regents of the University of California.  All rights reserved.
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
*/

#ifndef lib_pcap_h
#define lib_pcap_h

#include <sys/types.h>
#ifdef WIN32
#include <sys/timeb.h>
#include <time.h>
#else
#include <sys/time.h>
#endif

#include <net/bpf.h>

#include <stdio.h>

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define PCAP_ERRBUF_SIZE 256

/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 */
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (DLT_*) */
};

/*
 * Each packet in the dump file is prepended with this generic header.
 * This gets around the problem of different headers for different
 * packet interfaces.
 */
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

/*
 * As returned by the pcap_stats()
 */
struct pcap_stat {
	u_int ps_recv;		/* number of packets received */
	u_int ps_drop;		/* number of packets dropped */
	u_int ps_ifdrop;	/* drops by interface XXX not yet supported */
};

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
			     const u_char *);

/*
 * working modes
 */
#define MODE_CAPT 0
#define MODE_STAT 1


extern "C" int pcap_setmode(pcap_t *p, int mode, int interval);
extern "C" int pcap_setbuff(pcap_t *p, int dim);
extern "C" char* pcap_lookupdev(char *);
extern "C" int	pcap_lookupnet(char *, bpf_u_int32 *, bpf_u_int32 *, char *);
extern "C" pcap_t	*pcap_open_live(char *, int, int, int, char *);
extern "C" pcap_t	*pcap_open_offline(const char *, char *);
extern "C" void	pcap_close(pcap_t *);
extern "C" int	pcap_loop(pcap_t *, int, pcap_handler, u_char *);
extern "C" int	pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
extern "C" const u_char*
pcap_next(pcap_t *, struct pcap_pkthdr *);
extern "C" int	pcap_stats(pcap_t *, struct pcap_stat *);
extern "C" int	pcap_setfilter(pcap_t *, struct bpf_program *);
extern "C" void	pcap_perror(pcap_t *, char *);
extern "C" char	*pcap_strerror(int);
extern "C" char	*pcap_geterr(pcap_t *);
extern "C" int	pcap_compile(pcap_t *, struct bpf_program *, char *, int,
	    bpf_u_int32);
/* XXX */
extern "C" int	pcap_freecode(pcap_t *, struct bpf_program *);
extern "C" int	pcap_datalink(pcap_t *);
extern "C" int	pcap_snapshot(pcap_t *);
extern "C" int	pcap_is_swapped(pcap_t *);
extern "C" int	pcap_major_version(pcap_t *);
extern "C" int	pcap_minor_version(pcap_t *);

/* XXX */
extern "C" FILE	*pcap_file(pcap_t *);
extern "C" int	pcap_fileno(pcap_t *);

extern "C" pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
extern "C" void	pcap_dump_close(pcap_dumper_t *);
extern "C" void	pcap_dump(u_char *, const struct pcap_pkthdr *, const u_char *);

/* XXX this guy lives in the bpf tree */
extern "C" u_int	bpf_filter(struct bpf_insn *, u_char *, u_int, u_int);
extern "C" char	*bpf_image(struct bpf_insn *, int);
#endif
