
/***************************************************************************
 * global_structures.h -- Common structure definitions used by Nmap        *
 * components.                                                             *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *  The Nmap Security Scanner is (C) 1995-2002 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***************************************************************************/

/* $Id$ */


#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

class TargetGroup;
class Target;

/* Stores "port info" which is TCP/UDP ports or RPC program ids */
struct portinfo {
   unsigned long portno; /* TCP/UDP port or RPC program id or IP protocool */
   short trynum;
   int sd[3]; /* Socket descriptors for connect_scan */
   struct timeval sent[3]; 
   int state;
   int next; /* not struct portinfo * for historical reasons */
   int prev;
};

struct portinfolist {
   struct portinfo *openlist;
   struct portinfo *firewalled;
   struct portinfo *testinglist;
};

struct udpprobeinfo {
  u16 iptl;
  u16 ipid;
  u16 ipck;
  u16 sport;
  u16 dport;
  u16 udpck;
  u16 udplen;
  u8 patternbyte;
  struct in_addr target;
};

struct connectsockinfo {
  fd_set fds_read;
  fd_set fds_write;
  fd_set fds_except;
  struct portinfo *socklookup[2048]; /* index socket descriptor -> scan[] 
					index.  No OS better give us
					an SD > 2047!@#$ */
  int maxsd;
};

struct firewallmodeinfo {
  int active; /* is firewall mode currently active for the host? */
  int nonresponsive_ports; /* # Of ports we haven't received any response from */
  int responsive_ports; /* # of ports that told us whether they were open/closed/filtered/unfiltered */
};

/* The runtime statistics used to decide how fast to proced and how
   many ports we can try at once */
struct scanstats {
  int packet_incr;
  int initial_packet_width; /* Number of queries in parallel we should 
			       start with */
  double fallback_percent;
  int numqueries_outstanding; /* How many unexpired queries are on the 'net
				 right now? */
  double numqueries_ideal; /* How many do we WANT to be on the 'net right now? */
  int max_width; /* What is the MOST we will tolerate at once.  Can be 
		    modified via --max_parallelism */
  int min_width; /* We must always allow at least this many at once.  Can 
		    be modified via --min_parallelism*/
  int ports_left;
  int changed; /* Has anything changed since last round? */
  int alreadydecreasedqueries;
};

struct ftpinfo {
  char user[64];
  char pass[256]; /* methinks you're paranoid if you need this much space */
  char server_name[MAXHOSTNAMELEN + 1];
  struct in_addr server;
  u16 port;
  int sd; /* socket descriptor */
};

struct AVal {
  char *attribute;
  char value[128];
  struct AVal *next;
};

struct OS_Classification {
  char *OS_Vendor;
  char *OS_Family;
  char *OS_Generation; /* Can be NULL if unclassified */
  char *Device_Type;
};

#define MAX_OS_CLASSIFICATIONS_PER_FP 8
typedef struct FingerTest {
  char *OS_name;
  struct OS_Classification OS_class[MAX_OS_CLASSIFICATIONS_PER_FP];
  int num_OS_Classifications;
  int line; /* For reference prints, the line # in nmap-os-fingerprints */
  const char *name;
  struct AVal *results;
  struct FingerTest *next;
 } FingerPrint;

struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

struct seq_info {
  int responses;
  int seqclass; /* SEQ_* defines in nmap.h */
  int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
  time_t uptime; /* time of latest system boot (or 0 if unknown ) */
  int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
  u32 seqs[NUM_SEQ_SAMPLES];
  u32 timestamps[NUM_SEQ_SAMPLES];
  int index;
  u16 ipids[NUM_SEQ_SAMPLES];
  time_t lastboot; /* 0 means unknown */
};

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
	unsigned short *tcp_ports;
	int tcp_count;
	unsigned short *udp_ports;
	int udp_count;
	unsigned short *prots;
	int prot_count;
};


typedef enum { ACK_SCAN, SYN_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN, CONNECT_SCAN, NULL_SCAN, WINDOW_SCAN, RPC_SCAN, MAIMON_SCAN, IPPROT_SCAN } stype;

#endif /*GLOBAL_STRUCTURES_H */
