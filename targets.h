
/***************************************************************************
 * targets.h -- Functions relating to "ping scanning" as well as           *
 * determining the exact IPs to hit based on CIDR and other input formats. * 
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
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

#ifndef TARGETS_H
#define TARGETS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif /* WIN32 */
#endif /* HAVE_CONFIG_H */

/* This contains pretty much everythign we need ... */
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_PARAM_H   
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif

#include "nmap.h"
#include "global_structures.h"

class HostGroupState;

/**************************STRUCTURES******************************/
struct pingtune {
  int up_this_block;
  int down_this_block;
  int block_tries;
  int block_unaccounted;
  int max_tries;
  int num_responses;
  int dropthistry;
  double group_size;
  int min_group_size; /* The group size must never go below this value */
  int group_start;
  int group_end;
  u16 seq_offset; // For distinguishing between received packets from this 
                  // execution vs. concurrent nmaps
};

struct tcpqueryinfo {
  int *sockets[MAX_PROBE_PORTS];
  int maxsd;
  fd_set fds_r;
  fd_set fds_w;
  fd_set fds_x;
  int sockets_out;
};

struct pingtech {
  unsigned int icmpscan: 1,
    rawicmpscan: 1,
    connecttcpscan: 1,
    rawtcpscan: 1,
    rawudpscan: 1;
};


int get_ping_results(int sd, pcap_t *pd, Target *hostbatch[], 
		     int pingtype, struct timeval *time,  struct pingtune *pt,
		     struct timeout_info *to, int id, struct pingtech *ptech, 
		     struct scan_lists *ports);
int sendpingqueries(int sd, int rawsd, Target *target,  
		  u16 seq, unsigned short id, struct scanstats *ss, 
		  struct timeval *time, int pingtype, struct pingtech ptech);
int sendpingquery(int sd, int rawsd, Target *target,  
		  u16 seq, unsigned short id, struct scanstats *ss, 
		  struct timeval *time, int pingtype, struct pingtech ptech);
int sendrawtcpudppingqueries(int rawsd, Target *target, int pingtype,
			  u16 seq, struct timeval *time, struct pingtune *pt);
int sendrawtcppingquery(int rawsd, Target *target, int pingtype, u16 probe_port,
			u16 seq, struct timeval *time, struct pingtune *pt);
int sendrawudppingquery(int rawsd, Target *target, u16 probe_port,
			u16 seq, struct timeval *time, struct pingtune *pt);
int sendconnecttcpqueries(Target *hostbatch[], struct tcpqueryinfo *tqi, Target *target,
			  u16 seq, struct timeval *time, struct pingtune *pt, struct timeout_info *to, int max_sockets);
int sendconnecttcpquery(Target *hostbatch[], struct tcpqueryinfo *tqi, Target *target, int probe_port_num,
			u16 seq, struct timeval *time, struct pingtune *pt, struct timeout_info *to, int max_sockets);
int get_connecttcpscan_results(struct tcpqueryinfo *tqi, 
			       Target *hostbatch[], 
			       struct timeval *time, struct pingtune *pt, 
			       struct timeout_info *to);
char *readhoststate(int state);
void massping(Target *hostbatch[], int numhosts, 
		struct scan_lists *ports, int pingtype);
void hoststructfry(Target *hostbatch[], int nelem);
/* Ports is the list of ports the user asked to be scanned (0 terminated),
   you can just pass NULL (it is only a stupid optimization that needs it) */
Target *nexthost(HostGroupState *hs, struct scan_lists *ports, int *pingtype);
#endif /* TARGETS_H */










