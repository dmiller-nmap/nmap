
/***********************************************************************/
/* idle_scan.c -- Includes the function specific to "Idle Scan"        */
/* support (-sI).  This is an extraordinarily cool scan type that      */
/* can allow for completely blind scanning (eg no packets sent to the  */
/* target from your own IP address) and can also be used to penetrate  */
/* firewalls and scope out router ACLs.  This is one of the "advanced" */
/* scans meant for epxerienced Nmap users.                             */
/*                                                                     */
/***********************************************************************/
/*  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  */
/*  program is free software; you can redistribute it and/or modify    */
/*  it under the terms of the GNU General Public License as published  */
/*  by the Free Software Foundation; Version 2.  This guarantees your  */
/*  right to use, modify, and redistribute this software under certain */
/*  conditions.  If this license is unacceptable to you, we may be     */
/*  willing to sell alternative licenses (contact sales@insecure.com). */
/*                                                                     */
/*  If you received these files with a written license agreement       */
/*  stating terms other than the (GPL) terms above, then that          */
/*  alternative license agreement takes precendence over this comment. */
/*                                                                     */
/*  Source is provided to this software because we believe users have  */
/*  a right to know exactly what a program is going to do before they  */
/*  run it.  This also allows you to audit the software for security   */
/*  holes (none have been found so far).                               */
/*                                                                     */
/*  Source code also allows you to port Nmap to new platforms, fix     */
/*  bugs, and add new features.  You are highly encouraged to send     */
/*  your changes to fyodor@insecure.org for possible incorporation     */
/*  into the main distribution.  By sending these changes to Fyodor or */
/*  one the insecure.org development mailing lists, it is assumed that */
/*  you are offering Fyodor the unlimited, non-exclusive right to      */
/*  reuse, modify, and relicense the code.  This is important because  */
/*  the inability to relicense code has caused devastating problems    */
/*  for other Free Software projects (such as KDE and NASM).  Nmap     */
/*  will always be available Open Source.  If you wish to specify      */
/*  special license conditions of your contributions, just say so      */
/*  when you send them.                                                */
/*                                                                     */
/*  This program is distributed in the hope that it will be useful,    */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of     */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  */
/*  General Public License for more details (                          */
/*  http://www.gnu.org/copyleft/gpl.html ).                            */
/*                                                                     */
/***********************************************************************/

/* $Id$ */

#include "idle_scan.h"
#include "scan_engine.h"
#include "timing.h"
#include "osscan.h"
#include "nmap.h"

#include <stdio.h>

extern struct ops o;

/*  predefined filters -- I need to kill these globals at some pont. */
extern unsigned long flt_dsthost, flt_srchost, flt_baseport;


struct idle_proxy_info {
  struct hoststruct host; /* contains name, IP, source IP, timing info, etc. */
  int seqclass; /* IPID sequence class (IPID_SEQ_* defined in nmap.h) */
  u16 latestid; /* The most recent IPID we have received from the proxy */
  u16 probe_port; /* The port we use for probing IPID infoz */
};

/* takes a proxy name/IP, resolves it if neccessary, tests it for IPID
   suitability, and fills out an idle_proxy_info structure.  If the
   proxy is determined to be unsuitable, the function whines and exits
   the program */
#define NUM_IPID_PROBES 6
void initialize_idleproxy(struct idle_proxy_info *proxy, char *proxyName) {
  int probes_sent = 0, probes_returned = 0;
  int hardtimeout = 9000000; /* Generally don't wait more than 9 secs total */
  int bytes, to_usec;
  int timedout = 0;
  char *p, *q;
  char *endptr = NULL;
  int rawsd;
  int seq_response_num;
  char *dev;
  pcap_t *pd;
  int i;
  char filter[512]; /* Libpcap filter string */
  char name[MAXHOSTNAMELEN + 1];
  u32 sequence_base;
  struct timeval probe_send_times[NUM_IPID_PROBES], tmptv;
  u16 lastipid;
  struct ip *ip;
  struct tcphdr *tcp;
  u16 ipids[NUM_IPID_PROBES]; 
  u8 probe_returned[NUM_IPID_PROBES];
  assert(proxy);
  assert(proxyName);

  for(i=0; i < NUM_IPID_PROBES; i++) probe_returned[i] = 0;

  Strncpy(name, proxyName, sizeof(name));
  q = strchr(name, ':');
  if (q) {
    *q++ = '\0';
    proxy->probe_port = strtoul(q, &endptr, 10);
    if (*q || !endptr || *endptr != '\0' || !proxy->probe_port) {
      fatal("Invalid port number given in IPID proxy specification: %s", proxyName);
    }
  } else proxy->probe_port = o.tcp_probe_port;

  proxy->host.name = strdup(name);

  if (resolve(proxyName, &(proxy->host.host)) == 0) {
    fatal("Could not resolve idlescan proxy host: %s", proxyName);
  }

  /* Lets figure out the appropriate source address to use when sending
     the pr0bez */
  if (o.source->s_addr) {
    proxy->host.source_ip.s_addr = o.source->s_addr;
    Strncpy(proxy->host.device, o.device, sizeof(proxy->host.device));
  } else {
    dev = routethrough(&(proxy->host.host), &(proxy->host.source_ip));  
    if (!dev) fatal("Unable to find appropriate source address and device interface to use when sending packets to %s", proxyName);
    Strncpy(proxy->host.device, dev, sizeof(proxy->host.device));
  }
  /* Now lets send some probes to check IPID algorithm ... */
  /* First we need a raw socket ... */
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in get_fingerprint");
  unblock_socket(rawsd);
  broadcast_socket(rawsd);


/* Now for the pcap opening nonsense ... */
 /* Note that the snaplen is 152 = 64 byte max IPhdr + 24 byte max link_layer
  * header + 64 byte max TCP header. */
  pd = my_pcap_open_live(proxy->host.device, 152,  (o.spoofsource)? 1 : 0, 50);

  p = strdup(inet_ntoa(proxy->host.host));
  q = strdup(inet_ntoa(proxy->host.source_ip));
  snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s and src port %hi", p, q, proxy->probe_port);
 free(p); 
 free(q);
 set_pcap_filter(&(proxy->host), pd, flt_icmptcp, filter);
/* Windows nonsense -- I am not sure why this is needed, but I should
   get rid of it at sometime */

 flt_srchost = proxy->host.source_ip.s_addr;
 flt_dsthost = proxy->host.host.s_addr;

 sequence_base = get_random_u32();

 /* Yahoo!  It is finally time to send our pr0beZ! */

  while(probes_sent < NUM_IPID_PROBES) {
    if (o.scan_delay) enforce_scan_delay(NULL);
    else if (probes_sent) usleep(30000);
    send_tcp_raw_decoys(rawsd, &(proxy->host.host), 
			o.magic_port + probes_sent + 1, proxy->probe_port, 
			sequence_base + probes_sent + 1, 0, TH_SYN|TH_ACK, 0, 
			NULL, 0, NULL, 0);
    gettimeofday(&probe_send_times[probes_sent], NULL);
    probes_sent++;

    /* Time to collect any replies */
    while(probes_returned < probes_sent && !timedout) {

      to_usec = (probes_sent == NUM_IPID_PROBES)? hardtimeout : 1000;
      ip = (struct ip *) readip_pcap(pd, &bytes, to_usec);

      gettimeofday(&tmptv, NULL);

      if (!ip) {
	if (probes_sent < NUM_IPID_PROBES)
	  break;
	if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >= hardtimeout) {
	  timedout = 1;
	}
	continue;
      } else if (TIMEVAL_SUBTRACT(tmptv, probe_send_times[probes_sent - 1]) >=
		 hardtimeout)  {      
	timedout = 1;
      }

      if (lastipid != 0 && ip->ip_id == lastipid) {
	continue; /* probably a duplicate */
      }
      lastipid = ip->ip_id;

      if (bytes < ( 4 * ip->ip_hl) + 4U)
	continue;

      if (ip->ip_p == IPPROTO_TCP) {
	/*       readtcppacket((char *) ip, ntohs(ip->ip_len));  */
	tcp = ((struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl));
	if (ntohs(tcp->th_dport) < o.magic_port || ntohs(tcp->th_dport) - o.magic_port > NUM_IPID_PROBES  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
	  if (o.debugging > 1) error("Received unexpected response packet from %s during initial ipid proxy testing", inet_ntoa(proxy->host.host));
	  continue;
	}
	
	seq_response_num = (ntohl(tcp->th_ack) - 2 - sequence_base);
	if (seq_response_num < 0 || seq_response_num >= probes_sent) {
	  if (o.debugging) {
	    error("Unable to associate IPID proxy probe response with sent packet (received ack: %lX; sequence base: %lX. Packet:", ntohl(tcp->th_ack), sequence_base);
	       readtcppacket((char *)ip,BSDUFIX(ip->ip_len));
	  }
	  seq_response_num = probes_returned;
	}
	probes_returned++;
	ipids[seq_response_num] = (u16) ntohs(ip->ip_id);
	probe_returned[seq_response_num] = 1;
      }
    }
  }

  /* Yeah!  We're done sending/receiving probes ... now lets ensure all of our responses are adjacent in the array */
  for(i=0,probes_returned=0; i < NUM_IPID_PROBES; i++) {
    if (probe_returned[i]) {    
      if (i > probes_returned)
	ipids[probes_returned] = ipids[i];
      probes_returned++;
    }
  }

  proxy->seqclass = ipid_sequence(probes_returned, ipids, 0);
  switch(proxy->seqclass) {
  case IPID_SEQ_INCR:
  case IPID_SEQ_BROKEN_INCR:
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "Idlescan using proxy %s (%s:%hi); Class: %s\n", proxy->host.name, inet_ntoa(proxy->host.host), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
    break;
  default:
    fatal("Idlescan proxy %s (%s) port %hi cannot be used because IPID sequencability class is: %s.  Try another proxy.", proxy->host.name, inet_ntoa(proxy->host.host), proxy->probe_port, ipidclass2ascii(proxy->seqclass));
  }

  proxy->latestid = ipids[probes_returned - 1];

}



/* The very top-level idle scan function -- scans the given target
   host using the given proxy -- the proxy is cached so that you can keep
   calling this function with different targets */
void idle_scan(struct hoststruct *target, u16 *portarray, char *proxyName) {

  static char lastproxy[MAXHOSTNAMELEN + 1] = ""; /* The proxy used in any previous call */
  static struct idle_proxy_info proxy;
  if (!proxyName) fatal("Idlescan requires a proxy host");

  /* If this is the first call, or the proxy arg changed, we need to
     test the requested proxy.  */
  if (!*lastproxy || strcmp(proxyName, lastproxy)) {
    initialize_idleproxy(&proxy, proxyName);
  }


  return;
}
