
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
  u16 max_groupsz; /* We won't test groups larger than this ... */
  double current_groupsz; /* Current group size being used ... depends on
                          conditions ... won't be higher than
                          max_groupsz */
  int senddelay; /* Delay between sending pr0be SYN packets to target */

  pcap_t *pd; /* A Pcap descriptor which (starting in
                 initialize_idleproxy) listens for TCP packets from
                 the probe_port of the proxy box */
  int rawsd; /* Socket descriptor for sending probe packets to the proxy */
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
  int seq_response_num;
  char *dev;
  int i;
  char filter[512]; /* Libpcap filter string */
  char name[MAXHOSTNAMELEN + 1];
  u32 sequence_base;
  u32 ack = 0;
  struct timeval probe_send_times[NUM_IPID_PROBES], tmptv;
  u16 lastipid;
  struct ip *ip;
  struct tcphdr *tcp;
  u16 ipids[NUM_IPID_PROBES]; 
  u8 probe_returned[NUM_IPID_PROBES];
  assert(proxy);
  assert(proxyName);

  ack = get_random_u32();

  for(i=0; i < NUM_IPID_PROBES; i++) probe_returned[i] = 0;

  bzero(proxy, sizeof(*proxy));
  proxy->host.to.srtt = -1;
  proxy->host.to.rttvar = -1;
  proxy->host.to.timeout = o.initial_rtt_timeout * 1000;

  proxy->max_groupsz = (o.max_parallelism)? o.max_parallelism : 100;

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
  if (o.source && o.source->s_addr) {
    proxy->host.source_ip.s_addr = o.source->s_addr;
    Strncpy(proxy->host.device, o.device, sizeof(proxy->host.device));
  } else {
    dev = routethrough(&(proxy->host.host), &(proxy->host.source_ip));  
    if (!dev) fatal("Unable to find appropriate source address and device interface to use when sending packets to %s", proxyName);
    Strncpy(proxy->host.device, dev, sizeof(proxy->host.device));
  }
  /* Now lets send some probes to check IPID algorithm ... */
  /* First we need a raw socket ... */
  if ((proxy->rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in get_fingerprint");
  unblock_socket(proxy->rawsd);
  broadcast_socket(proxy->rawsd);


/* Now for the pcap opening nonsense ... */
 /* Note that the snaplen is 152 = 64 byte max IPhdr + 24 byte max link_layer
  * header + 64 byte max TCP header. */
  proxy->pd = my_pcap_open_live(proxy->host.device, 152,  (o.spoofsource)? 1 : 0, 50);

  p = strdup(inet_ntoa(proxy->host.host));
  q = strdup(inet_ntoa(proxy->host.source_ip));
  snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s and src port %hi", p, q, proxy->probe_port);
 free(p); 
 free(q);
 set_pcap_filter(&(proxy->host), proxy->pd, flt_icmptcp, filter);
/* Windows nonsense -- I am not sure why this is needed, but I should
   get rid of it at sometime */

 flt_srchost = proxy->host.source_ip.s_addr;
 flt_dsthost = proxy->host.host.s_addr;

 sequence_base = get_random_u32();

 /* Yahoo!  It is finally time to send our pr0beZ! */

  while(probes_sent < NUM_IPID_PROBES) {
    if (o.scan_delay) enforce_scan_delay(NULL);
    else if (probes_sent) usleep(30000);

    /* TH_SYN|TH_ACK is what the proxy will really be receiving from
       the target, and is more likely to get through firewalls.  But
       TH_SYN allows us to get a nonzero ACK back so we can associate
       a response with the exact request for timing purposes.  So I
       think I'll use TH_SYN, although it is a tough call. */
    /* We can't use decoys 'cause that would screw up the IPIDs */
    send_tcp_raw(proxy->rawsd, &(proxy->host.source_ip), &(proxy->host.host), 
		 o.magic_port + probes_sent + 1, proxy->probe_port, 
		 sequence_base + probes_sent + 1, 0, TH_SYN|TH_ACK, 
		 ack, NULL, 0, NULL, 0);
    gettimeofday(&probe_send_times[probes_sent], NULL);
    probes_sent++;

    /* Time to collect any replies */
    while(probes_returned < probes_sent && !timedout) {

      to_usec = (probes_sent == NUM_IPID_PROBES)? hardtimeout : 1000;
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec);

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

      if (bytes < ( 4 * ip->ip_hl) + 14U)
	continue;

      if (ip->ip_p == IPPROTO_TCP) {
	/*       readtcppacket((char *) ip, ntohs(ip->ip_len));  */
	tcp = ((struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl));
	if (ntohs(tcp->th_dport) < o.magic_port || ntohs(tcp->th_dport) - o.magic_port > NUM_IPID_PROBES  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
	  if (o.debugging > 1) error("Received unexpected response packet from %s during initial ipid proxy testing", inet_ntoa(ip->ip_src));
	  continue;
	}
	
	seq_response_num = probes_returned;

	/* The stuff below only works when we send SYN packets instead of
	   SYN|ACK, but then are slightly less stealthy and have less chance
	   of sneaking through the firewall.  Plus SYN|ACK is what they will
	   be receiving back from the target */
	/*	seq_response_num = (ntohl(tcp->th_ack) - 2 - sequence_base);
		if (seq_response_num < 0 || seq_response_num >= probes_sent) {
		if (o.debugging) {
		error("Unable to associate IPID proxy probe response with sent packet (received ack: %lX; sequence base: %lX. Packet:", ntohl(tcp->th_ack), sequence_base);
		readtcppacket((char *)ip,BSDUFIX(ip->ip_len));
		}
		seq_response_num = probes_returned;
		}
	*/
	probes_returned++;
	ipids[seq_response_num] = (u16) ntohs(ip->ip_id);
	probe_returned[seq_response_num] = 1;
	adjust_timeouts(probe_send_times[seq_response_num], &(proxy->host.to));
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
  proxy->current_groupsz = (probes_returned == NUM_IPID_PROBES)? 30 : 10;
  proxy->current_groupsz = MIN(proxy->max_groupsz, proxy->current_groupsz);

}




/* Adjust timing parameters up or down given that an idlescan found a
   count of 'testcount' while the 'realcount' is as given.  If the
   testcount was correct, timing is made more aggressive, while it is
   slowed down in the case of an error */
void adjust_idle_timing(struct idle_proxy_info *proxy, 
			struct hoststruct *target, int testcount, 
			int realcount) {

  if (o.debugging && testcount != realcount) {
    error("adjust_idle_timing: testcount: %d  realcount: %d", testcount, realcount);
  }

#if 0
    if (testcount < realcount) {
      /* We must have missed a port -- our probe could have been dropped, the
	 response to proxy could have been dropped, or we didn't wait long
	 enough before probing the proxy IPID. */
      proxy->current_groupsz *= 0.8; /* packets could be dropped because
					too many sent at once */
      proxy->current_groupsz = MAX(proxy->current_groupsz, 1);
      /* Increase the rttvar in case we missed the packets because we didn't
	 wait long enough */
      target->to.rttvar *= 1.1;
    } else if (testcount > realcount) {
      /* Perhaps the proxy host is not really idle ... */
      /* I guess all I can do is decrease the group size, so that if the proxy is not really idle, at least we may be able to scan cnunks more quickly in between outside packets */
      proxy->current_groupsz *= 0.8;
      proxy->current_groupsz = MAX(proxy->current_groupsz, 1);
    } else {
      /* W00p We got a perfect match.  That means we get a slight increase
	 in allowed group size */
      proxy->current_groupsz = MIN(proxy->max_groupsz, proxy->current_groupsz * 1.1);
    }
#endif

}

/* Sends an IPID probe to the proxy machine and returns the IPID.
   This function handles retransmissions, and returns -1 if it fails.
   Proxy timing is adjusted, but proxy->latestid is NOT ADJUSTED --
   you'll have to do that yourself */
int ipid_proxy_probe(struct idle_proxy_info *proxy) {
  struct timeval tv_end;
  int tries = 0;
  int trynum;
  int maxtries = 3; /* The maximum number of tries before we give up */
  struct timeval tv_sent[3];
  int ipid = -1;
  int to_usec;
  int bytes;
  int timedout = 0;
  struct ip *ip;
  struct tcphdr *tcp;
  static u32 seq_base = 0;
  static u32 ack = 0;
  static int packet_send_count = 0; /* Total # of probes sent by this program -- to ensure that our sequence # always changes */


  if (seq_base == 0) seq_base = get_random_u32();
  if (!ack) ack = get_random_u32();

  do {
    timedout = 0;
    gettimeofday(&tv_sent[tries], NULL);

    /* Time to send the pr0be!*/
    send_tcp_raw(proxy->rawsd, &(proxy->host.source_ip), &(proxy->host.host), 
		 o.magic_port + tries , proxy->probe_port, 
		 seq_base + (packet_send_count++ * 500) + 1, ack, 
		 TH_SYN|TH_ACK, 0, 
		 NULL, 0, NULL, 0);
    tries++;

    /* Now it is time to wait for the response ... */
    to_usec = proxy->host.to.timeout;
    while(ipid == -1 && to_usec >= 0) {
    
      ip = (struct ip *) readip_pcap(proxy->pd, &bytes, to_usec);      
      gettimeofday(&tv_end, NULL);
      to_usec -= TIMEVAL_SUBTRACT(tv_end, tv_sent[tries-1]);
      if (ip) {
	if (bytes < ( 4 * ip->ip_hl) + 14U)
	continue;

	if (ip->ip_p == IPPROTO_TCP) {

	  tcp = ((struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl));
	  if (ntohs(tcp->th_dport) < o.magic_port || ntohs(tcp->th_dport) - o.magic_port >= maxtries  || ntohs(tcp->th_sport) != proxy->probe_port || ((tcp->th_flags & TH_RST) == 0)) {
	    if (o.debugging > 1) {
	      error("Received unexpected response packet from %s during ipid proxy probing", inet_ntoa(ip->ip_src));
	      readtcppacket((char *)ip,BSDUFIX(ip->ip_len));
	    }
	    continue;
	  }
	  
	  trynum = ntohs(tcp->th_dport) - o.magic_port;

	  if (trynum >= tries) {

	    /* Uh-oh.  I think we just received a response from an
               earlier instance ... time to clobber the timing ... */
	    if (o.debugging) 
	      error("Received IPID proxy probe response which probably came from an earlier prober instance ... increasing rttvar from %f to %f", 
		    proxy->host.to.rttvar, proxy->host.to.rttvar * 1.2);
	    proxy->host.to.rttvar *= 1.3;
	    continue;
	  }
	  if (trynum > 1) {
	    if (o.debugging)
	      error("An IPID proxy probe (or the response) appears to have been lost ... adjusting timing");
	    proxy->senddelay += 10000;
	    proxy->host.to.rttvar *= 1.1;
	  }
	  ipid = ntohs(ip->ip_id);
	  adjust_timeouts(tv_sent[trynum], &(proxy->host.to));
	}
      }
    }
  } while(ipid == -1 && tries < maxtries);

  return ipid;
}


/* Returns the number of increments between an early IPID and a later
   one, assuming the given IPID Sequencing class.  Returns -1 if the
   distance cannot be determined */

int ipid_distance(int seqclass , u16 startid, u16 endid) {
  u16 a, b;
  if (seqclass == IPID_SEQ_INCR)
    return endid - startid;
  
  if (seqclass == IPID_SEQ_BROKEN_INCR) {
    /* Convert to network byte order */
    startid = (startid >> 8) + ((startid & 0xFF) << 8);
    endid = (endid >> 8) + ((endid & 0xFF) << 8);
    return endid - startid;
  }

  return -1;

}

/* OK, now this is the hardcore idlescan function which actually does
   the testing (most of the other cruft in this file is just
   coordination, preparation, etc).  This function simply uses the
   Idlescan technique to try and count the number of open ports in the
   given port array */
int idlescan_countopen2(struct idle_proxy_info *proxy, 
			struct hoststruct *target, u16 *ports, int numports) 
{

#if 0 /* Testing code */
  int i;
  for(i=0; i < numports; i++)
    if (ports[i] == 22)
      return 1;
  return 0;
#endif

  int ipid_dist;
  struct timeval start, end, latestchange;
  int pr0be;
  static u32 seq = 0;
  int newipid;
  if (seq == 0) seq = get_random_u32();

  bzero(&end, sizeof(end));
  bzero(&latestchange, sizeof(latestchange));
  gettimeofday(&start, NULL);

  /* I start by sending out the SYN pr0bez */
  for(pr0be = 0; pr0be < numports; pr0be++) {
    if (o.scan_delay) enforce_scan_delay(NULL);
    else if (proxy->senddelay && pr0be > 0) usleep(proxy->senddelay);
    
    /* Maybe I should involve decoys in the picture at some point --
       but doing it the straightforward way (using the same decoys as
       we use in probing the proxy box is risky.  I'll have to think
       about this more. */

    send_tcp_raw(proxy->rawsd, &(proxy->host.host), &target->host, o.magic_port, 
		 ports[pr0be], seq, 0, TH_SYN, 0, NULL, 0, 
		 o.extra_payload, o.extra_payload_length);
  }

  usleep(200000);
  /* Now that our pr0bes have been sent to the target, we start pr0bing the
     proxy for its IPID */
  newipid = ipid_proxy_probe(proxy);
  if (newipid > 0) {
    ipid_dist = ipid_distance(proxy->seqclass, proxy->latestid, newipid);
    if (ipid_dist > 0) {
      /* W00p!  Now we subtract one to make up for the response to our direct
	 probe */
      ipid_dist--;
    }
    proxy->latestid = newipid;
  } else ipid_dist = -1;
  error("The new IPID is %d and the distance is: %d", newipid, ipid_dist);
  return ipid_dist;
}



/* The job of this function is to use the Idlescan technique to count
   the number of open ports in the given list.  Under the covers, this
   function just farms out the hard work to another function */
int idlescan_countopen(struct idle_proxy_info *proxy, 
		       struct hoststruct *target, u16 *ports, int numports) {
  int tries = 0;
  int openports;

  do {
    if (o.debugging && tries >= 1) {
      error("idlescan_countopen: In try #%d to count open ports (out of %d), got %d", tries, numports, openports);
    }
    openports = idlescan_countopen2(proxy, target, ports, numports);
    tries++;
    if (tries > 1)
      sleep(tries * tries * tries * 3); /* Sleep a little while in
				   case a sudden (brief) burst of
				   traffic to the proxy is causing
				   problems */
  } while (tries < 3 && (openports < 0 || openports > numports));

  if (tries == 3 ) {
    /* Oh f*ck!!!! */
    fatal("Idlescan is unable to obtain meaningful results fro proxy %s (%s).  I'm sorry it didn't work out.", proxy->host.name, inet_ntoa(proxy->host.host));
  }

  return openports;
}

/* Recursively Idlescans scans a group of ports using a depth-first
   divide-and-conquer strategy to find the open one(s) */

int idle_treescan(struct idle_proxy_info *proxy, struct hoststruct *target,
		 u16 *ports, int numports, int expectedopen) {

  int firstHalfSz = (numports + 1)/2;
  int flatcount1, flatcount2;
  int deepcount1 = -1, deepcount2 = -1;
  int retrycount = -1;
  int totalfound = 0;
  /* Scan the first half of the range */

  if (o.debugging > 1)
    error("idle_treescan: Called against %s with %d ports, starting with %hi. expectedopen: %d", inet_ntoa(target->host), numports, ports[0], expectedopen);
  flatcount1 = idlescan_countopen(proxy, target, ports, firstHalfSz);
  
  if (firstHalfSz > 1 && flatcount1 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount1 = idle_treescan(proxy, target, ports, firstHalfSz, flatcount1);
    /* Now we assume deepcount1 is write, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount1, deepcount1);
  }

  /* I guess we had better do the second half too ... */
  flatcount2 = idlescan_countopen(proxy, target, ports + firstHalfSz, 
				  numports - firstHalfSz);
  
  if ((numports - firstHalfSz) > 1 && flatcount2 > 0) {
    /* A port appears open!  We dig down deeper to find it ... */
    deepcount2 = idle_treescan(proxy, target, ports + firstHalfSz, 
			       numports - firstHalfSz, flatcount2);
    /* Now we assume deepcount1 is right, and adjust timing if flatcount1 was
       wrong */
    adjust_idle_timing(proxy, target, flatcount2, deepcount2);
  }

  totalfound = (deepcount1 == -1)? flatcount1 : deepcount1;
  totalfound += (deepcount2 == -1)? flatcount2 : deepcount2;

  if (totalfound != expectedopen) {  
    if (deepcount1 == -1) {
      retrycount = idlescan_countopen(proxy, target, ports, firstHalfSz);
      if (retrycount != flatcount1) {      
	adjust_idle_timing(proxy, target, flatcount1, retrycount);
	/* We have to do a deep count if new ports were found and
	   there are more than 1 total */
	if (firstHalfSz > 1 && retrycount > 0)
	  retrycount = idle_treescan(proxy, target, ports, firstHalfSz, 
				     retrycount);
	totalfound += retrycount - flatcount1;
	flatcount1 = retrycount;
      }
    }
    
    if (deepcount2 == -1) {
      retrycount = idlescan_countopen(proxy, target, ports + firstHalfSz, 
				      numports - firstHalfSz);
      if (retrycount != flatcount2) {      
	adjust_idle_timing(proxy, target, flatcount2, retrycount);
	if (numports - firstHalfSz > 1 && retrycount > 0)
	  retrycount = idle_treescan(proxy, target, ports + firstHalfSz, 
				     numports - firstHalfSz, flatcount2);

	totalfound += retrycount - flatcount2;
	flatcount2 = retrycount;
      }
    }
  }

  if (firstHalfSz == 1 && flatcount1 == 1) 
    addport(&target->ports, ports[0], IPPROTO_TCP, NULL, PORT_OPEN);
  
  if ((numports - firstHalfSz == 1) && flatcount2 == 1) 
    addport(&target->ports, ports[firstHalfSz], IPPROTO_TCP, NULL, PORT_OPEN);
  return totalfound;

}



/* The very top-level idle scan function -- scans the given target
   host using the given proxy -- the proxy is cached so that you can keep
   calling this function with different targets */
void idle_scan(struct hoststruct *target, u16 *portarray, char *proxyName) {

  static char lastproxy[MAXHOSTNAMELEN + 1] = ""; /* The proxy used in any previous call */
  static struct idle_proxy_info proxy;
  int groupsz;
  int portidx = 0; /* Used for splitting the port array into chunks */
  int portsleft;
  time_t starttime;
  
  if (!proxyName) fatal("Idlescan requires a proxy host");

  if (*lastproxy && strcmp(proxyName, lastproxy))
    fatal("idle_scan(): You are not allowed to change proxies midstream.  Sorry");
  assert(target);



  /* If this is the first call,  */
  if (!*lastproxy) {
    initialize_idleproxy(&proxy, proxyName);
  }

  if (o.debugging || o.verbose) {  
    log_write(LOG_STDOUT, "Initiating Idlescan against %s (%s)\n", target->name, inet_ntoa(target->host));
  }
  starttime = time(NULL);

  /* If we don't have timing infoz for the new target, we'll use values 
     derived from the proxy */
  if (target->to.srtt == -1 && target->to.rttvar == -1) {
    target->to.srtt = 2 * proxy.host.to.srtt;
    target->to.rttvar = MAX(10000, MIN(target->to.srtt, 2000000));
    target->to.timeout = target->to.srtt + (target->to.rttvar << 2);
  }

  /* Now I guess it is time to let the scanning begin!  Since Idle
     scan is sort of tree structured (we scan a group and then divide
     it up and drill down in subscans of the group), we split the port
     space into smaller groups and then call a recursive
     divide-and-counquer function to find the open ports */
  while(portidx < o.numports) {
    portsleft = o.numports - portidx;
    /* current_grupsz is doubled below because idle_subscan cuts in half */
    groupsz = MIN(portsleft, (int) (proxy.current_groupsz * 2));
    idle_treescan(&proxy, target, portarray + portidx, groupsz, -1);
    portidx += groupsz;
  }


  if (o.verbose) {
    long timediff = time(NULL) - starttime;
    log_write(LOG_STDOUT, "The Idlescan took %ld %s to scan %d ports.\n", 
	      timediff, (timediff == 1)? "second" : "seconds", o.numports);
  }
  return;
}
