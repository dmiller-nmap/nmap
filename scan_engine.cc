
/***************************************************************************
 * scanengine.cc -- Includes much of the "engine" functions for scanning,  *
 * such as pos_scan and super_scan.  It also includes dependant functions  *
 * such as those for collectiong SYN/connect scan responses.               *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap                                                         *
 * o Integrates/includes/aggregates Nmap into an executable installer      *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://www.insecure.org/nmap/ to download Nmap.                         *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the (GPL) terms above, then that      *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html .                                  *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */

#include "scan_engine.h"
#include "timing.h"
#include "NmapOps.h"

extern NmapOps o;

#ifdef __amigaos__
extern void CloseLibs(void);
#endif

/*  predefined filters -- I need to kill these globals at some pont. */
extern unsigned long flt_dsthost, flt_srchost;
extern unsigned short flt_baseport;


/* Does the appropriate stuff when the port we are looking at is found
   to be open trynum is the try number that was successful 
   I USE CURRENT->STATE TO DETERMINE WHETHER THE PORT IS OPEN
   OR FIREWALLED */
static void posportupdate(Target *target, struct portinfo *current, 
		   struct timeval *rcvdtime, int trynum, struct portinfo *scan,
		   struct scanstats *ss ,stype scantype, int newstate,
		   struct portinfolist *pil, struct connectsockinfo *csi) {
  static int tryident = -1;
  static u32 lasttarget = 0;
  struct sockaddr_in mysock;
  recvfrom6_t sockaddr_in_len = sizeof(SA);
  int i;
  char owner[32];
  struct timeval tv;

  if (tryident == -1 || target->v4host().s_addr != lasttarget) 
    tryident = o.identscan;
  lasttarget = target->v4host().s_addr;
  owner[0] = '\0';
  if (current->state != PORT_OPEN && current->state != PORT_CLOSED &&
      current->state != PORT_FIREWALLED && current->state != PORT_TESTING) {
    if (o.debugging) error("Whacked packet to port %lu passed to posportupdate with state %s (%d)\n", current->portno, statenum2str(current->state), current->state);
    return;
  }

  /* Lets do the timing stuff */
  if (trynum > -1) {
    if (!rcvdtime) {
      gettimeofday(&tv, NULL);
      rcvdtime = &tv;
    }
    adjust_timeouts2(&(current->sent[trynum]), rcvdtime, &(target->to));
    target->firewallmode.responsive_ports++; 
  }
  /* If a non-zero trynum finds a port that hasn't been discovered, the
   earlier packets(s) were probably dropped.  So we decrease our 
   numqueries_ideal, otherwise we increase it slightly */
  if (trynum == 0) {
    ss->numqueries_ideal = MIN(ss->numqueries_ideal + (ss->packet_incr/ss->numqueries_ideal), ss->max_width);
  } else if (trynum != -1) {
    /* I don't want to decrease numqueries in the case port was
       already determined to be open since sometimes the target box
       ignores our RSTs and continues to resend SYN|ACK.  If this is
       for a try #2 (eg there was one real drop), we would keep
       getting whacked at every resend :(.  Even in a "legitimate"
       case here where the port is OPEN, the problem is probably not
       waiting long enough rather than a dropped packet -- and the
       adjust_timeouts() above will deal w/that.  Note that
       adjust_timeouts also was able to handle the bogus resends OK
       because the timing was so bogus */
    if (!ss->alreadydecreasedqueries && current->state != PORT_OPEN) {
      double oldideal = ss->numqueries_ideal;
      ss->alreadydecreasedqueries = 1;
      ss->numqueries_ideal *= ss->fallback_percent;
      if (target->firewallmode.active)
	ss->numqueries_ideal *= ss->fallback_percent; /* We need to act 
							 forcefully on what 
							 little info we have */
      ss->numqueries_ideal = MAX(ss->min_width, ss->numqueries_ideal);
      if (o.debugging && (ss->numqueries_ideal != oldideal)) 
	log_write(LOG_STDOUT, "Apparent packet loss -- reducing numqueries_ideal from %.3f to %.3f\n", oldideal, ss->numqueries_ideal);      
    }
  }

  /* Collect IDENT info if requested */
  if (newstate == PORT_OPEN && scantype == CONNECT_SCAN && tryident) {
    if (getsockname(current->sd[trynum], (SA *) &mysock,
		    &sockaddr_in_len )) {
      pfatal("getsockname");
    }
    if (getidentinfoz(target->v4host(), ntohs(mysock.sin_port), current->portno, owner, sizeof(owner)) == -1)
      tryident = 0;
  }

  /* Now we convert current->state to state by making whatever adjustments
   are neccessary */
  switch(current->state) {
  case PORT_OPEN:
    return; /* Whew!  That was easy! */
    break;
  case PORT_FRESH:
    fprintf(stderr, "Fresh port %lu passed to posportupdate!\n", current->portno);
    return;
    break;
  case PORT_CLOSED:
    if (newstate == PORT_CLOSED)
      return; /* Closed -> Closed is not important and can cause some 
		 dup port problems */
    ss->changed++;
    current->state = newstate;
    break;
  case PORT_TESTING:
    /* If the newstate is FIREWALLED, nothing really "changed" since the
       default if there is no responses is to put the port into the firewalled
       state.  OK, OK, I don't know if this justification completely holds 
       water, but the shortcut of not updating change can save us a LOT of 
       time in cases of infrequent host unreachable packets (for example).  
       In that case, a few unreachables during each scan run causes the changed
       flag to be set and we need to try again.  Eventually the systems notices
       all the tries and starts increasing senddelay() and we are in even 
       worse shape */
    if (newstate != PORT_FIREWALLED)
      ss->changed++;
    if (scantype == SYN_SCAN)
      ss->numqueries_outstanding--;
    else {
      for(i=0; i <= current->trynum; i++)
	if (current->sd[i] > -1) {
	  csi->socklookup[current->sd[i]] = NULL;
	  FD_CLR(current->sd[i], &(csi->fds_read));
	  FD_CLR(current->sd[i], &(csi->fds_write));
	  FD_CLR(current->sd[i], &(csi->fds_except));
	  if (current->sd[i] == csi->maxsd)
	    csi->maxsd--;
	  close(current->sd[i]);
	  current->sd[i] = -1;
	  ss->numqueries_outstanding--;
	}
    }
    /* Now we delete the port from the testinglist */
    if (current == pil->testinglist)
      pil->testinglist = (current->next >= 0)? &scan[current->next] : NULL;
    if (current->next >= 0)  scan[current->next].prev = current->prev;
    if (current->prev >= 0)  scan[current->prev].next = current->next;
    break;
  case PORT_FIREWALLED:
    if (newstate != PORT_FIREWALLED)
      ss->changed++;
    if (current == pil->firewalled)
      pil->firewalled = (current->next >= 0)? &scan[current->next] : NULL;
    if (current->next >= 0)  scan[current->next].prev = current->prev;
    if (current->prev >= 0)  scan[current->prev].next = current->next;
    break;
  default:
    fatal("Unexpected port state: %d\n", current->state);
    break;
  } 
  current->state = newstate;
  current->next = -1;
  current->prev = -1;
  target->ports.addPort(current->portno, IPPROTO_TCP, owner, newstate);
  return;
}

/* Grab results from a connect() scan (eg check all the non-blocking
   outstanding connect requests for completion.  */
static int get_connect_results(Target *target, 
			       struct portinfo *scan, 
			       struct scanstats *ss, struct portinfolist *pil, 
			       int *portlookup, u32 *sequences, 
			       struct connectsockinfo *csi) {
  fd_set fds_rtmp, fds_wtmp, fds_xtmp;
  int selectres;
  int selectedfound;
  int optval;
  recvfrom6_t optlen = sizeof(int);
  struct timeval timeout;
  int i, sd;
  int trynum;
  char buf[2048];
  struct portinfo *current = NULL;
  struct timeval tv;
  int res;
#ifdef LINUX
  struct sockaddr_storage sin,sout;
  struct sockaddr_in *s_in;
  struct sockaddr_in6 *s_in6;
  recvfrom6_t sinlen = sizeof(sin);
  recvfrom6_t soutlen = sizeof(sout);
#endif

  res = 0;  /* to prevent compiler warning */
  do {
    fds_rtmp = csi->fds_read;
    fds_wtmp = csi->fds_write;
    fds_xtmp = csi->fds_except;
    timeout.tv_sec = 0;
    timeout.tv_usec = 20000;
    selectedfound = 0;

    /* Insure there is no timeout ... */
    if (o.host_timeout) {	
      gettimeofday(&tv, NULL);
      if (TIMEVAL_MSEC_SUBTRACT(tv, target->host_timeout) >= 0) {
	target->timedout = 1;
	return 0;
      }
    }

    selectres = select(csi->maxsd+1, &fds_rtmp, &fds_wtmp, &fds_xtmp, &timeout);
    for(sd=0; selectedfound < selectres && sd <= csi->maxsd; sd++) {
      current = csi->socklookup[sd];
      if (!current) continue;
      trynum = -1;
      if  (FD_ISSET(sd, &fds_rtmp)  || FD_ISSET(sd, &fds_wtmp) || 
	   FD_ISSET(sd, &fds_xtmp)) {
	/*      current = csi->socklookup[i];*/
	for(i=0; i < 3; i++)
	  if (current->sd[i] == sd) {	
	    trynum = i;
	    break;
	  }

	if (o.debugging > 1 && current != NULL)
	  log_write(LOG_STDOUT, "portnumber %lu (try %d) selected for", current->portno, trynum);
	if (FD_ISSET(sd, &fds_rtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " READ");
	  selectedfound++;
	}
	if (FD_ISSET(sd, &fds_wtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " WRITE");
	  selectedfound++;
	}
	if (FD_ISSET(sd, &fds_xtmp)) {
	  if (o.debugging > 1) log_write(LOG_STDOUT, " EXCEPT");
	  selectedfound++;
	}
	if (o.debugging > 1 && current != NULL)
	  log_write(LOG_STDOUT, "\n");

	assert(trynum != -1);

	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, (char *) &optval, &optlen) != 0)
	  optval = socket_errno(); /* Stupid Solaris ... */

	switch(optval) {
	case 0:
#ifdef LINUX
	  if (!FD_ISSET(sd, &fds_rtmp)) {
	    /* Linux goofiness -- We need to actually test that it is writeable */
	    res = send(current->sd[trynum], "", 0, 0);

	    if (res < 0 ) {
	      if (o.debugging > 1) {
		log_write(LOG_STDOUT, "Bad port %lu caught by 0-byte write: ", current->portno);
		perror("");
	      }
	      posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	    } else {
	      if (getpeername(sd, (struct sockaddr *) &sin, &sinlen) < 0) {
		pfatal("error in getpeername of connect_results for port %hu", (u16) current->portno);
	      } else {
		s_in = (struct sockaddr_in *) &sin;
		s_in6 = (struct sockaddr_in6 *) &sin;
		if ((o.af() == AF_INET &&
		    current->portno != ntohs(s_in->sin_port))
#ifdef HAVE_IPV6
		    || (o.af() == AF_INET6 && current->portno != ntohs(s_in6->sin6_port))
#endif
) {
		  error("Mismatch!!!! we think we have port %hu but we really have a different one", (u16) current->portno);
		}
	      }

	      if (getsockname(sd, (struct sockaddr *) &sout, &soutlen) < 0) {
		pfatal("error in getsockname for port %hu", (u16) current->portno);
	      }
	      s_in = (struct sockaddr_in *) &sout;
	      s_in6 = (struct sockaddr_in6 *) &sout;
	      if ((o.af() == AF_INET && htons(s_in->sin_port) == current->portno) 
#ifdef HAVE_IPV6
|| (o.af() == AF_INET6 && htons(s_in6->sin6_port) == current->portno)
#endif
) {
		/* Linux 2.2 bug can lead to bogus successful connect()ions
		   in this case -- we treat the port as bogus even though it
		   is POSSIBLE that this is a real connection */
		posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	      } else {
		posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
	      }
	    }
	  } else {
	    posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
	  }
#else
	  posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_OPEN, pil, csi);
#endif
	  break;
	case ECONNREFUSED:
	  posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_CLOSED, pil, csi);
	  break;
	case EHOSTUNREACH:
	case ETIMEDOUT:
	case EHOSTDOWN:
	  /* It could be the host is down, or it could be firewalled.  We
	     will go on the safe side & assume port is closed ... on second
	     thought, lets go firewalled! and see if it causes any trouble */
	  posportupdate(target, current, NULL, trynum, scan, ss, CONNECT_SCAN, PORT_FIREWALLED, pil, csi);
	  break;
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case ECONNABORTED:
	  snprintf(buf, sizeof(buf), "Strange SO_ERROR from connection to %s (%d) -- bailing scan", target->targetipstr(), optval);
	  perror(buf);
	  return -1;
	  break;
	default:
	  snprintf(buf, sizeof(buf), "Strange read error from %s (%d)", target->targetipstr(), optval);
	  perror(buf);
	  break;
	}
      } else continue;
    }
  } while(ss->numqueries_outstanding > 0 && selectres > 0);

  return 0;
}

/* Grab results for a SYN scan.  We assume the SYNs have already been sent,
   and we sniff for SYN|ACK or RST packets */
static void get_syn_results(Target *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
		     int *portlookup, pcap_t *pd, u32 *sequences, 
		     stype scantype) {

  struct ip *ip;
  unsigned int bytes;
  struct tcphdr *tcp;
  int trynum;
  int newstate = -1;
  int i;
  int newport;
  struct portinfo *current = NULL;
  struct icmp *icmp;
  struct ip *ip2;
  u16 *data;
  struct timeval start, rcvdtime;
  int quit = 0;

  gettimeofday(&start, NULL);

  while (!quit && ss->numqueries_outstanding > 0 && 
	 ( ip = (struct ip*) readip_pcap(pd, &bytes, target->to.timeout, &rcvdtime))) {
    if (bytes < (4 * ip->ip_hl) + 4U)
      continue;
    current = NULL;
    trynum = newport = -1;
    newstate = PORT_UNKNOWN;

    /* Insure there is no timeout ... */
    if (o.host_timeout) {	
      if (TIMEVAL_MSEC_SUBTRACT(rcvdtime, target->host_timeout) >= 0) {
	target->timedout = 1;
	return;
      }
    }

    /* If this takes at least 1.5 secs and is more than the targets
       timeout, lets get out of here.  Otherwise stray network packets
       could cause us trouble. */
    if ( TIMEVAL_SUBTRACT(rcvdtime, start) > MAX(target->to.timeout, 1500)) {
      /* Lets quit after we process this packet */
      quit = 1;
    }

    if (ip->ip_src.s_addr == target->v4host().s_addr && 
	ip->ip_p == IPPROTO_TCP) {
      tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
      i = ntohs(tcp->th_dport);
      if (i < o.magic_port || i > o.magic_port + 15) {
	if (o.debugging > 1)
	  error("SYN scan got TCP packet to port %d (magic port is %d) ... ignoring", i, o.magic_port);
	continue;
      }
      newport = ntohs(tcp->th_sport);
      /* In case we are scanning localhost and see outgoing packets */
      /* If only one of SYN, ACK flags are set, we skip it */
      if (ip->ip_src.s_addr == target->v4source().s_addr && ((tcp->th_flags == TH_ACK) || (tcp->th_flags == TH_SYN))) {
	continue;
      }
      if (portlookup[newport] < 0 || scan[portlookup[newport]].state == PORT_FRESH) {
	if (o.debugging) {
	  log_write(LOG_STDOUT, "Strange packet from port %d:\n", ntohs(tcp->th_sport));
	  readtcppacket((unsigned char *)ip, bytes);
	}
	current = NULL;
	continue;
      }	      

      current = &scan[portlookup[newport]];
      for(i=0; i < 3; i++) {
	if (MOD_DIFF(sequences[i],ntohl(tcp->th_ack)) < 5)
	  break;
      }
      if (i < 3) trynum = i;
      else {
	if (o.debugging) 
	  log_write(LOG_STDOUT, "Strange ACK number from target: %lX\n", (unsigned long) ntohl(tcp->th_ack));
	trynum = (current->trynum == 0)? 0 : -1;	    
      }
      if (current->trynum < trynum) {
	if (o.debugging) 	    
	  error("Received SYN packet implying trynum %d from port %hu even though that port is only on trynum %d (could be from an earlier round)", trynum, newport, current->trynum);
	trynum = -1;
      }
      if (scantype == SYN_SCAN) {
	if (tcp->th_flags & TH_RST) {
	  newstate = PORT_CLOSED;
	} else if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
	  newstate = PORT_OPEN;
	} else {
	  if (o.debugging)
	    error("Received response to SYN scan with unexpected tcp flags: %d\n", tcp->th_flags);
	  continue;
	}
      }
      else if (scantype == WINDOW_SCAN) {
	if (tcp->th_flags & TH_RST) {
	  if (tcp->th_win) {
	    newstate = PORT_OPEN;
	  } else {
	    newstate = PORT_CLOSED;
	  }
	} else {
	  if (o.debugging)
	    error("Received response to WINDOW scan with unexpected tcp flags: %d\n", tcp->th_flags);
	  continue;
	}
      }
      else if (scantype == ACK_SCAN) {
	if (tcp->th_flags & TH_RST) {	  
	  newstate = PORT_UNFIREWALLED;
	} else {
	  if (o.debugging)
	    error("Received response to ACK scan with unexpected tcp flags: %d\n", tcp->th_flags);
	  continue;
	}
      } else {
	fatal("Unknown scan type!#$!@#$ passed to get_syn_results!  Please notify fyodor@insecure.org");
      }
    } else if (ip->ip_p == IPPROTO_ICMP) {
      icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);
      ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
      if (bytes <= 4 * ip->ip_hl + 28U ||
	  bytes <= /* IP1len */ 4 * ip->ip_hl + /*ICMPlen */ 8 + 
	  /* IP2len */ 4 * ip2->ip_hl + 4U /* TCP ports */)
	{
	  if (o.debugging) {
	    error("Icmp message too short (%d bytes)", bytes);
	  }
	  continue;
	}

      /* Lets ensure this packet relates to a packet to the host
	 we are scanning ... */
      if (ip2->ip_dst.s_addr != target->v4host().s_addr) {
	if (o.debugging > 1)
	  error("Got an ICMP message which does not relate to a packet sent to the host being scanned");
	continue;
      }

      data = (u16 *) ((char *)ip2 + 4 * ip2->ip_hl);
      /*	    log_write(LOG_STDOUT, "Caught ICMP packet:\n");
		    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */
      if (icmp->icmp_type == 3) {
	if (icmp->icmp_code != 0 && icmp->icmp_code != 1 && 
	    icmp->icmp_code != 2 && 
	    icmp->icmp_code != 3 && icmp->icmp_code != 13 &&
	    icmp->icmp_code != 9 && icmp->icmp_code != 10) {
	  error("Unexpected ICMP type/code 3/%d unreachable packet:", icmp->icmp_code);
	  hdump((unsigned char *)icmp, ntohs(ip->ip_len) - sizeof(struct ip));
	  continue;
	}
       
	newport = ntohs(data[1]);
	if (portlookup[newport] >= 0 && scan[portlookup[newport]].state != PORT_FRESH) {
	  current = &scan[portlookup[newport]];
	  trynum = (current->trynum == 0)? 0 : -1;
	  newstate = PORT_FIREWALLED;
	} else { 
	  if (o.debugging) {
	    error("Illegal ICMP type/code 3/%d unreachable packet:", 
		  icmp->icmp_code);
	    hdump((unsigned char *)icmp, ntohs(ip->ip_len) - sizeof(struct ip));
	  }
	  continue;
	}	      
      }
    }
    /* OK, now we manipulate the port lists and adjust the time */
    if (current) {
      posportupdate(target, current, &rcvdtime, trynum, scan, ss, SYN_SCAN, newstate,
		    pil, NULL);
      current = NULL;
      trynum = -1;
      newstate = PORT_UNKNOWN;
    }
  }
  return;
}


/* I want to reverse the order of all PORT_TESTING entries in
   the scan list -- this way if an intermediate router along the
   way got overloaded and dropped the last X packets, they are
   likely to get through (and flag us a problem if responsive)
   if we let them go first in the next round */
void reverse_testing_order(struct portinfolist *pil, struct portinfo *scanarray) {
  int currentidx, nextidx;
  struct portinfo *current;

  current = pil->testinglist;

  if (current == NULL || current->state != PORT_TESTING)
    return;

  while(1) {
    nextidx = current->next;
    currentidx = current - scanarray;
    /* current->state is always PORT_TESTING here */
    current->next = current->prev; // special case 1st node dealt w/later
    current->prev = nextidx; // special last TESTING node case dealt w/later
    if (nextidx == -1) {
      // Every node was in TESTING state
      current->prev = -1; // New head of list
      pil->testinglist->next = -1;
      pil->testinglist = current;
      break;
    } else if (scanarray[nextidx].state != PORT_TESTING) {
      current->prev = -1; // New head of list
      pil->testinglist->next = nextidx;
      scanarray[nextidx].prev = pil->testinglist - scanarray;
      pil->testinglist = current;
      break;
    }
    current = scanarray + nextidx;
  }
}

/* Handles the "positive-response" scans (where we get a response
   telling us that the port is open based on the probe.  This includes
   SYN Scan, Connect Scan, RPC scan, Window Scan, and ACK scan */
void pos_scan(Target *target, u16 *portarray, int numports, stype scantype) {
  struct scanstats ss;
  int rawsd = -1;
  int scanflags = 0;
  int victim;
  int senddelay = 0;
  int rpcportsscanned = 0;
  bool printedinitialmsg = false;
  pcap_t *pd = NULL;
  char filter[512];
  u32 ack_number = 0;
  int tries = 0;
  int  res;
  int connecterror = 0;
  time_t starttime;
  struct sockaddr_storage sock;
  struct sockaddr_in *sin = (struct sockaddr_in *) &sock;
#if HAVE_IPV6
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sock;
#endif
  size_t socklen;
  struct portinfo *scan = NULL,  *current, *next;
  struct portinfolist pil;
  int *portlookup = NULL; /* Indexes port number -> scan[] index */
  struct timeval now;
  struct connectsockinfo csi;
  struct rpcscaninfo rsi;
  u32 sequences[3]; /* for various reasons we use 3 separate
				 ones rather than simply incrementing from
				 a base */
  char hostname[1200];
  int i;
  unsigned long j;
  struct serviceDeductions sd;

  if (target->timedout)
    return;

  if (!numports && scantype != RPC_SCAN) return; /* nothing to scan for */

  if (scantype == RPC_SCAN && target->ports.state_counts[PORT_OPEN] == 0)
    return; // RPC Scan only works against already known-open ports

  /* If it is a SYN scan and we have already figured out the states
     of all the TCP ports, might as well skip the scan (this can happen
     if the ping scan determined the states) */
  if (target->ports.state_counts_tcp[PORT_OPEN] + target->ports.state_counts_tcp[PORT_CLOSED] + target->ports.state_counts_tcp[PORT_FIREWALLED] == numports && scantype == SYN_SCAN) {
    if (o.debugging)
      error("Skipping SYN scan since all ports already known");
    return;
  }

  if (o.debugging)
    log_write(LOG_STDOUT, "Starting pos_scan (%s)\n", scantype2str(scantype));

  ss.packet_incr = 4;
  ss.initial_packet_width = (scantype == RPC_SCAN)? 2 : 30;
  ss.fallback_percent = 0.7;
  ss.numqueries_outstanding = 0;
  ss.ports_left = numports;
  ss.alreadydecreasedqueries = 0;

  memset(&pil, 0, sizeof(pil));

  FD_ZERO(&csi.fds_read);
  FD_ZERO(&csi.fds_write);
  FD_ZERO(&csi.fds_except);
  csi.maxsd = 0;

  /* Start the firewall mode with a clean slate ... */
  target->firewallmode.active = 0;
  target->firewallmode.nonresponsive_ports = 0;
  target->firewallmode.responsive_ports = 0;

  if (o.max_parallelism) {
    ss.max_width = o.max_parallelism;
  } else {
    if (scantype == CONNECT_SCAN) {
      ss.max_width = MAX(5, max_sd() - 4);
    } else {
      ss.max_width = 150;
    }
  }

  if (o.min_parallelism) {
    ss.min_width = o.min_parallelism;
  } else ss.min_width = 1;

  ss.initial_packet_width = box(ss.min_width, ss.max_width, ss.initial_packet_width);
  ss.numqueries_ideal = ss.initial_packet_width;

  portlookup = (int *) safe_malloc(sizeof(int) * 65536);
  memset(portlookup, 255, sizeof(int) * 65536); /* 0xffffffff better always be (int) -1 */
  memset(csi.socklookup, 0, sizeof(csi.socklookup));

  if (scantype != RPC_SCAN) {
    /* Initialize our portlist (scan) */
    scan = (struct portinfo *) safe_zalloc(numports * sizeof(struct portinfo));
    for(i = 0; i < numports; i++) {
      scan[i].state = PORT_FRESH;
      scan[i].portno = portarray[i];
      scan[i].trynum = 0;
      scan[i].prev = i-1;
      scan[i].sd[0] = scan[i].sd[1] = scan[i].sd[2] = -1;
      if (i < numports -1 ) scan[i].next = i+1;
      else scan[i].next = -1;
      portlookup[portarray[i]] = i;
    }
    current = pil.testinglist = &scan[0]; /* testinglist is a list of all 
					     ports that haven't been determined 					    to be closed yet */
  }
   
  /* Init our raw socket */
  if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || 
      (scantype == ACK_SCAN)) {  
    if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      pfatal("socket troubles in pos_scan");
    /* We do not wan't to unblock the socket since we want to wait 
       if kernel send buffers fill up rather than get ENOBUF, and
       we won't be receiving on the socket anyway 
       unblock_socket(rawsd);*/

    broadcast_socket(rawsd);
    

    /* Init ISNs */
    get_random_bytes(sequences, sizeof(sequences));

    /* Now for the pcap opening nonsense ...
       Note that the snaplen is 100 = 64 byte max IPhdr + 24 byte max 
       link_layer header + first 12 bytes of TCP header.
    */
    
    pd = my_pcap_open_live(target->device, 100,  (o.spoofsource)? 1 : 0, 20);
    
    flt_srchost = target->v4host().s_addr;
    flt_dsthost = target->v4source().s_addr;

    snprintf(filter, sizeof(filter), "dst host %s and (icmp or (tcp and src host %s))", inet_ntoa(target->v4source()), target->targetipstr());

    set_pcap_filter(target, pd, flt_icmptcp, filter);

    if (o.scanflags != -1) scanflags = o.scanflags;
    else if (scantype == SYN_SCAN)
      scanflags = TH_SYN;
    else
      scanflags = TH_ACK;
  } else if (scantype == CONNECT_SCAN) {
    rawsd = -1;
    /* Init our sock */
    if (target->TargetSockAddr(&sock, &socklen) != 0) {
      fatal("Failed to get target socket address in pos_scan");
    }
  } else if (scantype == RPC_SCAN) {
    get_rpc_procs(&(rsi.rpc_progs), &(rsi.rpc_number));
    scan = (struct portinfo *) safe_malloc(rsi.rpc_number * sizeof(struct portinfo));
    for(j = 0; j < rsi.rpc_number; j++) {
      scan[j].state = PORT_FRESH;
      scan[j].portno = rsi.rpc_progs[j];
      scan[j].trynum = 0;
      scan[j].prev = j-1;
      scan[j].sd[0] = scan[j].sd[1] = scan[j].sd[2] = -1;
      if (j < rsi.rpc_number -1 ) scan[j].next = j+1;
      else scan[j].next = -1;
    }
    current = pil.testinglist = &scan[0]; 
    rawsd = -1;
    rsi.rpc_current_port = NULL; 
  } else {
    fatal("Unknown scan type given to pos_scan()");
  }

  starttime = time(NULL);

  if (scantype != SYN_SCAN)
    ack_number = get_random_uint();
  else ack_number = 0;

  do {
    ss.changed = 0;
    if (tries > 3 && tries < 10) {
      senddelay += 10000 * (tries - 3); 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by %d (to %d), due to excessive drops\n", 10000 * (tries - 3), senddelay);
    } else if (tries >= 10) {
      senddelay += 75000; 
      if (o.verbose) log_write(LOG_STDOUT, "Bumping up senddelay by 75000 (to %d), due to excessive drops\n", senddelay);
    }
    
    if (senddelay > 200000) {
      ss.max_width = MIN(ss.max_width, 5);
      ss.numqueries_ideal = MIN(ss.max_width, ss.numqueries_ideal);
    }

    if (target->timedout)
      goto posscan_timedout;

    /* Find a good port to scan if we are rpc scanning */
    if (scantype == RPC_SCAN) {
      /* Make sure we have ports left to scan */
      while(1) {
	rsi.rpc_current_port = target->ports.nextPort(rsi.rpc_current_port,
						      0, PORT_OPEN, true);
	// When service scan is in use, we only want to scan ports that have already
	// been determined to be RPC

	if (!o.servicescan)
	  break; // We do all open ports if no service scan
	if (!rsi.rpc_current_port) 
	  break; // done!
	rsi.rpc_current_port->getServiceDeductions(&sd);
	if (sd.name && sd.service_tunnel == SERVICE_TUNNEL_NONE && strcmp(sd.name, "rpc") == 0)
	  break; // Good - an RPC port for us to scan.
      }

      if (!rsi.rpc_current_port) /* Woop!  Done! */ break;

      /* Reinit our testinglist so we try each RPC prog */
      pil.testinglist = &scan[0];
      rsi.valid_responses_this_port = 0;
      rsi.rpc_status = RPC_STATUS_UNKNOWN;
      rpcportsscanned++;
    }

    // This initial message is way down here because we don't want to print it if
    // no RPC ports need scanning.
    if (o.verbose && !printedinitialmsg) {
      struct tm *tm = localtime(&starttime);
      assert(tm);
      log_write(LOG_STDOUT, "Initiating %s against %s at %02d:%02d\n", scantype2str(scantype), target->NameIP(hostname, sizeof(hostname)), tm->tm_hour, tm->tm_min);
      printedinitialmsg = true;
    }


    while(pil.testinglist != NULL)  /* While we have live queries or more ports to scan */
      {
	/* Check the possible retransmissions first */
	gettimeofday(&now, NULL);
      
	/* Insure we haven't overrun our allotted time ... */
	if (o.host_timeout && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto posscan_timedout;
	  }

	/* Check if we should be in firewall mode and occasionally make 
	   related adjustments*/
	check_firewallmode(target, &ss);

	for( current = pil.testinglist; current ; current = next) {
	  /* For each port or RPC program */
	  next = (current->next > -1)? &scan[current->next] : NULL;
	  if (current->state == PORT_TESTING) {
	    if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	      if (current->trynum > 1 ||
		  (current->trynum > 0 && target->firewallmode.active)) {
		/* No responses !#$!#@$ firewalled? */
		if (scantype == RPC_SCAN) {
		  if (rsi.valid_responses_this_port == 0) {	       
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "RPC Scan giving up on port %hu proto %d due to repeated lack of response\n", rsi.rpc_current_port->portno,  rsi.rpc_current_port->proto);
		    }
		    rsi.rpc_status = RPC_STATUS_NOT_RPC;
		    break;
		  }
		  else {
		    /* I think I am going to slow down a little */
		    target->to.rttvar = MIN(2000000, (int) (target->to.rttvar * 1.2));
		  }	      
		}
		if (o.debugging > 2) { log_write(LOG_STDOUT, "Moving port or prog %lu to the potentially firewalled list\n", current->portno); }
		target->firewallmode.nonresponsive_ports++;
		current->state = PORT_FIREWALLED; /* For various reasons */
		/* First delete from old list */
		if (current->next > -1) scan[current->next].prev = current->prev;
		if (current->prev > -1) scan[current->prev].next = current->next;
		if (current == pil.testinglist)
		  pil.testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		current->next = -1;
		current->prev = -1;
		/* Now move into new list */
		if (scantype != RPC_SCAN) {	      
		  if (!pil.firewalled) pil.firewalled = current;
		  else {
		    current->next = pil.firewalled - scan;
		    pil.firewalled = current;
		    scan[current->next].prev = current - scan;	      
		  }
		}
		if (scantype == CONNECT_SCAN) {
		  /* close the appropriate sd for each try */
		  for(i=0; i <= current->trynum; i++) {
		    if (current->sd[i] >= 0) {
		      csi.socklookup[current->sd[i]] = NULL;
		      FD_CLR(current->sd[i], &csi.fds_read);
		      FD_CLR(current->sd[i], &csi.fds_write);
		      FD_CLR(current->sd[i], &csi.fds_except);
		      close(current->sd[i]);
		      current->sd[i] = -1;
		      ss.numqueries_outstanding--;
		    }
		  }
		} else { ss.numqueries_outstanding--; }
	      } else {  /* timeout ... we've got to resend */
		if (o.scan_delay) enforce_scan_delay(NULL);
		if (o.debugging > 2) { log_write(LOG_STDOUT, "Timeout, resending to portno/progno %lu\n", current->portno); }
		current->trynum++;
		gettimeofday(&current->sent[current->trynum], NULL);
		now = current->sent[current->trynum];
		if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || (scantype == ACK_SCAN)) {	      
		  if (o.fragscan)
		    send_small_fragz_decoys(rawsd, target->v4hostip(), o.ttl, sequences[current->trynum], o.magic_port_set? o.magic_port : o.magic_port + tries * 3 + current->trynum, current->portno, scanflags);
		  else 
		    send_tcp_raw_decoys(rawsd, target->v4hostip(), o.ttl,
		    			o.magic_port_set? o.magic_port : 
					o.magic_port + tries * 3 + current->trynum, 
					current->portno, 
					sequences[current->trynum], 
					ack_number, scanflags, 0, NULL, 0, 
					o.extra_payload, 
					o.extra_payload_length);

		} else if (scantype == RPC_SCAN) {
		  if (send_rpc_query(target->v4hostip(), rsi.rpc_current_port->portno,
				     rsi.rpc_current_port->proto, 
				     current->portno, current - scan, 
				     current->trynum) == -1) {
		    /* Futz, I'll give up on this guy ... */
		    rsi.rpc_status = RPC_STATUS_NOT_RPC;
		    break;
		  }
		} else { /* Connect scan */
		  /* Unfortunately, retries cost us a socket!  If we are
		     out of sockets, we must drop one of our earlier tries
		     :( */
		  if (ss.numqueries_outstanding >= ss.max_width) {		
		    victim = -1;
		    for(i=0; i < current->trynum; i++)
		      if (current->sd[i] >= 0) {
			victim = i;
			break;
		      }
		    if (victim == -1) 
		      fatal("Illegal situation in pos_scan -- please report to fyodor@dhp.com");
		    csi.socklookup[current->sd[victim]] = NULL;
		    FD_CLR(current->sd[victim], &csi.fds_read);
		    FD_CLR(current->sd[victim], &csi.fds_write);
		    FD_CLR(current->sd[victim], &csi.fds_except);
		    close(current->sd[victim]);
		    current->sd[victim] = -1;
		  } else {
		    ss.numqueries_outstanding++;
		  }
		  res = socket(o.af(), SOCK_STREAM, IPPROTO_TCP);
		  if (res == -1) pfatal("Socket troubles in pos_scan 143");
		  csi.socklookup[res] = current;
		  unblock_socket(res);
		  init_socket(res);
		  if (sin->sin_family == AF_INET)
		    sin->sin_port = htons(current->portno);
#if HAVE_IPV6
		  else sin6->sin6_port = htons(current->portno);
#endif
		  current->sd[current->trynum] = res;		
		  res =  connect(res,(struct sockaddr *)&sock, socklen);
		  if (res != -1) {
		    posportupdate(target, current, NULL, current->trynum, scan, &ss, scantype, PORT_OPEN, &pil, &csi);
		  } else {
		    switch(socket_errno()) {
		    case EINPROGRESS: /* The one I always see */
		    case EAGAIN:
		      /* GOOD REASON FOR THIS????block_socket(sockets[current_socket]); */
		      if (csi.maxsd < current->sd[current->trynum])
			csi.maxsd = current->sd[current->trynum];
		      FD_SET( current->sd[current->trynum], &csi.fds_write);
		      FD_SET( current->sd[current->trynum], &csi.fds_read);
		      FD_SET( current->sd[current->trynum], &csi.fds_except);
		      break;
		    default:
		      if (!connecterror) {	
			connecterror++;
			fprintf(stderr, "Strange error from connect (%d):", socket_errno());
			fflush(stdout);
			perror(""); /*falling through intentionally*/
		      }
		    case ECONNREFUSED:
		      posportupdate(target, current, NULL, current->trynum, scan, &ss, scantype, PORT_CLOSED, &pil, &csi);
		      break;
		    }  		  
		  }
		}
		if (senddelay) usleep(senddelay);
	      }
	    }
	  } else { 
	    if (current->state != PORT_FRESH) 
	      fatal("State mismatch!!@ %d", current->state);
	    /* current->state == PORT_FRESH */
	    /* OK, now we have gone through our list of in-transit queries, so now
	       we try to send off new queries if we can ... */
	    if (ss.numqueries_outstanding >= (int) ss.numqueries_ideal) break;
	    if (o.scan_delay) enforce_scan_delay(NULL);
	    if (o.debugging > 2) log_write(LOG_STDOUT, "Sending initial query to port/prog %lu\n", current->portno);
	    /* Otherwise lets send a packet! */
	    current->state = PORT_TESTING;
	    current->trynum = 0;
	    /*	if (!testinglist) testinglist = current; */
	    ss.numqueries_outstanding++;
	    gettimeofday(&current->sent[0], NULL);
	    if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || 
		(scantype == ACK_SCAN)) {	  
	      if (o.fragscan)
		send_small_fragz_decoys(rawsd, target->v4hostip(), o.ttl, sequences[current->trynum], o.magic_port_set? o.magic_port : o.magic_port + tries * 3, current->portno, scanflags);
	      else
		send_tcp_raw_decoys(rawsd, target->v4hostip(), o.ttl, 
				    o.magic_port_set? o.magic_port : o.magic_port + tries * 3, current->portno,
				    sequences[current->trynum], ack_number, 
				    scanflags, 0, NULL, 0, o.extra_payload, 
				    o.extra_payload_length);
	    } else if (scantype == RPC_SCAN) {
	      if (send_rpc_query(target->v4hostip(), rsi.rpc_current_port->portno,
				 rsi.rpc_current_port->proto, current->portno, 
				 current - scan, current->trynum) == -1) {
		/* Futz, I'll give up on this guy ... */
		rsi.rpc_status = RPC_STATUS_NOT_RPC;
		break;
	      }
	    } else { /* CONNECT SCAN */
	      res = socket(o.af(), SOCK_STREAM, IPPROTO_TCP);
	      if (res == -1) pfatal("Socket troubles in pos_scan 11234");
#ifdef WIN32
	      if(res > 2047)
		    fatal("got sd > 2047 in pos_scan\n");
#endif
	      csi.socklookup[res] = current;
	      unblock_socket(res);
	      init_socket(res);
	      if (sin->sin_family == AF_INET)
		sin->sin_port = htons(current->portno);
#if HAVE_IPV6
	      else sin6->sin6_port = htons(current->portno);
#endif
	      current->sd[current->trynum] = res;		
	      res =  connect(res,(struct sockaddr *)&sock, socklen);
	      if (res != -1) {
		posportupdate(target, current, NULL, current->trynum, scan, &ss, scantype, PORT_OPEN, &pil, &csi);
	      } else {
		switch(socket_errno()) {
		case EINPROGRESS: /* The one I always see */
		case EAGAIN:
		  /* GOOD REASON FOR THIS????block_socket(sockets[current_socket]); */
		  if (csi.maxsd < current->sd[current->trynum])
		    csi.maxsd = current->sd[current->trynum];
		  FD_SET( current->sd[current->trynum], &csi.fds_write);
		  FD_SET( current->sd[current->trynum], &csi.fds_read);
		  FD_SET( current->sd[current->trynum], &csi.fds_except);
		  break;
		default:
		  if (!connecterror) {	
		    connecterror++;
		    fprintf(stderr, "Strange error from connect (%d):", socket_errno());
		    fflush(stdout);
		    perror(""); /*falling through intentionally*/
		  }
		case ECONNREFUSED:
		  posportupdate(target, current, NULL, current->trynum, scan, &ss, scantype, PORT_CLOSED, &pil, &csi);
		  break;
		}  		  
	      }	    
	    }
	    if (senddelay) usleep(senddelay);
	  }
	}
	if (o.debugging > 1) log_write(LOG_STDOUT, "Ideal number of queries: %d outstanding: %d max %d ports_left %d timeout %d senddelay: %dus\n", (int) ss.numqueries_ideal, ss.numqueries_outstanding, ss.max_width, ss.ports_left, target->to.timeout, senddelay);

	/* Now that we have sent the packets we wait for responses */
	ss.alreadydecreasedqueries = 0;
	if ((scantype == SYN_SCAN) || (scantype == WINDOW_SCAN) || (scantype == ACK_SCAN))
	  get_syn_results(target, scan, &ss, &pil, portlookup, pd, sequences, scantype);
	else if (scantype == RPC_SCAN) {
	  /* We only bother worrying about responses if we haven't reached
	     a conclusion yet */
	  if (rsi.rpc_status == RPC_STATUS_UNKNOWN) {	  
	    get_rpc_results(target, scan, &ss, &pil, &rsi);
	  }
	  if (rsi.rpc_status != RPC_STATUS_UNKNOWN)
	    break;
	}
	else {
	  get_connect_results(target, scan, &ss, &pil, portlookup, sequences, &csi);	
	}


	/* I want to reverse the order of all PORT_TESTING entries in
           the list -- this way if an intermediate router along the
           way got overloaded and dropped the last X packets, they are
           likely to get through (and flag us a problem if responsive)
           if we let them go first in the next round */
	reverse_testing_order(&pil, scan);

	/* If we timed out while trying to get results -- we're outta here! */
	if (target->timedout)
	  goto posscan_timedout;
      }

    if (scantype == RPC_SCAN) {
      /* Now we figure out the results of the port we just RPC scanned */

      rsi.rpc_current_port->setRPCProbeResults(rsi.rpc_status, rsi.rpc_program, 
					       rsi.rpc_lowver, rsi.rpc_highver);

      /* Time to put our RPC program scan list back together for the
	 next port ... */
      for(j = 0; j < rsi.rpc_number; j++) {
	scan[j].state = PORT_FRESH;
	scan[j].trynum = 0;
	scan[j].prev = j-1;
	if (j < rsi.rpc_number -1 ) scan[j].next = j+1;
	else scan[j].next = -1;
      }
      current = pil.testinglist = &scan[0]; 
      pil.firewalled = NULL;
      ss.numqueries_outstanding = 0;
      /* Now we out o' here! */
      continue;
    }

    if (ss.numqueries_outstanding != 0) {
      fatal("Bean counting error no. 4321897: ports_left: %d numqueries_outstanding: %d\n", ss.ports_left, ss.numqueries_outstanding);
    }

    /* We only want to try again if the 'firewalled' list contains
       elements, meaning that some ports timed out.  We retry until
       nothing changes for a round (not counting the very first
       round).  We don't retry if aggressive timing is being used and
       the vast majority of ports are filtered, since this is more
       likely a deny-by-default firewall than a packet loss indicator.  */
    if (pil.firewalled) {
      bool limitedfiltering = (double) target->firewallmode.nonresponsive_ports / (target->firewallmode.responsive_ports + target->firewallmode.nonresponsive_ports) < 0.1;
      if ((limitedfiltering || o.timing_level < 4) && (tries == 0 || ss.changed)) {	
	pil.testinglist = pil.firewalled;
	for( current = pil.testinglist; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  current->state = PORT_FRESH;
	  current->trynum = 0;
	  current->sd[0] = current->sd[1] = current->sd[2] = -1;
	}
	pil.firewalled = NULL;
      } else {
	/* Consider the ports firewalled */	
	for( current = pil.firewalled; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  target->ports.addPort(current->portno, IPPROTO_TCP, NULL, PORT_FIREWALLED);
	}
	pil.testinglist = NULL;
      }
    }

    tries++;

    if (o.debugging) {
      log_write(LOG_STDOUT, "Finished round #%d. Current stats: numqueries_ideal: %d; min_width: %d; max_width: %d; packet_incr: %d; senddelay: %dus; fallback: %d%%\n", tries, (int) ss.numqueries_ideal, ss.min_width, ss.max_width, ss.packet_incr, senddelay, (int) (100 * ss.fallback_percent));
    }
    ss.numqueries_ideal = ss.initial_packet_width;
    
  } while(pil.testinglist && tries < 20);
  
  if (tries == 20) {
    error("WARNING: GAVE UP ON SCAN AFTER 20 RETRIES");
  }

  if (scantype == RPC_SCAN) numports = rpcportsscanned;
  if (o.verbose && numports > 0)
    log_write(LOG_STDOUT, "The %s took %ld %s to scan %d ports.\n", scantype2str(scantype),  (long) time(NULL) - starttime, (((long) time(NULL) - starttime) == 1)? "second" : "seconds", numports);
  


 posscan_timedout:
  
  free(scan);
  if (rawsd >= 0) 
    close(rawsd);
  if (pd)
    pcap_close(pd);
  if (scantype == RPC_SCAN)
    close_rpc_query_sockets();
  free(portlookup);
  return;
}

/* FTP bounce attack scan.  This function is rather lame and should be
   rewritten.  But I don't think it is used much anyway.  If I'm going to
   allow FTP bounce scan, I should really allow SOCKS proxy scan.  */
void bounce_scan(Target *target, u16 *portarray, int numports,
		 struct ftpinfo *ftp) {
  time_t starttime;
  int res , sd = ftp->sd,  i=0;
  const char *t = (const char *)target->v4hostip(); 
  int retriesleft = FTP_RETRIES;
  char recvbuf[2048]; 
  char targetstr[20];
  char command[512];
  char hostname[1200];
  unsigned short portno,p1,p2;
  struct timeval now;

  if (! numports) return;		 /* nothing to scan for */

  snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));

  starttime = time(NULL);
  if (o.verbose || o.debugging) {
    struct tm *tm = localtime(&starttime);
    assert(tm);
    log_write(LOG_STDOUT, "Initiating TCP ftp bounce scan against %s at %02d:%02d\n", target->NameIP(hostname, sizeof(hostname)), tm->tm_hour, tm->tm_min );
  }
  for(i=0; i < numports; i++) {

    /* Check for timeout */
    if (o.host_timeout) {
      gettimeofday(&now, NULL);
      if ((TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	{
	  target->timedout = 1;
	  return;
	}
    }

    portno = htons(portarray[i]);
    p1 = ((unsigned char *) &portno)[0];
    p2 = ((unsigned char *) &portno)[1];
    snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1,p2);
    if (o.debugging) log_write(LOG_STDOUT, "Attempting command: %s", command);
    if (send(sd, command, strlen(command), 0) < 0 ) {
      perror("send in bounce_scan");
      if (retriesleft) {
	if (o.verbose || o.debugging) 
	  log_write(LOG_STDOUT, "Our ftp proxy server hung up on us!  retrying\n");
	retriesleft--;
	close(sd);
	ftp->sd = ftp_anon_connect(ftp);
	if (ftp->sd < 0) return;
	sd = ftp->sd;
	i--;
      }
      else {
	fprintf(stderr, "Our socket descriptor is dead and we are out of retries. Giving up.\n");
	close(sd);
	ftp->sd = -1;
	return;
      }
    } else { /* Our send is good */
      res = recvtime(sd, recvbuf, 2048,15);
      if (res <= 0) perror("recv problem from ftp bounce server\n");
  
      else { /* our recv is good */
	recvbuf[res] = '\0';
	if (o.debugging) log_write(LOG_STDOUT, "result of port query on port %i: %s", 
				 portarray[i],  recvbuf);
	if (recvbuf[0] == '5') {
	  if (portarray[i] > 1023) {
	    fprintf(stderr, "Your ftp bounce server sucks, it won't let us feed bogus ports!\n");
	    exit(1);
	  }
	  else {
	    fprintf(stderr, "Your ftp bounce server doesn't allow privileged ports, skipping them.\n");
	    while(i < numports && portarray[i] < 1024) i++;
	    if (!portarray[i]) {
	      fprintf(stderr, "And you didn't want to scan any unpriviliged ports.  Giving up.\n");
	      /*	  close(sd);
			  ftp->sd = -1;
			  return *ports;*/
	      /* screw this gentle return crap!  This is an emergency! */
	      exit(1);
	    }
	  }  
	}
	else  /* Not an error message */
	  if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
	    res = recvtime(sd, recvbuf, 2048,12);
	    if (res <= 0) {
	      perror("recv problem from ftp bounce server\n");
	    }
	    else {
	      recvbuf[res] = '\0';
	      if (o.debugging) log_write(LOG_STDOUT, "result of LIST: %s", recvbuf);
	      if (!strncmp(recvbuf, "500", 3)) {
		/* fuck, we are not aligned properly */
		if (o.verbose || o.debugging)
		  fprintf(stderr, "FTP command misalignment detected ... correcting.\n");
		res = recvtime(sd, recvbuf, 2048,10);
	      }
	      if (recvbuf[0] == '1' || recvbuf[0] == '2') {
		target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, PORT_OPEN);
		if (recvbuf[0] == '1') {
		  res = recvtime(sd, recvbuf, 2048,5);
		  recvbuf[res] = '\0';
		  if (res > 0) {
		    if (o.debugging) log_write(LOG_STDOUT, "nxt line: %s", recvbuf);
		    if (recvbuf[0] == '4' && recvbuf[1] == '2' && 
			recvbuf[2] == '6') {	      	
		      target->ports.removePort(portarray[i], IPPROTO_TCP);
		      if (o.debugging || o.verbose)
			log_write(LOG_STDOUT, "Changed my mind about port %i\n", portarray[i]);
		    }
		  }
		}
	      } else {
		/* This means the port is closed ... */
		target->ports.addPort(portarray[i], IPPROTO_TCP, NULL, PORT_CLOSED);
	      }
	    }
	  }
      }
    }
  }

  if (o.debugging || o.verbose) 
    log_write(LOG_STDOUT, "Scanned %d ports in %ld seconds via the Bounce scan.\n",
	    numports, (long) time(NULL) - starttime);
  return;
}

/* Handles the scan types where no positive-acknowledgement of open
   port is received (those scans are in pos_scan).  Super_scan
   includes scans such as FIN/XMAS/NULL/Maimon/UDP and IP Proto scans */
void super_scan(Target *target, u16 *portarray, int numports,
		stype scantype) {
  int initial_packet_width;  /* How many scan packets in parallel (to start with) */
  int packet_incr = 4; /* How much we increase the parallel packets by each round */
  double fallback_percent = 0.7;
  int rawsd;
  int scanflags = 0;

  int dropped = 0;  /* These three are for UDP squelching */
  int freshportstried = 0;
  int senddelay = 0;
  pcap_t *pd;
  unsigned int bytes;
  struct ip *ip, *ip2;
  struct tcphdr *tcp;
  char filter[512];
  int changed = 0;  /* Have we found new ports (or rejected earlier "found" ones) this round? */
  int numqueries_outstanding = 0; /* How many unexpired queries are on the 'net right now? */
  double numqueries_ideal; /* How many do we WANT to be on the 'net right now? */
  int max_width; /* No more packets than this at once, pleeze */
  int min_width; /* At least this many at once */
  int tries = 0;
  int tmp = 0;
  time_t starttime;
  u16 newport;
  int newstate = 999; /* This ought to break something if used illegally */
  struct portinfo *scan, *openlist, *current, *testinglist, *next;
  int *portlookup; /* Indexes port number -> scan[] index */
  struct timeval now, end;
  int packcount, timedout;
  int UDPPacketWarning = 0;
  int i;
  u16 *data;
  int packet_trynum = 0;
  int windowdecrease = 0; /* Has the window been decreased this round yet? */
  struct icmp *icmp;
  int portno;
  Port *current_port_tmp;
  char hostname[1200];

  if (target->timedout)
    return;

  if (! numports) return;		 /* nothing to scan for */

  if (o.debugging) 
    log_write(LOG_STDOUT, "Starting super_scan\n");

  max_width = (o.max_parallelism)? o.max_parallelism : 125;
  min_width = 1;
  min_width = (o.min_parallelism)? o.min_parallelism :
    (o.timing_level == 4)? 10 :
    (o.timing_level == 5)? 20 : 1;
  numqueries_ideal = initial_packet_width = MAX(min_width, MIN(max_width, 10));

  portlookup = (int *) safe_malloc(sizeof(int) * 65536);
  memset(portlookup, 255, 65536 * sizeof(int)); /* 0xffffffff better always be (int) -1 */
  scan = (struct portinfo *) safe_malloc(numports * sizeof(struct portinfo));

  /* Initialize timeout info */
  /*
    target->to.srtt = (target->rtt > 0)? 4 * target->rtt : 1000000;
    target->to.rttvar = (target->rtt > 0)? target->rtt / 2 : 1000000;
    target->to.timeout = target->to.srtt + 4 * target->to.rttvar;
  */

  /* Initialize our portlist (scan) */
  for(i = 0; i < numports; i++) {
    scan[i].state = PORT_FRESH;
    scan[i].portno = portarray[i];
    scan[i].trynum = 0;
    scan[i].prev = i-1;
    if (i < numports -1 ) scan[i].next = i+1;
    else scan[i].next = -1;
    portlookup[portarray[i]] = i;
  }

  current = testinglist = &scan[0]; /* fresh == unscanned ports, testinglist is a list of all ports that haven't been determined to be closed yet */
  openlist = NULL; /* we haven't shown any ports to be open yet... */


    
  /* Init our raw socket */
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket troubles in super_scan");
  broadcast_socket(rawsd); /* This isn't pretty, but I don't have much of a
			      choice */
  /* No reason to do this since we don't receive on this socket,
     and it can cause ENOBUF errors if socket transmit buffers
     overflow 
     unblock_socket(rawsd);
  */

  /* Now for the pcap opening nonsense ... */
  /* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
   * header + 4 bytes of TCP port info.
   */
  pd = my_pcap_open_live(target->device, 92,  (o.spoofsource)? 1 : 0, 10);


  flt_srchost = target->v4host().s_addr;
  flt_dsthost = target->v4source().s_addr;
  flt_baseport = o.magic_port;

  snprintf(filter, sizeof(filter), "(icmp and dst host %s) or (tcp and src host %s and dst host %s and ( dst port %d or dst port %d))", inet_ntoa(target->v4source()), target->targetipstr(), inet_ntoa(target->v4source()), o.magic_port , o.magic_port + 1);

  set_pcap_filter(target, pd, flt_icmptcp_2port, filter);

  if (o.scanflags != -1) scanflags = o.scanflags;
  else if (scantype == XMAS_SCAN) scanflags = TH_FIN|TH_URG|TH_PUSH;
  else if (scantype == NULL_SCAN) scanflags = 0;
  else if (scantype == FIN_SCAN) scanflags = TH_FIN;
  else if (scantype == MAIMON_SCAN) scanflags = TH_FIN|TH_ACK;
  else if (scantype != UDP_SCAN && scantype != IPPROT_SCAN) {
    fatal("Unknown scan type for super_scan"); }

  starttime = time(NULL);

  if (o.debugging || o.verbose) {
    struct tm *tm = localtime(&starttime);
    assert(tm);
    log_write(LOG_STDOUT, "Initiating %s against %s at %02d:%02d\n", scantype2str(scantype), target->NameIP(hostname, sizeof(hostname)), tm->tm_hour, tm->tm_min);
  }

  do {
    changed = 0;
    if (tries > 3 && senddelay == 0) senddelay = 10000; 
							   
    while(testinglist != NULL)  /* While we have live queries or more ports to scan */
      {
	/* Check the possible retransmissions first */
	gettimeofday(&now, NULL);

	/* Insure we haven't overrun our allotted time ... */
	if (o.host_timeout && numqueries_outstanding > 0 && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto superscan_timedout;
	  }

	for( current = testinglist; current ; current = next) {
	  next = (current->next > -1)? &scan[current->next] : NULL;
	  if (current->state == PORT_TESTING) {
	    if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	      if (current->trynum > 0) {
		/* We consider this port valid, move it to open list */
		if (o.debugging > 1) { log_write(LOG_STDOUT, "Moving port %lu to the open list\n", current->portno); }
		freshportstried--;
		current->state = PORT_OPEN;
		/* First delete from old list */
		if (current->next > -1) scan[current->next].prev = current->prev;
		if (current->prev > -1) scan[current->prev].next = current->next;
		if (current == testinglist)
		  testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		current->next = current->prev = -1;

		/* Now move into new list */
		if (!openlist) openlist = current;
		else {
		  current->next = openlist - scan;
		  openlist = current;
		  scan[current->next].prev = current - scan;	      
		}
		numqueries_outstanding--;
	      } else {
		/* Initial timeout ... we've got to resend */
		if (o.scan_delay) enforce_scan_delay(NULL);
		if (o.debugging > 1) { log_write(LOG_STDOUT, "Initial timeout, resending to portno %lu\n", current->portno); }
		current->trynum++;
		/* If they didn't specify the magic port, we use magic_port +1
		   so we can tell that it was a retransmit later */
		i = (o.magic_port_set)? o.magic_port : o.magic_port + 1;
		gettimeofday(&current->sent[1], NULL);
		now = current->sent[1];
		if (o.fragscan)
		  send_small_fragz_decoys(rawsd, target->v4hostip(), 0, o.ttl, i, current->portno, scanflags);
		else if (scantype == UDP_SCAN)
		  send_udp_raw_decoys(rawsd, target->v4hostip(), o.ttl, i,
				      current->portno, get_random_u16(), o.extra_payload, o.extra_payload_length);
		else if (scantype == IPPROT_SCAN)
		  send_ip_raw_decoys(rawsd, target->v4hostip(), o.ttl, current->portno, o.extra_payload, o.extra_payload_length);
		else
		  send_tcp_raw_decoys(rawsd, target->v4hostip(), o.ttl, i,
				      current->portno, 0, 0, scanflags, 0, NULL, 0,
				      o.extra_payload, o.extra_payload_length);
		if (senddelay &&
		    (scantype == UDP_SCAN || scantype == IPPROT_SCAN))
		  usleep(senddelay);
	      }
	    }
	  } else { 
	    /* current->state == PORT_FRESH */
	    /* OK, now we have gone through our list of in-transit queries, 
	       so now we try to send off new queries if we can ... */
	    if (numqueries_outstanding >= (int) numqueries_ideal) break;
	    if (o.scan_delay) enforce_scan_delay(NULL);
	    if (o.debugging > 1) log_write(LOG_STDOUT, "Sending initial query to port %lu\n", current->portno);
	    freshportstried++;
	    /* lets send a packet! */
	    current->state = PORT_TESTING;
	    /*	if (!testinglist) testinglist = current; */
	    numqueries_outstanding++;
	    gettimeofday(&current->sent[0], NULL);
	    if (o.fragscan)
	      send_small_fragz_decoys(rawsd, target->v4hostip(), 0, o.ttl, o.magic_port, current->portno, scanflags);
	    else if (scantype == UDP_SCAN)
	      send_udp_raw_decoys(rawsd, target->v4hostip(), o.ttl,
			      	  o.magic_port, current->portno,
				  get_random_u16(), o.extra_payload, 
				  o.extra_payload_length);
	    else if (scantype == IPPROT_SCAN)
	      send_ip_raw_decoys(rawsd, target->v4hostip(), o.ttl,
				 current->portno, o.extra_payload, o.extra_payload_length);
	    else
	      send_tcp_raw_decoys(rawsd, target->v4hostip(), o.ttl,
	      			  o.magic_port, 
				  current->portno, 0, 0, scanflags, 0, NULL, 0,
				  o.extra_payload, o.extra_payload_length);
	    if ((scantype == UDP_SCAN || scantype == IPPROT_SCAN) &&
		senddelay)
	      usleep(senddelay);
	  }
	}

	if (o.debugging > 1) log_write(LOG_STDOUT, "Ideal number of queries: %d\n", (int) numqueries_ideal);
	tmp++;
	/* Now that we have sent the packets we wait for responses */
	windowdecrease = 0;
	timedout = packcount = 0;
	gettimeofday(&now, NULL);
	if (o.host_timeout && (TIMEVAL_MSEC_SUBTRACT(now, target->host_timeout) >= 0))
	  {
	    target->timedout = 1;
	    goto superscan_timedout;
	  }
	while (!timedout && numqueries_outstanding > 0 && ( ip = (struct ip*) readip_pcap(pd, &bytes, target->to.timeout, &end)))
	  {
	    if (++packcount >= 30) {
	      /* We don't want to allow for the possibility if this going
		 forever */
	      if (TIMEVAL_SUBTRACT(end, now) > 8000000)
		timedout = 1;
	    }
	    if (bytes < (4 * ip->ip_hl) + 4U)
	      continue;	
	    current = NULL;
	    if (ip->ip_p == IPPROTO_ICMP ||
		ip->ip_src.s_addr == target->v4host().s_addr) {
	      if (ip->ip_p == IPPROTO_TCP) {
		tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
		if (tcp->th_flags & TH_RST) {	    
		  newstate = PORT_CLOSED;
		  newport = ntohs(tcp->th_sport);
		  if (portlookup[newport] < 0) {
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "Strange packet from port %d:\n", ntohs(tcp->th_sport));
		      readtcppacket((unsigned char *)ip, bytes);
		    }
		    current = NULL;
		    continue;
		  }	  
		  current = &scan[portlookup[newport]];
		
		  if (ntohs(tcp->th_dport) != o.magic_port && 
		      ntohs(tcp->th_dport) != o.magic_port + 1) {
		    if (o.debugging)  {		
		      error("BAD TCP packet detected to port %d from port %d", ntohs(tcp->th_dport), newport);
		    }
		    continue;		
		  }
		
		  if (current->state != PORT_TESTING && o.debugging) {
		    error("TCP packet detected from port %d which is in state %d (should usually be PORT_TESTING (but not always)", 
			  newport, current->state); 
		  }
		
		  if (!o.magic_port_set) {
		    packet_trynum = ntohs(tcp->th_dport) - o.magic_port;
		    if ((packet_trynum|1) != 1) packet_trynum = -1;
		  }  else packet_trynum = -1;
		  if (current->trynum == 0) packet_trynum = 0;
		} else { continue; } /* Wrong TCP flags */
	      
	      } else if (ip->ip_p == IPPROTO_ICMP) {
		icmp = (struct icmp *) ((char *)ip + 4 * ip->ip_hl);
		ip2 = (struct ip *) (((char *) icmp) + 8);
		if (ip2->ip_dst.s_addr != target->v4host().s_addr)
		  continue;
		data = (u16 *) ((char *)ip2 + 4 * ip2->ip_hl);
		/*	    log_write(LOG_STDOUT, "Caught ICMP packet:\n");
			    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */

		if (icmp->icmp_type == 3) {
		  if (scantype != IPPROT_SCAN)
		    newport = ntohs(data[1]);
		  else
		    newport = ip2->ip_p;
		  if (portlookup[newport] < 0) {
		    if (o.debugging) {
		      log_write(LOG_STDOUT, "Strange ICMP packet type 3 code %d related to port %d:\n", icmp->icmp_code, newport);
		      readtcppacket((unsigned char *)ip, bytes);		
		    }
		    continue;		
		  }
		  current = &scan[portlookup[newport]];
		  if (!o.magic_port_set) {
		    packet_trynum = ntohs(data[0]) - o.magic_port;
		    if ((packet_trynum|1) != 1) packet_trynum = -1;
		  } else {
		    if (current->trynum == 0)  {
		      packet_trynum = 0;
		    }
		    else packet_trynum = -1;
		  }
		
		  switch(icmp->icmp_code) {
		  
		  case 1: /* Host unreachable */
		  case 2: /* pr0t0c0l unreachable */
		    if (scantype == IPPROT_SCAN) {
		      newstate = PORT_CLOSED;
		    } else
		      newstate = PORT_FIREWALLED;
		    break;
		  
		  case 3: /* p0rt unreachable */		
		    if (scantype == UDP_SCAN && 
			ip->ip_src.s_addr == target->v4host().s_addr) {
		      newstate = PORT_CLOSED;
		    } else newstate = PORT_FIREWALLED;
		    break;
		  
		  case 9:
		  case 10:
		  case 13: /* Administratively prohibited packet */
		    newstate = PORT_FIREWALLED;
		    break;		
		  
		  default:
		    if (o.debugging) {
		      error("Received strange ICMP destunreach response -- code: %d", icmp->icmp_code);
		      hdump((unsigned char *)icmp, ntohs(ip->ip_len) - 
			    sizeof(struct ip));
		    }
		    continue;
		  }
		}
	      } else if (ip->ip_p == IPPROTO_UDP) {
		if (UDPPacketWarning == 0) {
		  UDPPacketWarning = 1;
		  if (o.debugging)
		    error("UDP packet received\n");
		}
		continue;
	      } else if (scantype == IPPROT_SCAN) {
		if (o.debugging)
		  error("packet with protocol %d received\n", ip->ip_p);
	      }
	    
	      if (current) {	  
		if (current->state == PORT_CLOSED && (packet_trynum < 0)) {
		  target->to.rttvar = (int) (target->to.rttvar * 1.2);
		  if (o.debugging) { log_write(LOG_STDOUT, "Late packet, couldn't figure out sendno so we do varianceincrease to %d\n", target->to.rttvar); 
		  }
		} 
		if (packet_trynum > -1) {		
		  /* Update our records */
		  adjust_timeouts2(&current->sent[packet_trynum], &end, &(target->to));
		  numqueries_ideal = MIN(numqueries_ideal + (packet_incr/numqueries_ideal), max_width);
		  if (packet_trynum > 0 && current->trynum > 0) {
		    /* The first packet was apparently lost, slow down */
		    dropped++;
		    if (freshportstried > 50 && ((double) dropped/freshportstried) > 0.3) {
		      if (!senddelay) senddelay = 50000;
		      else senddelay = MIN(senddelay * 2, 1000000);
		      if (senddelay >= 200000 &&
			  (scantype == UDP_SCAN || scantype == IPPROT_SCAN))
			max_width = MIN(max_width,2);
		      freshportstried = 0;
		      dropped = 0;
		      if (o.verbose || o.debugging )  
			log_write(LOG_STDOUT, "Too many drops ... increasing senddelay to %d\n", senddelay);
		    }
		    if (windowdecrease == 0) {
		      numqueries_ideal = MAX(min_width, numqueries_ideal * fallback_percent);
		      if (o.debugging) { log_write(LOG_STDOUT, "Lost a packet, decreasing window to %d\n", (int) numqueries_ideal);
		      windowdecrease++;
		      if (scantype == UDP_SCAN || scantype == IPPROT_SCAN)
			usleep(250000);
		      }
		    } else if (o.debugging > 1) { 
		      log_write(LOG_STDOUT, "Lost a packet, but not decreasing\n");
		    }
		  }
		}    
		if (current->state != newstate) {
		  changed++;
		}
		if (current->state != PORT_OPEN && 
		    current->state != PORT_CLOSED) {	    
		  numqueries_outstanding--;
		}
		if (current->state == PORT_TESTING && current == testinglist)
		  testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
		else if (current->state == PORT_OPEN && current == openlist)
		  openlist = (current->next >= 0)? &scan[current->next] : NULL;
		if (current->next >= 0) scan[current->next].prev = current->prev;
		if (current->prev >= 0) scan[current->prev].next = current->next;
		current->next = current->prev = -1;
		current->state = newstate;
		target->ports.addPort(current->portno, 
			(scantype == UDP_SCAN)? IPPROTO_UDP :
			  (scantype == IPPROT_SCAN? IPPROTO_IP: IPPROTO_TCP), 
			NULL, current->state);
	      }
	    }
	  }
      } 
  
    
    /* Prepare for retry */
    testinglist = openlist;
    for(current = openlist; current; current = (current->next >= 0)? &scan[current->next] : NULL) {
      current->state = PORT_FRESH;
      current->trynum = 0;
      if (o.debugging) { 
	log_write(LOG_STDOUT, "Preparing for retry, open port %lu noted\n", current->portno); 
      }
    }
    
    openlist = NULL;
    numqueries_ideal = initial_packet_width;
    if (o.debugging)
      log_write(LOG_STDOUT, "Done with round %d\n", tries);
    if (scantype == UDP_SCAN && changed && (tries + 1) < 100) {
      if (o.debugging) {
	log_write(LOG_STDOUT, "Sleeping for 1/2 second to overcome ICMP error rate limiting\n");
      }
      usleep(500000);
    }
  } while(changed && ++tries < 100);   

  openlist = testinglist;

  if (o.debugging || o.verbose)
    log_write(LOG_STDOUT, "The %s took %ld %s to scan %d ports.\n", scantype2str(scantype), (long) time(NULL) - starttime, (((long) time(NULL) - starttime) == 1)? "second" : "seconds",  numports);
  
  for (current = openlist; current;  current = (current->next >= 0)? &scan[current->next] : NULL) {
    if (scantype == IPPROT_SCAN)
      target->ports.addPort(current->portno, IPPROTO_IP, NULL, PORT_OPEN);
    else if (scantype != UDP_SCAN)
      target->ports.addPort(current->portno, IPPROTO_TCP, NULL, PORT_OPEN);
    else
      target->ports.addPort(current->portno, IPPROTO_UDP, NULL, PORT_OPEN);
  }

 superscan_timedout:

  free(scan);
  close(rawsd);
  pcap_close(pd);

  /* Super scan relies on us receiving a response if the port is
     CLOSED and no response if the port is OPEN.  A problem with
     this is that when a machine is doing heavy filtering, all ports
     will seem to be open.  Thus we add a little metric: if > 25
     ports were scanned and they are ALL considered open by this
     function, then it is reasonably to assume that the REAL reason
     they are all open is that they have been filtered. */
  if (numports > 25) {    
    if (scantype == UDP_SCAN) {
      if (target->ports.state_counts_udp[PORT_OPEN] == numports) {
	if (o.verbose) { 
	  error("(no udp responses received -- assuming all ports filtered)");
	}
	for(portno = 0; portno < 65536; portno++)
	  {
	    current_port_tmp = target->ports.lookupPort(portno, IPPROTO_UDP);
	    if (current_port_tmp) {
	      assert(current_port_tmp->state == PORT_OPEN);
	      current_port_tmp->state = PORT_FIREWALLED;
	      target->ports.state_counts[PORT_OPEN]--;
	      target->ports.state_counts[PORT_FIREWALLED]++;
	      target->ports.state_counts_udp[PORT_OPEN]--;
	      target->ports.state_counts_udp[PORT_FIREWALLED]++;
	    }
	  }
      }
    } else { 
      if (target->ports.state_counts_tcp[PORT_OPEN] == numports) {
	if (o.verbose) { 
	  error("(no tcp responses received -- assuming all ports filtered)");
	}
	for(portno = 0; portno < 65536; portno++)
	  {
	    current_port_tmp = target->ports.lookupPort(portno, IPPROTO_TCP);
	    if (current_port_tmp) {
	      assert(current_port_tmp->state == PORT_OPEN);
	      current_port_tmp->state = PORT_FIREWALLED;
	      target->ports.state_counts[PORT_OPEN]--;
	      target->ports.state_counts[PORT_FIREWALLED]++;
	      target->ports.state_counts_tcp[PORT_OPEN]--;
	      target->ports.state_counts_tcp[PORT_FIREWALLED]++;
	    }
	  }
      }
    }
  }
  free(portlookup);
  return;
}
