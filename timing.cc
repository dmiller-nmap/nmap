
/***************************************************************************
 * timing.cc -- Functions related to computing scan timing (such as        *
 * keeping track of and adjusting smoothed round trip times, statistical   *
 * deviations, timeout values, etc.  Various user options (such as the     *
 * timing policy (-T)) also play a role in these calculations              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1995-2003 Insecure.Com LLC. This       *
 * program is free software; you may redistribute and/or modify it under   *
 * the terms of the GNU General Public License as published by the Free    *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as   *
 * our remote OS fingerprinting database and code.                         *
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

#include "timing.h"
#include "NmapOps.h"

extern NmapOps o;

/* Adjust our timeout values based on the time the latest probe took for a 
   response.  We update our RTT averages, etc. */
void adjust_timeouts(struct timeval sent, struct timeout_info *to) {
  struct timeval received;
  gettimeofday(&received, NULL);

  adjust_timeouts2(&sent, &received, to);
  return;
}

/* Same as adjust_timeouts(), except this one allows you to specify
 the receive time too (which could be because it was received a while
 back or it could be for efficiency because the caller already knows
 the current time */
void adjust_timeouts2(const struct timeval *sent, 
		      const struct timeval *received, 
		      struct timeout_info *to) {
  long delta = 0;

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "Timeout vals: srtt: %d rttvar: %d to: %d ", to->srtt, to->rttvar, to->timeout);
  }

  delta = TIMEVAL_SUBTRACT(*received, *sent);

  /* Argh ... pcap receive time is sometimes a little off my
     getimeofday() results on various platforms :(.  So a packet may
     appear to be received as much as a hundredth of a second before
     it was sent.  So I will allow small negative RTT numbers */
  if (delta < 0 && delta > -50000) {
    if (o.debugging > 2)
      log_write(LOG_STDOUT, "Small negative delta (probably due to libpcap time / gettimeofday() discrepancy) - adjusting from %lius to %dus\n", delta, 10000);
    delta = 10000;
  }


  if (to->srtt == -1 && to->rttvar == -1) {
    /* We need to initialize the sucker ... */
    to->srtt = delta;
    to->rttvar = MAX(5000, MIN(to->srtt, 2000000));
    to->timeout = to->srtt + (to->rttvar << 2);
  }
  else {
    if (delta >= 8000000 || delta < 0) {
      if (o.verbose)
	error("adjust_timeout: packet supposedly had rtt of %lu microseconds.  Ignoring time.", delta);
      return;
    }
    delta -= to->srtt;
    /* sanity check 2*/
    if (delta > 1500000 && delta > 3 * to->srtt + 2 * to->rttvar) {
      /* WANKER ALERT! */
      if (o.debugging) {
	log_write(LOG_STDOUT, "Bogus delta: %ld (srtt %d) ... ignoring\n", delta, to->srtt);
      }
      return;
    }
    to->srtt += delta >> 3;
    to->rttvar += (ABS(delta) - to->rttvar) >> 2;
    to->timeout = to->srtt + (to->rttvar << 2);  
  }
  if (to->rttvar > 2300000) {
    fprintf(stderr, "RTTVAR has grown to over 2.3 seconds, decreasing to 2.0\n");
    to->rttvar = 2000000;
  }
  
  /* It hurts to do this ... it really does ... but otherwise we are being
     too risky */
  to->timeout = box(o.minRttTimeout() * 1000, o.maxRttTimeout() * 1000,  
		    to->timeout);

  if (o.scan_delay)
    to->timeout = MAX(to->timeout, o.scan_delay * 1000);

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "delta %ld ==> srtt: %d rttvar: %d to: %d\n", delta, to->srtt, to->rttvar, to->timeout);
  }

  if (to->srtt < 0 || to->rttvar < 0 || to->timeout < 0 || delta < -50000000 || 
      sent->tv_sec == 0 || received->tv_sec == 0 ) {
    fatal("Serious time computation problem in adjust_timeout ... received = (%ld, %ld) sent=(%ld,%ld) delta = %ld srtt = %d rttvar = %d to = %d", (long) received->tv_sec, (long)received->tv_usec, (long) sent->tv_sec, (long) sent->tv_usec, delta, to->srtt, to->rttvar, to->timeout);
  }
}

/* Sleeps if necessary to ensure that it isn't called twice withen less
   time than o.send_delay.  If it is passed a non-null tv, the POST-SLEEP
   time is recorded in it */
void enforce_scan_delay(struct timeval *tv) {
  static int init = -1;
  static struct timeval lastcall;
  struct timeval now;
  int time_diff;

  if (!o.scan_delay) {
    if (tv) gettimeofday(tv, NULL);
    return;
  }

  if (init == -1) {
    gettimeofday(&lastcall, NULL);
    init = 0;
    if (tv)
      memcpy(tv, &lastcall, sizeof(struct timeval));
    return;
  }

  gettimeofday(&now, NULL);
  time_diff = TIMEVAL_MSEC_SUBTRACT(now, lastcall);
  if (time_diff < o.scan_delay) {  
    if (o.debugging > 1) {
      printf("Sleeping for %d milliseconds in enforce_scan_delay()\n", o.scan_delay - time_diff);
    }
    usleep((o.scan_delay - time_diff) * 1000);
    gettimeofday(&lastcall, NULL);
  } else
    memcpy(&lastcall, &now, sizeof(struct timeval));
  if (tv) {
    memcpy(tv, &lastcall, sizeof(struct timeval));
  }

  return;    
}

