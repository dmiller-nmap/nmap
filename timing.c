
/***********************************************************************
 * timing.c -- Functions related to computing scan timing (such as     *
 * keeping track of and adjusting smoothed round trip times,           *
 * statistical deviations, timeout values, etc.  Various user options  *
 * (such as the timing policy (-T)) also play a role in these          *
 * calculations                                                        *
 *                                                                     *
 ***********************************************************************
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
 ***********************************************************************/

/* $Id$ */

#include "timing.h"

extern struct ops o;

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
  int delta = 0;

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "Timeout vals: srtt: %d rttvar: %d to: %d ", to->srtt, to->rttvar, to->timeout);
  }
  if (to->srtt == -1 && to->rttvar == -1) {
    /* We need to initialize the sucker ... */
    to->srtt = TIMEVAL_SUBTRACT(*received, *sent);
    to->rttvar = MAX(5000, MIN(to->srtt, 2000000));
    to->timeout = to->srtt + (to->rttvar << 2);
  }
  else {
    delta = TIMEVAL_SUBTRACT(*received, *sent);
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
	log_write(LOG_STDOUT, "Bogus delta: %d (srtt %d) ... ignoring\n", delta, to->srtt);
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
  to->timeout = MAX(to->timeout, o.min_rtt_timeout * 1000);
  to->timeout = MIN(to->timeout, o.max_rtt_timeout * 1000);

  if (o.scan_delay)
    to->timeout = MAX(to->timeout, o.scan_delay * 1000);

  if (o.debugging > 1) {
    log_write(LOG_STDOUT, "delta %d ==> srtt: %d rttvar: %d to: %d\n", delta, to->srtt, to->rttvar, to->timeout);
  }

  if (to->srtt < 0 || to->rttvar < 0 || to->timeout < 0 || delta < -50000000) {
    fatal("Serious time computation problem in adjust_timeout ... received = (%d, %d) sent=(%d,%d) delta = %d srtt = %d rttvar = %d to = %d", received->tv_sec, received->tv_usec, sent->tv_sec, sent->tv_usec, delta, to->srtt, to->rttvar, to->timeout);
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

