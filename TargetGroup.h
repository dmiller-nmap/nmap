
/***********************************************************************
 * TargetGroup.h -- The "TargetGroup" class holds a group of IP        *
 * addresses, such as those from a '/16' or '10.*.*.*' specification.  *
 * It also has a trivial HostGroupState class which handles a bunch    *
 * of expressions that go into TargetGroup classes.                    *
 *                                                                     *
 ***********************************************************************
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
 ***********************************************************************/

/* $Id$ */

#ifndef TARGETGROUP_H
#define TARGETGROUP_H

#include "nmap.h"

class TargetGroup {
 public:
  TargetGroup();

 /* Initializes (or reinitializes) the object with a new expression,
    such as 192.168.0.0/16 , 10.1.0-5.1-254 , or
    fe80::202:e3ff:fe14:1102 .  The af parameter is AF_INET or
    AF_INET6 Returns 0 for success */
  int parse_expr(const char * const target_expr, int af);
  /* Grab the next host from this expression (if any).  Returns 0 and
     fills in ss if successful.  ss must point to a pre-allocated
     sockaddr_storage structure */
  int get_next_host(struct sockaddr_storage *ss, size_t *sslen);
  /* Returns the last given host, so that it will be given again next
     time get_next_host is called.  Obviously, you should only call
     this if you have fetched at least 1 host since parse_expr() was
     called */
  int return_last_host();
 private:
  enum { TYPE_NONE, IPV4_NETMASK, IPV4_RANGES, IPV6_ADDRESS } targets_type;

  void Initialize();

#if HAVE_IPV6
  struct in6_addr ip6;
#endif

  /* These 4 are used for the '/mask' style of specifying target 
     net (IPV4_NETMASK) */
  u32 netmask;
  struct in_addr startaddr;
  struct in_addr currentaddr;
  struct in_addr endaddr;

  // These three are for the '138.[1-7,16,91-95,200-].12.1 style (IPV4_RANGES)
  u8 addresses[4][256];
  unsigned int current[4];
  u8 last[4];  

  int ipsleft; /* Number of IPs left in this structure -- set to 0 if 
		  the fields are not valid */
};

class HostGroupState {
 public:
  HostGroupState(int lookahead, int randomize, char *target_expressions[],
		 int num_expressions);
  ~HostGroupState();
  Target **hostbatch;
  int max_batch_sz; /* The size of the hostbatch[] array */
  int current_batch_sz; /* The number of VALID members of hostbatch[] */
  int next_batch_no; /* The index of the next hostbatch[] member to be given 
			back to the user */
  int randomize; /* Whether each bach should be "shuffled" prior to the ping 
		    scan (they will also be out of order when given back one
		    at a time to the client program */
  char **target_expressions; /* An array of target expression strings, passed
				to us by the client (client is also in charge
				of deleting it AFTER it is done with the 
				hostgroup_state */
  int num_expressions;       /* The number of valid expressions in 
				target_expressions member above */
  int next_expression;   /* The index of the next expression we have
			    to handle */
  TargetGroup current_expression; /* For batch chunking -- targets in queue */
};

#endif /* TARGETGROUP_H */
