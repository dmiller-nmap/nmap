
/***********************************************************************
 * Target.h -- The Target class encapsulates much of the information   *
 * Nmap has about a host.  Results (such as ping, OS scan, etc) are    *
 * stored in this class as they are determined.                        *
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

#ifndef TARGET_H
#define TARGET_H

#include "nmap.h"

class Target {
 public: /* For now ... a lot of the data members should be made private */
  Target();
  ~Target();
  /* Recycles the object by freeing internal objects and reinitializing
     to default state */
  void Recycle();
  /* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. */
  int TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setTargetSockAddr(struct sockaddr_storage *ss, size_t ss_len);
  // Returns IPv4 target host address or {0} if unavailable.
  struct in_addr v4host();
  const struct in_addr *v4hostip();
  /* The source address used to reach the target */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);
  struct in_addr v4source();
  const struct in_addr *v4sourceip();
  /* The IPv4 or IPv6 literal string for the target host */
  const char *targetipstr() { return targetipstring; }
  /* Give the name from the last setHostName() call, which should be
   the name obtained from reverse-resolution (PTR query) of the IP (v4
   or v6).  If the name has not been set, or was set to NULL, an empty
   string ("") is returned to make printing easier. */
  const char *HostName() { return hostname? : "";  }
  /* You can set to NULL to erase a name or if it failed to resolve -- or 
     just don't call this if it fails to resolve.  The hostname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  */
  void setHostName(char *name);
  /* Generates the a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in bufflen will be truncated. */
  const char *NameIP(char *buf, size_t buflen);
  struct seq_info seq;
  struct FingerPrintResults FPR;
  FingerPrint *FPs[10]; /* Fingerprint data obtained from host */
  int osscan_performed; /* nonzero if an osscan was performed */
  int osscan_openport; /* Open port used for scannig (if one found -- 
			  otherwise -1) */
  int osscan_closedport; /* Closed port used for scannig (if one found -- 
			    otherwise -1) */
  int numFPs;
  int goodFP;
  struct portlist ports;
  /*
  unsigned int up;
  unsigned int down; */
  int wierd_responses; /* echo responses from other addresses, Ie a network broadcast address */
  unsigned int flags; /* HOST_UP, HOST_DOWN, HOST_FIREWALLED, HOST_BROADCAST (instead of HOST_BROADCAST use wierd_responses */
  struct timeout_info to;
  struct timeval host_timeout;
  struct firewallmodeinfo firewallmode; /* For supporting "firewall mode" speed optimisations */
  int timedout; /* Nonzero if continued scanning should be aborted due to
		   timeout  */
  char device[64]; /* The device we transmit on */

 private:
  char *hostname; // Null if unable to resolve or unset
  void Initialize();
  void FreeInternal(); // Free memory allocated inside this object
 // Creates a "presentation" formatted string out of the IPv4/IPv6 address
  void GenerateIPString();
  struct sockaddr_storage targetsock, sourcesock;
  size_t targetsocklen, sourcesocklen;
  char targetipstring[INET6_ADDRSTRLEN];
};

#endif /* TARGET_H */
