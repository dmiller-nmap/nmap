
/***********************************************************************
 * Target.cc -- The Target class encapsulates much of the information  *
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

#include "Target.h"
#include "osscan.h"
#include "nbase.h"

Target::Target() {
  Initialize();
}

void Target::Initialize() {
  hostname = NULL;
  bzero(&seq, sizeof(seq));
  bzero(&FPR, sizeof(FPR));
  bzero(FPs, sizeof(FPs));
  osscan_performed = 0;
  osscan_openport = osscan_closedport = -1;
  numFPs = goodFP = 0;
  bzero(&ports, sizeof(struct portlist));
  wierd_responses = flags = 0;
  bzero(&to, sizeof(to));
  bzero(&host_timeout, sizeof(host_timeout));
  bzero(&firewallmode, sizeof(struct firewallmodeinfo));
  timedout = 0;
  device[0] = '\0';
  bzero(&targetsock, sizeof(targetsock));
  bzero(&sourcesock, sizeof(sourcesock));
  targetsocklen = sourcesocklen = 0;
  targetipstring[0] = '\0';
  nameIPBuf = NULL;
}

void Target::Recycle() {
  FreeInternal();
  Initialize();
}

Target::~Target() {
  FreeInternal();
}

void Target::FreeInternal() {
  int i;

  /* Free the DNS name if we resolved one */
  if (hostname)
    free(hostname);

  /* Free OS fingerprints of OS scanning was done */
  for(i=0; i < numFPs; i++) {
    freeFingerPrint(FPs[i]);
    FPs[i] = NULL;
  }
  numFPs = 0;

  if (nameIPBuf) {
    free(nameIPBuf);
    nameIPBuf = NULL;
  }

  /* Free the port lists */
  resetportlist(&ports);
}

/*  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
void Target::GenerateIPString() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &targetsock;

  if (inet_ntop(sin->sin_family, (sin->sin_family == AF_INET)? 
                (char *) &sin->sin_addr : 
#if HAVE_IPV6
                (char *) &sin6->sin6_addr, 
#else
                (char *) NULL,
#endif
		targetipstring, sizeof(targetipstring)) == NULL) {
    fatal("Failed to convert target address to presentation format!?!  Error: %s", strerror(errno));
  }
}

/* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. */
int Target::TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  assert(ss);
  assert(ss_len);  
  if (targetsocklen <= 0)
    return 1;
  assert(targetsocklen <= sizeof(*ss));
  memcpy(ss, &targetsock, targetsocklen);
  *ss_len = targetsocklen;
  return 0;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setTargetSockAddr(struct sockaddr_storage *ss, size_t ss_len) {

  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  if (targetsocklen > 0) {
    /* We had an old target sock, so we better blow away the hostname as
       this one may be new. */
    setHostName(NULL);
  }
  memcpy(&targetsock, ss, ss_len);
  targetsocklen = ss_len;
  GenerateIPString();
}

// Returns IPv4 host address or {0} if unavailable.
struct in_addr Target::v4host() {
  const struct in_addr *addy = v4hostip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

// Returns IPv4 host address or NULL if unavailable.
const struct in_addr *Target::v4hostip() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}

 /* The source address used to reach the target */
int Target::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
}

/* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
void Target::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

// Returns IPv4 host address or {0} if unavailable.
struct in_addr Target::v4source() {
  const struct in_addr *addy = v4sourceip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

// Returns IPv4 host address or NULL if unavailable.
const struct in_addr *Target::v4sourceip() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}


  /* You can set to NULL to erase a name or if it failed to resolve -- or 
     just don't call this if it fails to resolve */
void Target::setHostName(char *name) {
  if (hostname) {
    free(hostname);
    hostname = NULL;
  }
  if (name)
    hostname = strdup(name);
}

 /* Generates the a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in bufflen will be truncated. */
const char *Target::NameIP(char *buf, size_t buflen) {
  assert(buf);
  assert(buflen > 8);
  if (hostname) {
    snprintf(buf, buflen, "%s (%s)", hostname, targetipstring);
  } else Strncpy(buf, targetipstring, buflen);
  return buf;
}

/* This next version returns a static buffer -- so no concurrency */
const char *Target::NameIP() {
  if (!nameIPBuf) nameIPBuf = (char *) safe_malloc(MAXHOSTNAMELEN + INET6_ADDRSTRLEN);
  return NameIP(nameIPBuf, MAXHOSTNAMELEN + INET6_ADDRSTRLEN);
}
