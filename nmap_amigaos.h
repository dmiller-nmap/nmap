
/***************************************************************************
 * nmap_amigaos.h -- Handles various compilation issues for the Amiga port *
 * done by Diego Casorran (dcr8520@amiga.org)                              *
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

#ifndef _NMAP_AMIGAOS_H_
#define _NMAP_AMIGAOS_H_

#include <proto/miami.h>
#include <proto/miamibpf.h>
#include <proto/miamipcap.h>
#include <libraries/miami.h>
#include <devices/timer.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>


//Pcap functions replacement using miamipcap.library (MiamiSDK v2.11)
#define pcap_open_live(a, b, c, d...)	MiamiPCapOpenLive(a, b, 0, d)
#define pcap_filter(args...)		MiamiPCapFilter( args)
#define pcap_close(args...)		MiamiPCapClose( args)
#define pcap_datalink(args...)		MiamiPCapDatalink( args)
#define pcap_geterr(args...)		MiamiPCapGeterr( args)
#define pcap_next(args...)		MiamiPCapNext( args)
#define pcap_lookupnet(args...)		MiamiPCapLookupnet( args)
#define pcap_compile(args...)		MiamiPCapCompile( args)
#define pcap_setfilter(args...)		MiamiPCapSetfilter( args)

#ifndef DLT_MIAMI
#define DLT_MIAMI 100
#endif

#ifndef NI_NAMEREQD
#define NI_NAMEREQD 4
#endif

#define NBASE_IPV6_H

struct addrinfo {
  long		ai_flags;		/* AI_PASSIVE, AI_CANONNAME */
  long		ai_family;		/* PF_xxx */
  long		ai_socktype;		/* SOCK_xxx */
  long		ai_protocol;		/* IPPROTO_xxx for IPv4 and IPv6 */
  size_t	ai_addrlen;		/* length of ai_addr */
  char		*ai_canonname;		/* canonical name for host */
  struct sockaddr	*ai_addr;	/* binary address */
  struct addrinfo	*ai_next;	/* next structure in linked list */
};


#define exit(x); {CloseLibs();exit(x);}

#endif /* _NMAP_AMIGAOS_H_ */
