
/***********************************************************************
 * portlist.h -- Functions for manipulating various lists of ports     *
 * maintained internally by Nmap.                                      *
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

#ifndef PORTLIST_H
#define PORTLIST_H

#include <nbase.h>

/* port states */
#define PORT_UNKNOWN 0
#define PORT_CLOSED 1
#define PORT_OPEN 2
#define PORT_FIREWALLED 3
#define PORT_TESTING 4
#define PORT_FRESH 5
#define PORT_UNFIREWALLED 6
#define PORT_HIGHEST_STATE 7 /* ***IMPORTANT -- BUMP THIS UP WHEN STATES ARE 
				ADDED *** */
 
#define CONF_NONE 0
#define CONF_LOW 1
#define CONF_HIGH 2

enum serviceprobestate {
  PROBESTATE_INITIAL=1, // No probes started yet
  PROBESTATE_NULLPROBE, // Is working on the NULL Probe
  PROBESTATE_MATCHINGPROBES, // Is doing matching probe(s)
  PROBESTATE_NONMATCHINGPROBES, // The above failed, is checking nonmatches
  PROBESTATE_FINISHED_HARDMATCHED, // Yay!  Found a match
  PROBESTATE_FINISHED_SOFTMATCHED, // Well, a soft match anyway
  PROBESTATE_FINISHED_NOMATCH, // D'oh!  Failed to find the service.
  PROBESTATE_FINISHED_TCPWRAPPED, // We think the port is blocked via tcpwrappers
  PROBESTATE_INCOMPLETE // failed to complete (error, host timeout, etc.)
};

enum service_detection_type { SERVICE_DETECTION_TABLE, SERVICE_DETECTION_PROBED };

enum service_tunnel_type { SERVICE_TUNNEL_NONE, SERVICE_TUNNEL_SSL };

struct serviceDeductions {
  const char *name; // will be NULL if can't determine
  // Confidence is a number from 0 (least confident) to 10 (most
  // confident) expressing how accurate the service detection is
  // likely to be.
  int name_confidence;
  // Any of these three will be NULL if undetermined.
  const char *product;
  const char *version;
  const char *extrainfo;
  // SERVICE_TUNNEL_NONE or SERVICE_TUNNEL_SSL
  enum service_tunnel_type service_tunnel; 
  // This is the combined version of the three fields above.  It will be 
  // zero length if unavailable.
  char fullversion[128];
  // if we should give the user a service fingerprint to submit, here it is.  Otherwise NULL.
  const char *service_fp; 
  enum service_detection_type dtype; // definition above
  int rpc_status; /* RPC_STATUS_UNTESTED means we haven't checked
		    RPC_STATUS_UNKNOWN means the port appears to be RPC
		    but we couldn't find a match
		    RPC_STATUS_GOOD_PROG means rpc_program gives the prog #
		    RPC_STATUS_NOT_RPC means the port doesn't appear to 
		    be RPC */
  unsigned long rpc_program; /* Only valid if rpc_state == RPC_STATUS_GOOD_PROG */
  unsigned int rpc_lowver;
  unsigned int rpc_highver;
};



class Port {
 public:
  Port();
  ~Port();

  // pass in an allocated struct serviceDeductions (don't wory about initializing, and
  // you don't have to free any inernal ptrs.  See the serviceDeductions definition for
  // the fields that are populated.  Returns 0 if at least a name is available.
  int getServiceDeductions(struct serviceDeductions *sd);

  // sname should be NULL if sres is not
  // PROBESTATE_FINISHED_MATCHED. product,version, and/or extrainfo
  // will be NULL if unavailable. Note that this function makes its
  // own copy of sname and product/version/extrainfo.  This function
  // also takes care of truncating the version strings to a
  // 'reasonable' length if neccessary, and cleaning up any unprinable
  // chars. (these tests are to avoid annoying DOS (or other) attacks
  // by malicious services).  The fingerprint should be NULL unless
  // one is available and the user should submit it.  tunnel must be
  // SERVICE_TUNNEL_NULL (normal) or SERVICE_TUNNEL_SSL (means ssl was
  // detected and we tried to tunnel through it ).
  void setServiceProbeResults(enum serviceprobestate sres, const char *sname,
			      enum service_tunnel_type tunnel, const char *product, 
			      const char *version, 
			      const char *extrainfo, const char *fingerprint);

  /* Sets the results of an RPC scan.  if rpc_status is not
   RPC_STATUS_GOOD_PROGRAM, pass 0 for the other args. This function
   takes care of setting the port's service and version
   appropriately. */
  void setRPCProbeResults(int rpc_status, unsigned long rpc_program, 
			  unsigned int rpc_lowver, unsigned int rpc_highver);

  u16 portno;
  u8 proto;
  char *owner;
  int state; 
  int confidence; /* How sure are we about the state? */


 private:
  int rpc_status; /* RPC_STATUS_UNTESTED means we haven't checked
		    RPC_STATUS_UNKNOWN means the port appears to be RPC
		    but we couldn't find a match
		    RPC_STATUS_GOOD_PROG means rpc_program gives the prog #
		    RPC_STATUS_NOT_RPC means the port doesn't appear to 
		    be RPC */
  unsigned long rpc_program; /* Only valid if rpc_state == RPC_STATUS_GOOD_PROG */
  unsigned int rpc_lowver;
  unsigned int rpc_highver;
  Port *next; /* Internal use only -- we sometimes like to link them
			together */
  enum serviceprobestate serviceprobe_results; // overall results of service scan
  char *serviceprobe_service; // If a service was discovered, points to the name
  // Any of these next three can be NULL if the details are not available
  char *serviceprobe_product; 
  char *serviceprobe_version; 
  char *serviceprobe_extrainfo; 
  enum service_tunnel_type serviceprobe_tunnel;
  // A fingerprint that the user can submit if the service wasn't recognized
  char *serviceprobe_fp;

};

class PortList {
 public:
  PortList();
  ~PortList();
  // Add a new port to this list
  int addPort(u16 portno, u8 protocol, char *owner, int state);
  int removePort(u16 portno, u8 protocol);
/* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP or IPPROTO_UDP for allowed_protocol.  A 0 for
   allowed_protocol matches either.  allowed_state works in the same
   fashion as allowed_protocol. This function returns ports in numeric
   order from lowest to highest, except that if you ask for both TCP &
   UDP, every TCP port will be returned before we start returning UDP
   ports */
    Port *nextPort(Port *afterthisport, 
		   u8 allowed_protocol, int allowed_state, 
		   bool allow_portzero);

  Port *lookupPort(u16 portno, u8 protocol);
  Port **udp_ports;
  Port **tcp_ports;
  Port **ip_prots;
  int state_counts[PORT_HIGHEST_STATE]; /* How many ports in list are in each
					   state */
  int state_counts_udp[PORT_HIGHEST_STATE];
  int state_counts_tcp[PORT_HIGHEST_STATE];
  int state_counts_ip[PORT_HIGHEST_STATE];
  int getIgnoredPortState(); /* The state of the port we ignore for output */
  int numports; /* Total number of ports in list in ANY state */
 private:

};

#endif
