
/***********************************************************************
 * portlist.cc -- Functions for manipulating various lists of ports    *
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


#include "portlist.h"
#include "nmap_error.h"
#include "nmap.h"
#include "NmapOps.h"

#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

extern NmapOps o;  /* option structure */

Port::Port() {
  portno = proto = 0;
  owner = NULL;
  rpc_status = RPC_STATUS_UNTESTED;
  rpc_program = rpc_lowver = rpc_highver = 0;
  state = confidence = 0;
  next = NULL;
  serviceprobe_results = PROBESTATE_INITIAL;
  serviceprobe_service = NULL;
}

Port::~Port() {
 if (owner)
   free(owner);
}

// Obtain the service name listening on the port (NULL if port is
  // not open or service) is unknown.  Detection type will be
  // SERVICE_DETECTION_TABLE or SERVICE_DETECTION_PROBED.  Confidence
  // is a number from 0 (least confident) to 10 (most confident)
  // expressing how accurate the service detection is likely to be.  Either argument
  // can be NULL if you aren't interested.
const char *Port::serviceName(enum service_detection_type *detection_type, int *confidence) {
  int conf = 0;
  struct servent *service;

  if (!confidence) confidence = &conf; // to make code cleaner

  if (serviceprobe_results == PROBESTATE_FINISHED_MATCHED) {
    assert(serviceprobe_service);
    if (detection_type)
      *detection_type = SERVICE_DETECTION_PROBED;
    *confidence = 10;
    return serviceprobe_service;
  } else if (serviceprobe_results == PROBESTATE_FINISHED_TCPWRAPPED) {
    if (detection_type)
      *detection_type = SERVICE_DETECTION_PROBED;
    *confidence = 8;
    return "tcpwrapped";
  }

  // TODO:  Should do RPC-related stuff here.

  // So much for service detection or RPC.  Maybe we can find it in the file
  service = nmap_getservbyport(htons(portno), (proto == IPPROTO_TCP)? "tcp" : "udp");
  if (service) {
    if (detection_type) *detection_type = SERVICE_DETECTION_TABLE;
    *confidence = 3;
    return service->s_name;
  }
  
  // Couldn't find it.  [shrug]
  return NULL;

}

void Port::setServiceProbeResults(enum serviceprobestate sres, const char *sname) {
  serviceprobe_results = sres;
  serviceprobe_service = sname;
}

PortList::PortList() {
  udp_ports = tcp_ports = ip_prots;
  bzero(state_counts, sizeof(state_counts));
  bzero(state_counts_udp, sizeof(state_counts_udp));
  bzero(state_counts_tcp, sizeof(state_counts_tcp));
  bzero(state_counts_ip, sizeof(state_counts_ip));
  numports = 0;
}

PortList::~PortList() {
  int i;

  if (tcp_ports) {  
    for(i=0; i < 65536; i++) {
      if (tcp_ports[i])
	delete tcp_ports[i];
    }
    free(tcp_ports);
    tcp_ports = NULL;
  }

  if (udp_ports) {  
    for(i=0; i < 65536; i++) {
      if (udp_ports[i])
	delete udp_ports[i];
    }
    free(udp_ports);
    udp_ports = NULL;
  }

  if (ip_prots) {
    for(i=0; i < 256; ++i) {
      if (ip_prots[i])
	delete ip_prots[i];
    }
    free(ip_prots);
    ip_prots = NULL;
  }
}


int PortList::addPort(u16 portno, u8 protocol, char *owner, int state) {
  Port *current = NULL;
  Port **portarray = NULL;
  char msg[128];

  if ((state == PORT_OPEN && o.verbose) || (o.debugging > 1)) {
    if (owner && *owner) {
      snprintf(msg, sizeof(msg), " (owner: %s)", owner);
    } else msg[0] = '\0';
    
    log_write(LOG_STDOUT, "Adding %s port %hu/%s%s\n",
	      statenum2str(state), portno, 
	      (protocol == IPPROTO_TCP)? "tcp" : "udp", msg);
    log_flush(LOG_STDOUT);
    
    /* Write out add port messages for XML format so wrapper libraries can
       use it and not have to parse LOG_STDOUT ;), which is a pain! */
    
    log_write(LOG_XML, "<addport state=\"%s\" portid=\"%hu\" protocol=\"%s\" owner=\"%s\"/>\n", statenum2str(state), portno, (protocol == IPPROTO_TCP)? "tcp" : "udp", ((owner && *owner) ? owner : ""));
    log_flush(LOG_XML); 
  }


/* Make sure state is OK */
  if (state != PORT_OPEN && state != PORT_CLOSED && state != PORT_FIREWALLED &&
      state != PORT_UNFIREWALLED)
    fatal("addPort: attempt to add port number %d with illegal state %d\n", portno, state);

  if (protocol == IPPROTO_TCP) {
    if (!tcp_ports) {
      tcp_ports = (Port **) safe_zalloc(65536 * sizeof(Port *));
    }
    portarray = tcp_ports;
  } else if (protocol == IPPROTO_UDP) {
    if (!udp_ports) {
      udp_ports = (Port **) safe_zalloc(65536 * sizeof(Port *));
    }
    portarray = udp_ports;
  } else if (protocol == IPPROTO_IP) {
    assert(portno < 256);
    if (!ip_prots) {
      ip_prots = (Port **) safe_zalloc(256 * sizeof(Port *));
    }
    portarray = ip_prots;
  } else fatal("addPort: attempted port insertion with invalid protocol");

  if (portarray[portno]) {
    /* We must discount our statistics from the old values.  Also warn
       if a complete duplicate */
    current = portarray[portno];    
    if (o.debugging && current->state == state && (!owner || !*owner)) {
      error("Duplicate port (%hu/%s)\n", portno ,
	    (protocol == IPPROTO_TCP)? "tcp":
	    (protocol == IPPROTO_UDP)? "udp": "ip");
    } 
    state_counts[current->state]--;
    if (current->proto == IPPROTO_TCP) {
      state_counts_tcp[current->state]--;
    } else if (current->proto == IPPROTO_UDP) {
      state_counts_udp[current->state]--;
    } else
      state_counts_ip[current->state]--;
  } else {
    portarray[portno] = new Port();
    current = portarray[portno];
    numports++;
    current->rpc_status = RPC_STATUS_UNTESTED;
    current->confidence = CONF_HIGH;
    current->portno = portno;
  }
  
  state_counts[state]++;
  current->state = state;
  if (protocol == IPPROTO_TCP) {
    state_counts_tcp[state]++;
  } else if (protocol == IPPROTO_UDP) {
    state_counts_udp[state]++;
  } else
    state_counts_ip[state]++;
  current->proto = protocol;

  if (owner && *owner) {
    if (current->owner)
      free(current->owner);
    current->owner = strdup(owner);
  }

  return 0; /*success */
}

int PortList::removePort(u16 portno, u8 protocol) {
  Port *answer = NULL;

  if (protocol == IPPROTO_TCP && tcp_ports) {
   answer = tcp_ports[portno];
   tcp_ports[portno] = NULL;
  }

  if (protocol == IPPROTO_UDP && udp_ports) {  
    answer = udp_ports[portno];
    udp_ports[portno] = NULL;
  } else if (protocol == IPPROTO_IP && ip_prots) {
    answer = ip_prots[portno] = NULL;
  }

  if (!answer)
    return -1;

  if (o.verbose) {  
    log_write(LOG_STDOUT, "Deleting port %hu/%s, which we thought was %s\n",
	      portno, (answer->proto == IPPROTO_TCP)? "tcp" : "udp", 
	      statenum2str(answer->state));
    log_flush(LOG_STDOUT);
  }    

  delete answer;
  return 0;
}


Port *PortList::lookupPort(u16 portno, u8 protocol) {

  if (protocol == IPPROTO_TCP && tcp_ports)
    return tcp_ports[portno];

  if (protocol == IPPROTO_UDP && udp_ports)
    return udp_ports[portno];

  if (protocol == IPPROTO_IP && ip_prots)
    return ip_prots[portno];

  return NULL;
}

int PortList::getIgnoredPortState() {
  int ignored = PORT_UNKNOWN;

  if (state_counts[PORT_FIREWALLED] > 10 + 
      MAX(state_counts[PORT_UNFIREWALLED], 
	  state_counts[PORT_CLOSED])) {
    ignored = PORT_FIREWALLED;
  } else if (state_counts[PORT_UNFIREWALLED] > 
	     state_counts[PORT_CLOSED]) {
    ignored = PORT_UNFIREWALLED;
  } else ignored = PORT_CLOSED;

  if (state_counts[ignored] < 10)
    ignored = PORT_UNKNOWN;

  return ignored;
}

/* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP or IPPROTO_UDP for allowed_protocol.  A 0 for
   allowed_protocol matches either.  allowed_state works in the same
   fashion as allowed_protocol. This function returns ports in numeric
   order from lowest to highest, except that if you ask for both TCP &
   UDP, every TCP port will be returned before we start returning UDP
   ports.  */

Port *PortList::nextPort(Port *afterthisport, 
			 u8 allowed_protocol, int allowed_state, 
			 bool allow_portzero) {

  /* These two are chosen because they come right "before" port 1/tcp */
unsigned int current_portno = 0;
unsigned int current_proto = IPPROTO_TCP;

if (afterthisport) {
  current_portno = afterthisport->portno;
  current_proto = afterthisport->proto;  /* (afterthisport->proto == IPPROTO_TCP)? IPPROTO_TCP : IPPROTO_UDP; */
  current_portno++; /* Start on the port after the one we were given */ 
} 

 if (!allow_portzero && current_portno == 0) current_portno++;

/* First we look for TCP ports ... */
if (current_proto == IPPROTO_TCP) {
 if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_TCP) && 
    current_proto == IPPROTO_TCP && tcp_ports)
  for(; current_portno < 65536; current_portno++) {
    if (tcp_ports[current_portno] &&
	(!allowed_state || tcp_ports[current_portno]->state == allowed_state))
      return tcp_ports[current_portno];
  }

  /*  Uh-oh.  We have tried all tcp ports, lets move to udp */
  current_portno = 0;
  current_proto = IPPROTO_UDP;
}

if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_UDP) && 
    current_proto == IPPROTO_UDP && udp_ports) {
  for(; current_portno < 65536; current_portno++) {
    if (udp_ports[current_portno] &&
	(!allowed_state || udp_ports[current_portno]->state == allowed_state))
      return udp_ports[current_portno];
  }
}

/*  No more ports */
return NULL;
}

