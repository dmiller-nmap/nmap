

#include "portlist.h"
#include "error.h"
#include "nmap.h"

#include <strings.h>

struct ops o;  /* option structure */
static struct port *freeportlist = NULL;

/* gawd, my next project will be in c++ so I don't have to deal with
   this crap ... simple linked list implementation */
int addport(portlist *plist, unsigned short portno, unsigned short protocol,
	    char *owner, int state) {
  struct port *current = NULL;
  struct port **portarray = NULL;

/* Make sure state is OK */
  if (state != PORT_OPEN && state != PORT_CLOSED && state != PORT_FIREWALLED &&
      state != PORT_UNFIREWALLED)
    fatal("addport: attempt to add port number %d with illegal state %d\n", portno, state);

  if (protocol == IPPROTO_TCP) {
    if (!plist->tcp_ports) {
      plist->tcp_ports = safe_malloc(65536 * sizeof(struct port *));
      bzero(plist->tcp_ports, 65536 * sizeof(struct port *));
    }
    portarray = plist->tcp_ports;
  } else if (protocol == IPPROTO_UDP) {
    if (!plist->udp_ports) {
      plist->udp_ports = safe_malloc(65536 * sizeof(struct port *));
      bzero(plist->udp_ports, 65536 * sizeof(struct port *));
    }
    portarray = plist->udp_ports;
  } else fatal("addport: attempted port insertion with invalid protocol");

  if (portarray[portno]) {
    /* We must discount our statistics from the old values.  Also warn
       if a complete duplicate */
    current = portarray[portno];    
    if (o.debugging && current->state == state && (!owner || !*owner)) {
      error("Duplicate port (%hu/%s)\n", portno ,
	    (protocol == IPPROTO_TCP)? "tcp": "udp");
    } 
    plist->state_counts[current->state]--;
    if (current->proto == IPPROTO_TCP) {
      plist->state_counts_tcp[current->state]--;
    } else {
      plist->state_counts_udp[current->state]--;
    }  
  } else {
    portarray[portno] = make_empty_port();
    current = portarray[portno];
    plist->numports++;
    current->rpc_status = RPC_STATUS_UNTESTED;
    current->confidence = CONF_HIGH;
    current->portno = portno;
  }
  
  plist->state_counts[state]++;
  current->state = state;
  if (protocol == IPPROTO_TCP) {
    plist->state_counts_tcp[state]++;
  } else {
    plist->state_counts_udp[state]++;
  }
  current->proto = protocol;

  if (owner && *owner) {
    if (current->owner)
      free(current->owner);
    current->owner = strdup(owner);
  }

  return 0; /*success */
}

int deleteport(portlist *plist, unsigned short portno,
	       unsigned short protocol) {
  struct port *answer = NULL;

  if (protocol == IPPROTO_TCP && plist->tcp_ports) {
   answer = plist->tcp_ports[portno];
   plist->tcp_ports[portno] = NULL;
  }

  if (protocol == IPPROTO_UDP && plist->udp_ports) {  
    answer = plist->udp_ports[portno];
    plist->udp_ports[portno] = NULL;
  }

  if (!answer)
    return -1;

  free_port(answer);
  return 0;
}


struct port *lookupport(portlist *ports, unsigned short portno, unsigned short protocol) {

  if (protocol == IPPROTO_TCP && ports->tcp_ports)
    return ports->tcp_ports[portno];

  if (protocol == IPPROTO_UDP && ports->udp_ports)
    return ports->udp_ports[portno];
  
  return NULL;
}


/* RECYCLES the port so that it can later be obtained again using 
   make_port_structure */
void free_port(struct port *pt) {
  struct port *tmp;
  if (pt->owner)
    free(pt->owner);
  tmp = freeportlist;
  freeportlist = pt;
  pt->next = tmp;
}

struct port *make_empty_port() {
int i;
struct port *newpt;

 if (!freeportlist) {
   freeportlist = safe_malloc(sizeof(struct port) * 1024);
   for(i=0; i < 1023; i++)
     freeportlist[i].next = &freeportlist[i+1];
   freeportlist[1023].next = NULL;
 }

 newpt = freeportlist;
 freeportlist = freeportlist->next;
 bzero(newpt, sizeof(struct port));
 return newpt;
}

/* Empties out a portlist so that it can be reused (or freed).  All the 
   internal structures that must be freed are done so here. */
void resetportlist(portlist *plist) {
  int i;
  if (plist->tcp_ports) {  
    for(i=0; i < 65536; i++) {
      if (plist->tcp_ports[i])
	free_port(plist->tcp_ports[i]);
    }
    free(plist->tcp_ports);
  }

  if (plist->udp_ports) {  
    for(i=0; i < 65536; i++) {
      if (plist->udp_ports[i])
	free_port(plist->udp_ports[i]);
    }
    free(plist->udp_ports);
  }
  bzero(plist, sizeof(portlist));
}


/* Decide which port we want to ignore in output (for example, we don't want
 to show closed ports if there are 40,000 of them.) */
void assignignoredportstate(portlist *plist) {

  if (plist->state_counts[PORT_FIREWALLED] > 10 + 
      MAX(plist->state_counts[PORT_UNFIREWALLED], 
	  plist->state_counts[PORT_CLOSED])) {
    plist->ignored_port_state = PORT_FIREWALLED;
  } else if (plist->state_counts[PORT_UNFIREWALLED] > 
	     plist->state_counts[PORT_CLOSED]) {
    plist->ignored_port_state = PORT_UNFIREWALLED;
  } else plist->ignored_port_state = PORT_CLOSED;
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
   ports */

struct port *nextport(portlist *plist, struct port *afterthisport, 
		      int allowed_protocol, int allowed_state) {

  /* These two are chosen because they come right "before" port 1/tcp */
unsigned int current_portno = 0;
unsigned int current_proto = IPPROTO_TCP;

if (afterthisport) {
  current_portno = afterthisport->portno;
  current_proto = afterthisport->proto;  /* (afterthisport->proto == IPPROTO_TCP)? IPPROTO_TCP : IPPROTO_UDP; */
} 

 current_portno++; /* Start on the port after the one we were given */

/* First we look for TCP ports ... */
if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_TCP) && 
    current_proto == IPPROTO_TCP && plist->tcp_ports) {
  for(; current_portno < 65536; current_portno++) {
    if (plist->tcp_ports[current_portno] &&
	(!allowed_state || plist->tcp_ports[current_portno]->state == allowed_state))
      return plist->tcp_ports[current_portno];
  }
  /*  Uh-oh.  We have tried all tcp ports, lets move to udp */
  current_portno = 0;
  current_proto = IPPROTO_UDP;
}

if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_UDP) && 
    current_proto == IPPROTO_UDP && plist->udp_ports) {
  for(; current_portno < 65536; current_portno++) {
    if (plist->udp_ports[current_portno] &&
	(!allowed_state || plist->udp_ports[current_portno]->state == allowed_state))
      return plist->udp_ports[current_portno];
  }
}

/*  No more ports */
return NULL;
}

