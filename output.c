
/***********************************************************************
 * output.c -- Handles the Nmap output system.  This currently         *
 * involves console-style human readable output, XML output,           *
 * Script |<iddi3 output, and the legacy greppable output (used to be  *
 * called "machine readable").  I expect that future output forms      *
 * (such as HTML) may be created by a different program, library, or   *
 * script using the XML output.                                        *
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

#include "output.h"
#include "osscan.h"

extern struct ops o;
char *logtypes[LOG_TYPES]=LOG_NAMES;

/* Prints the familiar Nmap tabular output showing the "interesting"
   ports found on the machine.  It also handles the Machine/Greppable
   output and the XML output.  It is pretty ugly -- in particular I
   should write helper functions to handle the table creation */
void printportoutput(struct hoststruct *currenths, portlist *plist) {
  char protocol[4];
  char rpcinfo[64];
  char rpcmachineinfo[64];
  char portinfo[64];
  char tmpbuf[64];
  char *state;
  char serviceinfo[64];
  char *name=NULL;
  int first = 1;
  struct servent *service;
  struct protoent *proto;
  struct port *current;
  int numignoredports;
  int portno, protocount;
  struct port **protoarrays[2];

  numignoredports = plist->state_counts[plist->ignored_port_state];

  assert(numignoredports <= plist->numports);


  log_write(LOG_XML, "<ports><extraports state=\"%s\" count=\"%d\" />\n", 
	    statenum2str(currenths->ports.ignored_port_state), 
	    numignoredports);

  if (numignoredports == plist->numports) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
              "%s %d scanned %s on %s (%s) %s: %s\n",
	      (numignoredports == 1)? "The" : "All", numignoredports,
	      (numignoredports == 1)? "port" : "ports", currenths->name, 
	      inet_ntoa(currenths->host), 
	      (numignoredports == 1)? "is" : "are", 
	      statenum2str(currenths->ports.ignored_port_state));
    log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up", 
	      inet_ntoa(currenths->host), currenths->name);
    log_write(LOG_XML, "</ports>\n");
    return;
  }

  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Interesting %s on %s (%s):\n",
	    (o.ipprotscan)? "protocols" : "ports", currenths->name, 
	    inet_ntoa(currenths->host));
  log_write(LOG_MACHINE,"Host: %s (%s)", inet_ntoa(currenths->host), 
	    currenths->name);
  
  if (numignoredports > 0) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"(The %d %s%s scanned but not shown below %s in state: %s)\n", numignoredports, o.ipprotscan?"protocol":"port", (numignoredports == 1)? "" : "s", (numignoredports == 1)? "is" : "are", statenum2str(plist->ignored_port_state));
  }

  if (o.ipprotscan) {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Protocol   State       Name");
  } else if (!o.rpcscan) {  
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Port       State       Service");
  } else {
    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Port       State       Service (RPC)");
  }
  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s", (o.identscan)? ((o.rpcscan)? "           Owner\n" : "                 Owner\n") :"\n");
  log_write(LOG_MACHINE,"\t%s: ", (o.ipprotscan)? "Protocols" : "Ports" );
  
  protoarrays[0] = plist->tcp_ports;
  protoarrays[1] = plist->udp_ports;
  current = NULL;
  if (o.ipprotscan) {
    for (portno = 1; portno < 256; portno++) {
      if (!plist->ip_prots[portno]) continue;
      current = plist->ip_prots[portno];
      if (current->state != plist->ignored_port_state) {
	if (!first) log_write(LOG_MACHINE,", ");
	else first = 0;
	state = statenum2str(current->state);
	proto = nmap_getprotbynum(htons(current->portno));
	snprintf(portinfo, sizeof(portinfo), "%-24s",
		 proto?proto->p_name: "unknown");
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%-11d%-12s%-24s\n", portno, state, portinfo);
	log_write(LOG_MACHINE,"%d/%s/%s/", current->portno, state, 
		  (proto)? proto->p_name : "");
	log_write(LOG_XML, "<port protocol=\"ip\" portid=\"%d\"><state state=\"%s\" />", current->portno, state);
	if (proto && proto->p_name && *proto->p_name)
	  log_write(LOG_XML, "\n<service name=\"%s\" conf=\"3\" method=\"table\" />", proto->p_name);
	log_write(LOG_XML, "</port>\n");
      }
    }
  } else {
   for(portno = 1; portno < 65536; portno++) {
    for(protocount = 0; protocount < 2; protocount++) {
      if (protoarrays[protocount] && protoarrays[protocount][portno]) 
	current = protoarrays[protocount][portno];
      else continue;
      
      if (current->state != plist->ignored_port_state) {    
	if (!first) log_write(LOG_MACHINE,", ");
	else first = 0;
	strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
	snprintf(portinfo, sizeof(portinfo), "%d/%s", current->portno, protocol);
	state = statenum2str(current->state);
	service = nmap_getservbyport(htons(current->portno), protocol);
	
	if (o.rpcscan) {
	  switch(current->rpc_status) {
	  case RPC_STATUS_UNTESTED:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "");
	    break;
	  case RPC_STATUS_UNKNOWN:
	    strcpy(rpcinfo, "(RPC (Unknown Prog #))");
	    strcpy(rpcmachineinfo, "R");
	    break;
	  case RPC_STATUS_NOT_RPC:
	    rpcinfo[0] = '\0';
	    strcpy(rpcmachineinfo, "N");
	    break;
	  case RPC_STATUS_GOOD_PROG:
	    name = nmap_getrpcnamebynum(current->rpc_program);
	    snprintf(rpcmachineinfo, sizeof(rpcmachineinfo), "(%s:%li*%i-%i)", (name)? name : "", current->rpc_program, current->rpc_lowver, current->rpc_highver);
	    if (!name) {
	      snprintf(rpcinfo, sizeof(rpcinfo), "(#%li (unknown) V%i-%i)", current->rpc_program, current->rpc_lowver, current->rpc_highver);
	    } else {
	      if (current->rpc_lowver == current->rpc_highver) {
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i)", name, current->rpc_lowver);
	      } else 
		snprintf(rpcinfo, sizeof(rpcinfo), "(%s V%i-%i)", name, current->rpc_lowver, current->rpc_highver);
	    }
	    break;
	  default:
	    fatal("Unknown rpc_status %d", current->rpc_status);
	    break;
	  }
	  snprintf(serviceinfo, sizeof(serviceinfo), "%s%s%s", (service)? service->s_name : ((*rpcinfo)? "" : "unknown"), (service)? " " : "",  rpcinfo);
	} else {
	  Strncpy(serviceinfo, (service)? service->s_name : "unknown" , sizeof(serviceinfo));
	  strcpy(rpcmachineinfo, "");
	}
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%-11s%-12s%-24s", portinfo, state, serviceinfo);
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s\n", (current->owner)? current->owner : "");
	
	log_write(LOG_MACHINE,"%d/%s/%s/%s/%s/%s//", current->portno, state, 
		  protocol, (current->owner)? current->owner : "",
		  (service)? service->s_name: "", rpcmachineinfo);    
	
	log_write(LOG_XML, "<port protocol=\"%s\" portid=\"%d\">", protocol, current->portno);
	log_write(LOG_XML, "<state state=\"%s\" />", state);
	if (current->owner && *current->owner) {
	  log_write(LOG_XML, "<owner name=\"%s\" />", current->owner);
	}
	if (o.rpcscan && current->rpc_status == RPC_STATUS_GOOD_PROG) {
	  if (name) Strncpy(tmpbuf, name, sizeof(tmpbuf));
	  else snprintf(tmpbuf, sizeof(tmpbuf), "#%li", current->rpc_program);
	  log_write(LOG_XML, "<service name=\"%s\" proto=\"rpc\" rpcnum=\"%li\" lowver=\"%i\" highver=\"%i\" method=\"detection\" conf=\"5\" />\n", tmpbuf, current->rpc_program, current->rpc_lowver, current->rpc_highver);
	} else if (service) {
	  log_write(LOG_XML, "<service name=\"%s\" method=\"table\" conf=\"3\"%s />\n", service->s_name, (o.rpcscan && current->rpc_status == RPC_STATUS_UNKNOWN)? "proto=\"rpc\"" : ""); 
	}
	log_write(LOG_XML, "</port>\n");
      }
    }
   }
  }
  /*  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n"); */
  log_write(LOG_MACHINE, "\tIgnored State: %s (%d)", statenum2str(plist->ignored_port_state), plist->state_counts[plist->ignored_port_state]);
  log_write(LOG_XML, "</ports>\n");
}

char* xml_convert (const char* str) {
  char *temp, ch=0, prevch = 0, *p;
  temp = malloc(strlen(str)*6+1);
  for (p = temp;(prevch = ch, ch = *str);str++) {
    char *a;
    switch (ch) {
    case '<':
      a = "&lt;";
      break;
    case '>':
      a = "&gt;";
      break;
    case '&':
      a =  "&amp;";
      break;
    case '"':
      a = "&quot;";
      break;
    case '\'':
      a = "&apos;";
      break;
    case '-': 
      if (prevch == '-') { /* Must escape -- for comments */
        a =  "&#45;";
        break;
      }
    default:
      *p++ = ch;
      continue;
    }
    strcpy(p,a); p += strlen(a);
  }
  *p = 0;
  temp = realloc(temp,strlen(temp)+1);
  return temp;
}

/* Write some information (printf style args) to the given log stream(s) */
void log_write(int logt, const char *fmt, ...)
{
  va_list  ap;
  int i,l=logt,skid=1;
  char buffer[1000];

  va_start(ap, fmt);
  if (l & LOG_STDOUT) {
    vfprintf(o.nmap_stdout, fmt, ap);
    l-=LOG_STDOUT;
  }
  if (l & LOG_SKID_NOXLT) { skid=0; l -= LOG_SKID_NOXLT; l |= LOG_SKID; }
  if (l<0 || l>LOG_MASK) return;
  for (i=0;l;l>>=1,i++)
    {
      if (!o.logfd[i] || !(l&1)) continue;
      vsnprintf(buffer,sizeof(buffer)-1,fmt,ap);
      if (skid && ((1<<i)&LOG_SKID)) skid_output(buffer);
      fwrite(buffer,1,strlen(buffer),o.logfd[i]);
    }
  va_end(ap);
}

/* Close the given log stream(s) */
void log_close(int logt)
{
  int i;
  if (logt<0 || logt>LOG_MASK) return;
  for (i=0;logt;logt>>=1,i++) if (o.logfd[i] && (logt&1)) fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt) {
  int i;

  if (logt & LOG_STDOUT) {
    fflush(o.nmap_stdout);
    logt -= LOG_STDOUT;
  }
  if (logt & LOG_SKID_NOXLT)
    fatal("You are not allowed to log_flush() with LOG_SKID_NOXLT");

  if (logt<0 || logt>LOG_MASK) return;

  for (i=0;logt;logt>>=1,i++)
    {
      if (!o.logfd[i] || !(logt&1)) continue;
      fflush(o.logfd[i]);
    }

}

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all() {
  int fileno;

  for(fileno = 0; fileno < LOG_TYPES; fileno++) {
    if (o.logfd[fileno]) fflush(o.logfd[fileno]);
  }
  fflush(stdout);
  fflush(stderr);
}

/* Open a log descriptor of the type given to the filename given.  If 
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename)
{
  int i=0;
  if (logt<=0 || logt>LOG_MASK) return -1;
  while ((logt&1)==0) { i++; logt>>=1; }
  if (o.logfd[i]) fatal("Only one %s output filename allowed",logtypes[i]);
  if (*filename == '-' && *(filename + 1) == '\0')
    {
      o.logfd[i]=stdout;
      o.nmap_stdout = fopen("/dev/null", "w");
      if (!o.nmap_stdout)
	fatal("Could not assign /dev/null to stdout for writing");
  }
  else
    {
      if (o.append_output)
	o.logfd[i] = fopen(filename, "a");
      else
	o.logfd[i] = fopen(filename, "w");
      if (!o.logfd[i])
	fatal("Failed to open %s output file %s for writing", logtypes[i], filename);
    }
  return 1;
}

/* Used in creating skript kiddie style output.  |<-R4d! */
void skid_output(char *s)
{
  int i;
  for (i=0;s[i];i++)
    if (rand()%2==0)
      /* Substitutions commented out are not known to me, but maybe look nice */
      switch(s[i])
	{
	case 'A': s[i]='4'; break;
	  /*	case 'B': s[i]='8'; break;
	 	case 'b': s[i]='6'; break;
	        case 'c': s[i]='k'; break;
	        case 'C': s[i]='K'; break; */
	case 'e':
	case 'E': s[i]='3'; break;
	case 'i':
	case 'I': s[i]="!|1"[rand()%3]; break;
	  /*      case 'k': s[i]='c'; break;
	        case 'K': s[i]='C'; break;*/
	case 'o':
	case 'O': s[i]='0'; break;
	case 's':
	case 'S': 
	  if (s[i+1] && !isalnum((int) s[i+1])) 
	    s[i] = 'z';
	  else s[i] = '$';
	  break;
	case 'z': s[i]='s'; break;
	case 'Z': s[i]='S'; break;
	}  
    else
      {
	if (s[i]>='A' && s[i]<='Z' && (rand()%3==0)) s[i]+='a'-'A';
	else if (s[i]>='a' && s[i]<='z' && (rand()%3==0)) s[i]-='a'-'A';
      }
}

/* The items in ports should be
   in sequential order for space savings and easier to read output.  Outputs
   the rangelist to the log stream given (such as LOG_MACHINE or LOG_XML) */
void output_rangelist_given_ports(int logt, unsigned short *ports,
						    int numports) {
int i, previous_port = -2, range_start = -2, port;
char outpbuf[128];

 for(i=0; i <= numports; i++) {
   port = (i < numports)? ports[i] : 0xABCDE;
   if (port != previous_port + 1) {
     outpbuf[0] = '\0';
     if (range_start != previous_port && range_start != -2)
       sprintf(outpbuf, "-%hu", previous_port);
     if (port != 0xABCDE) {
       if (range_start != -2)
	 strcat(outpbuf, ",");
       sprintf(outpbuf + strlen(outpbuf), "%hu", port);
     }
     log_write(logt, "%s", outpbuf);
     range_start = port;
   }
   previous_port = port;
 }
}

/* Output the list of ports scanned to the top of machine parseable
   logs (in a comment, unfortunately).  The items in ports should be
   in sequential order for space savings and easier to read output */
void output_ports_to_machine_parseable_output(struct scan_lists *ports, 
					      int tcpscan, int udpscan,
					      int protscan) {
  int tcpportsscanned = ports->tcp_count;
  int udpportsscanned = ports->udp_count;
  int protsscanned = ports->prot_count;
 log_write(LOG_MACHINE, "# Ports scanned: TCP(%d;", tcpportsscanned);
 if (tcpportsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->tcp_ports, tcpportsscanned);
 log_write(LOG_MACHINE, ") UDP(%d;", udpportsscanned);
 if (udpportsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->udp_ports, udpportsscanned);
 log_write(LOG_MACHINE, ") PROTOCOLS(%d;", protsscanned);
 if (protsscanned)
   output_rangelist_given_ports(LOG_MACHINE, ports->prots, protsscanned);
 log_write(LOG_MACHINE, ")\n");
}

/* Simple helper function for output_xml_scaninfo_records */
static void doscaninfo(char *type, char *proto, unsigned short *ports, 
		  int numports) {
  log_write(LOG_XML, "<scaninfo type=\"%s\" protocol=\"%s\" numservices=\"%d\" services=\"", type, proto, numports);
  output_rangelist_given_ports(LOG_XML, ports, numports);
  log_write(LOG_XML, "\" />\n");
}

/* Similar to output_ports_to_machine_parseable_output, this function
   outputs the XML version, which is scaninfo records of each scan
   requested and the ports which it will scan for */
void output_xml_scaninfo_records(struct scan_lists *scanlist) {
  if (o.synscan) 
    doscaninfo("syn", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.ackscan) 
    doscaninfo("ack", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.bouncescan) 
    doscaninfo("bounce", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.connectscan)
    doscaninfo("connect", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.nullscan)
    doscaninfo("null", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.xmasscan)
    doscaninfo("xmas", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.windowscan)
    doscaninfo("window", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.maimonscan) 
    doscaninfo("maimon", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.finscan) 
    doscaninfo("fin", "tcp", scanlist->tcp_ports, scanlist->tcp_count);
  if (o.udpscan) 
    doscaninfo("udp", "udp", scanlist->udp_ports, scanlist->udp_count);
  if (o.ipprotscan) 
    doscaninfo("ipproto", "ip", scanlist->prots, scanlist->prot_count); 
}

/* Helper function to write the status and address/hostname info of a host 
   into the XML log */
static void write_xml_initial_hostinfo(struct hoststruct *currenths,
				  char *status) {
  log_write(LOG_XML, "<status state=\"%s\" />\n<address addr=\"%s\" addrtype=\"ipv4\" />\n", status,inet_ntoa(currenths->host));
  if (currenths->name && *currenths->name) {
    log_write(LOG_XML, "<hostnames><hostname name=\"%s\" type=\"PTR\" /></hostnames>\n", currenths->name);
  } else /* If machine is up, put blank hostname so front ends know that
	    no name resolution is forthcoming */
    if (strcmp(status, "up") == 0) log_write(LOG_XML, "<hostnames />\n");
}

/* Writes host status info to the log streams (including STDOUT).  An
   example is "Host: 10.11.12.13 (foo.bar.example.com)\tStatus: Up\n" to 
   machine log.  resolve_all should be passed nonzero if the user asked
   for all hosts (even down ones) to be resolved */
void write_host_status(struct hoststruct *currenths, int resolve_all) {

  if (o.listscan) {
    /* write "unknown" to stdout, machine, and xml */
    log_write(LOG_STDOUT|LOG_NORMAL|LOG_SKID, "Host %s (%s) not scanned\n", currenths->name, inet_ntoa(currenths->host));
    log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Unknown\n", inet_ntoa(currenths->host), currenths->name);
    write_xml_initial_hostinfo(currenths, "unknown");
  } 

  else if (currenths->wierd_responses) { /* SMURF ADDRESS */
    /* Write xml "down" or "up" based on flags and the smurf info */
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    log_write(LOG_XML, "<smurf responses=\"%d\" />\n", 
	      currenths->wierd_responses);
    log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Smurf (%d responses)\n",  inet_ntoa(currenths->host), currenths->name, currenths->wierd_responses);
    
    if (o.pingscan)
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings).%s\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses, 
		(currenths->flags & HOST_UP)? " Note -- the actual IP also responded." : "");
    else {
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings). %s.\n",  currenths->name, 
		inet_ntoa(currenths->host), currenths->wierd_responses,
		(currenths->flags & HOST_UP)? 
		" Still scanning it due to ping response from its own IP" 
		: "Skipping host");
    }
  } 

  else if (o.pingscan) {
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    if (currenths->flags & HOST_UP) {
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be up.\n", currenths->name, inet_ntoa(currenths->host));
      log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Up\n", inet_ntoa(currenths->host), currenths->name);
    } else if (o.verbose || resolve_all) {
      if (resolve_all)
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
      else log_write(LOG_STDOUT,"Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
      log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n", inet_ntoa(currenths->host), currenths->name);
    }
  } 

  else {   /* Normal case (non ping/list scan or smurf address) */
    write_xml_initial_hostinfo(currenths, 
			       (currenths->flags & HOST_UP)? "up" : "down");
    if (o.verbose) {
      if (currenths->flags & HOST_UP) {
	log_write(LOG_STDOUT, "Host %s (%s) appears to be up ... good.\n", 
		  currenths->name, inet_ntoa(currenths->host));
      } else {

	if (resolve_all) {   
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
	}
	else {
	  log_write(LOG_STDOUT,"Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
	}
	log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Down\n", inet_ntoa(currenths->host), currenths->name);
      }
    }
  }
}


/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(struct hoststruct *currenths) {
  int i;
  char numlst[512]; /* For creating lists of numbers */
  char *p; /* Used in manipulating numlst above */

  if (currenths->osscan_performed) {
    log_write(LOG_XML, "<os>");
    if (currenths->osscan_openport > 0) {
      log_write(LOG_XML, 
		"<portused state=\"open\" proto=\"tcp\" portid=\"%hu\" />\n",
		currenths->osscan_openport);
    }
    if (currenths->osscan_closedport > 0) {
      log_write(LOG_XML, 
		"<portused state=\"closed\" proto=\"tcp\" portid=\"%hu\" />\n",
		currenths->osscan_closedport);
    }
    
    if (currenths->FPR.overall_results == OSSCAN_SUCCESS) {
      if (currenths->FPR.num_perfect_matches > 0) {
        char *p;
	log_write(LOG_MACHINE,"\tOS: %s",  currenths->FPR.prints[0]->OS_name);
	log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"100\" />\n", 
		  p = xml_convert(currenths->FPR.prints[0]->OS_name));
        free(p);
	i = 1;
	while(currenths->FPR.accuracy[i] == 1 ) {
	  log_write(LOG_MACHINE,"|%s", currenths->FPR.prints[i]->OS_name);
	  log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"100\" />\n", 
		    p = xml_convert(currenths->FPR.prints[i]->OS_name));
          free(p);
	  i++;
	}
	
	if (currenths->FPR.num_perfect_matches == 1)
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
		    "Remote operating system guess: %s", 
		    currenths->FPR.prints[0]->OS_name);
	
	else {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,
		    "Remote OS guesses: %s", 
		    currenths->FPR.prints[0]->OS_name);
	  i = 1;
	  while(currenths->FPR.accuracy[i] == 1) {
	    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,", %s", 
		      currenths->FPR.prints[i]->OS_name);
	    i++;
	  }
	}
      } else {
	if (o.osscan_guess && currenths->FPR.num_matches > 0) {
	  /* Print the best guesses available */
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Aggressive OS guesses: %s (%d%%)", currenths->FPR.prints[0]->OS_name, (int) (currenths->FPR.accuracy[0] * 100));
	  for(i=1; i < 10 && currenths->FPR.num_matches > i &&
		currenths->FPR.accuracy[i] > 
		currenths->FPR.accuracy[0] - 0.10; i++) {
            char *p;
	    log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,", %s (%d%%)", currenths->FPR.prints[i]->OS_name, (int) (currenths->FPR.accuracy[i] * 100));
	    log_write(LOG_XML, "<osmatch name=\"%s\" accuracy=\"%d\" />\n", 
		      p = xml_convert(currenths->FPR.prints[i]->OS_name),  
		      (int) (currenths->FPR.accuracy[i] * 100));
            free(p);
	  }
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT, "\n");
	}
	if (o.scan_delay < 500 && currenths->osscan_openport > 0 &&
	    currenths->osscan_closedport > 0 ) {
	  log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No exact OS matches for host (If you know what OS is running on it, see http://www.insecure.org/cgi-bin/nmap-submit.cgi).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPs, currenths->numFPs, currenths->osscan_openport, currenths->osscan_closedport));
	} else {
	  log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No exact OS matches for host (test conditions non-ideal).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPs, currenths->numFPs, currenths->osscan_openport, currenths->osscan_closedport));
	}
      }
      
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");	  
      if (currenths->goodFP >= 0 && (o.debugging || o.verbose > 1) && currenths->FPR.num_perfect_matches > 0 ) {
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"OS Fingerprint:\n%s\n", fp2ascii(currenths->FPs[currenths->goodFP]));
      }
    } else if (currenths->FPR.overall_results == OSSCAN_NOMATCHES) {
      if (o.scan_delay < 500  && currenths->osscan_openport > 0 &&
	  currenths->osscan_closedport > 0 ) {
	log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No OS matches for host (If you know what OS is running on it, see http://www.insecure.org/cgi-bin/nmap-submit.cgi).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPs, currenths->numFPs, currenths->osscan_openport, currenths->osscan_closedport));
      } else {
	log_write(LOG_NORMAL|LOG_SKID_NOXLT|LOG_STDOUT,"No OS matches for host (test conditions non-ideal).\nTCP/IP fingerprint:\n%s\n", mergeFPs(currenths->FPs, currenths->numFPs, currenths->osscan_openport, currenths->osscan_closedport));
      }
    } else if (currenths->FPR.overall_results == OSSCAN_TOOMANYMATCHES)
      {
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Too many fingerprints match this host for me to give an accurate OS guess\n");
	if (o.debugging || o.verbose) {
	  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"TCP/IP fingerprint:\n%s\n\n",  mergeFPs(currenths->FPs, currenths->numFPs, currenths->osscan_openport, currenths->osscan_closedport));
	}
      } else { assert(0); }
     log_write(LOG_XML, "</os>\n");

     if (currenths->seq.lastboot) {
       char tmbuf[128];
       struct timeval tv;
       gettimeofday(&tv, NULL);
       strncpy(tmbuf, ctime(&(currenths->seq.lastboot)), sizeof(tmbuf));
       chomp(tmbuf);
       log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Uptime %.3f days (since %s)\n", (double) (tv.tv_sec - currenths->seq.lastboot) / 86400, tmbuf);
       log_write(LOG_XML, "<uptime seconds=\"%li\" lastboot=\"%s\" />\n", tv.tv_sec - currenths->seq.lastboot, tmbuf);
     }

     if (currenths->seq.responses > 3) {
       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%X", currenths->seq.seqs[i]);
	 while(*p) p++;
       }

       log_write(LOG_XML, "<tcpsequence index=\"%li\" class=\"%s\" difficulty=\"%s\" values=\"%s\" />\n", currenths->seq.index, seqclass2ascii(currenths->seq.seqclass), seqidx2difficultystr(currenths->seq.index), numlst); 
       if (o.verbose)
	 log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"%s", seqreport(&(currenths->seq)));
       log_write(LOG_MACHINE,"\tSeq Index: %d", currenths->seq.index);
     }

     if (currenths->seq.responses > 2) {
       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3876 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%hX", currenths->seq.ipids[i]);
	 while(*p) p++;
       }
       log_write(LOG_XML, "<ipidsequence class=\"%s\" values=\"%s\"/>\n", ipidclass2ascii(currenths->seq.ipid_seqclass), numlst);
       if (o.verbose)
	 log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"IPID Sequence Generation: %s\n", ipidclass2ascii(currenths->seq.ipid_seqclass));
       log_write(LOG_MACHINE,"\tIPID Seq: %s", ipidclass2ascii(currenths->seq.ipid_seqclass));

       p=numlst;
       for(i=0; i < currenths->seq.responses; i++) {
	 if (p - numlst > (sizeof(numlst) - 15)) 
	   fatal("STRANGE ERROR #3877 -- please report to fyodor@insecure.org\n");
	 if (p != numlst) *p++=',';
	 sprintf(p, "%X", currenths->seq.timestamps[i]);
	 while(*p) p++;
       }
       
       log_write(LOG_XML, "<tcptssequence class=\"%s\"", tsseqclass2ascii(currenths->seq.ts_seqclass));
       if (currenths->seq.ts_seqclass != TS_SEQ_UNSUPPORTED) {
	 log_write(LOG_XML, " values=\"%s\"", numlst);
       }
       log_write(LOG_XML, "/>\n");
     }
  }
}

/* Prints the statistics and other information that goes at the very end
   of an Nmap run */
void printfinaloutput(int numhosts_scanned, int numhosts_up, 
		      time_t starttime) {
  time_t timep;
  int i;
  char mytime[128];

  timep = time(NULL);
  i = timep - starttime;
  
  if (numhosts_scanned == 0)
    fprintf(stderr, "WARNING: No targets were specified, so 0 hosts scanned.\n");
  if (numhosts_scanned == 1 && numhosts_up == 0 && !o.listscan)
    log_write(LOG_STDOUT, "Note: Host seems down. If it is really up, but blocking our ping probes, try -P0\n");
  /*  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n"); */
  log_write(LOG_STDOUT|LOG_SKID, "Nmap run completed -- %d %s (%d %s up) scanned in %d %s\n", numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  i, (i == 1)? "second": "seconds");


  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  
  log_write(LOG_XML, "<runstats><finished time=\"%d\" /><hosts up=\"%d\" down=\"%d\" total=\"%d\" />\n", timep, numhosts_up, numhosts_scanned - numhosts_up, numhosts_scanned);

  log_write(LOG_XML, "<!-- Nmap run completed at %s; %d %s (%d %s up) scanned in %d %s -->\n", mytime, numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  i, (i == 1)? "second": "seconds");
  log_write(LOG_NORMAL|LOG_MACHINE, "# Nmap run completed at %s -- %d %s (%d %s up) scanned in %d %s\n", mytime, numhosts_scanned, (numhosts_scanned == 1)? "IP address" : "IP addresses", numhosts_up, (numhosts_up == 1)? "host" : "hosts",  i, (i == 1)? "second": "seconds");

  log_write(LOG_XML, "</runstats></nmaprun>\n");

}



