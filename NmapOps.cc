
/***********************************************************************
 * NmapOps.cc -- The NmapOps class contains global options, mostly     *
 * based on user-provided command-line settings.                       *
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
#include "nmap.h"

#include "NmapOps.h"

NmapOps o;

NmapOps::NmapOps() {
  Initialize();
}

void NmapOps::ReInit() {
  Initialize();
}

int NmapOps::SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
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
void NmapOps::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
}

struct in_addr NmapOps::v4source() {
 const struct in_addr *addy = v4sourceip();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
}

const struct in_addr *NmapOps::v4sourceip() {
   struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
}

// Number of milliseconds since getStartTime().  The current time is an
// optional argument to avoid an extre gettimeofday() call.
int NmapOps::TimeSinceStartMS(struct timeval *now) {
  struct timeval tv;
  if (!now)
    gettimeofday(&tv, NULL);
  else tv = *now;

  return TIMEVAL_MSEC_SUBTRACT(tv, start_time);
}

void NmapOps::Initialize() {
  setaf(AF_INET);
#ifndef WIN32
  isr00t = !(geteuid());
#else
  winip_init();	/* wrapper for all win32 initialization */
#endif
  debugging = DEBUGGING;
  verbose = DEBUGGING;
  randomize_hosts = 0;
  spoofsource = 0;
  device[0] = '\0';
  interactivemode = 0;
  host_group_sz = HOST_GROUP_SZ;
  generate_random_ips = 0;
  reference_FPs = NULL;
  magic_port = 33000 + (get_random_uint() % 31000);
  magic_port_set = 0;
  tcp_probe_port = DEFAULT_TCP_PROBE_PORT;
  max_parallelism = 0;
  min_parallelism = 0;
  max_rtt_timeout = MAX_RTT_TIMEOUT;
  min_rtt_timeout = MIN_RTT_TIMEOUT;
  initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  extra_payload_length = 0;
  extra_payload = NULL;
  host_timeout = HOST_TIMEOUT;
  scan_delay = 0;
  scanflags = -1;
  resume_ip.s_addr = 0;
  osscan_limit = 0;
  osscan_guess = 0;
  numdecoys = 0;
  decoyturn = -1;
  identscan = 0;
  osscan = 0;
  pingtype = PINGTYPE_UNKNOWN;
  listscan = pingscan = allowall = ackscan = bouncescan = connectscan = 0;
  rpcscan = nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  maimonscan = idlescan = finscan = udpscan = ipprotscan = noresolve = 0;
  force = append_output = 0;
  bzero(logfd, sizeof(FILE *) * LOG_TYPES);
  nmap_stdout = stdout;
  gettimeofday(&start_time, NULL);
  pTrace = false;
}

bool NmapOps::TCPScan() {
  return ackscan|bouncescan|connectscan|finscan|idlescan|maimonscan|nullscan|synscan|windowscan|xmasscan;
}

bool NmapOps::UDPScan() {
  return udpscan;
}


void NmapOps::ValidateOptions() {

  if (pingtype == PINGTYPE_UNKNOWN) {
    if (isr00t && af() == AF_INET) pingtype = PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_ICMP_PING;
    else pingtype = PINGTYPE_TCP; // if nonr00t or IPv6
  }

  /* Insure that at least one scantype is selected */
  if (TCPScan() + UDPScan() + ipprotscan + listscan + pingscan == 0) {
    if (isr00t && af() == AF_INET)
      synscan++;
    else connectscan++;
    if (verbose) error("No tcp, udp, or ICMP scantype specified, assuming %s scan. Use -sP if you really don't want to portscan (and just want to see what hosts are up).", synscan? "SYN Stealth" : "vanilla tcp connect()");
  }

  if (pingtype != PINGTYPE_NONE && spoofsource) {
    error("WARNING:  If -S is being used to fake your source address, you may also have to use -e <iface> and -P0 .  If you are using it to specify your real source address, you can ignore this warning.");
  }

  if (pingtype != PINGTYPE_NONE && idlescan) {
    error("WARNING: Many people use -P0 w/Idlescan to prevent pings from their true IP.  On the other hand, timing info Nmap gains from pings can allow for faster, more reliable scans.");
    sleep(2); /* Give ppl a chance for ^C :) */
  }

 if (numdecoys > 1 && idlescan) {
    error("WARNING: Your decoys won't be used in the Idlescan portion of your scanning (although all packets sent to the target are spoofed anyway");
  }

 if (connectscan && spoofsource) {
    error("WARNING:  -S will only affect the source address used in a connect() scan if you specify one of your own addresses.  Use -sS or another raw scan if you want to completely spoof your source address, but then you need to know what you're doing to obtain meaningful results.");
  }

 if (ipprotscan + (TCPScan() || UDPScan()) + listscan + pingscan > 1) {
   fatal("Sorry, the IPProtoscan, Listscan, and Pingscan (-sO, -sL, -sP) must currently be used alone rathre than combined with other scan types.");
 }

 if ((pingscan && pingtype == PINGTYPE_NONE)) {
    fatal("-P0 (skip ping) is incompatable with -sP (ping scan).  If you only want to enumerate hosts, try list scan (-sL)");
  }

 if (pingscan && (TCPScan() || UDPScan() || ipprotscan || listscan)) {
   fatal("Ping scan is not valid with any other scan types (the other ones all include a ping scan");
 }

/* We start with stuff users should not do if they are not root */
  if (!isr00t) {

#ifndef WIN32	/*	Win32 has perfectly fine ICMP socket support */
    if (pingtype & (PINGTYPE_ICMP_PING|PINGTYPE_ICMP_MASK|PINGTYPE_ICMP_TS)) {
      error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
      pingtype = PINGTYPE_TCP;
    }
#endif
    
    if (ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|synscan|udpscan|windowscan|xmasscan) {
#ifndef WIN32
      fatal("You requested a scan type which requires r00t privileges, and you do not have them.\n");
#else
      winip_barf(0);
#endif
    }
    
    if (numdecoys > 0) {
#ifndef WIN32
      fatal("Sorry, but you've got to be r00t to use decoys, boy!");
#else
      winip_barf(0);
#endif
    }
    
    if (fragscan) {
#ifndef WIN32
      fatal("Sorry, but fragscan requires r00t privileges\n");
#else
      winip_barf(0);
#endif
    }
    
    if (osscan) {
#ifndef WIN32
      fatal("TCP/IP fingerprinting (for OS scan) requires root privileges which you do not appear to possess.  Sorry, dude.\n");
#else
      winip_barf(0);
#endif
    }
  }
  
  
  if (numdecoys > 0 && rpcscan) {
    error("WARNING:  RPC scan currently does not make use of decoys so don't count on that protection");
  }
  
  if (bouncescan && pingtype != PINGTYPE_NONE) 
    log_write(LOG_STDOUT, "Hint: if your bounce scan target hosts aren't reachable from here, remember to use -P0 so we don't try and ping them prior to the scan\n");
  
  if (ackscan+bouncescan+connectscan+finscan+idlescan+maimonscan+nullscan+synscan+windowscan+xmasscan > 1)
    fatal("You specified more than one type of TCP scan.  Please choose only one of -sA, -b, -sT, -sF, -sI, -sM, -sN, -sS, -sW, and -sX");
  
  if (numdecoys > 0 && (bouncescan || connectscan)) {
    error("WARNING: Decoys are irrelevant to the bounce or connect scans");
  }
  
  if (fragscan && !(ackscan|finscan|maimonscan|nullscan|synscan|windowscan|xmasscan)) {
    fatal("Fragscan only works with ACK, FIN, Maimon, NULL, SYN, Window, and XMAS scan types");
  }
  
  if (identscan && !connectscan) {
    error("Identscan only works with connect scan (-sT) ... ignoring option");
    identscan = 0;
  }
  
  if (osscan && bouncescan)
    error("Combining bounce scan with OS scan seems silly, but I will let you do whatever you want!");
  
#if !defined(LINUX) && !defined(OPENBSD) && !defined(FREEBSD) && !defined(NETBSD)
  if (fragscan) {
    fprintf(stderr, "Warning: Packet fragmentation selected on a host other than Linux, OpenBSD, FreeBSD, or NetBSD.  This may or may not work.\n");
  }
#endif
  
  if (osscan && pingscan) {
    fatal("WARNING:  OS Scan is unreliable with a ping scan.  You need to use a scan type along with it, such as -sS, -sT, -sF, etc instead of -sP");
  }
  
  if (resume_ip.s_addr && generate_random_ips)
    resume_ip.s_addr = 0;
  
  if (magic_port_set && connectscan) {
    error("WARNING:  -g is incompatible with the default connect() scan (-sT).  Use a raw scan such as -sS if you want to set the source port.");
  }

  if (min_parallelism > max_parallelism) {
    fatal("--min_parallelism must be less than or equal to --max_parallelism");
  }
  
  if (af() == AF_INET6 && (numdecoys|osscan|bouncescan|fragscan|ackscan|finscan|idlescan|ipprotscan|maimonscan|nullscan|rpcscan|synscan|udpscan|windowscan|xmasscan)) {
    fatal("Sorry -- IPv6 support is currently only available for connect() scan (-sT), ping scan (-sP), and list scan (-sL).  If you want better IPv6 support, send your request to fyodor@insecure.org so he can guage demand.");
  }
}
  
