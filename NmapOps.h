
/***********************************************************************
 * NmapOps.h -- The NmapOps class contains global options, mostly      *
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

class NmapOps {
 public:
  NmapOps();
  void ReInit(); // Reinitialize the class to default state
  void setaf(int af) { addressfamily = af; }
  int af() { return addressfamily; }
  // no setpf() because it is based on setaf() values
  int pf() { return (af() == AF_INET)? PF_INET : PF_INET6; }
  /* Returns 0 for success, nonzero if no source has been set or any other
     failure */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);
// The time this obj. was instantiated   or last ReInit()ed.
  const struct timeval *getStartTime() { return &start_time; }
  // Number of milliseconds since getStartTime().  The current time is an
  // optional argument to avoid an extre gettimeofday() call.
  int TimeSinceStartMS(struct timeval *now=NULL); 
  struct in_addr v4source();
  const struct in_addr *v4sourceip();
  bool TCPScan(); /* Returns true if at least one chosen scan type is TCP */
  bool UDPScan(); /* Returns true if at least one chosen scan type is UDP */
  bool RawScan();
  void ValidateOptions(); /* Checks that the options given are
                             reasonable and consistant.  If they aren't, the
                             function may bail out of Nmap or make small
		             adjustments (quietly or with a warning to the
		             user). */
  int isr00t;
  int debugging;
  bool packetTrace() { return (debugging >= 3)? true : pTrace;  }
  // Note that packetTrace may turn on at high debug levels even if
  // setPacketTrace(false) has been called
  void setPacketTrace(bool pt) { pTrace = pt;  }
  int verbose;
  int randomize_hosts;
  int spoofsource; /* -S used */
  char device[64];
  int interactivemode;
  int host_group_sz;
  int generate_random_ips; /* -iR option */
  FingerPrint **reference_FPs;
  u16 magic_port;
  unsigned short magic_port_set; /* Was this set by user? */
  u16 tcp_probe_port;

  /* Scan timing/politeness issues */
  int max_parallelism; // 0 means it has not been set
  int min_parallelism; // 0 means it has not been set
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  int extra_payload_length; /* These two are for --data_length op */
  char *extra_payload;
  unsigned long host_timeout;
  int scan_delay;
  int scanflags; /* if not -1, this value should dictate the TCP flags
		    for the core portscaning routine (eg to change a
		    FIN scan into a PSH scan.  Sort of a hack, but can
		    be very useful sometimes. */

  struct in_addr resume_ip; /* The last IP in the log file if user 
			       requested --restore .  Otherwise 
			       restore_ip.s_addr == 0.  Also 
			       target_struct_get will eventually set it 
			       to 0. */

  struct in_addr decoys[MAX_DECOYS];
  int osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  int osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  int identscan;
  int osscan;
  int pingtype;
  int listscan;
  int pingscan;
  int allowall;
  int fragscan;
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int rpcscan;
  int synscan;
  int udpscan;
  int windowscan;
  int xmasscan;
  int noresolve;
  int force; /* force nmap to continue on even when the outcome seems somewhat certain */
  int append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_TYPES];
  FILE *nmap_stdout; /* Nmap standard output */
 private:
  void Initialize();
  int addressfamily; /*  Address family:  AF_INET or AF_INET6 */  
  struct sockaddr_storage sourcesock;
  size_t sourcesocklen;
  struct timeval start_time;
  bool pTrace; // Whether packet tracing has been enabled
};
  
