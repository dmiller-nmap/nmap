#include "nmap.h"
#include "osscan.h"

/* global options */
extern char *optarg;
extern int optind;
struct ops o;  /* option structure */

int main(int argc, char *argv[]) {
char *p;
int i, j, arg, argvlen;
FILE *inputfd = NULL;
char *host_spec;
short fastscan=0, randomize=1, resolve_all=0;
short quashargv = 0;
int numhosts_scanned = 0;
int starttime;
int lookahead = LOOKAHEAD;
struct timeval tv; /* Just for seeding random generator */
short bouncescan = 0;
unsigned short *ports = NULL;
char myname[MAXHOSTNAMELEN + 1];
#if (defined(IN_ADDR_DEEPSTRUCT) || defined( SOLARIS))
/* Note that struct in_addr in solaris is 3 levels deep just to store an
 * unsigned int! */
struct ftpinfo ftp = { FTPUSER, FTPPASS, "",  { { { 0 } } } , 21, 0};
#else
struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
#endif
struct hostent *target = NULL;
struct in_addr *source=NULL;
char **fakeargv = (char **) safe_malloc(sizeof(char *) * (argc + 1));
struct hoststruct *currenths;
char emptystring[1];
int sourceaddrwarning = 0; /* Have we warned them yet about unguessable
			      source addresses? */
/* argv faking silliness */
for(i=0; i < argc; i++) {
  fakeargv[i] = safe_malloc(strlen(argv[i]) + 1);
  strncpy(fakeargv[i], argv[i], strlen(argv[i]) + 1);
}
fakeargv[argc] = NULL;

printf("\nStarting nmap V. %s by Fyodor (fyodor@dhp.com, www.insecure.org/nmap/)\n", VERSION);

/* Seed our random generator */
gettimeofday(&tv, NULL);
if (tv.tv_usec) srand(tv.tv_usec);
else if (tv.tv_sec) srand(tv.tv_sec);
else srand(time(NULL));

/* initialize our options */
options_init();

emptystring[0] = '\0'; /* It wouldn't be an emptystring w/o this ;) */

/* Trap these sigs for cleanup */
signal(SIGINT, sigdie);
signal(SIGTERM, sigdie);
signal(SIGHUP, sigdie); 

if (argc < 2 ) printusage(argv[0]);

/* OK, lets parse these args! */
while((arg = getopt(argc,fakeargv,"Ab:D:de:Ffg:hIi:L:M:NnOo:P::p:qrRS:s:T:w:Vv")) != EOF) {
  switch(arg) {
  case 'A': o.allowall++; break;
  case 'b': 
    bouncescan++;
    if (parse_bounce(&ftp, optarg) < 0 ) {
      fprintf(stderr, "Your argument to -b is fucked up. Use the normal url style:  user:pass@server:port or just use server and use default anon login\n  Use -h for help\n");
    }
    break;
  case 'D':
    if (o.numdecoys >= MAX_DECOYS -1)
      fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)");
    if (resolve(optarg, &o.decoys[o.numdecoys])) {
      o.numdecoys++;
    } else {
    fatal("Failed to resolve decoy host: %s (must be hostname or IP address", optarg);
    }
    break;
  case 'd': o.debugging++; o.verbose++; break;
  case 'e': strncpy(o.device, optarg,63); o.device[63] = '\0'; break;
  case 'F': fastscan++; break;
  case 'f': o.fragscan++; break;
  case 'g': 
    o.magic_port = atoi(optarg);
    o.magic_port_set = 1;
    if (!o.magic_port) fatal("-g needs nonzero argument");
    break;    
  case 'h': 
  case '?': printusage(argv[0]);
  case 'I': o.identscan++; break;
  case 'i': 
    if (inputfd) {
      fatal("Only one input filename allowed");
    }
    if (!strcmp(optarg, "-")) {
      inputfd = stdin;
      printf("Reading target specifications from stdin\n");
    } else {    
      inputfd = fopen(optarg, "r");
      if (!inputfd) {
	fatal("Failed to open input file %s for writing", optarg);
      }  
      printf("Reading target specifications from FILE: %s\n", optarg);
    }
    break;  
  case 'L': lookahead = atoi(optarg); break;
    /*  case 'l': o.lamerscan++; o.udpscan++; break; */
  case 'M': 
    o.max_sockets = atoi(optarg); 
    if (o.max_sockets < 1) fatal("Argument to -M must be at least 1!");
    if (o.max_sockets > MAX_SOCKETS_ALLOWED) {
      printf("Warning: You are limited to MAX_SOCKETS_ALLOWD (%d) paralell sockets.  If you really need more, change the #define and recompile.\n", MAX_SOCKETS_ALLOWED);
      o.max_sockets = MAX_SOCKETS_ALLOWED;
    }
    break;
  case 'n': o.noresolve++; break;
  case 'N': o.force++; break;
  case 'O': 
    o.osscan++; 
    o.reference_FPs = parse_fingerprint_reference_file();
    break;
  case 'o': 
    if (o.logfd) fatal("Only one log filename allowed");
    o.logfd = fopen(optarg, "w");
    if (!o.logfd) 
      fatal("Failed to open output file %s for writing", optarg);
    break;
  case 'P': 
    if (*optarg == '\0' || *optarg == 'I')
      o.pingtype = icmp;
    else if (*optarg == '0' || *optarg == 'N' || *optarg == 'D')
      o.pingtype = none;
    else if (*optarg == 'T') {
      o.pingtype = tcp;
      if (isdigit((int) *(optarg+1)))
	o.tcp_probe_port = atoi(optarg+1);
	printf("TCP probe port is %hu\n", o.tcp_probe_port);
    }
    else {fatal("Illegal Argument to -P, use -P0, -PI, -PT, or -PT80 (or whatever number you want for the TCP probe destination port)"); }
    break;
  case 'p': 
    if (ports)
      fatal("Only 1 -p option allowed, seperate multiple ranges with commas.");
    ports = getpts(optarg); break;
  case 'R': resolve_all++; break;
  case 'r': 
    randomize = 0;
    error("Warning: Randomize syntax has been changed, -r now requests that ports NOT be randomized");
    break;
  case 's': 
    if (!*optarg) {
      fprintf(stderr, "An option is required for -s, most common are -sT (tcp scan), -sS (SYN scan), -sF (FIN scan), -sU (UDP scan) and -sP (Ping scan)");
      printusage(argv[0]);
    }
      p = optarg;
      while(*p) {
	switch(*p) {
	case 'B':  break;
	case 'F':  o.finscan++;break;
	case 'M':  o.maimonscan++;break;
	case 'N':  o.nullscan++;break;
	case 'P':  o.pingscan++;break;
	case 'S':  o.synscan++;break;
	case 'T':  o.connectscan++;break;
	case 'U':  
	  printf("WARNING:  -sU is now UDP scan -- for TCP FIN scan use -sF\n");
	  o.udpscan++;
	  break;
	case 'X':  o.xmasscan++;break;
	default:  error("Scantype %c not supported\n",*p); printusage(argv[0]); break;
	}
	p++;
      }
      break;
  case 'S': 
    if (o.spoofsource)
      fatal("You can only use the source option once!  Use -D <decoy1> -D <decoy2> etc. for decoys\n");
    source = safe_malloc(sizeof(struct in_addr));
    o.spoofsource = 1;
    if (!resolve(optarg, source))
      fatal("Failed to resolve source address, try dotted decimal IP address\n");
    break;
  case 'T': o.ptime = atoi(optarg); break;
  case 'q': quashargv++; break;
  case 'w': o.wait = atoi(optarg); break;
  case 'V': 
    printf("\nnmap V. %s by Fyodor (fyodor@dhp.com, www.insecure.org/nmap/)\n", VERSION); 
    exit(0);
    break;
  case 'v': o.verbose++; break;
  }
}

/* Take care of user wierdness */
if (!o.isr00t && o.pingtype == icmp) {
  error("Warning:  You are not root -- using TCP pingscan rather than ICMP");
  o.pingtype = tcp;
}
if (bouncescan && o.pingtype != none) printf("Hint: if your bounce scan target hosts aren't reachable from here, remember to use -P0 so we don't try and ping them prior to the scan\n");
if (o.connectscan && (o.synscan || o.finscan || o.maimonscan || o.xmasscan || o.nullscan)) 
  fatal("Pick just one of -t, -s, and -U.  They all do a TCP portscan.\
 If you are trying to do TCP SYN scanning, just use -s, for FIN use -U, and \
 for normal connect() style scanning, use -t");
if ((o.fragscan && !o.synscan && !o.finscan &&!o.maimonscan && !o.nullscan && !o.xmasscan)) {
  printf("Specified -f but don't know whether to fragment SYN,FIN,NULL, or XMAS scan.  Ie you need to still specify -S[something].  Doing fragmented SYN scan\n");
  o.synscan++;
}
#ifndef LINUX
 if (o.fragscan) {
   fprintf(stderr, "Warning: Packet fragmentation selected on non-linux host.  This may or may not work.\n");
 }
#endif
if (o.pingtype == tcp && o.numdecoys > 1)
  printf("Warning: Using TCPping could theoretically reveal your IP address (even though you are using decoys.  If this concerns you, use -pI (the default)\n"); 
if ((o.synscan || o.finscan || o.maimonscan || o.udpscan || o.fragscan || o.xmasscan || o.nullscan) && !o.isr00t)
  fatal("Options specified require r00t privileges.  You don't have them!");
if (!o.connectscan && !o.udpscan && !o.synscan && !o.finscan && !o.maimonscan &&  !o.nullscan && !o.xmasscan && !bouncescan && !o.pingscan) {
  o.connectscan++;
  if (o.verbose) error("No scantype specified, assuming vanilla tcp connect()\
 scan. Use -sP if you really don't want to portscan (and just want to see what hosts are up).");
if (fastscan && ports)
  fatal("You can use -F (fastscan) OR -p for explicit port specification.\
  Not both!\n");
}
if (o.max_sockets > MAX_SOCKETS_ALLOWED) {
   printf("Warning: You are limited to MAX_SOCKETS_ALLOWD (%d) paralell sockets.  If you really need more, change the #define and recompile.\n", MAX_SOCKETS_ALLOWED);
   o.max_sockets = MAX_SOCKETS_ALLOWED;
}

/* Default dest port for tcp probe */
if (!o.tcp_probe_port) o.tcp_probe_port = o.magic_port;

/* Set up our array of decoys! */
o.decoyturn = (o.numdecoys == 0)?  0 : rand() % o.numdecoys; 
o.numdecoys++;
for(i=o.numdecoys-1; i > o.decoyturn; i--)
  o.decoys[i] = o.decoys[i-1];

/* If he wants to bounce off of an ftp site, that site better damn well be reachable! */
if (bouncescan) {
  if (!inet_aton(ftp.server_name, &ftp.server)) {
    if ((target = gethostbyname(ftp.server_name)))
      memcpy(&ftp.server, target->h_addr_list[0], 4);
    else {
      fprintf(stderr, "Failed to resolve ftp bounce proxy hostname/IP: %s\n",
	      ftp.server_name);
      exit(1);
    } 
  }  else if (o.verbose)
    printf("Resolved ftp bounce attack proxy to %s (%s).\n", 
	   ftp.server_name, inet_ntoa(ftp.server)); 
}
fflush(stdout);

if (o.logfd) {
  /* Brief info incase they forget what was scanned */
  fprintf(o.logfd, "# Log of: ");
  for(i=0; i < argc; i++)
    fprintf(o.logfd, "%s ", fakeargv[i]);
  fprintf(o.logfd, "\n");
}

if (fastscan)
  ports = getfastports(o.synscan|o.connectscan|o.fragscan|o.finscan|o.maimonscan|bouncescan|o.nullscan|o.xmasscan,
                       o.udpscan|o.lamerscan);
if (!ports && !o.pingscan) ports = getpts("1-1024");


/* more fakeargv junk, BTW malloc'ing extra space in argv[0] doesn't work */
if (quashargv) {
  argvlen = strlen(argv[0]);
  if (argvlen < strlen(FAKE_ARGV))
    fatal("If you want me to fake your argv, you need to call the program with a longer name.  Try the full pathname, or rename it fyodorssuperdedouperportscanner");
  strncpy(argv[0], FAKE_ARGV, strlen(FAKE_ARGV));
  for(i = strlen(FAKE_ARGV); i < argvlen; i++) argv[0][i] = '\0';
  for(i=1; i < argc; i++) {
    argvlen = strlen(argv[i]);
    for(j=0; j <= argvlen; j++)
      argv[i][j] = '\0';
  }
}

signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our program doesn't crash because
                             of it, but we really shouldn't get an unsuspected
                             SIGPIPE */
if (o.max_sockets && (i = max_sd()) && i < o.max_sockets) {
  printf("Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway\n", o.max_sockets, i);
}

if (!o.max_sockets) {
  o.max_sockets = max_sd();
  if (!o.max_sockets)
    o.max_sockets = 60;
  o.max_sockets = MIN(o.max_sockets, 125);
}

if (o.debugging > 1) printf("The max # of sockets on your system is: %d\n", i);

if (randomize)
  shortfry(ports); 

starttime = time(NULL);

while((host_spec = grab_next_host_spec(inputfd, argc, fakeargv))) {
  while((currenths = nexthost(host_spec, 500, o.ptime)) && currenths->host.s_addr) {
    numhosts_scanned++;
    /* Ugly temporary hack to init timeout info */
    currenths->rtt = currenths->to.timeout;

    /*    printf("Nexthost() returned: %s\n", inet_ntoa(currenths->host));*/
    target = NULL;
    if (((currenths->flags & HOST_UP) || resolve_all) && !o.noresolve)
      target = gethostbyaddr((char *) &currenths->host, 4, AF_INET);
    if (target) {
      currenths->name = strdup(target->h_name);
    }
    else {
      currenths->name = emptystring;
    }
    if (o.wait && currenths->rtt) currenths->rtt += o.wait;
    if (source) memcpy(&currenths->source_ip, source, sizeof(struct in_addr));
if (!o.pingscan) {
  if (o.pingtype != none && (currenths->flags & HOST_UP) && (o.verbose || o.debugging)) 
    printf("Host %s (%s) appears to be up ... good.\n", currenths->name, inet_ntoa(currenths->host));    
  else if (o.verbose && o.pingtype != none && !(currenths->flags & HOST_UP)) {  
    if (resolve_all)
      nmap_log("Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
    else printf("Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
  }

}
else {
  if (currenths->flags & HOST_UP) 
    nmap_log("Host %s (%s) appears to be up.\n", currenths->name, inet_ntoa(currenths->host));    
  else 
    if (o.verbose || o.debugging || resolve_all) {    
      if (resolve_all)
	nmap_log("Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
      else printf("Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
    }
  if (currenths->wierd_responses)
    nmap_log("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
}
if (currenths->flags & HOST_UP && !currenths->source_ip.s_addr && ( o.synscan || o.finscan || o.maimonscan || o.udpscan || o.nullscan || o.xmasscan)) {
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(target = gethostbyname(myname)))
    fatal("Your system is messed up.  Cannot get hostname!  You might have to use -S <my_IP_address>\n"); 
  memcpy(&currenths->source_ip, target->h_addr_list[0], sizeof(struct in_addr));
  if (! sourceaddrwarning) {
    printf("We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.\n", inet_ntoa(currenths->source_ip));
    sourceaddrwarning = 1;
  }
}

 if (o.device[0]) { strcpy(currenths->device, o.device); }

/* Figure out what link-layer device (interface) to use (ie eth0, ppp0, etc) */
if (!o.device[0] && currenths->flags & HOST_UP && (o.nullscan || o.xmasscan || o.udpscan || o.finscan || o.maimonscan ||  o.synscan) && !ipaddr2devname( currenths->device, &currenths->source_ip))
  fatal("Could not figure out what device to send the packet out on!  You might possibly want to try -S (but this is probably a bigger problem).  If you are trying to sp00f the source of a SYN/FIN scan with -S <fakeip>, then you must use -e eth0 (or other devicename) to tell us what interface to use.\n");
/* Set up the decoy */
o.decoys[o.decoyturn] = currenths->source_ip;

    /* Time for some actual scanning! */    
    if (currenths->flags & HOST_UP) {
      if (o.connectscan) tcp_scan(currenths, ports, o.ptime);
      
      if (o.synscan) pos_scan(currenths, ports, SYN_SCAN);
      
      if (o.finscan) super_scan(currenths, ports, FIN_SCAN);
      if (o.xmasscan) super_scan(currenths, ports, XMAS_SCAN);
      if (o.nullscan) super_scan(currenths, ports, NULL_SCAN);
      if (o.maimonscan) super_scan(currenths, ports, MAIMON_SCAN);
      if (o.udpscan) super_scan(currenths, ports, UDP_SCAN);
      
      if (bouncescan) {
	if (ftp.sd <= 0) ftp_anon_connect(&ftp);
	if (ftp.sd > 0) bounce_scan(currenths, ports, &ftp);
      }
      /*      if (o.udpscan) {
	if (!o.isr00t || o.lamerscan) 
	  lamer_udp_scan(currenths, ports);

	else udp_scan(currenths, ports);
	}*/
      
      if (o.osscan) {
	os_scan(currenths);
      }
    
      if (!currenths->ports && !o.pingscan) {
	nmap_log("No ports open for host %s (%s)\n", currenths->name,
	       inet_ntoa(currenths->host));
	if (currenths->wierd_responses)
	  nmap_log("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
      }
      if (currenths->ports) {
	nmap_log("Interesting ports on %s (%s):\n", currenths->name, 
	       inet_ntoa(currenths->host));
	printandfreeports(currenths->ports);
	if (currenths->wierd_responses)
	  nmap_log("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
      } if (o.osscan) {
	if (currenths->seq.responses > 3) {
	  nmap_log("TCP Seq prediction report:  %s\n", seqreport(&(currenths->seq)));
	}
	if (currenths->FP_matches[0]) {
	  i=0;
	  if (!currenths->FP_matches[1])
	    nmap_log("Remote operating system guess: ");
	  else  nmap_log("Remote OS guesses: ");
	  while(currenths->FP_matches[i]) {
	    nmap_log(" %s", currenths->FP_matches[i]->OS_name);
	    i++;
	  }
	  nmap_log("\n");
	  if (o.debugging || o.verbose > 1) {
	    nmap_log("OS Fingerprint:\n%s\n", fp2ascii(currenths->FP));
	  }
	} else {
	  nmap_log("No OS matches for this host.  TCP fingerprint:\n%s\n", fp2ascii(currenths->FP));
	}


      }
    }
    fflush(stdout);
  }
}

printf("Nmap run completed -- %d host(s) scanned in %ld seconds\n", numhosts_scanned, (long) time(NULL) - starttime);
return 0;
}

void options_init() {
bzero( (char *) &o, sizeof(struct ops));
o.isr00t = !(geteuid());
o.debugging = DEBUGGING;
o.verbose = DEBUGGING;
/*o.max_sockets = MAX_SOCKETS;*/
o.magic_port = 33000 + (rand() % 31000);
#ifdef IGNORE_ZERO_AND_255_HOSTS
o.allowall = !(IGNORE_ZERO_AND_255_HOSTS);
#endif
o.ptime = PING_TIMEOUT;
o.pingtype = (o.isr00t)? icmp : tcp;
}

__inline__ void max_rcvbuf(int sd) {
int optval = 524288 /*2^19*/, optlen = sizeof(int);

if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (void *) &optval, optlen))
  if (o.debugging) perror("Problem setting large socket recieve buffer");
if (o.debugging) {
  getsockopt(sd, SOL_SOCKET, SO_RCVBUF,(void *) &optval, &optlen);
  printf("Our buffer size is now %d\n", optval);
}
}
/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd() {
struct rlimit r;
#if(defined(RLIMIT_NOFILE))
if (!getrlimit(RLIMIT_NOFILE, &r)) {
r.rlim_cur = r.rlim_max;
if (setrlimit(RLIMIT_NOFILE, &r))
  if (o.debugging) perror("setrlimit RLIMIT_NOFILE failed");
if (!getrlimit(RLIMIT_NOFILE, &r))
  return r.rlim_cur;
else return 0;
}
#endif
#if(defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE))
if (!getrlimit(RLIMIT_OFILE, &r)) {
r.rlim_cur = r.rlim_max;
if (setrlimit(RLIMIT_OFILE, &r))
  if (o.debugging) perror("setrlimit RLIMIT_OFILE failed");
if (!getrlimit(RLIMIT_OFILE, &r))
  return r.rlim_cur;
else return 0;
}
#endif
return 0;
}

__inline__ int block_socket(int sd) {
int options;
options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
return 1;
}

__inline__ void broadcast_socket(int sd) {
  int one = 1;
  if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (void *)&one, sizeof(int)) != 0) {
    printf("Failed to secure socket broadcasting permission\n");
    perror("setsockopt");
  }
}

/* We set the socket lingering so we will RST connection instead of wasting
   bandwidth with the four step close  */
__inline__ void init_socket(int sd) {
struct linger l;

l.l_onoff = 1;
l.l_linger = 0;

if (setsockopt(sd, SOL_SOCKET, SO_LINGER,  (void *) &l, sizeof(struct linger)))
  {
   fprintf(stderr, "Problem setting socket SO_LINGER, errno: %d\n", errno);
   perror("setsockopt");
  }
}

/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array 
   of port numbers*/
unsigned short *getpts(char *origexpr) {
int exlen = strlen(origexpr);
char *p,*q;
unsigned short *tmp, *ports;
int i=0, j=0,start,end;
char *expr = strdup(origexpr);
char *mem = expr;

ports = safe_malloc(65536 * sizeof(short));
for(;j < exlen; j++) 
  if (expr[j] != ' ') expr[i++] = expr[j]; 
expr[i] = '\0';
exlen = i;
i=0;
while((p = strchr(expr,','))) {
  *p = '\0';
  if (*expr == '-') {start = 1; end = atoi(expr+ 1);}
  else {
    start = end = atoi(expr);
    if ((q = strchr(expr,'-')) && *(q+1) ) end = atoi(q + 1);
    else if (q && !*(q+1)) end = 65535;
  }
  if (o.debugging)
    printf("The first port is %d, and the last one is %d\n", start, end);
  if (start < 1 || start > end) fatal("Your port specifications are illegal!");
  for(j=start; j <= end; j++) 
    ports[i++] = j;
  expr = p + 1;
}
if (*expr == '-') {
  start = 1;
  end = atoi(expr+ 1);
}
else {
  start = end = atoi(expr);
  if ((q =  strchr(expr,'-')) && *(q+1) ) end = atoi(q+1);
  else if (q && !*(q+1)) end = 65535;
}
if (o.debugging)
  printf("The first port is %d, and the last one is %d\n", start, end);
if (start < 1 || start > end) fatal("Your port specifications are illegal!");
for(j=start; j <= end; j++) 
  ports[i++] = j;
o.numports = i;
ports[i++] = 0;
tmp = realloc(ports, i * sizeof(short));
  free(mem);
  return tmp;
}

unsigned short *getfastports(int tcpscan, int udpscan) {
  int portindex = 0, res, lastport = 0;
  unsigned int portno = 0;
  unsigned short *ports;
  char proto[10];
  char line[81];
  FILE *fp;
  ports = safe_malloc(65535 * sizeof(unsigned short));
  proto[0] = '\0';
  if (!(fp = fopen("/etc/services", "r"))) {
    printf("We can't open /etc/services for reading!  Fix your system or don't use -f\n");
    perror("fopen");
    exit(1);
  }
  
  while(fgets(line, 80, fp)) {
    res = sscanf(line, "%*s %u/%s", &portno, proto);
    if (res == 2 && portno != 0 && portno != lastport) { 
      lastport = portno;
      if (tcpscan && proto[0] == 't')
	ports[portindex++] = portno;
      else if (udpscan && proto[0] == 'u')
	ports[portindex++] = portno;
    }
  }


o.numports = portindex;
ports[portindex++] = 0;
return realloc(ports, portindex * sizeof(unsigned short));
}

void printusage(char *name) {
printf("nmap V. %s usage: nmap [Scan Type(s)] [Options] <host or net #1 ... [#N]>\n\
Scan types\n\
   -sT tcp connect() port scan\n\
   -sS tcp SYN stealth port scan (must be root)\n\
   -sF,-SX, -sN Stealth FIN, Xmas, or Null scan (only works against UNIX).\n\
   -sP ping \"scan\". Find which hosts on specified network(s) are up but don't \n\
       port scan them\n\
   -sU UDP port scan, must be r00t\n\
   -b <ftp_relay_host> ftp \"bounce attack\" port scan\n\
Options (none are required, most can be combined):\n\
   -f use tiny fragmented packets for SYN, FIN, Xmas, or NULL scan.\n\
   -P0 Don't ping hosts (needed to scan www.microsoft.com and others)\n\
   -PT Use \"TCP Ping\" to see what hosts are up (for normal and ping scans).\n\
   -PT80 Use \"TCP Ping\" scan with probe destination port of 80 (or whatever).\n\
   -PI Use ICMP ping packet to determines hosts that are up (default for root users)\n\
   -i Get identd (rfc 1413) info on listening TCP processes.\n\
   -p <range> ports: ex: \'-p 23\' will only try port 23 of the host(s)\n\
                  \'-p 20-30,63000-\' scans 20-30 and 63000-65535. default: 1-1024\n\
   -D <decoy_host> Make it appear that a scan is also coming from decoy_host.  Even\n\
      if the target detects the scan, they won't know who is scanning them.\n\
   -F fast scan. Only scans ports in /etc/services, a la strobe(1).\n\
   -n Don't DNS resolve anything unless we have to (makes ping scans faster)\n\
   -o <logfile> Output scan logs to <logfile>.\n\
   -i <inputfile> Grab IP numbers or hostnames from file.  Use '-' for stdin\n\
   -g <portnumber> Sets the source port used for scans.  20 and 53 are good choices.\n\
   -L <num> Number of pings to perform in parallel.  Your default is: %d\n\
   -R Try to resolve all hosts, even down ones (can take a lot of time)\n\
   -r do NOT randomize target port scanning order.\n\
   -S <your_IP> If you want to specify the source address of SYN or FYN scan.\n", VERSION, LOOKAHEAD);
if (!o.allowall) printf("   -A Allow scanning .0 and .255 addresses" );
printf("   -T <seconds> Set the ping and tcp connect() timeout.\n\
   -v Verbose.  Its use is recommended.  Use twice for greater effect.\n\
   -h help, print this junk.  Also see http://www.insecure.org/nmap/\n\
   -V Print version number and exit.\n\
   -w <n> delay.  n microsecond delay. Not recommended unless needed.\n\
   -M <n> maximum number of parallel sockets.  Larger isn't always better.\n");
printf("   -e <devicename>. Send packets on interface <devicename> (eth0,ppp0,etc.).\n"); 
printf("   -q quash argv to something benign, currently set to \"%s\". (deprecated)\n", FAKE_ARGV);
printf("Hostnames specified as internet hostname or IP address.  Optional '/mask' \
specifies subnet. cert.org/24 or 192.88.209.5/24 or 192.88.209.0-255 or '128.88.209.*' scan CERT's Class C.\n\
SEE THE MAN PAGE FOR MORE THOROUGH EXPLANATIONS AND EXAMPLES.\n");
exit(0);
}

portlist tcp_scan(struct hoststruct *target, unsigned short *portarray, int timeout) {
int connecterror = 0; /* Have we given the "strange connect error" message yet? */
int starttime, current_out = 0, res , deadindex = 0, i=0, j=0, k=0, max=0; 
struct sockaddr_in sock, stranger, mysock;
int sockaddr_in_len = sizeof(struct sockaddr_in);
int seconds, seconds2;  /* Store time temporarily for timeout purposes */
int sockets[MAX_SOCKETS_ALLOWED];   /* All socket descriptors */
int deadstack[MAX_SOCKETS_ALLOWED]; /* Stack of dead descriptors (indexes to sockets[] */
unsigned short portno[MAX_SOCKETS_ALLOWED];  /* port numbers of sd's, parallel to sockets[] */
int times[MAX_SOCKETS_ALLOWED]; /* initial connect() times of sd's, parallel to sockets[].  For timeout information. */
int retrystack[MAX_SOCKETS_ALLOWED]; /* sd's that need to be retried */
static int retries[65535]; /* nr. or retries for this port */
int retryindex = -1;
int numretries = 2; /* How many retries before we give up on a connection */
char owner[513], buf[65536]; 
int tryident = o.identscan, current_socket /*actually it is a socket INDEX*/;
fd_set fds_read, fds_write;
struct timeval nowait = {0,0},  longwait = {7,0}; 
int timeouts=0;
 static int threshold_warning = 0; /* Have we given the threshold warning yet?*/
signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our 'write 0 bytes' test
			     doesn't crash our program!*/

owner[0] = '\0';
starttime = time(NULL);
bzero((char *)&sock,sizeof(struct sockaddr_in));
sock.sin_addr.s_addr = target->host.s_addr;
if (o.verbose || o.debugging)
  printf("Initiating TCP connect() scan against %s (%s)\n",
	 target->name,  inet_ntoa(sock.sin_addr));
sock.sin_family=AF_INET;
FD_ZERO(&fds_read);
FD_ZERO(&fds_write);

if (tryident)
  tryident = check_ident_port(target->host);

/* Initially, all of our sockets are "dead" */
for(i = 0 ; i < o.max_sockets; i++) {
  deadstack[deadindex++] = i;
  portno[i] = 0;
}

deadindex--; 
/* deadindex always points to the most recently added dead socket index */

while(portarray[j] || retryindex >= 0 || current_out != 0) {
  longwait.tv_sec = timeout;
  longwait.tv_usec = nowait.tv_sec = nowait.tv_usec = 0;
  seconds = time(NULL);
  for(i=current_out; i < o.max_sockets && (portarray[j] || retryindex >= 0); i++) {
    current_socket = deadstack[deadindex--];
    if ((sockets[current_socket] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
      {perror("Socket troubles"); exit(1);}
    if (sockets[current_socket] > max) max = sockets[current_socket]; 
    current_out++;
    unblock_socket(sockets[current_socket]);
    init_socket(sockets[current_socket]);
    if (retryindex < 0) {
      portno[current_socket] = portarray[j++];
    }
    else { /* we have retries to do ...*/
      portno[current_socket] = retrystack[retryindex--];
    }
    sock.sin_port = htons(portno[current_socket]);
    times[current_socket] = seconds;
    if ((res = connect(sockets[current_socket],(struct sockaddr *)&sock,sizeof(struct sockaddr)))!=-1) {
	/* This can happen on localhost, successful connection immediately
           in non-blocking mode */
      if (o.debugging || o.verbose) 
	printf("Adding TCP port %hi due to successful connection.\n", 
	       portno[current_socket]);
      if (tryident) {
	if (getsockname(sockets[current_socket], (SA *) &mysock,
			&sockaddr_in_len )) {
	  perror("getsockname");
	  exit(1);
	}
	if (getidentinfoz(target->host, ntohs(mysock.sin_port), portno[current_socket],
			  owner) == -1)
	  tryident = 0;
      }	    
      addport(&target->ports, portno[current_socket], IPPROTO_TCP, owner, PORT_OPEN);

      if (max == sockets[current_socket])
	max--;
      FD_CLR(sockets[current_socket], &fds_read);
      FD_CLR(sockets[current_socket], &fds_write);
      deadstack[++deadindex] = current_socket;
      current_out--;
      portno[current_socket] = 0;
      close(sockets[current_socket]);
    }
    else {  /* Connect() failed, normal case */
      switch(errno) {
      case EINPROGRESS: /* The one I always see */
      case EAGAIN:
	block_socket(sockets[current_socket]); 
	FD_SET(sockets[current_socket], &fds_write);
	FD_SET(sockets[current_socket], &fds_read);
	break;
      default:
	if (!connecterror) {	
	printf("Strange error from connect (%d):", errno);
	fflush(stdout);
	perror(""); /*falling through intentionally*/
	connecterror++;
	}
      case ECONNREFUSED:
	if (max == sockets[current_socket]) max--;
	deadstack[++deadindex] = current_socket;
	current_out--;
	portno[current_socket] = 0;
	close(sockets[current_socket]);
	timeouts = 0; /* We may not want to give up on this host */
	break;
      }
    }
  }
  /*  if (!portarray[j] && retryindex < 0) sleep(2); *//*If we are done, 
      wait a second for any last packets*/
  /*  Use nowait if we have more to send, but if we already have max_sockets
      out or if we are out of ports & retries, might as well wait awhile */
  while((res = select(max + 1, &fds_read, &fds_write, NULL, 
		      ((current_out < o.max_sockets) &&  
		       (current_out == 0 || portarray[j] || retryindex >= 0) )?
		      &nowait : &longwait)) > 0) {
    fflush(stdout);
    for(k=0; k < o.max_sockets; k++)
      if (portno[k]) {
	if (FD_ISSET(sockets[k], &fds_write)
	    && FD_ISSET(sockets[k], &fds_read)) {
	  /*printf("Socket at port %hi is selectable for r & w.", portno[k]);*/
	  res = recvfrom(sockets[k], buf, 65536, 0, (struct sockaddr *)
			 & stranger, &sockaddr_in_len);
	  if (res >= 0) {
	    if (o.debugging || o.verbose)
	      printf("Adding TCP port %hi due to successful read.\n", 
		     portno[k]);
	    if (tryident) {
	      if ( getsockname(sockets[k], (struct sockaddr *) &mysock,
			       &sockaddr_in_len ) ) {
		perror("getsockname");
		exit(1);
	      }
	      if (getidentinfoz(target->host, ntohs(mysock.sin_port),  portno[k],
				owner) == -1)
		tryident = 0;
	    }	    
	    addport(&target->ports, portno[k], IPPROTO_TCP, owner, PORT_OPEN);
	  }
	  if (max == sockets[k])
	    max--;
	  FD_CLR(sockets[k], &fds_read);
	  FD_CLR(sockets[k], &fds_write);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else if(FD_ISSET(sockets[k], &fds_write)) {
	  /*printf("Socket at port %hi is selectable for w only.VERIFYING\n",
	    portno[k]);*/
	  res = send(sockets[k], buf, 0, 0);
	  if (res < 0 ) {
	    signal(SIGPIPE, SIG_IGN);
	    if (o.debugging > 1)
	      printf("Bad port %hi caught by 0-byte write!\n", portno[k]);
	  }
	  else {
	    if (o.debugging || o.verbose)
	      printf("Adding TCP port %hi due to successful 0-byte write!\n",
		     portno[k]);
	    if (tryident) {
	      if ( getsockname(sockets[k], (struct sockaddr *) &mysock ,
			       &sockaddr_in_len ) ) {
		perror("getsockname");
		exit(1);
	      }
	      if (getidentinfoz(target->host, ntohs(mysock.sin_port),portno[k],
				owner) == -1)
		tryident = 0;
	    }	    
	    addport(&target->ports, portno[k], IPPROTO_TCP, owner, PORT_OPEN);	 
	  }
	  if (max == sockets[k]) max--;
	  FD_CLR(sockets[k], &fds_write);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else if ( FD_ISSET(sockets[k], &fds_read) ) {       
	  printf("Socket at port %hi is selectable for r only.  This is very wierd.\n", portno[k]);
	  if (max == sockets[k]) max--;
	  FD_CLR(sockets[k], &fds_read);
	  deadstack[++deadindex] = k;
	  current_out--;
	  portno[k] = 0;
	  close(sockets[k]);
	}
	else { /* neither read nor write selected */
	  if (time(NULL) - times[k] < o.ptime) {
	  /*printf("Socket at port %hi not selecting, readding.\n",portno[k]);*/
	  FD_SET(sockets[k], &fds_write);
	  FD_SET(sockets[k], &fds_read);
	  }
	  else { /* time elapsed */
	    if (retries[portno[k]] < numretries  && 
		(portarray[j] || retryindex >= 0)) {
	    /* don't readd if we are done with all other ports */ 
	      if (o.debugging) printf("Initial timeout.\n");
	      retries[portno[k]]++;
	      retrystack[++retryindex] = portno[k];
	    }
	    else {
	      if (o.verbose || o.debugging)
		printf("Port %d timed out\n", portno[k]);
	      timeouts++;	      
	      if (timeouts > MAX_TIMEOUTS && !target->ports && !o.force) {
		if (!o.verbose && !o.debugging  && !threshold_warning)
		  nmap_log("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.  This warning won't be repeated during this session\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
		else if (o.verbose || o.debugging)
		  nmap_log("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
		threshold_warning++;
		 for(k=0; k < o.max_sockets; k++) 
		   if (portno[k]) 
		     close(sockets[k]);
		 return NULL;
	      }
	    }	  	    
	    if (max == sockets[k]) max--;
	    FD_CLR(sockets[k], &fds_write);
	    FD_CLR(sockets[k], &fds_read);
	    deadstack[++deadindex] = k;
	    current_out--;
	    portno[k] = 0;
	    close(sockets[k]);
	  }
	}
      }
  longwait.tv_sec = timeout;
  longwait.tv_usec = 0;
  }
  /* If we can't send anymore packets (because full or out of ports) */
  if (current_out == o.max_sockets || (!portarray[j] && retryindex < 0)) {
    int z;
    seconds2 = time(NULL);
    for(z=0; z < o.max_sockets; z++) {
      if (portno[z] && seconds2 - times[z] >= o.ptime) { /* Timed out, dr0p it */
	if (retries[portno[z]] < numretries && 
	    (portarray[j] || retryindex >= 0)) { /* don't re-add if we
						    are done with all other
						    ports */
	  if (o.debugging) printf("Initial timeout.\n");
	  retries[portno[z]]++;
	  retrystack[++retryindex] = portno[z];
	}
	else {
	  if (o.debugging)
	    printf("Port %d timed out\n", portno[z]);
	  timeouts++;	      
	  if (timeouts > MAX_TIMEOUTS && !target->ports && !o.force) {
	    if (!o.verbose && !o.debugging  && !threshold_warning)
	      nmap_log("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.  This warning won't be repeated during this session\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
	    else if (o.verbose || o.debugging)
	      nmap_log("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
	    threshold_warning++;
	    for(k=0; k < o.max_sockets; k++) 
	      if (portno[k]) 
		close(sockets[k]);
	    return NULL;
	  }
	  if (max == sockets[z]) max--;
	  FD_CLR(sockets[z], &fds_write);
	  FD_CLR(sockets[z], &fds_read);
	  deadstack[++deadindex] = z;
	  current_out--;
	  portno[z] = 0;
	  close(sockets[z]);
	}
      }
    }
  }
}

for(k=0; k < o.max_sockets; k++) {
  if (portno[k]) {
    printf("Almost missed port %d\n", portno[k]);
    close(sockets[k]);
  }
}

if (o.debugging || o.verbose) 
  printf("Scanned %d ports in %ld seconds with %d parallel sockets.\n",
	 o.numports, (long) time(NULL) - starttime, o.max_sockets);
return target->ports;
}

char *seqreport(struct seq_info *seq) {
static char report[512];
char tmp[256];
char *p;
int i;
int len;
 sprintf(report, "Class=%s; Difficulty=%s;Index=%d  (lower=easier)", seqclass2ascii(seq->class), (seq->index < 10)? "Trivial joke" : (seq->index < 40)? "Easy" : (seq->index < 150)? "Medium" : (seq->index < 1000)? "Formidable" : (seq->index < 100000)? "Very difficult" : "Good luck!", seq->index);
 if (o.verbose) {
   tmp[0] = '\n';
   tmp[1] = '\0'; 
   p = tmp + 1;
   strcpy(p, "Sequence numbers: ");
   p += 18;
   for(i=0; i < seq->responses; i++) {
     len = sprintf(p, "%lX ", seq->seqs[i]);
     p += len;
   }
   strcat(report, tmp);
 }
return report;
}

char *seqclass2ascii(int class) {
  switch(class) {
  case SEQ_CONSTANT:
    return "constant sequence number (!)";
  case SEQ_64K:
    return "64K rule";
  case SEQ_TD:
    return "trivial time dependence";
  case SEQ_i800:
    return "increments by 800";
  case SEQ_RI:
    return "random positive increments";
  case SEQ_TR:
    return "truly random";
  case SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "Error, WTF?";
  }
}



struct port *lookupport(portlist ports, unsigned short portno, unsigned short protocol) {
  portlist result = ports;
  while(result && result->portno <= portno) {
    if(result->portno == portno && result->proto == protocol)
      return result;
    result = result->next;
  }
  return NULL;
}



/* gawd, my next project will be in c++ so I don't have to deal with
   this crap ... simple linked list implementation */
int addport(portlist *ports, unsigned short portno, unsigned short protocol,
	    char *owner, int state) {
struct port *current, *tmp;
int len;

if (*ports) {
  current = *ports;
  /* case 1: we add to the front of the list */
  if (portno <= current->portno) {
    if (current->portno == portno && current->proto == protocol) {
      if (current->state != state) {      
	current->state = state;
	return 0;
      }
      if (o.debugging || o.verbose) 
	printf("Duplicate port (%hi/%s)\n", portno , 
	       (protocol == IPPROTO_TCP)? "tcp": "udp");
      return -1;
    }  
    tmp = current;
    *ports = safe_malloc(sizeof(struct port));
    (*ports)->next = tmp;
    current = *ports;
    current->portno = portno;
    current->proto = protocol;
    current->confidence = CONF_HIGH;
    current->state = state;
    if (owner && *owner) {
      len = strlen(owner);
      current->owner = malloc(sizeof(char) * (len + 1));
      strncpy(current->owner, owner, len + 1);
    }
    else current->owner = NULL;
  }
  else { /* case 2: we add somewhere in the middle or end of the list */
    while( current->next  && current->next->portno < portno)
      current = current->next;
    if (current->next && current->next->portno == portno 
	&& current->next->proto == protocol) {
      if (current->state != state) {      
	current->state = state;
	return 0;
      }
      if (o.debugging || o.verbose) 
	printf("Duplicate port (%hi/%s)\n", portno , 
	       (protocol == IPPROTO_TCP)? "tcp": "udp");
      return -1;
    }
    tmp = current->next;
    current->next = safe_malloc(sizeof(struct port));
    current->next->next = tmp;
    tmp = current->next;
    tmp->portno = portno;
    tmp->proto = protocol;
    tmp->confidence = CONF_HIGH;
    tmp->state = state;
    if (owner && *owner) {
      len = strlen(owner);
      tmp->owner = malloc(sizeof(char) * (len + 1));
      strncpy(tmp->owner, owner, len + 1);
    }
    else tmp->owner = NULL;
  }
}

else { /* Case 3, list is null */
  *ports = safe_malloc(sizeof(struct port));
  tmp = *ports;
  tmp->portno = portno;
  tmp->proto = protocol;
  tmp->confidence = CONF_HIGH;
  tmp->state = state;
  if (owner && *owner) {
    len = strlen(owner);
    tmp->owner = safe_malloc(sizeof(char) * (len + 1));
    strncpy(tmp->owner, owner, len + 1);
  }
  else tmp->owner = NULL;
  tmp->next = NULL;
}
return 0; /*success */
}

int deleteport(portlist *ports, unsigned short portno,
	       unsigned short protocol) {
  portlist current, tmp;
  
  if (!*ports) {
    if (o.debugging > 1) error("Tried to delete from empty port list!");
    return -1;
  }
  /* Case 1, deletion from front of list*/
  if ((*ports)->portno == portno && (*ports)->proto == protocol) {
    tmp = (*ports)->next;
    if ((*ports)->owner) free((*ports)->owner);
    free(*ports);
    *ports = tmp;
  }
  else {
    current = *ports;
    for(;current->next && (current->next->portno != portno || current->next->proto != protocol); current = current->next);
    if (!current->next)
      return -1;
    tmp = current->next;
    current->next = tmp->next;
    if (tmp->owner) free(tmp->owner);
    free(tmp);
}
  return 0; /* success */
}

char *grab_next_host_spec(FILE *inputfd, int argc, char **fakeargv) {
  static char host_spec[512];
  int host_spec_index;
  int ch;
  if (!inputfd) {
    return( (optind < argc)?  fakeargv[optind++] : NULL);
  }
  host_spec_index = 0;
  while((ch = getc(inputfd)) != EOF) {
    if (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\0') {
      if (host_spec_index == 0) continue;
      host_spec[host_spec_index] = '\0';
      return host_spec;
    } else if (host_spec_index < 511) {
      host_spec[host_spec_index++] = (char) ch;
    } else fatal("One of the host_specifications from your input file is too long (> %d chars)", sizeof(host_spec));
  }
  host_spec[host_spec_index] = '\0';
  if (!*host_spec) return NULL;
  return host_spec;
}


void printandfreeports(portlist ports) {
  char protocol[4];
  struct servent *service;
  port *current = ports, *tmp;
  
  nmap_log("Port    State       Protocol  Service");
  nmap_log("%s", (o.identscan)?"         Owner\n":"\n");
  while(current != NULL) {
    strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
    service = getservbyport(htons(current->portno), protocol);
    nmap_log("%-8d%-12s%-11s%-16s%s\n", current->portno, 
	     (current->state == PORT_OPEN)? "open" :
	     (current->state == PORT_FIREWALLED)? "firewalled" :
	     "whacked", protocol,
	   (service)? service->s_name: "unknown",
	   (current->owner)? current->owner : "");
    tmp = current;
    current = current->next;
    if (tmp->owner) free(tmp->owner);
    free(tmp);
  }
  nmap_log("\n");
}

/* This is the version of udp_scan that uses raw ICMP sockets and requires 
   root priviliges.*/
portlist udp_scan(struct hoststruct *target, unsigned short *portarray) {
  int icmpsock, udpsock, tmp, done=0, retries, bytes = 0, res,  num_out = 0;
  int i=0,j=0, k=0, icmperrlimittime, max_tries = UDP_MAX_PORT_RETRIES;
  unsigned short outports[MAX_SOCKETS_ALLOWED];
  unsigned short numtries[MAX_SOCKETS_ALLOWED];
  struct sockaddr_in her;
  char senddata[] = "blah\n";
  unsigned long starttime, sleeptime;
  struct timeval shortwait = {1, 0 };
  fd_set  fds_read, fds_write;
  
  bzero( (char *) outports, o.max_sockets * sizeof(unsigned short));
  bzero( (char *) numtries, o.max_sockets * sizeof(unsigned short));
  
   /* Some systems (like linux) follow the advice of rfc1812 and limit
    * the rate at which they will respons with icmp error messages 
    * (like port unreachable).  icmperrlimittime is to compensate for that.
    */
  icmperrlimittime = 60000;

  sleeptime = (target->rtt)? ( target->rtt) + 30000 : 1e5;
if (o.wait) icmperrlimittime = o.wait;

starttime = time(NULL);

FD_ZERO(&fds_read);
FD_ZERO(&fds_write);

if (o.verbose || o.debugging) 
 printf("Initiating UDP (raw ICMP version) scan against %s (%s) using wait delay of %li usecs.\n", target->name,  inet_ntoa(target->host), sleeptime);

if ((icmpsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
  perror("Opening ICMP RAW socket");
if ((udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
  perror("Opening datagram socket");

unblock_socket(icmpsock);
her.sin_addr = target->host;
her.sin_family = AF_INET;

while(!done) {
  tmp = num_out;
  for(i=0; (i < o.max_sockets && portarray[j]) || i < tmp; i++) {
    close(udpsock);
    if ((udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      perror("Opening datagram socket");
    if ((i > tmp && portarray[j]) || numtries[i] > 1) {
      if (i > tmp) her.sin_port = htons(portarray[j++]);
      else her.sin_port = htons(outports[i]);
      FD_SET(udpsock, &fds_write);
      FD_SET(icmpsock, &fds_read);
      shortwait.tv_sec = 1; shortwait.tv_usec = 0;
      usleep(icmperrlimittime);
      res = select(udpsock + 1, NULL, &fds_write, NULL, &shortwait);
       if (FD_ISSET(udpsock, &fds_write))
	  bytes = sendto(udpsock, senddata, sizeof(senddata), 0,
			 (struct sockaddr *) &her, sizeof(struct sockaddr_in));
      else {
	printf("udpsock not set for writing port %d!",  ntohs(her.sin_port));
	return target->ports;
      }
      if (bytes <= 0) {
	if (errno == ECONNREFUSED) {
	  retries = 10;
	  do {	  
	    /* This is from when I was using the same socket and would 
	     * (rather often) get strange connection refused errors, it
	     * shouldn't happen now that I create a new udp socket for each
	     * port.  At some point I will probably go back to 1 socket again.
	     */
	    printf("sendto said connection refused on port %d but trying again anyway.\n", ntohs(her.sin_port));
	    usleep(icmperrlimittime);
	    bytes = sendto(udpsock, senddata, sizeof(senddata), 0,
			  (struct sockaddr *) &her, sizeof(struct sockaddr_in));
	    printf("This time it returned %d\n", bytes);
	  } while(bytes <= 0 && retries-- > 0);
	}
	if (bytes <= 0) {
	  printf("sendto returned %d.", bytes);
	  fflush(stdout);
	  perror("sendto");
	}
      }
      if (bytes > 0 && i > tmp) {
	num_out++;
	outports[i] = portarray[j-1];
      }
    }
  }
  usleep(sleeptime);
  tmp = listen_icmp(icmpsock, outports, numtries, &num_out, target->host, &target->ports);
  if (o.debugging) printf("listen_icmp caught %d bad ports.\n", tmp);
  done = !portarray[j];
  for (i=0,k=0; i < o.max_sockets; i++) 
    if (outports[i]) {
      if (++numtries[i] > max_tries - 1) {
	if (o.debugging || o.verbose)
	  printf("Adding port %d for 0 unreachable port generations\n",
		 outports[i]);
	addport(&target->ports, outports[i], IPPROTO_UDP, NULL, PORT_OPEN);
	num_out--;
	outports[i] = numtries[i] = 0;      
      }
      else {
	done = 0;
	outports[k] = outports[i];
	numtries[k] = numtries[i];
	if (k != i)
	  outports[i] = numtries[i] = 0;
	k++;
      }
    }
  if (num_out == o.max_sockets) {
  printf("Numout is max sockets, that is a problem!\n");
  sleep(1); /* Give some time for responses to trickle back, 
	       and possibly to reset the hosts ICMP error limit */
  }
}


if (o.debugging || o.verbose) 
  printf("The UDP raw ICMP scanned %d ports in  %ld seconds with %d parallel sockets.\n", o.numports, time(NULL) - starttime, o.max_sockets);
close(icmpsock);
close(udpsock);
return target->ports;
}

int listen_icmp(int icmpsock,  unsigned short outports[], 
		unsigned short numtries[], int *num_out, struct in_addr target,
		portlist *ports) {
  char response[1024];
  struct sockaddr_in stranger;
  int sockaddr_in_size = sizeof(struct sockaddr_in);
  struct in_addr bs;
  struct ip *ip = (struct ip *)response;
  struct ip *ip2;
  struct icmp *icmp = (struct icmp *) (response + sizeof(struct ip));
  unsigned short *data;
  int badport, numcaught=0, bytes, i, tmptry=0, found=0;
  
  while  ((bytes = recvfrom(icmpsock, response, 1024, 0,
			    (struct sockaddr *) &stranger,
			    &sockaddr_in_size)) > 0) {
    numcaught++;
    
    bs.s_addr = ip->ip_src.s_addr;
    if (ip->ip_src.s_addr == target.s_addr && ip->ip_p == IPPROTO_ICMP 
	&& icmp->icmp_type == 3 && icmp->icmp_code == 3) {    
      ip2 = (struct ip *) (response + 4 * ip->ip_hl + sizeof(struct icmp));
      data = (unsigned short *) ((char *)ip2 + 4 * ip2->ip_hl);
      
      badport = ntohs(data[1]);
      /*delete it from our outports array */
      found = 0;
      for(i=0; i < o.max_sockets; i++) 
	if (outports[i] == badport) {
	  found = 1;
	  tmptry = numtries[i];
	  outports[i] = numtries[i] = 0;
	  (*num_out)--;
	  break;
	}
      if (o.debugging && found && tmptry > 0) 
	printf("Badport: %d on try number %d\n", badport, tmptry);
      if (!found) {
	if (o.debugging) 
	  printf("Badport %d came in late, deleting from portlist.\n", badport);
	if (deleteport(ports, badport, IPPROTO_UDP) < 0)
	  if (o.debugging) printf("Port deletion failed.\n");
      }
    }
    else {
      
      if (o.debugging) printf("Caught icmp type %d code %d\n", icmp->icmp_type, icmp->icmp_code);
      
    }
  }
  return numcaught;
}

/* This fucntion is nonsense.  I wrote it all, really optimized etc.  Then
   found out that many hosts limit the rate at which they send icmp errors :(
   I will probably totally rewrite it to be much simpler at some point.  For
   now I won't worry about it since it isn't a very important functions (UDP
   is lame, plus there is already a much better function for people who 
   are r00t */
portlist lamer_udp_scan(struct hoststruct *target, unsigned short *portarray) {
int sockaddr_in_size = sizeof(struct sockaddr_in),i=0,j=0,k=0, bytes;
int sockets[MAX_SOCKETS_ALLOWED];
int trynum[MAX_SOCKETS_ALLOWED];
unsigned short portno[MAX_SOCKETS_ALLOWED];
int last_open = 0;
char response[1024];
struct sockaddr_in her, stranger;
char data[] = "\nhelp\nquit\n";
unsigned long sleeptime;
unsigned int starttime;

/* Initialize our target sockaddr_in */
bzero((char *) &her, sizeof(struct sockaddr_in));
her.sin_family = AF_INET;
her.sin_addr = target->host;

if (o.wait) sleeptime = o.wait;
else sleeptime =  calculate_sleep(target->host) + 60000; /*large to be on the 
						    safe side */

if (o.verbose || o.debugging)
  printf("Initiating UDP scan against %s (%s), sleeptime: %li\n", target->name,
	 inet_ntoa(target->host), sleeptime);

starttime = time(NULL);

for(i = 0 ; i < o.max_sockets; i++)
  trynum[i] =  portno[i] = 0;

while(portarray[j]) {
  for(i=0; i < o.max_sockets && portarray[j]; i++, j++) {
    if (i >= last_open) {
      if ((sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {perror("datagram socket troubles"); exit(1);}
      block_socket(sockets[i]);
      portno[i] = portarray[j];
    }
    her.sin_port = htons(portarray[j]);
    bytes = sendto(sockets[i], data, sizeof(data), 0, (struct sockaddr *) &her,
		   sizeof(struct sockaddr_in));
    usleep(5000);
    if (o.debugging > 1) 
      printf("Sent %d bytes on socket %d to port %hi, try number %d.\n",
	     bytes, sockets[i], portno[i], trynum[i]);
    if (bytes < 0 ) {
      printf("Sendto returned %d the FIRST TIME!@#$!, errno %d\n", bytes,
	     errno);
      perror("");
      trynum[i] = portno[i] = 0;
      close(sockets[i]);
    }
  }
  last_open = i;
  /* Might need to change this to 1e6 if you are having problems*/
  usleep(sleeptime + 5e5);
  for(i=0; i < last_open ; i++) {
    if (portno[i]) {
      unblock_socket(sockets[i]);
      if ((bytes = recvfrom(sockets[i], response, 1024, 0, 
			    (struct sockaddr *) &stranger,
			    &sockaddr_in_size)) == -1)
        {
          if (o.debugging > 1) 
	    printf("2nd recvfrom on port %d returned %d with errno %d.\n",
		   portno[i], bytes, errno);
          if (errno == EAGAIN /*11*/)
            {
              if (trynum[i] < 2) trynum[i]++;
              else { 
		if (RISKY_UDP_SCAN) {	       
		  printf("Adding port %d after 3 EAGAIN errors.\n", portno[i]);
		  addport(&target->ports, portno[i], IPPROTO_UDP, NULL, PORT_OPEN); 
		}
		else if (o.debugging)
		  printf("Skipping possible false positive, port %d\n",
			 portno[i]);
                trynum[i] = portno[i] = 0;
                close(sockets[i]);
              }
            }
          else if (errno == ECONNREFUSED /*111*/) {
            if (o.debugging > 1) 
	      printf("Closing socket for port %d, ECONNREFUSED received.\n",
		     portno[i]);
            trynum[i] = portno[i] = 0;
            close(sockets[i]);
          }
          else {
            printf("Curious recvfrom error (%d) on port %hi: ", 
		   errno, portno[i]);
            perror("");
            trynum[i] = portno[i] = 0;
            close(sockets[i]);
          }
        }
      else /*bytes is positive*/ {
        if (o.debugging || o.verbose)
	  printf("Adding UDP port %d due to positive read!\n", portno[i]);
        addport(&target->ports,portno[i], IPPROTO_UDP, NULL, PORT_OPEN);
        trynum[i] = portno[i] = 0;
        close(sockets[i]);
      }
    }
  }
  /* Update last_open, we need to create new sockets.*/
  for(i=0, k=0; i < last_open; i++)
    if (portno[i]) {
      close(sockets[i]);
      sockets[k] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      /*      unblock_socket(sockets[k]);*/
      portno[k] = portno[i];
      trynum[k] = trynum[i];
      k++;
    }
 last_open = k;
  for(i=k; i < o.max_sockets; i++)
    trynum[i] = sockets[i] = portno[i] = 0;
}
if (o.debugging)
  printf("UDP scanned %d ports in %ld seconds with %d parallel sockets\n",
	 o.numports, (long) time(NULL) - starttime, o.max_sockets);
return target->ports;
}


/* This attempts to calculate the round trip time (rtt) to a host by timing a
   connect() to a port which isn't listening.  A better approach is to time a
   ping (since it is more likely to get through firewalls.  This is now 
   implemented in isup() for users who are root.  */
unsigned long calculate_sleep(struct in_addr target) {
struct timeval begin, end;
int sd;
struct sockaddr_in sock;
int res;

if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
  {perror("Socket troubles"); exit(1);}

sock.sin_family = AF_INET;
sock.sin_addr.s_addr = target.s_addr;
sock.sin_port = htons(o.magic_port);

gettimeofday(&begin, NULL);
if ((res = connect(sd, (struct sockaddr *) &sock, 
		   sizeof(struct sockaddr_in))) != -1)
  printf("You might want to use a different value of -g (or change o.magic_port in the include file), as it seems to be listening on the target host!\n");
close(sd);
gettimeofday(&end, NULL);
if (end.tv_sec - begin.tv_sec > 5 ) /*uh-oh!*/
  return 0;
return (end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec);
}

/* Checks whether the identd port (113) is open on the target machine.  No
   sense wasting time trying it for each good port if it is down! */

int check_ident_port(struct in_addr target) {
int sd;
char buf[4096];
struct sockaddr_in sock;
int res;
struct sockaddr_in stranger;
int sockaddr_in_len = sizeof(struct sockaddr_in);
fd_set fds_read, fds_write;
struct timeval tv;
tv.tv_sec = o.ptime;
tv.tv_usec = 0;
if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
  {perror("Socket troubles"); exit(1);}
unblock_socket(sd);
sock.sin_family = AF_INET;
sock.sin_addr.s_addr = target.s_addr;
sock.sin_port = htons(113); /*should use getservbyname(3), yeah, yeah */
FD_SET(sd, &fds_read);
FD_SET(sd, &fds_write);
res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
if (res != -1) /* must be scanning localhost, this socket is non-blocking */ 
  goto success;
if (errno == ECONNREFUSED) /* Unlikely in non-blocking, but could happen  */ 
  goto failure;
if ((res = select(sd+1, &fds_read, &fds_write, NULL, &tv)) > 0) {
  /* Yay, it may be up ... */
  if (FD_ISSET(sd, &fds_read) && FD_ISSET(sd, &fds_write)) {
    res = recvfrom(sd, buf,4096, 0, (struct sockaddr *) & stranger, &sockaddr_in_len);
    if (res >= 0) goto success;
    goto failure;
  }
  else if (FD_ISSET(sd, &fds_write)) {
    res = send(sd, buf, 0, 0);
    if (res < 0) goto failure;
    goto success;
  } else if (FD_ISSET(sd, &fds_read)) {
    printf("I have never seen this type of socket selectable for read only.  Please let me know how you did it and what OS you are running (fyodor@dhp.com).\n");
    goto success;
  }
  else {
    printf("Wow, select blatantly lied to us!  Please let fyodor know what OS you are running (fyodor@dhp.com).\n");
    goto failure;
  } 
}

failure:
close(sd);
if (o.debugging || o.verbose) printf("identd port not active\n");
return 0;

success:
close(sd);
if (o.debugging || o.verbose) printf("identd port is active\n");
return 1;
}

/* returns 0 for possibly temporary error, -1 means we shouldn't attempt
   inetd again on this host */
int getidentinfoz(struct in_addr target, int localport, int remoteport,
		  char *owner) {
int sd;
struct sockaddr_in sock;
int res;
char request[15];
char response[1024];
char *p,*q;
char  *os;

owner[0] = '\0';
if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
  {perror("Socket troubles"); exit(1);}

sock.sin_family = AF_INET;
sock.sin_addr.s_addr = target.s_addr;
sock.sin_port = htons(113);
usleep(50000);   /* If we aren't careful, we really MIGHT take out inetd, 
		    some are very fragile */
res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));

if (res < 0 ) {
  if (o.debugging || o.verbose)
    printf("identd port not active now for some reason ... hope we didn't break it!\n");
  close(sd);
  return 0;
}
sprintf(request,"%hi,%hi\r\n", remoteport, localport);
if (o.debugging > 1) printf("Connected to identd, sending request: %s", request);
if (write(sd, request, strlen(request) + 1) == -1) {
  perror("identd write");
  close(sd);
  return 0;
}
else if ((res = read(sd, response, 1024)) == -1) {
  perror("reading from identd");
  close(sd);
  return 0;
}
else {
  close(sd);
  if (o.debugging > 1) printf("Read %d bytes from identd: %s\n", res, response);
  if ((p = strchr(response, ':'))) {
    p++;
    if ((q = strtok(p, " :"))) {
      if (!strcasecmp( q, "error")) {
	if (strstr(response, "HIDDEN-USER") || strstr(response, "hidden-user")) {
	  printf("identd returning HIDDEN-USER, giving up on it\n");
	  return -1;
	}
	if (o.debugging) printf("ERROR returned from identd for port %d\n", remoteport);
	return 0;
      }
      if ((os = strtok(NULL, " :"))) {
	if ((p = strtok(NULL, " :"))) {
	  if ((q = strchr(p, '\r'))) *q = '\0';
	  if ((q = strchr(p, '\n'))) *q = '\0';
	  strncpy(owner, p, 512);
	  owner[512] = '\0';
	}
      }
    } 
  }  
}
return 1;
}

/* SYN scan, we now use libpcap instead of the non-portable Linux technique
   of using recvfrom() to read TCP packets from a RAW socket */
portlist syn_scan(struct hoststruct *target, unsigned short *portarray) {
int i=0, j=0, starttime;
int decoy;
unsigned int bytes;
int sockets[MAX_SOCKETS_ALLOWED];
struct timeval tv,start,end;
unsigned int elapsed_time;
/*char packet[65535];*/
struct ip *ip = NULL; /* = (struct ip *) packet;*/
struct tcphdr *tcp = NULL; /*(struct tcphdr *) (packet + sizeof(struct ip));*/
fd_set fd_read, fd_write;
struct hostent *myhostent = NULL;
char myname[MAXHOSTNAMELEN + 1];
unsigned short magic_port_NBO;
int packets_out;
pcap_t *pd;
struct bpf_program fcode;
char filter[512];
int tmpsocket;
unsigned int localnet, netmask;
char *p = NULL;
char err0r[PCAP_ERRBUF_SIZE];
magic_port_NBO = htons(o.magic_port);

FD_ZERO(&fd_read);
FD_ZERO(&fd_write);

/*if ((received = socket(AF_INET, SOCK_RAW,  IPPROTO_TCP)) < 0 )
  perror("socket troubles in syn_scan");*/
/*if ((received = socket(AF_INET, SOCK_PACKET,  htons(ETH_P_IP))) < 0 )
  perror("socket troubles in syn_scan");*/
/*unblock_socket(received);*/
/*(max_rcvbuf(received);*/ /* does nothing for linux */
/*FD_SET(received, &fd_read);*/

if (!target->source_ip.s_addr) {
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is fucked up.\n"); 
  memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
  if (o.debugging || o.verbose)
    printf("We skillfully deduced that your address is %s\n", 
	   inet_ntoa(target->source_ip));
}

/* Now for the pcap opening nonsense ... */
/* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
 * header + 4 bytes of TCP port info.
 * Also note that we are going into promiscuous mode because Solaris
 * apparently requires that for some unknown reason(!).  I'd like to
 * get out of promisc. if we can figure out the problem.
 */
if (!(pd = pcap_open_live(target->device, 92, (o.spoofsource)? 1 : 0, 1000, err0r)))
  fatal("pcap_open_live in syn_scan: %s", err0r);
if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
  fatal("Failed to lookup device subnet/netmask: %s", err0r);
p = strdup(inet_ntoa(target->host));
#ifdef HAVE_SNPRINTF
snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s and dst port %d", p, inet_ntoa(target->source_ip), o.magic_port );
#else
sprintf(filter, "tcp and src host %s and dst host %s and dst port %d", p, inet_ntoa(target->source_ip), o.magic_port );
#endif
free(p);
if (o.debugging)
  printf("Packet capture filter: %s\n", filter);
if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
  fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
if (pcap_setfilter(pd, &fcode) < 0 )
  fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));

starttime = time(NULL);

do {
  for(i=0; i < o.max_sockets && portarray[j]; i++) {
    if ((sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      perror("socket trobles in syn_scan");
    else {
      for(decoy=0; decoy < o.numdecoys; decoy++) {
	if (decoy != o.decoyturn) {
	  if ((tmpsocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 ) /* It is lame that we have to do this */
	    perror("decoy socket trobles in syn_scan");
	} else tmpsocket = sockets[i];
	if (o.fragscan)
	  send_small_fragz(tmpsocket, &o.decoys[decoy], &target->host, 0, o.magic_port,
			   portarray[j], TH_SYN);
	else send_tcp_raw(tmpsocket, &o.decoys[decoy] , &target->host, o.magic_port, 
			  portarray[j],0,0,TH_SYN, 0,NULL, 0, 0,0);
	if (decoy != o.decoyturn) close(tmpsocket);
	usleep(10000);
      }
      j++;
    }
  }
  gettimeofday(&start, NULL);
  packets_out = i;
  do {
    tv.tv_sec = o.ptime;
    tv.tv_usec = 0;
    /*    FD_SET(received, &fd_read);*/
    /*    if ((res = select(received + 1, &fd_read, NULL, NULL, &tv)) < 0)
      perror("select problems in syn_scan");
      else*/ /*if (res > 0)*//* {*/
      /* Linux-Specific ... LAME
            while  ((bytes = recvfrom(received, packet, 65535, 0, 
				(struct sockaddr *)&from, &fromsize)) > 0 ) {
      */
      while (( ip = (struct ip*) readip_pcap(pd, &bytes))) 

	{
	  if (bytes < (4 * ip->ip_hl) + 4)
	    continue;
	  tcp = (struct tcphdr *) (((char *)ip) + (4 * ip->ip_hl));
	  if (ip->ip_src.s_addr == target->host.s_addr && (o.magic_port < 1024 || tcp->th_sport != magic_port_NBO ) && tcp->th_dport == magic_port_NBO) {
	    
	    packets_out--;
	    if (tcp->th_flags & TH_RST) {
	      if (o.debugging > 1) printf("Nothing open on port %d\n",
					  ntohs(tcp->th_sport));
	    }
	    else /*if (tcp->th_flags & TH_SYN && tcp->th_flags & TH_ACK)*/ {
	      if (o.debugging || o.verbose) {	  
		printf("Possible catch on port %d!  Here it is:\n", 
		       ntohs(tcp->th_sport));
		readtcppacket((char *)ip,1);
	      }
	      addport(&target->ports, ntohs(tcp->th_sport), IPPROTO_TCP, NULL, PORT_OPEN);
	    }
	  }
	}
      gettimeofday(&end, NULL);
      elapsed_time = (end.tv_sec - start.tv_sec) * 1e6 + end.tv_usec - start.tv_usec;
  } while ( packets_out && elapsed_time < 1e6 * (double) o.ptime / 3 );
  /*for(i=0; i < o.max_sockets && portarray[j]; i++) close(sockets[i]);*/
  for(; i >= 0; i--) close(sockets[i]);
  
} while (portarray[j]);
 if (o.debugging || o.verbose)
   printf("The TCP SYN scan took %ld seconds to scan %d ports.\n",
	  (long) time(NULL) - starttime, o.numports);
 /*close(received);*/
 pcap_close(pd);
 return target->ports;
}

/* We don't exactly need real crypto here (thank god!)\n"*/
int shortfry(unsigned short *ports) {
int num;
unsigned short tmp;
int i;

for(i=0; i < o.numports; i++) {
  num = rand() % (o.numports);
  tmp = ports[i];
  ports[i] = ports[num];
  ports[num] = tmp;
}
return 1;
}


/* Much of this is swiped from my send_tcp_raw function above, which 
   doesn't support fragmentation */
int send_small_fragz(int sd, struct in_addr *source, struct in_addr *victim,
		     unsigned long seq, int sport, int dport, int flags) {

struct pseudo_header { 
/*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
  unsigned long s_addy;
  unsigned long d_addr;
  char zer0;
  unsigned char protocol;
  unsigned short length;
};
/*In this placement we get data and some field alignment so we aren't wasting
  too much to compute the TCP checksum.*/

char packet[sizeof(struct ip) + sizeof(struct tcphdr) + 100];
struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
struct pseudo_header *pseudo = (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header)); 
char *frag2 = packet + sizeof(struct ip) + 16;
struct ip *ip2 = (struct ip *) (frag2 - sizeof(struct ip));
int res;
struct sockaddr_in sock;
int id;

/* It was a tough decision whether to do this here for every packet
   or let the calling function deal with it.  In the end I grudgingly decided
   to do it here and potentially waste a couple microseconds... */
sethdrinclude(sd);

/*Why do we have to fill out this damn thing? This is a raw packet, after all */
sock.sin_family = AF_INET;
sock.sin_port = htons(dport);

sock.sin_addr.s_addr = victim->s_addr;

bzero((char *)packet, sizeof(struct ip) + sizeof(struct tcphdr));

pseudo->s_addy = source->s_addr;
pseudo->d_addr = victim->s_addr;
pseudo->protocol = IPPROTO_TCP;
pseudo->length = htons(sizeof(struct tcphdr));

tcp->th_sport = htons(sport);
tcp->th_dport = htons(dport);
tcp->th_seq = (seq)? htonl(seq) : rand() + rand();

tcp->th_off = 5 /*words*/;
tcp->th_flags = flags;

tcp->th_win = htons(2048); /* Who cares */

tcp->th_sum = in_cksum((unsigned short *)pseudo, 
		       sizeof(struct tcphdr) + sizeof(struct pseudo_header));

/* Now for the ip header of frag1 */

bzero((char *) packet, sizeof(struct ip)); 
ip->ip_v = 4;
ip->ip_hl = 5;
/*RFC 791 allows 8 octet frags, but I get "operation not permitted" (EPERM)
  when I try that.  */
ip->ip_len = BSDFIX(sizeof(struct ip) + 16);
id = ip->ip_id = rand();
ip->ip_off = BSDFIX(MORE_FRAGMENTS);
ip->ip_ttl = 255;
ip->ip_p = IPPROTO_TCP;
ip->ip_src.s_addr = source->s_addr;
ip->ip_dst.s_addr = victim->s_addr;
#if HAVE_IP_IP_SUM
ip->ip_sum= in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif
if (o.debugging > 1) {
  printf("Raw TCP packet fragment #1 creation completed!  Here it is:\n");
  hdump(packet,20);
}
if (o.debugging > 1) 
  printf("\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n",
	 sd, ntohs(ip->ip_len), inet_ntoa(*victim),
	 (int) sizeof(struct sockaddr_in));
/* Lets save this and send it AFTER we send the second one, just to be
   cute ;) */

if ((res = sendto(sd, packet,sizeof(struct ip) + 16 , 0, 
		  (struct sockaddr *)&sock, sizeof(struct sockaddr_in))) == -1)
  {
    perror("sendto in send_syn_fragz");
    return -1;
  }
if (o.debugging > 1) printf("successfully sent %d bytes of raw_tcp!\n", res);

/* Create the second fragment */

bzero((char *) ip2, sizeof(struct ip));
ip2->ip_v= 4;
ip2->ip_hl = 5;
ip2->ip_len = BSDFIX(sizeof(struct ip) + 4); /* the rest of our TCP packet */
ip2->ip_id = id;
ip2->ip_off = BSDFIX(2);
ip2->ip_ttl = 255;
ip2->ip_p = IPPROTO_TCP;
ip2->ip_src.s_addr = source->s_addr;
ip2->ip_dst.s_addr= victim->s_addr;
#if HAVE_IP_IP_SUM
ip2->ip_sum = in_cksum((unsigned short *)ip2, sizeof(struct ip));
#endif
if (o.debugging > 1) {
  printf("Raw TCP packet fragment creation completed!  Here it is:\n");
  hdump(packet,20);
}
if (o.debugging > 1) 

  printf("\nTrying sendto(%d , ip2, %d, 0 , %s , %d)\n", sd, 
	 ntohs(ip2->ip_len), inet_ntoa(*victim), (int) sizeof(struct sockaddr_in));
if ((res = sendto(sd, (void *)ip2,sizeof(struct ip) + 4 , 0, 
		  (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)
  {
    perror("sendto in send_tcp_raw frag #2");
    return -1;
  }

return 1;
}


portlist super_scan(struct hoststruct *target, unsigned short *portarray, stype scantype) {
  int initial_packet_width = 10;  /* How many scan packets in parallel (to start with) */
  int packet_incr = 4; /* How much we increase the parallel packets by each round */
  double fallback_percent = 0.7;
  int rawsd;
  char myname[513];
  int scanflags = 0;

  int dropped = 0;  /* These three are for UDP squelching */
  int freshportstried = 0;
  int senddelay = 0;
  pcap_t *pd;
  int bytes;
  struct ip *ip, *ip2;
  struct tcphdr *tcp;
  struct bpf_program fcode;
  char err0r[PCAP_ERRBUF_SIZE];
  char filter[512];
  char *p;
  int changed = 0;  /* Have we found new ports (or rejected earlier "found" ones) this round? */
  int numqueries_outstanding = 0; /* How many unexpired queries are on the 'net right now? */
  double numqueries_ideal = initial_packet_width; /* How many do we WANT to be on the 'net right now? */
  int max_width = 150; /* No more packets than this at once, pleeze */
  int tries = 0;
  int tmp = 0;
  unsigned int localnet, netmask;
  int starttime, delta;
  unsigned short newport;
  struct hostent *myhostent = NULL;
  struct portinfo *scan, *openlist, *current, *fresh, *testinglist, *next;
  int portlookup[65536]; /* Indexes port number -> scan[] index */
  int decoy;
  struct timeval now;
  int i;
  unsigned short *data;
  int packet_trynum =0;
  int windowdecrease = 0; /* Has the window been decreased this round yet? */
  struct icmp *icmp;

  memset(portlookup, 255, 65536 * sizeof(int)); /* 0xffffffff better always be (int) -1 */
  scan = safe_malloc(o.numports * sizeof(struct portinfo));

  /* Initialize timeout info */
  /*
  target->to.srtt = (target->rtt > 0)? 4 * target->rtt : 1000000;
  target->to.rttvar = (target->rtt > 0)? target->rtt / 2 : 1000000;
  target->to.timeout = target->to.srtt + 4 * target->to.rttvar;
  */

  /* Initialize our portlist (scan) */
  for(i = 0; i < o.numports; i++) {
    scan[i].state = PORT_FRESH;
    scan[i].portno = portarray[i];
    scan[i].trynum = 0;
    scan[i].prev = i-1;
    if (i < o.numports -1 ) scan[i].next = i+1;
    else scan[i].next = -1;
    portlookup[portarray[i]] = i;
  }

  current = fresh = testinglist = &scan[0]; /* fresh == unscanned ports, testinglist is a list of all ports that haven't been determined to be closed yet */
  openlist = NULL; /* we haven't shown any ports to be open yet... */


    
  /* Init our raw socket */
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in super_scan");
  unblock_socket(rawsd);

  /* Do we have a correct source address? */
  if (!target->source_ip.s_addr) {
    if (gethostname(myname, MAXHOSTNAMELEN) != 0 && 
	!((myhostent = gethostbyname(myname))))
      fatal("Your system is messed up.\n"); 
    memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
    if (o.debugging || o.verbose) 
      printf("We skillfully deduced that your address is %s\n",
	     inet_ntoa(target->source_ip));
  }

/* Now for the pcap opening nonsense ... */
/* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
 * header + 4 bytes of TCP port info.
 */

if (!(pd = pcap_open_live(target->device, 92,  (o.spoofsource)? 1 : 0, 20, err0r)))
  fatal("pcap_open_live: %s", err0r);

if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
  fatal("Failed to lookup device subnet/netmask: %s", err0r);
p = strdup(inet_ntoa(target->host));
sprintf(filter, "(icmp and dst host %s) or (tcp and src host %s and dst host %s and ( dst port %d or dst port %d))", inet_ntoa(target->source_ip), p, inet_ntoa(target->source_ip), o.magic_port , o.magic_port + 1);
 free(p);
 if (o.debugging)
   printf("Packet capture filter: %s\n", filter);
 if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
   fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
 if (pcap_setfilter(pd, &fcode) < 0 )
   fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
 
if (scantype == XMAS_SCAN) scanflags = TH_FIN|TH_URG|TH_PUSH;
else if (scantype == NULL_SCAN) scanflags = 0;
else if (scantype == FIN_SCAN) scanflags = TH_FIN;
else if (scantype == MAIMON_SCAN) scanflags = TH_FIN|TH_ACK;
else if (scantype != UDP_SCAN) { fatal("Unknown scna type for super_scan"); }

starttime = time(NULL);

if (o.debugging || o.verbose)
  printf("Initiating FIN,NULL, UDP, or Xmas stealth scan against %s (%s)\n", target->name, inet_ntoa(target->host));
  

  do {
    changed = 0;
    if (tries > 3 && senddelay == 0) senddelay = 10000; /* Currently only 
							   affects UDP */
    while(testinglist != NULL)  /* While we have live queries or more ports to scan */
    {
      /* Check the possible retransmissions first */
      gettimeofday(&now, NULL);
      for( current = testinglist; current ; current = next) {
	next = (current->next > -1)? &scan[current->next] : NULL;
	if (current->state == PORT_TESTING) {
	  if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	    if (current->trynum > 0) {
	      /* We consider this port valid, move it to open list */
	      if (o.debugging > 1) { printf("Moving port %hi to the open list\n", current->portno); }
	      freshportstried--;
	      current->state = PORT_OPEN;
	      /* First delete from old list */
	      if (current->next > -1) scan[current->next].prev = current->prev;
	      if (current->prev > -1) scan[current->prev].next = current->next;
	      if (current == testinglist)
		testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
	      current->next = -1;
	      current->prev = -1;
	      /* Now move into new list */
	      if (!openlist) openlist = current;
	      else {
		current->next = openlist - scan;
		openlist = current;
		scan[current->next].prev = current - scan;	      
	      }
	      numqueries_outstanding--;
	    } else {
	      /* Initial timeout ... we've got to resend */
	      if (o.debugging > 1) { printf("Initial timeout, resending to portno %hi\n", current->portno); }
	      current->trynum++;
	      /* If they didn't specify the magic port, we use magic_port +1
		 so we can tell that it was a retransmit later */
	      i = (o.magic_port_set)? o.magic_port : o.magic_port + 1;
	      gettimeofday(&current->sent[1], NULL);
	      now = current->sent[1];
	      for(decoy=0; decoy < o.numdecoys; decoy++) {
		if (o.fragscan)
		  send_small_fragz(rawsd, &o.decoys[decoy], &target->host, 0,i, current->portno, scanflags);
		else if (scantype != UDP_SCAN) 
		  send_tcp_raw(rawsd, &o.decoys[decoy], &target->host, i, 
			       current->portno, 0, 0, scanflags, 0, NULL, 0,
			       0, 0);
		else send_udp_raw(rawsd, &o.decoys[decoy], &target->host, i,
				  current->portno, NULL ,0);	      
		if (scantype == UDP_SCAN && senddelay) usleep(senddelay);
		/*usleep(10000);*/ /* *WE* normally do not need this, but the target 
		  lamer often does */
	      }
	    }
	  }
	} else { 
	  /* current->state == PORT_FRESH */
	  /* OK, now we have gone through our list of in-transit queries, so now
	     we try to send off new queries if we can ... */
	  if (numqueries_outstanding > (int) numqueries_ideal) break;
	  if (o.debugging > 1) printf("Sending initial query to port %hu\n", current->portno);
	  freshportstried++;
	  /* Otherwise lets send a packet! */
	  current->state = PORT_TESTING;
	  /*	if (!testinglist) testinglist = current; */
	  numqueries_outstanding++;
	  gettimeofday(&current->sent[0], NULL);
	  for(decoy=0; decoy < o.numdecoys; decoy++) {
	    if (o.fragscan)
	      send_small_fragz(rawsd, &o.decoys[decoy], &target->host, 0, o.magic_port, current->portno, scanflags);
	    else if (scantype != UDP_SCAN) 
	      send_tcp_raw(rawsd, &o.decoys[decoy], &target->host, o.magic_port, 
			   current->portno, 0, 0, scanflags, 0, NULL, 0, 0, 0);
	    else send_udp_raw(rawsd, &o.decoys[decoy], &target->host, o.magic_port,
			      current->portno, NULL, 0);
	    	    if (scantype == UDP_SCAN && senddelay) usleep(senddelay);
	    /*usleep(10000);*/ /* *WE* normally do not need this, but the target 
	      lamer often does */
	  }
	}
      }

      if (o.debugging > 1) printf("Ideal number of queries: %d\n", (int) numqueries_ideal);
      tmp++;
      /* Now that we have sent the packets we wait for responses */
      windowdecrease = 0;
      while (( ip = (struct ip*) readip_pcap(pd, &bytes))) {
	if (bytes < (4 * ip->ip_hl) + 4)
	  continue;
	if (ip->ip_src.s_addr == target->host.s_addr) {
	  if (ip->ip_p == IPPROTO_TCP) {
	    tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
	    if (tcp->th_flags & TH_RST) {	    
	      newport = ntohs(tcp->th_sport);
	      if (portlookup[newport] < 0) {
		if (o.debugging) {
		  printf("Strange packet from port %d:\n", ntohs(tcp->th_sport));
		  readtcppacket((char *)ip, bytes);
		}
		current = NULL;
		continue;
	      }	      
	      /* We figure out the scan number (and put it in i) */
	      current = &scan[portlookup[newport]];

	      if (!o.magic_port_set) {
		packet_trynum = ntohs(tcp->th_dport) - o.magic_port;
		if ((packet_trynum|1) != 1) packet_trynum = -1;
	      } else if (current->trynum == 0) packet_trynum = 0;
	      else packet_trynum = -1;
	    } else { continue; }
	  } else if (ip->ip_p == IPPROTO_ICMP) {
	    icmp = (struct icmp *) ((char *)ip + sizeof(struct ip));
	    ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
	    data = (unsigned short *) ((char *)ip2+ 4 * ip2->ip_hl);
	    /*	    printf("Caught ICMP packet:\n");
		    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */
	    if (icmp->icmp_type == 3) {
	      switch(icmp->icmp_code) {
		
	      case 3: /* p0rt unreachable */		
		newport = ntohs(data[1]);
		if (portlookup[newport] >= 0) {
		  current = &scan[portlookup[newport]];
		  if (!o.magic_port_set) {
		    packet_trynum = ntohs(data[0]) - o.magic_port;
		    if ((packet_trynum|1) != 1) packet_trynum = -1;
		  } else if (current->trynum == 0) packet_trynum = 0;
		  else packet_trynum = -1;
		}
		else { 
		  if (o.debugging) {
		    printf("Illegal ICMP port unreachable packet:\n");
		    hdump((unsigned char *)icmp, ntohs(ip->ip_len) -sizeof(struct ip));
		  }
		    continue; 
		}		  		
		break;
	      }    
	    }
	  } else if (ip->ip_p == IPPROTO_UDP) {
	    printf("Received udp packet back ... interesting\n");
	    continue;
	  }
	  gettimeofday(&now, NULL);
	  if (current->state == PORT_CLOSED && (packet_trynum < 0)) {
	    target->to.rttvar *= 1.2;
	    if (o.debugging) { printf("Late packet, couldn't figure out sendno so we do varianceincrease to %d\n", target->to.rttvar); 
	    }
	  } else if (packet_trynum > -1) {		
	    /* Update our records */
	    delta = TIMEVAL_SUBTRACT(now,current->sent[packet_trynum]) - target->to.srtt;
	    if (o.debugging > 1) printf("Got packet (trynum %d, packetnum %d), delta %d srtt %d rttvar %d timeout %d ->", current->trynum, packet_trynum, delta, target->to.srtt, target->to.rttvar, target->to.timeout);
	    numqueries_ideal = MIN(numqueries_ideal + (packet_incr/numqueries_ideal), max_width);
	    target->to.srtt += delta >> 3;
	    target->to.rttvar += (ABS(delta) - target->to.rttvar) >> 2;
	    target->to.timeout = target->to.srtt + (target->to.rttvar << 2);
	    if (o.debugging > 1) printf("srtt %d rttvar %d timeout %d senddelay %d dropped %d freshportstried %d\n",  target->to.srtt, target->to.rttvar, target->to.timeout, senddelay, dropped, freshportstried);
	    if (packet_trynum > 0 && current->trynum > 0) {
	      /* The first packet was apparently lost, slow down */
	      dropped++;
	      if (freshportstried > 50 && ((double) dropped/freshportstried) > 0.2) {
		if (!senddelay) senddelay = 50000;
		else senddelay = MIN(senddelay * 2, 1000000);
		freshportstried = 0;
		dropped = 0;
		if (o.verbose || o.debugging )  
		  printf("Too many drops ... increasing senddelay to %d\n", senddelay);
	      }
	      if (windowdecrease == 0) {
		numqueries_ideal *= fallback_percent;
		if (numqueries_ideal < 1) numqueries_ideal = 1;
		if (o.debugging) { printf("Lost a packet, decreasing window to %d\n", (int) numqueries_ideal);
		windowdecrease++;
		if (scantype == UDP_SCAN) usleep(250000);
		}
	      } else if (o.debugging > 1) { printf("Lost a packet, but not decreasing\n");
	      }
	    }
	  }  	      
	  if (current->state != PORT_CLOSED) {
	    changed++;
	    numqueries_outstanding--;
	    current->state = PORT_CLOSED;
	    if (current == testinglist)
	      testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
	    if (current->next >= 0) scan[current->next].prev = current->prev;
	    if (current->prev >= 0) scan[current->prev].next = current->next;
	  }
	}
      } 
    }
    /* Prepare for retry */
    testinglist = openlist;
    for(current = openlist; current; current = (current->next >= 0)? &scan[current->next] : NULL) {
      current->state = PORT_FRESH;
      current->trynum = 0;
      if (o.debugging) { 
	printf("Preparing for retry, open port %d noted\n", current->portno); 
      }
    }  
    openlist = NULL;
    numqueries_ideal = initial_packet_width;
    printf("Done with round %d\n", tries);
  } while(changed && ++tries < 100);   

  openlist = testinglist;

  if (o.debugging || o.verbose)
    printf("The UDP or stealth FIN/NULL/XMAS scan took %ld seconds to scan %d ports.\n", 
	   (long) time(NULL) - starttime, o.numports);
  
  for (current = openlist; current;  current = (current->next >= 0)? &scan[current->next] : NULL) {
    if (scantype != UDP_SCAN)
      addport(&target->ports, current->portno, IPPROTO_TCP, NULL, PORT_OPEN);
    else
       addport(&target->ports, current->portno, IPPROTO_UDP, NULL, PORT_OPEN);
  }
    free(scan);
    close(rawsd);
    pcap_close(pd);
    return target->ports;
}


portlist pos_scan(struct hoststruct *target, unsigned short *portarray, stype scantype) {
  int initial_packet_width = 10;  /* How many scan packets in parallel (to start with) */
  struct scanstats ss;
  int rawsd;
  char myname[513];
  int scanflags = 0;

  int victim;
  int senddelay = 0;

  pcap_t *pd;
  struct bpf_program fcode;
  char err0r[PCAP_ERRBUF_SIZE];
  char filter[512];
  char *p;
  int tries = 0;
  int  res;
  unsigned int localnet, netmask;
  int starttime;
  struct hostent *myhostent = NULL;
  struct sockaddr_in sock;
  struct portinfo *scan,  *current, *fresh, *next;
  struct portinfolist pil;
  int portlookup[65536]; /* Indexes port number -> scan[] index */
  int decoy;
  struct timeval now;
  unsigned long sequences[3]; /* for various reasons we use 3 seperate
				 ones rather than simply incrementing from
				 a base */
  int i;

  ss.packet_incr = 4;
  ss.fallback_percent = 0.7;
  ss.numqueries_outstanding = 0;
  ss.numqueries_ideal = initial_packet_width;
  ss.ports_left = o.numports;
  ss.alreadydecreasedqueries = 0;

  bzero(&pil, sizeof(pil));

  if (scantype == SYN_SCAN)
    ss.max_width = 150;
  else ss.max_width = o.max_sockets;
  memset(portlookup, 255, 65536 * sizeof(int)); /* 0xffffffff better always be (int) -1 */
  scan = safe_malloc(o.numports * sizeof(struct portinfo));
  
  /* Initialize our portlist (scan) */
  for(i = 0; i < o.numports; i++) {
    scan[i].state = PORT_FRESH;
    scan[i].portno = portarray[i];
    scan[i].trynum = 0;
    scan[i].prev = i-1;
    scan[i].sd[0] = scan[i].sd[1] = scan[i].sd[2] = -1;
    if (i < o.numports -1 ) scan[i].next = i+1;
    else scan[i].next = -1;
    portlookup[portarray[i]] = i;
  }

  current = fresh = pil.testinglist = &scan[0]; /* fresh == unscanned ports, testinglist is a list of all ports that haven't been determined to be closed yet */


    
  /* Init our raw socket */
  if (scantype == SYN_SCAN) {  
    if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      pfatal("socket trobles in super_scan");
    unblock_socket(rawsd);
    

    /* Init ISNs */
    sequences[0] = rand() + rand();
    sequences[1] = rand() + rand();
    sequences[2] = rand() + rand();

    /* Do we have a correct source address? */
    if (!target->source_ip.s_addr) {
      if (gethostname(myname, MAXHOSTNAMELEN) != 0 && 
	  !((myhostent = gethostbyname(myname))))
	fatal("Your system is messed up.\n"); 
      memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
      if (o.debugging || o.verbose) 
	printf("We skillfully deduced that your address is %s\n",
	       inet_ntoa(target->source_ip));
    }
    
    /* Now for the pcap opening nonsense ... */
    /* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
     * header + 4 bytes of TCP port info.
     */
    
    if (!(pd = pcap_open_live(target->device, 92,  (o.spoofsource)? 1 : 0, 20, err0r)))
      fatal("pcap_open_live: %s", err0r);
    
    if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
      fatal("Failed to lookup device subnet/netmask: %s", err0r);
    p = strdup(inet_ntoa(target->host));
    sprintf(filter, "(icmp and dst host %s) or (tcp and src host %s and dst host %s)", inet_ntoa(target->source_ip), p, inet_ntoa(target->source_ip));
    free(p);
    /* Stupid libpcap problem, is this Linux only? */
#ifdef LINUX
    if (target->source_ip.s_addr == htonl(0x7F000001))
      filter[0] = '\0';
#endif


    if (o.debugging)
      printf("Packet capture filter: %s\n", filter);
    if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
      fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
    if (pcap_setfilter(pd, &fcode) < 0 )
      fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
    scanflags = TH_SYN;
  } else {
    rawsd = -1;
    /* Init our sock */
    bzero((char *)&sock,sizeof(struct sockaddr_in));
    sock.sin_addr.s_addr = target->host.s_addr;
    sock.sin_family=AF_INET;
  }

  starttime = time(NULL);

  if (o.debugging || o.verbose) {  
    if (scantype == SYN_SCAN)
      printf("Initiating SYN half-open stealth scan against %s (%s)\n", target->name, inet_ntoa(target->host));
    else printf("Initiating TCP connect() scan against %s (%s)\n",target->name, inet_ntoa(target->host)); 
  }

  do {
    ss.changed = 0;
    if (tries > 3 && senddelay == 0) {
      senddelay = 10000; 
      if (o.verbose) printf("Bumping up senddelay, due to excessive drops\n");
    }
			    
    while(pil.testinglist != NULL)  /* While we have live queries or more ports to scan */
    {
      /* Check the possible retransmissions first */
      gettimeofday(&now, NULL);
      for( current = pil.testinglist; current ; current = next) {
	next = (current->next > -1)? &scan[current->next] : NULL;
	if (current->state == PORT_TESTING) {
	  if ( TIMEVAL_SUBTRACT(now, current->sent[current->trynum]) > target->to.timeout) {
	    if (current->trynum > 1) {
	      /* No responses !#$!#@$ firewalled? */
	      if (o.debugging) { printf("Moving port %hi to the potentially firewalled list\n", current->portno); }
	      if (current->state != PORT_TESTING)
		fatal("Whacked port state!  Bailing!");
	      current->state = PORT_FIREWALLED; /* For various reasons */
	      /* First delete from old list */
	      if (current->next > -1) scan[current->next].prev = current->prev;
	      if (current->prev > -1) scan[current->prev].next = current->next;
	      if (current == pil.testinglist)
		pil.testinglist = (current->next >= 0)?  &scan[current->next] : NULL;
	      current->next = -1;
	      current->prev = -1;
	      /* Now move into new list */
	      if (!pil.firewalled) pil.firewalled = current;
	      else {
		current->next = pil.firewalled - scan;
		pil.firewalled = current;
		scan[current->next].prev = current - scan;	      
	      }
	      if (scantype == SYN_SCAN)
		ss.numqueries_outstanding--;
	      else {
		/* close the appropriate sd for each try */
		for(i=0; i <= current->trynum; i++) {
		  if (current->sd[i] >= 0) {		  
		    close(current->sd[i]);
		    current->sd[i] = -1;
		    ss.numqueries_outstanding--;
		  }
		}
	      }
	    } else {  /* timeout ... we've got to resend */
	      if (o.debugging > 1) { printf("Timeout, resending to portno %hi\n", current->portno); }
	      current->trynum++;
	      gettimeofday(&current->sent[current->trynum], NULL);
	      now = current->sent[current->trynum];
	      if (scantype == SYN_SCAN) {	      
		for(decoy=0; decoy < o.numdecoys; decoy++) {
		  if (o.fragscan)
		    send_small_fragz(rawsd, &o.decoys[decoy], &target->host, sequences[current->trynum],o.magic_port + tries * 3 + current->trynum, current->portno, scanflags);
		  else 
		    send_tcp_raw(rawsd, &o.decoys[decoy], &target->host, o.magic_port + tries * 3 + current->trynum, 
				 current->portno, sequences[current->trynum], 0, scanflags, 0, NULL, 0,0, 0);
		}
	      } else   { /* Connect scan */
		/* Unfortunately, retries cost us a socket!  If we are
		   out of sockets, we must drop one of our earlier tries
		   :( */
		if (ss.numqueries_outstanding >= ss.max_width) {		
		  victim = -1;
		  for(i=0; i < current->trynum; i++)
		    if (current->sd[i] < 0) {
		      victim = i;
		      break;
		    }
		  if (victim == -1) 
		    fatal("Illegal situation in pos_scan -- please report to fyodor@dhp.com");
		  close(current->sd[victim]);
		  current->sd[victim] = -1;
		} else {
		  ss.numqueries_outstanding++;
		}
		res = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (res == -1) pfatal("Socket troubles in pos_scan 143");
		unblock_socket(res);
		init_socket(res);
		sock.sin_port = htons(current->portno);
		current->sd[current->trynum] = res;
		
		res =  connect(res,(struct sockaddr *)&sock,sizeof(struct sockaddr));
		if (res != -1) {
		  posportupdate(target, current, current->trynum, scan, &ss, scantype, PORT_OPEN, &pil);
		}
	      }
	      if (senddelay) usleep(senddelay);
	    }
	  }
	} else { 
	  if (current->state != PORT_FRESH) fatal("State mismatch!%!@% %d", current->state);
	  /* current->state == PORT_FRESH */
	  /* OK, now we have gone through our list of in-transit queries, so now
	     we try to send off new queries if we can ... */
	  if (ss.numqueries_outstanding > (int) ss.numqueries_ideal) break;
	  if (o.debugging > 1) printf("Sending initial query to port %hu\n", current->portno);
	  /* Otherwise lets send a packet! */
	  current->state = PORT_TESTING;
	  /*	if (!testinglist) testinglist = current; */
	  ss.numqueries_outstanding++;
	  gettimeofday(&current->sent[0], NULL);
	  if (scantype == SYN_SCAN) {	  
	    for(decoy=0; decoy < o.numdecoys; decoy++) {
	      if (o.fragscan)
		send_small_fragz(rawsd, &o.decoys[decoy], &target->host, sequences[current->trynum], o.magic_port + tries * 3, current->portno, scanflags);
	      else
		send_tcp_raw(rawsd, &o.decoys[decoy], &target->host, o.magic_port + tries * 3, current->portno, sequences[current->trynum], 0, scanflags, 0, NULL, 0, 0, 0);
	      if (senddelay) usleep(senddelay);
	    }
	  } else { /* CONNECT SCAN */
	    
	    res = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	    if (res == -1) pfatal("Socket troubles in pos_scan 143");
	    unblock_socket(res);
	    init_socket(res);
	    sock.sin_port = htons(current->portno);
	    current->sd[current->trynum] = res;
	    
	    res =  connect(res,(struct sockaddr *)&sock,sizeof(struct sockaddr));
	    if (res != -1) {
	      posportupdate(target, current, current->trynum, scan,&ss, scantype, PORT_OPEN, &pil);
	    }
	  }
	  if (senddelay) usleep(senddelay);
	}
      }
      /*      if (o.debugging > 1) printf("Ideal number of queries: %d outstanding: %d max %d ports_left %d timeout %d\n", (int) ss.numqueries_ideal, ss.numqueries_outstanding, ss.max_width, ss.ports_left, target->to.timeout);*/

      /* Now that we have sent the packets we wait for responses */
      ss.alreadydecreasedqueries = 0;
      if (scantype == SYN_SCAN)
	get_syn_results(target, scan, &ss, &pil, portlookup, pd, sequences);
      else {
	/*	get_connect_results(target, scan, ss, openports);*/
      }
    }

    if (ss.numqueries_outstanding != 0) {
      fatal("Bean counting error no. 4321897: ports_left: %d numqueries_outstanding: %d\n", ss.ports_left, ss.numqueries_outstanding);
    }
    
    /* We only want to try if the 'firewalled' list contains elements,
       meaning that some ports timed out.  We retry until nothing
       changes for a round (not counting the very first round).
    */
    if (pil.firewalled) {
      if (tries == 0 || ss.changed) {	
	pil.testinglist = pil.firewalled;
	for( current = pil.testinglist; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  current->state = PORT_FRESH;
	  current->trynum = 0;
	  current->sd[0] = current->sd[1] = current->sd[2] = -1;
	  if (o.debugging) { 
	    printf("Preparing for retry, nonresponsive port %d noted\n", current->portno); 
	  }
	}
	pil.firewalled = NULL;
      } else {
	/* Consider the ports firewalled */	
	for( current = pil.firewalled; current ; 
	     current = (current->next > -1)? &scan[current->next] : NULL) {
	  addport(&target->ports, current->portno, IPPROTO_TCP, NULL, PORT_FIREWALLED);
	}
	pil.testinglist = NULL;
      }
      tries++;
    }
    ss.numqueries_ideal = initial_packet_width;
    if (o.debugging)
      printf("Done with round %d\n", tries);
  } while(pil.testinglist && tries < 20);

  if (tries == 20) {
    error("WARNING: GAVE UP ON SYN SCAN AFTER 20 RETRIES");
  }

  if (o.verbose)
    printf("The SYN scan took %ld seconds to scan %d ports.\n", 
	   (long) time(NULL) - starttime, o.numports);
  
    free(scan);
    if (rawsd >= 0) 
      close(rawsd);
    pcap_close(pd);
    return target->ports;
}

/* Does the appropriate stuff when the port we are looking at is found
   to be open trynum is the try number that was successful 
   I USE CURRENT->STATE TO DETERMINE WHETHER THE PORT IS OPEN
   OR FIREWALLED */
void posportupdate(struct hoststruct *target, struct portinfo *current, 
		 int trynum, struct portinfo *scan,
		 struct scanstats *ss ,stype scantype, int newstate,
		 struct portinfolist *pil) {
static int tryident = -1;
static struct hoststruct *lasttarget = NULL;
struct sockaddr_in mysock;
int sockaddr_in_len = sizeof(SA);
int i;
char owner[1024];
if (tryident == -1 || target != lasttarget) 
  tryident = o.identscan;
lasttarget = target;

if (current->state != PORT_OPEN && current->state != PORT_CLOSED &&
    current->state != PORT_FIREWALLED && current->state != PORT_TESTING) {
  if (o.debugging) error("Whacked packet to port %hi passed to posportupdate with state %d\n", current->portno, current->state);
  return;
}

/* Lets do the timing stuff */
  if (o.debugging > 1) 
    printf("Got packet (trynum %d, packetnum %d), srtt %d rttvar %d timeout %d ->", current->trynum, trynum, target->to.srtt, target->to.rttvar, target->to.timeout);
if (trynum > -1) 
  adjust_timeouts(current->sent[trynum], &(target->to));

 if (o.debugging > 1) 
    printf(" srtt %d rttvar %d timeout %d\n", target->to.srtt, target->to.rttvar, target->to.timeout);


/* If a non-zero trynum finds a port that hasn't been discovered, the
   earlier packets(s) were probably dropped.  So we decrease our 
   numqueries_ideal, otherwise we increase it slightly */
if (trynum == 0) {
  ss->numqueries_ideal = MIN(ss->numqueries_ideal + (ss->packet_incr/ss->numqueries_ideal), ss->max_width);
} else if (trynum != -1) {
  if (!ss->alreadydecreasedqueries) {
    ss->alreadydecreasedqueries = 1;
    ss->numqueries_ideal *= ss->fallback_percent;
    if (ss->numqueries_ideal < 1.0) ss->numqueries_ideal = 1.0;
  }
}

/* Now we convert current->state to state by making whatever adjustments
   are neccessary */
switch(current->state) {
 case PORT_OPEN:
   return; /* Whew!  That was easy! */
   break;
 case PORT_FRESH:
   printf("Fresh port %hi passed to posportupdate!\n", current->portno);
   return;
   break;
 case PORT_CLOSED:
   current->state = newstate;
   break;
 case PORT_TESTING:
   ss->changed++;
   if (scantype == SYN_SCAN)
     ss->numqueries_outstanding--;
   else {
     for(i=0; i <= current->trynum; i++)
       if (current->sd[i] > -1) {
	 close(current->sd[i]);
	 current->sd[i] = -1;
	 ss->numqueries_outstanding--;
       }
   }
   /* Now we delete the port from the testinglist */
   if (current == pil->testinglist)
     pil->testinglist = (current->next >= 0)? &scan[current->next] : NULL;
   if (current->next >= 0)  scan[current->next].prev = current->prev;
   if (current->prev >= 0)  scan[current->prev].next = current->next;
   break;
 case PORT_FIREWALLED:
   ss->changed++;
   if (current == pil->firewalled)
     pil->firewalled = (current->next >= 0)? &scan[current->next] : NULL;
   if (current->next >= 0)  scan[current->next].prev = current->prev;
   if (current->prev >= 0)  scan[current->prev].next = current->next;
   break;
 default:
   fatal("Unexpected port state: %d\n", current->state);
   break;
} 
 current->state = newstate;
 if (newstate == PORT_OPEN || newstate == PORT_FIREWALLED) {
   if (o.verbose) printf("Adding TCP port %hi (state %d).\n", current->portno, current->state);
   if (newstate == PORT_OPEN && scantype == CONNECT_SCAN && tryident) {
     if (getsockname(current->sd[trynum], (SA *) &mysock,
		     &sockaddr_in_len )) {
       pfatal("getsockname");
     }
     if (getidentinfoz(target->host, ntohs(mysock.sin_port), current->portno, owner) == -1)
       tryident = 0;
   }
   addport(&target->ports, current->portno, IPPROTO_TCP, owner, newstate);
 }
 return;
}

void adjust_timeouts(struct timeval sent, struct timeout_info *to) {
  int delta;
  struct timeval end;
  gettimeofday(&end, NULL);
  delta = TIMEVAL_SUBTRACT(end, sent) - to->srtt;
  to->srtt += delta >> 3;
  to->rttvar += (ABS(delta) - to->rttvar) >> 2;
  to->timeout = to->srtt + (to->rttvar << 2);
  
}

void get_syn_results(struct hoststruct *target, struct portinfo *scan,
		     struct scanstats *ss, struct portinfolist *pil, 
		     int *portlookup, pcap_t *pd, unsigned long *sequences) {

struct ip *ip;
int bytes;
struct tcphdr *tcp;
int trynum;
int newstate = -1;
int i;
int newport;
struct portinfo *current = NULL;
struct icmp *icmp;
struct ip *ip2;
unsigned short *data;

      while (ss->numqueries_outstanding > 0 && ( ip = (struct ip*) readip_pcap(pd, &bytes))) {
	if (bytes < (4 * ip->ip_hl) + 4)
	  continue;
	current = NULL;
	trynum = newport = -1;
	newstate = PORT_UNKNOWN;
	if (ip->ip_src.s_addr == target->host.s_addr && ip->ip_p == IPPROTO_TCP) {
	  tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
	  newport = ntohs(tcp->th_sport);
	  /* In case we are scanning localhost and see outgoing packets */
	  if (ip->ip_src.s_addr == target->source_ip.s_addr && !tcp->th_ack) {
	    continue;
	  }
	  if (portlookup[newport] < 0) {
	    if (o.debugging) {
	      printf("Strange packet from port %d:\n", ntohs(tcp->th_sport));
	      readtcppacket((char *)ip, bytes);
	    }
	    current = NULL;
	    continue;
	  }	      

	  current = &scan[portlookup[newport]];
	  for(i=0; i < 3; i++) {
	    if (MOD_DIFF(sequences[i],ntohl(tcp->th_ack)) < 5)
	      break;
	  }
	  if (i < 3) trynum = i;
	  else {
	    if (o.debugging) 
	      printf("Strange ACK number from target\n");
	    trynum = (current->trynum == 0)? 0 : -1;	    
	  }
	  if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {	  
	    newstate = PORT_OPEN;
	  }
	  else if (tcp->th_flags & TH_RST) {	  
	    newstate = PORT_CLOSED;
	    }	
	} else if (ip->ip_p == IPPROTO_ICMP) {
	  icmp = (struct icmp *) ((char *)ip + sizeof(struct ip));
	  ip2 = (struct ip *) (((char *) ip) + 4 * ip->ip_hl + 8);
	  data = (unsigned short *) ((char *)ip2+ 4 * ip2->ip_hl);
	  /*	    printf("Caught ICMP packet:\n");
		    hdump(icmp, ntohs(ip->ip_len) - sizeof(struct ip)); */
	  if (icmp->icmp_type == 3) {
	    switch(icmp->icmp_code) {
	      
	    case 3: /* p0rt unreachable */		
	      newport = ntohs(data[1]);
	      if (portlookup[newport] >= 0) {
		current = &scan[portlookup[newport]];
		trynum = (current->trynum == 0)? 0 : -1;
		newstate = PORT_FIREWALLED;
	      }
	      else { 
		if (o.debugging) {
		  printf("Illegal ICMP port unreachable packet:\n");
		  hdump((unsigned char *)icmp, ntohs(ip->ip_len) -sizeof(struct ip));
		}
		continue; 
	      }	  		
	      break;
	    case 13:
	      newport = ntohs(data[1]);
	      if (portlookup[newport] >= 0) {
		current = &scan[portlookup[newport]];
		trynum = (current->trynum == 0)? 0 : -1;
		newstate = PORT_FIREWALLED;
	      }
	      else { 
		if (o.debugging) {
		  printf("Illegal ICMP port unreachable packet:\n");
		  hdump((unsigned char *)icmp, ntohs(ip->ip_len) -sizeof(struct ip));
		}
		continue; 
	      }	  		
	      break;
	    }
	  }	
	}      
	/* OK, now we manipulate the port lists and adjust the time */
	if (current) {
	  posportupdate(target, current, trynum, scan, ss, SYN_SCAN, newstate,
			pil);
	  current = NULL;
	  trynum = -1;
	  newstate = PORT_UNKNOWN;
	}
      }
}

portlist fin_scan(struct hoststruct *target, unsigned short *portarray) {

int rawsd;
int done = 0, badport, starttime, someleft, i, j=0, retries=2;
int waiting_period = retries, sockaddr_in_size = sizeof(struct sockaddr_in);
int dupesinarow = 0;
unsigned bytes;
int scanflags =0;
unsigned long timeout;
struct hostent *myhostent = NULL;
char response[65535], myname[513];
pcap_t *pd;
struct bpf_program fcode;
char filter[512];
unsigned int localnet, netmask;
char *p = NULL;
char err0r[PCAP_ERRBUF_SIZE];
struct ip *ip = NULL; /*(struct ip *) response;*/
struct tcphdr *tcp = NULL;
unsigned short portno[MAX_SOCKETS_ALLOWED];
unsigned short trynum[MAX_SOCKETS_ALLOWED];
struct sockaddr_in stranger;
int decoy=0;

timeout = (target->rtt)? target->rtt + 10000 : 1e5;

bzero(&stranger, sockaddr_in_size);
bzero(portno, o.max_sockets * sizeof(unsigned short));
bzero(trynum, o.max_sockets * sizeof(unsigned short));
starttime = time(NULL);

if (o.xmasscan) scanflags = TH_FIN|TH_URG|TH_PUSH;
else if (o.nullscan) scanflags = 0;
else if (o.finscan) scanflags = TH_FIN;
else if (o.maimonscan) scanflags = TH_FIN|TH_ACK;

if (o.debugging || o.verbose)
  printf("Initiating FIN,NULL,or Xmas stealth scan against %s (%s), sleep delay: %ld useconds\n", target->name, inet_ntoa(target->host), timeout);

if (!target->source_ip.s_addr) {
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is messed up.\n"); 
  memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
  if (o.debugging || o.verbose) 
    printf("We skillfully deduced that your address is %s\n",
	   inet_ntoa(target->source_ip));
}

/* Now for the pcap opening nonsense ... */
/* Note that the snaplen is 92 = 64 byte max IPhdr + 24 byte max link_layer
 * header + 4 bytes of TCP port info.
 */

if (!(pd = pcap_open_live(target->device, 92,  (o.spoofsource)? 1 : 0, 1500, err0r)))
  fatal("pcap_open_live: %s", err0r);

if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
  fatal("Failed to lookup device subnet/netmask: %s", err0r);
p = strdup(inet_ntoa(target->host));
#ifdef HAVE_SNPRINTF
snprintf(filter, sizeof(filter), "tcp and src host %s and dst host %s and dst port %d", p, inet_ntoa(target->source_ip), o.magic_port );
#else
sprintf(filter, "tcp and src host %s and dst host %s and dst port %d", p, inet_ntoa(target->source_ip), o.magic_port );
#endif
free(p);
if (o.debugging)
  printf("Packet capture filter: %s\n", filter);
if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
  fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
if (pcap_setfilter(pd, &fcode) < 0 )
  fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));


if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
  perror("socket trobles in fin_scan");

/*if ((tcpsd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 )
  perror("socket trobles in fin_scan");*/

/*unblock_socket(tcpsd);*/
while(!done) {
  for(i=0; i <  o.max_sockets; i++) {
    if (!portno[i] && portarray[j]) {
      portno[i] = portarray[j++];
    }
    if (portno[i]) {
      for(decoy=0; decoy < o.numdecoys; decoy++) {
	if (o.fragscan)
	  send_small_fragz(rawsd, &o.decoys[decoy], &target->host, 0, o.magic_port, portno[i], scanflags);
	else send_tcp_raw(rawsd, &o.decoys[decoy], &target->host, o.magic_port, 
			  portno[i], 0, 0, scanflags, 0, NULL, 0, 0, 0);
	usleep(10000); /* *WE* normally do not need this, but the target 
			  lamer often does */
      }
    }
  }

  usleep(timeout);
  dupesinarow = 0;
  /* NOT PORTABLE, USING libpcap INSTEAD */
  /*while ((bytes = recvfrom(tcpsd, response, 65535, 0, (struct sockaddr *)
    &stranger, &sockaddr_in_size)) > 0) */
  while(( ip = (struct ip*) readip_pcap(pd, &bytes))) 
    {    
      if (bytes < (4 * ip->ip_hl) + 4)
	continue;
      if (ip->ip_src.s_addr == target->host.s_addr) {
	tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
	if (tcp->th_flags & TH_RST) {
	  badport = ntohs(tcp->th_sport);
	  if (o.debugging > 1) printf("Nothing open on port %d\n", badport);
	  /* delete the port from active scanning */
	  for(i=0; i < o.max_sockets; i++) 
	    if (portno[i] == badport) {
	      if (o.debugging && trynum[i] > 0)
		printf("Bad port %d caught on fin scan, try number %d\n",
		       badport, trynum[i] + 1);
	      trynum[i] = 0;
	      portno[i] = 0;
	      break;
	    }
	  if (i == o.max_sockets) {
	    if (o.debugging)
	      printf("Late packet or dupe, deleting port %d.\n", badport);
	    dupesinarow++;
	    if (target->ports) deleteport(&target->ports, badport, IPPROTO_TCP);
	  }
	}
	else 
	  if (o.debugging > 1) {	  
	    printf("Strange packet from target%d!  Here it is:\n", 
		   ntohs(tcp->th_sport));
	    if (bytes >= 40) readtcppacket(response,1);
	    else hdump(response,bytes);
	  }
      }
    }
  
  /* adjust waiting time if neccessary */
  if (dupesinarow > 6) {
    if (o.debugging || o.verbose)
      printf("Slowing down send frequency due to multiple late packets.\n");
    if (timeout < 10 * (target->rtt + 20000)) timeout *= 1.5;
    else {
      printf("Too many late packets despite send frequency decreases, skipping scan.\n");
      return target->ports;
    }
  }
  
  /* Ok, collect good ports (those that we haven't received responses too 
     after all our retries */
  someleft = 0;
  for(i=0; i < o.max_sockets; i++)
    if (portno[i]) {
      if (++trynum[i] >= retries) {
	if (o.verbose || o.debugging)
	  printf("Good port %d detected by fin_scan!\n", portno[i]);
	addport(&target->ports, portno[i], IPPROTO_TCP, NULL, PORT_OPEN);
	send_tcp_raw( rawsd, &target->source_ip, &target->host, o.magic_port, portno[i], 0, 0, 
		scanflags, 0, NULL, 0, 0, 0); 
	portno[i] = trynum[i] = 0;
      }
      else someleft = 1;
    }  
  
  if (!portarray[j] && (!someleft || --waiting_period <= 0)) done++;
}
 
 if (o.debugging || o.verbose)
  printf("The TCP stealth FIN/NULL/XMAS scan took %ld seconds to scan %d ports.\n", 
	 (long) time(NULL) - starttime, o.numports);
/*close(tcpsd);*/
pcap_close(pd);
close(rawsd);
return target->ports;
}

int ftp_anon_connect(struct ftpinfo *ftp) {
int sd;
struct sockaddr_in sock;
int res;
char recvbuf[2048];
char command[512];

if (o.verbose || o.debugging) 
  printf("Attempting connection to ftp://%s:%s@%s:%i\n", ftp->user, ftp->pass,
	 ftp->server_name, ftp->port);

if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
  perror("Couldn't create ftp_anon_connect socket");
  return 0;
}

sock.sin_family = AF_INET;
sock.sin_addr.s_addr = ftp->server.s_addr;
sock.sin_port = htons(ftp->port); 
res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
if (res < 0 ) {
  printf("Your ftp bounce proxy server won't talk to us!\n");
  exit(1);
}
if (o.verbose || o.debugging) printf("Connected:");
while ((res = recvtime(sd, recvbuf, 2048,7)) > 0) 
  if (o.debugging || o.verbose) {
    recvbuf[res] = '\0';
    printf("%s", recvbuf);
  }
if (res < 0) {
  perror("recv problem from ftp bounce server");
  exit(1);
}

#ifndef HAVE_SNPRINTF
sprintf(command, "USER %s\r\n", ftp->user);
#else
snprintf(command, 511, "USER %s\r\n", ftp->user);
#endif

send(sd, command, strlen(command), 0);
res = recvtime(sd, recvbuf, 2048,12);
if (res <= 0) {
  perror("recv problem from ftp bounce server");
  exit(1);
}
recvbuf[res] = '\0';
if (o.debugging) printf("sent username, received: %s", recvbuf);
if (recvbuf[0] == '5') {
  printf("Your ftp bounce server doesn't like the username \"%s\"\n", 
	 ftp->user);
  exit(1);
}

#ifndef HAVE_SNPRINTF
sprintf(command, "PASS %s\r\n", ftp->pass);
#else
snprintf(command, 511, "PASS %s\r\n", ftp->pass);
#endif

send(sd, command, strlen(command), 0);
res = recvtime(sd, recvbuf, 2048,12);
if (res < 0) {
  perror("recv problem from ftp bounce server\n");
  exit(1);
}
if (!res) printf("Timeout from bounce server ...");
else {
recvbuf[res] = '\0';
if (o.debugging) printf("sent password, received: %s", recvbuf);
if (recvbuf[0] == '5') {
  fprintf(stderr, "Your ftp bounce server refused login combo (%s/%s)\n",
	 ftp->user, ftp->pass);
  exit(1);
}
}
while ((res = recvtime(sd, recvbuf, 2048,2)) > 0) 
  if (o.debugging) {
    recvbuf[res] = '\0';
    printf("%s", recvbuf);
  }
if (res < 0) {
  perror("recv problem from ftp bounce server");
  exit(1);
}
if (o.verbose) printf("Login credentials accepted by ftp server!\n");

ftp->sd = sd;
return sd;
}

int recvtime(int sd, char *buf, int len, int seconds) {

int res;
struct timeval timeout;
fd_set readfd;

timeout.tv_sec = seconds;
timeout.tv_usec = 0;
FD_ZERO(&readfd);
FD_SET(sd, &readfd);
res = select(sd + 1, &readfd, NULL, NULL, &timeout);
if (res > 0 ) {
res = recv(sd, buf, len, 0);
if (res >= 0) return res;
perror("recv in recvtime");
return 0; 
}
else if (!res) return 0;
perror("select() in recvtime");
return -1;
}

portlist bounce_scan(struct hoststruct *target, unsigned short *portarray,
		     struct ftpinfo *ftp) {
int starttime,  res , sd = ftp->sd,  i=0;
char *t = (char *)&target->host; 
int retriesleft = FTP_RETRIES;
char recvbuf[2048]; 
char targetstr[20];
char command[512];
unsigned short portno,p1,p2;

#ifndef HAVE_SNPRINTF
sprintf(targetstr, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));
#else
  snprintf(targetstr, 20, "%d,%d,%d,%d,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));
#endif

starttime = time(NULL);
if (o.verbose || o.debugging)
  printf("Initiating TCP ftp bounce scan against %s (%s)\n",
	 target->name,  inet_ntoa(target->host));
for(i=0; portarray[i]; i++) {
  portno = htons(portarray[i]);
  p1 = ((char *) &portno)[0];
  p2 = ((char *) &portno)[1];
#ifndef HAVE_SNPRINTF
  sprintf(command, "PORT %s%i,%i\r\n", targetstr, p1,p2);
#else
  snprintf(command, 512, "PORT %s%i,%i\r\n", targetstr, p1,p2);
#endif
  if (o.debugging) printf("Attempting command: %s", command);
  if (send(sd, command, strlen(command), 0) < 0 ) {
    perror("send in bounce_scan");
    if (retriesleft) {
      if (o.verbose || o.debugging) 
	printf("Our ftp proxy server hung up on us!  retrying\n");
      retriesleft--;
      close(sd);
      ftp->sd = ftp_anon_connect(ftp);
      if (ftp->sd < 0) return target->ports;
      sd = ftp->sd;
      i--;
    }
    else {
      fprintf(stderr, "Our socket descriptor is dead and we are out of retries. Giving up.\n");
      close(sd);
      ftp->sd = -1;
      return target->ports;
    }
  } else { /* Our send is good */
    res = recvtime(sd, recvbuf, 2048,15);
    if (res <= 0) perror("recv problem from ftp bounce server\n");
  
    else { /* our recv is good */
      recvbuf[res] = '\0';
      if (o.debugging) printf("result of port query on port %i: %s", 
			    portarray[i],  recvbuf);
      if (recvbuf[0] == '5') {
	if (portarray[i] > 1023) {
	fprintf(stderr, "Your ftp bounce server sucks, it won't let us feed bogus ports!\n");
	exit(1);
      }
      else {
	fprintf(stderr, "Your ftp bounce server doesn't allow priviliged ports, skipping them.\n");
	while(portarray[i] && portarray[i] < 1024) i++;
	if (!portarray[i]) {
	  fprintf(stderr, "And you didn't want to scan any unpriviliged ports.  Giving up.\n");
	  /*	  close(sd);
	  ftp->sd = -1;
	  return *ports;*/
	  /* screw this gentle return crap!  This is an emergency! */
	  exit(1);
	}
      }  
      }
    else  /* Not an error message */
      if (send(sd, "LIST\r\n", 6, 0) > 0 ) {
	res = recvtime(sd, recvbuf, 2048,12);
	if (res <= 0)  perror("recv problem from ftp bounce server\n");
	else {
	  recvbuf[res] = '\0';
	  if (o.debugging) printf("result of LIST: %s", recvbuf);
	  if (!strncmp(recvbuf, "500", 3)) {
	    /* fuck, we are not aligned properly */
	    if (o.verbose || o.debugging)
	      printf("misalignment detected ... correcting.\n");
	     res = recvtime(sd, recvbuf, 2048,10);
	  }
	  if (recvbuf[0] == '1' || recvbuf[0] == '2') {
	    if (o.verbose || o.debugging) printf("Port number %i appears good.\n",
				portarray[i]);
	    addport(&target->ports, portarray[i], IPPROTO_TCP, NULL, PORT_OPEN);
	    if (recvbuf[0] == '1') {
	    res = recvtime(sd, recvbuf, 2048,5);
	    recvbuf[res] = '\0';
	    if (res > 0) {
	      if (o.debugging) printf("nxt line: %s", recvbuf);
	      if (recvbuf[0] == '4' && recvbuf[1] == '2' && 
		  recvbuf[2] == '6') {	      	
		deleteport(&target->ports, portarray[i], IPPROTO_TCP);
		if (o.debugging || o.verbose)
		  printf("Changed my mind about port %i\n", portarray[i]);
	      }
	    }
	    }
	  }
	}
      }
    }
  }
}
if (o.debugging || o.verbose) 
  printf("Scanned %d ports in %ld seconds via the Bounce scan.\n",
	 o.numports, (long) time(NULL) - starttime);
return target->ports;
}

/* parse a URL stype ftp string of the form user:pass@server:portno */
int parse_bounce(struct ftpinfo *ftp, char *url) {
char *p = url,*q, *s;

if ((q = strrchr(url, '@'))) /*we have username and/or pass */ {
  *(q++) = '\0';
  if ((s = strchr(q, ':')))
    { /* has portno */
      *(s++) = '\0';
      strncpy(ftp->server_name, q, MAXHOSTNAMELEN);
      ftp->port = atoi(s);
    }
  else  strncpy(ftp->server_name, q, MAXHOSTNAMELEN);

  if ((s = strchr(p, ':'))) { /* User AND pass given */
    *(s++) = '\0';
    strncpy(ftp->user, p, 63);
    strncpy(ftp->pass, s, 255);
  }
  else { /* Username ONLY given */
    printf("Assuming %s is a username, and using the default password: %s\n",
	   p, ftp->pass);
    strncpy(ftp->user, p, 63);
  }
}
else /* no username or password given */ 
  if ((s = strchr(url, ':'))) { /* portno is given */
    *(s++) = '\0';
    strncpy(ftp->server_name, url, MAXHOSTNAMELEN);
    ftp->port = atoi(s);
  }
  else  /* default case, no username, password, or portnumber */
    strncpy(ftp->server_name, url, MAXHOSTNAMELEN);

ftp->user[63] = ftp->pass[255] = ftp->server_name[MAXHOSTNAMELEN] = 0;

return 1;
}

void nmap_log(char *fmt, ...) {
va_list  ap;
va_start(ap, fmt);
vfprintf(stdout, fmt, ap);
fflush(stdout);
if (o.logfd && o.logfd != stdout) {
  vfprintf(o.logfd, fmt, ap);
}
va_end(ap);
return;
}

void sigdie(int signo) {
 switch(signo) {
 case SIGINT:
   fprintf(stderr, "caught SIGINT signal, cleaning up\n");
   break;
 case SIGTERM:
   fprintf(stderr, "caught SIGTERM signal, cleaning up\n");
   break;
 case SIGHUP:
   fprintf(stderr, "caught SIGHUP signal, cleaning up\n");
   break;
 case SIGSEGV:
   fprintf(stderr, "caught SIGSEGV signal, cleaning up\n");
   break;
 case SIGBUS:
   fprintf(stderr, "caught SIGBUS signal, cleaning up\n");
   break;
 default:
   fprintf(stderr, "caught signal %d, cleaning up\n", signo);
   break;
 }
 fflush(stdout);
 if (o.logfd && o.logfd != stdout) fclose(o.logfd);
 exit(1);
}


