#include "nmap.h"

/* global options */
extern char *optarg;
extern int optind;
struct ops o;  /* option structure */

int main(int argc, char *argv[]) {
int i, j, arg, argvlen;
short fastscan=0, tcpscan=0, udpscan=0, randomize=0, resolve_all=0;
short quashargv = 0, pingscan = 0, lamerscan = 0;
int lookahead = LOOKAHEAD;
short bouncescan = 0;
unsigned short *ports = NULL;
#ifdef IN_ADDR_DEEPSTRUCT
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

/* argv faking silliness */
for(i=0; i < argc; i++) {
  fakeargv[i] = safe_malloc(strlen(argv[i]) + 1);
  strncpy(fakeargv[i], argv[i], strlen(argv[i]) + 1);
}
fakeargv[argc] = NULL;
/* initialize our options */
options_init();

emptystring[0] = '\0'; /* It wouldn't be an emptystring w/o this ;) */

if (argc < 2 ) printusage(argv[0]);

/* OK, lets parse these args! */
while((arg = getopt(argc,fakeargv,"Ab:DdFfhiL:lM:NnPp:qrRS:sT:tUuw:Vv")) != EOF) {
  switch(arg) {
  case 'A': o.allowall++; break;
  case 'b': 
    bouncescan++;
    if (parse_bounce(&ftp, optarg) < 0 ) {
      fprintf(stderr, "Your argument to -b is fucked up. Use the normal url style:  user:pass@server:port or just use server and use default anon login\n  Use -h for help\n");
    }
    break;
  case 'D': o.dontping++; break;
  case 'd': o.debugging++; break;
  case 'F': fastscan++; break;
  case 'f': o.fragscan++; break;
  case 'h': 
  case '?': printusage(argv[0]);
  case 'i': o.identscan++; break;
  case 'L': lookahead = atoi(optarg); break;
  case 'l': lamerscan++; udpscan++; break;
  case 'M': o.max_sockets = atoi(optarg); break;
  case 'n': o.noresolve++; break;
  case 'N': o.force++; break;
  case 'P': pingscan++; break;
  case 'p': 
    if (ports)
      fatal("Only 1 -p option allowed, seperate multiple ranges with commas.");
    ports = getpts(optarg); break;
  case 'R': resolve_all++; break;
  case 'r': randomize++; break;
  case 's': o.synscan++; break;
  case 'S': 
    if (source)
      fatal("You can only use the source option once!\n");
    source = safe_malloc(sizeof(struct in_addr));
    if (!inet_aton(optarg, source))
      fatal("You must give the source address in dotted decimal, currently.\n");
    break;
  case 'T': o.ptime = atoi(optarg); break;
  case 't': tcpscan++; break;
  case 'U': o.finscan++; break;
  case 'u': udpscan++; break;
  case 'q': quashargv++; break;
  case 'w': o.wait = atoi(optarg); break;
  case 'V': 
    printf("\nnmap V. %s by Fyodor (fyodor@dhp.com, www.dhp.com/~fyodor/nmap/)\n", VERSION); 
    exit(0);
    break;
  case 'v': o.verbose++;
  }
}

/* Take care of user wierdness */
o.isr00t = !(geteuid()|geteuid());
if (!o.isr00t && pingscan) fatal("You can't do a ping scan if you aren't root");
if (pingscan && o.dontping) fatal("ICMP ping scan -P and don't ping -D are incompatible options, Duh.");
if (!o.isr00t) o.dontping++;
if (bouncescan && !o.dontping) printf("Hint: if your bounce scan target hosts aren't reachable from here, remember to use -D\n");
if (tcpscan && o.synscan) 
  fatal("The -t and -s options can't be used together.\
 If you are trying to do TCP SYN scanning, just use -s.\
 For normal connect() style scanning, use -t");
if ((o.synscan || o.finscan || o.fragscan || pingscan) && !o.isr00t)
  fatal("Options specified require r00t privileges.  You don't have them!");
if (!tcpscan && !udpscan && !o.synscan && !o.finscan && !bouncescan && !pingscan) {
  tcpscan++;
  if (o.verbose) error("No scantype specified, assuming vanilla tcp connect()\
 scan. Use -P if you really don't want to portscan.");
if (fastscan && ports)
  fatal("You can use -F (fastscan) OR -p for explicit port specification.\
  Not both!\n");
}
if (pingscan && o.dontping)
/* If he wants to bounce of an ftp site, that site better damn well be reachable! */

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
	   target->h_name, inet_ntoa(ftp.server)); 
}
printf("\nStarting nmap V. %s by Fyodor (fyodor@dhp.com, www.dhp.com/~fyodor/nmap/)\n", VERSION);
/* I seriously doubt anyone likes this "feature"
if (!o.verbose) 
  error("Hint: The -v option notifies you of open ports as they are found.\n");
  */
if (fastscan)
  ports = getfastports(o.synscan|tcpscan|o.fragscan|o.finscan|bouncescan,
                       udpscan|lamerscan);
if (!ports && !pingscan) ports = getpts("1-1024");


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
if ((i = max_sd()) && i < o.max_sockets) {
  printf("Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway\n", o.max_sockets, i);
}
if (o.debugging > 1) printf("The max # of sockets on your system is: %d\n", i);
srand(time(NULL));

if (randomize)
  shortfry(ports); 
while(optind < argc) {
  while((currenths = nexthost(fakeargv[optind], lookahead, o.ptime)) && currenths->host.s_addr) {
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
if (!pingscan) {
  if (!o.dontping && (currenths->flags & HOST_UP) && (o.verbose || o.debugging)) 
    printf("Host %s (%s) appears to be up ... good.\n", currenths->name, inet_ntoa(currenths->host));    
  else if (o.verbose && !o.dontping && !(currenths->flags & HOST_UP)) 
    printf("Host %s (%s) appears to be down, skipping it.\n", currenths->name, inet_ntoa(currenths->host));
}
else {
  if (currenths->flags & HOST_UP) 
    printf("Host %s (%s) appears to be up.\n", currenths->name, inet_ntoa(currenths->host));    
  else 
    if (o.verbose || o.debugging || resolve_all) printf("Host %s (%s) appears to be down.\n", currenths->name, inet_ntoa(currenths->host));
  if (currenths->wierd_responses)
    printf("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
}
if (currenths->flags & HOST_UP && !currenths->source_ip.s_addr && ( o.synscan || o.finscan)) {
  getsourceip(currenths);
}

    /* Time for some actual scanning! */    
    if (currenths->flags & HOST_UP) {
      if (tcpscan) tcp_scan(currenths, ports, o.ptime);
      
      if (o.synscan) syn_scan(currenths, ports);
      
      if (o.finscan) fin_scan(currenths, ports);
      
      if (bouncescan) {
	if (ftp.sd <= 0) ftp_anon_connect(&ftp);
	if (ftp.sd > 0) bounce_scan(currenths, ports, &ftp);
	  }
      if (udpscan) {
	if (!o.isr00t || lamerscan) 
	  lamer_udp_scan(currenths, ports);

	else udp_scan(currenths, ports);
      }
    
      if (!currenths->ports && !pingscan) {
	printf("No ports open for host %s (%s)\n", currenths->name,
	       inet_ntoa(currenths->host));
	if (currenths->wierd_responses)
	  printf("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
      }
      if (currenths->ports) {
	printf("Open ports on %s (%s):\n", currenths->name, 
	       inet_ntoa(currenths->host));
	printandfreeports(currenths->ports);
	if (currenths->wierd_responses)
	  printf("Host  %s (%s) seems to be a subnet broadcast address (returned %d extra pings)\n",  currenths->name, inet_ntoa(currenths->host), currenths->wierd_responses);
      }
    }
    fflush(stdout);
  }
  optind++;
}

return 0;
}

void options_init() {
bzero( (char *) &o, sizeof(struct ops));
o.debugging = DEBUGGING;
o.verbose = DEBUGGING;
o.max_sockets = MAX_SOCKETS;
#ifdef IGNORE_ZERO_AND_255_HOSTS
o.allowall = !(IGNORE_ZERO_AND_255_HOSTS);
#endif
o.ptime = PING_TIMEOUT;
}


__inline__ unsigned short in_cksum(unsigned short *ptr,int nbytes) {

register long           sum;            /* assumes long == 32 bits */
u_short                 oddbyte;
register u_short        answer;         /* assumes u_short == 16 bits */

/*
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */

sum = 0;
while (nbytes > 1)  {
sum += *ptr++;
nbytes -= 2;
}

/* mop up an odd byte, if necessary */
if (nbytes == 1) {
oddbyte = 0;            /* make sure top half is zero */
*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
sum += oddbyte;
}

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */

sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
sum += (sum >> 16);                     /* add carry */
answer = ~sum;          /* ones-complement, then truncate to 16 bits */
return(answer);
}

__inline__ int unblock_socket(int sd) {
int options;
/*Unblock our socket to prevent recvfrom from blocking forever 
  on certain target ports. */
options = O_NONBLOCK | fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
return 1;
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
printf("%s [options] [hostname[/mask] . . .]\n\
options (none are required, most can be combined):\n\
   -t tcp connect() port scan\n\
   -s tcp SYN stealth port scan (must be root)\n\
   -u UDP port scan, will use MUCH better version if you are root\n\
   -U Uriel Maimon (P49-15) style FIN stealth scan.\n\
   -l Do the lamer UDP scan even if root.  Less accurate.\n\
   -P ping \"scan\". Find which hosts on specified network(s) are up.\n\
   -D Don't ping hosts (needed to scan scan www.microsoft.com and others)\n\
   -b <ftp_relay_host> ftp \"bounce attack\" port scan\n\
   -f use tiny fragmented packets for SYN or FIN scan.\n\
   -i Get identd (rfc 1413) info on listening TCP processes.\n\
   -n Don't DNS resolve anything unless we have too (makes ping scans faster)\n\
   -p <range> ports: ex: \'-p 23\' will only try port 23 of the host(s)\n\
                  \'-p 20-30,63000-\' scans 20-30 and 63000-65535 default: 1-1024\n\
   -F fast scan. Only scans ports in /etc/services, a la strobe(1).\n\
   -L <num> Number of pings to perform in parallel.  Your default is: %d\n\
   -R Try to resolve all hosts, even down ones (can take a lot of time)\n\
   -r randomize target port scanning order.\n\
   -h help, print this junk.  Also see http://www.dhp.com/~fyodor/nmap/\n\
   -S If you want to specify the source address of SYN or FYN scan.\n", name, LOOKAHEAD);
if (!o.allowall) printf("-A Allow scanning .0 and .255 addresses" );
printf("-T <seconds> Set the ping and tcp connect() timeout.\n\
   -V Print version number and exit.\n\
   -v Verbose.  Its use is recommended.  Use twice for greater effect.\n\
   -w <n> delay.  n microsecond delay. Not recommended unless needed.\n\
   -M <n> maximum number of parallel sockets.  Larger isn't always better.\n\
   -q quash argv to something benign, currently set to \"%s\".\n\
Hostnames specified as internet hostname or IP address.  Optional '/mask' \
specifies subnet. cert.org/24 or 192.88.209.5/24 scan CERT's Class C.\n",
        FAKE_ARGV);
exit(1);
}

portlist tcp_scan(struct hoststruct *target, unsigned short *portarray, int timeout) {

int starttime, current_out = 0, res , deadindex = 0, i=0, j=0, k=0, max=0; 
struct sockaddr_in sock, stranger, mysock;
int sockaddr_in_len = sizeof(struct sockaddr_in);
int seconds, seconds2;  /* Store time temporarily for timeout purposes */
int *sockets = safe_malloc(sizeof(int) * o.max_sockets);  /* All socket descriptors */
int *deadstack = safe_malloc(sizeof(int) * o.max_sockets); /* Stack of dead descriptors (indexes to sockets[] */
unsigned short *portno = safe_malloc(sizeof(unsigned short) * o.max_sockets); /* port numbers of sd's, parallel to sockets[] */
int *times = safe_malloc(sizeof(int) * o.max_sockets); /* initial connect() times of sd's, parallel to sockets[].  For timeout information. */
int *retrystack = safe_malloc(sizeof(int) * o.max_sockets); /* sd's that need to be retried */
int *retries = safe_malloc(sizeof(int) * 65535); /* nr. or retries for this port */
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
      printf("successful connection in non-blocking mode!$\n");
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
      addport(&target->ports, portno[current_socket], IPPROTO_TCP, owner);

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
	printf("Strange error from connect (%d):", errno);
	perror(""); /*falling through intentionally*/
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
  /*  if (!portarray[j] && retryindex < 0) sleep(2); *//*If we are done, wait a second for any last packets*/
  while((res = select(max + 1, &fds_read, &fds_write, NULL, 
		      (current_out < o.max_sockets)?
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
	    addport(&target->ports, portno[k], IPPROTO_TCP, owner);
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
	    addport(&target->ports, portno[k], IPPROTO_TCP, owner);	 
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
		  printf("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.  This warning won't be repeated during this session\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
		else if (o.verbose || o.debugging)
		  printf("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));
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
	    printf("MAX_TIMEOUT threshold (%d) reached, giving up on host %s (%s).  Use -N to skip this check.\n", MAX_TIMEOUTS, target->name, inet_ntoa(target->host));		
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

/* gawd, my next project will be in c++ so I don't have to deal with
   this crap ... simple linked list implementation */
int addport(portlist *ports, unsigned short portno, unsigned short protocol,
	    char *owner) {
struct port *current, *tmp;
int len;

if (*ports) {
  current = *ports;
  /* case 1: we add to the front of the list */
  if (portno <= current->portno) {
    if (current->portno == portno && current->proto == protocol) {
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


void *safe_malloc(int size)
{
  void *mymem;
  if (size < 0)
    fatal("Tried to malloc negative amount of memmory!!!");
  if ((mymem = malloc(size)) == NULL)
    fatal("Malloc Failed! Probably out of space.");
  return mymem;
}

void printandfreeports(portlist ports) {
  char protocol[4];
  struct servent *service;
  port *current = ports, *tmp;
  
  printf("Port Number  Protocol  Service");
  printf("%s", (o.identscan)?"         Owner\n":"\n");
  while(current != NULL) {
    strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
    service = getservbyport(htons(current->portno), protocol);
    printf("%-13d%-11s%-16s%s\n", current->portno, protocol,
	   (service)? service->s_name: "unknown",
	   (current->owner)? current->owner : "");
    tmp = current;
    current = current->next;
    if (tmp->owner) free(tmp->owner);
    free(tmp);
  }
  printf("\n");
}

/* This is the version of udp_scan that uses raw ICMP sockets and requires 
   root priviliges.*/
portlist udp_scan(struct hoststruct *target, unsigned short *portarray) {
  int icmpsock, udpsock, tmp, done=0, retries, bytes = 0, res,  num_out = 0;
  int i=0,j=0, k=0, icmperrlimittime, max_tries = UDP_MAX_PORT_RETRIES;
  unsigned short *outports = safe_malloc(sizeof(unsigned short) * o.max_sockets);
  unsigned short *numtries = safe_malloc(sizeof(unsigned short) * o.max_sockets);
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
	addport(&target->ports, outports[i], IPPROTO_UDP, NULL);
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

/* This fucntion is nonsens.  I wrote it all, really optimized etc.  Then
   found out that many hosts limit the rate at which they send icmp errors :(
   I will probably totally rewrite it to be much simpler at some point.  For
   now I won't worry about it since it isn't a very important functions (UDP
   is lame, plus there is already a much better function for people who 
   are r00t */
portlist lamer_udp_scan(struct hoststruct *target, unsigned short *portarray) {
int sockaddr_in_size = sizeof(struct sockaddr_in),i=0,j=0,k=0, bytes;
int *sockets = safe_malloc(sizeof(int) * o.max_sockets);
int *trynum = safe_malloc(sizeof(int) * o.max_sockets);
unsigned short *portno = safe_malloc(sizeof(unsigned short) * o.max_sockets);
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
		  addport(&target->ports, portno[i], IPPROTO_UDP, NULL); 
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
        addport(&target->ports,portno[i], IPPROTO_UDP, NULL);
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


int getsourceip(struct hoststruct *target) {
  int sd;
  struct sockaddr_in sock;
  int socklen = sizeof(struct sockaddr_in);
  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {perror("Socket troubles"); return 0;}
  sock.sin_family = AF_INET;
  sock.sin_addr = target->host;
  sock.sin_port = htons(MAGIC_PORT);
  if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
    { perror("UDP connect()");
    close(sd);
    return 0;
    }
  bzero( (char * )&sock, sizeof(struct sockaddr_in));
  if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
    perror("getsockname");
    close(sd);
    return 0;
  }
  if (sock.sin_addr.s_addr == target->host.s_addr) {
    /* could be valid, but only if we are sending to ourself */
    /* Its probably an error so I'm returning 0 */
    /* Linux has the very bad habit of doing this */
    close(sd);
    return 0;
  }
  if (sock.sin_addr.s_addr) {
    target->source_ip = sock.sin_addr;
    if (o.debugging) printf("getsourceip: %s routes through interface %s\n", inet_ntoa(target->host), inet_ntoa(target->source_ip));
  }
  else {
    if (o.debugging) printf("failted to obtain your IP address\n");
    close(sd);
    return 0;
  }
  close(sd);
  return 1;
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
sock.sin_port = htons(MAGIC_PORT);

gettimeofday(&begin, NULL);
if ((res = connect(sd, (struct sockaddr *) &sock, 
		   sizeof(struct sockaddr_in))) != -1)
  printf("You might want to change MAGIC_PORT in the include file, it seems to be listening on the target host!\n");
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
struct sockaddr_in sock;
int res;

if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
  {perror("Socket troubles"); exit(1);}

sock.sin_family = AF_INET;
sock.sin_addr.s_addr = target.s_addr;
sock.sin_port = htons(113); /*should use getservbyname(3), yeah, yeah */
res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
close(sd);
if (res < 0 ) {
  if (o.debugging || o.verbose) printf("identd port not active\n");
  return 0;
}
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

portlist syn_scan(struct hoststruct *target, unsigned short *portarray) {
int i=0, j=0, received, bytes, starttime;
struct sockaddr_in from;
int fromsize = sizeof(struct sockaddr_in);
int *sockets = safe_malloc(sizeof(int) * o.max_sockets);
struct timeval tv,start,end;
unsigned int elapsed_time;
char packet[65535];
struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
fd_set fd_read, fd_write;
int res;
struct hostent *myhostent;
char myname[MAXHOSTNAMELEN + 1];
short magic_port_NBO;
int packets_out;

magic_port_NBO = htons(MAGIC_PORT);

FD_ZERO(&fd_read);
FD_ZERO(&fd_write);

if ((received = socket(AF_INET, SOCK_RAW,  IPPROTO_TCP)) < 0 )
  perror("socket troubles in syn_scan");
/*if ((received = socket(AF_INET, SOCK_PACKET,  htons(ETH_P_IP))) < 0 )
  perror("socket troubles in syn_scan");*/
unblock_socket(received);
max_rcvbuf(received); /* does nothing for linux */
FD_SET(received, &fd_read);

if (!target->source_ip.s_addr) {
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is fucked up.\n"); 
  memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
  if (o.debugging || o.verbose)
    printf("We skillfully deduced that your address is %s\n", 
	   inet_ntoa(target->source_ip));
}

starttime = time(NULL);

do {
  for(i=0; i < o.max_sockets && portarray[j]; i++) {
    if ((sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
      perror("socket trobles in syn_scan");
    else {
      if (o.fragscan)
	send_small_fragz(sockets[i], &target->source_ip, &target->host, MAGIC_PORT,
			 portarray[j++], TH_SYN);
      else send_tcp_raw(sockets[i], &target->source_ip , &target->host, MAGIC_PORT, 
			portarray[j++],0,0,TH_SYN,0,0,0);
      usleep(10000);
    }
  }
  gettimeofday(&start, NULL);
  packets_out = i;
  do {
    tv.tv_sec = o.ptime;
    tv.tv_usec = 0;
    FD_SET(received, &fd_read);
    if ((res = select(received + 1, &fd_read, NULL, NULL, &tv)) < 0)
      perror("select problems in syn_scan");
    else /*if (res > 0)*/ {
      while  ((bytes = recvfrom(received, packet, 65535, 0, 
				(struct sockaddr *)&from, &fromsize)) > 0 ) {

	if (ip->ip_src.s_addr == target->host.s_addr && tcp->th_sport != magic_port_NBO
	    && tcp->th_dport == magic_port_NBO) {

	  packets_out--;
	  if (tcp->th_flags & TH_RST) {
	    if (o.debugging > 1) printf("Nothing open on port %d\n",
				      ntohs(tcp->th_sport));
	  }
	  else /*if (tcp->th_flags & TH_SYN && tcp->th_flags & TH_ACK)*/ {
	    if (o.debugging || o.verbose) {	  
	      printf("Possible catch on port %d!  Here it is:\n", 
		     ntohs(tcp->th_sport));
	      readtcppacket(packet,1);
	    }
	    addport(&target->ports, ntohs(tcp->th_sport), IPPROTO_TCP, NULL); 	    
	  }
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
close(received);
return target->ports;
}


int send_tcp_raw( int sd, struct in_addr *source, 
		  struct in_addr *victim, unsigned short sport, 
		  unsigned short dport, unsigned long seq,
		  unsigned long ack, unsigned char flags,
		  unsigned short window, char *data, 
		  unsigned short datalen) 
{

struct pseudo_header { 
  /*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
  unsigned long s_addy;
  unsigned long d_addr;
  char zer0;
  unsigned char protocol;
  unsigned short length;
};

char *packet = safe_malloc(sizeof(struct ip) + sizeof(struct tcphdr) + datalen);
struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
struct pseudo_header *pseudo =  (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header)); 

 /*With these placement we get data and some field alignment so we aren't
   wasting too much in computing the checksum */
int res;
struct sockaddr_in sock;
char myname[MAXHOSTNAMELEN + 1];
struct hostent *myhostent;
int source_malloced = 0;

/* check that required fields are there and not too silly */
if ( !victim || !sport || !dport || sd < 0) {
  fprintf(stderr, "send_tcp_raw: One or more of your parameters suck!\n");
  return -1;
}

/* if they didn't give a source address, fill in our first address */
if (!source) {
  source_malloced = 1;
  source = safe_malloc(sizeof(struct in_addr));
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is fucked up.\n"); 
  memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
  if (o.debugging > 1)
    printf("We skillfully deduced that your address is %s\n", 
	   inet_ntoa(*source));
}


/*do we even have to fill out this damn thing?  This is a raw packet, 
  after all */
sock.sin_family = AF_INET;
sock.sin_port = htons(dport);
sock.sin_addr.s_addr = victim->s_addr;


bzero((char *) packet, sizeof(struct ip) + sizeof(struct tcphdr));

pseudo->s_addy = source->s_addr;
pseudo->d_addr = victim->s_addr;
pseudo->protocol = IPPROTO_TCP;
pseudo->length = htons(sizeof(struct tcphdr) + datalen);

tcp->th_sport = htons(sport);
tcp->th_dport = htons(dport);
if (seq)
  tcp->th_seq = htonl(seq);
else if (flags & TH_SYN) tcp->th_seq = rand() + rand();

if (ack)
  tcp->th_ack = htonl(ack);
/*else if (flags & TH_ACK)
  tcp->th_ack = rand() + rand();*/

tcp->th_off = 5 /*words*/;
tcp->th_flags = flags;

if (window)
  tcp->th_win = htons(window);
else tcp->th_win = htons(2048); /* Who cares */

tcp->th_sum = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) + 
		       sizeof(struct pseudo_header) + datalen);

/* Now for the ip header */

bzero(packet, sizeof(struct ip)); 
ip->ip_v = 4;
ip->ip_hl = 5;
ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + datalen);
ip->ip_id = rand();
ip->ip_ttl = 255;
ip->ip_p = IPPROTO_TCP;
ip->ip_src.s_addr = source->s_addr;
ip->ip_dst.s_addr= victim->s_addr;
ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));

 /* We should probably copy the data over too */
if (data)
  memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), data, datalen);

if (o.debugging > 1) {
printf("Raw TCP packet creation completed!  Here it is:\n");

readtcppacket(packet,ntohs(ip->ip_len));
}
if (o.debugging > 1) 

  printf("\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n",
	 sd, ntohs(ip->ip_len), inet_ntoa(*victim),
	 sizeof(struct sockaddr_in));
if ((res = sendto(sd, packet, ntohs(ip->ip_len), 0,
		  (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)
  {
    perror("sendto in send_tcp_raw");
    if (source_malloced) free(source);
    return -1;
  }
if (o.debugging > 1) printf("successfully sent %d bytes of raw_tcp!\n", res);

if (source_malloced) free(source);
return res;
}

/* A simple program I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readtcppacket(char *packet, int readdata) {

struct ip *ip = (struct ip *) packet;
struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
char *data = packet +  sizeof(struct ip) + sizeof(struct tcphdr);
int tot_len;
struct in_addr bullshit, bullshit2;
char sourcehost[16];
int i;
int realfrag = 0;

if (!packet) {
  fprintf(stderr, "readtcppacket: packet is NULL!\n");
  return -1;
    }

bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
/* this is gay */
realfrag = ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */;
tot_len = ntohs(ip->ip_len);
strncpy(sourcehost, inet_ntoa(bullshit), 16);
i =  4 * (ntohs(ip->ip_hl) + ntohs(tcp->th_off));
if (ip->ip_p== IPPROTO_TCP) {
  if (realfrag) 
    printf("Packet is fragmented, offset field: %u\n", realfrag);
  else {
    printf("TCP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, 
	   ntohs(tcp->th_sport), inet_ntoa(bullshit2), 
	   ntohs(tcp->th_dport), tot_len);
    printf("Flags: ");
    if (!tcp->th_flags) printf("(none)");
    if (tcp->th_flags & TH_RST) printf("RST ");
    if (tcp->th_flags & TH_SYN) printf("SYN ");
    if (tcp->th_flags & TH_ACK) printf("ACK ");
    if (tcp->th_flags & TH_PUSH) printf("PSH ");
    if (tcp->th_flags & TH_FIN) printf("FIN ");
    if (tcp->th_flags & TH_URG) printf("URG ");
    printf("\n");

    printf("ttl: %hi ", ip->ip_ttl);

    if (tcp->th_flags & (TH_SYN | TH_ACK)) printf("Seq: %lu\tAck: %lu\n", 
						  (unsigned long) ntohl(tcp->th_seq), (unsigned long) ntohl(tcp->th_ack));
    else if (tcp->th_flags & TH_SYN) printf("Seq: %lu\n", (unsigned long) ntohl(tcp->th_seq));
    else if (tcp->th_flags & TH_ACK) printf("Ack: %lu\n", (unsigned long) ntohl(tcp->th_ack));
  }
}
if (readdata && i < tot_len) {
printf("Data portion:\n");
while(i < tot_len)  printf("%2X%c", data[i], (++i%16)? ' ' : '\n');
printf("\n");
}
return 0;
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
		     int sport, int dport, int flags) {

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
tcp->th_seq = rand() + rand();

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
ip->ip_len = htons(sizeof(struct ip) + 16);
id = ip->ip_id = rand();
ip->ip_off = htons(MORE_FRAGMENTS);
ip->ip_ttl = 255;
ip->ip_p = IPPROTO_TCP;
ip->ip_src.s_addr = source->s_addr;
ip->ip_dst.s_addr = victim->s_addr;
ip->ip_sum= in_cksum((unsigned short *)ip, sizeof(struct ip));

if (o.debugging > 1) {
  printf("Raw TCP packet fragment #1 creation completed!  Here it is:\n");
  hdump(packet,20);
}
if (o.debugging > 1) 
  printf("\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n",
	 sd, ntohs(ip->ip_len), inet_ntoa(*victim),
	 (int) sizeof(struct sockaddr_in));
if ((res = sendto(sd, packet, ntohs(ip->ip_len), 0, 
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
ip2->ip_len = htons(sizeof(struct ip) + 4); /* the rest of our TCP packet */
ip2->ip_id = id;
ip2->ip_off = htons(2);
ip2->ip_ttl = 255;
ip2->ip_p = IPPROTO_TCP;
ip2->ip_src.s_addr = source->s_addr;
ip2->ip_dst.s_addr= victim->s_addr;
ip2->ip_sum = in_cksum((unsigned short *)ip2, sizeof(struct ip));

if (o.debugging > 1) {
  printf("Raw TCP packet fragment creation completed!  Here it is:\n");
  hdump(packet,20);
}
if (o.debugging > 1) 

  printf("\nTrying sendto(%d , ip2, %d, 0 , %s , %d)\n", sd, 
	 ntohs(ip2->ip_len), inet_ntoa(*victim), (int) sizeof(struct sockaddr_in));
if ((res = sendto(sd, (void *)ip2, ntohs(ip2->ip_len), 0, 
		  (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)

  {
    perror("sendto in send_tcp_raw");
    return -1;
  }
return 1;
}

/* Hex dump */
void hdump(unsigned char *packet, int len) {
unsigned int i=0, j=0;

printf("Here it is:\n");

for(i=0; i < len; i++){
  j = (unsigned) (packet[i]);
  printf("%-2X ", j);
  if (!((i+1)%16))
    printf("\n");
  else if (!((i+1)%4))
    printf("  ");
}
printf("\n");
}


portlist fin_scan(struct hoststruct *target, unsigned short *portarray) {

int rawsd, tcpsd;
int done = 0, badport, starttime, someleft, i, j=0, retries=2;
int waiting_period = retries, sockaddr_in_size = sizeof(struct sockaddr_in);
int bytes, dupesinarow = 0;
unsigned long timeout;
struct hostent *myhostent;
char response[65535], myname[513];

struct ip *ip = (struct ip *) response;

struct tcphdr *tcp;
unsigned short *portno = safe_malloc(sizeof(unsigned short) * o.max_sockets);
unsigned short *trynum = safe_malloc(sizeof(unsigned short) * o.max_sockets);
struct sockaddr_in stranger;


timeout = (target->rtt)? target->rtt + 10000 : 1e5;

bzero(&stranger, sockaddr_in_size);
bzero(portno, o.max_sockets * sizeof(unsigned short));
bzero(trynum, o.max_sockets * sizeof(unsigned short));
starttime = time(NULL);


if (o.debugging || o.verbose)
  printf("Initiating FIN stealth scan against %s (%s), sleep delay: %ld useconds\n", target->name, inet_ntoa(target->host), timeout);

if (!target->source_ip.s_addr) {
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is fucked up.\n"); 
  memcpy(&target->source_ip, myhostent->h_addr_list[0], sizeof(struct in_addr));
  if (o.debugging || o.verbose) 
    printf("We skillfully deduced that your address is %s\n",
	   inet_ntoa(target->source_ip));
}

if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
  perror("socket trobles in fin_scan");

if ((tcpsd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 )
  perror("socket trobles in fin_scan");

unblock_socket(tcpsd);
while(!done) {
  for(i=0; i <  o.max_sockets; i++) {
    if (!portno[i] && portarray[j]) {
      portno[i] = portarray[j++];
    }
    if (portno[i]) {
    if (o.fragscan)
      send_small_fragz(rawsd, &target->source_ip, &target->host, MAGIC_PORT, portno[i], TH_FIN);
    else send_tcp_raw(rawsd, &target->source_ip , &target->host, MAGIC_PORT, 
		      portno[i], 0, 0, TH_FIN, 0, 0, 0);
    usleep(10000); /* *WE* normally do not need this, but the target 
		      lamer often does */
    }
  }

  usleep(timeout);
  dupesinarow = 0;
  while ((bytes = recvfrom(tcpsd, response, 65535, 0, (struct sockaddr *)
			   &stranger, &sockaddr_in_size)) > 0) 

    if (ip->ip_src.s_addr == target->host.s_addr) {
      tcp = (struct tcphdr *) (response + 4 * ip->ip_hl);

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
	addport(&target->ports, portno[i], IPPROTO_TCP, NULL);
    send_tcp_raw( rawsd, &target->source_ip, &target->host, MAGIC_PORT, portno[i], 0, 0, 
		  TH_FIN, 0, 0, 0);
    portno[i] = trynum[i] = 0;
      }
      else someleft = 1;
    }  

  if (!portarray[j] && (!someleft || --waiting_period <= 0)) done++;
}

if (o.debugging || o.verbose)
  printf("The TCP stealth FIN scan took %ld seconds to scan %d ports.\n", 
	 (long) time(NULL) - starttime, o.numports);
close(tcpsd);
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

#ifndef HAVE_SNPRINTF
sprintf(targetstr, "%d,%d,%d,%d,0,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));
#else
  snprintf(targetstr, 20, "%d,%d,%d,%d,0,", UC(t[0]), UC(t[1]), UC(t[2]), UC(t[3]));
#endif

starttime = time(NULL);
if (o.verbose || o.debugging)
  printf("Initiating TCP ftp bounce scan against %s (%s)\n",
	 target->name,  inet_ntoa(target->host));
for(i=0; portarray[i]; i++) {
#ifndef HAVE_SNPRINTF
  sprintf(command, "PORT %s%i\r\n", targetstr, portarray[i]);
#else
  snprintf(command, 512, "PORT %s%i\r\n", targetstr, portarray[i]);
#endif
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
	    addport(&target->ports, portarray[i], IPPROTO_TCP, NULL);
	    if (recvbuf[0] == '1') {
	    res = recvtime(sd, recvbuf, 2048,5);
	    recvbuf[res] = '\0';
	    if ((res > 0) && o.debugging) printf("nxt line: %s", recvbuf);
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

