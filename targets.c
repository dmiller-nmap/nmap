#include "targets.h"

extern struct ops o;

struct hoststruct *nexthost(char *hostexp, int lookahead, int pingtimeout) {
static int lastindex = -1;
static struct hoststruct *hostbatch  = NULL;
char *device;
int numhosts = 0;
static int targets_valid = 0;
static char *lastexp = NULL;
static int i;
static struct targets targets;
static char *lasthostexp = NULL;
if (!hostbatch) hostbatch = safe_malloc((lookahead + 1) * sizeof(struct hoststruct));

if (!lastexp) {
  lastexp = safe_malloc(1024);
  *lastexp = '\0';
}

if (strcmp(lastexp, hostexp)) {
 /* New expression -- reinit everything */
  targets_valid = 0;
  lastindex = -1;
  strncpy(lastexp, hostexp, 1024);
  lastexp[1023] = '\0';
}

if (!targets_valid) {
  if (!parse_targets(&targets, hostexp)) 
    return NULL;
  targets_valid = 1;
  lasthostexp = hostexp;
}
if (lastindex >= 0 && lastindex < lookahead  && hostbatch[lastindex + 1].host.s_addr)  
  return &hostbatch[++lastindex];

/* OK, we need to refresh our target array */

lastindex = 0;
bzero((char *) hostbatch, (lookahead + 1) * sizeof(struct hoststruct));
do {
  if (targets.maskformat) {
    for(i = 0; i < lookahead && targets.currentaddr.s_addr <= targets.end.s_addr; i++) {
      if (!o.allowall && ((!(targets.currentaddr.s_addr % 256) 
			 || targets.currentaddr.s_addr % 256 == 255)))
	{
	  struct in_addr iii;
	  iii.s_addr = htonl(targets.currentaddr.s_addr);
	  printf("Skipping host %s because no '-A' and IGNORE_ZERO_AND_255_HOSTS is set in the source.\n", inet_ntoa(iii));
	  targets.currentaddr.s_addr++;
	  i--;
	}
      else
	hostbatch[i].host.s_addr = htonl(targets.currentaddr.s_addr++);
    }
    hostbatch[i].host.s_addr = 0;  
  }
  else {
    for(i=0; targets.current[0] <= targets.last[0] && i < lookahead ;) {
      for(; targets.current[1] <= targets.last[1] && i < lookahead ;) {
	for(; targets.current[2] <= targets.last[2] && i < lookahead ;) {	
	  for(; targets.current[3] <= targets.last[3]  && i < lookahead ; targets.current[3]++) {
	    if (o.debugging > 1) 
	      printf("doing %d.%d.%d.%d = %d.%d.%d.%d\n", targets.current[0], targets.current[1], targets.current[2], targets.current[3], targets.addresses[0][targets.current[0]],targets.addresses[1][targets.current[1]],targets.addresses[2][targets.current[2]],targets.addresses[3][targets.current[3]]);
	    hostbatch[i++].host.s_addr = htonl(targets.addresses[0][targets.current[0]] << 24 | targets.addresses[1][targets.current[1]] << 16 |
					       targets.addresses[2][targets.current[2]] << 8 | targets.addresses[3][targets.current[3]]);
	    if (!o.allowall && (!(ntohl(hostbatch[i - 1].host.s_addr) % 256) || ntohl(hostbatch[i - 1].host.s_addr) % 256 == 255))
	      {
		printf("Skipping host %s because no '-A' and IGNORE_ZERO_AND_255_HOSTS is set in the source.\n", inet_ntoa(hostbatch[i - 1].host));
		i--;
	      }
	  }
	  if (i < lookahead && targets.current[3] > targets.last[3]) {
	    targets.current[3] = 0;
	    targets.current[2]++;
	  }
	}
	if (i < lookahead && targets.current[2] > targets.last[2]) {
	  targets.current[2] = 0;
	  targets.current[1]++;
	}
      }
      if (i < lookahead && targets.current[1] > targets.last[1]) {
	targets.current[1] = 0;
	targets.current[0]++;
      }
    }
    hostbatch[i].host.s_addr = 0;
  }

  numhosts = i;
  for(i=0; i < numhosts; i++) {  
    /* If we were given an IP address & device, insert it now */
    if (o.source) {
      memcpy((char *)&hostbatch[i].source_ip,(char *) o.source, 
	     sizeof(struct in_addr));
      strcpy(hostbatch[i].device, o.device);
    }
    /* If we still do not have a source IP, we create one IFF
       1) We are r00t AND
       2) We are doing tcp pingscan OR
       3) We are doing NO scan AND we are doing a raw-mode portscan or osscan*/
    else {
      if (o.isr00t && ((o.pingtype & PINGTYPE_TCP) || (o.pingtype == PINGTYPE_NONE && (o.synscan || o.finscan || o.xmasscan || o.nullscan || o.maimonscan || o.udpscan || o.osscan )))) {
	device = routethrough(&(hostbatch[i].host), &(hostbatch[i].source_ip));
	if (!device) {
	  if (o.pingtype == PINGTYPE_NONE) {
	    fatal("Could not determine what interface to route packets through, run again with -e <device>");
	  } else {
	    error("WARNING:  Could not determine what interface to route packets through to %s, changing ping scantype to ICMP only", inet_ntoa(hostbatch[i].host));
	    o.pingtype = PINGTYPE_ICMP;
	  }
	} else {
	  strcpy(hostbatch[i].device, device);
	}
      }
    }
  }

if ((o.pingtype == PINGTYPE_ICMP) || (hostbatch[0].host.s_addr && (o.pingtype != PINGTYPE_NONE))) 
  massping(hostbatch, i, pingtimeout);
else for(i=0; hostbatch[i].host.s_addr; i++)  {
  hostbatch[i].to.srtt = -1;
  hostbatch[i].to.rttvar = -1;
  hostbatch[i].to.timeout = 6000000;
  hostbatch[i].flags |= HOST_UP; /*hostbatch[i].up = 1;*/
}

} while(i != 0 && !hostbatch[0].host.s_addr);  /* Loop now unneeded */
return &hostbatch[0];
}


int parse_targets(struct targets *targets, char *h) {
int i=0,j=0,k=0;
int start, end;
char *r,*s, *target_net;
char *addy[5];
char *hostexp = strdup(h);
struct hostent *target;
unsigned long longtmp;
int namedhost = 0;
/*struct in_addr current_in;*/
addy[0] = addy[1] = addy[2] = addy[3] = addy[4] = NULL;
addy[0] = r = hostexp;
/* First we break the expression up into the four parts of the IP address
   + the optional '/mask' */
target_net = strtok(hostexp, "/");
targets->netmask = (int) (s = strtok(NULL,""))? atoi(s) : 32;
if (targets->netmask < 0 || targets->netmask > 32) {
  printf("Illegal netmask value (%d), must be /0 - /32 .  Assuming /32 (one host)\n", targets->netmask);
  targets->netmask = 32;
}
for(i=0; *(hostexp + i); i++) 
  if (isupper((int) *(hostexp +i)) || islower((int) *(hostexp +i))) {
  namedhost = 1;
  break;
}
if (targets->netmask != 32 || namedhost) {
  targets->maskformat = 1;
 if (!inet_aton(target_net, &(targets->start))) {
    if ((target = gethostbyname(target_net)))
      memcpy(&(targets->start), target->h_addr_list[0], sizeof(struct in_addr));
    else {
      fprintf(stderr, "Failed to resolve given hostname/IP: %s.  Note that you can't use '/mask' AND '[1-4,7,100-]' style IP ranges\n", target_net);
      free(hostexp);
      return 0;
    }
 } 
 longtmp = ntohl(targets->start.s_addr);
 targets->start.s_addr = longtmp & (unsigned long) (0 - (1<<(32 - targets->netmask)));
 targets->end.s_addr = longtmp | (unsigned long)  ((1<<(32 - targets->netmask)) - 1);
 targets->currentaddr = targets->start;
 if (targets->start.s_addr <= targets->end.s_addr) { free(hostexp); return 1; }
 fprintf(stderr, "Host specification invalid");
 free(hostexp);
 return 0;
}
else {
  i=0;
  targets->maskformat = 0;
  while(*++r) {
    if (*r == '.' && ++i < 4) {
      *r = '\0';
      addy[i] = r + 1;
    }
    else if (*r == '[') {
      *r = '\0';
      addy[i]++;
    }
    else if (*r == ']') *r = '\0';
    /*else if ((*r == '/' || *r == '\\') && i == 3) {
     *r = '\0';
     addy[4] = r + 1;
     }*/
    else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int)*r)) fatal("Invalid character in  host specification.");
  }
  if (i != 3) fatal("Target host specification is illegal.");
  
  for(i=0; i < 4; i++) {
    j=0;
    while((s = strchr(addy[i],','))) {
      *s = '\0';
      if (*addy[i] == '*') { start = 0; end = 255; } 
      else if (*addy[i] == '-') {
	start = 0;
	if (!addy[i] + 1) end = 255;
	else end = atoi(addy[i]+ 1);
      }
      else {
	start = end = atoi(addy[i]);
	if ((r = strchr(addy[i],'-')) && *(r+1) ) end = atoi(r + 1);
	else if (r && !*(r+1)) end = 255;
      }
      if (o.debugging)
	printf("The first host is %d, and the last one is %d\n", start, end);
      if (start < 0 || start > end) fatal("Your host specifications are illegal!");
      for(k=start; k <= end; k++)
	targets->addresses[i][j++] = k;
      addy[i] = s + 1;
    }
    if (*addy[i] == '*') { start = 0; end = 255; } 
    else if (*addy[i] == '-') {
      start = 0;
      if (!addy[i] + 1) end = 255;
      else end = atoi(addy[i]+ 1);
    }
    else {
      start = end = atoi(addy[i]);
      if ((r =  strchr(addy[i],'-')) && *(r+1) ) end = atoi(r+1);
      else if (r && !*(r+1)) end = 255;
    }
    if (o.debugging)
      printf("The first host is %d, and the last one is %d\n", start, end);
    if (start < 0 || start > end) fatal("Your host specifications are illegal!");
    if (j + (end - start) > 255) fatal("Your host specifications are illegal!");
    for(k=start; k <= end; k++) 
      targets->addresses[i][j++] = k;
    targets->last[i] = j - 1;
    
  }
}
  bzero((char *)targets->current, 4);
  free(hostexp);
  return 1;
}



void massping(struct hoststruct *hostbatch, int num_hosts, int pingtimeout) {
static struct timeout_info to = { 0,0,0};
static int gsize = LOOKAHEAD;
int hostnum;
struct pingtune pt;
struct scanstats ss;
struct timeval begin_select;
struct pingtech ptech;
struct tcpqueryinfo tqi;
int max_block_size = 150;
struct ppkt {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short seq;
};
unsigned int elapsed_time;
int blockinc;
int sd_blocking = 1;
struct sockaddr_in sock;
short seq = 0;
int sd, rawsd, rawpingsd;
struct timeval *time;
struct timeval start, end, t1, t2;
unsigned short id;
pcap_t *pd = NULL;
struct bpf_program fcode;
char err0r[PCAP_ERRBUF_SIZE];
char filter[512];
unsigned int localnet, netmask;

bzero((char *)&ptech, sizeof(struct pingtech));

bzero((char *) &pt, sizeof(struct pingtune)); 
pt.up_this_block = 0;
pt.block_unaccounted = LOOKAHEAD;
pt.discardtimesbefore = 0;
pt.down_this_block = 0;
pt.num_responses = 0;
pt.max_tries = 5; /* Maximum number of tries for a block */
pt.group_size = gsize;
pt.group_start = 0;
pt.block_tries = 0; /* How many tries this block has gone through */

/* What kind of scans are we doing? */
if ((o.pingtype & PINGTYPE_ICMP) &&  hostbatch[0].source_ip.s_addr) 
  ptech.rawicmpscan = 1;
else if (o.pingtype & PINGTYPE_ICMP) 
  ptech.icmpscan = 1;
if (o.pingtype & PINGTYPE_TCP) {
  if (o.isr00t)
    ptech.rawtcpscan = 1;
  else ptech.connecttcpscan = 1;
}

time = safe_malloc(sizeof(struct timeval) * ((pt.max_tries) * num_hosts));
id = (unsigned short) rand();

if (ptech.connecttcpscan) 
  max_block_size = MIN(150, o.max_sockets);


bzero((char *)&tqi, sizeof(tqi));
if (ptech.connecttcpscan) {
  tqi.sockets = safe_malloc(sizeof(int) * (pt.max_tries) * num_hosts);
  memset(tqi.sockets, 255, sizeof(int) * (pt.max_tries) * num_hosts);
  FD_ZERO(&(tqi.fds_r));
  FD_ZERO(&(tqi.fds_w));
  FD_ZERO(&(tqi.fds_x));
  tqi.sockets_out = 0;
  tqi.maxsd = 0;
}

if (ptech.icmpscan) {
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sd < 0) pfatal("Socket trouble in massping"); 
  unblock_socket(sd);
  sd_blocking = 0;
  if (num_hosts > 10)
    max_rcvbuf(sd);
  if (o.allowall) broadcast_socket(sd);
} else sd = -1;


/* if to timeout structure hasn't been initialized yet */
if (!to.srtt && !to.rttvar && !to.timeout) {
  /*  to.srtt = 800000;
      to.rttvar = 500000; */ /* we will init these when we get real data */
  to.timeout = pingtimeout * 1e6;
} 

/* Init our raw socket */
if (o.numdecoys > 1 || ptech.rawtcpscan || ptech.rawicmpscan) {
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in massping");
  if (o.allowall) broadcast_socket(rawsd);

  if ((rawpingsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in massping");
  if (o.allowall) broadcast_socket(rawpingsd);
}
else rawsd = -1; 

if (ptech.rawicmpscan || ptech.rawtcpscan) {
  /* we need a pcap descript0r! */
  /* MAX snaplen needed = 
     24 bytes max link_layer header
     64 bytes max IPhdr
     16 bytes of the TCP header
     ---
   = 104 byte snaplen */
  
  if (!(pd = pcap_open_live(hostbatch[0].device, 104,  (o.spoofsource)? 1 : 0, 20, err0r)))
    fatal("pcap_open_live: %s", err0r);

  if (pcap_lookupnet(hostbatch[0].device, &localnet, &netmask, err0r) < 0)
    fatal("Failed to lookup device subnet/netmask: %s", err0r);
  sprintf(filter, "(icmp and dst host %s) or (tcp and dst host %s and ( dst port %d or dst port %d or dst port %d or dst port %d or dst port %d))", 
	  inet_ntoa(hostbatch[0].source_ip),inet_ntoa(hostbatch[0].source_ip),
	  o.magic_port , o.magic_port + 1, o.magic_port + 2, o.magic_port + 3, 
	  o.magic_port + 4);

  /* Due to apparent bug in libpcap */
  if (hostbatch[0].source_ip.s_addr == htonl(0x7F000001))
    filter[0] = '\0';

  if (o.debugging)
    printf("Packet capture filter: %s\n", filter);
  if (pcap_compile(pd, &fcode, filter, 0, netmask) < 0)
    fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
  if (pcap_setfilter(pd, &fcode) < 0 )
    fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
  
}

 if (ptech.rawicmpscan + ptech.icmpscan + ptech.connecttcpscan +
     ptech.rawtcpscan == 1)
   blockinc = 8;
 else blockinc = 5;

bzero((char *)&sock,sizeof(struct sockaddr_in));
gettimeofday(&start, NULL);

 pt.group_end = MIN(pt.group_start + pt.group_size -1, num_hosts -1);
 
 while(pt.group_start < num_hosts) { /* while we have hosts left to scan */
   do { /* one block */
     pt.discardtimesbefore = -1;
     pt.up_this_block = 0;
     pt.down_this_block = 0;
     pt.block_unaccounted = 0;
     for(hostnum=pt.group_start; hostnum <= pt.group_end; hostnum++) {      
       /* If (we don't know whether the host is up yet) ... */
       if (!(hostbatch[hostnum].flags & HOST_UP) && !hostbatch[hostnum].wierd_responses && !(hostbatch[hostnum].flags & HOST_DOWN)) {  
	 /* Send a ping packet to it */
	 seq = hostnum * pt.max_tries + pt.block_tries;
	 if (ptech.icmpscan && !sd_blocking) { 
	   block_socket(sd); sd_blocking = 1; 
	 }
	 if (ptech.icmpscan || ptech.rawicmpscan)
	   sendpingquery(sd, rawpingsd, &hostbatch[hostnum],  
			 seq, id, &ss, time, ptech);
       
	 if (ptech.rawtcpscan) {
	   sendrawtcppingquery(rawsd, &hostbatch[hostnum],  seq, time, &pt);
	 }
	 else if (ptech.connecttcpscan) {
	   sendconnecttcpquery(hostbatch, &tqi, &hostbatch[hostnum], seq, time, &pt, &to);
	 }
	 pt.block_unaccounted++;
	 gettimeofday(&t2, NULL);
	 if (TIMEVAL_SUBTRACT(t2,time[seq]) > 1000000) {
	   pt.discardtimesbefore = hostnum;
	   if (o.debugging) 
	     printf("Huge send delay: %lu microseconds\n", (unsigned long) TIMEVAL_SUBTRACT(t2,t1));
	 }
       }
     } /* for() loop */
     /* OK, we have sent our ping packets ... now we wait for responses */
     gettimeofday(&begin_select, NULL);
     do {
       if (ptech.icmpscan && sd_blocking ) { 
	 unblock_socket(sd); sd_blocking = 0; 
       }
       if(ptech.icmpscan || ptech.rawicmpscan || ptech.rawtcpscan) {       
	 get_ping_results(sd, pd, hostbatch, time, &pt, &to, id, &ptech);
       }
       if (ptech.connecttcpscan) {
	 get_connecttcpscan_results(&tqi, hostbatch, time, &pt, &to);
       }
       gettimeofday(&end, NULL);
       elapsed_time = TIMEVAL_SUBTRACT(end, begin_select);
     } while( elapsed_time < to.timeout);
     /* try again if a new box was found but some are still unaccounted for and
	we haven't run out of retries.  Also retry if the block is extremely
        small.
     */
     pt.dropthistry = 0;
     pt.block_tries++;
   } while ((pt.up_this_block > 0 || pt.group_end - pt.group_start <= 3) && pt.block_unaccounted > 0 && pt.block_tries < pt.max_tries);

   if (o.debugging)
     printf("Finished block: srtt: %d rttvar: %d timeout: %d block_tries: %d up_this_block: %d down_this_block: %d group_sz: %d\n", to.srtt, to.rttvar, to.timeout, pt.block_tries, pt.up_this_block, pt.down_this_block, pt.group_end - pt.group_start + 1);

   if ((pt.block_tries == 1) || (pt.block_tries == 2 && pt.up_this_block == 0 && pt.down_this_block == 0)) 
     /* Then it did not miss any hosts (that we know of)*/
     if (ptech.rawicmpscan + ptech.icmpscan + ptech.connecttcpscan +
	 ptech.rawtcpscan == 1)
       pt.group_size = MIN(pt.group_size + blockinc, max_block_size);
   
   /* Move to next block */
   pt.block_tries = 0;
   pt.group_start = pt.group_end +1;
   pt.group_end = MIN(pt.group_start + pt.group_size -1, num_hosts -1);
   /*   pt.block_unaccounted = pt.group_end - pt.group_start + 1;   */
 }

 close(sd);
 if (o.numdecoys > 1)
   close(rawsd);
 if (ptech.connecttcpscan) free(tqi.sockets);
 if (sd >= 0) close(sd);
 if (rawsd >= 0) close(rawsd);
 free(time);
 if (pd) pcap_close(pd);
 if (o.debugging) 
   printf("massping done:  num_hosts: %d  num_responses: %d\n", num_hosts, pt.num_responses);
 gsize = pt.group_size;
 return;
}

int sendconnecttcpquery(struct hoststruct *hostbatch, struct tcpqueryinfo *tqi, struct hoststruct *target, 
			int seq, struct timeval *time, struct pingtune *pt, struct timeout_info *to) {

  int res,i;
  int tmpsd;
  int hostnum, trynum;
  struct sockaddr_in sock;
  int sockaddr_in_len = sizeof(struct sockaddr_in);
  
  trynum = seq % pt->max_tries;
  hostnum = seq / pt->max_tries;

  assert(tqi->sockets_out <= o.max_sockets);
  if (tqi->sockets_out == o.max_sockets) {
    /* We've got to free one! */
    for(i=0; i < trynum; i++) {
      tmpsd = hostnum * pt->max_tries + i;
      if (tqi->sockets[tmpsd] >= 0) {
	if (o.debugging) 
	  printf("sendconnecttcpquery: Scavenging a free socket due to serious shortage\n");
	close(tqi->sockets[tmpsd]);
	tqi->sockets[tmpsd] = -1;
	tqi->sockets_out--;
	break;
      }
    }
    if (i == trynum)
      fatal("sendconnecttcpquery: Could not scavenge a free socket!");
  }
    
  /* Since we know we now have a free s0cket, lets take it */

  assert(tqi->sockets[seq] == -1);
  tqi->sockets[seq] =  socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (tqi->sockets[seq] == -1) 
    fatal("Socket creation in sendconnecttcpquery");
  tqi->maxsd = MAX(tqi->maxsd, tqi->sockets[seq]);
  tqi->sockets_out++;
  unblock_socket(tqi->sockets[seq]);
  init_socket(tqi->sockets[seq]);

  bzero(&sock, sockaddr_in_len);
  sock.sin_family = AF_INET;
  sock.sin_port = htons(o.tcp_probe_port);
  sock.sin_addr.s_addr = target->host.s_addr;
  
  res = connect(tqi->sockets[seq],(struct sockaddr *)&sock,sizeof(struct sockaddr));
  gettimeofday(&time[seq], NULL);

  if ((res != -1 || errno == ECONNREFUSED)) {
    /* This can happen on localhost, successful/failing connection immediately
       in non-blocking mode */
      hostupdate(hostbatch, target, HOST_UP, 1, trynum, to, 
		 &time[seq], pt, tqi, PINGTYPE_CONNECTTCP);
    if (tqi->maxsd == tqi->sockets[seq]) tqi->maxsd--;
  }
  else if (errno == ENETUNREACH) {
    if (o.debugging) 
      error("Got ENETUNREACH from sendconnecttcpquery connect()");
    hostupdate(hostbatch, target, HOST_DOWN, 1, trynum, to, 
	       &time[seq], pt, tqi, PINGTYPE_CONNECTTCP);
  }
  else {
    /* We'll need to select() and wait it out */
    FD_SET(tqi->sockets[seq], &(tqi->fds_r));
    FD_SET(tqi->sockets[seq], &(tqi->fds_w));
    FD_SET(tqi->sockets[seq], &(tqi->fds_x));
  }
return 0;
}

int sendrawtcppingquery(int rawsd, struct hoststruct *target, int seq,
			struct timeval *time, struct pingtune *pt) {
int decoy, trynum;
int myseq;
trynum = seq % pt->max_tries;

 myseq = (rand() << 19) + (seq << 3) + 3; /* Response better end in 011 or 100 */
 memcpy((char *)&(o.decoys[o.decoyturn]), (char *)&target->source_ip, sizeof(struct in_addr));
 for (decoy = 0; decoy < o.numdecoys; decoy++) {
   if (o.pingtype & PINGTYPE_TCP_USE_SYN) {   
   send_tcp_raw( rawsd, &o.decoys[decoy], &(target->host), o.magic_port + trynum, o.tcp_probe_port, myseq, 0, TH_SYN, 0, NULL, 0, NULL, 0);
   } else {
     send_tcp_raw( rawsd, &o.decoys[decoy], &(target->host), o.magic_port + trynum, o.tcp_probe_port, myseq, 0, TH_ACK, 0, NULL, 0, NULL, 0);
   }
 }

 gettimeofday(&time[seq], NULL);
 return 0;
}


int sendpingquery(int sd, int rawsd, struct hoststruct *target,  
		  int seq, unsigned short id, struct scanstats *ss, 
		  struct timeval *time, struct pingtech ptech) {
  
struct ppkt {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short seq;
} pingpkt;
int decoy;
int res;
struct sockaddr_in sock;
char *ping = (char *) &pingpkt;

/* Fill out the ping packet */
pingpkt.type = 8;
pingpkt.code = 0;
pingpkt.id = id;
pingpkt.seq = seq;
pingpkt.checksum = 0;
pingpkt.checksum = in_cksum((unsigned short *)ping, 8);

/* Now for our sock */
if (ptech.icmpscan) {
  bzero((char *)&sock, sizeof(struct sockaddr_in));
  sock.sin_family= AF_INET;
  sock.sin_addr = target->host;
  
  if (sizeof(struct ppkt) != 8) 
    fatal("Your native data type sizes are too screwed up for this to work.");
} else {
  memcpy((char *) &(o.decoys[o.decoyturn]), (char *)&target->source_ip, sizeof(struct in_addr));
}

for (decoy = 0; decoy < o.numdecoys; decoy++) {
  if (ptech.icmpscan && decoy == o.decoyturn) {
    if ((res = sendto(sd,(char *) ping,8,0,(struct sockaddr *)&sock,
		      sizeof(struct sockaddr))) != 8) {
      fprintf(stderr, "sendto in sendpingquery returned %d (should be 8)!\n", res);
      perror("sendto");
    }
  } else {
    send_ip_raw( rawsd, &o.decoys[decoy], &(target->host), IPPROTO_ICMP, ping, 8);
  }
}
gettimeofday(&time[seq], NULL);
return 0;
}

int get_connecttcpscan_results(struct tcpqueryinfo *tqi, 
			       struct hoststruct *hostbatch, 
			       struct timeval *time, struct pingtune *pt, 
			       struct timeout_info *to) {

int res, res2, tm;
struct timeval myto, start, end;
int hostindex;
int trynum, newstate;
int seq;
char buf[256];
int foundsomething = 0;
fd_set myfds_r,myfds_w,myfds_x;
gettimeofday(&start, NULL);
 
while(pt->block_unaccounted) {

  /* OK so there is a little fudge factor, SUE ME! */
  myto.tv_sec  = to->timeout / 1000000; 
  myto.tv_usec = to->timeout % 1000000;
  foundsomething = 0;
  myfds_r = tqi->fds_r;
  myfds_w = tqi->fds_w;
  myfds_x = tqi->fds_x;
  res = select(tqi->maxsd + 1, &myfds_r, &myfds_w, &myfds_x, &myto);
  if (res > 0) {
    for(hostindex = pt->group_start; hostindex <= pt->group_end; hostindex++) {
      for(trynum=0; trynum <= pt->block_tries; trynum++) {
	seq = hostindex * pt->max_tries + trynum;
	if (tqi->sockets[seq] >= 0) {
	  if (o.debugging > 1) {
	    if (FD_ISSET(tqi->sockets[seq], &(myfds_r))) {
	      printf("WRITE selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host));  
	    }
	    if ( FD_ISSET(tqi->sockets[seq], &myfds_w)) {
	      printf("READ selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host)); 
	    }
	    if  ( FD_ISSET(tqi->sockets[seq], &myfds_x)) {
	      printf("EXC selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host));
	    }
	  }
	  if (FD_ISSET(tqi->sockets[seq], &myfds_r) || FD_ISSET(tqi->sockets[seq], &myfds_w) ||  FD_ISSET(tqi->sockets[seq], &myfds_x)) {
	    foundsomething = 0;
	    res2 = read(tqi->sockets[seq], buf, sizeof(buf));
	    if (res2 == -1) {
	      switch(errno) {
	      case ECONNREFUSED:
	      case EAGAIN:
		if (errno == EAGAIN && o.verbose) {
		  printf("Machine %s MIGHT actually be listening on probe port %d\n", inet_ntoa(hostbatch[hostindex].host), o.tcp_probe_port);
		}
		foundsomething = 1;
		newstate = HOST_UP;	
		break;
	      case ENETDOWN:
	      case ENETUNREACH:
	      case ENETRESET:
	      case ECONNABORTED:
	      case ETIMEDOUT:
	      case EHOSTDOWN:
	      case EHOSTUNREACH:
		foundsomething = 1;
		newstate = HOST_DOWN;
		break;
	      default:
		sprintf (buf, "Strange read error from %s", inet_ntoa(hostbatch[hostindex].host));
		perror(buf);
		break;
	      }
	    } else { 
	      foundsomething = 1;
	      newstate = HOST_UP;
	      if (o.verbose) {	      
		buf[res2] = '\0';
		if (res2 == 0)
		  printf("Machine %s is actually LISTENING on probe port %d\n",
			 inet_ntoa(hostbatch[hostindex].host), 
			 o.tcp_probe_port);
		else 
		  printf("Machine %s is actually LISTENING on probe port %d, banner: %s\n",
			 inet_ntoa(hostbatch[hostindex].host), 
			 o.tcp_probe_port, buf);
	      }
	    }
	    if (foundsomething) {
	      hostupdate(hostbatch, &hostbatch[hostindex], newstate, 1, trynum,
			 to,  &time[seq], pt, tqi, PINGTYPE_CONNECTTCP);
	      /*	      break;*/
	    }
	  }
	}
      }
    }
  }
  gettimeofday(&end, NULL);
  tm = TIMEVAL_SUBTRACT(end,start);  
  if (tm > (30 * to->timeout)) {
    error("WARNING: getconnecttcpscanresults is taking way to long, skipping");
    break;
  }
  if (res == 0 &&  tm > to->timeout) break; 
}

/* OK, now we have to kill all outstanding queries to make room for
   the next group :( I'll miss these little guys. */
 for(hostindex = pt->group_start; hostindex <= pt->group_end; hostindex++) { 
      for(trynum=0; trynum <= pt->block_tries; trynum++) {
	seq = hostindex * pt->max_tries + trynum;
	if ( tqi->sockets[seq] >= 0) {
	  tqi->sockets_out--;
	  close(tqi->sockets[seq]);
	  tqi->sockets[seq] = -1;
	}
      }
 }
 tqi->maxsd = 0;
 assert(tqi->sockets_out == 0);
 FD_ZERO(&(tqi->fds_r));
 FD_ZERO(&(tqi->fds_w));
 FD_ZERO(&(tqi->fds_x));
	 
return 0;
}


int get_ping_results(int sd, pcap_t *pd, struct hoststruct *hostbatch, struct timeval *time,  struct pingtune *pt, struct timeout_info *to, int id, struct pingtech *ptech) {
fd_set fd_r, fd_x;
struct timeval myto, tmpto, start, end;
int bytes, res;
struct ppkt {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short seq;
};
struct {
  struct ip ip;
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short identifier;
  unsigned short sequence;
  char crap[16536];
}  response;
struct tcphdr *tcp;
struct ip *ip;
int hostnum;
int tm;
int dotimeout;
int newstate;
int foundsomething;
unsigned short newport;
int trynum;
int pingtype;
unsigned short sequence;
unsigned long tmpl;
FD_ZERO(&fd_r);
FD_ZERO(&fd_x);

/* Decide on the timeout, based on whether we need to also watch for TCP stuff */
if (ptech->icmpscan && !ptech->rawtcpscan) {
  /* We only need to worry about pings, so we set timeout for the whole she-bang! */
  myto.tv_sec  = to->timeout / 1000000;
  myto.tv_usec = to->timeout % 1000000;
} else {
  myto.tv_sec = 0;
  myto.tv_usec = 20000;
}


gettimeofday(&start, NULL);
while(pt->block_unaccounted > 0) {
  tmpto = myto;

  if (pd) {
    ip = (struct ip*) readip_pcap(pd, &bytes);
    if (bytes > sizeof(response)) {
      error("Huge packet caught by get_ping_results");
      continue;
    }
    if (bytes > 0) {    
      memcpy((char *)&response, (char *)ip, bytes);  
    }
  } else {    
    FD_SET(sd, &fd_r);
    FD_SET(sd, &fd_x);
    res = select(sd+1, &fd_r, NULL, &fd_x, &tmpto);
    if (res == 0) break;
    bytes = read(sd,&response,sizeof(response));
  }
  if (bytes > 0 && bytes <= 20) {  
    error("%d byte micro packet received in get_ping_results");
  }
  else if (bytes > 20) {  
    foundsomething = 0;
    /* First check if it is ICMP or TCP */
    if (response.ip.ip_p == IPPROTO_ICMP) {    
      /* if it is our response */
      if  ( !response.type && !response.code && response.identifier == id) {
	hostnum = response.sequence / pt->max_tries;
	if (hostnum > pt->group_end) continue;
	if (!hostbatch[hostnum].source_ip.s_addr)
	  hostbatch[hostnum].source_ip.s_addr = response.ip.ip_dst.s_addr;
	if (o.debugging) printf("We got a ping packet back from %s: id = %d seq = %d checksum = %d\n", inet_ntoa(*(struct in_addr *)(&response.ip.ip_src.s_addr)), response.identifier, response.sequence, response.checksum);
	if (hostbatch[hostnum].host.s_addr == response.ip.ip_src.s_addr) {
	  foundsomething = 1;
	  pingtype = PINGTYPE_ICMP;
	  sequence = response.sequence;
	  if (pt->discardtimesbefore < response.sequence)
	    dotimeout = 1;
	  trynum = sequence % pt->max_tries;
	  newstate = HOST_UP;
	}
	else hostbatch[hostnum].wierd_responses++;
      } 
      else if (response.type == 3 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == id) {
	sequence = ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->seq;
	hostnum = sequence / pt->max_tries;
	if (hostnum > pt->group_end) continue;
	if (o.debugging) printf("Got destination unreachable for %s\n", inet_ntoa(hostbatch[hostnum].host));
	/* Since this gives an idea of how long it takes to get an answer,
	   we add it into our times */
	if (pt->discardtimesbefore < sequence)
	  dotimeout = 1;
	foundsomething = 1;
	pingtype = PINGTYPE_ICMP;
	trynum = sequence % pt->max_tries;
	newstate = HOST_DOWN;
      }
      else if (response.type == 4 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == id)  {      
	if (o.debugging) printf("Got ICMP source quench\n");
	usleep(50000);
      }   
      else if (o.debugging > 1 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == id ) {      
	printf("Got ICMP message type %d code %d\n", response.type, response.code);
      }
    } else if (response.ip.ip_p == IPPROTO_TCP) {
      tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
      if (!(tcp->th_flags & TH_RST) && ((tcp->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK)))
	continue;
      newport = ntohs(tcp->th_sport);
      tmpl = ntohl(tcp->th_ack);
      /* Grab the sequence nr */
      if (o.pingtype & PINGTYPE_TCP_USE_SYN) {      
	if ((tmpl & 7) == 4 || (tmpl & 7) == 3) {
	  sequence = (tmpl >> 3) & 0xffff;
	  hostnum = sequence / pt->max_tries;
	  trynum = sequence % pt->max_tries;
	} else {
	  if (o.debugging) {
	    error("Whacked ACK number from %s", inet_ntoa(response.ip.ip_src));
	  }
	  continue;	
	}
      } else {
	trynum = ntohs(tcp->th_dport) - o.magic_port;
	if (trynum >= pt->max_tries) {
	  continue;
	}
	/* FUDGE!  This ACK scan is cool but we don't get sequence numbers
	   back! We'll have to brute force lookup to find the hostnum */
	for(hostnum = pt->group_end; hostnum >= 0; hostnum--) {
	  if (hostbatch[hostnum].host.s_addr == ip->ip_src.s_addr)
	    break;
	}
	if (hostnum < 0) {	
	  if (o.debugging) 
	    error("Warning, unexpacted packet from machine %s", inet_ntoa(ip->ip_src));
	  continue;
	}	
	sequence = hostnum * pt->max_tries + trynum;
      }
      if (hostnum > pt->group_end) {
	if (o.debugging) {
	  error("Response from host beyond group_end");
	}
	continue;
      }
      if (o.debugging) 
	printf("We got a TCP ping packet back from %s (hostnum = %d trynum = %d\n", inet_ntoa(*(struct in_addr *)(&response.ip.ip_src.s_addr)),
	       hostnum, trynum);
      foundsomething = 1;
      pingtype = PINGTYPE_RAWTCP;
      foundsomething = 1;
      if (pt->discardtimesbefore < response.sequence)
	dotimeout = 1;
      newstate = HOST_UP;
    } else if (o.debugging) {
      error("Found whacked packet protocol %d in get_ping_results", response.ip.ip_p);
    }
    if (foundsomething) {  
      hostupdate(hostbatch, &hostbatch[hostnum], newstate, dotimeout, 
		 trynum, to, &time[sequence], pt, NULL,pingtype);
    }
  }
  gettimeofday(&end, NULL);
  tm = TIMEVAL_SUBTRACT(end,start);  
  if (tm > (3 * to->timeout))
    break;
  if (bytes == 0 &&  tm > to->timeout) break;
}
return 0;
}

int hostupdate(struct hoststruct *hostbatch, struct hoststruct *target, 
	       int newstate, int dotimeout, int trynum, 
	       struct timeout_info *to, struct timeval *sent, 
	       struct pingtune *pt, struct tcpqueryinfo *tqi, int pingtype) {

int hostnum = target - hostbatch;
int i;
int seq;
int tmpsd;

if (o.debugging) 
  printf("Hostupdate called for machne %s state %s -> %s (trynum %d)\n", inet_ntoa(target->host), readhoststate(target->flags), readhoststate(newstate), trynum);
assert(hostnum <= pt->group_end);

if (dotimeout) {
  adjust_timeouts(*sent, to);
}

/* If this is a tcp connect() pingscan, close all sockets */

if (pingtype == PINGTYPE_CONNECTTCP) {
  seq = (target - hostbatch) * pt->max_tries + trynum;
  assert(tqi->sockets[seq] >= 0);
  for(i=0; i <= pt->block_tries; i++) {  
    seq = (target - hostbatch) * pt->max_tries + i;
    tmpsd = tqi->sockets[seq];
    if (tmpsd >= 0) {
      assert(tqi->sockets_out > 0);
      tqi->sockets_out--;
      close(tmpsd);
      if (tmpsd == tqi->maxsd) tqi->maxsd--;
      FD_CLR(tmpsd, &(tqi->fds_r));
      FD_CLR(tmpsd, &(tqi->fds_w));
      FD_CLR(tmpsd, &(tqi->fds_x));
      tqi->sockets[seq] = -1;
    }
  }
}


target->to = *to;

if (target->flags & HOST_UP) {
  /* The target is already up and that takes precedence over HOST_DOWN
     or HOST_FIREWALLED, so we just return. */
  return 0;
}

if (trynum > 0 && !(pt->dropthistry)) {
  pt->dropthistry = 1;
  pt->group_size = MAX(pt->group_size * 0.75, 10);
  if (o.debugging) 
    printf("Decreasing massping group size to %d\n", pt->group_size);
}

if (newstate == HOST_DOWN && (target->flags & HOST_DOWN)) {
  /* I see nothing to do here */
} else if (newstate == HOST_UP && (target->flags & HOST_DOWN)) {
  /* We give host_up precedence */
  target->flags &= ~HOST_DOWN; /* Kill the host_down flag */
  target->flags |= HOST_UP;
  if (hostnum >= pt->group_start) {  
    assert(pt->down_this_block > 0);
    pt->down_this_block--;
    pt->up_this_block++;
  }
} else if (newstate == HOST_DOWN) {
  target->flags |= HOST_DOWN;
  pt->down_this_block++;
  pt->block_unaccounted--;
  pt->num_responses++;
} else {
  assert(newstate == HOST_UP);
  target->flags |= HOST_UP;
  pt->up_this_block++;
  pt->block_unaccounted--;
  pt->num_responses++;
}
return 0;
}

char *readhoststate(int state) {
  switch(state) {
  case HOST_UP:
    return "HOST_UP";
  case HOST_DOWN:
    return "HOST_DOWN";
  case HOST_FIREWALLED:
    return "HOST_FIREWALLED";
  default:
    return "UNKNOWN/COMBO";
  }
  return NULL;
}



