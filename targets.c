#include "nmap.h"

extern struct ops o;
struct hoststruct *nexthost(char *hostexp, int lookahead, int pingtimeout) {
static int lastindex = -1;
static struct hoststruct *hostbatch  = NULL;
static int targets_valid = 0;
static int i;
static struct targets targets;
static char *lasthostexp = NULL;
if (!hostbatch) hostbatch = safe_malloc((lookahead + 1) * sizeof(struct hoststruct));

if (lasthostexp && lasthostexp != hostexp) {
 /* New expression -- reinit everything */
  targets_valid = 0;
  lastindex = -1;
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
      if (!o.allowall && (!(targets.currentaddr.s_addr % 256) 
			 || targets.currentaddr.s_addr % 256 == 255))
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

if (hostbatch[0].host.s_addr && !o.dontping ) massping(hostbatch, i, pingtimeout);
else for(i=0; hostbatch[i].host.s_addr; i++) 
	hostbatch[i].flags |= HOST_UP; /*hostbatch[i].up = 1;*/

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
 targets->start.s_addr = longtmp & (unsigned long) (0 - pow(2,32 - targets->netmask));
 targets->end.s_addr = longtmp | (unsigned long) (pow(2,32 - targets->netmask) - 1);
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
    if (start < 0 || start > end) fatal("Your port specifications are illegal!");
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
int num_responses = 0;
int i=0;
unsigned int elapsed_time;
int res, retries = 1;
int num_down = 0;
int bytes;
int hostno; /* host number, to avoid a long expression each line */
int rounds = 0; /* number of rounds of sends we've completed; */
struct sockaddr_in sock;
short seq = -1;
/*type(8bit)=8, code(8)=0 (echo REQUEST), checksum(16)=34190, id(16)=27002 */
unsigned char *ping; /*[64] = { 0x8, 0x0, 0x8e, 0x85, 0x69, 0x7A };*/
unsigned short ushorttmp;
int prod;
int sd;
struct timeval *time = safe_malloc(sizeof(struct timeval) * ((retries + 1) * num_hosts));
struct timeval start, end;
unsigned short pid;
struct ppkt {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short seq;
} pingpkt;
struct {
  struct ip ip;
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short identifier;
  unsigned short sequence;
  char crap[16536];
}  response;

pid = getpid();
/* Lets create our base ping packet here ... */
pingpkt.type = 8;
pingpkt.code = 0;
pingpkt.checksum = 0;
pingpkt.id = pid; /* intentionally not in NBO */
pingpkt.seq = seq; /* Any reason to use NBO here? */
ping = (char *) &pingpkt;
pingpkt.checksum = in_cksum((unsigned short *) ping, 8);
if (sizeof(struct ppkt) != 8) 
  fatal("Your native data type sizes are too screwed up for this to work.");

sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
bzero((char *)&sock,sizeof(struct sockaddr_in));
sock.sin_family=AF_INET;
gettimeofday(&start, NULL);
unblock_socket(sd);
if (num_hosts > 10) 
  max_rcvbuf(sd);
if (o.allowall) broadcast_socket(sd);

prod = (retries + 1) * num_hosts;
for(;;) {

  for(i=0; i < num_hosts && rounds <= retries; i++) {

    /* Update the new packet sequence nr. and checksum */
    pingpkt.seq = ++seq;
    if (seq > 0 ) { /* Don't increment the very first packet */
      if (ping[2] != 0) ping[2]--; /* Shit, now not using NBO is hitting the fan ;) */
      else if (ping[1] != 255) { 
	ping[2] = 255;
	ping[1]--;
      }
      else ping[2] = ping[3] = 255;
    }

    /* If (we don't know whether the host is up yet) ... */
    if (!(hostbatch[seq%num_hosts].flags & HOST_UP) && !hostbatch[seq%num_hosts].wierd_responses && !(hostbatch[seq%num_hosts].flags & HOST_DOWN)) {  
      /* Send a ping packet to it */
      sock.sin_addr = hostbatch[seq%num_hosts].host;
      gettimeofday(&time[i], NULL);
      if ((res = sendto(sd,(char *) ping,8,0,(struct sockaddr *)&sock,
			sizeof(struct sockaddr))) != 8) {
	fprintf(stderr, "sendto in massping returned %d (should be 8)!\n", res);
	perror("sendto");
      }
    }
  } /* for() loop */
  rounds += 1;
  do {
    while ((bytes = read(sd,&response,sizeof(response))) > 0) {
      /* if it is our response */
      if  ( !response.type && !response.code && response.identifier == pid) {
	gettimeofday(&end, NULL);
	hostno = response.sequence % num_hosts;

	hostbatch[hostno].source_ip.s_addr = response.ip.ip_dst.s_addr;
	if (o.debugging) printf("We got a ping packet back from %s: id = %d seq = %d checksum = %d\n", inet_ntoa(*(struct in_addr *)(&response.ip.ip_src.s_addr)), response.identifier, response.sequence, response.checksum);
	if (hostbatch[hostno].host.s_addr == response.ip.ip_src.s_addr) {
	  hostbatch[hostno].rtt = (end.tv_sec - time[response.sequence].tv_sec) * 1e6
	    + end.tv_usec - time[response.sequence].tv_usec;
	  if (!(hostbatch[hostno].flags & HOST_UP)) {	  
	    num_responses++;
	    hostbatch[hostno].flags |= HOST_UP;
	    if (num_responses + num_down == num_hosts) goto alldone; /* GOTO!  Hell yeah! */
	  }
	}
	else  hostbatch[hostno].wierd_responses++;
      }

      else if (response.type == 3 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == pid) {
	ushorttmp = ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->seq;
	if (o.debugging) printf("Got destination unreachable for %s\n", inet_ntoa(hostbatch[ushorttmp % num_hosts].host));
	hostbatch[ushorttmp % num_hosts].flags |= HOST_DOWN;
	num_down++;
	if (num_responses + num_down == num_hosts) goto alldone; /* GOTO!  Hell yeah! */
      }

      else if (response.type == 4 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == pid)  {      
	if (o.debugging) printf("Got ICMP source quench\n");
	usleep(15000);
      }

      else if (o.debugging > 1 && ((struct ppkt *) (response.crap + 4 * response.ip.ip_hl))->id == pid ) {

	printf("Got ICMP message type %d code %d\n", response.type, response.code);
      }
    }
    gettimeofday(&end, NULL);
    elapsed_time = (end.tv_sec - start.tv_sec) * 1e6 + end.tv_usec - start.tv_usec;
    if (elapsed_time > pingtimeout * 1e6) goto alldone;
  } while( elapsed_time < pingtimeout * 1e6 * (double) rounds / (retries + 1));
}
alldone:
close(sd);
free(time);
if (o.debugging) printf("massping done:  num_hosts: %d  num_responses: %d\n", num_hosts, num_responses);
}



