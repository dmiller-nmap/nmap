#include "targets.h"

extern struct ops o;
struct hoststruct *nexthost(char *hostexp, int lookahead, int pingtimeout) {
static int lastindex = -1;
static struct hoststruct *hostbatch  = NULL;
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

if (hostbatch[0].host.s_addr && (o.pingtype & PINGTYPE_ICMP )) 
  massping(hostbatch, i, pingtimeout);
else if (hostbatch[0].host.s_addr && (o.pingtype & PINGTYPE_TCP))
  masstcpping(hostbatch, i, pingtimeout);
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
int icmpscan = 0, rawtcpscan = 0, connecttcpscan = 0;
struct ppkt {
  unsigned char type;
  unsigned char code;
  unsigned short checksum;
  unsigned short id;
  unsigned short seq;
};
unsigned int elapsed_time;
int sd_blocking = 1;
struct sockaddr_in sock;
short seq = 0;
int sd,rawsd;
struct timeval *time;
struct timeval start, end, t1, t2;
unsigned short id;

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
if (o.pingtype & PINGTYPE_ICMP) icmpscan++;
if (o.pingtype & PINGTYPE_TCP) {
  if (o.isr00t)
    rawtcpscan++;
  else connecttcpscan++;
}

time = safe_malloc(sizeof(struct timeval) * ((pt.max_tries) * num_hosts));
id = (unsigned short) rand();

if (icmpscan)
  sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
else sd = -1;

if (sd < 0) pfatal("Socket trouble in massping"); 
unblock_socket(sd);
sd_blocking = 0;

/* if to timeout structure hasn't been initialized yet */
if (!to.srtt && !to.rttvar && !to.timeout) {
  /*  to.srtt = 800000;
      to.rttvar = 500000; */ /* we will init these when we get real data */
  to.timeout = 6000000;
} 

/* Init our raw socket */
if (o.numdecoys > 1)
  if ((rawsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
    pfatal("socket trobles in massping");

unblock_socket(rawsd);

bzero((char *)&sock,sizeof(struct sockaddr_in));
gettimeofday(&start, NULL);

 if (num_hosts > 10) 
   max_rcvbuf(sd);
 if (o.allowall) broadcast_socket(sd);
 
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
         if (!sd_blocking) { block_socket(sd); sd_blocking = 1; }
	 sendpingquery(sd, rawsd, &hostbatch[hostnum],  
		       seq, id, &ss, time);
	 pt.block_unaccounted++;
	 gettimeofday(&t2, NULL);
	 if (TIMEVAL_SUBTRACT(t2,time[seq]) > 1000000) {
	   pt.discardtimesbefore = hostnum;
	   if (o.debugging) 
	     printf("Huge send delay: %lu microseconds\n", TIMEVAL_SUBTRACT(t2,t1));
	 }
       }
     } /* for() loop */
     /* OK, we have sent our ping packets ... now we wait for responses */
     gettimeofday(&begin_select, NULL);
     do {
       if (sd_blocking) { unblock_socket(sd); sd_blocking = 0; }
       get_ping_results(sd, hostbatch, time, &pt, &to, id);
     
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
     pt.group_size = MIN(pt.group_size + 10, 150);
   
   /* Move to next block */
   pt.block_tries = 0;
   pt.group_start = pt.group_end +1;
   pt.group_end = MIN(pt.group_start + pt.group_size -1, num_hosts -1);
   /*   pt.block_unaccounted = pt.group_end - pt.group_start + 1;   */
 }

 close(sd);
 if (o.numdecoys > 1)
   close(rawsd);
 if (sd >= 0) close(sd);
 free(time);
 if (o.debugging) 
   printf("massping done:  num_hosts: %d  num_responses: %d\n", num_hosts, pt.num_responses);
 gsize = pt.group_size;
 return;
}

void masstcpping(struct hoststruct *hostbatch, int num_hosts, int pingtimeout) {
  int sockets[MAX_SOCKETS_ALLOWED];
  int hostindex = 0;
  struct timeval start, waittime, tmptv;
  int numretries = 3;
  int maxsock = 0;
  int res;
  char buf[255];
  int numcomplete = 0;
  struct sockaddr_in sock;
  int sockaddr_in_len = sizeof(struct sockaddr_in);
  int retry;
  fd_set fds_read, fds_write, fds_ex;

  gettimeofday(&start, NULL);
  bzero(sockets, sizeof(int) * MAX_SOCKETS_ALLOWED);
  bzero(&sock, sockaddr_in_len);
  FD_ZERO(&fds_read);
  FD_ZERO(&fds_write);
  FD_ZERO(&fds_ex);
  sock.sin_family = AF_INET;
  waittime.tv_sec = pingtimeout / (numretries + 1);
  waittime.tv_usec = ((pingtimeout % (numretries +1)) * 1e6) / (numretries +1);
  /*  unsigned short tport = rand() % 27500 + 38000;  */
  for(retry = 0;(numcomplete < num_hosts) && retry <= numretries; retry++) {
    for(hostindex = 0; hostindex < num_hosts; hostindex++) {
      if ((hostbatch[hostindex].flags & (HOST_UP|HOST_DOWN)) == 0) {
	sockets[hostindex] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (o.debugging > 1) {
	  printf("Just created a socket for %d (flags %d)\n", hostindex,hostbatch[hostindex].flags );
	}
	if (sockets[hostindex] == -1) { pfatal("Socket troubles in masstcpping\n"); }
	maxsock = MAX(maxsock, sockets[hostindex]);
	unblock_socket(sockets[hostindex]);
	init_socket(sockets[hostindex]);
	sock.sin_port =  htons(o.tcp_probe_port);
	sock.sin_addr.s_addr = hostbatch[hostindex].host.s_addr;
	res = connect(sockets[hostindex],(struct sockaddr *)&sock,sizeof(struct sockaddr));
	if ((res != -1 || errno == ECONNREFUSED)) {
	  /* This can happen on localhost, successful/failing connection immediately
	     in non-blocking mode */
	  close(sockets[hostindex]);
	  if (maxsock == sockets[hostindex]) maxsock--;
	  sockets[hostindex] = 0;
	  hostbatch[hostindex].flags |= HOST_UP;	 
	  numcomplete++;
      }
	else if (errno == ENETUNREACH) {
	  if (o.debugging) error("Got ENETUNREACH from masstcpping connect()");
	  close(sockets[hostindex]);
	  if (maxsock == sockets[hostindex]) maxsock--;
	  sockets[hostindex] = 0;
	  hostbatch[hostindex].flags |= HOST_DOWN;	 
	  numcomplete++;
	}
	else {
	  /* We'll need to select() and wait it out */
	  FD_SET(sockets[hostindex], &fds_read);
	  FD_SET(sockets[hostindex], &fds_write);
	  FD_SET(sockets[hostindex], &fds_ex);
	}
      }
    }
    tmptv = waittime;
    while((numcomplete < num_hosts) && (res = select(maxsock+1, &fds_read, &fds_write, &fds_ex, &tmptv)) > 0) {
      if (FD_ISSET(0, &fds_read) || FD_ISSET(0, &fds_write) ||  FD_ISSET(0, &fds_ex)) { fatal("Ack, 0 is set!"); }	
      for(hostindex = 0; hostindex < num_hosts; hostindex++) {
	if (sockets[hostindex]) {
	  if (o.debugging > 1) {
	    if (FD_ISSET(sockets[hostindex], &fds_read)) {
	      printf("WRITE selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host));  
	    }
	    if ( FD_ISSET(sockets[hostindex], &fds_write)) {
	      printf("READ selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host)); 
	    }
	    if  ( FD_ISSET(sockets[hostindex], &fds_ex)) {
	      printf("EXC selected for machine %s\n", inet_ntoa(hostbatch[hostindex].host));
	    }
	  }
	  if (FD_ISSET(sockets[hostindex], &fds_read) || FD_ISSET(sockets[hostindex], &fds_write) ||  FD_ISSET(sockets[hostindex], &fds_ex)) {
	    res = read(sockets[hostindex], buf, 1);
	    if (res == -1) {
	      switch(errno) {
	      case ECONNREFUSED:
	      case EAGAIN:
		hostbatch[hostindex].flags |= HOST_UP;	
		break;
	      case ENETDOWN:
	      case ENETUNREACH:
	      case ENETRESET:
	      case ECONNABORTED:
	      case ETIMEDOUT:
	      case EHOSTDOWN:
	      case EHOSTUNREACH:
		hostbatch[hostindex].flags |= HOST_DOWN;
		break;
	      default:
		sprintf (buf, "Strange read error from %s", inet_ntoa(hostbatch[hostindex].host));
		perror(buf);
		break;
	      }
	    } else { 
	      error("Read succeeded from %s (returned %d) ... strange\n", inet_ntoa(hostbatch[hostindex].host), res); 
	    } 
	    close(sockets[hostindex]);
	    if (maxsock == sockets[hostindex]) maxsock--;
	    FD_CLR(sockets[hostindex], &fds_write);
	    FD_CLR(sockets[hostindex], &fds_read);
	    FD_CLR(sockets[hostindex], &fds_ex);
	    sockets[hostindex] = 0;
	    numcomplete++;
	  }
	}
      }
      tmptv = waittime;
    }
    /* Now we kill the sockets that haven't selected yet */
    maxsock = 0;
    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);
    FD_ZERO(&fds_ex);
     for(hostindex = 0; hostindex < num_hosts; hostindex++) {
       if (sockets[hostindex]) {
	 close(sockets[hostindex]);
	 sockets[hostindex] = 0;
       }
     }
  }
  if (o.debugging) {
    printf("MassTCP ping got responses from %d of %d hosts\n", numcomplete, num_hosts);
  }
}







int sendpingquery(int sd, int rawsd, struct hoststruct *target,  
		  int seq, unsigned short id, struct scanstats *ss, 
		  struct timeval *time) {
  
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
bzero((char *)&sock, sizeof(struct sockaddr_in));
sock.sin_family= AF_INET;
sock.sin_addr = target->host;

if (sizeof(struct ppkt) != 8) 
  fatal("Your native data type sizes are too screwed up for this to work.");


for (decoy = 0; decoy < o.numdecoys; decoy++) {
  if (decoy == o.decoyturn) {
    if ((res = sendto(sd,(char *) ping,8,0,(struct sockaddr *)&sock,
		      sizeof(struct sockaddr))) != 8) {
      fprintf(stderr, "sendto in sendpingquery returned %d (should be 8)!\n", res);
      perror("sendto");
    }
  } else {
    send_ip_raw( rawsd, &o.decoys[decoy], &(sock.sin_addr), IPPROTO_ICMP, ping, 8);
  }
}
gettimeofday(&time[seq], NULL);
return 0;
}

int get_ping_results(int sd, struct hoststruct *hostbatch, struct timeval *time,  struct pingtune *pt, struct timeout_info *to, int id) {
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
int hostnum;
int dotimeout;
int newstate;
int foundsomething;
int trynum;
unsigned short sequence;

FD_ZERO(&fd_r);
FD_ZERO(&fd_x);

/* Decide on the timeout, based on whether we need to also watch for TCP stuff */
if (!(o.pingtype & PINGTYPE_TCP)) {
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
  FD_SET(sd, &fd_r);
  FD_SET(sd, &fd_x);

  res = select(sd+1, &fd_r, NULL, &fd_x, &tmpto);
  if (res == 0) break;
  while (pt->block_unaccounted && (bytes = read(sd,&response,sizeof(response))) > 0) {
    foundsomething = 0;
    /* if it is our response */
    if  ( !response.type && !response.code && response.identifier == id) {
      hostnum = response.sequence / pt->max_tries;
      if (hostnum > pt->group_end) continue;
      hostbatch[hostnum].source_ip.s_addr = response.ip.ip_dst.s_addr;
      if (o.debugging) printf("We got a ping packet back from %s: id = %d seq = %d checksum = %d\n", inet_ntoa(*(struct in_addr *)(&response.ip.ip_src.s_addr)), response.identifier, response.sequence, response.checksum);
      if (hostbatch[hostnum].host.s_addr == response.ip.ip_src.s_addr) {
	foundsomething = 1;
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
  if (foundsomething) {  
    printf("Calling hostupdate %s sequence %d\n", inet_ntoa(hostbatch[hostnum].host), sequence);
    hostupdate(hostbatch, &hostbatch[hostnum], newstate, dotimeout, trynum, 
	       to, &time[sequence], pt, PINGTYPE_ICMP);
  }
  }
  gettimeofday(&end, NULL);
  if (TIMEVAL_SUBTRACT(end, start) > (3 * to->timeout))
    break;  
}
return 0;
}

int hostupdate(struct hoststruct *hostbatch, struct hoststruct *target, 
	       int newstate, int dotimeout, int trynum, 
	       struct timeout_info *to, struct timeval *sent, 
	       struct pingtune *pt, int pingtype) {

int hostnum = target - hostbatch;
assert(hostnum <= pt->group_end);

if (dotimeout) {
  adjust_timeouts(*sent, to);
}

target->to = *to;

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




