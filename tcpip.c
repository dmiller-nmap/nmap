#include "tcpip.h"


/* Globals */
int jumpok = 0;
static jmp_buf jmp_env;

/* Sig_ALRM handler */
void sig_alarm(int signo) {
if (jumpok)
  longjmp(jmp_env, 1);
return;
}

__inline__ void sethdrinclude(int sd) {
#ifdef IP_HDRINCL
int one = 1;
setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (void *) &one, sizeof(one));
#endif
}

/* Standard swiped internet checksum routine */
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




/* Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip) {
  struct hostent *h;

  if (inet_aton(hostname, ip))
    return 1; /* damn, that was easy ;) */
  if ((h = gethostbyname(hostname))) {
    memcpy(ip, h->h_addr_list[0], sizeof(struct in_addr));
    return 1;
  }
  return 0;
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
static int myttl = 0;

 /*With these placement we get data and some field alignment so we aren't
   wasting too much in computing the checksum */
int res;
struct sockaddr_in sock;
char myname[MAXHOSTNAMELEN + 1];
struct hostent *myhostent = NULL;
int source_malloced = 0;

/* check that required fields are there and not too silly */
if ( !victim || !sport || !dport || sd < 0) {
  fprintf(stderr, "send_tcp_raw: One or more of your parameters suck!\n");
  return -1;
}

if (!myttl)  myttl = (time(NULL) % 14) + 51;

/* It was a tough decision whether to do this here for every packet
   or let the calling function deal with it.  In the end I grudgingly decided
   to do it here and potentially waste a couple microseconds... */
sethdrinclude(sd); 

/* if they didn't give a source address, fill in our first address */
if (!source) {
  source_malloced = 1;
  source = safe_malloc(sizeof(struct in_addr));
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is fucked up.\n"); 
  memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
#if ( TCPIP_DEBUGGING )
    printf("We skillfully deduced that your address is %s\n", 
	   inet_ntoa(*source));
#endif
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
ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(struct tcphdr) + datalen);
ip->ip_id = rand();
ip->ip_ttl = myttl;
ip->ip_p = IPPROTO_TCP;
ip->ip_src.s_addr = source->s_addr;
ip->ip_dst.s_addr= victim->s_addr;
#if HAVE_IP_IP_SUM
ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif

 /* We should probably copy the data over too */
if (data)
  memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), data, datalen);

if (TCPIP_DEBUGGING > 1) {
printf("Raw TCP packet creation completed!  Here it is:\n");
readtcppacket(packet,BSDUFIX(ip->ip_len));
}
if (TCPIP_DEBUGGING > 1) 

  printf("\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n",
	 sd, BSDUFIX(ip->ip_len), inet_ntoa(*victim),
	 sizeof(struct sockaddr_in));
if ((res = sendto(sd, packet, BSDUFIX(ip->ip_len), 0,
		  (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)
  {
    perror("sendto in send_tcp_raw");
    if (source_malloced) free(source);
    return -1;
  }
if (TCPIP_DEBUGGING > 1) printf("successfully sent %d bytes of raw_tcp!\n", res);

if (source_malloced) free(source);
return res;
}


/* A simple function I wrote to help in debugging, shows the important fields
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
realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
tot_len = BSDFIX(ip->ip_len);
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

/* A simple function I wrote to help in debugging, shows the important fields
   of a TCP packet*/
int readudppacket(char *packet, int readdata) {

struct ip *ip = (struct ip *) packet;
struct udphdr_bsd *udp = (struct udphdr_bsd *) (packet + sizeof(struct ip));
char *data = packet +  sizeof(struct ip) + sizeof(struct udphdr_bsd);
int tot_len;
struct in_addr bullshit, bullshit2;
char sourcehost[16];
int i;
int realfrag = 0;

if (!packet) {
  fprintf(stderr, "readudppacket: packet is NULL!\n");
  return -1;
    }

bullshit.s_addr = ip->ip_src.s_addr; bullshit2.s_addr = ip->ip_dst.s_addr;
/* this is gay */
realfrag = BSDFIX(ntohs(ip->ip_off) & 8191 /* 2^13 - 1 */);
tot_len = BSDFIX(ip->ip_len);
strncpy(sourcehost, inet_ntoa(bullshit), 16);
i =  4 * (ntohs(ip->ip_hl)) + 8;
if (ip->ip_p== IPPROTO_UDP) {
  if (realfrag) 
    printf("Packet is fragmented, offset field: %u\n", realfrag);
  else {
    printf("UDP packet: %s:%d -> %s:%d (total: %d bytes)\n", sourcehost, 
	   ntohs(udp->uh_sport), inet_ntoa(bullshit2), 
	   ntohs(udp->uh_dport), tot_len);

    printf("ttl: %hi ", ip->ip_ttl);
  }
}
 if (readdata && i < tot_len) {
   printf("Data portion:\n");
   while(i < tot_len)  printf("%2X%c", data[i], (++i%16)? ' ' : '\n');
   printf("\n");
 }
 return 0;
}

int send_udp_raw( int sd, struct in_addr *source, 
		  struct in_addr *victim, unsigned short sport, 
		  unsigned short dport, char *data, unsigned short datalen) 
{

char *packet = safe_malloc(sizeof(struct ip) + sizeof(struct udphdr_bsd) + datalen);
struct ip *ip = (struct ip *) packet;
struct udphdr_bsd *udp = (struct udphdr_bsd *) (packet + sizeof(struct ip));
static int myttl = 0;

int res;
struct sockaddr_in sock;
char myname[MAXHOSTNAMELEN + 1];
struct hostent *myhostent = NULL;
int source_malloced = 0;

/* check that required fields are there and not too silly */
if ( !victim || !sport || !dport || sd < 0) {
  fprintf(stderr, "send_udp_raw: One or more of your parameters suck!\n");
  return -1;
}

if (!myttl)  myttl = (time(NULL) % 14) + 51;

/* It was a tough decision whether to do this here for every packet
   or let the calling function deal with it.  In the end I grudgingly decided
   to do it here and potentially waste a couple microseconds... */
sethdrinclude(sd); 

/* if they didn't give a source address, fill in our first address */
if (!source) {
  source_malloced = 1;
  source = safe_malloc(sizeof(struct in_addr));
  if (gethostname(myname, MAXHOSTNAMELEN) || 
      !(myhostent = gethostbyname(myname)))
    fatal("Your system is messed up.\n"); 
  memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
#if ( TCPIP_DEBUGGING )
    printf("We skillfully deduced that your address is %s\n", 
	   inet_ntoa(*source));
#endif
}


/*do we even have to fill out this damn thing?  This is a raw packet, 
  after all */
sock.sin_family = AF_INET;
sock.sin_port = htons(dport);
sock.sin_addr.s_addr = victim->s_addr;


bzero((char *) packet, sizeof(struct ip) + sizeof(struct udphdr_bsd));

udp->uh_sport = htons(sport);
udp->uh_dport = htons(dport);
udp->uh_ulen = BSDFIX(8 + datalen);
/*udp->uh_sum = 0;*/

/* Now for the ip header */

bzero(packet, sizeof(struct ip)); 
ip->ip_v = 4;
ip->ip_hl = 5;
ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(struct udphdr_bsd) + datalen);
ip->ip_id = rand();
ip->ip_ttl = myttl;
ip->ip_p = IPPROTO_UDP;
ip->ip_src.s_addr = source->s_addr;
ip->ip_dst.s_addr= victim->s_addr;
#if HAVE_IP_IP_SUM
ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));
#endif

 /* We should probably copy the data over too */
if (data)
  memcpy(packet + sizeof(struct ip) + sizeof(struct udphdr_bsd), data, datalen);

if (TCPIP_DEBUGGING > 1) {
  printf("Raw UDP packet creation completed!  Here it is:\n");
  readudppacket(packet,1);
}
if (TCPIP_DEBUGGING > 1) 

  printf("\nTrying sendto(%d , packet, %d, 0 , %s , %d)\n",
	 sd, BSDUFIX(ip->ip_len), inet_ntoa(*victim),
	 sizeof(struct sockaddr_in));
if ((res = sendto(sd, packet, BSDUFIX(ip->ip_len), 0,
		  (struct sockaddr *)&sock, (int) sizeof(struct sockaddr_in))) == -1)
  {
    perror("sendto in send_tcp_raw");
    if (source_malloced) free(source);
    return -1;
  }
if (TCPIP_DEBUGGING > 1) printf("successfully sent %d bytes of raw_tcp!\n", res);

if (source_malloced) free(source);
return res;
}


__inline__ int unblock_socket(int sd) {
int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
options = O_NONBLOCK | fcntl(sd, F_GETFL);
fcntl(sd, F_SETFL, options);
return 1;
}

/* Get the source address and interface name */
#if 0
char *getsourceif(struct in_addr *src, struct in_addr *dst) {
int sd, sd2;
unsigned short p1;
struct sockaddr_in sock;
int socklen = sizeof(struct sockaddr_in);
struct sockaddr sa;
int sasize = sizeof(struct sockaddr);
int ports, res;
char buf[65536];
struct timeval tv;
unsigned int start;
int data_offset, ihl, *intptr;
int done = 0;

  /* Get us some unreserved port numbers */
  do {
    p1 = rand();
  } while (p1 < 5000);

  if (!getuid()) {
    if ((sd2 = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
      {perror("Linux Packet Socket troubles"); return 0;}
    unblock_socket(sd2);
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
      {perror("Socket troubles"); return 0;}
    sock.sin_family = AF_INET;
    sock.sin_addr = *dst;
    sock.sin_port = htons(p1);
    if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
      { perror("UDP connect()");
      close(sd);
      close(sd2);
      return NULL;
      }
    if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
      perror("getsockname");
      close(sd);
      close(sd2);
      return NULL;
    }
    ports = (ntohs(sock.sin_port) << 16) + p1;
#if ( TCPIP_DEBUGGING )
      printf("ports is %X\n", ports);
#endif
    if (send(sd, "", 0, 0) == -1)
    fatal("Could not send UDP packet");
    start = time(NULL);
    do {
      tv.tv_sec = 2;
      tv.tv_usec = 0;
      res = recvfrom(sd2, buf, 65535, 0, &sa, &sasize);
      if (res < 0) {
	if (errno != EWOULDBLOCK)
	  perror("recvfrom");
      }
      if (res > 0) {
#if ( TCPIP_DEBUGGING )
	printf("Got packet!\n");
	printf("sa.sa_data: %s\n", sa.sa_data);
	printf("Hex dump of packet (len %d):\n", res);
	hdump(buf, res);
#endif
	data_offset = get_link_offset(sa.sa_data);
	ihl = (*(buf + data_offset) & 0xf) * 4;
	/* If it is big enough and it is IPv4 */
	if (res >=  data_offset + ihl + 4 &&
	    (*(buf + data_offset) & 0x40)) {
	  intptr = (int *)  ((char *) buf + data_offset + ihl);
	  if (*intptr == ntohl(ports)) {
	    intptr = (int *) ((char *) buf + data_offset + 12);
#if ( TCPIP_DEBUGGING )
	    printf("We've found our packet [krad]\n");
#endif
	    memcpy(src, buf + data_offset + 12, 4);
	    close(sd);
	    close(sd2);
	    return strdup(sa.sa_data);
	  }
	}
      }        
    } while(!done && time(NULL) - start < 2);
    close(sd);
    close(sd2);
  }

return NULL;
}
#endif /* 0 */

#ifdef NOT_DEFINED
int getsourceip(struct in_addr *src, struct in_addr *dst) {
  int sd, sd2;
  struct sockaddr_in sock;
  struct sockaddr sa;
  int sasize = sizeof(struct sockaddr);
  int socklen = sizeof(struct sockaddr_in);
  char buf[65535];
  unsigned short p1;
  struct timeval tv;
  int done = 0;
  int res;
  int ihl;
  int ports;
  int start;
  int data_offset;
  unsigned int *intptr;

  /* Get us some unreserved port numbers */
  do {
    p1 = rand();
  } while (p1 < 5000);

  if (!getuid()) {
    if ((sd2 = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
      {perror("Linux Packet Socket troubles"); return 0;}
    unblock_socket(sd2);
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
      {perror("Socket troubles"); return 0;}
    sock.sin_family = AF_INET;
    sock.sin_addr = *dst;
    sock.sin_port = htons(p1);
    if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
      { perror("UDP connect()");
      close(sd);
      return 0;
      }
    if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
      perror("getsockname");
      close(sd);
      return 0;
    }
    ports = (ntohs(sock.sin_port) << 16) + p1;
#if ( TCPIP_DEBUGGING )
    printf("ports is %X\n", ports);
#endif
    if (send(sd, "", 0, 0) == -1)
    fatal("Could not send UDP packet");
    start = time(NULL);
    do {
      tv.tv_sec = 2;
      tv.tv_usec = 0;
      res = recvfrom(sd2, buf, 65535, 0, &sa, &sasize);
      if (res < 0) {
	if (errno != EWOULDBLOCK)
	  perror("recvfrom");
      }
      if (res > 0) {
#if (TCPIP_DEBUGGING)
	printf("Got packet!\n");
	printf("sa.sa_data: %s\n", sa.sa_data);
	printf("Hex dump of packet (len %d):\n", res);
	hdump(buf, res);
#endif      
	data_offset = get_link_offset(sa.sa_data);
	ihl = (*(buf + data_offset) & 0xf) * 4;
	/* If it is big enough and it is IPv4 */
	if (res >=  data_offset + ihl + 4 &&
	    (*(buf + data_offset) & 0x40)) {
	  intptr = (int *)  ((char *) buf + data_offset + ihl);
	  if (*intptr == ntohl(ports)) {
	    intptr = (int *) ((char *) buf + data_offset + 12);
#if (TCPIP_DEBUGGING)
	    printf("We've found our packet [krad]\n");
#endif
	    memcpy(src, buf + data_offset + 12, 4);
	    close(sd);
	    close(sd2);
	    return 1;
	  }
	}
      }  
      
    } while(!done && time(NULL) - start < 3);
    close(sd);
    close(sd2);
  }

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {perror("Socket troubles"); return 0;}
  sock.sin_family = AF_INET;
  sock.sin_addr = *dst;
  sock.sin_port = htons(MAGIC_PORT);
  if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
    { perror("UDP connect()");
    close(sd);
    return 0;
    }
  bzero(&sock, sizeof(struct sockaddr_in));
  if (getsockname(sd, (SA *)&sock, &socklen) == -1) {
    perror("getsockname");
    close(sd);
    return 0;
  }
  /* should check whether a bind() succeeds */
  if (sock.sin_addr.s_addr == dst->s_addr) {
    /* could be valid, but only if we are sending to ourself */
    /* Its probably an error so I'm returning 0 */
    /* Linux has the very bad habit of doing this */
    close(sd);
    return 0;
  }
  if (sock.sin_addr.s_addr) {
    src->s_addr = sock.sin_addr.s_addr;
#if ( TCPIP_DEBUGGING )
    printf("getsourceip: %s routes through interface %s\n", inet_ntoa(*dst), inet_ntoa(*src));
#endif
  }
  else {
#if (TCPIP_DEBUGGING)
    printf("failed to obtain your IP address\n");
#endif
    close(sd);
    return 0;
  }
  close(sd);
  return 1;
}

#endif /* NOT_DEFINED */

#if 0
int get_link_offset(char *device) {
int sd;
struct ifreq ifr;
sd = socket(AF_INET, SOCK_DGRAM, 0);
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
#if (defined(SIOCGIFHWADDR) && defined(ARPHRD_ETHER) && 
     defined(ARPHRD_METRICOM) && defined(ARPHRD_SLIP) && defined(ARPHRD_CSLIP)
     && defined(ARPHRD_SLIP6) && defined(ARPHRD_PPP) && 
     defined(ARPHRD_LOOPBACK) )
if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0 ) {
  fatal("Can't obtain link offset.  What kind of interface are you using?");
  }
close(sd);
switch (ifr.ifr_hwaddr.sa_family) {
case ARPHRD_ETHER:  /* These two are standard ethernet */
case ARPHRD_METRICOM:
  return 14;
  break;
case ARPHRD_SLIP:
case ARPHRD_CSLIP:
case ARPHRD_SLIP6:
case ARPHRD_CSLIP6:
case ARPHRD_PPP:
  return 0;
  break;
case ARPHRD_LOOPBACK:  /* Loopback interface (obviously) */
  return 14;
  break;
default:
  fatal("Unknown link layer device: %d", ifr.ifr_hwaddr.sa_family);
}
#else
printf("get_link_offset called even though your host doesn't support it.  Assuming Ethernet or Loopback connection (wild guess)\n");
return 14;
#endif
/* Not reached */
exit(1);
}
#endif

/* Convert an IP address into the name of the device which uses that IP
   address return 1 if successful, 0 if failure */
int ipaddr2devname( char *dev, struct in_addr *addr ) {
  int sd;
  int len = 2048;
  char buf[2048];
  char *pbuf = buf;
  struct ifconf ifc;
  struct ifreq *ifr;
  struct sockaddr_in *sin;
  char *p;

  if (!dev) fatal("NULL pointer given to ipaddr2devname");
  if (!addr) fatal("ipaddr2devname passed a NULL address");
  /* Dummy socket for ioctl */
  sd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sd < 0) pfatal("socket in ipaddr2devname");
  ifc.ifc_len = len;
  ifc.ifc_buf = buf;
  if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
    fatal("Failed to determine your configured interfaces!\n");
  }
  close(sd);
ifr = (struct ifreq *) pbuf;
if (ifc.ifc_len == 0) 
  fatal("SIOCGIFCONF claims you have no network interfaces!\n");
#if HAVE_SOCKADDR_SA_LEN
  len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);
#else
  len = sizeof(SA);
#endif
  for( ifr = (struct ifreq *) pbuf;
       ifr && *((char *)ifr) && ((char *)ifr) < pbuf + ifc.ifc_len; 
       ((*(char **)&ifr) +=  sizeof(ifr->ifr_name) + len )) {
    sin = (struct sockaddr_in *) &ifr->ifr_addr;
    if (sin->sin_addr.s_addr == addr->s_addr) {
      /* Stevens does this in UNP, so it may be useful in some cases */
      if ((p = strchr(ifr->ifr_name, ':')))
	*p = '\0';
      /* If an app gives me less than 64 bytes, they deserve to be
	 overflowed! */
      strncpy(dev, ifr->ifr_name, 63);
      dev[63] = '\0';
      return 1;
    }
  }
  /* Shucks, we didn't find it ... */
  dev[0] = '\0';
  return 0;
}

/* Read an IP packet using libpcap .  We return the packet and take
   a pcap descripter and a pointer to the packet length (which we set
   in the function.  If you want a read timeout, specify one in 
   pcap_open_live(). If you want a maximum length returned, you also
   should specify that in pcap_open_live() */

char *readip_pcap(pcap_t *pd, unsigned int *len) {
static int offset = -1;
static pcap_t *lastpcap = NULL;
struct pcap_pkthdr head;
char *p;
int datalink;

if (!pd) fatal("NULL packet device passed to readip_pcap");
if (!lastpcap || pd != lastpcap) { 
  /* New packet capture device, need to recompute offset */
  if ( (datalink = pcap_datalink(pd)) < 0)
    fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));
  switch(datalink) {
  case DLT_EN10MB: offset = 14; break;
  case DLT_NULL: offset = 4; break;
  case DLT_SLIP: 
  case DLT_PPP: offset = 24; break;
  case DLT_RAW: offset = 0; break;
  default: fatal("Unknown datalink type (%d)", datalink);
  }
}
lastpcap = pd;
do {
  printf("Calling pcap_next\n");
  p = (char *) pcap_next(pd, &head);
  printf("Done with pcap_next\n");
  if (p)
    p += offset;
  else {
    /* timed out */ 
    *len=0;
    printf("leaving\n");
    return NULL;
  }
} while(!p || (*p & 0x40) != 0x40); /* Go until we get IPv4 packet */
*len = head.caplen - offset;
return p;
}

/* Like readip_pcap except we use our own timeout value.  This is needed
   due to a "bug" in libpcap.  The Linux pcap_open_live takes a timeout
   but DOES NOT EVEN LOOK AT IT! */
char *readip_pcap_timed(pcap_t *pd, unsigned int *len, unsigned long timeout /*seconds
 */) {
static int offset = -1;
static pcap_t *lastpcap = NULL;
struct pcap_pkthdr head;
char *p;
int datalink;

if (!pd) fatal("NULL packet device passed to readip_pcap");
if (!lastpcap || pd != lastpcap) {
  /* New packet capture device, need to recompute offset */
  if ( (datalink = pcap_datalink(pd)) < 0)
    fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));
  switch(datalink) {
  case DLT_EN10MB: offset = 14; break;
  case DLT_NULL: offset = 4; break;
  case DLT_SLIP:
  case DLT_PPP: offset = 24; break;
  case DLT_RAW: offset = 0; break;
  default: fatal("Unknown datalink type (%d)", datalink);
  }
}
lastpcap = pd;
signal(SIGALRM, sig_alarm);
if (setjmp(jmp_env)) {
  /* We've timed out */
  *len = 0;
  return NULL;
}
jumpok = 1;
alarm(timeout);
do {
p = (char *) pcap_next(pd, &head);
if (p)
  p += offset;
} while(!p || (*p & 0x40) != 0x40); /* Go until we get IPv4 packet */
alarm(0);
jumpok = 0;
signal(SIGALRM, SIG_DFL);
*len = head.caplen - offset;
return p;
}

