#ifndef NMAP_H
#define NMAP_H

/************************INCLUDES**********************************/

#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_INLINE
#define __inline__
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
void *malloc();
void *realloc();
#endif

#if STDC_HEADERS || HAVE_STRING_H
#include <string.h>
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#ifndef HAVE_BZERO
#define bzero(s, n) memset((s), 0, (n))
#endif

#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#endif

#include <ctype.h>
#include <sys/types.h>

#ifdef HAVE_SYS_PARAM_H   
#include <sys/param.h> /* Defines MAXHOSTNAMELEN on BSD*/
#endif

/* Linux uses these defines in netinet/ip.h and netinet/tcp.h to
   use the correct struct ip and struct tcphdr */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

/* BSDI needs this to insure the correct struct ip */
#undef _IP_VHL

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>
#include <rpc/types.h>
#include <sys/socket.h>
#include <sys/socket.h> 
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h> 
#include <signal.h>
#include <stdarg.h>
#ifndef NETINET_IN_SYSTEM_H  /* why the HELL does OpenBSD not do this? */
#include <netinet/in_systm.h> /* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTEM_H
#endif
#ifndef NETINET_IP_H  /* why the HELL does OpenBSD not do this? */
#include <netinet/ip.h> 
#define NETINET_IP_H
#endif
#include <netinet/ip_icmp.h> 
#include <arpa/inet.h>
#include <math.h>
#include <sys/time.h> 
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H  /* why the HELL does OpenBSD not do this? */
#include <netinet/tcp.h>          /*#include <netinet/ip_tcp.h>*/
#define NETINET_TCP_H
#endif
#include <sys/resource.h>
/*#include <net/if_arp.h> *//* defines struct arphdr needed for if_ether.h */
#ifndef NET_IF_H  /* why the HELL does OpenBSD not do this? */
#include <net/if.h>
#define NET_IF_H
#endif
#if HAVE_NETINET_IF_ETHER_H 
#ifndef NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#define NETINET_IF_ETHER_H
#endif /* NETINET_IF_ETHER_H */
#endif /* HAVE_NETINET_IF_ETHER_H */

#include "tcpip.h"
#include "error.h"
#include "utils.h"

/*******  DEFINES  ************/

/* User configurable #defines: */
/* #define to zero if you don't want to	ignore hosts of the form 
   xxx.xxx.xxx.{0,255} (usually network and broadcast addresses) */
#define IGNORE_ZERO_AND_255_HOSTS 0
#define VERSION "1.60"
#ifndef DEBUGGING
#define DEBUGGING 0
#endif
/* Default number of ports in parallel.  Doesn't always involve actual 
   sockets.  Can also adjust with the -M command line option.  */
#define MAX_SOCKETS 36 
/* As an optimisation we limit the maximum value of MAX_SOCKETS to a very
   high value (avoids dynamic memmory allocation */
#define MAX_SOCKETS_ALLOWED 1025
/* How many hosts do we ping in parallel to see if they are up? */
#define LOOKAHEAD 52
/* If reads of a UDP port keep returning EAGAIN (errno 13), do we want to 
   count the port as valid? */
#define RISKY_UDP_SCAN 0
 /* This ideally should be a port that isn't in use for any protocol on our machine or on the target */ 
#define MAGIC_PORT 49724
/* How many udp sends without a ICMP port unreachable error does it take before we consider the port open? */
#define UDP_MAX_PORT_RETRIES 4
 /*How many seconds before we give up on a host being alive? */
#define PING_TIMEOUT 6 /* Also timeout for a connect() tcp scan port */
#define FAKE_ARGV "pine" /* What ps and w should show if you use -q */
/* How do we want to log into ftp sites for */ 
#define FTPUSER "anonymous"
#define FTPPASS "-wwwuser@"
#define FTP_RETRIES 2 /* How many times should we relogin if we lose control
                         connection? */
#define MAX_TIMEOUTS MAX_SOCKETS   /* How many timed out connection attempts 
				      in a row before we decide the host is 
				      dead? */
#define MAX_DECOYS 128 /* How many decoys are allowed? */



/* DO NOT change stuff after this point */
#define UC(b)   (((int)b)&0xff)
#define MORE_FRAGMENTS 8192 /*NOT a user serviceable parameter*/
#define SA    struct sockaddr  /*Ubertechnique from R. Stevens */
/*#define fatal(x) { fprintf(stderr, "%s\n", x); exit(-1); }
  #define error(x) fprintf(stderr, "%s\n", x);*/
/* hoststruct->flags stuff */
#define HOST_UP 1
#define HOST_DOWN 2 
#define HOST_FIREWALLED 4 
#define HOST_BROADCAST 8 /* use the wierd_responses member of hoststruct instead */
/* struct port stuff */
#define PORT_CLOSED 0;
#define PORT_OPEN 1;
#define CONF_NONE 0;
#define CONF_LOW 1;
#define CONF_HIGH 2;

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifdef FREEBSD
#define BSDFIX(x) x
#define BSDUFIX(x) x
#else
#define BSDFIX(x) htons(x)
#define BSDUFIX(x) ntohs(x)
#endif

/***********************STRUCTURES**********************************/

typedef struct port {
  unsigned short portno;
  unsigned char proto;
  char *owner;
  int state; 
  int confidence; /* How sure are we about the state? */
  struct port *next;
} port;

struct ftpinfo {
  char user[64];
  char pass[256]; /* methinks you're paranoid if you need this much space */
  char server_name[MAXHOSTNAMELEN + 1];
  struct in_addr server;
  unsigned short port;
  int sd; /* socket descriptor */
};

struct targets {
  /* These 4 are used for the '/mask' style of specifying target net*/
  unsigned int netmask;
  unsigned int maskformat;
  struct in_addr start;
  struct in_addr currentaddr;
  struct in_addr end;
  /* These two are for the '138.[1-7,16,91-95,200-].12.1 style */
  unsigned char addresses[4][256];
  unsigned int current[4];
  unsigned char last[4];
};

struct hoststruct {
  struct in_addr host;
  struct in_addr source_ip;
  char *name;
  struct port *ports;
  /*
  unsigned int up;
  unsigned int down; */
  int wierd_responses; /* echo responses from other addresses, Ie a network broadcast address */
  unsigned int flags; /* HOST_UP, HOST_DOWN, HOST_FIREWALLED, HOST_BROADCAST (instead of HOST_BROADCAST use wierd_responses */
  unsigned long rtt; /* microseconds */
  char device[64]; /* The device we transmit on */
};

struct ops /* someone took struct options, <grrr> */ {
  int debugging;
  int verbose;
  int spoofsource; /* -S used */
  char device[64];
  int number_of_ports;
  int max_sockets;
  int isr00t;
  struct in_addr decoys[MAX_DECOYS];
  int numdecoys;
  int decoyturn;
  int identscan;
  enum { icmp, tcp, none} pingtype;
  int pingscan;
  int allowall;
  int wait;
  int ptime;
  int numports;
  int connectscan;
  int nullscan;
  int xmasscan;
  int fragscan;
  int synscan;
  int finscan;
  int udpscan;
  int lamerscan;
  int noresolve;
  int force; /* force nmap to continue on even when the outcome seems somewhat certain */
  FILE *logfd; /* Output log file descriptor */
};
  
typedef port *portlist;

/***********************PROTOTYPES**********************************/

/* print usage information */
void printusage(char *name);

/* our scanning functions */
portlist tcp_scan(struct hoststruct *target, unsigned short *portarray,                  int timeout);
portlist syn_scan(struct hoststruct *target, unsigned short *portarray);
portlist fin_scan(struct hoststruct *target, unsigned short *portarray);
portlist udp_scan(struct hoststruct *target, unsigned short *portarray);
portlist lamer_udp_scan(struct hoststruct *target,unsigned short *portarray);
portlist bounce_scan(struct hoststruct *target, unsigned short *portarray,
		     struct ftpinfo *ftp);

/* Scan helper functions */
unsigned long calculate_sleep(struct in_addr target);
int check_ident_port(struct in_addr target);
int getidentinfoz(struct in_addr target, int localport, int remoteport,
		  char *owner);
int parse_bounce(struct ftpinfo *ftp, char *url);
int ftp_anon_connect(struct ftpinfo *ftp);

/* port manipulators */
unsigned short *getpts(char *expr); /* someone stole the name getports()! */
unsigned short *getfastports(int tcpscan, int udpscan);
int addport(portlist *ports, unsigned short portno, unsigned short protocol,
	    char *owner);
int deleteport(portlist *ports, unsigned short portno, unsigned short protocol);
void printandfreeports(portlist ports);
int shortfry(unsigned short *ports);

/* socket manipulation functions */
void init_socket(int sd);
int unblock_socket(int sd);
int block_socket(int sd);
void broadcast_socket(int sd);
int recvtime(int sd, char *buf, int len, int seconds);
void max_rcvbuf(int sd);
int max_sd();
/* RAW packet building/dissasembling stuff */
int isup(struct in_addr target);
int send_small_fragz(int sd, struct in_addr *source, struct in_addr *victim,
		     int sport, int dport, int flags);
int listen_icmp(int icmpsock, unsigned short outports[],
		unsigned short numtries[], int *num_out,
		struct in_addr target, portlist *ports);
void massping(struct hoststruct *hostbatch, int numhosts, int pingtimeout);
void masstcpping(struct hoststruct *hostbatch, int num_hosts, int pingtimeout);
/* general helper functions */
void hdump(unsigned char *packet, int len);
void *safe_malloc(int size);
int parse_targets(struct targets *targets, char *h);
struct hoststruct *nexthost(char *hostexp, int lookahead, int pingtimeout);
void options_init();
void nmap_log(char *fmt, ...);
void sigdie(int signo);
/* From glibc 2.0.6 because Solaris doesn't seem to have this function */
#ifndef HAVE_INET_ATON
int inet_aton(register const char *, struct in_addr *);
#endif
#endif /* NMAP_H */





